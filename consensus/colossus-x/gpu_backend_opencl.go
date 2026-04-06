//go:build !cuda

package miner

import (
	_ "embed"
	"fmt"
	"unsafe"

	cx "colossusx/colossusx"
)

type gpuKernelConfig struct {
	WorkgroupSize int
	BatchNonces   int
	Source        string
	VerifierPct   int
}

type GPUDispatchResult struct {
	Hashes []HashResult
	Plan   GPUExecutionPlan
}

type GPUDispatcher interface {
	Initialize() error
	Prepare(*DAG, gpuKernelConfig) error
	Dispatch(header []byte, startNonce cx.Nonce, batch int, dag *DAG) (GPUDispatchResult, error)
	Plan() GPUExecutionPlan
	RuntimeState() runtimeState
}

type kernelPreparedOpenCLRuntime interface {
	openclRuntime
	SetContext(OpenCLContext)
}

type openclDispatcher struct {
	runtime          openclRuntime
	config           gpuKernelConfig
	plan             GPUExecutionPlan
	scratch          *pooledScratch
	sharedKernel     sharedDAGHashKernel
	deviceSharedHash openCLSharedAllocationKernel
}

func (d *openclDispatcher) Initialize() error {
	return d.runtime.Initialize()
}

func (d *openclDispatcher) RuntimeState() runtimeState { return d.runtime }

func (d *openclDispatcher) Prepare(dag *DAG, cfg gpuKernelConfig) error {
	if dag == nil {
		return ErrNilDAG
	}
	if cfg.Source == "" {
		return fmt.Errorf("gpu backend requires an embedded OpenCL kernel source")
	}
	d.config = cfg
	if err := d.runtime.Initialize(); err != nil {
		d.plan = newHostReferenceGPUPlan("opencl", cfg)
		d.plan.Fallback = "runtime-unavailable"
		d.plan.UsedFallback = true
		return err
	}
	ctx, ok := d.runtime.OpenCLContext()
	if !ok {
		d.plan = newHostReferenceGPUPlan("opencl", cfg)
		d.plan.Fallback = "runtime-context-unavailable"
		d.plan.UsedFallback = true
		return fmt.Errorf("opencl runtime initialized without an exported context")
	}
	ctx, err := buildOpenCLProgram(ctx, cfg.Source)
	if err != nil {
		d.plan = newHostReferenceGPUPlan("opencl", cfg)
		d.plan.Fallback = "kernel-build-failed"
		d.plan.UsedFallback = true
		return fmt.Errorf("build opencl program: %w", err)
	}
	if runtimeWithContext, ok := d.runtime.(kernelPreparedOpenCLRuntime); ok {
		runtimeWithContext.SetContext(ctx)
	}
	if _, err := newRawContiguousDAGBuffer(dag); err != nil {
		return err
	}
	plan := newHostReferenceGPUPlan("opencl", cfg)
	plan.SVMEnabled = d.runtime.SupportsSVM()
	plan.Fallback = "cpu-reference"
	if plan.SVMEnabled {
		raw, err := newRawContiguousDAGBuffer(dag)
		if err != nil {
			return err
		}
		if err := setOpenCLSVMKernelArg(ctx, 0, raw.Ptr); err != nil {
			return fmt.Errorf("configure OpenCL SVM DAG argument: %w", err)
		}
	}
	d.plan = plan
	if d.scratch == nil {
		d.scratch = newPooledScratch()
	}
	return nil
}

func (d *openclDispatcher) Dispatch(header []byte, startNonce cx.Nonce, batch int, dag *DAG) (GPUDispatchResult, error) {
	colossusx := dag != nil && dag.Spec().Mode == cx.ModeColossusX
	plan := d.plan
	if batch <= 0 {
		plan.UsedFallback = true
		plan.ExecutionPath = GPUExecutionPathHostReference
		return GPUDispatchResult{Plan: plan}, nil
	}
	if !d.runtime.Available() {
		plan.UsedFallback = true
		plan.ExecutionPath = GPUExecutionPathHostReference
		return GPUDispatchResult{Plan: plan}, fmt.Errorf("opencl runtime unavailable")
	}
	raw, err := newRawContiguousDAGBuffer(dag)
	if err != nil {
		return GPUDispatchResult{Plan: plan}, err
	}
	if plan.SVMEnabled {
		if ctx, ok := d.runtime.OpenCLContext(); ok {
			if err := setOpenCLSVMKernelArg(ctx, 0, raw.Ptr); err != nil {
				plan.UsedFallback = true
				plan.ExecutionPath = GPUExecutionPathHostReference
				return GPUDispatchResult{Plan: plan}, fmt.Errorf("configure OpenCL SVM DAG argument: %w", err)
			}
			deviceKernel := d.deviceSharedHash
			if deviceKernel == nil {
				deviceKernel = newOpenCLSharedAllocationKernel()
			}
			if deviceKernel != nil {
				results, err := deviceKernel.HashBatchOpenCL(ctx, dag.Spec(), header, startNonce, uint64(batch), raw)
				if err == nil {
					plan.UsedFallback = false
					plan.ExecutionPath = GPUExecutionPathDeviceKernel
					plan.ExecutionBackend = "opencl"
					plan.DeviceDispatchAttempted = true
					plan.CopiedDAG = false
					plan.DeviceDAGCopyPerformed = false
					return GPUDispatchResult{Hashes: results, Plan: plan}, nil
				}
			}
		}
	}
	if colossusx {
		plan.UsedFallback = false
		plan.ExecutionPath = GPUExecutionPathDeviceKernel
		return GPUDispatchResult{Plan: plan}, fmt.Errorf("colossusx mode requires successful OpenCL device-kernel execution; host-reference fallback is forbidden")
	}
	results := make([]HashResult, 0, batch)
	view, err := newUnifiedMemoryDAGViewFromBytes(dag.Spec(), raw.Bytes)
	if err != nil {
		return GPUDispatchResult{Plan: plan}, err
	}
	for i := 0; i < batch; i++ {
		nonce, ok := startNonce.AddUint64(uint64(i))
		if !ok {
			break
		}
		s := d.scratch.acquire(len(header))
		results = append(results, latticeHashWithAccessor(dag.Spec(), header, nonce, view, s))
		d.scratch.release(s)
	}
	plan.UsedFallback = true
	plan.ExecutionPath = GPUExecutionPathHostReference
	plan.ExecutionBackend = "shared-host"
	plan.DeviceDispatchAttempted = false
	plan.CopiedDAG = false
	plan.DeviceDAGCopyPerformed = false
	return GPUDispatchResult{Hashes: results, Plan: plan}, nil
}

func (d *openclDispatcher) Plan() GPUExecutionPlan { return d.plan }

type GPUBackend struct {
	config           gpuKernelConfig
	dispatcher       GPUDispatcher
	cpuFallback      CPUBackend
	lastPlan         GPUExecutionPlan
	runtimeReady     bool
	runtimeInitError error
}

func (b *GPUBackend) Mode() BackendMode { return BackendOpenCL }
func (b *GPUBackend) Description() string {
	return "gpu backend with shared-memory-first OpenCL execution that hashes directly from the canonical contiguous DAG allocation when SVM is available, and otherwise falls back to the validated host reference path"
}
func (b *GPUBackend) InitializeRuntime() error {
	if b.runtimeReady || b.runtimeInitError != nil {
		return b.runtimeInitError
	}
	if b.dispatcher == nil {
		b.dispatcher = &openclDispatcher{runtime: newOpenCLRuntime()}
	}
	b.runtimeInitError = b.dispatcher.Initialize()
	if b.runtimeInitError == nil {
		b.runtimeReady = true
	}
	return b.runtimeInitError
}
func (b *GPUBackend) CUDADeviceOrdinal() (int, bool) { return 0, false }
func (b *GPUBackend) OpenCLContext() (OpenCLContext, bool) {
	if b.dispatcher == nil {
		return OpenCLContext{}, false
	}
	return b.dispatcher.RuntimeState().OpenCLContext()
}
func (b *GPUBackend) MetalContext() (MetalContext, bool) { return MetalContext{}, false }
func (b *GPUBackend) Prepare(dag *DAG) error {
	if b.config.WorkgroupSize == 0 {
		b.config = gpuKernelConfig{WorkgroupSize: 64, BatchNonces: 1024, Source: openclKernelSource, VerifierPct: 100}
	}
	if b.dispatcher == nil {
		b.dispatcher = &openclDispatcher{runtime: newOpenCLRuntime()}
	}
	if err := b.dispatcher.Prepare(dag, b.config); err != nil {
		b.lastPlan = b.dispatcher.Plan()
		return err
	}
	b.lastPlan = b.dispatcher.Plan()
	return nil
}
func (b *GPUBackend) Hash(header []byte, nonce cx.Nonce, dag *DAG) HashResult {
	results, err := b.HashBatch(header, nonce, 1, dag)
	if err != nil || len(results) == 0 {
		return HashResult{}
	}
	return results[0]
}
func (b *GPUBackend) HashBatch(header []byte, startNonce cx.Nonce, count uint64, dag *DAG) ([]HashResult, error) {
	if b.dispatcher == nil {
		b.dispatcher = &openclDispatcher{runtime: newOpenCLRuntime()}
	}
	result, err := b.dispatcher.Dispatch(header, startNonce, int(count), dag)
	b.lastPlan = result.Plan
	if err != nil {
		return nil, err
	}
	return result.Hashes, nil
}

func (b *GPUBackend) KernelSource() string            { return b.config.Source }
func (b *GPUBackend) WorkgroupSize() int              { return b.config.WorkgroupSize }
func (b *GPUBackend) BatchSize() int                  { return b.config.BatchNonces }
func (b *GPUBackend) ExecutionPlan() GPUExecutionPlan { return b.lastPlan }

func NewGPUBackend() (HashBackend, error) {
	return &GPUBackend{}, nil
}

//go:embed opencl_kernel.cl
var openclKernelSource string

func newHostReferenceGPUPlan(executionBackend string, cfg gpuKernelConfig) GPUExecutionPlan {
	return GPUExecutionPlan{
		KernelName:              "colossusx_hash",
		GlobalSize:              cfg.BatchNonces,
		LocalSize:               cfg.WorkgroupSize,
		BatchNonces:             cfg.BatchNonces,
		MemoryModel:             GPUMemoryModelUnified,
		VerifySample:            cfg.VerifierPct,
		Fallback:                "cpu-reference",
		UsedFallback:            true,
		CopiedDAG:               false,
		ExecutionBackend:        executionBackend,
		ExecutionPath:           GPUExecutionPathHostReference,
		SVMEnabled:              false,
		DeviceDAGCopyPerformed:  false,
		DeviceDispatchAttempted: false,
	}
}

var _ = unsafe.Pointer(nil)
