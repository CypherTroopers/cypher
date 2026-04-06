//go:build !cuda

package miner

import (
	"errors"
	"testing"
	"unsafe"

	cx "colossusx/colossusx"
)

type recordingSharedKernel struct {
	spec          Spec
	calls         int
	lastPtr       uintptr
	lastByteLen   uint64
	lastNodeCount uint64
}

func (k *recordingSharedKernel) HashBatchShared(header []byte, startNonce cx.Nonce, count uint64, dag rawContiguousDAGBuffer) ([]HashResult, error) {
	k.calls++
	k.lastPtr = uintptr(dag.Ptr)
	k.lastByteLen = dag.ByteLen
	k.lastNodeCount = dag.NodeCount
	results := make([]HashResult, 0, count)
	for i := uint64(0); i < count; i++ {
		nonce, ok := startNonce.AddUint64(i)
		if !ok {
			break
		}
		results = append(results, latticeHashSharedBuffer(k.spec, header, nonce, dag))
	}
	return results, nil
}

type fakeOpenCLDeviceKernel struct {
	spec  Spec
	calls int
}

func (k *fakeOpenCLDeviceKernel) HashBatchOpenCL(ctx OpenCLContext, spec Spec, header []byte, startNonce cx.Nonce, count uint64, dag rawContiguousDAGBuffer) ([]HashResult, error) {
	k.calls++
	results := make([]HashResult, 0, count)
	for i := uint64(0); i < count; i++ {
		nonce, ok := startNonce.AddUint64(i)
		if !ok {
			break
		}
		results = append(results, latticeHashSharedBuffer(spec, header, nonce, dag))
	}
	return results, nil
}

type failingOpenCLDeviceKernel struct{}

func (failingOpenCLDeviceKernel) HashBatchOpenCL(ctx OpenCLContext, spec Spec, header []byte, startNonce cx.Nonce, count uint64, dag rawContiguousDAGBuffer) ([]HashResult, error) {
	return nil, errors.New("device kernel launch failed")
}

type fakeOpenCLRuntime struct {
	initErr     error
	available   bool
	svm         bool
	ctx         OpenCLContext
	initCalls   int
	setCtxCalls int
}

func (r *fakeOpenCLRuntime) Initialize() error {
	r.initCalls++
	if r.initErr != nil {
		return r.initErr
	}
	if r.ctx.Context == nil {
		r.ctx = OpenCLContext{Context: unsafe.Pointer(uintptr(1)), Device: unsafe.Pointer(uintptr(2)), Queue: unsafe.Pointer(uintptr(3))}
	}
	return nil
}
func (r *fakeOpenCLRuntime) Available() bool { return r.available }
func (r *fakeOpenCLRuntime) SupportsSVM() bool {
	return r.svm
}
func (r *fakeOpenCLRuntime) CUDADeviceOrdinal() (int, bool) { return 0, false }
func (r *fakeOpenCLRuntime) OpenCLContext() (OpenCLContext, bool) {
	if !r.available {
		return OpenCLContext{}, false
	}
	return r.ctx, true
}
func (r *fakeOpenCLRuntime) SetContext(ctx OpenCLContext) {
	r.ctx = ctx
	r.setCtxCalls++
}
func (r *fakeOpenCLRuntime) MetalContext() (MetalContext, bool) { return MetalContext{}, false }

func testResearchDAG(t *testing.T) *DAG {
	t.Helper()
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 1024 * 1024, NodeSize: DefaultNodeSize, ReadsPerHash: 8, EpochBlocks: DefaultEpochBlocks}
	dag, err := NewDAG(spec)
	if err != nil {
		t.Fatalf("NewDAG: %v", err)
	}
	if err := GenerateDAG(dag, []byte("0123456789abcdef0123456789abcdef"), 2); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	return dag
}

func TestGPUBackendCanBeConstructed(t *testing.T) {
	backend, err := NewGPUBackend()
	if err != nil {
		t.Fatalf("NewGPUBackend: %v", err)
	}
	if backend == nil {
		t.Fatal("expected gpu backend instance")
	}
	if backend.Mode() != BackendOpenCL {
		t.Fatalf("unexpected backend mode: %s", backend.Mode())
	}
}

func TestGPUHashMatchesCPUReference(t *testing.T) {
	dag := testResearchDAG(t)
	defer dag.Close()
	header := []byte("header")
	nonce := cx.NewUint64Nonce(42)

	gpu := &fakeGPUBackend{}
	cpu := &CPUBackend{}
	if err := gpu.Prepare(dag); err != nil {
		t.Fatalf("gpu Prepare: %v", err)
	}
	if err := cpu.Prepare(dag); err != nil {
		t.Fatalf("cpu Prepare: %v", err)
	}

	gpuHash := gpu.Hash(header, nonce, dag)
	cpuHash := cpu.Hash(header, nonce, dag)
	if gpuHash != cpuHash {
		t.Fatalf("expected gpu and cpu backends to match; gpu=%x cpu=%x", gpuHash.Pow256, cpuHash.Pow256)
	}
}

func TestSuccessfulGPURunAvoidsNormalFallback(t *testing.T) {
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 64 * 64, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}
	dag, err := NewDAG(spec)
	if err != nil {
		t.Fatalf("NewDAG: %v", err)
	}
	defer dag.Close()
	if err := GenerateDAG(dag, []byte("seedseedseedseedseedseedseedseed"), 1); err != nil {
		t.Fatalf("GenerateDAG: %v", err)
	}
	backend := &fakeGPUBackend{}
	if _, err := InitializeBackendRuntime(backend); err != nil {
		t.Fatalf("InitializeBackendRuntime: %v", err)
	}
	if !backend.runtimeCalled {
		t.Fatal("expected runtime initialization before allocator resolution")
	}
	if err := backend.Prepare(dag); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	results, err := backend.HashBatch([]byte("header"), cx.NewUint64Nonce(0), 4, dag)
	if err != nil {
		t.Fatalf("HashBatch: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 gpu results, got %d", len(results))
	}
	if backend.fallbackUsed {
		t.Fatal("expected successful GPU dispatch to avoid CPU fallback")
	}
}

func TestOpenCLDispatcherSVMRejectsHostFallbackInColossusXMode(t *testing.T) {
	dag := testResearchDAG(t)
	defer dag.Close()
	runtime := &fakeOpenCLRuntime{available: true, svm: true}
	sharedKernel := &recordingSharedKernel{spec: dag.Spec()}
	dispatcher := &openclDispatcher{runtime: runtime, sharedKernel: sharedKernel}
	cfg := gpuKernelConfig{WorkgroupSize: 64, BatchNonces: 4, Source: openclKernelSource, VerifierPct: 100}
	if err := dispatcher.Prepare(dag, cfg); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	result, err := dispatcher.Dispatch([]byte("header"), cx.NewUint64Nonce(10), 3, dag)
	if err == nil {
		t.Fatal("expected colossusx mode to reject host-reference fallback when device dispatch does not run")
	}
	plan := result.Plan
	if !plan.SVMEnabled {
		t.Fatal("expected SVM metadata to reflect runtime capability")
	}
	if runtime.setCtxCalls == 0 {
		t.Fatal("expected Prepare to wire buildOpenCLProgram output back into the runtime context")
	}
	if sharedKernel.calls != 0 {
		t.Fatalf("expected the host shared kernel to remain unused on the shared-host reference path, got %d calls", sharedKernel.calls)
	}
	raw, err := newRawContiguousDAGBuffer(dag)
	if err != nil {
		t.Fatalf("newRawContiguousDAGBuffer: %v", err)
	}
	_ = raw
}

func TestOpenCLDispatcherReportsDeviceKernelOnlyAfterSuccessfulDeviceDispatch(t *testing.T) {
	dag := testResearchDAG(t)
	defer dag.Close()
	runtime := &fakeOpenCLRuntime{available: true, svm: true}
	deviceKernel := &fakeOpenCLDeviceKernel{spec: dag.Spec()}
	dispatcher := &openclDispatcher{runtime: runtime, deviceSharedHash: deviceKernel}
	cfg := gpuKernelConfig{WorkgroupSize: 64, BatchNonces: 4, Source: openclKernelSource, VerifierPct: 100}
	if err := dispatcher.Prepare(dag, cfg); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	header := []byte("header")
	startNonce := cx.NewUint64Nonce(10)
	result, err := dispatcher.Dispatch(header, startNonce, 3, dag)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if deviceKernel.calls != 1 {
		t.Fatalf("expected one device-kernel dispatch, got %d", deviceKernel.calls)
	}
	if len(result.Hashes) != 3 {
		t.Fatalf("expected 3 hashes, got %d", len(result.Hashes))
	}
	raw, err := newRawContiguousDAGBuffer(dag)
	if err != nil {
		t.Fatalf("newRawContiguousDAGBuffer: %v", err)
	}
	for i := 0; i < 3; i++ {
		nonce, _ := startNonce.AddUint64(uint64(i))
		want := latticeHashSharedBuffer(dag.Spec(), header, nonce, raw)
		if result.Hashes[i] != want {
			t.Fatalf("hash %d mismatch: got=%x want=%x", i, result.Hashes[i].Pow256, want.Pow256)
		}
	}
	plan := result.Plan
	if plan.UsedFallback {
		t.Fatal("expected successful OpenCL device kernel dispatch to avoid fallback")
	}
	if plan.ExecutionPath != GPUExecutionPathDeviceKernel {
		t.Fatalf("expected device-kernel execution path, got %q", plan.ExecutionPath)
	}
	if plan.ExecutionBackend != "opencl" {
		t.Fatalf("expected opencl execution backend, got %q", plan.ExecutionBackend)
	}
	if !plan.DeviceDispatchAttempted {
		t.Fatal("expected successful device dispatch to be reported")
	}
	if plan.CopiedDAG || plan.DeviceDAGCopyPerformed {
		t.Fatalf("expected no device DAG copy, got CopiedDAG=%v DeviceDAGCopyPerformed=%v", plan.CopiedDAG, plan.DeviceDAGCopyPerformed)
	}
}

func TestOpenCLDispatcherRejectsFallbackWhenDeviceKernelFailsInColossusXMode(t *testing.T) {
	dag := testResearchDAG(t)
	defer dag.Close()
	runtime := &fakeOpenCLRuntime{available: true, svm: true}
	dispatcher := &openclDispatcher{runtime: runtime, deviceSharedHash: failingOpenCLDeviceKernel{}}
	cfg := gpuKernelConfig{WorkgroupSize: 64, BatchNonces: 4, Source: openclKernelSource, VerifierPct: 100}
	if err := dispatcher.Prepare(dag, cfg); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	_, err := dispatcher.Dispatch([]byte("header"), cx.NewUint64Nonce(10), 3, dag)
	if err == nil {
		t.Fatal("expected colossusx mode to reject host fallback after device-kernel failure")
	}
}

func TestGPUBackendPrepareFailsHardWhenRuntimeUnavailable(t *testing.T) {
	dag := testResearchDAG(t)
	defer dag.Close()
	backend := &GPUBackend{
		config:     gpuKernelConfig{WorkgroupSize: 64, BatchNonces: 4, Source: openclKernelSource, VerifierPct: 100},
		dispatcher: &openclDispatcher{runtime: &fakeOpenCLRuntime{initErr: errors.New("no opencl runtime")}},
	}
	if err := backend.Prepare(dag); err == nil {
		t.Fatal("expected Prepare to fail when the OpenCL runtime cannot initialize")
	}
	plan := backend.ExecutionPlan()
	if !plan.UsedFallback {
		t.Fatal("expected runtime initialization failure to report fallback usage")
	}
	if plan.ExecutionPath != GPUExecutionPathHostReference {
		t.Fatalf("expected host-reference execution path on failure, got %q", plan.ExecutionPath)
	}
}

func TestOpenCLDispatcherRejectsHostFallbackWithoutSVMInColossusXMode(t *testing.T) {
	dag := testResearchDAG(t)
	defer dag.Close()
	runtime := &fakeOpenCLRuntime{available: true, svm: false}
	sharedKernel := &recordingSharedKernel{spec: dag.Spec()}
	dispatcher := &openclDispatcher{runtime: runtime, sharedKernel: sharedKernel}
	cfg := gpuKernelConfig{WorkgroupSize: 64, BatchNonces: 4, Source: openclKernelSource, VerifierPct: 100}
	if err := dispatcher.Prepare(dag, cfg); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	result, err := dispatcher.Dispatch([]byte("header"), cx.NewUint64Nonce(10), 3, dag)
	if err == nil {
		t.Fatal("expected colossusx mode to reject host-reference fallback when SVM is unavailable")
	}
	plan := result.Plan
	if plan.CopiedDAG || plan.DeviceDAGCopyPerformed {
		t.Fatalf("expected no DAG copy on rejected host-reference path, got CopiedDAG=%v DeviceDAGCopyPerformed=%v", plan.CopiedDAG, plan.DeviceDAGCopyPerformed)
	}
	if sharedKernel.calls != 0 {
		t.Fatalf("expected shared kernel to stay unused without SVM, got %d calls", sharedKernel.calls)
	}
}
