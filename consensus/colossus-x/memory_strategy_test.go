package miner

import (
	"testing"
	"unsafe"

	cx "colossusx/colossusx"
)

type testAllocation struct {
	buf   []byte
	freed bool
}

func (a *testAllocation) Bytes() []byte { return a.buf }
func (a *testAllocation) Free() error   { a.freed = true; return nil }
func (a *testAllocation) Name() string  { return "test-allocation" }

func TestNewDAGWithStrategyGoHeap(t *testing.T) {
	spec := Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 1024, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}
	dag, err := NewDAGWithStrategy(spec, GoHeapMemory{})
	if err != nil {
		t.Fatalf("NewDAGWithStrategy: %v", err)
	}
	defer dag.Close()
	if got := uint64(len(dag.Bytes())); got != spec.DAGSizeBytes {
		t.Fatalf("expected DAG bytes %d, got %d", spec.DAGSizeBytes, got)
	}
}

func TestUnsupportedStrategyReturnsExplicitError(t *testing.T) {
	alloc, err := NewDAGWithStrategy(Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 1024, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}, PinnedMemory{})
	if err != nil {
		t.Fatalf("expected pinned strategy to allocate, got: %v", err)
	}
	defer alloc.Close()
	if got := alloc.AllocationName(); got != "pinned-host" {
		t.Fatalf("expected pinned-host allocation, got %q", got)
	}
	if _, err := (CUDAManagedMemory{}).Alloc(64); err == nil {
		t.Fatal("expected CUDA managed memory to fail without initialized runtime")
	}
	if _, err := (OpenCLSVM{}).Alloc(64); err == nil {
		t.Fatal("expected OpenCL SVM to fail without live context/device")
	}
}

func TestDAGCloseReleasesOwnedAllocation(t *testing.T) {
	alloc := &testAllocation{buf: make([]byte, 1024)}
	dag, err := NewDAGWithAllocation(Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 1024, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}, alloc, true)
	if err != nil {
		t.Fatalf("NewDAGWithAllocation: %v", err)
	}
	if err := dag.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !alloc.freed {
		t.Fatal("expected DAG.Close to free owned allocation")
	}
}

func TestSelectDAGStrategyAutoFallsBackToGoHeapWithoutRuntime(t *testing.T) {
	strategy, err := dagStrategyResolver{backend: BackendCPU}.Resolve("auto")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	alloc, err := strategy.Alloc(64)
	if err != nil {
		t.Fatalf("Alloc: %v", err)
	}
	defer alloc.Free()
	if alloc.Name() != "go-heap" {
		t.Fatalf("expected auto strategy to fall back to go-heap in test environment, got %q", alloc.Name())
	}
}

func TestAllocatorResolutionDependsOnRuntimeInitialization(t *testing.T) {
	resolver := dagStrategyResolver{backend: BackendGPU}
	if _, err := resolver.Resolve("cuda-managed"); err == nil {
		t.Fatal("expected cuda-managed resolution to fail before runtime initialization")
	}
	resolver.runtime = fakeRuntimeState{cudaOrdinal: 3, cudaOK: true}
	strategy, err := resolver.Resolve("cuda-managed")
	if err != nil {
		t.Fatalf("Resolve(cuda-managed): %v", err)
	}
	if strategy.Name() != "cuda-managed" {
		t.Fatalf("unexpected strategy: %s", strategy.Name())
	}
	if _, err := (dagStrategyResolver{backend: BackendGPU}).Resolve("opencl-svm"); err == nil {
		t.Fatal("expected opencl-svm resolution to fail before runtime initialization")
	}
	strategy, err = (dagStrategyResolver{backend: BackendGPU, runtime: fakeRuntimeState{openclCtx: OpenCLContext{Context: unsafe.Pointer(new(byte)), Device: unsafe.Pointer(new(byte))}, openclOK: true}}).Resolve("opencl-svm")
	if err != nil {
		t.Fatalf("Resolve(opencl-svm): %v", err)
	}
	if strategy.Name() != "opencl-svm" {
		t.Fatalf("unexpected strategy: %s", strategy.Name())
	}
}

func TestNewDAGWithAllocationRejectsShortBuffer(t *testing.T) {
	alloc := &testAllocation{buf: make([]byte, 8)}
	_, err := NewDAGWithAllocation(Spec{Mode: cx.ModeColossusX, DAGSizeBytes: 1024, NodeSize: DefaultNodeSize, ReadsPerHash: 4, EpochBlocks: DefaultEpochBlocks}, alloc, false)
	if err == nil {
		t.Fatal("expected short allocation to fail")
	}
	if err.Error() != "managed allocation is smaller than the DAG" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidationReuseCapabilityForManagedAllocators(t *testing.T) {
	if !(GoHeapMemory{}).ValidationCanReuseDAG() {
		t.Fatal("expected go-heap DAGs to be validation reusable")
	}
	if !(PinnedMemory{}).ValidationCanReuseDAG() {
		t.Fatal("expected pinned-host DAGs to be validation reusable")
	}
	if (CUDAManagedMemory{}).ValidationCanReuseDAG() {
		t.Fatal("expected uninitialized cuda-managed strategy to refuse DAG reuse")
	}
	if !(CUDAManagedMemory{DeviceOrdinal: 0, Ready: true}).ValidationCanReuseDAG() {
		t.Fatal("expected ready cuda-managed strategy to allow DAG reuse")
	}
	if (OpenCLSVM{}).ValidationCanReuseDAG() {
		t.Fatal("expected invalid opencl-svm strategy to refuse DAG reuse")
	}
	ctx := OpenCLContext{Context: unsafe.Pointer(new(byte)), Device: unsafe.Pointer(new(byte))}
	if !(OpenCLSVM{Context: ctx}).ValidationCanReuseDAG() {
		t.Fatal("expected valid opencl-svm strategy to allow DAG reuse")
	}
}

func TestResolveDAGStrategyForModeColossusXAllowsHostAllocators(t *testing.T) {
	if _, err := ResolveDAGStrategyForMode(cx.ModeColossusX, BackendOpenCL, nil, "go-heap"); err != nil {
		t.Fatalf("expected colossusx mode to allow go-heap, got: %v", err)
	}
	if _, err := ResolveDAGStrategyForMode(cx.ModeColossusX, BackendOpenCL, nil, "pinned-host"); err != nil {
		t.Fatalf("expected colossusx mode to allow pinned-host, got: %v", err)
	}
}

func TestValidateColossusXProductionConfigEnforcesProductionRules(t *testing.T) {
	if err := ValidateColossusXProductionConfig(cx.ModeColossusX, BackendCPU, "auto"); err != nil {
		t.Fatalf("expected cpu backend auto allocator to pass validation, got: %v", err)
	}
	if err := ValidateColossusXProductionConfig(cx.ModeColossusX, BackendCPU, "cuda-managed"); err == nil {
		t.Fatal("expected cpu backend to reject gpu-only allocator")
	}
	if err := ValidateColossusXProductionConfig(cx.ModeColossusX, BackendUnified, "go-heap"); err == nil {
		t.Fatal("expected host allocator to be rejected in colossusx production")
	}
	if err := ValidateColossusXProductionConfig(cx.ModeColossusX, BackendUnified, "auto"); err != nil {
		t.Fatalf("expected unified backend auto allocator to pass validation, got: %v", err)
	}
}
