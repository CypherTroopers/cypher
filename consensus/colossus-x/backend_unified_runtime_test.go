package miner

import (
	"fmt"
	"testing"
)

type testOpenCLRuntime struct {
	initErr     error
	available   bool
	supportsSVM bool
	ctx         OpenCLContext
}

func (r *testOpenCLRuntime) Initialize() error { return r.initErr }
func (r *testOpenCLRuntime) Available() bool   { return r.available }
func (r *testOpenCLRuntime) SupportsSVM() bool { return r.supportsSVM }
func (r *testOpenCLRuntime) CUDADeviceOrdinal() (int, bool) {
	return 0, false
}
func (r *testOpenCLRuntime) OpenCLContext() (OpenCLContext, bool) {
	if !r.available {
		return OpenCLContext{}, false
	}
	return r.ctx, true
}
func (r *testOpenCLRuntime) MetalContext() (MetalContext, bool) { return MetalContext{}, false }

func TestUnifiedBackendInitializeRuntimePublishesCapabilities(t *testing.T) {
	origCUDAProbe := probeCUDADeviceOrdinal
	origOpenCLFactory := newUnifiedOpenCLRuntime
	t.Cleanup(func() {
		probeCUDADeviceOrdinal = origCUDAProbe
		newUnifiedOpenCLRuntime = origOpenCLFactory
	})

	probeCUDADeviceOrdinal = func() (int, error) { return 4, nil }
	newUnifiedOpenCLRuntime = func() openclRuntime {
		return &testOpenCLRuntime{
			available:   true,
			supportsSVM: true,
			ctx:         OpenCLContext{Context: struct{}{}, Device: struct{}{}},
		}
	}

	backend := &UnifiedBackend{}
	if err := backend.InitializeRuntime(); err != nil {
		t.Fatalf("InitializeRuntime: %v", err)
	}

	if ord, ok := backend.CUDADeviceOrdinal(); !ok || ord != 4 {
		t.Fatalf("expected CUDA ordinal (4,true), got (%d,%t)", ord, ok)
	}
	if _, ok := backend.OpenCLContext(); !ok {
		t.Fatal("expected OpenCL SVM capability to be exported")
	}
}

func TestUnifiedRuntimeAutoFallsBackToGoHeapWithoutCapabilities(t *testing.T) {
	origCUDAProbe := probeCUDADeviceOrdinal
	origOpenCLFactory := newUnifiedOpenCLRuntime
	t.Cleanup(func() {
		probeCUDADeviceOrdinal = origCUDAProbe
		newUnifiedOpenCLRuntime = origOpenCLFactory
	})

	probeCUDADeviceOrdinal = func() (int, error) { return 0, fmt.Errorf("cuda unavailable") }
	newUnifiedOpenCLRuntime = func() openclRuntime {
		return &testOpenCLRuntime{initErr: fmt.Errorf("opencl unavailable")}
	}

	backend := &UnifiedBackend{}
	if _, err := InitializeBackendRuntime(backend); err != nil {
		t.Fatalf("InitializeBackendRuntime: %v", err)
	}

	strategy, err := ResolveDAGStrategyForMode("colossusx", BackendUnified, backend, "auto")
	if err != nil {
		t.Fatalf("ResolveDAGStrategyForMode: %v", err)
	}
	alloc, err := strategy.Alloc(64)
	if err != nil {
		t.Fatalf("Alloc: %v", err)
	}
	defer alloc.Free()
	if alloc.Name() != "go-heap" {
		t.Fatalf("expected auto to fall back to go-heap, got %q", alloc.Name())
	}
}
