package miner

import (
	"fmt"
	"strings"

	cx "colossusx/colossusx"
)

type managedAllocation = cx.Allocation

type MemoryStrategy interface{ cx.Allocator }

type ValidationReusableAllocator interface{ ValidationCanReuseDAG() bool }

type MetalContext struct{ Device any }

type runtimeState interface {
	CUDADeviceOrdinal() (int, bool)
	OpenCLContext() (OpenCLContext, bool)
	MetalContext() (MetalContext, bool)
}

type dagStrategyResolver struct {
	mode    cx.Mode
	backend BackendMode
	runtime runtimeState
}

type fallbackMemoryStrategy struct {
	name       string
	strategies []MemoryStrategy
}

func (m fallbackMemoryStrategy) Alloc(size uint64) (cx.Allocation, error) {
	var errs []string
	for _, strategy := range m.strategies {
		if strategy == nil {
			continue
		}
		alloc, err := strategy.Alloc(size)
		if err == nil {
			return alloc, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", strategy.Name(), err))
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("%s: no allocation strategies configured", m.Name())
	}
	return nil, fmt.Errorf("%s: %s", m.Name(), strings.Join(errs, "; "))
}
func (m fallbackMemoryStrategy) Name() string {
	if m.name == "" {
		return "fallback"
	}
	return m.name
}

type sliceAllocation struct {
	name string
	buf  []byte
	free func() error
}

func (a *sliceAllocation) Bytes() []byte { return a.buf }
func (a *sliceAllocation) Name() string  { return a.name }
func (a *sliceAllocation) Free() error {
	if a == nil || a.free == nil {
		return nil
	}
	return a.free()
}

type GoHeapMemory struct{}

func (GoHeapMemory) Alloc(size uint64) (cx.Allocation, error) {
	return &sliceAllocation{name: "go-heap", buf: make([]byte, size)}, nil
}
func (GoHeapMemory) Name() string                { return "go-heap" }
func (GoHeapMemory) ValidationCanReuseDAG() bool { return true }

type PinnedMemory struct{}

func (PinnedMemory) Alloc(size uint64) (cx.Allocation, error) { return allocPinnedHost(size) }
func (PinnedMemory) Name() string                             { return "pinned-host" }
func (PinnedMemory) ValidationCanReuseDAG() bool              { return true }

type CUDAManagedMemory struct {
	DeviceOrdinal int
	Ready         bool
}

func (m CUDAManagedMemory) Alloc(size uint64) (cx.Allocation, error) {
	if !m.Ready {
		return nil, fmt.Errorf("cuda managed allocation requires initialized runtime/device")
	}
	return allocCUDAManaged(m.DeviceOrdinal, size)
}
func (CUDAManagedMemory) Name() string                  { return "cuda-managed" }
func (m CUDAManagedMemory) ValidationCanReuseDAG() bool { return m.Ready }

type OpenCLSVM struct{ Context OpenCLContext }

func (m OpenCLSVM) Alloc(size uint64) (cx.Allocation, error) {
	if !m.Context.valid() {
		return nil, fmt.Errorf("opencl svm requires a live OpenCL context and device")
	}
	return allocOpenCLSVM(m.Context, size)
}
func (OpenCLSVM) Name() string                  { return "opencl-svm" }
func (m OpenCLSVM) ValidationCanReuseDAG() bool { return m.Context.valid() }

type MetalSharedMemory struct{ Context MetalContext }

func (m MetalSharedMemory) Alloc(size uint64) (cx.Allocation, error) {
	if m.Context.Device == nil {
		return nil, fmt.Errorf("metal shared allocation requires initialized runtime/device")
	}
	return &sliceAllocation{name: "metal-shared", buf: make([]byte, size)}, nil
}
func (MetalSharedMemory) Name() string                  { return "metal-shared" }
func (m MetalSharedMemory) ValidationCanReuseDAG() bool { return m.Context.Device != nil }

type notImplementedError string

func (e notImplementedError) Error() string { return "not implemented: " + string(e) }
func ErrNotImplemented(s string) error      { return notImplementedError(s) }

func ResolveDAGStrategy(backend BackendMode, runtime runtimeState, dagAlloc string) (MemoryStrategy, error) {
	return ResolveDAGStrategyForMode(cx.ModeColossusX, backend, runtime, dagAlloc)
}
func ResolveDAGStrategyForMode(mode cx.Mode, backend BackendMode, runtime runtimeState, dagAlloc string) (MemoryStrategy, error) {
	return dagStrategyResolver{mode: mode, backend: backend, runtime: runtime}.Resolve(dagAlloc)
}
func selectDAGStrategy(backend BackendMode, dagAlloc string) (MemoryStrategy, error) {
	return ResolveDAGStrategy(backend, nil, dagAlloc)
}
func (r dagStrategyResolver) Resolve(dagAlloc string) (MemoryStrategy, error) {
	choice := strings.ToLower(strings.TrimSpace(dagAlloc))
	if choice == "" {
		choice = "auto"
	}
	if r.mode == "" || r.mode == cx.ModeColossusX {
		return r.resolveColossusX(choice)
	}
	return nil, fmt.Errorf("unsupported mode %q", r.mode)
}
func (r dagStrategyResolver) resolveColossusX(choice string) (MemoryStrategy, error) {
	if choice == "auto" {
		s := r.autoColossusXStrategies()
		return fallbackMemoryStrategy{name: "auto", strategies: s}, nil
	}
	switch choice {
	case "go", "go-heap":
		return GoHeapMemory{}, nil
	case "pinned", "pinned-host":
		return PinnedMemory{}, nil
	case "cuda-managed":
		if o, ok := r.cudaDeviceOrdinal(); ok {
			return CUDAManagedMemory{DeviceOrdinal: o, Ready: true}, nil
		}
	case "opencl-svm":
		if c, ok := r.openclContext(); ok {
			return OpenCLSVM{Context: c}, nil
		}
	case "metal-shared":
		if c, ok := r.metalContext(); ok {
			return MetalSharedMemory{Context: c}, nil
		}
	}
	return nil, fmt.Errorf("colossusx mode requires one of: auto, go-heap, pinned-host, cuda-managed, opencl-svm, metal-shared")
}
func (r dagStrategyResolver) autoColossusXStrategies() []MemoryStrategy {
	strategies := make([]MemoryStrategy, 0, 4)
	if o, ok := r.cudaDeviceOrdinal(); ok {
		strategies = append(strategies, CUDAManagedMemory{DeviceOrdinal: o, Ready: true})
	}
	if c, ok := r.openclContext(); ok {
		strategies = append(strategies, OpenCLSVM{Context: c})
	}
	if c, ok := r.metalContext(); ok {
		strategies = append(strategies, MetalSharedMemory{Context: c})
	}
	strategies = append(strategies, GoHeapMemory{})
	return strategies
}
func (r dagStrategyResolver) cudaDeviceOrdinal() (int, bool) {
	if r.runtime == nil {
		return 0, false
	}
	return r.runtime.CUDADeviceOrdinal()
}
func (r dagStrategyResolver) openclContext() (OpenCLContext, bool) {
	if r.runtime == nil {
		return OpenCLContext{}, false
	}
	return r.runtime.OpenCLContext()
}
func (r dagStrategyResolver) metalContext() (MetalContext, bool) {
	if r.runtime == nil {
		return MetalContext{}, false
	}
	return r.runtime.MetalContext()
}
