//go:build !opencl || !cgo

package miner

import (
	"fmt"
	"unsafe"
)

type OpenCLContext struct {
	Context any
	Device  any
	Queue   any
	Program any
	Kernel  any
	Flags   uint64
}

func (c OpenCLContext) valid() bool {
	return c.Context != nil && c.Device != nil
}

type openclRuntime interface {
	runtimeState
	Initialize() error
	Available() bool
	SupportsSVM() bool
}

type stubOpenCLRuntime struct{}

func newOpenCLRuntime() openclRuntime { return stubOpenCLRuntime{} }
func (stubOpenCLRuntime) Initialize() error {
	return ErrNotImplemented("opencl svm requires a cgo + opencl build")
}
func (stubOpenCLRuntime) Available() bool                { return false }
func (stubOpenCLRuntime) SupportsSVM() bool              { return false }
func (stubOpenCLRuntime) CUDADeviceOrdinal() (int, bool) { return 0, false }
func (stubOpenCLRuntime) OpenCLContext() (OpenCLContext, bool) {
	return OpenCLContext{}, false
}
func (stubOpenCLRuntime) MetalContext() (MetalContext, bool) { return MetalContext{}, false }
func (stubOpenCLRuntime) SetContext(OpenCLContext)           {}

func allocOpenCLSVM(ctx OpenCLContext, size uint64) (managedAllocation, error) {
	_, _ = ctx, size
	return nil, ErrNotImplemented("opencl svm requires a cgo + opencl build")
}

func buildOpenCLProgram(ctx OpenCLContext, source string) (OpenCLContext, error) {
	if !ctx.valid() {
		return OpenCLContext{}, fmt.Errorf("opencl build helpers require a live context")
	}
	if source == "" {
		return OpenCLContext{}, fmt.Errorf("opencl build helpers require kernel source")
	}
	ctx.Program = struct{}{}
	ctx.Kernel = struct{}{}
	return ctx, nil
}

func setOpenCLSVMKernelArg(ctx OpenCLContext, index uint32, ptr unsafe.Pointer) error {
	if ctx.Kernel == nil {
		return fmt.Errorf("opencl svm arg helpers require a built kernel")
	}
	if index != 0 {
		return fmt.Errorf("opencl svm arg helpers only stub argument 0")
	}
	if ptr == nil {
		return fmt.Errorf("opencl svm arg helpers require a non-nil DAG pointer")
	}
	return nil
}
