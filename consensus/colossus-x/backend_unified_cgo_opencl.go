//go:build cgo && opencl

package miner

/*
#cgo LDFLAGS: -lOpenCL
#include <stdlib.h>
#if defined(__has_include)
#  if __has_include(<CL/opencl.h>)
#    include <CL/opencl.h>
#    define COLOSSUSX_HAVE_OPENCL_HEADERS 1
#  endif
#endif
#ifndef COLOSSUSX_HAVE_OPENCL_HEADERS
    typedef void* cl_context;
    typedef void* cl_device_id;
    typedef void* cl_command_queue;
    typedef void* cl_program;
    typedef void* cl_kernel;
    typedef unsigned long cl_svm_mem_flags;
    typedef unsigned long cl_device_svm_capabilities;
    typedef int cl_int;
    typedef unsigned int cl_uint;
    typedef unsigned long cl_ulong;
    #define CL_SUCCESS 0
    #define CL_DEVICE_SVM_CAPABILITIES 0
    #define CL_DEVICE_SVM_COARSE_GRAIN_BUFFER 0
    #define CL_DEVICE_SVM_FINE_GRAIN_BUFFER 0
    static int colossusx_missing_opencl_headers(void) { return 1; }
    static const char* colossusx_opencl_init(cl_context *ctx, cl_device_id *dev, cl_command_queue *queue) { (void)ctx; (void)dev; (void)queue; return "opencl headers were not found at build time"; }
    static const char* colossusx_opencl_build_program(cl_context ctx, cl_device_id dev, const char *src, cl_program *program, cl_kernel *kernel) { (void)ctx; (void)dev; (void)src; (void)program; (void)kernel; return "opencl headers were not found at build time"; }
    static int colossusx_has_svm(cl_device_id device) { (void)device; return 0; }
    static void* colossusx_svm_alloc(cl_context context, cl_svm_mem_flags flags, size_t size) { (void)context; (void)flags; (void)size; return NULL; }
    static void colossusx_svm_free(cl_context context, void *ptr) { (void)context; (void)ptr; }
    static const char* colossusx_opencl_set_svm_arg(cl_kernel kernel, cl_uint index, const void *ptr) { (void)kernel; (void)index; (void)ptr; return "opencl headers were not found at build time"; }
#else
    static int colossusx_missing_opencl_headers(void) { return 0; }
    static const char* colossusx_opencl_init(cl_context *ctx, cl_device_id *dev, cl_command_queue *queue) {
        cl_platform_id platform = NULL;
        cl_uint numPlatforms = 0;
        cl_int err = clGetPlatformIDs(1, &platform, &numPlatforms);
        if (err != CL_SUCCESS || numPlatforms == 0) return "clGetPlatformIDs failed";
        err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, dev, NULL);
        if (err != CL_SUCCESS) return "clGetDeviceIDs failed";
        *ctx = clCreateContext(NULL, 1, dev, NULL, NULL, &err);
        if (err != CL_SUCCESS || *ctx == NULL) return "clCreateContext failed";
        *queue = clCreateCommandQueueWithProperties(*ctx, *dev, NULL, &err);
        if (err != CL_SUCCESS || *queue == NULL) return "clCreateCommandQueueWithProperties failed";
        return NULL;
    }
    static const char* colossusx_opencl_build_program(cl_context ctx, cl_device_id dev, const char *src, cl_program *program, cl_kernel *kernel) {
        cl_int err = CL_SUCCESS;
        *program = clCreateProgramWithSource(ctx, 1, &src, NULL, &err);
        if (err != CL_SUCCESS || *program == NULL) return "clCreateProgramWithSource failed";
        err = clBuildProgram(*program, 1, &dev, NULL, NULL, NULL);
        if (err != CL_SUCCESS) return "clBuildProgram failed";
        *kernel = clCreateKernel(*program, "colossusx_hash", &err);
        if (err != CL_SUCCESS || *kernel == NULL) return "clCreateKernel failed";
        return NULL;
    }
    static int colossusx_has_svm(cl_device_id device) {
        cl_device_svm_capabilities caps = 0;
        cl_int err = clGetDeviceInfo(device, CL_DEVICE_SVM_CAPABILITIES, sizeof(caps), &caps, NULL);
        if (err != CL_SUCCESS) return 0;
        return (caps & (CL_DEVICE_SVM_COARSE_GRAIN_BUFFER | CL_DEVICE_SVM_FINE_GRAIN_BUFFER)) != 0;
    }
    static void* colossusx_svm_alloc(cl_context context, cl_svm_mem_flags flags, size_t size) { return clSVMAlloc(context, flags, size, 0); }
    static void colossusx_svm_free(cl_context context, void *ptr) { clSVMFree(context, ptr); }
    static const char* colossusx_opencl_set_svm_arg(cl_kernel kernel, cl_uint index, const void *ptr) {
        cl_int err = clSetKernelArgSVMPointer(kernel, index, ptr);
        if (err != CL_SUCCESS) return "clSetKernelArgSVMPointer failed";
        return NULL;
    }
#endif
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type OpenCLContext struct {
	Context unsafe.Pointer
	Device  unsafe.Pointer
	Queue   unsafe.Pointer
	Program unsafe.Pointer
	Kernel  unsafe.Pointer
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

type nativeOpenCLRuntime struct {
	ctx         OpenCLContext
	available   bool
	initialized bool
	initErr     error
}

func newOpenCLRuntime() openclRuntime { return &nativeOpenCLRuntime{} }

func (r *nativeOpenCLRuntime) Initialize() error {
	if r.initialized {
		return r.initErr
	}
	r.initialized = true
	if C.colossusx_missing_opencl_headers() != 0 {
		r.initErr = fmt.Errorf("opencl headers were not found at build time")
		return r.initErr
	}
	var ctx C.cl_context
	var dev C.cl_device_id
	var queue C.cl_command_queue
	if err := C.colossusx_opencl_init(&ctx, &dev, &queue); err != nil {
		r.initErr = fmt.Errorf("%s", C.GoString(err))
		return r.initErr
	}
	r.ctx = OpenCLContext{Context: unsafe.Pointer(ctx), Device: unsafe.Pointer(dev), Queue: unsafe.Pointer(queue), Flags: 0}
	r.available = true
	return nil
}

func (r *nativeOpenCLRuntime) Available() bool { return r.available }
func (r *nativeOpenCLRuntime) SupportsSVM() bool {
	return r.available && C.colossusx_has_svm(C.cl_device_id(r.ctx.Device)) != 0
}
func (r *nativeOpenCLRuntime) CUDADeviceOrdinal() (int, bool) { return 0, false }
func (r *nativeOpenCLRuntime) OpenCLContext() (OpenCLContext, bool) {
	return r.ctx, r.available
}

func (r *nativeOpenCLRuntime) SetContext(ctx OpenCLContext) {
	r.ctx = ctx
}

func allocOpenCLSVM(ctx OpenCLContext, size uint64) (managedAllocation, error) {
	if C.colossusx_missing_opencl_headers() != 0 {
		return nil, fmt.Errorf("opencl headers were not found at build time")
	}
	if !ctx.valid() {
		return nil, fmt.Errorf("opencl svm requires a live OpenCL context and device")
	}
	device := C.cl_device_id(ctx.Device)
	if C.colossusx_has_svm(device) == 0 {
		return nil, fmt.Errorf("opencl device does not advertise SVM support")
	}
	ptr := C.colossusx_svm_alloc(C.cl_context(ctx.Context), C.cl_svm_mem_flags(ctx.Flags), C.size_t(size))
	if ptr == nil {
		return nil, fmt.Errorf("clSVMAlloc(%d) returned NULL", size)
	}
	buf := unsafe.Slice((*byte)(ptr), int(size))
	return &sliceAllocation{
		name: "opencl-svm",
		buf:  buf,
		free: func() error {
			C.colossusx_svm_free(C.cl_context(ctx.Context), ptr)
			return nil
		},
	}, nil
}

func buildOpenCLProgram(ctx OpenCLContext, source string) (OpenCLContext, error) {
	csrc := C.CString(source)
	defer C.free(unsafe.Pointer(csrc))
	var program C.cl_program
	var kernel C.cl_kernel
	if err := C.colossusx_opencl_build_program(C.cl_context(ctx.Context), C.cl_device_id(ctx.Device), csrc, &program, &kernel); err != nil {
		return OpenCLContext{}, fmt.Errorf("%s", C.GoString(err))
	}
	ctx.Program = unsafe.Pointer(program)
	ctx.Kernel = unsafe.Pointer(kernel)
	return ctx, nil
}

func setOpenCLSVMKernelArg(ctx OpenCLContext, index uint32, ptr unsafe.Pointer) error {
	if err := C.colossusx_opencl_set_svm_arg(C.cl_kernel(ctx.Kernel), C.cl_uint(index), ptr); err != nil {
		return fmt.Errorf("%s", C.GoString(err))
	}
	return nil
}
