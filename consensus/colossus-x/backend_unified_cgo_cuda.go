//go:build cgo && cuda

package miner

/*
#cgo LDFLAGS: -lcudart
#include <stdlib.h>
#if defined(__has_include)
#  if __has_include(<cuda_runtime.h>)
#    include <cuda_runtime.h>
#    define COLOSSUSX_HAVE_CUDA_HEADERS 1
#  endif
#endif
#ifndef COLOSSUSX_HAVE_CUDA_HEADERS
    typedef int cudaError_t;
    #define cudaSuccess 0
    #define cudaMemAttachGlobal 0
    #define cudaMemAdviseSetPreferredLocation 0
    static const char* colossusx_cuda_missing_headers(void) { return "cuda headers were not found at build time"; }
    static void* colossusx_cuda_malloc_managed(size_t size, const char **errstr) { (void)size; *errstr = "cuda headers were not found at build time"; return NULL; }
    static const char* colossusx_cuda_mem_advise(void *ptr, size_t size, int advice, int device) { (void)ptr; (void)size; (void)advice; (void)device; return "cuda headers were not found at build time"; }
    static const char* colossusx_cuda_prefetch(void *ptr, size_t size, int device) { (void)ptr; (void)size; (void)device; return "cuda headers were not found at build time"; }
    static const char* colossusx_cuda_get_device(int *device) { (void)device; return "cuda headers were not found at build time"; }
    static cudaError_t cudaFree(void *ptr) { (void)ptr; return cudaSuccess; }
    static const char* cudaGetErrorString(cudaError_t err) { (void)err; return "cuda headers were not found at build time"; }
#else
    static const char* colossusx_cuda_missing_headers(void) { return NULL; }
    static void* colossusx_cuda_malloc_managed(size_t size, const char **errstr) {
        void *ptr = NULL;
        cudaError_t err = cudaMallocManaged(&ptr, size, cudaMemAttachGlobal);
        if (err != cudaSuccess) {
            *errstr = cudaGetErrorString(err);
            return NULL;
        }
        *errstr = NULL;
        return ptr;
    }
    static const char* colossusx_cuda_mem_advise(void *ptr, size_t size, int advice, int device) {
        cudaError_t err = cudaMemAdvise(ptr, size, advice, device);
        if (err != cudaSuccess) return cudaGetErrorString(err);
        return NULL;
    }
    static const char* colossusx_cuda_prefetch(void *ptr, size_t size, int device) {
        cudaError_t err = cudaMemPrefetchAsync(ptr, size, device, 0);
        if (err != cudaSuccess) return cudaGetErrorString(err);
        err = cudaDeviceSynchronize();
        if (err != cudaSuccess) return cudaGetErrorString(err);
        return NULL;
    }
    static const char* colossusx_cuda_get_device(int *device) {
        cudaError_t err = cudaGetDevice(device);
        if (err != cudaSuccess) return cudaGetErrorString(err);
        return NULL;
    }
#endif
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func currentCUDADeviceOrdinal() (int, error) {
	if errStr := C.colossusx_cuda_missing_headers(); errStr != nil {
		return 0, fmt.Errorf("%s", C.GoString(errStr))
	}
	var device C.int
	if errStr := C.colossusx_cuda_get_device(&device); errStr != nil {
		return 0, fmt.Errorf("%s", C.GoString(errStr))
	}
	return int(device), nil
}

func allocCUDAManaged(deviceOrdinal int, size uint64) (managedAllocation, error) {
	if errStr := C.colossusx_cuda_missing_headers(); errStr != nil {
		return nil, fmt.Errorf("%s", C.GoString(errStr))
	}
	var errStr *C.char
	ptr := C.colossusx_cuda_malloc_managed(C.size_t(size), (**C.char)(unsafe.Pointer(&errStr)))
	if errStr != nil {
		return nil, fmt.Errorf("cudaMallocManaged(%d): %s", size, C.GoString(errStr))
	}
	buf := unsafe.Slice((*byte)(ptr), int(size))
	_ = C.colossusx_cuda_mem_advise(ptr, C.size_t(size), C.int(C.cudaMemAdviseSetPreferredLocation), C.int(deviceOrdinal))
	_ = C.colossusx_cuda_prefetch(ptr, C.size_t(size), C.int(deviceOrdinal))
	return &sliceAllocation{
		name: "cuda-managed",
		buf:  buf,
		free: func() error {
			if err := C.cudaFree(ptr); err != C.cudaSuccess {
				return fmt.Errorf("cudaFree: %s", C.GoString(C.cudaGetErrorString(err)))
			}
			return nil
		},
	}, nil
}
