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
    #define cudaHostAllocPortable 0
    static void* colossusx_cuda_host_alloc(size_t size, const char **errstr) { (void)size; *errstr = "cuda headers were not found at build time"; return NULL; }
    static cudaError_t cudaFreeHost(void *ptr) { (void)ptr; return cudaSuccess; }
    static const char* cudaGetErrorString(cudaError_t err) { (void)err; return "cuda headers were not found at build time"; }
#else
    static void* colossusx_cuda_host_alloc(size_t size, const char **errstr) {
        void *ptr = NULL;
        cudaError_t err = cudaHostAlloc(&ptr, size, cudaHostAllocPortable);
        if (err != cudaSuccess) {
            *errstr = cudaGetErrorString(err);
            return NULL;
        }
        *errstr = NULL;
        return ptr;
    }
#endif
*/
import "C"
import (
	"fmt"
	"unsafe"

	cx "colossusx/colossusx"
)

func allocPinnedHost(size uint64) (cx.Allocation, error) {
	var errStr *C.char
	ptr := C.colossusx_cuda_host_alloc(C.size_t(size), (**C.char)(unsafe.Pointer(&errStr)))
	if errStr != nil {
		return nil, fmt.Errorf("cudaHostAlloc(%d): %s", size, C.GoString(errStr))
	}
	buf := unsafe.Slice((*byte)(ptr), int(size))
	return &sliceAllocation{
		name: "pinned-host",
		buf:  buf,
		free: func() error {
			if err := C.cudaFreeHost(ptr); err != C.cudaSuccess {
				return fmt.Errorf("cudaFreeHost: %s", C.GoString(C.cudaGetErrorString(err)))
			}
			return nil
		},
	}, nil
}
