package miner

import (
	"fmt"
	"strings"

	cx "colossusx/colossusx"
)

func ValidateColossusXProductionConfig(mode cx.Mode, backend BackendMode, dagAlloc string) error {
	if mode != "" && mode != cx.ModeColossusX {
		return nil
	}
	alloc := strings.ToLower(strings.TrimSpace(dagAlloc))
	if alloc == "" {
		alloc = "auto"
	}
	switch backend {
	case BackendCPU, BackendUnified, BackendGPU, BackendCUDA, BackendOpenCL, BackendMetal:
	default:
		return fmt.Errorf("unsupported colossusx backend %q", backend)
	}
	switch alloc {
	case "auto", "go-heap", "pinned-host", "cuda-managed", "opencl-svm", "metal-shared":
	default:
		return fmt.Errorf("colossusx production disallows dag allocator %q (allowed: auto, go-heap, pinned-host, cuda-managed, opencl-svm, metal-shared)", dagAlloc)
	}
	switch backend {
	case BackendCPU:
		if alloc != "auto" && alloc != "go-heap" && alloc != "pinned-host" {
			return fmt.Errorf("cpu backend requires auto, go-heap, or pinned-host dag allocator")
		}
	case BackendCUDA:
		if alloc == "opencl-svm" || alloc == "metal-shared" {
			return fmt.Errorf("cuda backend requires auto or cuda-managed dag allocator")
		}
	case BackendOpenCL:
		if alloc == "cuda-managed" || alloc == "metal-shared" {
			return fmt.Errorf("opencl backend requires auto or opencl-svm dag allocator")
		}
	case BackendMetal:
		if alloc == "cuda-managed" || alloc == "opencl-svm" {
			return fmt.Errorf("metal backend requires auto or metal-shared dag allocator")
		}
	case BackendUnified:
		if alloc != "auto" {
			return fmt.Errorf("unified backend requires auto dag allocator in colossusx production")
		}
	}
	return nil
}
