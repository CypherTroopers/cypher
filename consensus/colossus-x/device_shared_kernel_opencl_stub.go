//go:build !(cgo && opencl)

package miner

func newOpenCLSharedAllocationKernel() openCLSharedAllocationKernel { return nil }
