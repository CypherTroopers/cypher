//go:build !cuda

package miner

func NewCUDABackend() (HashBackend, error) { return &CUDACompatBackend{}, nil }

type CUDACompatBackend struct{ GPUBackend }

func (b *CUDACompatBackend) Mode() BackendMode { return BackendCUDA }
