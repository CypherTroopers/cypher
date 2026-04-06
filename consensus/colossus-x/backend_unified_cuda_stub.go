//go:build !cuda || !cgo

package miner

func currentCUDADeviceOrdinal() (int, error) {
	return 0, ErrNotImplemented("cuda managed memory requires a cgo + cuda build")
}

func allocCUDAManaged(deviceOrdinal int, size uint64) (managedAllocation, error) {
	_, _ = deviceOrdinal, size
	return nil, ErrNotImplemented("cuda managed memory requires a cgo + cuda build")
}
