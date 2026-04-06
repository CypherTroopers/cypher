//go:build !cuda || !cgo

package miner

import cx "colossusx/colossusx"

func allocPinnedHost(size uint64) (cx.Allocation, error) {
	return &sliceAllocation{name: "pinned-host", buf: make([]byte, size)}, nil
}
