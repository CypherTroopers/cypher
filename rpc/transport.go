package rpc

import "context"

type transportContextKey struct{}
type transportKind uint8

const (
	transportUnknown transportKind = iota
	transportNetwork
	transportIPC
	transportInProc
)

// IsIPC reports whether the server accepted this request on a local OS IPC
// connection. HTTP headers, peer addresses and client contexts cannot set it.
func IsIPC(ctx context.Context) bool {
	return ctx.Value(transportContextKey{}) == transportIPC
}

// IsLocal also accepts a trusted in-process connection. It must not be used for
// APIs whose contract specifically requires IPC.
func IsLocal(ctx context.Context) bool {
	kind := ctx.Value(transportContextKey{})
	return kind == transportIPC || kind == transportInProc
}

// Only transport entrypoints in this package can attach the authenticated mark.
type transportCodec struct {
	ServerCodec
	kind transportKind
}
