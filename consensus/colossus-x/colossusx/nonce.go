package colossusx

import (
	"encoding/binary"
	"fmt"
)

// Nonce abstracts the seed-domain input used by lattice hashing.
//
// Current mining still uses uint64-backed nonces, but the interface is kept
// narrow so a future 256-bit nonce implementation can participate in hashing,
// formatting, and simple range stepping without rewriting the hash pipeline.
type Nonce interface {
	AppendTo(dst []byte) []byte
	AddUint64(delta uint64) (Nonce, bool)
	String() string
}

type Uint64Nonce uint64

func NewUint64Nonce(v uint64) Uint64Nonce { return Uint64Nonce(v) }

func (n Uint64Nonce) Uint64() uint64 { return uint64(n) }

func (n Uint64Nonce) AppendTo(dst []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, 8)...)
	binary.LittleEndian.PutUint64(dst[start:], uint64(n))
	return dst
}

func (n Uint64Nonce) AddUint64(delta uint64) (Nonce, bool) {
	if ^uint64(0)-uint64(n) < delta {
		return nil, false
	}
	return Uint64Nonce(uint64(n) + delta), true
}

func (n Uint64Nonce) String() string { return fmt.Sprintf("%d", uint64(n)) }
