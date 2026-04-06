package colossusx

import "golang.org/x/crypto/sha3"

func keccak512(data []byte) [64]byte {
	var out [64]byte
	h := sha3.NewLegacyKeccak512()
	_, _ = h.Write(data)
	h.Sum(out[:0])
	return out
}
