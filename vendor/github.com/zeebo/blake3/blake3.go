package blake3

import "golang.org/x/crypto/blake2b"

func Sum256(data []byte) (out [32]byte) {
	return blake2b.Sum256(data)
}

func Sum512(data []byte) (out [64]byte) {
	return blake2b.Sum512(data)
}
