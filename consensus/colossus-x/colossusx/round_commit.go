package colossusx

import "crypto/sha256"

func RoundCommit(round uint32, state [32]byte) [32]byte {
	var in [36]byte
	copy(in[:32], state[:])
	in[32] = byte(round)
	in[33] = byte(round >> 8)
	in[34] = byte(round >> 16)
	in[35] = byte(round >> 24)
	return sha256.Sum256(in[:])
}
