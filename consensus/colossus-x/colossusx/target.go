package colossusx

import (
	"encoding/hex"
	"fmt"
)

type Target [32]byte

func ParseTargetHex(s string) (Target, error) {
	var t Target
	b, err := hex.DecodeString(s)
	if err != nil {
		return t, err
	}
	if len(b) != len(t) {
		return t, fmt.Errorf("target must be exactly %d bytes, got %d", len(t), len(b))
	}
	copy(t[:], b)
	return t, nil
}

func (t Target) String() string { return hex.EncodeToString(t[:]) }

func LessOrEqualBE(a [32]byte, b Target) bool {
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true
}
