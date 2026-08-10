// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package strictproto

import (
	"testing"

	"google.golang.org/protobuf/types/dynamicpb"
)

func FuzzPreflightNeverPanics(f *testing.F) {
	descriptor := strictTestDescriptor(f)
	limits := testLimits()
	limits.MaxMessageBytes = 512
	limits.MaxFieldBytes = 256
	f.Add([]byte(nil))
	f.Add(wireVarintField(1, 1))
	f.Add(wireBytesField(6, wireVarintField(1, 7)))
	f.Add([]byte{0x08, 0x81, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Preflight(data, descriptor, limits)
	})
}

func FuzzStrictUnmarshalNeverPanics(f *testing.F) {
	descriptor := strictTestDescriptor(f)
	limits := testLimits()
	limits.MaxMessageBytes = 512
	limits.MaxFieldBytes = 256
	f.Add([]byte(nil))
	f.Add(appendFields(wireBytesField(11, []byte("valid")), wireVarintField(1, 1)))
	f.Add(wireBytesField(1, []byte{1, 2, 3}))
	f.Fuzz(func(t *testing.T, data []byte) {
		target := dynamicpb.NewMessage(descriptor)
		_ = Unmarshal(data, target, descriptor, limits)
	})
}
