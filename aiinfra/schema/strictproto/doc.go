// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package strictproto provides bounded, descriptor-driven validation for
// Protobuf transport bytes before they are unmarshaled.
//
// This package is deliberately unrelated to signing serialization. Validated
// Protobuf messages must still be translated into the independently defined
// CCSE signing projections before authorization or signature verification.
// Only linked proto3 descriptors are accepted; maps, groups, weak fields, and
// extension ranges are rejected because the CPH AIIE schemas intentionally do
// not use their merge or extension semantics.
package strictproto
