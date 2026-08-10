// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package ccse implements CPH Canonical Signing Encoding version 1.
//
// CCSE is deliberately independent from the transport representation. Protobuf
// messages are projected into the explicit, schema-ordered encoders in this
// package before they are signed. The package never canonicalizes a Protobuf
// wire message, JSON object, map, floating-point value, or host-native integer.
//
// The implementation is shared by the CPH AI Infrastructure Extension services
// but has no dependency on validator, GPU, database, or transport packages.
package ccse
