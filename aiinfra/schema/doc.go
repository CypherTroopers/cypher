// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package schema owns the CPH AI Infrastructure Extension schema registry.
//
// Protobuf files embedded by this package define transport and data-model
// messages. The independently versioned registry defines the exact ordered
// CCSE-v1 signing projection. Code must never substitute Protobuf wire bytes
// for a registry projection.
package schema

//go:generate ./scripts/generate.sh
