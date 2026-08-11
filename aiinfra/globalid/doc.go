// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package globalid defines the deployment-wide identifier ownership contract
// used by CPH AI Infrastructure Extension state planners. Identifier strings
// are unique without a kind namespace: the owner domain is stored as binding
// metadata and can never make the same identifier valid twice.
package globalid
