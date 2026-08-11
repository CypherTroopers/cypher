// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"encoding/hex"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

const (
	entityReplayDomainDigestDomain = "CPH-AIIE-IAM-ENTITY-REPLAY-DOMAIN-V1\x00"
	entityReplayDomainPrefix       = "cph-iam-replay-v1:sha256:"
)

// DeriveEntityReplayDomainID returns the collision-resistant replay namespace
// for one IAM mutation target. The base namespace is deployment policy; the
// target binding prevents CounterExpectedGeneration values from colliding
// across independent identities, keys, or ownership transfers.
//
// digest = SHA256("CPH-AIIE-IAM-ENTITY-REPLAY-DOMAIN-V1\x00" ||
//
//	CCSE(base, entity-kind, principal-kind, entity-id))
func DeriveEntityReplayDomainID(base string, entity EntityRef) (string, error) {
	if base == "" || entity.Kind < EntityIdentity || entity.Kind > EntityOwnershipTransfer ||
		entity.PrincipalKind < 1 || entity.PrincipalKind > 8 || entity.ID == "" {
		return "", ErrAuthorizationMismatch
	}
	encoded, err := ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.String(base)
		out.Uint32(uint32(entity.Kind))
		out.Uint32(entity.PrincipalKind)
		out.String(entity.ID)
	})
	if err != nil {
		return "", ErrAuthorizationMismatch
	}
	digest := domainDigest(entityReplayDomainDigestDomain, encoded)
	return entityReplayDomainPrefix + hex.EncodeToString(digest[:]), nil
}
