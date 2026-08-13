// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import "github.com/cypherium/cypher/aiinfra/ccse"

const enrollmentBindingDomain = "CPH-AIIE-IAM-ENROLLMENT-BINDING-V1\x00"

func enrollmentBindingDigest(material KeyMaterialSnapshot) ([32]byte, error) {
	var zero [32]byte
	policies, err := canonicalDigests(material.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return zero, err
	}
	elements, err := encodedDigestSet(policies)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(32768, func(out *ccse.Encoder) {
		out.String(material.KeyID)
		out.String(material.SubjectIdentity)
		out.Uint32(material.SubjectKind)
		out.Uint32(uint32(material.TargetIdentity.Kind))
		out.Uint32(material.TargetIdentity.PrincipalKind)
		out.String(material.TargetIdentity.ID)
		out.FixedBytes(material.TransferEvidenceDigest[:], 32)
		out.String(material.EnrollmentDomain.EnrollmentDomainID)
		out.String(material.EnrollmentDomain.Environment)
		out.FixedBytes(material.EnrollmentDomain.GenesisHash[:], 32)
		out.FixedBytes(material.ProofDigest[:], 32)
		out.FixedBytes(material.ChallengeEvidenceDigest[:], 32)
		out.String(material.EnrollmentAuthorityIdentity)
		out.EncodedSet(elements)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(enrollmentBindingDomain, encoded), nil
}

// KeyMaterialEnrollmentBindingDigest derives the frozen v1 enrollment
// commitment for explicit audited bootstrap writers. The returned digest is
// not authority by itself; NewKeyMaterialSemanticProjectionV2 subsequently
// validates PoP, key ID, deployment anchors and every retained scalar.
func KeyMaterialEnrollmentBindingDigest(material KeyMaterialSnapshot) ([32]byte, error) {
	return enrollmentBindingDigest(cloneKeyMaterial(material))
}
