// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"crypto/sha256"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	transferCollectionDigestDomain  = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-COLLECTION-V1\x00"
	acceptedTransferDigestDomain    = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-ACCEPTED-V1\x00"
	transferCollectionPlanDomain    = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-COLLECTION-PLAN-V1\x00"
	transferReceiverProfileDomain   = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-RECEIVER-PROFILE-V1\x00"
	transferEvidenceDecisionDomain  = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-EVIDENCE-DECISION-V1\x00"
	transferEvidenceAdmissionDomain = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-EVIDENCE-ADMISSION-V1\x00"
)

func canonicalReceiverProfile(receiver ReceiverProfile) ([]byte, error) {
	if err := validateReceiverProfile(receiver); err != nil {
		return nil, ErrTransferAuthorizationRequired
	}
	audience := make([][]byte, len(receiver.Audience))
	for index, value := range receiver.Audience {
		encoded, err := ccse.Marshal(2048, func(out *ccse.Encoder) { out.String(value) })
		if err != nil {
			return nil, ErrTransferAuthorizationRequired
		}
		audience[index] = encoded
	}
	return ccse.Marshal(128<<10, func(out *ccse.Encoder) {
		out.Uint32(receiver.ProtocolVersion.Major)
		out.Uint32(receiver.ProtocolVersion.Minor)
		out.Uint32(receiver.SchemaVersion.Major)
		out.Uint32(receiver.SchemaVersion.Minor)
		out.String(receiver.Purpose)
		out.EncodedSet(audience)
		out.OptionalString(receiver.TenantOrganization.Present, receiver.TenantOrganization.Value)
		out.OptionalString(receiver.ProviderOrganization.Present, receiver.ProviderOrganization.Value)
		out.String(receiver.Environment)
		out.String(receiver.EnrollmentDomainID)
		out.FixedBytes(receiver.ChainID[:], 32)
		out.FixedBytes(receiver.GenesisHash[:], 32)
		out.String(receiver.ReplayDomainID)
		out.Uint32(uint32(receiver.CounterKind))
		out.Int64(receiver.MaxClockSkewNanos)
		out.Int64(receiver.MaxValidityWindowNanos)
		out.Int64(receiver.MaxPlanCommitLatencyNanos)
	})
}

func receiverProfileDigest(receiver ReceiverProfile) ([32]byte, error) {
	var zero [32]byte
	encoded, err := canonicalReceiverProfile(receiver)
	if err != nil {
		return zero, err
	}
	return domainDigest(transferReceiverProfileDomain, encoded), nil
}

func canonicalRetainedRecord(record RetainedVerifiedRecord) ([]byte, error) {
	digest, err := record.record.Digest(ccse.DefaultLimits())
	if err != nil || digest != record.digest || digest == ([32]byte{}) {
		return nil, ErrTransferAuthorizationRequired
	}
	signed, err := canonicalSignedAuthorizationEvidence(record.record)
	if err != nil {
		return nil, ErrTransferAuthorizationRequired
	}
	return ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.FixedBytes(record.digest[:], 32)
		out.Bytes(signed)
	})
}

func canonicalMaterialSnapshot(material KeyMaterialSnapshot) ([]byte, error) {
	material, err := validateMaterialSnapshot(material)
	if err != nil {
		return nil, err
	}
	policies, err := encodedDigestSet(material.EnrollmentPolicyDigestsSHA256)
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(128<<10, func(out *ccse.Encoder) {
		out.String(material.KeyID)
		out.Uint32(uint32(material.Algorithm))
		out.Bytes(material.CanonicalPublicKey)
		out.String(material.SubjectIdentity)
		out.Uint32(material.SubjectKind)
		encodeEntity(out, material.TargetIdentity)
		out.FixedBytes(material.TransferEvidenceDigest[:], 32)
		out.String(material.EnrollmentDomain.EnrollmentDomainID)
		out.String(material.EnrollmentDomain.Environment)
		out.FixedBytes(material.EnrollmentDomain.GenesisHash[:], 32)
		out.FixedBytes(material.ProofChallenge[:], 32)
		out.Int64(material.ProofExpiresAtUnixNano)
		out.Bytes(material.ProofSignature)
		out.FixedBytes(material.ProofDigest[:], 32)
		out.FixedBytes(material.ChallengeEvidenceDigest[:], 32)
		out.String(material.EnrollmentAuthorityIdentity)
		out.EncodedSet(policies)
		out.FixedBytes(material.EnrollmentBindingDigest[:], 32)
		out.String(material.WriterIdentity)
		out.String(material.HomeRegion)
		out.Uint64(material.WriterEpoch)
		out.Uint64(material.StateVersion)
		out.FixedBytes(material.IdempotencyKey[:], 16)
	})
}

func canonicalSnapshotPreconditions(values []SnapshotPrecondition) ([]byte, error) {
	values, err := canonicalPreconditions(values)
	if err != nil {
		return nil, err
	}
	elements := make([][]byte, len(values))
	for index, value := range values {
		elements[index], err = ccse.Marshal(2048, func(out *ccse.Encoder) {
			encodeEntity(out, value.Entity)
			out.Uint64(value.ExpectedStateVersion)
			out.Uint64(value.ExpectedWriterEpoch)
			out.Uint32(value.ExpectedState)
			out.FixedBytes(value.ExpectedSnapshotDigest[:], 32)
		})
		if err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(512<<10, func(out *ccse.Encoder) { out.EncodedList(elements) })
}

func transferAuthorityAdmissionFingerprint(admission OwnershipTransferAuthorityAdmission) ([32]byte, error) {
	var zero [32]byte
	recordBytes, err := canonicalRetainedRecord(admission.Signed)
	if err != nil {
		return zero, err
	}
	materialBytes, err := canonicalMaterialSnapshot(admission.Historical.Material)
	if err != nil {
		return zero, err
	}
	lifecycle, err := normalizeViewLifecycle(admission.Historical.Lifecycle)
	if err != nil {
		return zero, err
	}
	identity, err := normalizeViewIdentity(admission.Historical.Identity)
	if err != nil {
		return zero, err
	}
	preconditions, err := canonicalSnapshotPreconditions(admission.CurrentPreconditions)
	if err != nil {
		return zero, err
	}
	receiver, err := canonicalReceiverProfile(admission.Receiver)
	if err != nil {
		return zero, err
	}
	authorityBytes, err := ccse.Marshal(8192, func(out *ccse.Encoder) {
		out.String(admission.Authority.Identity)
		out.String(admission.Authority.KeyID)
		out.String(admission.Authority.ProviderID)
		out.String(admission.Authority.OrganizationID)
		out.String(admission.Authority.Role)
		out.FixedBytes(admission.Authority.AuthorizationPolicyDigestSHA256[:], 32)
		out.Bool(admission.Authority.Coordinator)
	})
	if err != nil || admission.ValidatedAtUnixNano < 0 || admission.AdmissionProfileDigest == zero ||
		admission.AdmissionActivationDigest == zero {
		return zero, ErrTransferAuthorizationRequired
	}
	encoded, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) {
		out.Bytes(authorityBytes)
		out.Bool(admission.OldSide)
		out.Bytes(recordBytes)
		out.Bytes(materialBytes)
		out.Bytes(lifecycle.CanonicalPayload)
		out.Bytes(identity.CanonicalPayload)
		out.Bytes(preconditions)
		out.Bytes(receiver)
		out.FixedBytes(admission.AdmissionProfileDigest[:], 32)
		out.FixedBytes(admission.AdmissionActivationDigest[:], 32)
		out.Int64(admission.ValidatedAtUnixNano)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(transferAdmissionDigestDomain, encoded), nil
}

func canonicalHistoricalAuthorization(snapshot HistoricalKeyAuthorizationSnapshot) ([]byte, error) {
	material, err := canonicalMaterialSnapshot(snapshot.Material)
	if err != nil {
		return nil, err
	}
	lifecycle, err := normalizeViewLifecycle(snapshot.Lifecycle)
	if err != nil {
		return nil, err
	}
	identity, err := normalizeViewIdentity(snapshot.Identity)
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(512<<10, func(out *ccse.Encoder) {
		out.Bytes(material)
		out.Bytes(lifecycle.CanonicalPayload)
		out.Bytes(identity.CanonicalPayload)
	})
}

func transferEvidencePolicyDecisionDigest(
	projection foundationv1.OwnershipTransferAuthorizationSigningProjection,
	transferDigest [32]byte, admission OwnershipTransferEvidenceAdmission) ([32]byte, error) {
	var zero [32]byte
	if transferDigest == zero || admission.RecordDigest == zero || admission.EvidenceKind == 0 ||
		admission.ProfileDigest == zero || admission.ActivationDigest == zero ||
		admission.ValidatedAtUnixNano < 0 {
		return zero, ErrTransferAuthorizationRequired
	}
	receiver, err := canonicalReceiverProfile(admission.Receiver)
	if err != nil {
		return zero, err
	}
	historical, err := canonicalHistoricalAuthorization(admission.Historical)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.String(projection.TransferAuthorizationID)
		out.Uint32(projection.SubjectKind)
		out.String(projection.PreviousEntityID)
		out.String(projection.NextEntityID)
		out.FixedBytes(transferDigest[:], 32)
		out.Uint32(admission.EvidenceKind)
		out.FixedBytes(admission.RecordDigest[:], 32)
		out.Bytes(receiver)
		out.Bytes(historical)
		out.FixedBytes(admission.ProfileDigest[:], 32)
		out.FixedBytes(admission.ActivationDigest[:], 32)
		out.Int64(admission.ValidatedAtUnixNano)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(transferEvidenceDecisionDomain, encoded), nil
}

func transferEvidenceAdmissionFingerprint(admission OwnershipTransferEvidenceAdmission) ([32]byte, error) {
	var zero [32]byte
	if admission.RecordDigest == zero || admission.EvidenceKind == 0 ||
		admission.PolicyDecisionDigest == zero || admission.ProfileDigest == zero ||
		admission.ActivationDigest == zero || admission.ValidatedAtUnixNano < 0 {
		return zero, ErrTransferAuthorizationRequired
	}
	receiver, err := canonicalReceiverProfile(admission.Receiver)
	if err != nil {
		return zero, err
	}
	historical, err := canonicalHistoricalAuthorization(admission.Historical)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(2<<20, func(out *ccse.Encoder) {
		out.FixedBytes(admission.RecordDigest[:], 32)
		out.Uint32(admission.EvidenceKind)
		out.Bytes(historical)
		out.Bytes(receiver)
		out.FixedBytes(admission.ProfileDigest[:], 32)
		out.FixedBytes(admission.ActivationDigest[:], 32)
		out.FixedBytes(admission.PolicyDecisionDigest[:], 32)
		out.Int64(admission.ValidatedAtUnixNano)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(transferEvidenceAdmissionDomain, encoded), nil
}

func canonicalTransferEvidenceAdmissions(values []OwnershipTransferEvidenceAdmission) ([]byte, error) {
	if len(values) > 64 {
		return nil, ErrTransferAuthorizationRequired
	}
	values = append([]OwnershipTransferEvidenceAdmission(nil), values...)
	sort.Slice(values, func(i, j int) bool {
		return bytes.Compare(values[i].RecordDigest[:], values[j].RecordDigest[:]) < 0
	})
	elements := make([][]byte, len(values))
	for index, value := range values {
		fingerprint, err := transferEvidenceAdmissionFingerprint(value)
		if err != nil || fingerprint != value.Fingerprint ||
			(index > 0 && values[index-1].RecordDigest == value.RecordDigest) {
			return nil, ErrTransferAuthorizationRequired
		}
		elements[index], err = ccse.Marshal(1024, func(out *ccse.Encoder) {
			out.FixedBytes(value.RecordDigest[:], 32)
			out.Uint32(value.EvidenceKind)
			out.FixedBytes(value.Fingerprint[:], 32)
		})
		if err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(128<<10, func(out *ccse.Encoder) { out.EncodedSet(elements) })
}

func canonicalTransferAdmissions(values []OwnershipTransferAuthorityAdmission) ([]byte, error) {
	if len(values) == 0 || len(values) > maxTransferAuthorities {
		return nil, ErrTransferAuthorizationRequired
	}
	values = append([]OwnershipTransferAuthorityAdmission(nil), values...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].Authority.Identity != values[j].Authority.Identity {
			return values[i].Authority.Identity < values[j].Authority.Identity
		}
		return values[i].Authority.KeyID < values[j].Authority.KeyID
	})
	elements := make([][]byte, len(values))
	for index, value := range values {
		digest, err := transferAuthorityAdmissionFingerprint(value)
		if err != nil || digest != value.Fingerprint ||
			(index > 0 && values[index-1].Authority.Identity == value.Authority.Identity) {
			return nil, ErrTransferAuthorizationRequired
		}
		recordBytes, err := canonicalRetainedRecord(value.Signed)
		if err != nil {
			return nil, err
		}
		elements[index], err = ccse.Marshal(2<<20, func(out *ccse.Encoder) {
			out.String(value.Authority.Identity)
			out.String(value.Authority.KeyID)
			out.Bool(value.OldSide)
			out.FixedBytes(value.Fingerprint[:], 32)
			out.Bytes(recordBytes)
		})
		if err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(4<<20, func(out *ccse.Encoder) { out.EncodedSet(elements) })
}

func canonicalTransferFixedEvidence(evidence OwnershipTransferFixedEvidence) ([]byte, error) {
	previous, err := normalizeViewIdentity(evidence.PreviousTerminalIdentity)
	if err != nil {
		return nil, ErrTransferAuthorizationRequired
	}
	next, err := normalizeViewIdentity(evidence.NextPendingIdentity)
	if err != nil {
		return nil, ErrTransferAuthorizationRequired
	}
	identityCAS, err := canonicalSnapshotPreconditions([]SnapshotPrecondition{evidence.PreviousIdentityCAS})
	if err != nil {
		return nil, err
	}
	closures, err := canonicalRetainedRecordSet(evidence.KeyClosureRecords, 256)
	if err != nil {
		return nil, err
	}
	if len(evidence.KeyClosureSnapshots) != len(evidence.KeyClosureRecords) {
		return nil, ErrTransferAuthorizationRequired
	}
	closureSnapshots := make([][]byte, len(evidence.KeyClosureSnapshots))
	for index, snapshot := range evidence.KeyClosureSnapshots {
		normalized, normalizeErr := normalizeViewLifecycle(snapshot)
		if normalizeErr != nil {
			return nil, ErrTransferAuthorizationRequired
		}
		closureSnapshots[index] = normalized.CanonicalPayload
	}
	sort.Slice(closureSnapshots, func(i, j int) bool { return bytes.Compare(closureSnapshots[i], closureSnapshots[j]) < 0 })
	closureSnapshotBytes, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) { out.EncodedSet(closureSnapshots) })
	if err != nil {
		return nil, err
	}
	records, err := canonicalRetainedRecordSet(evidence.EvidenceRecords, 64)
	if err != nil {
		return nil, err
	}
	if len(evidence.EvidenceAdmissions) != len(evidence.EvidenceRecords) {
		return nil, ErrTransferAuthorizationRequired
	}
	evidenceAdmissions, err := canonicalTransferEvidenceAdmissions(evidence.EvidenceAdmissions)
	if err != nil {
		return nil, err
	}
	preconditions, err := canonicalSnapshotPreconditions(evidence.ClosurePreconditions)
	if err != nil {
		return nil, err
	}
	evidencePreconditions, err := canonicalSnapshotPreconditions(evidence.EvidencePreconditions)
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(4<<20, func(out *ccse.Encoder) {
		out.Bytes(previous.CanonicalPayload)
		out.Bytes(next.CanonicalPayload)
		out.Bytes(identityCAS)
		out.Bytes(closures)
		out.Bytes(closureSnapshotBytes)
		out.Bytes(records)
		out.Bytes(evidenceAdmissions)
		out.Bytes(preconditions)
		out.Bytes(evidencePreconditions)
	})
}

func canonicalRetainedRecordSet(values []RetainedVerifiedRecord, max int) ([]byte, error) {
	if len(values) == 0 || len(values) > max {
		return nil, ErrTransferAuthorizationRequired
	}
	elements := make([][]byte, len(values))
	var err error
	for index, value := range values {
		elements[index], err = canonicalRetainedRecord(value)
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(elements, func(i, j int) bool { return bytes.Compare(elements[i], elements[j]) < 0 })
	for index := 1; index < len(elements); index++ {
		if bytes.Equal(elements[index-1], elements[index]) {
			return nil, ErrTransferAuthorizationRequired
		}
	}
	return ccse.Marshal(4<<20, func(out *ccse.Encoder) { out.EncodedSet(elements) })
}

func transferCollectionDigest(snapshot OwnershipTransferApprovalCollectionSnapshot) ([32]byte, error) {
	var zero [32]byte
	bindingDigest, err := idempotency.BindingDigest(snapshot.Binding)
	if err != nil || snapshot.Version == 0 || snapshot.TransferEvidenceDigest == zero ||
		snapshot.ProfileDigest == zero || snapshot.HomeRegion == "" || snapshot.WriterEpoch == 0 {
		return zero, ErrTransferAuthorizationRequired
	}
	projection, canonical, digest, err := normalizeOwnershipTransferPayload(snapshot.CanonicalPayload)
	if err != nil || digest != snapshot.TransferEvidenceDigest {
		return zero, ErrTransferAuthorizationRequired
	}
	profile, profileDigest, err := normalizeTransferProfile(snapshot.Profile, projection)
	if err != nil || profileDigest != snapshot.ProfileDigest {
		return zero, ErrTransferAuthorizationRequired
	}
	_ = profile
	if err := validateTransferSnapshotBindings(projection, canonical, snapshot.TransferEvidenceDigest,
		snapshot.Profile, snapshot.ProfileDigest, snapshot.Approvals, snapshot.FixedEvidence, 0); err != nil {
		return zero, err
	}
	approvals, err := canonicalTransferAdmissions(snapshot.Approvals)
	if err != nil {
		return zero, err
	}
	fixed, err := canonicalTransferFixedEvidence(snapshot.FixedEvidence)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(8<<20, func(out *ccse.Encoder) {
		out.FixedBytes(bindingDigest[:], 32)
		out.Uint64(snapshot.Version)
		out.Bytes(canonical)
		out.FixedBytes(snapshot.TransferEvidenceDigest[:], 32)
		out.FixedBytes(snapshot.ProfileDigest[:], 32)
		out.FixedBytes(snapshot.Profile.Activation.SnapshotDigest[:], 32)
		out.Bytes(approvals)
		out.Bytes(fixed)
		out.String(snapshot.HomeRegion)
		out.Uint64(snapshot.WriterEpoch)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(transferCollectionDigestDomain, encoded), nil
}

func acceptedTransferDigest(snapshot AcceptedOwnershipTransferSnapshot) ([32]byte, error) {
	var zero [32]byte
	canonical, err := snapshot.Projection.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, snapshot.CanonicalPayload) ||
		sha256Bytes(canonical) != snapshot.TransferEvidenceDigest || snapshot.ProfileDigest == zero ||
		snapshot.AcceptedAtUnixNano < snapshot.Projection.Metadata.CreatedAtUnixNano ||
		snapshot.AcceptedAtUnixNano >= snapshot.Projection.ExpiresAtUnixNano ||
		snapshot.StateVersion == 0 || snapshot.WriterEpoch == 0 {
		return zero, ErrTransferAuthorizationRequired
	}
	_, profileDigest, err := normalizeTransferProfile(snapshot.Profile, snapshot.Projection)
	if err != nil || profileDigest != snapshot.ProfileDigest {
		return zero, ErrTransferAuthorizationRequired
	}
	if err := validateTransferSnapshotBindings(snapshot.Projection, canonical, snapshot.TransferEvidenceDigest,
		snapshot.Profile, snapshot.ProfileDigest, snapshot.Approvals, snapshot.FixedEvidence,
		snapshot.AcceptedAtUnixNano); err != nil {
		return zero, err
	}
	approvals, err := canonicalTransferAdmissions(snapshot.Approvals)
	if err != nil || !transferQuorumSatisfied(snapshot.Profile, snapshot.ProfileDigest, snapshot.Approvals) {
		return zero, ErrTransferAuthorizationRequired
	}
	fixed, err := canonicalTransferFixedEvidence(snapshot.FixedEvidence)
	if err != nil {
		return zero, err
	}
	encoded, err := ccse.Marshal(8<<20, func(out *ccse.Encoder) {
		out.Bytes(canonical)
		out.FixedBytes(snapshot.TransferEvidenceDigest[:], 32)
		out.FixedBytes(snapshot.ProfileDigest[:], 32)
		out.FixedBytes(snapshot.Profile.Activation.SnapshotDigest[:], 32)
		out.Bytes(approvals)
		out.Bytes(fixed)
		out.Int64(snapshot.AcceptedAtUnixNano)
		out.Uint64(snapshot.StateVersion)
		out.Uint64(snapshot.WriterEpoch)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(acceptedTransferDigestDomain, encoded), nil
}

// canonicalAcceptedTransferState returns the exact IAM-owned state preimage
// whose domain digest is AcceptedOwnershipTransferSnapshot.SnapshotDigest.
// Storage adapters must persist these bytes rather than reconstructing the
// private transfer codec from public fields.
func canonicalAcceptedTransferState(snapshot AcceptedOwnershipTransferSnapshot) ([]byte, [32]byte, error) {
	digest, err := acceptedTransferDigest(snapshot)
	if err != nil {
		return nil, [32]byte{}, err
	}
	canonical, err := snapshot.Projection.CanonicalBytes()
	if err != nil {
		return nil, [32]byte{}, err
	}
	approvals, err := canonicalTransferAdmissions(snapshot.Approvals)
	if err != nil {
		return nil, [32]byte{}, err
	}
	fixed, err := canonicalTransferFixedEvidence(snapshot.FixedEvidence)
	if err != nil {
		return nil, [32]byte{}, err
	}
	encoded, err := ccse.Marshal(8<<20, func(out *ccse.Encoder) {
		out.Bytes(canonical)
		out.FixedBytes(snapshot.TransferEvidenceDigest[:], 32)
		out.FixedBytes(snapshot.ProfileDigest[:], 32)
		out.FixedBytes(snapshot.Profile.Activation.SnapshotDigest[:], 32)
		out.Bytes(approvals)
		out.Bytes(fixed)
		out.Int64(snapshot.AcceptedAtUnixNano)
		out.Uint64(snapshot.StateVersion)
		out.Uint64(snapshot.WriterEpoch)
	})
	if err != nil || domainDigest(acceptedTransferDigestDomain, encoded) != digest {
		return nil, [32]byte{}, ErrPendingPlanInvalid
	}
	return encoded, digest, nil
}

func sha256Bytes(value []byte) [32]byte {
	return sha256.Sum256(value)
}

func ownershipTransferCollectionPlanDigest(plan OwnershipTransferApprovalCollectionPlan) ([32]byte, error) {
	var zero [32]byte
	nextDigest, err := transferCollectionDigest(plan.next)
	if err != nil || nextDigest != plan.next.ProgressDigest || plan.evaluatedAtUnixNano < 0 ||
		plan.commitNotBeforeUnixNano < 0 || plan.commitNotBeforeUnixNano > plan.evaluatedAtUnixNano ||
		plan.commitNotAfterUnixNano <= plan.evaluatedAtUnixNano || plan.authorizedWriterEpoch == 0 ||
		plan.authorizedWriterIdentity == "" || plan.authorizedWriterHomeRegion == "" ||
		plan.writerEvidenceDigest == zero {
		return zero, ErrPendingPlanInvalid
	}
	idempotencyBytes, err := idempotency.CanonicalBytes(plan.idempotencyClaims)
	if err != nil {
		return zero, err
	}
	identifierBytes, err := globalid.CanonicalBytes(plan.identifierClaims)
	if err != nil {
		return zero, err
	}
	dependencies, err := canonicalSnapshotPreconditions(plan.dependencies)
	if err != nil {
		return zero, err
	}
	joinedAuditBytes, err := canonicalIdempotencySnapshot(plan.joinedAuditSnapshot)
	if err != nil {
		return zero, err
	}
	if plan.accepted != nil || plan.audit != nil || len(plan.idempotencyCompletion) != 0 {
		return zero, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(12<<20, func(out *ccse.Encoder) {
		out.Uint32(uint32(plan.disposition))
		out.Int64(plan.evaluatedAtUnixNano)
		out.Int64(plan.commitNotBeforeUnixNano)
		out.Int64(plan.commitNotAfterUnixNano)
		out.Uint64(plan.expectedVersion)
		out.FixedBytes(plan.expectedProgressDigest[:], 32)
		out.String(plan.expectedHomeRegion)
		out.Uint64(plan.expectedWriterEpoch)
		out.Uint64(plan.authorizedWriterEpoch)
		out.String(plan.authorizedWriterIdentity)
		out.String(plan.authorizedWriterHomeRegion)
		out.FixedBytes(plan.writerEvidenceDigest[:], 32)
		out.Bytes(dependencies)
		out.FixedBytes(nextDigest[:], 32)
		out.Bytes(idempotencyBytes)
		out.Bytes(joinedAuditBytes)
		out.Bytes(identifierBytes)
		out.Bool(plan.quorumSatisfied)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(transferCollectionPlanDomain, encoded), nil
}

func verifyOwnershipTransferApprovalCollectionPlan(plan OwnershipTransferApprovalCollectionPlan) error {
	if err := verifyOwnershipTransferApprovalCollectionShape(plan); err != nil {
		return err
	}
	digest, err := ownershipTransferCollectionPlanDigest(plan)
	if err != nil || digest != plan.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func verifyOwnershipTransferApprovalCollectionShape(plan OwnershipTransferApprovalCollectionPlan) error {
	next := cloneTransferCollection(plan.next)
	joined, err := idempotency.JoinedAuditBinding(next.Binding)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	if next.Version == 0 || next.WriterEpoch != plan.authorizedWriterEpoch ||
		plan.authorizedWriterIdentity == "" || plan.authorizedWriterHomeRegion != next.HomeRegion ||
		plan.writerEvidenceDigest == ([32]byte{}) {
		return ErrPendingPlanInvalid
	}
	var expectedClaims []idempotency.Claim
	switch plan.disposition {
	case OwnershipTransferCollectionAppend:
		if plan.expectedVersion != 0 || plan.expectedProgressDigest != ([32]byte{}) ||
			plan.expectedHomeRegion != "" || plan.expectedWriterEpoch != 0 || next.Version != 1 ||
			plan.joinedAuditSnapshot != (idempotency.Snapshot{}) {
			return ErrPendingPlanInvalid
		}
		projection, _, _, projectionErr := normalizeOwnershipTransferPayload(next.CanonicalPayload)
		if projectionErr != nil || next.HomeRegion != projection.Metadata.HomeRegion ||
			next.WriterEpoch != projection.Metadata.WriterEpoch {
			return ErrPendingPlanInvalid
		}
		parentClaim, claimErr := idempotency.NewReserveCollection(next.Binding, next.ProgressDigest)
		if claimErr != nil {
			return ErrPendingPlanInvalid
		}
		parentDigest, digestErr := idempotency.BindingDigest(next.Binding)
		if digestErr != nil {
			return ErrPendingPlanInvalid
		}
		auditClaim, claimErr := idempotency.NewReserveCollection(joined, parentDigest)
		if claimErr != nil {
			return ErrPendingPlanInvalid
		}
		expectedClaims = []idempotency.Claim{parentClaim, auditClaim}
	case OwnershipTransferCollectionReplace:
		if plan.expectedVersion == 0 || next.Version != plan.expectedVersion+1 ||
			plan.expectedProgressDigest == ([32]byte{}) || plan.expectedHomeRegion == "" ||
			plan.expectedWriterEpoch == 0 || next.WriterEpoch < plan.expectedWriterEpoch ||
			(next.HomeRegion != plan.expectedHomeRegion && next.WriterEpoch <= plan.expectedWriterEpoch) ||
			plan.joinedAuditSnapshot.Binding != joined ||
			plan.joinedAuditSnapshot.State != idempotency.StateCollecting ||
			plan.joinedAuditSnapshot.Version != 1 {
			return ErrPendingPlanInvalid
		}
		parent := idempotency.Snapshot{Binding: next.Binding, State: idempotency.StateCollecting,
			Version: plan.expectedVersion, ProgressDigest: plan.expectedProgressDigest}
		advance, claimErr := idempotency.NewAdvanceCollection(parent, next.ProgressDigest)
		if claimErr != nil {
			return ErrPendingPlanInvalid
		}
		expectedClaims = []idempotency.Claim{advance}
	default:
		return ErrPendingPlanInvalid
	}
	if !sameIdempotencyClaims(expectedClaims, plan.idempotencyClaims) {
		return ErrPendingPlanInvalid
	}
	projection, _, _, projectionErr := normalizeOwnershipTransferPayload(next.CanonicalPayload)
	if projectionErr != nil {
		return ErrPendingPlanInvalid
	}
	expectedDependencies, err := transferCollectionDependencies(next.Approvals, next.FixedEvidence,
		next.Profile, projection.SubjectKind)
	if err != nil || !sameSnapshotPreconditions(expectedDependencies, plan.dependencies) {
		return ErrPendingPlanInvalid
	}
	if err := verifyTransferIdentifierClaims(next, plan.disposition, plan.identifierClaims); err != nil {
		return err
	}
	quorum := transferQuorumSatisfied(next.Profile, next.ProfileDigest, next.Approvals)
	if quorum != plan.quorumSatisfied {
		return ErrPendingPlanInvalid
	}
	if plan.accepted != nil || plan.audit != nil || len(plan.idempotencyCompletion) != 0 {
		return ErrPendingPlanInvalid
	}
	return nil
}

func sameSnapshotPreconditions(left, right []SnapshotPrecondition) bool {
	leftBytes, leftErr := canonicalSnapshotPreconditions(left)
	rightBytes, rightErr := canonicalSnapshotPreconditions(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func verifyTransferIdentifierClaims(snapshot OwnershipTransferApprovalCollectionSnapshot,
	disposition OwnershipTransferCollectionDisposition, claims []globalid.Claim) error {
	claims, err := globalid.NormalizeClaims(claims)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	projection, _, _, err := normalizeOwnershipTransferPayload(snapshot.CanonicalPayload)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	eventID, err := idempotency.JoinedAuditEventID(snapshot.Binding)
	if err != nil {
		return ErrPendingPlanInvalid
	}
	oldRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.PreviousEntityID}
	newRef := EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.NextEntityID}
	canonicalOwner := globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: projection.TransferAuthorizationID}
	oldOwner, newOwner := identityGlobalOwner(oldRef), identityGlobalOwner(newRef)
	newMode := globalid.ReserveNew
	if disposition == OwnershipTransferCollectionReplace {
		newMode = globalid.AssertExisting
	}
	required := []struct {
		id    string
		owner globalid.Owner
		mode  globalid.ClaimMode
	}{
		{projection.TransferAuthorizationID, canonicalOwner, newMode},
		{projection.Metadata.RecordID, canonicalOwner, newMode},
		{eventID, globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID}, newMode},
		{projection.PreviousEntityID, oldOwner, globalid.AssertExisting},
		{projection.PreviousPrincipalIdentity, oldOwner, globalid.AssertExisting},
		{projection.NextEntityID, newOwner, newMode},
		{projection.NewKeyID, keyGlobalOwner(projection.NewKeyID), newMode},
		{snapshot.FixedEvidence.PreviousTerminalIdentity.RecordID,
			recordGlobalOwner(oldRef, snapshot.FixedEvidence.PreviousTerminalIdentity.RecordID), newMode},
		{snapshot.FixedEvidence.NextPendingIdentity.RecordID,
			recordGlobalOwner(newRef, snapshot.FixedEvidence.NextPendingIdentity.RecordID), newMode},
	}
	principalOwner, principalMode := oldOwner, globalid.AssertExisting
	if projection.SubjectKind == 2 {
		principalOwner, principalMode = newOwner, newMode
	}
	required = append(required, struct {
		id    string
		owner globalid.Owner
		mode  globalid.ClaimMode
	}{projection.NextPrincipalIdentity, principalOwner, principalMode})
	for _, lifecycle := range snapshot.FixedEvidence.KeyClosureSnapshots {
		ref := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID}
		required = append(required, struct {
			id    string
			owner globalid.Owner
			mode  globalid.ClaimMode
		}{lifecycle.RecordID, recordGlobalOwner(ref, lifecycle.RecordID), newMode})
	}
	expectedIDs := make(map[string]struct{}, len(required)+len(snapshot.FixedEvidence.EvidenceRecords))
	for _, expected := range required {
		expectedIDs[expected.id] = struct{}{}
		found := false
		for _, claim := range claims {
			if claim.Identifier == expected.id && claim.Owner == expected.owner && claim.Mode == expected.mode {
				found = true
				break
			}
		}
		if !found {
			return ErrPendingPlanInvalid
		}
	}
	for _, record := range snapshot.FixedEvidence.EvidenceRecords {
		recordID, owner, recordErr := retainedEvidenceRecordGlobalOwner(record)
		if recordErr != nil {
			return ErrPendingPlanInvalid
		}
		expectedIDs[recordID] = struct{}{}
		found := false
		for _, claim := range claims {
			if claim.Identifier == recordID && claim.Mode == globalid.AssertExisting &&
				claim.ExpectedOwner == owner && claim.Owner == owner {
				found = true
				break
			}
		}
		if !found {
			return ErrPendingPlanInvalid
		}
	}
	if len(claims) != len(expectedIDs) {
		return ErrPendingPlanInvalid
	}
	for _, claim := range claims {
		if _, expected := expectedIDs[claim.Identifier]; !expected {
			return ErrPendingPlanInvalid
		}
	}
	return nil
}

func canonicalIdempotencySnapshot(snapshot idempotency.Snapshot) ([]byte, error) {
	if snapshot == (idempotency.Snapshot{}) {
		return ccse.Marshal(8, func(out *ccse.Encoder) { out.Bool(false) })
	}
	if err := snapshot.Validate(); err != nil {
		return nil, ErrPendingPlanInvalid
	}
	bindingDigest, err := idempotency.BindingDigest(snapshot.Binding)
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(160, func(out *ccse.Encoder) {
		out.Bool(true)
		out.FixedBytes(bindingDigest[:], 32)
		out.Uint32(uint32(snapshot.State))
		out.Uint64(snapshot.Version)
		out.FixedBytes(snapshot.ProgressDigest[:], 32)
		out.FixedBytes(snapshot.OutcomeDigest[:], 32)
	})
}

func transferQuorumSatisfied(profile OwnershipTransferProfile, profileDigest [32]byte,
	approvals []OwnershipTransferAuthorityAdmission) bool {
	if len(approvals) != len(profile.OldAuthorities)+len(profile.NewAuthorities) {
		return false
	}
	seen := make(map[string]OwnershipTransferAuthorityAdmission, len(approvals))
	for _, approval := range approvals {
		key := approval.Authority.Identity + "\x00" + approval.Authority.KeyID
		if _, duplicate := seen[key]; duplicate || approval.AdmissionProfileDigest != profileDigest ||
			approval.AdmissionActivationDigest != profile.Activation.SnapshotDigest {
			return false
		}
		seen[key] = approval
	}
	for _, side := range []struct {
		old    bool
		values []OwnershipTransferAuthorityRequirement
	}{{true, profile.OldAuthorities}, {false, profile.NewAuthorities}} {
		for _, requirement := range side.values {
			approval, found := seen[requirement.Identity+"\x00"+requirement.KeyID]
			if !found || approval.Authority != requirement || approval.OldSide != side.old {
				return false
			}
		}
	}
	return true
}

func validateTransferSnapshotBindings(projection foundationv1.OwnershipTransferAuthorizationSigningProjection,
	canonical []byte, transferDigest [32]byte, profile OwnershipTransferProfile, profileDigest [32]byte,
	approvals []OwnershipTransferAuthorityAdmission, fixed OwnershipTransferFixedEvidence, acceptedAt int64) error {
	if payload, err := projection.CanonicalBytes(); err != nil || !bytes.Equal(payload, canonical) ||
		sha256.Sum256(canonical) != transferDigest || !sameTransferCorrelation(approvals) ||
		(acceptedAt != 0 && (acceptedAt < profile.Activation.ValidFromUnixNano ||
			acceptedAt >= profile.Activation.ValidUntilUnixNano)) {
		return ErrTransferAuthorizationRequired
	}
	previous, err := normalizeViewIdentity(fixed.PreviousTerminalIdentity)
	if err != nil || sha256.Sum256(previous.CanonicalPayload) != projection.PreviousTerminalIdentityPayloadDigestSHA256 ||
		previous.Ref != (EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.PreviousEntityID}) ||
		previous.PrincipalIdentity != projection.PreviousPrincipalIdentity || previous.State != 5 ||
		previous.Generation != projection.ExpectedGeneration || previous.Bindings.ProviderID != projection.PreviousProviderID {
		return ErrTransferAuthorizationRequired
	}
	next, err := normalizeViewIdentity(fixed.NextPendingIdentity)
	if err != nil || sha256.Sum256(next.CanonicalPayload) != projection.NextPendingIdentityPayloadDigestSHA256 ||
		next.Ref != (EntityRef{Kind: EntityIdentity, PrincipalKind: projection.SubjectKind, ID: projection.NextEntityID}) ||
		next.PrincipalIdentity != projection.NextPrincipalIdentity || next.State != 1 || next.StateVersion != 1 ||
		next.Generation != projection.NextGeneration || next.Bindings.ProviderID != projection.NextProviderID ||
		next.KeyID != projection.NewKeyID || next.ValidFromUnixNano > projection.EffectiveAtUnixNano ||
		projection.EffectiveAtUnixNano >= next.ValidUntilUnixNano {
		return ErrTransferAuthorizationRequired
	}
	if fixed.PreviousIdentityCAS.Entity != previous.Ref || fixed.PreviousIdentityCAS.ExpectedStateVersion == 0 ||
		fixed.PreviousIdentityCAS.ExpectedStateVersion+1 != previous.StateVersion ||
		(fixed.PreviousIdentityCAS.ExpectedState != 2 && fixed.PreviousIdentityCAS.ExpectedState != 3) ||
		fixed.PreviousIdentityCAS.ExpectedSnapshotDigest == ([32]byte{}) {
		return ErrTransferAuthorizationRequired
	}
	closures := make(map[string][32]byte, len(projection.OldKeyClosures))
	for _, closure := range projection.OldKeyClosures {
		closures[closure.KeyID] = closure.TerminalKeyLifecyclePayloadDigestSHA256
	}
	if len(fixed.KeyClosureRecords) != len(closures) || len(fixed.KeyClosureSnapshots) != len(closures) {
		return ErrTransferAuthorizationRequired
	}
	closureRecords := make(map[[32]byte]RetainedVerifiedRecord, len(fixed.KeyClosureRecords))
	for _, retained := range fixed.KeyClosureRecords {
		if retained.record.MessageTypeID != schema.MessageTypeKeyLifecycle {
			return ErrTransferAuthorizationRequired
		}
		closureRecords[sha256.Sum256(retained.record.Payload)] = retained
	}
	for _, lifecycle := range fixed.KeyClosureSnapshots {
		lifecycle, err = normalizeViewLifecycle(lifecycle)
		expectedDigest, found := closures[lifecycle.KeyID]
		retained, recordFound := closureRecords[expectedDigest]
		if err != nil || !found || !recordFound || !bytes.Equal(retained.record.Payload, lifecycle.CanonicalPayload) ||
			sha256.Sum256(lifecycle.CanonicalPayload) != expectedDigest || !terminalLifecycleState(lifecycle.State) ||
			lifecycle.SubjectKind != projection.SubjectKind || lifecycle.SubjectIdentity != projection.PreviousPrincipalIdentity {
			return ErrTransferAuthorizationRequired
		}
		matchedCAS := false
		for _, precondition := range fixed.ClosurePreconditions {
			if precondition.Entity == (EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID}) &&
				precondition.ExpectedStateVersion > 0 && precondition.ExpectedStateVersion+1 == lifecycle.StateVersion &&
				precondition.ExpectedState != 4 && precondition.ExpectedState != 5 {
				matchedCAS = true
				break
			}
		}
		if !matchedCAS {
			return ErrTransferAuthorizationRequired
		}
	}
	commitments := make(map[[32]byte]uint32, len(projection.EvidenceCommitments))
	for _, commitment := range projection.EvidenceCommitments {
		commitments[commitment.CCSERecordDigestSHA256] = commitment.EvidenceKind
	}
	if len(fixed.EvidenceRecords) != len(commitments) ||
		len(fixed.EvidenceAdmissions) != len(commitments) {
		return ErrTransferAuthorizationRequired
	}
	recordsByDigest := make(map[[32]byte]struct{}, len(fixed.EvidenceRecords))
	for _, retained := range fixed.EvidenceRecords {
		if _, found := commitments[retained.digest]; !found {
			return ErrTransferAuthorizationRequired
		}
		if _, duplicate := recordsByDigest[retained.digest]; duplicate {
			return ErrTransferAuthorizationRequired
		}
		recordsByDigest[retained.digest] = struct{}{}
	}
	admissionsByDigest := make(map[[32]byte]struct{}, len(fixed.EvidenceAdmissions))
	for _, admission := range fixed.EvidenceAdmissions {
		kind, found := commitments[admission.RecordDigest]
		if !found || kind != admission.EvidenceKind ||
			admission.ProfileDigest != profileDigest ||
			admission.ActivationDigest != profile.Activation.SnapshotDigest {
			return ErrTransferAuthorizationRequired
		}
		if _, recordFound := recordsByDigest[admission.RecordDigest]; !recordFound {
			return ErrTransferAuthorizationRequired
		}
		if _, duplicate := admissionsByDigest[admission.RecordDigest]; duplicate {
			return ErrTransferAuthorizationRequired
		}
		decision, decisionErr := transferEvidencePolicyDecisionDigest(projection,
			transferDigest, admission)
		fingerprint, fingerprintErr := transferEvidenceAdmissionFingerprint(admission)
		if decisionErr != nil || decision != admission.PolicyDecisionDigest ||
			fingerprintErr != nil || fingerprint != admission.Fingerprint {
			return ErrTransferAuthorizationRequired
		}
		admissionsByDigest[admission.RecordDigest] = struct{}{}
	}
	validationAt := int64(-1)
	if len(approvals) > 0 {
		validationAt = approvals[0].ValidatedAtUnixNano
	}
	for _, approval := range approvals {
		digest, fingerprintErr := transferAuthorityAdmissionFingerprint(approval)
		record := approval.Signed.record
		requirement, oldSide, found := transferAuthorityRequirement(profile,
			record.Domain.SenderIdentity, record.Envelope.SignatureKeyID)
		if fingerprintErr != nil || digest != approval.Fingerprint || !found || approval.Authority != requirement ||
			approval.OldSide != oldSide || approval.AdmissionProfileDigest != profileDigest ||
			approval.AdmissionActivationDigest != profile.Activation.SnapshotDigest ||
			record.MessageTypeID != schema.MessageTypeOwnershipTransferAuthorization ||
			record.SchemaVersion != (ccse.Version{Major: 1}) || !bytes.Equal(record.Payload, canonical) ||
			record.Domain.CounterKind != ccse.CounterExpectedGeneration ||
			record.Domain.Counter != projection.ExpectedGeneration ||
			record.Domain.IssuedAtUnixNano < projection.Metadata.CreatedAtUnixNano ||
			record.Domain.IssuedAtUnixNano >= record.Domain.ExpiresAtUnixNano ||
			approval.Historical.Material.KeyID != requirement.KeyID ||
			approval.Historical.Material.SubjectIdentity != requirement.Identity ||
			approval.Historical.Lifecycle.KeyID != requirement.KeyID ||
			approval.Historical.Identity.PrincipalIdentity != requirement.Identity ||
			len(approval.CurrentPreconditions) != 2 || validationAt < 0 ||
			approval.ValidatedAtUnixNano != validationAt || validationAt < record.Domain.IssuedAtUnixNano ||
			validationAt >= record.Domain.ExpiresAtUnixNano {
			return ErrTransferAuthorizationRequired
		}
		if acceptedAt != 0 && (acceptedAt < record.Domain.IssuedAtUnixNano ||
			acceptedAt >= record.Domain.ExpiresAtUnixNano) {
			return ErrTransferAuthorizationRequired
		}
		activeLifecycle, activeIdentity := false, false
		for _, precondition := range approval.CurrentPreconditions {
			switch precondition.Entity.Kind {
			case EntityKeyLifecycle:
				activeLifecycle = precondition.Entity.ID == requirement.KeyID && precondition.ExpectedState == 2
			case EntityIdentity:
				activeIdentity = precondition.ExpectedState == 2
			}
		}
		if !activeLifecycle || !activeIdentity {
			return ErrTransferAuthorizationRequired
		}
	}
	return nil
}

func coordinatorApproval(profile OwnershipTransferProfile,
	approvals []OwnershipTransferAuthorityAdmission) (OwnershipTransferAuthorityAdmission, bool) {
	for _, requirement := range profile.NewAuthorities {
		if !requirement.Coordinator {
			continue
		}
		for _, approval := range approvals {
			if approval.Authority == requirement && !approval.OldSide {
				return cloneTransferAdmission(approval), true
			}
		}
	}
	return OwnershipTransferAuthorityAdmission{}, false
}

func sameTransferFixedEvidence(left, right OwnershipTransferFixedEvidence) bool {
	leftBytes, leftErr := canonicalTransferFixedEvidence(left)
	rightBytes, rightErr := canonicalTransferFixedEvidence(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func sameTransferProfile(left, right OwnershipTransferProfile) bool {
	left = cloneTransferProfile(left)
	right = cloneTransferProfile(right)
	sortTransferRequirements(left.OldAuthorities)
	sortTransferRequirements(left.NewAuthorities)
	sortTransferRequirements(right.OldAuthorities)
	sortTransferRequirements(right.NewAuthorities)
	leftBytes, leftErr := encodeTransferProfile(left)
	rightBytes, rightErr := encodeTransferProfile(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func encodeTransferProfile(profile OwnershipTransferProfile) ([]byte, error) {
	policy, err := encodeTransferProfilePolicy(profile)
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(384<<10, func(out *ccse.Encoder) {
		out.Bytes(policy)
		out.FixedBytes(profile.Activation.ProfileDigest[:], 32)
		out.Uint64(profile.Activation.ActivationVersion)
		out.Int64(profile.Activation.ValidFromUnixNano)
		out.Int64(profile.Activation.ValidUntilUnixNano)
		out.FixedBytes(profile.Activation.EvidenceDigest[:], 32)
		out.Uint64(profile.Activation.StateVersion)
		out.Uint64(profile.Activation.WriterEpoch)
		out.FixedBytes(profile.Activation.SnapshotDigest[:], 32)
	})
}

func encodeTransferProfilePolicy(profile OwnershipTransferProfile) ([]byte, error) {
	oldEncoded, err := encodeTransferRequirements(profile.OldAuthorities)
	if err != nil {
		return nil, err
	}
	newEncoded, err := encodeTransferRequirements(profile.NewAuthorities)
	if err != nil {
		return nil, err
	}
	return ccse.Marshal(256<<10, func(out *ccse.Encoder) {
		out.String(profile.ProfileID)
		out.Uint64(profile.ProfileVersion)
		out.FixedBytes(profile.PolicyDigest[:], 32)
		out.FixedBytes(profile.RecordIntegrityDigestSHA256[:], 32)
		out.EncodedSet(oldEncoded)
		out.EncodedSet(newEncoded)
	})
}
