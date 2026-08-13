// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	canonicalStateAssertionDigestDomain = "CPH-AIIE-GOVERNANCE-CANONICAL-STATE-ASSERTION-V1\x00"
	canonicalStateMutationDigestDomain  = "CPH-AIIE-GOVERNANCE-CANONICAL-STATE-MUTATION-V1\x00"
	canonicalKeyStateAssertionDomain    = "CPH-AIIE-GOVERNANCE-CANONICAL-KEY-STATE-ASSERTION-V1\x00"
	canonicalAuditWriterLeaseDomain     = "CPH-AIIE-GOVERNANCE-CANONICAL-AUDIT-WRITER-LEASE-ASSERTION-V1\x00"
	canonicalProfileActivationDomain    = "CPH-AIIE-GOVERNANCE-PROFILE-ACTIVATION-STATE-V1\x00"
	canonicalStateMaxBytes              = 16 << 20
)

func cloneCanonicalStateRecord(value CanonicalStateRecord) CanonicalStateRecord {
	value.CanonicalState = append([]byte(nil), value.CanonicalState...)
	return value
}

func validCanonicalStateRecord(value CanonicalStateRecord) bool {
	if (value.Namespace != CanonicalStateNamespaceIAM && value.Namespace != CanonicalStateNamespaceGovernance) ||
		!validDurableEvidenceStorageText(value.ObjectID, 1024) ||
		value.Version == 0 || isZeroDigest(value.StateDigestSHA256) ||
		len(value.CanonicalState) == 0 || len(value.CanonicalState) > canonicalStateMaxBytes ||
		!validDurableEvidenceStorageText(value.AuditEventID, 1024) {
		return false
	}
	if value.Namespace == CanonicalStateNamespaceIAM {
		if value.HasValidityWindow || value.ValidFromUnixNano != 0 || value.ValidUntilUnixNano != 0 {
			return false
		}
		switch value.Kind {
		case CanonicalStateKindIAMKeyMaterial:
			return value.ContentType == CanonicalStateContentTypeIAMKeyMaterial && value.Terminal
		case CanonicalStateKindIAMKeyLifecycle:
			return value.ContentType == CanonicalStateContentTypeIAMKeyLifecycle
		case CanonicalStateKindIAMIdentity:
			return value.ContentType == CanonicalStateContentTypeIAMIdentity
		case CanonicalStateKindIAMWriterLease:
			return value.ContentType == CanonicalStateContentTypeIAMWriterLease && !value.Terminal
		default:
			return false
		}
	}
	switch value.Kind {
	case CanonicalStateKindGovernancePolicyRegistry:
		if value.ContentType != CanonicalStateContentTypeGovernancePolicyRegistry || value.HasValidityWindow ||
			value.ValidFromUnixNano != 0 || value.ValidUntilUnixNano != 0 || value.Terminal {
			return false
		}
	case CanonicalStateKindGovernanceProfileActivation:
		if value.ContentType != CanonicalStateContentTypeGovernanceProfileActivation || !value.HasValidityWindow ||
			value.ValidFromUnixNano < 0 || value.ValidUntilUnixNano <= value.ValidFromUnixNano || value.Terminal {
			return false
		}
	default:
		return false
	}
	return true
}

func validCanonicalAuditWriterLeaseRequirement(value CanonicalAuditWriterLeaseRequirement) bool {
	return validDurableEvidenceStorageText(value.StreamID, 255) &&
		value.WriterLeaseEntityKind == uint32(iam.EntityIdentity) &&
		value.WriterLeaseEntityPrincipalKind >= 1 && value.WriterLeaseEntityPrincipalKind <= 8 &&
		validDurableEvidenceStorageText(value.WriterLeaseEntityID, 1024) &&
		validDurableEvidenceStorageText(value.AuthorizedWriterIdentity, 1024) &&
		validDurableEvidenceStorageText(value.AuthorizedHomeRegion, 255) &&
		value.AuthorizedWriterEpoch != 0 &&
		!isZeroDigest(value.AuthorizedGovernanceProfileDigestSHA256) &&
		!isZeroDigest(value.WriterLeaseEvidenceDigestSHA256) &&
		value.WriterLeaseNotBeforeUnixNano >= 0 &&
		value.WriterLeaseNotAfterUnixNano > value.WriterLeaseNotBeforeUnixNano
}

func auditWriterLeaseRequirement(head AuditHeadSnapshot,
	key GovernanceKeySnapshot) CanonicalAuditWriterLeaseRequirement {
	return CanonicalAuditWriterLeaseRequirement{
		StreamID: head.StreamID, WriterLeaseEntityKind: key.TargetIdentityKind,
		WriterLeaseEntityPrincipalKind: key.TargetPrincipalKind, WriterLeaseEntityID: key.TargetIdentityID,
		AuthorizedWriterIdentity: head.AuthorizedWriterIdentity,
		AuthorizedHomeRegion:     head.AuthorizedHomeRegion, AuthorizedWriterEpoch: head.AuthorizedWriterEpoch,
		AuthorizedGovernanceProfileDigestSHA256: head.AuthorizedGovernanceProfileDigestSHA256,
		WriterLeaseEvidenceDigestSHA256:         head.WriterLeaseEvidenceDigestSHA256,
		WriterLeaseNotBeforeUnixNano:            head.WriterLeaseNotBeforeUnixNano,
		WriterLeaseNotAfterUnixNano:             head.WriterLeaseNotAfterUnixNano,
	}
}

func iamCanonicalStateRecord(value CanonicalStateRecord) iam.CanonicalStateRecord {
	return iam.CanonicalStateRecord{
		Namespace: value.Namespace, Kind: value.Kind, ObjectID: value.ObjectID, Version: value.Version,
		StateDigestSHA256: value.StateDigestSHA256, ContentType: value.ContentType,
		CanonicalState: append([]byte(nil), value.CanonicalState...), Terminal: value.Terminal,
		AuditEventID: value.AuditEventID, HasValidityWindow: value.HasValidityWindow,
		ValidFromUnixNano: value.ValidFromUnixNano, ValidUntilUnixNano: value.ValidUntilUnixNano,
	}
}

func verifyCanonicalAuditWriterLeaseRecord(requirement CanonicalAuditWriterLeaseRequirement,
	record CanonicalStateRecord) error {
	lease := iam.WriterLeaseSnapshot{
		Entity: iam.EntityRef{Kind: iam.EntityKind(requirement.WriterLeaseEntityKind),
			PrincipalKind: requirement.WriterLeaseEntityPrincipalKind, ID: requirement.WriterLeaseEntityID},
		WriterIdentity: requirement.AuthorizedWriterIdentity, HomeRegion: requirement.AuthorizedHomeRegion,
		WriterEpoch:        requirement.AuthorizedWriterEpoch,
		ValidFromUnixNano:  requirement.WriterLeaseNotBeforeUnixNano,
		ValidUntilUnixNano: requirement.WriterLeaseNotAfterUnixNano,
		EvidenceDigest:     requirement.WriterLeaseEvidenceDigestSHA256,
	}
	iamRequirement, err := iam.NewCanonicalWriterLeaseRequirement(lease, record.AuditEventID)
	if err != nil || iamRequirement.VerifyDigest() != nil ||
		iam.VerifyCanonicalWriterLeaseRecord(iamRequirement, iamCanonicalStateRecord(record)) != nil {
		return ErrSnapshotInconsistent
	}
	return nil
}

func digestCanonicalAuditWriterLeaseAssertion(requirement CanonicalAuditWriterLeaseRequirement,
	record CanonicalStateAssertion) ([ccse.DigestSize]byte, error) {
	if !validCanonicalAuditWriterLeaseRequirement(requirement) || record.VerifyDigest() != nil ||
		record.record.Namespace != CanonicalStateNamespaceIAM ||
		record.record.Kind != CanonicalStateKindIAMWriterLease ||
		record.record.ContentType != CanonicalStateContentTypeIAMWriterLease ||
		record.record.Version != requirement.AuthorizedWriterEpoch || record.record.Terminal ||
		record.record.HasValidityWindow || record.record.ValidFromUnixNano != 0 || record.record.ValidUntilUnixNano != 0 ||
		verifyCanonicalAuditWriterLeaseRecord(requirement, record.record) != nil {
		return [ccse.DigestSize]byte{}, ErrSnapshotInconsistent
	}
	w := newDigestWriter(canonicalAuditWriterLeaseDomain)
	w.string(requirement.StreamID)
	w.uint64(uint64(requirement.WriterLeaseEntityKind))
	w.uint64(uint64(requirement.WriterLeaseEntityPrincipalKind))
	w.string(requirement.WriterLeaseEntityID)
	w.string(requirement.AuthorizedWriterIdentity)
	w.string(requirement.AuthorizedHomeRegion)
	w.uint64(requirement.AuthorizedWriterEpoch)
	w.digest(requirement.AuthorizedGovernanceProfileDigestSHA256)
	w.digest(requirement.WriterLeaseEvidenceDigestSHA256)
	w.int64(requirement.WriterLeaseNotBeforeUnixNano)
	w.int64(requirement.WriterLeaseNotAfterUnixNano)
	writeCanonicalStateRecord(w, record.record)
	w.digest(record.digest)
	return w.sum()
}

func (p *Planner) canonicalAuditWriterLeaseAssertion(ctx context.Context,
	head AuditHeadSnapshot, key GovernanceKeySnapshot) (CanonicalAuditWriterLeaseAssertion, error) {
	view, ok := p.audit.(CanonicalAuditWriterLeaseView)
	if !ok {
		return CanonicalAuditWriterLeaseAssertion{}, ErrInvalidConfiguration
	}
	requirement := auditWriterLeaseRequirement(head, key)
	if !validCanonicalAuditWriterLeaseRequirement(requirement) {
		return CanonicalAuditWriterLeaseAssertion{}, ErrSnapshotInconsistent
	}
	record, found, err := view.CanonicalAuditWriterLease(ctx, requirement)
	if err != nil || !found {
		return CanonicalAuditWriterLeaseAssertion{}, ErrSnapshotInconsistent
	}
	assertion, err := newCanonicalStateAssertion(record)
	if err != nil {
		return CanonicalAuditWriterLeaseAssertion{}, ErrSnapshotInconsistent
	}
	digest, err := digestCanonicalAuditWriterLeaseAssertion(requirement, assertion)
	if err != nil {
		return CanonicalAuditWriterLeaseAssertion{}, err
	}
	return CanonicalAuditWriterLeaseAssertion{requirement: requirement, record: assertion, digest: digest}, nil
}

func validateCanonicalAuditWriterLeaseAssertion(value MutationPlanSnapshot) error {
	present := value.CanonicalAuditWriterLeaseAssertion.digest != ([ccse.DigestSize]byte{}) ||
		value.CanonicalAuditWriterLeaseAssertion.record.digest != ([ccse.DigestSize]byte{})
	if !value.CommitReady {
		if present {
			return ErrSnapshotInconsistent
		}
		return nil
	}
	if !present || value.CanonicalAuditWriterLeaseAssertion.VerifyDigest() != nil {
		return ErrSnapshotInconsistent
	}
	expected := CanonicalAuditWriterLeaseRequirement{
		StreamID:                       value.AuditStreamID,
		WriterLeaseEntityKind:          value.AuditWriterKeyPrecondition.IdentityKind,
		WriterLeaseEntityPrincipalKind: value.AuditWriterKeyPrecondition.IdentityPrincipalKind,
		WriterLeaseEntityID:            value.AuditWriterKeyPrecondition.IdentityObjectID,
		AuthorizedWriterIdentity:       value.AuthorizedAuditWriterIdentity,
		AuthorizedHomeRegion:           value.AuthorizedAuditHomeRegion, AuthorizedWriterEpoch: value.AuthorizedAuditWriterEpoch,
		AuthorizedGovernanceProfileDigestSHA256: value.AuthorizedAuditGovernanceProfileDigestSHA256,
		WriterLeaseEvidenceDigestSHA256:         value.ExpectedAuditWriterLeaseEvidenceDigestSHA256,
		WriterLeaseNotBeforeUnixNano:            value.ExpectedAuditWriterLeaseNotBeforeUnixNano,
		WriterLeaseNotAfterUnixNano:             value.ExpectedAuditWriterLeaseNotAfterUnixNano,
	}
	if value.CanonicalAuditWriterLeaseAssertion.requirement != expected {
		return ErrSnapshotInconsistent
	}
	return nil
}

func digestCanonicalKeyStateAssertion(precondition KeyStatePrecondition,
	records []CanonicalStateAssertion) ([ccse.DigestSize]byte, error) {
	if !validKeyStatePrecondition(precondition) || len(records) != 3 {
		return [ccse.DigestSize]byte{}, ErrSnapshotInconsistent
	}
	expectedKinds := [...]string{
		CanonicalStateKindIAMKeyMaterial,
		CanonicalStateKindIAMKeyLifecycle,
		CanonicalStateKindIAMIdentity,
	}
	for index := range records {
		if records[index].VerifyDigest() != nil || records[index].record.Namespace != CanonicalStateNamespaceIAM ||
			records[index].record.Kind != expectedKinds[index] {
			return [ccse.DigestSize]byte{}, ErrSnapshotInconsistent
		}
	}
	material, lifecycle, identity := records[0].record, records[1].record, records[2].record
	if material.ObjectID != precondition.KeyID || lifecycle.ObjectID != precondition.KeyID ||
		material.Version != precondition.KeyMaterialStateVersion ||
		material.StateDigestSHA256 != precondition.KeyMaterialStateDigestSHA256 ||
		lifecycle.Terminal || identity.Terminal ||
		lifecycle.Version != precondition.StateVersion || lifecycle.StateDigestSHA256 != precondition.SnapshotDigestSHA256 ||
		identity.ObjectID != precondition.IdentityObjectID ||
		identity.Version != precondition.IdentityStateVersion ||
		identity.StateDigestSHA256 != precondition.IdentitySnapshotDigestSHA256 {
		return [ccse.DigestSize]byte{}, ErrSnapshotInconsistent
	}
	w := newDigestWriter(canonicalKeyStateAssertionDomain)
	w.keyPrecondition(precondition)
	for index := range records {
		writeCanonicalStateRecord(w, records[index].record)
		w.digest(records[index].digest)
	}
	return w.sum()
}

func newCanonicalKeyStateAssertion(precondition KeyStatePrecondition,
	projection CanonicalGovernanceKeyStateProjection) (CanonicalKeyStateAssertion, error) {
	rows := [...]CanonicalStateRecord{projection.KeyMaterial, projection.Lifecycle, projection.Identity}
	records := make([]CanonicalStateAssertion, len(rows))
	for index := range rows {
		assertion, err := newCanonicalStateAssertion(rows[index])
		if err != nil {
			return CanonicalKeyStateAssertion{}, ErrSnapshotInconsistent
		}
		records[index] = assertion
	}
	digest, err := digestCanonicalKeyStateAssertion(precondition, records)
	if err != nil {
		return CanonicalKeyStateAssertion{}, err
	}
	return CanonicalKeyStateAssertion{precondition: precondition, records: records, digest: digest}, nil
}

func (p *Planner) canonicalKeyStateAssertions(ctx context.Context,
	preconditions []KeyStatePrecondition) ([]CanonicalKeyStateAssertion, error) {
	view, ok := p.iam.(CanonicalGovernanceKeyStateView)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	unique := make(map[string]KeyStatePrecondition, len(preconditions))
	for _, precondition := range preconditions {
		if !validKeyStatePrecondition(precondition) {
			return nil, ErrSnapshotInconsistent
		}
		if prior, exists := unique[precondition.KeyID]; exists && prior != precondition {
			return nil, ErrSnapshotInconsistent
		}
		unique[precondition.KeyID] = precondition
	}
	keys := make([]string, 0, len(unique))
	for keyID := range unique {
		keys = append(keys, keyID)
	}
	sort.Strings(keys)
	result := make([]CanonicalKeyStateAssertion, 0, len(keys))
	for _, keyID := range keys {
		precondition := unique[keyID]
		projection, found, err := view.CanonicalGovernanceKeyState(ctx, precondition)
		if err != nil || !found {
			return nil, ErrSnapshotInconsistent
		}
		assertion, err := newCanonicalKeyStateAssertion(precondition, projection)
		if err != nil {
			return nil, err
		}
		result = append(result, assertion)
	}
	return result, nil
}

func validateCanonicalKeyStateAssertions(value MutationPlanSnapshot) error {
	if !value.CommitReady {
		if len(value.CanonicalKeyStateAssertions) != 0 {
			return ErrSnapshotInconsistent
		}
		return nil
	}
	expected := make(map[string]KeyStatePrecondition, len(value.AuditSourceKeyPreconditions)+len(value.ApprovalKeyPreconditions)+1)
	add := func(precondition KeyStatePrecondition) bool {
		if !validKeyStatePrecondition(precondition) {
			return false
		}
		prior, exists := expected[precondition.KeyID]
		if exists && prior != precondition {
			return false
		}
		expected[precondition.KeyID] = precondition
		return true
	}
	for _, precondition := range value.AuditSourceKeyPreconditions {
		if !add(precondition) {
			return ErrSnapshotInconsistent
		}
	}
	for _, precondition := range value.ApprovalKeyPreconditions {
		if !add(precondition) {
			return ErrSnapshotInconsistent
		}
	}
	if !add(value.AuditWriterKeyPrecondition) || len(expected) != len(value.CanonicalKeyStateAssertions) {
		return ErrSnapshotInconsistent
	}
	priorKeyID := ""
	for _, assertion := range value.CanonicalKeyStateAssertions {
		if assertion.VerifyDigest() != nil || assertion.precondition.KeyID <= priorKeyID ||
			expected[assertion.precondition.KeyID] != assertion.precondition {
			return ErrSnapshotInconsistent
		}
		priorKeyID = assertion.precondition.KeyID
		delete(expected, assertion.precondition.KeyID)
	}
	if len(expected) != 0 {
		return ErrSnapshotInconsistent
	}
	return nil
}

func validateApprovalAdmissionCanonicalReadSet(value ApprovalCollectionPlanSnapshot) error {
	if len(value.CanonicalStateAssertions) != 1 || len(value.CanonicalKeyStateAssertions) != 1 {
		return ErrSnapshotInconsistent
	}
	profile := value.CanonicalStateAssertions[0]
	if profile.VerifyDigest() != nil || profile.record.Kind != CanonicalStateKindGovernanceProfileActivation ||
		profile.record.Version != value.GovernanceProfileActivation.Version ||
		profile.record.ValidFromUnixNano != value.GovernanceProfileActivation.ValidFromUnixNano ||
		profile.record.ValidUntilUnixNano != value.GovernanceProfileActivation.ValidUntilUnixNano {
		return ErrSnapshotInconsistent
	}
	key := value.CanonicalKeyStateAssertions[0]
	if key.VerifyDigest() != nil || key.precondition != value.NextKeyPrecondition {
		return ErrSnapshotInconsistent
	}
	return nil
}

func writeCanonicalStateRecord(w *digestWriter, value CanonicalStateRecord) {
	if !validCanonicalStateRecord(value) {
		w.err = ErrSnapshotInconsistent
		return
	}
	w.uint8(value.Namespace)
	w.string(value.Kind)
	w.string(value.ObjectID)
	w.uint64(value.Version)
	w.digest(value.StateDigestSHA256)
	w.string(value.ContentType)
	w.bytes(value.CanonicalState)
	w.bool(value.Terminal)
	w.string(value.AuditEventID)
	w.bool(value.HasValidityWindow)
	w.int64(value.ValidFromUnixNano)
	w.int64(value.ValidUntilUnixNano)
}

func digestCanonicalStateAssertion(value CanonicalStateRecord) ([ccse.DigestSize]byte, error) {
	w := newDigestWriter(canonicalStateAssertionDigestDomain)
	writeCanonicalStateRecord(w, value)
	return w.sum()
}

func newCanonicalStateAssertion(value CanonicalStateRecord) (CanonicalStateAssertion, error) {
	value = cloneCanonicalStateRecord(value)
	digest, err := digestCanonicalStateAssertion(value)
	if err != nil {
		return CanonicalStateAssertion{}, err
	}
	return CanonicalStateAssertion{record: value, digest: digest}, nil
}

func digestCanonicalStateMutation(expected *CanonicalStateRecord,
	next CanonicalStateRecord) ([ccse.DigestSize]byte, error) {
	w := newDigestWriter(canonicalStateMutationDigestDomain)
	w.bool(expected != nil)
	if expected != nil {
		writeCanonicalStateRecord(w, *expected)
	}
	writeCanonicalStateRecord(w, next)
	if expected == nil {
		if next.Version != 1 {
			w.err = ErrSnapshotInconsistent
		}
	} else if expected.Namespace != next.Namespace || expected.Kind != next.Kind ||
		expected.ObjectID != next.ObjectID || expected.Terminal || next.Version != expected.Version+1 ||
		bytes.Equal(expected.CanonicalState, next.CanonicalState) || expected.StateDigestSHA256 == next.StateDigestSHA256 {
		w.err = ErrSnapshotInconsistent
	}
	return w.sum()
}

func newCanonicalStateMutation(expected *CanonicalStateRecord,
	next CanonicalStateRecord) (CanonicalStateMutation, error) {
	var ownedExpected *CanonicalStateRecord
	if expected != nil {
		copy := cloneCanonicalStateRecord(*expected)
		ownedExpected = &copy
	}
	next = cloneCanonicalStateRecord(next)
	digest, err := digestCanonicalStateMutation(ownedExpected, next)
	if err != nil {
		return CanonicalStateMutation{}, err
	}
	return CanonicalStateMutation{expected: ownedExpected, next: next, digest: digest}, nil
}

func (p *Planner) canonicalProfileAssertion(ctx context.Context,
	activation GovernanceProfileActivationSnapshot) (CanonicalStateAssertion, error) {
	view, ok := p.profiles.(CanonicalGovernanceProfileActivationView)
	if !ok {
		return CanonicalStateAssertion{}, ErrInvalidConfiguration
	}
	record, found, err := view.CanonicalGovernanceProfileActivation(ctx, activation)
	expectedBytes, expectedDigest, expectedObjectID, canonicalErr := canonicalProfileActivationState(activation)
	if err != nil || canonicalErr != nil || !found || record.Namespace != CanonicalStateNamespaceGovernance ||
		record.Kind != CanonicalStateKindGovernanceProfileActivation ||
		record.ContentType != CanonicalStateContentTypeGovernanceProfileActivation ||
		record.ObjectID != expectedObjectID || record.Version != activation.Version ||
		record.StateDigestSHA256 != expectedDigest || !bytes.Equal(record.CanonicalState, expectedBytes) ||
		record.Terminal || !record.HasValidityWindow ||
		record.ValidFromUnixNano != activation.ValidFromUnixNano || record.ValidUntilUnixNano != activation.ValidUntilUnixNano {
		return CanonicalStateAssertion{}, ErrSnapshotInconsistent
	}
	return newCanonicalStateAssertion(record)
}

func canonicalProfileActivationState(activation GovernanceProfileActivationSnapshot) (
	[]byte, [ccse.DigestSize]byte, string, error) {
	if !validGovernanceProfileActivation(activation, activation.ValidFromUnixNano) {
		return nil, [ccse.DigestSize]byte{}, "", ErrSnapshotInconsistent
	}
	canonical, err := ccse.Marshal(256, func(out *ccse.Encoder) {
		out.FixedBytes(activation.GovernanceProfileDigestSHA256[:], ccse.DigestSize)
		out.Uint64(activation.Version)
		out.Int64(activation.ValidFromUnixNano)
		out.Int64(activation.ValidUntilUnixNano)
		out.FixedBytes(activation.EvidenceDigestSHA256[:], ccse.DigestSize)
	})
	if err != nil {
		return nil, [ccse.DigestSize]byte{}, "", ErrSnapshotInconsistent
	}
	return canonical, domainSeparatedContentDigest(canonicalProfileActivationDomain, canonical),
		"governance-profile:" + hex.EncodeToString(activation.GovernanceProfileDigestSHA256[:]), nil
}

func (p *Planner) canonicalPolicyMutation(ctx context.Context, policy MutationPlanSnapshot) (CanonicalStateMutation, error) {
	if len(policy.ApprovalEvidence) == 0 || policy.ApprovalEvidence[0].record.MessageTypeID != schema.MessageTypePolicyBundle ||
		len(policy.ApprovalEvidence[0].record.Payload) == 0 ||
		sha256.Sum256(policy.ApprovalEvidence[0].record.Payload) != policy.PolicyBundleDigestSHA256 {
		return CanonicalStateMutation{}, ErrSnapshotInconsistent
	}
	view, ok := p.policies.(CanonicalGovernancePolicyRegistryView)
	if !ok {
		return CanonicalStateMutation{}, ErrInvalidConfiguration
	}
	request := CanonicalPolicyRegistryTransition{
		Action: policy.Kind, PolicyKind: policy.PolicyKind, PolicyBundleID: policy.PolicyBundleID,
		PolicyRecordID: policy.PolicyRecordID, PolicySequence: policy.PolicySequence,
		PolicyBundleDigestSHA256: policy.PolicyBundleDigestSHA256,
		CanonicalPolicyBundle:    append([]byte(nil), policy.ApprovalEvidence[0].record.Payload...),
		AuditEventID:             policy.AuditEventID, ExpectedHeadPresent: policy.ExpectedPolicyHeadPresent,
		ExpectedHeadSequence:           policy.ExpectedPolicyHeadSequence,
		ExpectedHeadBundleDigestSHA256: policy.ExpectedPolicyHeadDigest,
		GovernanceProfileActivation:    policy.GovernanceProfileActivation,
	}
	expected, found, next, err := view.CanonicalGovernancePolicyRegistryTransition(ctx, request)
	if err != nil || found != policy.ExpectedPolicyHeadPresent || (!found && !isZeroCanonicalStateRecord(expected)) {
		return CanonicalStateMutation{}, ErrSnapshotInconsistent
	}
	if found && (expected.Kind != CanonicalStateKindGovernancePolicyRegistry ||
		expected.ObjectID != policy.PolicyKind || expected.Version != policy.ExpectedPolicyHeadSequence ||
		expected.StateDigestSHA256 != policy.ExpectedPolicyHeadDigest ||
		sha256.Sum256(expected.CanonicalState) != policy.ExpectedPolicyHeadDigest) {
		return CanonicalStateMutation{}, ErrSnapshotInconsistent
	}
	if next.Kind != CanonicalStateKindGovernancePolicyRegistry || next.ObjectID != policy.PolicyKind ||
		next.Version != policy.PolicySequence || next.AuditEventID != policy.AuditEventID ||
		next.StateDigestSHA256 != policy.PolicyBundleDigestSHA256 ||
		!bytes.Equal(next.CanonicalState, request.CanonicalPolicyBundle) {
		return CanonicalStateMutation{}, ErrSnapshotInconsistent
	}
	if found {
		return newCanonicalStateMutation(&expected, next)
	}
	return newCanonicalStateMutation(nil, next)
}

func isZeroCanonicalStateRecord(value CanonicalStateRecord) bool {
	return value.Namespace == 0 && value.Kind == "" && value.ObjectID == "" && value.Version == 0 &&
		isZeroDigest(value.StateDigestSHA256) && value.ContentType == "" && len(value.CanonicalState) == 0 &&
		!value.Terminal && value.AuditEventID == "" && !value.HasValidityWindow &&
		value.ValidFromUnixNano == 0 && value.ValidUntilUnixNano == 0
}

func equalCanonicalStateRecords(left, right CanonicalStateRecord) bool {
	return left.Namespace == right.Namespace && left.Kind == right.Kind && left.ObjectID == right.ObjectID &&
		left.Version == right.Version && left.StateDigestSHA256 == right.StateDigestSHA256 &&
		left.ContentType == right.ContentType && bytes.Equal(left.CanonicalState, right.CanonicalState) &&
		left.Terminal == right.Terminal && left.AuditEventID == right.AuditEventID &&
		left.HasValidityWindow == right.HasValidityWindow && left.ValidFromUnixNano == right.ValidFromUnixNano &&
		left.ValidUntilUnixNano == right.ValidUntilUnixNano
}

func equalCanonicalStateAssertions(left, right CanonicalStateAssertion) bool {
	return left.digest == right.digest && equalCanonicalStateRecords(left.record, right.record)
}

func equalCanonicalStateMutations(left, right CanonicalStateMutation) bool {
	if left.digest != right.digest || (left.expected == nil) != (right.expected == nil) ||
		!equalCanonicalStateRecords(left.next, right.next) {
		return false
	}
	return left.expected == nil || equalCanonicalStateRecords(*left.expected, *right.expected)
}

func cloneCanonicalStateAssertions(input []CanonicalStateAssertion) []CanonicalStateAssertion {
	result := make([]CanonicalStateAssertion, len(input))
	for index := range input {
		result[index] = CanonicalStateAssertion{
			record: cloneCanonicalStateRecord(input[index].record), digest: input[index].digest,
		}
	}
	return result
}

func cloneCanonicalKeyStateAssertions(input []CanonicalKeyStateAssertion) []CanonicalKeyStateAssertion {
	result := make([]CanonicalKeyStateAssertion, len(input))
	for index := range input {
		result[index].precondition = input[index].precondition
		result[index].records = cloneCanonicalStateAssertions(input[index].records)
		result[index].digest = input[index].digest
	}
	return result
}

func cloneCanonicalAuditWriterLeaseAssertion(input CanonicalAuditWriterLeaseAssertion) CanonicalAuditWriterLeaseAssertion {
	input.record.record = cloneCanonicalStateRecord(input.record.record)
	return input
}

func cloneCanonicalStateMutations(input []CanonicalStateMutation) []CanonicalStateMutation {
	result := make([]CanonicalStateMutation, len(input))
	for index := range input {
		result[index].next = cloneCanonicalStateRecord(input[index].next)
		result[index].digest = input[index].digest
		if input[index].expected != nil {
			expected := cloneCanonicalStateRecord(*input[index].expected)
			result[index].expected = &expected
		}
	}
	return result
}
