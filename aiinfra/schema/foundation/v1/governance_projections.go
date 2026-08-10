// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

const (
	policyBundleMaxPayload = 49152
	auditEventMaxPayload   = 65536
)

var (
	policyBundleSigningFields = [...]string{
		"metadata", "policy_bundle_id", "policy_kind", "policy_version", "sequence",
		"predecessor_digest_sha256", "approved_at_unix_nano", "effective_at_unix_nano",
		"expires_at_unix_nano", "policy_document_digest_sha256", "policy_document_media_type",
		"approver_identities", "approver_key_ids", "minimum_approvals", "emergency",
		"rollback_target_digest_sha256", "break_glass_expires_at_unix_nano", "state",
	}
	auditEventSigningFields = [...]string{
		"metadata", "audit_event_id", "event_type", "actor_identity", "actor_key_id", "subject_ids",
		"cause_code", "correlation_id", "causation_id", "occurred_at_unix_nano", "outcome",
		"applied_policy_digests_sha256", "evidence_digests_sha256", "redacted_details_digest_sha256",
		"previous_event_digest_sha256", "audit_sequence",
	}
)

type PolicyBundleSigningProjection struct {
	Metadata                    RecordMetadataSigningProjection
	PolicyBundleID              string
	PolicyKind                  string
	PolicyVersion               SchemaVersionSigningProjection
	Sequence                    uint64
	PredecessorDigestSHA256     OptionalFixedBytes32
	ApprovedAtUnixNano          int64
	EffectiveAtUnixNano         int64
	ExpiresAtUnixNano           int64
	PolicyDocumentDigestSHA256  [32]byte
	PolicyDocumentMediaType     string
	ApproverIdentities          []string
	ApproverKeyIDs              []string
	MinimumApprovals            uint32
	Emergency                   bool
	RollbackTargetDigestSHA256  OptionalFixedBytes32
	BreakGlassExpiresAtUnixNano OptionalInt64
	State                       uint32
}

type AuditEventSigningProjection struct {
	Metadata                    RecordMetadataSigningProjection
	AuditEventID                string
	EventType                   string
	ActorIdentity               string
	ActorKeyID                  string
	SubjectIDs                  []string
	CauseCode                   string
	CorrelationID               [16]byte
	CausationID                 OptionalFixedBytes16
	OccurredAtUnixNano          int64
	Outcome                     uint32
	AppliedPolicyDigestsSHA256  [][32]byte
	EvidenceDigestsSHA256       [][32]byte
	RedactedDetailsDigestSHA256 OptionalFixedBytes32
	PreviousEventDigestSHA256   [32]byte
	AuditSequence               uint64
}

func (p PolicyBundleSigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"policy_bundle_id", p.PolicyBundleID, 256}, {"policy_kind", p.PolicyKind, 128},
		{"policy_document_media_type", p.PolicyDocumentMediaType, 128},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	if p.PolicyVersion.Major == 0 {
		return nil, fmt.Errorf("%w: policy_version.major is zero", ErrInvalidProjectionValue)
	}
	if err := validatePositive("sequence", p.Sequence); err != nil {
		return nil, err
	}
	if err := validateOptionalFixed32("predecessor_digest_sha256", p.PredecessorDigestSHA256); err != nil {
		return nil, err
	}
	if (p.Sequence == 1) == p.PredecessorDigestSHA256.Present {
		return nil, fmt.Errorf("%w: predecessor presence does not match sequence", ErrInvalidProjectionValue)
	}
	if err := validateRequiredFixed32("policy_document_digest_sha256", p.PolicyDocumentDigestSHA256); err != nil {
		return nil, err
	}
	if p.ApprovedAtUnixNano < 0 || p.EffectiveAtUnixNano < p.ApprovedAtUnixNano || p.ExpiresAtUnixNano <= p.EffectiveAtUnixNano {
		return nil, fmt.Errorf("%w: policy approval/effective/expiry", ErrInvalidTimeRange)
	}
	approvers, err := canonicalStringSetField("approver_identities", p.ApproverIdentities, 64, 17408, true)
	if err != nil {
		return nil, err
	}
	approverKeys, err := canonicalStringSetField("approver_key_ids", p.ApproverKeyIDs, 64, 17408, true)
	if err != nil {
		return nil, err
	}
	if p.MinimumApprovals == 0 || int(p.MinimumApprovals) > len(p.ApproverIdentities) || int(p.MinimumApprovals) > len(p.ApproverKeyIDs) {
		return nil, fmt.Errorf("%w: minimum_approvals", ErrInvalidProjectionValue)
	}
	if len(p.ApproverIdentities) != len(p.ApproverKeyIDs) {
		return nil, fmt.Errorf("%w: approver identity/key cardinality differs", ErrInvalidProjectionValue)
	}
	if err := validateOptionalFixed32("rollback_target_digest_sha256", p.RollbackTargetDigestSHA256); err != nil {
		return nil, err
	}
	if err := validateOptionalInt64("break_glass_expires_at_unix_nano", p.BreakGlassExpiresAtUnixNano); err != nil {
		return nil, err
	}
	if p.Emergency != p.BreakGlassExpiresAtUnixNano.Present {
		return nil, fmt.Errorf("%w: emergency and break-glass expiry presence differ", ErrInvalidProjectionValue)
	}
	if p.BreakGlassExpiresAtUnixNano.Present && (p.BreakGlassExpiresAtUnixNano.Value <= p.EffectiveAtUnixNano || p.BreakGlassExpiresAtUnixNano.Value > p.ExpiresAtUnixNano) {
		return nil, fmt.Errorf("%w: break-glass expiry", ErrInvalidTimeRange)
	}
	if err := validateEnumRange("state", p.State, 1, 6); err != nil {
		return nil, err
	}
	if p.State == 4 && !p.RollbackTargetDigestSHA256.Present {
		return nil, fmt.Errorf("%w: rolled-back policy lacks rollback target", ErrInvalidProjectionValue)
	}
	if p.RollbackTargetDigestSHA256.Present && (p.RollbackTargetDigestSHA256.Value == p.PolicyDocumentDigestSHA256 ||
		(p.PredecessorDigestSHA256.Present && p.RollbackTargetDigestSHA256.Value == p.PredecessorDigestSHA256.Value)) {
		return nil, fmt.Errorf("%w: rollback target does not identify a distinct policy", ErrInvalidProjectionValue)
	}
	return ccse.Marshal(policyBundleMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.PolicyBundleID)
		out.String(p.PolicyKind)
		out.Uint32(p.PolicyVersion.Major)
		out.Uint32(p.PolicyVersion.Minor)
		out.Uint64(p.Sequence)
		encodeOptionalFixed32(out, p.PredecessorDigestSHA256)
		out.Int64(p.ApprovedAtUnixNano)
		out.Int64(p.EffectiveAtUnixNano)
		out.Int64(p.ExpiresAtUnixNano)
		out.FixedBytes(p.PolicyDocumentDigestSHA256[:], len(p.PolicyDocumentDigestSHA256))
		out.String(p.PolicyDocumentMediaType)
		out.EncodedSet(approvers)
		out.EncodedSet(approverKeys)
		out.Uint32(p.MinimumApprovals)
		out.Bool(p.Emergency)
		encodeOptionalFixed32(out, p.RollbackTargetDigestSHA256)
		out.Bool(p.BreakGlassExpiresAtUnixNano.Present)
		if p.BreakGlassExpiresAtUnixNano.Present {
			out.Int64(p.BreakGlassExpiresAtUnixNano.Value)
		}
		out.Uint32(p.State)
	})
}

func (PolicyBundleSigningProjection) MessageTypeID() uint32 { return schema.MessageTypePolicyBundle }
func (PolicyBundleSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(policyBundleSigningFields[:])
}

func (p AuditEventSigningProjection) CanonicalBytes() ([]byte, error) {
	metadata, err := p.Metadata.prepare()
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"audit_event_id", p.AuditEventID, 256}, {"event_type", p.EventType, 128},
		{"actor_identity", p.ActorIdentity, 1024}, {"actor_key_id", p.ActorKeyID, 256}, {"cause_code", p.CauseCode, 128},
	} {
		if err := validateRequiredStringField(field.name, field.value, field.max); err != nil {
			return nil, err
		}
	}
	subjects, err := canonicalStringSetField("subject_ids", p.SubjectIDs, 128, 33792, true)
	if err != nil {
		return nil, err
	}
	if err := validateRequiredFixed16("correlation_id", p.CorrelationID); err != nil {
		return nil, err
	}
	if err := validateOptionalFixed16("causation_id", p.CausationID); err != nil {
		return nil, err
	}
	if err := validateTimestamp("occurred_at_unix_nano", p.OccurredAtUnixNano); err != nil {
		return nil, err
	}
	if p.OccurredAtUnixNano > p.Metadata.CreatedAtUnixNano {
		return nil, fmt.Errorf("%w: audit occurred after record creation", ErrInvalidTimeRange)
	}
	if err := validateEnumRange("outcome", p.Outcome, 1, 4); err != nil {
		return nil, err
	}
	policies, err := canonicalDigestSetField("applied_policy_digests_sha256", p.AppliedPolicyDigestsSHA256, 64, 2564, true)
	if err != nil {
		return nil, err
	}
	evidence, err := canonicalDigestSetField("evidence_digests_sha256", p.EvidenceDigestsSHA256, 128, 5124, true)
	if err != nil {
		return nil, err
	}
	if err := validateOptionalFixed32("redacted_details_digest_sha256", p.RedactedDetailsDigestSHA256); err != nil {
		return nil, err
	}
	if err := validateRequiredFixed32("previous_event_digest_sha256", p.PreviousEventDigestSHA256); err != nil {
		return nil, err
	}
	if err := validatePositive("audit_sequence", p.AuditSequence); err != nil {
		return nil, err
	}
	return ccse.Marshal(auditEventMaxPayload, func(out *ccse.Encoder) {
		metadata.encode(out)
		out.String(p.AuditEventID)
		out.String(p.EventType)
		out.String(p.ActorIdentity)
		out.String(p.ActorKeyID)
		out.EncodedSet(subjects)
		out.String(p.CauseCode)
		out.FixedBytes(p.CorrelationID[:], len(p.CorrelationID))
		encodeOptionalFixed16(out, p.CausationID)
		out.Int64(p.OccurredAtUnixNano)
		out.Uint32(p.Outcome)
		out.EncodedSet(policies)
		out.EncodedSet(evidence)
		encodeOptionalFixed32(out, p.RedactedDetailsDigestSHA256)
		out.FixedBytes(p.PreviousEventDigestSHA256[:], len(p.PreviousEventDigestSHA256))
		out.Uint64(p.AuditSequence)
	})
}

func (AuditEventSigningProjection) MessageTypeID() uint32 { return schema.MessageTypeAuditEvent }
func (AuditEventSigningProjection) SigningFieldNames() []string {
	return copyFieldNames(auditEventSigningFields[:])
}
