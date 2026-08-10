// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package canonical

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func decodePolicyBundle(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	policyBundleID := decoder.String(2, "policy_bundle_id")
	policyKind := decoder.String(3, "policy_kind")
	if !decoder.InlineMessage(4, "policy_version", schemaVersionType) {
		return nil, decoder.FinishFields()
	}
	policyVersion, versionErr := decodeSchemaVersion(in, v.nested.schemaVersion)
	decoder.record(versionErr)
	value := foundationv1.PolicyBundleSigningProjection{
		Metadata:                    metadata,
		PolicyBundleID:              policyBundleID,
		PolicyKind:                  policyKind,
		PolicyVersion:               policyVersion,
		Sequence:                    decoder.Uint64(5, "sequence"),
		PredecessorDigestSHA256:     decoder.OptionalFixed32(6, "predecessor_digest_sha256"),
		ApprovedAtUnixNano:          decoder.Int64(7, "approved_at_unix_nano"),
		EffectiveAtUnixNano:         decoder.Int64(8, "effective_at_unix_nano"),
		ExpiresAtUnixNano:           decoder.Int64(9, "expires_at_unix_nano"),
		PolicyDocumentDigestSHA256:  decoder.Fixed32(10, "policy_document_digest_sha256"),
		PolicyDocumentMediaType:     decoder.String(11, "policy_document_media_type"),
		ApproverIdentities:          decoder.StringSet(12, "approver_identities"),
		ApproverKeyIDs:              decoder.StringSet(13, "approver_key_ids"),
		MinimumApprovals:            decoder.Uint32(14, "minimum_approvals"),
		Emergency:                   decoder.Bool(15, "emergency"),
		RollbackTargetDigestSHA256:  decoder.OptionalFixed32(16, "rollback_target_digest_sha256"),
		BreakGlassExpiresAtUnixNano: decoder.OptionalInt64(17, "break_glass_expires_at_unix_nano"),
		State:                       decoder.Enum(18, "state", 1, 6),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeAuditEvent(v *Validator, in *ccse.Decoder, rules projectionRules) (Payload, error) {
	decoder := newProjectionDecoder(in, rules)
	metadata, _ := decodeMetadataField(v, decoder)
	value := foundationv1.AuditEventSigningProjection{
		Metadata:                    metadata,
		AuditEventID:                decoder.String(2, "audit_event_id"),
		EventType:                   decoder.String(3, "event_type"),
		ActorIdentity:               decoder.String(4, "actor_identity"),
		ActorKeyID:                  decoder.String(5, "actor_key_id"),
		SubjectIDs:                  decoder.StringSet(6, "subject_ids"),
		CauseCode:                   decoder.String(7, "cause_code"),
		CorrelationID:               decoder.Fixed16(8, "correlation_id"),
		CausationID:                 decoder.OptionalFixed16(9, "causation_id"),
		OccurredAtUnixNano:          decoder.Int64(10, "occurred_at_unix_nano"),
		Outcome:                     decoder.Enum(11, "outcome", 1, 4),
		AppliedPolicyDigestsSHA256:  decoder.Fixed32Set(12, "applied_policy_digests_sha256"),
		EvidenceDigestsSHA256:       decoder.Fixed32Set(13, "evidence_digests_sha256"),
		RedactedDetailsDigestSHA256: decoder.OptionalFixed32(14, "redacted_details_digest_sha256"),
		PreviousEventDigestSHA256:   decoder.Fixed32(15, "previous_event_digest_sha256"),
		AuditSequence:               decoder.Uint64(16, "audit_sequence"),
	}
	if err := decoder.FinishFields(); err != nil {
		return nil, err
	}
	return value, nil
}
