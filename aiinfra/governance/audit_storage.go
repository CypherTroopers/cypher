// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"crypto/sha256"
	"reflect"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	foundationcanonical "github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const canonicalAuditAppendCapabilityDigestDomain = "CPH-AIIE-GOVERNANCE-CANONICAL-AUDIT-APPEND-CAPABILITY-V1\x00"

func newCanonicalAuditAppendCapability(value MutationPlanSnapshot,
	event foundationv1.AuditEventSigningProjection) (CanonicalAuditAppendCapability, error) {
	record := value.AuditEventEvidence.record
	if record.MessageTypeID != schema.MessageTypeAuditEvent || value.AuditEventEvidence.recordDigest == ([ccse.DigestSize]byte{}) {
		return CanonicalAuditAppendCapability{}, ErrAuditAnchor
	}
	result := CanonicalAuditAppendCapability{
		eventID: value.AuditEventID, streamID: value.AuditStreamID, sequence: value.NextAuditSequence,
		eventDigest: record.Envelope.PayloadDigest, recordDigest: value.NextAuditRecordDigestSHA256,
		canonicalEvent: append([]byte(nil), record.Payload...), occurredAtUnixNano: event.OccurredAtUnixNano,
		deploymentAnchorDigest:              value.DeploymentAnchorSHA256,
		expectedHeadWriterIdentity:          value.ExpectedAuditHeadWriterIdentity,
		authorizedWriterIdentity:            value.AuthorizedAuditWriterIdentity,
		expectedHeadHomeRegion:              value.ExpectedAuditHeadHomeRegion,
		authorizedHomeRegion:                value.AuthorizedAuditHomeRegion,
		expectedHeadWriterEpoch:             value.ExpectedAuditHeadWriterEpoch,
		authorizedWriterEpoch:               value.AuthorizedAuditWriterEpoch,
		expectedHeadGovernanceProfileDigest: value.ExpectedAuditHeadGovernanceProfileDigestSHA256,
		authorizedGovernanceProfileDigest:   value.AuthorizedAuditGovernanceProfileDigestSHA256,
		writerLeaseEvidenceDigest:           value.ExpectedAuditWriterLeaseEvidenceDigestSHA256,
		writerLeaseNotBeforeUnixNano:        value.ExpectedAuditWriterLeaseNotBeforeUnixNano,
		writerLeaseNotAfterUnixNano:         value.ExpectedAuditWriterLeaseNotAfterUnixNano,
	}
	if result.sequence > 1 {
		result.hasPrevious = true
		result.previousEventDigest = value.ExpectedAuditHeadDigest
	}
	var err error
	result.digest, err = digestCanonicalAuditAppendCapability(result)
	if err != nil || event.AuditEventID != result.eventID || event.AuditSequence != result.sequence ||
		event.PreviousEventDigestSHA256 != expectedAuditPreviousDigest(value) {
		return CanonicalAuditAppendCapability{}, ErrAuditAnchor
	}
	return result, nil
}

func expectedAuditPreviousDigest(value MutationPlanSnapshot) [ccse.DigestSize]byte {
	if value.ExpectedAuditSequence == 0 {
		return value.DeploymentAnchorSHA256
	}
	return value.ExpectedAuditHeadDigest
}

func digestCanonicalAuditAppendCapability(value CanonicalAuditAppendCapability) ([ccse.DigestSize]byte, error) {
	if !validDurableEvidenceStorageText(value.eventID, 1024) ||
		!validDurableEvidenceStorageText(value.streamID, 255) || value.sequence == 0 ||
		isZeroDigest(value.eventDigest) || isZeroDigest(value.recordDigest) ||
		len(value.canonicalEvent) == 0 || len(value.canonicalEvent) > 8<<20 ||
		sha256.Sum256(value.canonicalEvent) != value.eventDigest || value.occurredAtUnixNano <= 0 ||
		(value.sequence == 1 && (value.hasPrevious || !isZeroDigest(value.previousEventDigest))) ||
		(value.sequence > 1 && (!value.hasPrevious || isZeroDigest(value.previousEventDigest))) ||
		isZeroDigest(value.deploymentAnchorDigest) ||
		!validDurableEvidenceStorageText(value.authorizedWriterIdentity, 1024) ||
		!validDurableEvidenceStorageText(value.authorizedHomeRegion, 255) ||
		value.authorizedWriterEpoch == 0 || isZeroDigest(value.authorizedGovernanceProfileDigest) ||
		isZeroDigest(value.writerLeaseEvidenceDigest) || value.writerLeaseNotBeforeUnixNano < 0 ||
		value.writerLeaseNotAfterUnixNano <= value.writerLeaseNotBeforeUnixNano ||
		value.occurredAtUnixNano < value.writerLeaseNotBeforeUnixNano ||
		value.occurredAtUnixNano >= value.writerLeaseNotAfterUnixNano {
		return [ccse.DigestSize]byte{}, ErrAuditAnchor
	}
	if value.sequence == 1 {
		if value.expectedHeadWriterIdentity != "" || value.expectedHeadHomeRegion != "" ||
			value.expectedHeadWriterEpoch != 0 || !isZeroDigest(value.expectedHeadGovernanceProfileDigest) {
			return [ccse.DigestSize]byte{}, ErrAuditAnchor
		}
	} else if !validDurableEvidenceStorageText(value.expectedHeadWriterIdentity, 1024) ||
		!validDurableEvidenceStorageText(value.expectedHeadHomeRegion, 255) || value.expectedHeadWriterEpoch == 0 ||
		isZeroDigest(value.expectedHeadGovernanceProfileDigest) {
		return [ccse.DigestSize]byte{}, ErrAuditAnchor
	}
	w := newDigestWriter(canonicalAuditAppendCapabilityDigestDomain)
	w.string(value.eventID)
	w.string(value.streamID)
	w.uint64(value.sequence)
	w.bool(value.hasPrevious)
	w.digest(value.previousEventDigest)
	w.digest(value.eventDigest)
	w.digest(value.recordDigest)
	w.bytes(value.canonicalEvent)
	w.int64(value.occurredAtUnixNano)
	w.digest(value.deploymentAnchorDigest)
	w.string(value.expectedHeadWriterIdentity)
	w.string(value.authorizedWriterIdentity)
	w.string(value.expectedHeadHomeRegion)
	w.string(value.authorizedHomeRegion)
	w.uint64(value.expectedHeadWriterEpoch)
	w.uint64(value.authorizedWriterEpoch)
	w.digest(value.expectedHeadGovernanceProfileDigest)
	w.digest(value.authorizedGovernanceProfileDigest)
	w.digest(value.writerLeaseEvidenceDigest)
	w.int64(value.writerLeaseNotBeforeUnixNano)
	w.int64(value.writerLeaseNotAfterUnixNano)
	return w.sum()
}

func validateCanonicalAuditAppend(value MutationPlanSnapshot) error {
	if !value.CommitReady {
		if !zeroCanonicalAuditAppendCapability(value.CanonicalAuditAppend) {
			return ErrAuditAnchor
		}
		return nil
	}
	if value.CanonicalAuditAppend.VerifyDigest() != nil {
		return ErrAuditAnchor
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return ErrAuditAnchor
	}
	decoded, err := validator.Decode(schema.MessageTypeAuditEvent, value.AuditEventEvidence.record.SchemaVersion,
		value.AuditEventEvidence.record.Payload)
	event, ok := decoded.(foundationv1.AuditEventSigningProjection)
	if err != nil || !ok {
		return ErrAuditAnchor
	}
	expected, err := newCanonicalAuditAppendCapability(value, event)
	if err != nil || !equalCanonicalAuditAppendCapabilities(expected, value.CanonicalAuditAppend) {
		return ErrAuditAnchor
	}
	return nil
}

func zeroCanonicalAuditAppendCapability(value CanonicalAuditAppendCapability) bool {
	return value.eventID == "" && value.streamID == "" && value.sequence == 0 &&
		isZeroDigest(value.previousEventDigest) && !value.hasPrevious && isZeroDigest(value.eventDigest) &&
		isZeroDigest(value.recordDigest) && len(value.canonicalEvent) == 0 && value.occurredAtUnixNano == 0 &&
		isZeroDigest(value.deploymentAnchorDigest) && value.expectedHeadWriterIdentity == "" &&
		value.authorizedWriterIdentity == "" && value.expectedHeadHomeRegion == "" &&
		value.authorizedHomeRegion == "" && value.expectedHeadWriterEpoch == 0 &&
		value.authorizedWriterEpoch == 0 && isZeroDigest(value.expectedHeadGovernanceProfileDigest) &&
		isZeroDigest(value.authorizedGovernanceProfileDigest) && isZeroDigest(value.writerLeaseEvidenceDigest) &&
		value.writerLeaseNotBeforeUnixNano == 0 && value.writerLeaseNotAfterUnixNano == 0 && isZeroDigest(value.digest)
}

func equalCanonicalAuditAppendCapabilities(left, right CanonicalAuditAppendCapability) bool {
	leftBytes, rightBytes := left.canonicalEvent, right.canonicalEvent
	left.canonicalEvent, right.canonicalEvent = nil, nil
	return reflect.DeepEqual(left, right) && bytes.Equal(leftBytes, rightBytes)
}

func cloneCanonicalAuditAppendCapability(value CanonicalAuditAppendCapability) CanonicalAuditAppendCapability {
	value.canonicalEvent = append([]byte(nil), value.canonicalEvent...)
	return value
}
