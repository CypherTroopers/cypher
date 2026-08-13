// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"math"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	durablePendingRevisionCapabilityDigestDomain = "CPH-AIIE-GOVERNANCE-DURABLE-PENDING-REVISION-CAPABILITY-V1\x00"
	durablePendingTerminalTemplateDigestDomain   = "CPH-AIIE-GOVERNANCE-DURABLE-PENDING-TERMINAL-TEMPLATE-V1\x00"
	durablePendingTerminalOutcomeUnsetSentinel   = "OUTCOME-DIGEST-UNSET-V1"
	durablePendingTerminalTemplateVersion        = uint32(1)
)

func clonePolicyApprovalCollectionPersistenceSnapshot(value PolicyApprovalCollectionPersistenceSnapshot) PolicyApprovalCollectionPersistenceSnapshot {
	value.CanonicalEnvelope = append([]byte(nil), value.CanonicalEnvelope...)
	value.EvidenceDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.EvidenceDigestsSHA256...)
	return value
}

func (p *Planner) policyApprovalPersistenceSnapshot(ctx context.Context, binding idempotency.Binding,
	expected idempotency.Snapshot, entries []PolicyApprovalCollectionEntry) (PolicyApprovalCollectionPersistenceSnapshot, error) {
	view, ok := p.collections.(PolicyApprovalCollectionPersistenceView)
	if !ok {
		return PolicyApprovalCollectionPersistenceSnapshot{}, ErrApprovalCollection
	}
	actual, found, err := view.SnapshotPolicyApprovalCollectionPersistence(ctx, binding.Key)
	if err != nil || !found {
		return PolicyApprovalCollectionPersistenceSnapshot{}, ErrApprovalCollection
	}
	return validatePolicyApprovalPersistenceSnapshot(actual, binding, expected, entries)
}

func validatePolicyApprovalPersistenceSnapshot(actual PolicyApprovalCollectionPersistenceSnapshot,
	binding idempotency.Binding, expected idempotency.Snapshot,
	entries []PolicyApprovalCollectionEntry) (PolicyApprovalCollectionPersistenceSnapshot, error) {
	actual = clonePolicyApprovalCollectionPersistenceSnapshot(actual)
	if expected.Validate() != nil || expected.Binding != binding || expected.State != idempotency.StateCollecting ||
		actual.PendingKey != binding.Key || actual.Revision != expected.Version ||
		actual.Status != DurablePendingOpen || !isZeroDigest(actual.TerminalOutcomeDigestSHA256) {
		return PolicyApprovalCollectionPersistenceSnapshot{}, ErrApprovalCollection
	}
	encoded, err := EncodePolicyApprovalCollection(binding, expected.Version, expected.ProgressDigest, entries)
	if err != nil || actual.Kind != DurablePendingGovernancePolicyApprovalCollection ||
		actual.Codec != DurablePolicyApprovalCollectionCodec ||
		actual.CodecVersion != DurablePolicyApprovalCollectionCodecVersion ||
		actual.EnvelopeDigestSHA256 != encoded.Digest() ||
		!bytes.Equal(actual.CanonicalEnvelope, encoded.Bytes()) ||
		!equalDigestSets(actual.EvidenceDigestsSHA256, encoded.EvidenceDigests()) ||
		actual.CommitNotBeforeUnixNano <= 0 || actual.CommitNotAfterUnixNano < actual.CommitNotBeforeUnixNano ||
		!validDurableEvidenceStorageText(actual.ExpectedAuditEventID, 1024) {
		return PolicyApprovalCollectionPersistenceSnapshot{}, ErrApprovalCollection
	}
	if (actual.Revision == 1 && !isZeroDigest(actual.PreviousEnvelopeDigestSHA256)) ||
		(actual.Revision > 1 && isZeroDigest(actual.PreviousEnvelopeDigestSHA256)) {
		return PolicyApprovalCollectionPersistenceSnapshot{}, ErrApprovalCollection
	}
	return actual, nil
}

func (p *Planner) buildOpenPolicyApprovalPendingRevision(ctx context.Context,
	binding idempotency.Binding, prior idempotency.Snapshot, priorEntries []PolicyApprovalCollectionEntry,
	nextRevision uint64, nextProgress [ccse.DigestSize]byte, nextEntries []PolicyApprovalCollectionEntry,
	commitNotBefore, commitNotAfter int64, eventID string) (DurablePendingRevisionCapability, error) {
	if binding.Validate() != nil || nextRevision == 0 || isZeroDigest(nextProgress) ||
		commitNotBefore <= 0 || commitNotAfter < commitNotBefore ||
		!validDurableEvidenceStorageText(eventID, 1024) {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	next, err := EncodePolicyApprovalCollection(binding, nextRevision, nextProgress, nextEntries)
	if err != nil {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	result := DurablePendingRevisionCapability{
		pendingKey: binding.Key, kind: DurablePendingGovernancePolicyApprovalCollection,
		codec: DurablePolicyApprovalCollectionCodec, codecVersion: DurablePolicyApprovalCollectionCodecVersion,
		revision: nextRevision, envelopeDigest: next.Digest(), canonicalEnvelope: next.Bytes(),
		evidenceDigests: next.EvidenceDigests(), status: DurablePendingOpen,
		commitNotBeforeUnixNano: commitNotBefore, commitNotAfterUnixNano: commitNotAfter,
		expectedAuditEventID: eventID,
	}
	view, ok := p.collections.(PolicyApprovalCollectionPersistenceView)
	if !ok {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	stored, found, snapshotErr := view.SnapshotPolicyApprovalCollectionPersistence(ctx, binding.Key)
	if snapshotErr != nil {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	if nextRevision == 1 {
		if found || !zeroPolicyApprovalCollectionPersistenceSnapshot(stored) || prior != (idempotency.Snapshot{}) || len(priorEntries) != 0 {
			return DurablePendingRevisionCapability{}, ErrApprovalCollection
		}
	} else {
		if !found || prior.Validate() != nil || prior.Binding != binding || prior.State != idempotency.StateCollecting ||
			prior.Version == math.MaxUint64 || nextRevision != prior.Version+1 {
			return DurablePendingRevisionCapability{}, ErrApprovalCollection
		}
		validated, validateErr := validatePolicyApprovalPersistenceSnapshot(stored, binding, prior, priorEntries)
		if validateErr != nil || stored.EnvelopeDigestSHA256 != validated.EnvelopeDigestSHA256 ||
			!bytes.Equal(stored.CanonicalEnvelope, validated.CanonicalEnvelope) {
			return DurablePendingRevisionCapability{}, ErrApprovalCollection
		}
		result.expectedKind = DurablePendingGovernancePolicyApprovalCollection
		result.previousEnvelopeDigest = validated.EnvelopeDigestSHA256
		result.previousCanonicalEnvelope = append([]byte(nil), validated.CanonicalEnvelope...)
		result.previousCommitNotBeforeUnixNano = validated.CommitNotBeforeUnixNano
		result.previousCommitNotAfterUnixNano = validated.CommitNotAfterUnixNano
		result.sourcePreviousEnvelopeDigest = validated.PreviousEnvelopeDigestSHA256
		result.sourceEvidenceDigests = append([][ccse.DigestSize]byte(nil), validated.EvidenceDigestsSHA256...)
	}
	result.digest, err = digestDurablePendingRevisionCapability(result)
	if err != nil {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	return result, nil
}

func zeroPolicyApprovalCollectionPersistenceSnapshot(value PolicyApprovalCollectionPersistenceSnapshot) bool {
	return value.PendingKey == ([ccse.MessageIDSize]byte{}) && value.Kind == 0 && value.Codec == "" &&
		value.CodecVersion == 0 && value.Revision == 0 && isZeroDigest(value.EnvelopeDigestSHA256) &&
		isZeroDigest(value.PreviousEnvelopeDigestSHA256) &&
		len(value.CanonicalEnvelope) == 0 && len(value.EvidenceDigestsSHA256) == 0 && value.Status == 0 &&
		value.CommitNotBeforeUnixNano == 0 && value.CommitNotAfterUnixNano == 0 &&
		isZeroDigest(value.TerminalOutcomeDigestSHA256) && value.ExpectedAuditEventID == ""
}

func (p *Planner) buildPolicyApprovalTerminalTemplate(ctx context.Context, binding idempotency.Binding,
	current idempotency.Snapshot, entries []PolicyApprovalCollectionEntry,
	eventID string) (DurablePendingTerminalTemplate, error) {
	stored, err := p.policyApprovalPersistenceSnapshot(ctx, binding, current, entries)
	if err != nil || current.Version == math.MaxUint64 || stored.ExpectedAuditEventID != eventID {
		return DurablePendingTerminalTemplate{}, ErrApprovalCollection
	}
	base := DurablePendingRevisionCapability{
		pendingKey: binding.Key, expectedKind: DurablePendingGovernancePolicyApprovalCollection,
		kind: DurablePendingGovernancePolicyApprovalCollection, codec: DurablePolicyApprovalCollectionCodec,
		codecVersion: DurablePolicyApprovalCollectionCodecVersion, revision: current.Version + 1,
		previousEnvelopeDigest:          stored.EnvelopeDigestSHA256,
		previousCanonicalEnvelope:       append([]byte(nil), stored.CanonicalEnvelope...),
		previousCommitNotBeforeUnixNano: stored.CommitNotBeforeUnixNano,
		previousCommitNotAfterUnixNano:  stored.CommitNotAfterUnixNano,
		sourcePreviousEnvelopeDigest:    stored.PreviousEnvelopeDigestSHA256,
		sourceEvidenceDigests:           append([][ccse.DigestSize]byte(nil), stored.EvidenceDigestsSHA256...),
		envelopeDigest:                  stored.EnvelopeDigestSHA256, canonicalEnvelope: append([]byte(nil), stored.CanonicalEnvelope...),
		evidenceDigests: append([][ccse.DigestSize]byte(nil), stored.EvidenceDigestsSHA256...),
		status:          DurablePendingTerminal, commitNotBeforeUnixNano: stored.CommitNotBeforeUnixNano,
		commitNotAfterUnixNano: stored.CommitNotAfterUnixNano, expectedAuditEventID: eventID,
	}
	baseDigest, err := digestDurablePendingTerminalTemplate(base)
	if err != nil {
		return DurablePendingTerminalTemplate{}, ErrApprovalCollection
	}
	base.terminalTemplateBaseDigest = baseDigest
	return DurablePendingTerminalTemplate{base: base, baseDigest: baseDigest}, nil
}

func writeDurablePendingRevision(w *digestWriter, value DurablePendingRevisionCapability,
	includeOutcome bool) {
	w.bytes(value.pendingKey[:])
	w.uint8(uint8(value.expectedKind))
	w.uint8(uint8(value.kind))
	w.string(value.codec)
	w.uint64(uint64(value.codecVersion))
	w.uint64(value.revision)
	w.digest(value.previousEnvelopeDigest)
	w.bytes(value.previousCanonicalEnvelope)
	w.int64(value.previousCommitNotBeforeUnixNano)
	w.int64(value.previousCommitNotAfterUnixNano)
	w.digest(value.sourcePreviousEnvelopeDigest)
	w.digests(value.sourceEvidenceDigests)
	w.digest(value.envelopeDigest)
	w.bytes(value.canonicalEnvelope)
	w.digests(value.evidenceDigests)
	w.uint8(uint8(value.status))
	w.int64(value.commitNotBeforeUnixNano)
	w.int64(value.commitNotAfterUnixNano)
	if includeOutcome {
		w.digest(value.terminalOutcomeDigest)
	}
	w.string(value.expectedAuditEventID)
}

func validateDurablePendingRevisionBase(value DurablePendingRevisionCapability, terminalTemplate bool) error {
	if value.pendingKey == ([ccse.MessageIDSize]byte{}) ||
		value.kind != DurablePendingGovernancePolicyApprovalCollection ||
		value.codec != DurablePolicyApprovalCollectionCodec ||
		value.codecVersion != DurablePolicyApprovalCollectionCodecVersion || value.revision == 0 ||
		isZeroDigest(value.envelopeDigest) || len(value.canonicalEnvelope) == 0 ||
		len(value.canonicalEnvelope) > durablePolicyApprovalCollectionMaxBytes ||
		len(value.evidenceDigests) == 0 || len(value.evidenceDigests) > maxApprovals ||
		value.commitNotBeforeUnixNano <= 0 || value.commitNotAfterUnixNano < value.commitNotBeforeUnixNano ||
		!validDurableEvidenceStorageText(value.expectedAuditEventID, 1024) {
		return ErrApprovalCollection
	}
	for index, digest := range value.evidenceDigests {
		if isZeroDigest(digest) || (index > 0 && bytes.Compare(value.evidenceDigests[index-1][:], digest[:]) >= 0) {
			return ErrApprovalCollection
		}
	}
	for index, digest := range value.sourceEvidenceDigests {
		if isZeroDigest(digest) ||
			(index > 0 && bytes.Compare(value.sourceEvidenceDigests[index-1][:], digest[:]) >= 0) {
			return ErrApprovalCollection
		}
	}
	decoded, err := DecodePolicyApprovalCollection(value.canonicalEnvelope)
	if err != nil || decoded.Digest() != value.envelopeDigest || decoded.Binding().Key != value.pendingKey ||
		!equalDigestSets(decoded.EvidenceDigests(), value.evidenceDigests) {
		return ErrApprovalCollection
	}
	switch value.status {
	case DurablePendingOpen:
		if terminalTemplate || !isZeroDigest(value.terminalOutcomeDigest) || !isZeroDigest(value.terminalTemplateBaseDigest) ||
			value.revision != decoded.Revision() ||
			(value.revision == 1 && (value.expectedKind != 0 || !isZeroDigest(value.previousEnvelopeDigest) ||
				len(value.previousCanonicalEnvelope) != 0 || value.previousCommitNotBeforeUnixNano != 0 ||
				value.previousCommitNotAfterUnixNano != 0 || !isZeroDigest(value.sourcePreviousEnvelopeDigest) ||
				len(value.sourceEvidenceDigests) != 0)) ||
			(value.revision > 1 && (value.expectedKind != DurablePendingGovernancePolicyApprovalCollection ||
				isZeroDigest(value.previousEnvelopeDigest) || len(value.previousCanonicalEnvelope) == 0 ||
				value.previousEnvelopeDigest == value.envelopeDigest || value.previousCommitNotBeforeUnixNano <= 0 ||
				value.previousCommitNotAfterUnixNano < value.previousCommitNotBeforeUnixNano ||
				len(value.sourceEvidenceDigests) == 0 ||
				(value.revision == 2 && !isZeroDigest(value.sourcePreviousEnvelopeDigest)) ||
				(value.revision > 2 && isZeroDigest(value.sourcePreviousEnvelopeDigest)))) {
			return ErrApprovalCollection
		}
		if value.revision > 1 {
			previous, decodeErr := DecodePolicyApprovalCollection(value.previousCanonicalEnvelope)
			if decodeErr != nil || previous.Digest() != value.previousEnvelopeDigest ||
				previous.Binding() != decoded.Binding() || previous.Revision()+1 != value.revision ||
				!equalDigestSets(previous.EvidenceDigests(), value.sourceEvidenceDigests) {
				return ErrApprovalCollection
			}
		}
	case DurablePendingTerminal:
		if value.expectedKind != DurablePendingGovernancePolicyApprovalCollection || value.revision < 2 ||
			decoded.Revision()+1 != value.revision || value.previousEnvelopeDigest != value.envelopeDigest ||
			!bytes.Equal(value.previousCanonicalEnvelope, value.canonicalEnvelope) ||
			value.previousCommitNotBeforeUnixNano != value.commitNotBeforeUnixNano ||
			value.previousCommitNotAfterUnixNano != value.commitNotAfterUnixNano ||
			len(value.sourceEvidenceDigests) == 0 ||
			!equalDigestSets(value.sourceEvidenceDigests, value.evidenceDigests) ||
			(value.revision == 2 && !isZeroDigest(value.sourcePreviousEnvelopeDigest)) ||
			(value.revision > 2 && isZeroDigest(value.sourcePreviousEnvelopeDigest)) ||
			(!terminalTemplate && (isZeroDigest(value.terminalOutcomeDigest) || isZeroDigest(value.terminalTemplateBaseDigest))) ||
			(terminalTemplate && !isZeroDigest(value.terminalOutcomeDigest)) {
			return ErrApprovalCollection
		}
	default:
		return ErrApprovalCollection
	}
	return nil
}

func digestDurablePendingTerminalTemplate(value DurablePendingRevisionCapability) ([ccse.DigestSize]byte, error) {
	copy := cloneDurablePendingRevisionCapability(value)
	copy.terminalOutcomeDigest = [ccse.DigestSize]byte{}
	copy.terminalTemplateBaseDigest = [ccse.DigestSize]byte{}
	copy.digest = [ccse.DigestSize]byte{}
	if validateDurablePendingRevisionBase(copy, true) != nil {
		return [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	w := newDigestWriter(durablePendingTerminalTemplateDigestDomain)
	w.uint64(uint64(durablePendingTerminalTemplateVersion))
	w.string(durablePendingTerminalOutcomeUnsetSentinel)
	writeDurablePendingRevision(w, copy, false)
	return w.sum()
}

func digestDurablePendingRevisionCapability(value DurablePendingRevisionCapability) ([ccse.DigestSize]byte, error) {
	if validateDurablePendingRevisionBase(value, false) != nil {
		return [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	if value.status == DurablePendingTerminal {
		base, err := digestDurablePendingTerminalTemplate(value)
		if err != nil || base != value.terminalTemplateBaseDigest {
			return [ccse.DigestSize]byte{}, ErrApprovalCollection
		}
	}
	w := newDigestWriter(durablePendingRevisionCapabilityDigestDomain)
	writeDurablePendingRevision(w, value, true)
	w.digest(value.terminalTemplateBaseDigest)
	return w.sum()
}

func cloneDurablePendingRevisionCapability(value DurablePendingRevisionCapability) DurablePendingRevisionCapability {
	value.previousCanonicalEnvelope = append([]byte(nil), value.previousCanonicalEnvelope...)
	value.sourceEvidenceDigests = append([][ccse.DigestSize]byte(nil), value.sourceEvidenceDigests...)
	value.canonicalEnvelope = append([]byte(nil), value.canonicalEnvelope...)
	value.evidenceDigests = append([][ccse.DigestSize]byte(nil), value.evidenceDigests...)
	return value
}

func cloneDurablePendingTerminalTemplate(value DurablePendingTerminalTemplate) DurablePendingTerminalTemplate {
	value.base = cloneDurablePendingRevisionCapability(value.base)
	return value
}

func zeroDurablePendingTerminalTemplate(value DurablePendingTerminalTemplate) bool {
	return value.baseDigest == ([ccse.DigestSize]byte{}) && value.base.pendingKey == ([ccse.MessageIDSize]byte{}) &&
		len(value.base.canonicalEnvelope) == 0 && len(value.base.previousCanonicalEnvelope) == 0 &&
		len(value.base.evidenceDigests) == 0 && value.base.digest == ([ccse.DigestSize]byte{})
}

func policyApprovalEntriesFromApprovals(input []policyApproval) []PolicyApprovalCollectionEntry {
	result := make([]PolicyApprovalCollectionEntry, 0, len(input))
	for _, approval := range input {
		record := cloneCCSERecord(&approval.record.record)
		result = append(result, PolicyApprovalCollectionEntry{
			Signed: SignedRecord{Record: &record}, AdmissionKey: cloneKeySnapshot(approval.admissionKey),
			GovernanceProfileDigestSHA256: approval.admissionProfileDigest,
			GovernanceProfileActivation:   approval.admissionActivation,
			ValidatedAtUnixNano:           approval.admissionValidatedAt,
			AdmissionFingerprintSHA256:    approval.admissionFingerprint,
		})
	}
	return result
}
