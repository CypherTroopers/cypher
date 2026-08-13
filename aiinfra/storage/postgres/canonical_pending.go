// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

// DurableEvidenceKind is the closed storage representation. Semantic
// packages remain responsible for validating the content behind each kind.
type DurableEvidenceKind uint8

const (
	DurableEvidenceContentSHA256 DurableEvidenceKind = iota + 1
	DurableEvidenceSignedCCSERecord
	DurableEvidenceAuthenticatedRecord
	DurableEvidenceSemanticReceipt
)

// DurablePendingKind is deliberately closed at 1..5. IAM's ephemeral
// ownership-transfer acceptance capability is not a durable pending kind: its
// audited UoW closes kind 3 and may create a future kind-5 child.
type DurablePendingKind uint8

const (
	DurablePendingMutation DurablePendingKind = iota + 1
	DurablePendingKeyEnrollment
	DurablePendingOwnershipTransferCollection
	DurablePendingReconciliation
	DurablePendingOwnershipTransferCutover
	// Value 6 is intentionally unused by storage. IAM uses it for an ephemeral
	// audited acceptance capability which closes kind 3 and may create kind 5.
	_
	DurablePendingGovernancePolicyApprovalCollection

	DurablePendingIAMCodec        = "cph.aiinfra.iam.pending.v1"
	DurablePendingGovernanceCodec = "cph.aiinfra.governance.policy-approval-collection.v1"
)

type DurablePendingStatus uint8

const (
	DurablePendingOpen DurablePendingStatus = iota + 1
	DurablePendingTerminal
)

// DurableEvidenceRecord is an owned content-addressed preimage.
// ExpectedAuditEventID is the terminal EventID reserved by the owning
// workflow. For Admission rows it is not actual event provenance; an event
// does not exist yet. It is compared on every explicit assertion.
type DurableEvidenceRecord struct {
	Digest               [sha256.Size]byte
	Kind                 DurableEvidenceKind
	ContentType          string
	CanonicalContent     []byte
	ExpectedAuditEventID string
}

// DurablePendingRevision is a storage-neutral envelope revision. The digest
// algorithm is intentionally owned by the semantic codec; this layer stores
// the already-verified digest and byte-exact canonical envelope.
type DurablePendingRevision struct {
	PendingKey [ccse.MessageIDSize]byte
	// ExpectedKind is zero for a version-one absent-row insert. For every
	// update it names the exact locked head kind. Reconciliation is the sole
	// kind-changing transition: OPEN 1/2/3/5 to TERMINAL 4.
	ExpectedKind           DurablePendingKind
	Kind                   DurablePendingKind
	Codec                  string
	CodecVersion           uint32
	Revision               uint64
	PreviousEnvelopeDigest [sha256.Size]byte
	// PreviousCanonicalEnvelope is an update-only exact CAS input. It is not
	// duplicated in the stored next revision and is empty on reload.
	PreviousCanonicalEnvelope []byte
	// PreviousCommit* are update-only exact CAS inputs for every same-kind
	// transition. They are zero for inserts, kind-changing reconciliation and
	// reload snapshots, which do not carry an optimistic predecessor window.
	PreviousCommitNotBeforeUnixNano int64
	PreviousCommitNotAfterUnixNano  int64
	EnvelopeDigest                  [sha256.Size]byte
	CanonicalEnvelope               []byte
	EvidenceDigests                 [][sha256.Size]byte
	Status                          DurablePendingStatus
	CommitNotBeforeUnixNano         int64
	CommitNotAfterUnixNano          int64
	TerminalOutcomeDigest           [sha256.Size]byte
	ExpectedAuditEventID            string
}

// EvidenceAssertion proves that an audited-final UoW re-read retained
// evidence. HasPending binds the assertion to one exact pending revision.
type EvidenceAssertion struct {
	EvidenceDigest  [sha256.Size]byte
	HasPending      bool
	PendingKey      [ccse.MessageIDSize]byte
	PendingRevision uint64
}

const selectDurableEvidenceForUpdateSQL = `
	SELECT evidence_kind, content_type, canonical_content, audit_event_id
	FROM cph_aiinfra.durable_evidence
	WHERE evidence_digest = $1`

const insertDurableEvidenceSQL = `
	INSERT INTO cph_aiinfra.durable_evidence
		(evidence_digest, evidence_kind, content_type, canonical_content,
		 audit_event_id, uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, pg_current_xact_id())`

// ReserveDurableEvidence inserts a new immutable evidence row. An existing
// digest, even with identical bytes, is a failed absent-row CAS.
func (uow *CanonicalUOW) ReserveDurableEvidence(ctx context.Context, record DurableEvidenceRecord) error {
	state, err := uow.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := prepareDurableEvidence(record)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if int(uow.bound.evidenceRecordCount)+1 > v2MaxUOWEvidenceRecords ||
		!canonicalBudgetAllows(uow.bound.canonicalBytes, len(prepared.CanonicalContent), v2MaxUOWCanonicalBytes) {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var storedKind int16
	var storedType, storedEvent string
	var storedContent []byte
	err = state.tx.QueryRowContext(ctx, selectDurableEvidenceForUpdateSQL, prepared.Digest[:]).
		Scan(&storedKind, &storedType, &storedContent, &storedEvent)
	if err == nil {
		return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return poisonCanonicalLocked(state,
			fmt.Errorf("%w: read durable evidence: %v", ErrCanonicalStateCorrupt, err))
	}
	result, err := state.tx.ExecContext(ctx, insertDurableEvidenceSQL, prepared.Digest[:],
		int16(prepared.Kind), prepared.ContentType, prepared.CanonicalContent,
		prepared.ExpectedAuditEventID, state.scope[:], state.entry.MessageID[:])
	if err != nil {
		return poisonCanonicalLocked(state,
			fmt.Errorf("%w: insert durable evidence: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	uow.bound.evidenceRecordCount++
	uow.bound.canonicalBytes += uint64(len(prepared.CanonicalContent))
	return nil
}

// AssertDurableEvidenceContent reads an immutable row on the active
// SERIALIZABLE transaction and compares its complete content and original
// AuditEvent attribution without manufacturing an update.
func (uow *CanonicalUOW) AssertDurableEvidenceContent(ctx context.Context,
	record DurableEvidenceRecord) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := prepareDurableEvidence(record)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	var storedKind int16
	var storedType, storedEvent string
	var storedContent []byte
	err = state.tx.QueryRowContext(ctx, selectDurableEvidenceForUpdateSQL, prepared.Digest[:]).
		Scan(&storedKind, &storedType, &storedContent, &storedEvent)
	if errors.Is(err, sql.ErrNoRows) {
		return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
	}
	if err != nil {
		return poisonCanonicalLocked(state,
			fmt.Errorf("%w: read durable evidence: %v", ErrCanonicalStateCorrupt, err))
	}
	if storedKind != int16(prepared.Kind) || storedType != prepared.ContentType ||
		!bytes.Equal(storedContent, prepared.CanonicalContent) || storedEvent != prepared.ExpectedAuditEventID {
		return poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return nil
}

// LoadDurableEvidence returns an owned exact immutable row using the active
// transaction connection.
func (uow *CanonicalUOW) LoadDurableEvidence(ctx context.Context,
	digest [sha256.Size]byte) (DurableEvidenceRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return DurableEvidenceRecord{}, false, err
	}
	defer state.mu.Unlock()
	if !nonzeroDigest(digest) {
		return DurableEvidenceRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var kind int16
	var contentType, eventID string
	var content []byte
	err = state.tx.QueryRowContext(ctx, selectDurableEvidenceForUpdateSQL, digest[:]).
		Scan(&kind, &contentType, &content, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return DurableEvidenceRecord{}, false, nil
	}
	if err != nil {
		return DurableEvidenceRecord{}, false,
			poisonCanonicalLocked(state, fmt.Errorf("%w: read durable evidence: %v", ErrCanonicalStateCorrupt, err))
	}
	record := DurableEvidenceRecord{Digest: digest, Kind: DurableEvidenceKind(kind),
		ContentType: contentType, CanonicalContent: content, ExpectedAuditEventID: eventID}
	prepared, prepareErr := prepareDurableEvidence(record)
	if prepareErr != nil {
		return DurableEvidenceRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return prepared, true, nil
}

func prepareDurableEvidence(record DurableEvidenceRecord) (DurableEvidenceRecord, error) {
	if !nonzeroDigest(record.Digest) || record.Kind < DurableEvidenceContentSHA256 ||
		record.Kind > DurableEvidenceSemanticReceipt ||
		validateCanonicalText(record.ContentType, 255) != nil ||
		len(record.CanonicalContent) == 0 || len(record.CanonicalContent) > v2EvidenceMaxBytes ||
		validateCanonicalText(record.ExpectedAuditEventID, 1024) != nil {
		return DurableEvidenceRecord{}, ErrCanonicalInvalid
	}
	record.CanonicalContent = bytes.Clone(record.CanonicalContent)
	return record, nil
}

const insertPendingHeadSQL = `
	INSERT INTO cph_aiinfra.durable_pending_head
		(pending_key, pending_kind, codec, codec_version, revision,
		 previous_envelope_digest, envelope_digest, canonical_envelope,
		 evidence_count, status, commit_not_before_unix_nano,
		 commit_not_after_unix_nano, terminal_outcome_digest, audit_event_id,
		 uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
		$13, $14, $15, $16, pg_current_xact_id())`

const updatePendingHeadSQL = `
	UPDATE cph_aiinfra.durable_pending_head
	SET pending_kind = $2, codec = $3, codec_version = $4,
		revision = $6, previous_envelope_digest = $7, envelope_digest = $8,
		canonical_envelope = $9, evidence_count = $10, status = $11,
		commit_not_before_unix_nano = $12, commit_not_after_unix_nano = $13,
		terminal_outcome_digest = $14, uow_scope_sha256 = $15,
		uow_message_id = $16
	WHERE pending_key = $1 AND pending_kind = $19 AND codec = $20
		AND codec_version = $21 AND audit_event_id = $5 AND revision = $17
		AND envelope_digest = $18 AND canonical_envelope = $22 AND status = 1
		AND (NOT $23 OR (commit_not_before_unix_nano = $24
			AND commit_not_after_unix_nano = $25))
		AND terminal_outcome_digest IS NULL`

const insertPendingRevisionSQL = `
	INSERT INTO cph_aiinfra.durable_pending_revision
		(pending_key, revision, pending_kind, codec, codec_version,
		 previous_envelope_digest, envelope_digest, canonical_envelope,
		 evidence_count, status, commit_not_before_unix_nano,
		 commit_not_after_unix_nano, terminal_outcome_digest, audit_event_id,
		 uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
		$13, $14, $15, $16, pg_current_xact_id())`

const insertPendingEvidenceSQL = `
	INSERT INTO cph_aiinfra.durable_pending_evidence
		(pending_key, revision, evidence_ordinal, evidence_digest,
		 audit_event_id, uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, pg_current_xact_id())`

// ApplyDurablePendingRevision validates and owns the complete envelope and
// evidence set before SQL, then writes the head, exact revision, and links.
func (uow *CanonicalUOW) ApplyDurablePendingRevision(ctx context.Context,
	revision DurablePendingRevision) error {
	state, err := uow.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := preparePendingRevision(uow.bound.receipt, revision)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if int(uow.bound.pendingRevisionCount)+1 > v2MaxUOWPendingRevisions ||
		int(uow.bound.pendingEvidenceLinkCount)+len(prepared.EvidenceDigests) > v2MaxPendingEvidence ||
		!canonicalBudgetAllows(uow.bound.canonicalBytes, len(prepared.CanonicalEnvelope), v2MaxUOWCanonicalBytes) {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	previous := nullableDigest(prepared.PreviousEnvelopeDigest)
	outcome := nullableDigest(prepared.TerminalOutcomeDigest)
	var result sql.Result
	if prepared.Revision == 1 {
		result, err = state.tx.ExecContext(ctx, insertPendingHeadSQL, prepared.PendingKey[:],
			int16(prepared.Kind), prepared.Codec, int64(prepared.CodecVersion),
			strconv.FormatUint(prepared.Revision, 10), previous, prepared.EnvelopeDigest[:],
			prepared.CanonicalEnvelope, int16(len(prepared.EvidenceDigests)), int16(prepared.Status),
			prepared.CommitNotBeforeUnixNano, prepared.CommitNotAfterUnixNano, outcome,
			prepared.ExpectedAuditEventID, state.scope[:], state.entry.MessageID[:])
	} else {
		expectedCodec := durablePendingCodec(prepared.ExpectedKind)
		result, err = state.tx.ExecContext(ctx, updatePendingHeadSQL, prepared.PendingKey[:],
			int16(prepared.Kind), prepared.Codec, int64(prepared.CodecVersion),
			prepared.ExpectedAuditEventID, strconv.FormatUint(prepared.Revision, 10), previous,
			prepared.EnvelopeDigest[:], prepared.CanonicalEnvelope, int16(len(prepared.EvidenceDigests)),
			int16(prepared.Status), prepared.CommitNotBeforeUnixNano, prepared.CommitNotAfterUnixNano,
			outcome, state.scope[:], state.entry.MessageID[:],
			strconv.FormatUint(prepared.Revision-1, 10), prepared.PreviousEnvelopeDigest[:],
			int16(prepared.ExpectedKind), expectedCodec, int64(1),
			prepared.PreviousCanonicalEnvelope, hasPreviousWindowCAS(prepared),
			prepared.PreviousCommitNotBeforeUnixNano, prepared.PreviousCommitNotAfterUnixNano)
	}
	if err != nil {
		return poisonCanonicalLocked(state,
			fmt.Errorf("%w: write durable pending head: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	result, err = state.tx.ExecContext(ctx, insertPendingRevisionSQL, prepared.PendingKey[:],
		strconv.FormatUint(prepared.Revision, 10), int16(prepared.Kind), prepared.Codec,
		int64(prepared.CodecVersion), previous, prepared.EnvelopeDigest[:], prepared.CanonicalEnvelope,
		int16(len(prepared.EvidenceDigests)), int16(prepared.Status), prepared.CommitNotBeforeUnixNano,
		prepared.CommitNotAfterUnixNano, outcome, prepared.ExpectedAuditEventID,
		state.scope[:], state.entry.MessageID[:])
	if err != nil {
		return poisonCanonicalLocked(state,
			fmt.Errorf("%w: insert durable pending revision: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	for index, digest := range prepared.EvidenceDigests {
		result, err = state.tx.ExecContext(ctx, insertPendingEvidenceSQL, prepared.PendingKey[:],
			strconv.FormatUint(prepared.Revision, 10), int16(index+1), digest[:],
			prepared.ExpectedAuditEventID, state.scope[:], state.entry.MessageID[:])
		if err != nil {
			return poisonCanonicalLocked(state,
				fmt.Errorf("%w: insert durable pending evidence: %v", ErrCanonicalCASMismatch, err))
		}
		if err := requireOneCanonicalRow(result); err != nil {
			return poisonCanonicalLocked(state, err)
		}
	}
	uow.bound.pendingRevisionCount++
	uow.bound.pendingEvidenceLinkCount += uint16(len(prepared.EvidenceDigests))
	uow.bound.canonicalBytes += uint64(len(prepared.CanonicalEnvelope))
	return nil
}

func preparePendingRevision(receipt CanonicalUOWReceipt,
	revision DurablePendingRevision) (DurablePendingRevision, error) {
	if revision.PendingKey == ([ccse.MessageIDSize]byte{}) ||
		!validDurablePendingCodec(revision.Kind, revision.Codec, revision.CodecVersion) ||
		revision.Revision == 0 || !nonzeroDigest(revision.EnvelopeDigest) ||
		len(revision.CanonicalEnvelope) == 0 || len(revision.CanonicalEnvelope) > v2DurableEnvelopeMaxBytes ||
		len(revision.EvidenceDigests) > v2MaxPendingEvidence ||
		revision.CommitNotBeforeUnixNano <= 0 ||
		revision.CommitNotAfterUnixNano < revision.CommitNotBeforeUnixNano ||
		validateCanonicalText(revision.ExpectedAuditEventID, 1024) != nil {
		return DurablePendingRevision{}, ErrCanonicalInvalid
	}
	if (revision.Revision == 1 && (revision.ExpectedKind != 0 ||
		nonzeroDigest(revision.PreviousEnvelopeDigest) || len(revision.PreviousCanonicalEnvelope) != 0)) ||
		(revision.Revision > 1 && (revision.ExpectedKind == 0 ||
			!nonzeroDigest(revision.PreviousEnvelopeDigest) ||
			len(revision.PreviousCanonicalEnvelope) == 0 ||
			len(revision.PreviousCanonicalEnvelope) > v2DurableEnvelopeMaxBytes)) ||
		(revision.Kind == DurablePendingGovernancePolicyApprovalCollection && len(revision.EvidenceDigests) == 0) {
		return DurablePendingRevision{}, ErrCanonicalInvalid
	}
	sameKindUpdate := hasPreviousWindowCAS(revision)
	lifecycleTerminal := isLifecycleTerminal(revision)
	if sameKindUpdate {
		if revision.PreviousCommitNotBeforeUnixNano <= 0 ||
			revision.PreviousCommitNotAfterUnixNano < revision.PreviousCommitNotBeforeUnixNano {
			return DurablePendingRevision{}, ErrCanonicalInvalid
		}
	} else if revision.PreviousCommitNotBeforeUnixNano != 0 ||
		revision.PreviousCommitNotAfterUnixNano != 0 {
		return DurablePendingRevision{}, ErrCanonicalInvalid
	}
	if lifecycleTerminal {
		if revision.EnvelopeDigest != revision.PreviousEnvelopeDigest ||
			!bytes.Equal(revision.CanonicalEnvelope, revision.PreviousCanonicalEnvelope) ||
			revision.PreviousCommitNotBeforeUnixNano != revision.CommitNotBeforeUnixNano ||
			revision.PreviousCommitNotAfterUnixNano != revision.CommitNotAfterUnixNano {
			return DurablePendingRevision{}, ErrCanonicalInvalid
		}
	} else {
		if revision.Revision > 1 && revision.EnvelopeDigest == revision.PreviousEnvelopeDigest {
			return DurablePendingRevision{}, ErrCanonicalInvalid
		}
	}
	if revision.Kind == DurablePendingReconciliation {
		if receipt.kind != CanonicalAuditedFinal || revision.Status != DurablePendingTerminal ||
			revision.Revision < 2 || !validReconciliationSourceKind(revision.ExpectedKind) {
			return DurablePendingRevision{}, ErrCanonicalUOWPhase
		}
	} else if revision.Revision > 1 && revision.ExpectedKind != revision.Kind {
		return DurablePendingRevision{}, ErrCanonicalInvalid
	}
	switch revision.Status {
	case DurablePendingOpen:
		if nonzeroDigest(revision.TerminalOutcomeDigest) ||
			(receipt.kind == CanonicalAuditedFinal && revision.ExpectedAuditEventID == receipt.auditEventID) {
			return DurablePendingRevision{}, ErrCanonicalUOWPhase
		}
	case DurablePendingTerminal:
		if revision.Revision < 2 || receipt.kind != CanonicalAuditedFinal ||
			revision.ExpectedAuditEventID != receipt.auditEventID ||
			revision.TerminalOutcomeDigest != receipt.result.Digest() {
			return DurablePendingRevision{}, ErrCanonicalUOWPhase
		}
	default:
		return DurablePendingRevision{}, ErrCanonicalInvalid
	}
	digests := append([][sha256.Size]byte(nil), revision.EvidenceDigests...)
	for _, digest := range digests {
		if !nonzeroDigest(digest) {
			return DurablePendingRevision{}, ErrCanonicalInvalid
		}
	}
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i][:], digests[j][:]) < 0 })
	for index := 1; index < len(digests); index++ {
		if digests[index] == digests[index-1] {
			return DurablePendingRevision{}, ErrCanonicalInvalid
		}
	}
	revision.CanonicalEnvelope = bytes.Clone(revision.CanonicalEnvelope)
	revision.PreviousCanonicalEnvelope = bytes.Clone(revision.PreviousCanonicalEnvelope)
	revision.EvidenceDigests = digests
	return revision, nil
}

func isLifecycleTerminal(revision DurablePendingRevision) bool {
	return revision.Revision > 1 && revision.Kind != DurablePendingReconciliation &&
		revision.ExpectedKind == revision.Kind && revision.Status == DurablePendingTerminal
}

func hasPreviousWindowCAS(revision DurablePendingRevision) bool {
	return revision.Revision > 1 && revision.ExpectedKind == revision.Kind
}

const selectPendingHeadForUpdateSQL = `
	SELECT pending_kind, codec, codec_version, revision,
		previous_envelope_digest, envelope_digest, canonical_envelope,
		evidence_count, status, commit_not_before_unix_nano,
		commit_not_after_unix_nano, terminal_outcome_digest, audit_event_id
	FROM cph_aiinfra.durable_pending_head
	WHERE pending_key = $1
	FOR UPDATE`

const selectPendingEvidenceForUpdateSQL = `
	SELECT evidence_ordinal, evidence_digest
	FROM cph_aiinfra.durable_pending_evidence
	WHERE pending_key = $1 AND revision = $2
	ORDER BY evidence_ordinal`

const selectTerminalSourceRevisionSQL = `
	SELECT pending_kind, codec, codec_version, status, terminal_outcome_digest,
		envelope_digest, canonical_envelope, commit_not_before_unix_nano,
		commit_not_after_unix_nano, audit_event_id
	FROM cph_aiinfra.durable_pending_revision
	WHERE pending_key = $1 AND revision = $2`

// LoadDurablePending returns an owned, internally consistent locked head plus
// its immutable exact retained evidence set on the same transaction.
func (uow *CanonicalUOW) LoadDurablePending(ctx context.Context,
	key [ccse.MessageIDSize]byte) (DurablePendingRevision, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return DurablePendingRevision{}, false, err
	}
	defer state.mu.Unlock()
	return loadDurablePendingLocked(ctx, state, key)
}

// AssertDurablePendingOpen locks and byte-compares one complete optimistic
// OPEN-head snapshot, including its immutable ordered evidence links. This is
// the final-transaction fence used before changing an admitted operation into
// a reconciliation revision; the update predicate alone intentionally cannot
// reconstruct the semantic pre-sign snapshot.
func (uow *CanonicalUOW) AssertDurablePendingOpen(ctx context.Context,
	expected DurablePendingRevision) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := preparePendingRevisionForReload(expected)
	if err != nil || prepared.Status != DurablePendingOpen ||
		nonzeroDigest(prepared.TerminalOutcomeDigest) {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	actual, found, err := loadDurablePendingLocked(ctx, state, prepared.PendingKey)
	if err != nil {
		return err
	}
	if !found || !equalDurablePendingSnapshot(actual, prepared) {
		return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
	}
	return nil
}

func loadDurablePendingLocked(ctx context.Context, state *transactionState,
	key [ccse.MessageIDSize]byte) (DurablePendingRevision, bool, error) {
	if key == ([ccse.MessageIDSize]byte{}) {
		return DurablePendingRevision{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var kind, evidenceCount, status int16
	var codec string
	var codecVersion int64
	var revisionText string
	var previous, digest, envelope, outcome []byte
	var notBefore, notAfter int64
	var eventID string
	err := state.tx.QueryRowContext(ctx, selectPendingHeadForUpdateSQL, key[:]).Scan(
		&kind, &codec, &codecVersion, &revisionText, &previous, &digest, &envelope,
		&evidenceCount, &status, &notBefore, &notAfter, &outcome, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return DurablePendingRevision{}, false, nil
	}
	if err != nil {
		return DurablePendingRevision{}, false,
			poisonCanonicalLocked(state, fmt.Errorf("%w: read durable pending: %v", ErrCanonicalStateCorrupt, err))
	}
	revisionNumber, parseErr := strconv.ParseUint(revisionText, 10, 64)
	if parseErr != nil || codecVersion <= 0 || codecVersion > math.MaxUint32 ||
		evidenceCount < 0 || evidenceCount > v2MaxPendingEvidence || len(digest) != sha256.Size ||
		(len(previous) != 0 && len(previous) != sha256.Size) ||
		(len(outcome) != 0 && len(outcome) != sha256.Size) {
		return DurablePendingRevision{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	record := DurablePendingRevision{PendingKey: key, Kind: DurablePendingKind(kind), Codec: codec,
		CodecVersion: uint32(codecVersion), Revision: revisionNumber,
		CanonicalEnvelope: bytes.Clone(envelope), Status: DurablePendingStatus(status),
		CommitNotBeforeUnixNano: notBefore, CommitNotAfterUnixNano: notAfter,
		ExpectedAuditEventID: eventID}
	copy(record.PreviousEnvelopeDigest[:], previous)
	copy(record.EnvelopeDigest[:], digest)
	copy(record.TerminalOutcomeDigest[:], outcome)
	rows, err := state.tx.QueryContext(ctx, selectPendingEvidenceForUpdateSQL, key[:], revisionText)
	if err != nil {
		return DurablePendingRevision{}, false,
			poisonCanonicalLocked(state, fmt.Errorf("%w: read pending evidence: %v", ErrCanonicalStateCorrupt, err))
	}
	defer rows.Close()
	record.EvidenceDigests = make([][sha256.Size]byte, 0, evidenceCount)
	for rows.Next() {
		var ordinal int16
		var encoded []byte
		if err := rows.Scan(&ordinal, &encoded); err != nil ||
			int(ordinal) != len(record.EvidenceDigests)+1 || len(encoded) != sha256.Size {
			return DurablePendingRevision{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		var evidenceDigest [sha256.Size]byte
		copy(evidenceDigest[:], encoded)
		record.EvidenceDigests = append(record.EvidenceDigests, evidenceDigest)
	}
	if err := rows.Err(); err != nil || len(record.EvidenceDigests) != int(evidenceCount) {
		return DurablePendingRevision{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	prepared, err := preparePendingRevisionForReload(record)
	if err != nil {
		return DurablePendingRevision{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	if prepared.Status == DurablePendingTerminal {
		if err := assertTerminalSourceRevisionLocked(ctx, state, prepared); err != nil {
			return DurablePendingRevision{}, false, poisonCanonicalLocked(state, err)
		}
	}
	return prepared, true, nil
}

func equalDurablePendingSnapshot(left, right DurablePendingRevision) bool {
	if left.PendingKey != right.PendingKey || left.Kind != right.Kind || left.Codec != right.Codec ||
		left.CodecVersion != right.CodecVersion || left.Revision != right.Revision ||
		left.PreviousEnvelopeDigest != right.PreviousEnvelopeDigest ||
		left.EnvelopeDigest != right.EnvelopeDigest || left.Status != right.Status ||
		left.CommitNotBeforeUnixNano != right.CommitNotBeforeUnixNano ||
		left.CommitNotAfterUnixNano != right.CommitNotAfterUnixNano ||
		left.TerminalOutcomeDigest != right.TerminalOutcomeDigest ||
		left.ExpectedAuditEventID != right.ExpectedAuditEventID ||
		!bytes.Equal(left.CanonicalEnvelope, right.CanonicalEnvelope) ||
		len(left.EvidenceDigests) != len(right.EvidenceDigests) {
		return false
	}
	for index := range left.EvidenceDigests {
		if left.EvidenceDigests[index] != right.EvidenceDigests[index] {
			return false
		}
	}
	return true
}

func assertTerminalSourceRevisionLocked(ctx context.Context, state *transactionState,
	terminal DurablePendingRevision) error {
	var kind, status int16
	var codec, eventID string
	var codecVersion int64
	var notBefore, notAfter int64
	var outcome, envelopeDigest, canonicalEnvelope []byte
	err := state.tx.QueryRowContext(ctx, selectTerminalSourceRevisionSQL,
		terminal.PendingKey[:], strconv.FormatUint(terminal.Revision-1, 10)).Scan(
		&kind, &codec, &codecVersion, &status, &outcome, &envelopeDigest,
		&canonicalEnvelope, &notBefore, &notAfter, &eventID)
	if err != nil {
		return ErrCanonicalStateCorrupt
	}
	sourceKind := DurablePendingKind(kind)
	if codecVersion != 1 || codec != durablePendingCodec(sourceKind) ||
		DurablePendingStatus(status) != DurablePendingOpen || len(outcome) != 0 ||
		len(envelopeDigest) != sha256.Size || len(canonicalEnvelope) == 0 ||
		!bytes.Equal(envelopeDigest, terminal.PreviousEnvelopeDigest[:]) ||
		eventID != terminal.ExpectedAuditEventID {
		return ErrCanonicalStateCorrupt
	}
	if terminal.Kind == DurablePendingReconciliation {
		if !validReconciliationSourceKind(sourceKind) ||
			terminal.EnvelopeDigest == terminal.PreviousEnvelopeDigest {
			return ErrCanonicalStateCorrupt
		}
		return nil
	}
	if sourceKind != terminal.Kind || terminal.EnvelopeDigest != terminal.PreviousEnvelopeDigest ||
		!bytes.Equal(canonicalEnvelope, terminal.CanonicalEnvelope) ||
		notBefore != terminal.CommitNotBeforeUnixNano || notAfter != terminal.CommitNotAfterUnixNano {
		return ErrCanonicalStateCorrupt
	}
	rows, err := state.tx.QueryContext(ctx, selectPendingEvidenceForUpdateSQL,
		terminal.PendingKey[:], strconv.FormatUint(terminal.Revision-1, 10))
	if err != nil {
		return ErrCanonicalStateCorrupt
	}
	defer rows.Close()
	prior := make([][sha256.Size]byte, 0, len(terminal.EvidenceDigests))
	for rows.Next() {
		var ordinal int16
		var encoded []byte
		if err := rows.Scan(&ordinal, &encoded); err != nil ||
			int(ordinal) != len(prior)+1 || len(encoded) != sha256.Size {
			return ErrCanonicalStateCorrupt
		}
		var digest [sha256.Size]byte
		copy(digest[:], encoded)
		prior = append(prior, digest)
	}
	if err := rows.Err(); err != nil || len(prior) != len(terminal.EvidenceDigests) {
		return ErrCanonicalStateCorrupt
	}
	for index := range prior {
		if prior[index] != terminal.EvidenceDigests[index] {
			return ErrCanonicalStateCorrupt
		}
	}
	return nil
}

func preparePendingRevisionForReload(revision DurablePendingRevision) (DurablePendingRevision, error) {
	// Reload cannot apply phase rules from the historical UoW receipt, but all
	// intrinsic bounds, transition shape and canonical evidence ordering remain
	// closed here.
	if revision.PendingKey == ([ccse.MessageIDSize]byte{}) ||
		!validDurablePendingCodec(revision.Kind, revision.Codec, revision.CodecVersion) ||
		revision.Revision == 0 || !nonzeroDigest(revision.EnvelopeDigest) ||
		len(revision.CanonicalEnvelope) == 0 || len(revision.CanonicalEnvelope) > v2DurableEnvelopeMaxBytes ||
		len(revision.EvidenceDigests) > v2MaxPendingEvidence ||
		revision.CommitNotBeforeUnixNano <= 0 || revision.CommitNotAfterUnixNano < revision.CommitNotBeforeUnixNano ||
		validateCanonicalText(revision.ExpectedAuditEventID, 1024) != nil ||
		(revision.Revision == 1 && nonzeroDigest(revision.PreviousEnvelopeDigest)) ||
		(revision.Revision > 1 && !nonzeroDigest(revision.PreviousEnvelopeDigest)) ||
		(revision.Kind == DurablePendingGovernancePolicyApprovalCollection && len(revision.EvidenceDigests) == 0) {
		return DurablePendingRevision{}, ErrCanonicalStateCorrupt
	}
	if revision.Kind == DurablePendingReconciliation && (revision.Revision < 2 ||
		revision.Status != DurablePendingTerminal || revision.EnvelopeDigest == revision.PreviousEnvelopeDigest) {
		return DurablePendingRevision{}, ErrCanonicalStateCorrupt
	}
	if revision.Status == DurablePendingOpen {
		if nonzeroDigest(revision.TerminalOutcomeDigest) {
			return DurablePendingRevision{}, ErrCanonicalStateCorrupt
		}
	} else if revision.Status != DurablePendingTerminal || revision.Revision < 2 ||
		!nonzeroDigest(revision.TerminalOutcomeDigest) ||
		(revision.Kind != DurablePendingReconciliation &&
			revision.EnvelopeDigest != revision.PreviousEnvelopeDigest) {
		return DurablePendingRevision{}, ErrCanonicalStateCorrupt
	}
	for index, digest := range revision.EvidenceDigests {
		if !nonzeroDigest(digest) || (index > 0 && bytes.Compare(revision.EvidenceDigests[index-1][:], digest[:]) >= 0) {
			return DurablePendingRevision{}, ErrCanonicalStateCorrupt
		}
	}
	return revision, nil
}

func validDurablePendingCodec(kind DurablePendingKind, codec string, version uint32) bool {
	if validateCanonicalText(codec, 255) != nil || version != 1 {
		return false
	}
	if kind >= DurablePendingMutation && kind <= DurablePendingOwnershipTransferCutover {
		return codec == DurablePendingIAMCodec
	}
	return kind == DurablePendingGovernancePolicyApprovalCollection && codec == DurablePendingGovernanceCodec
}

func durablePendingCodec(kind DurablePendingKind) string {
	if kind >= DurablePendingMutation && kind <= DurablePendingOwnershipTransferCutover {
		return DurablePendingIAMCodec
	}
	if kind == DurablePendingGovernancePolicyApprovalCollection {
		return DurablePendingGovernanceCodec
	}
	return ""
}

func validReconciliationSourceKind(kind DurablePendingKind) bool {
	return kind == DurablePendingMutation || kind == DurablePendingKeyEnrollment ||
		kind == DurablePendingOwnershipTransferCollection ||
		kind == DurablePendingOwnershipTransferCutover
}

const insertEvidenceAssertionSQL = `
	INSERT INTO cph_aiinfra.durable_evidence_assertion
		(uow_scope_sha256, uow_message_id, evidence_ordinal, evidence_digest,
		 pending_key, pending_revision, audit_event_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, pg_current_xact_id())`

// AssertDurableEvidence records the exact evidence re-read by an audited-final
// UoW. The receipt's declared count must be met exactly before Complete.
func (uow *CanonicalUOW) AssertDurableEvidence(ctx context.Context,
	assertions []EvidenceAssertion) error {
	state, err := uow.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := prepareEvidenceAssertions(uow.bound, assertions)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	for _, assertion := range prepared {
		ordinal := uow.bound.evidenceAssertions + 1
		var pendingKey, pendingRevision interface{}
		if assertion.HasPending {
			pendingKey = assertion.PendingKey[:]
			pendingRevision = strconv.FormatUint(assertion.PendingRevision, 10)
		}
		result, err := state.tx.ExecContext(ctx, insertEvidenceAssertionSQL, state.scope[:],
			state.entry.MessageID[:], int16(ordinal), assertion.EvidenceDigest[:], pendingKey,
			pendingRevision, uow.bound.receipt.auditEventID)
		if err != nil {
			return poisonCanonicalLocked(state,
				fmt.Errorf("%w: insert durable evidence assertion: %v", ErrCanonicalCASMismatch, err))
		}
		if err := requireOneCanonicalRow(result); err != nil {
			return poisonCanonicalLocked(state, err)
		}
		uow.bound.evidenceAssertions = ordinal
	}
	return nil
}

func prepareEvidenceAssertions(bound *canonicalTransactionState,
	input []EvidenceAssertion) ([]EvidenceAssertion, error) {
	if bound == nil || bound.receipt.kind != CanonicalAuditedFinal || len(input) == 0 ||
		len(input) > v2MaxPendingEvidence || bound.evidenceAssertions != 0 ||
		len(input) != int(bound.receipt.evidenceAssertionCount) {
		return nil, ErrCanonicalUOWPhase
	}
	assertions := append([]EvidenceAssertion(nil), input...)
	for _, assertion := range assertions {
		if !nonzeroDigest(assertion.EvidenceDigest) ||
			(assertion.HasPending && (assertion.PendingKey == ([ccse.MessageIDSize]byte{}) || assertion.PendingRevision == 0)) ||
			(!assertion.HasPending && (assertion.PendingKey != ([ccse.MessageIDSize]byte{}) || assertion.PendingRevision != 0)) {
			return nil, ErrCanonicalInvalid
		}
	}
	sort.Slice(assertions, func(i, j int) bool {
		return bytes.Compare(assertions[i].EvidenceDigest[:], assertions[j].EvidenceDigest[:]) < 0
	})
	for index := 1; index < len(assertions); index++ {
		if assertions[index].EvidenceDigest == assertions[index-1].EvidenceDigest {
			return nil, ErrCanonicalInvalid
		}
	}
	return assertions, nil
}
