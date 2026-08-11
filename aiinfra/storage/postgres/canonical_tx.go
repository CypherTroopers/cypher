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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/replayresult"
	"github.com/cypherium/cypher/aiinfra/schema"
)

var (
	ErrCanonicalUOWRequired  = errors.New("aiinfra postgres: canonical unit of work is not active")
	ErrCanonicalUOWDuplicate = errors.New("aiinfra postgres: canonical unit of work is already bound")
	ErrCanonicalUOWMismatch  = errors.New("aiinfra postgres: canonical unit of work does not match the outer replay")
	ErrCanonicalUOWPhase     = errors.New("aiinfra postgres: canonical unit-of-work phase violation")
	ErrCanonicalInvalid      = errors.New("aiinfra postgres: invalid canonical storage input")
	ErrCanonicalCASMismatch  = errors.New("aiinfra postgres: canonical compare-and-swap mismatch")
	ErrCanonicalStateCorrupt = errors.New("aiinfra postgres: canonical durable state is corrupt")
)

// CanonicalUOWKind is the closed storage phase of one outer replay result.
// Admission has no AuditEvent. AuditedFinal owns exactly one signed event.
type CanonicalUOWKind uint8

const (
	CanonicalAdmission CanonicalUOWKind = iota + 1
	CanonicalAuditedFinal
)

// CanonicalUOWReceipt is an owned, immutable description of the result that
// will later be passed byte-for-byte to AtomicTx.Complete.
type CanonicalUOWReceipt struct {
	kind                   CanonicalUOWKind
	result                 replayresult.Result
	auditEventID           string
	evidenceAssertionCount uint16
}

// NewAdmissionUOWReceipt constructs a receipt for collection/evidence
// admission. It deliberately has no future EventID field; each child owns its
// own expected terminal EventID.
func NewAdmissionUOWReceipt(contentType string, payload []byte) (CanonicalUOWReceipt, error) {
	result, err := replayresult.New(contentType, payload)
	if err != nil {
		return CanonicalUOWReceipt{}, fmt.Errorf("%w: admission result: %v", ErrCanonicalInvalid, err)
	}
	return CanonicalUOWReceipt{kind: CanonicalAdmission, result: result}, nil
}

// NewAuditedFinalUOWReceipt constructs the exact outer signed-AuditEvent
// receipt. At least one retained evidence assertion is mandatory.
func NewAuditedFinalUOWReceipt(contentType string, payload []byte, auditEventID string,
	evidenceAssertionCount uint16) (CanonicalUOWReceipt, error) {
	result, err := replayresult.New(contentType, payload)
	if err != nil {
		return CanonicalUOWReceipt{}, fmt.Errorf("%w: audited result: %v", ErrCanonicalInvalid, err)
	}
	if validateCanonicalText(auditEventID, 1024) != nil || evidenceAssertionCount == 0 ||
		evidenceAssertionCount > v2MaxPendingEvidence {
		return CanonicalUOWReceipt{}, ErrCanonicalInvalid
	}
	return CanonicalUOWReceipt{
		kind: CanonicalAuditedFinal, result: result, auditEventID: auditEventID,
		evidenceAssertionCount: evidenceAssertionCount,
	}, nil
}

func (receipt CanonicalUOWReceipt) Kind() CanonicalUOWKind { return receipt.kind }
func (receipt CanonicalUOWReceipt) ResultDigest() [sha256.Size]byte {
	return receipt.result.Digest()
}
func (receipt CanonicalUOWReceipt) ResultContentType() string { return receipt.result.ContentType() }
func (receipt CanonicalUOWReceipt) ResultPayload() []byte     { return receipt.result.Payload() }
func (receipt CanonicalUOWReceipt) AuditEventID() (string, bool) {
	return receipt.auditEventID, receipt.kind == CanonicalAuditedFinal
}
func (receipt CanonicalUOWReceipt) EvidenceAssertionCount() uint16 {
	return receipt.evidenceAssertionCount
}

type canonicalTransactionState struct {
	receipt                  CanonicalUOWReceipt
	outerRecordDigest        [sha256.Size]byte
	outerMessageTypeID       uint32
	outerSchemaVersion       ccse.Version
	outerCanonicalPayload    []byte
	auditEventAppended       bool
	globalEventAsserted      bool
	evidenceAssertions       uint16
	globalClaimOrdinal       uint16
	businessClaimCount       uint16
	pendingRevisionCount     uint16
	pendingEvidenceLinkCount uint16
	evidenceRecordCount      uint16
	canonicalStateWrites     uint16
	canonicalStateAssertions uint16
	canonicalBytes           uint64
	canonicalStateKeys       map[canonicalStateKey]struct{}
}

// CanonicalUOW is a capability for v2 internal tables on the exact active
// ReplayStore transaction. It cannot be constructed outside BindCanonicalUOW.
type CanonicalUOW struct {
	state *transactionState
	bound *canonicalTransactionState
}

const insertAuthoritativeUOWSQL = `
	INSERT INTO cph_aiinfra.authoritative_uow
		(scope_sha256, message_id, uow_kind, outcome_digest, result_content_type,
		 result_payload, evidence_assertion_count, audit_event_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, pg_current_xact_id())`

// BindCanonicalUOW binds one typed v2 receipt to the active Execute handler.
// verified must be the exact immutable record passed to that handler.
func BindCanonicalUOW(ctx context.Context, verified ccse.VerifiedRecord,
	receipt CanonicalUOWReceipt) (*CanonicalUOW, error) {
	active, ok := ctx.Value(replayTransactionContextKey{}).(replayTransactionContext)
	if !ok || active.store == nil || active.state == nil || active.state.tx == nil ||
		active.state.store != active.store {
		return nil, ErrCanonicalUOWRequired
	}
	state := active.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !contextOwnsTransaction(ctx, state) || state.sealed {
		return nil, poisonCanonicalLocked(state, ErrCanonicalUOWRequired)
	}
	if state.poisoned != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransactionPoisoned, state.poisoned)
	}
	if state.canonical != nil {
		return nil, poisonCanonicalLocked(state, ErrCanonicalUOWDuplicate)
	}
	entry, err := verified.ReplayEntry()
	if err != nil || entry != state.entry {
		return nil, poisonCanonicalLocked(state, ErrCanonicalUOWMismatch)
	}
	scope, err := replayScopeDigest(entry)
	if err != nil || scope != state.scope || entry.MessageID != state.entry.MessageID {
		return nil, poisonCanonicalLocked(state, ErrCanonicalUOWMismatch)
	}
	if err := validateCanonicalReceipt(receipt); err != nil {
		return nil, poisonCanonicalLocked(state, err)
	}
	if receipt.kind == CanonicalAuditedFinal &&
		(verified.MessageTypeID() != schema.MessageTypeAuditEvent ||
			verified.SchemaVersion() != (ccse.Version{Major: 1})) {
		return nil, poisonCanonicalLocked(state, ErrCanonicalUOWMismatch)
	}
	payload := receipt.result.Payload()
	var auditEventID interface{}
	if receipt.kind == CanonicalAuditedFinal {
		auditEventID = receipt.auditEventID
	}
	digest := receipt.result.Digest()
	result, err := state.tx.ExecContext(ctx, insertAuthoritativeUOWSQL,
		state.scope[:], state.entry.MessageID[:], int16(receipt.kind), digest[:],
		receipt.result.ContentType(), payload, int16(receipt.evidenceAssertionCount), auditEventID)
	if err != nil {
		return nil, poisonCanonicalLocked(state, fmt.Errorf("%w: insert authoritative receipt: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return nil, poisonCanonicalLocked(state, err)
	}
	bound := &canonicalTransactionState{receipt: receipt, outerRecordDigest: verified.Digest(),
		outerMessageTypeID: verified.MessageTypeID(), outerSchemaVersion: verified.SchemaVersion(),
		outerCanonicalPayload: verified.Payload()}
	state.canonical = bound
	state.claimed = true
	return &CanonicalUOW{state: state, bound: bound}, nil
}

func validateCanonicalReceipt(receipt CanonicalUOWReceipt) error {
	if receipt.result.Verify() != nil {
		return ErrCanonicalInvalid
	}
	switch receipt.kind {
	case CanonicalAdmission:
		if receipt.auditEventID != "" || receipt.evidenceAssertionCount != 0 {
			return ErrCanonicalInvalid
		}
	case CanonicalAuditedFinal:
		if validateCanonicalText(receipt.auditEventID, 1024) != nil ||
			receipt.evidenceAssertionCount == 0 || receipt.evidenceAssertionCount > v2MaxPendingEvidence {
			return ErrCanonicalInvalid
		}
	default:
		return ErrCanonicalInvalid
	}
	return nil
}

func (uow *CanonicalUOW) lock(ctx context.Context) (*transactionState, error) {
	if uow == nil || uow.state == nil || uow.bound == nil {
		return nil, ErrCanonicalUOWRequired
	}
	state := uow.state
	state.mu.Lock()
	if !contextOwnsTransaction(ctx, state) || state.canonical != uow.bound || state.sealed {
		err := poisonCanonicalLocked(state, ErrCanonicalUOWRequired)
		state.mu.Unlock()
		return nil, err
	}
	if state.poisoned != nil {
		err := fmt.Errorf("%w: %v", ErrTransactionPoisoned, state.poisoned)
		state.mu.Unlock()
		return nil, err
	}
	return state, nil
}

func poisonCanonicalLocked(state *transactionState, err error) error {
	if state != nil && state.poisoned == nil {
		state.poisoned = err
	}
	return err
}

func requireOneCanonicalRow(result sql.Result) error {
	if result == nil {
		return ErrCanonicalCASMismatch
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return fmt.Errorf("%w: affected rows=%d: %v", ErrCanonicalCASMismatch, count, err)
	}
	return nil
}

func canonicalBudgetAllows(used uint64, additional int, maximum uint64) bool {
	return additional >= 0 && used <= maximum && uint64(additional) <= maximum-used
}

func validateCanonicalCompletionLocked(state *transactionState, completion DurableCompletion) error {
	if state.canonical == nil {
		return nil
	}
	bound := state.canonical
	receipt := bound.receipt
	if completion.ContentType != receipt.result.ContentType() ||
		!bytes.Equal(completion.Payload, receipt.result.Payload()) ||
		DurableResultDigest(completion.ContentType, completion.Payload) != receipt.result.Digest() {
		return ErrCanonicalUOWMismatch
	}
	switch receipt.kind {
	case CanonicalAdmission:
		if bound.auditEventAppended || bound.globalEventAsserted || bound.evidenceAssertions != 0 {
			return ErrCanonicalUOWPhase
		}
	case CanonicalAuditedFinal:
		if !bound.auditEventAppended || !bound.globalEventAsserted ||
			bound.evidenceAssertions != receipt.evidenceAssertionCount {
			return ErrCanonicalUOWPhase
		}
	default:
		return ErrCanonicalUOWPhase
	}
	return nil
}

// AuditEventRecord is the storage-neutral exact signed event projection.
type AuditEventRecord struct {
	EventID             string
	StreamID            string
	Sequence            uint64
	PreviousEventDigest [sha256.Size]byte
	HasPrevious         bool
	EventDigest         [sha256.Size]byte
	RecordDigest        [sha256.Size]byte
	CanonicalEvent      []byte
	OccurredAtUnixNano  int64
	Head                 AuditHeadCAS
}

// AuditHeadCAS is the complete governance authorization tuple committed by
// MutationAuditAppend. Head* is the prior logical writer state; Authorized*
// and the lease fields are the exact authority for this append and become the
// next logical head state.
type AuditHeadCAS struct {
	DeploymentAnchorDigest            [sha256.Size]byte
	ExpectedHeadWriterIdentity         string
	AuthorizedWriterIdentity           string
	ExpectedHeadHomeRegion             string
	AuthorizedHomeRegion               string
	ExpectedHeadWriterEpoch            uint64
	AuthorizedWriterEpoch              uint64
	ExpectedHeadGovernanceProfileDigest [sha256.Size]byte
	AuthorizedGovernanceProfileDigest  [sha256.Size]byte
	WriterLeaseEvidenceDigest          [sha256.Size]byte
	WriterLeaseNotBeforeUnixNano       int64
	WriterLeaseNotAfterUnixNano        int64
}

const insertAuditEventSQL = `
	INSERT INTO cph_aiinfra.audit_event
		(event_id, stream_id, audit_sequence, previous_event_digest, event_digest,
		 record_digest, canonical_event, scope_sha256, message_id,
		 occurred_at_unix_nano, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, pg_current_xact_id())`

const insertAuditHeadSQL = `
	INSERT INTO cph_aiinfra.audit_head
		(stream_id, deployment_anchor_digest, highest_sequence, latest_record_digest,
		 audit_event_id, head_writer_identity, authorized_writer_identity,
		 home_region, authorized_home_region, writer_epoch, authorized_writer_epoch,
		 head_governance_profile_digest, authorized_governance_profile_digest,
		 writer_lease_evidence_digest, writer_lease_not_before_unix_nano,
		 writer_lease_not_after_unix_nano,
		 uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $7, $8, $8, $9, $9,
		$10, $11, $12, $13, $14, pg_current_xact_id())`

const updateAuditHeadSQL = `
	UPDATE cph_aiinfra.audit_head
	SET highest_sequence = $3, latest_record_digest = $4, audit_event_id = $5,
		head_writer_identity = $6, authorized_writer_identity = $6,
		home_region = $7, authorized_home_region = $7,
		writer_epoch = $8, authorized_writer_epoch = $8,
		head_governance_profile_digest = $9,
		authorized_governance_profile_digest = $9,
		writer_lease_evidence_digest = $10,
		writer_lease_not_before_unix_nano = $11,
		writer_lease_not_after_unix_nano = $12,
		uow_scope_sha256 = $13, uow_message_id = $14
	WHERE stream_id = $1 AND deployment_anchor_digest = $2
		AND highest_sequence = $15 AND latest_record_digest = $16
		AND head_writer_identity = $17 AND authorized_writer_identity = $6
		AND home_region = $18 AND authorized_home_region = $7
		AND writer_epoch = $19 AND authorized_writer_epoch = $8
		AND head_governance_profile_digest = $20
		AND authorized_governance_profile_digest = $9
		AND writer_lease_evidence_digest = $10
		AND writer_lease_not_before_unix_nano = $11
		AND writer_lease_not_after_unix_nano = $12`

// AppendAuditEvent appends the audited-final receipt's exact event and advances
// its stream head with a one-row CAS. Admission receipts cannot call it.
func (uow *CanonicalUOW) AppendAuditEvent(ctx context.Context, event AuditEventRecord) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	if err := validateAuditEventRecord(uow.bound, event); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if uow.bound.auditEventAppended {
		return poisonCanonicalLocked(state, ErrCanonicalUOWDuplicate)
	}
	var previous interface{}
	if event.HasPrevious {
		previous = event.PreviousEventDigest[:]
	}
	result, err := state.tx.ExecContext(ctx, insertAuditEventSQL, event.EventID, event.StreamID,
		strconv.FormatUint(event.Sequence, 10), previous, event.EventDigest[:], event.RecordDigest[:],
		event.CanonicalEvent, state.scope[:], state.entry.MessageID[:], event.OccurredAtUnixNano)
	if err != nil {
		return poisonCanonicalLocked(state, fmt.Errorf("%w: insert AuditEvent: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if event.Sequence == 1 {
		result, err = state.tx.ExecContext(ctx, insertAuditHeadSQL, event.StreamID,
			event.Head.DeploymentAnchorDigest[:], strconv.FormatUint(event.Sequence, 10),
			event.RecordDigest[:], event.EventID, event.Head.AuthorizedWriterIdentity,
			event.Head.AuthorizedHomeRegion, strconv.FormatUint(event.Head.AuthorizedWriterEpoch, 10),
			event.Head.AuthorizedGovernanceProfileDigest[:], event.Head.WriterLeaseEvidenceDigest[:],
			event.Head.WriterLeaseNotBeforeUnixNano, event.Head.WriterLeaseNotAfterUnixNano,
			state.scope[:], state.entry.MessageID[:])
	} else {
		result, err = state.tx.ExecContext(ctx, updateAuditHeadSQL, event.StreamID,
			event.Head.DeploymentAnchorDigest[:], strconv.FormatUint(event.Sequence, 10),
			event.RecordDigest[:], event.EventID, event.Head.AuthorizedWriterIdentity,
			event.Head.AuthorizedHomeRegion, strconv.FormatUint(event.Head.AuthorizedWriterEpoch, 10),
			event.Head.AuthorizedGovernanceProfileDigest[:], event.Head.WriterLeaseEvidenceDigest[:],
			event.Head.WriterLeaseNotBeforeUnixNano, event.Head.WriterLeaseNotAfterUnixNano,
			state.scope[:], state.entry.MessageID[:], strconv.FormatUint(event.Sequence-1, 10),
			event.PreviousEventDigest[:], event.Head.ExpectedHeadWriterIdentity,
			event.Head.ExpectedHeadHomeRegion, strconv.FormatUint(event.Head.ExpectedHeadWriterEpoch, 10),
			event.Head.ExpectedHeadGovernanceProfileDigest[:])
	}
	if err != nil {
		return poisonCanonicalLocked(state, fmt.Errorf("%w: advance audit head: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	uow.bound.auditEventAppended = true
	return nil
}

func validateAuditEventRecord(bound *canonicalTransactionState, event AuditEventRecord) error {
	if bound == nil || bound.receipt.kind != CanonicalAuditedFinal ||
		bound.outerMessageTypeID != schema.MessageTypeAuditEvent ||
		bound.outerSchemaVersion != (ccse.Version{Major: 1}) ||
		event.EventID != bound.receipt.auditEventID ||
		event.RecordDigest != bound.outerRecordDigest ||
		!bytes.Equal(event.CanonicalEvent, bound.outerCanonicalPayload) ||
		validateCanonicalText(event.EventID, 1024) != nil || validateCanonicalText(event.StreamID, 255) != nil ||
		event.Sequence == 0 || event.EventDigest == ([sha256.Size]byte{}) ||
		event.RecordDigest == ([sha256.Size]byte{}) || len(event.CanonicalEvent) == 0 ||
		len(event.CanonicalEvent) > v2AuditEventMaxBytes || event.OccurredAtUnixNano <= 0 ||
		(event.Sequence == 1 && event.HasPrevious) || (event.Sequence > 1 && !event.HasPrevious) ||
		(event.HasPrevious && event.PreviousEventDigest == ([sha256.Size]byte{})) ||
		!validateAuditHeadCAS(event) {
		return ErrCanonicalUOWPhase
	}
	return nil
}

func validateAuditHeadCAS(event AuditEventRecord) bool {
	head := event.Head
	if !nonzeroDigest(head.DeploymentAnchorDigest) ||
		validateCanonicalText(head.AuthorizedWriterIdentity, 1024) != nil ||
		validateCanonicalText(head.AuthorizedHomeRegion, 255) != nil ||
		head.AuthorizedWriterEpoch == 0 ||
		!nonzeroDigest(head.AuthorizedGovernanceProfileDigest) ||
		!nonzeroDigest(head.WriterLeaseEvidenceDigest) ||
		head.WriterLeaseNotBeforeUnixNano < 0 ||
		head.WriterLeaseNotAfterUnixNano <= head.WriterLeaseNotBeforeUnixNano ||
		event.OccurredAtUnixNano < head.WriterLeaseNotBeforeUnixNano ||
		event.OccurredAtUnixNano >= head.WriterLeaseNotAfterUnixNano {
		return false
	}
	if event.Sequence == 1 {
		return head.ExpectedHeadWriterIdentity == "" && head.ExpectedHeadHomeRegion == "" &&
			head.ExpectedHeadWriterEpoch == 0 &&
			head.ExpectedHeadGovernanceProfileDigest == ([sha256.Size]byte{})
	}
	return validateCanonicalText(head.ExpectedHeadWriterIdentity, 1024) == nil &&
		validateCanonicalText(head.ExpectedHeadHomeRegion, 255) == nil &&
		head.ExpectedHeadWriterEpoch > 0 &&
		nonzeroDigest(head.ExpectedHeadGovernanceProfileDigest)
}

func validateCanonicalText(value string, maximum int) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 {
		return ErrCanonicalInvalid
	}
	return nil
}
