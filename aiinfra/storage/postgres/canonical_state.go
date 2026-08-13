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
)

// CanonicalStateNamespace and CanonicalStateKind form a closed storage
// matrix. Adding a consumer requires a numbered migration and verifier update.
type CanonicalStateNamespace uint8
type CanonicalStateKind string

const (
	CanonicalStateIAM        CanonicalStateNamespace = 1
	CanonicalStateGovernance CanonicalStateNamespace = 2

	CanonicalStateIAMKeyMaterial               CanonicalStateKind = "cph.aiinfra.iam.key-material.v1"
	CanonicalStateIAMIdentity                  CanonicalStateKind = "cph.aiinfra.iam.identity.v1"
	CanonicalStateIAMKeyLifecycle              CanonicalStateKind = "cph.aiinfra.iam.key-lifecycle.v1"
	CanonicalStateIAMAcceptedOwnershipTransfer CanonicalStateKind = "cph.aiinfra.iam.accepted-ownership-transfer.v1"
	CanonicalStateIAMProofChallenge            CanonicalStateKind = "cph.aiinfra.iam.proof-challenge.v1"
	CanonicalStateIAMPrincipalIdentityIndex    CanonicalStateKind = "cph.aiinfra.iam.principal-identity-index.v1"
	CanonicalStateIAMRotationPredecessorIndex  CanonicalStateKind = "cph.aiinfra.iam.rotation-predecessor-index.v1"
	CanonicalStateIAMSubjectKeySet             CanonicalStateKind = "cph.aiinfra.iam.subject-key-set.v1"
	CanonicalStateIAMWriterLease               CanonicalStateKind = "cph.aiinfra.iam.writer-lease.v1"
	CanonicalStateIAMTransferProfileActivation CanonicalStateKind = "cph.aiinfra.iam.ownership-transfer-profile-activation.v1"
	CanonicalStateGovernancePolicyRegistry     CanonicalStateKind = "cph.aiinfra.governance.policy-registry.v1"
	CanonicalStateGovernanceProfileActivation  CanonicalStateKind = "cph.aiinfra.governance.profile-activation.v1"

	CanonicalStateIAMKeyMaterialContentType               = "application/cph.aiinfra.iam.key-material-state.v1"
	CanonicalStateIAMIdentityContentType                  = "application/cph.aiinfra.iam.identity-state.v1"
	CanonicalStateIAMKeyLifecycleContentType              = "application/cph.aiinfra.iam.key-lifecycle-state.v1"
	CanonicalStateIAMAcceptedOwnershipTransferContentType = "application/cph.aiinfra.iam.accepted-ownership-transfer-state.v1"
	CanonicalStateIAMProofChallengeContentType            = "application/cph.aiinfra.iam.proof-challenge-state.v1"
	CanonicalStateIAMPrincipalIdentityIndexContentType    = "application/cph.aiinfra.iam.principal-identity-index-state.v1"
	CanonicalStateIAMRotationPredecessorIndexContentType  = "application/cph.aiinfra.iam.rotation-predecessor-index-state.v1"
	CanonicalStateIAMSubjectKeySetContentType             = "application/cph.aiinfra.iam.subject-key-set-state.v1"
	CanonicalStateIAMWriterLeaseContentType               = "application/cph.aiinfra.iam.writer-lease-state.v1"
	CanonicalStateIAMTransferProfileActivationContentType = "application/cph.aiinfra.iam.ownership-transfer-profile-activation-state.v1"
	CanonicalStateGovernancePolicyRegistryContentType     = "application/cph.aiinfra.governance.policy-registry-state.v1"
	CanonicalStateGovernanceProfileActivationContentType  = "application/cph.aiinfra.governance.profile-activation-state.v1"

	// MaxCanonicalStateAssertions covers the largest admitted ownership-transfer
	// cutover (IAM permits 1,024 exact reads) plus Governance's independently
	// bounded 384-row authorization read set. Mutations remain a separate,
	// smaller batch: conflating the two caps makes the valid 256-closure shape
	// impossible to execute.
	MaxCanonicalStateAssertions = 1408
	MaxCanonicalStateMutations  = 384
	// MaxCanonicalUOWBytes is the shared write budget across newly reserved
	// evidence, durable pending envelopes and canonical-state next rows. The
	// composition layer uses the same value to reject an unrepresentable
	// signed operation before issuing semantic writes.
	MaxCanonicalUOWBytes = 64 << 20
)

type canonicalStateKindSpec struct {
	namespace      CanonicalStateNamespace
	kind           CanonicalStateKind
	contentType    string
	validityWindow bool
}

var canonicalStateKindCatalog = [...]canonicalStateKindSpec{
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMKeyMaterial, contentType: CanonicalStateIAMKeyMaterialContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMIdentity, contentType: CanonicalStateIAMIdentityContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMKeyLifecycle, contentType: CanonicalStateIAMKeyLifecycleContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMAcceptedOwnershipTransfer, contentType: CanonicalStateIAMAcceptedOwnershipTransferContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMProofChallenge, contentType: CanonicalStateIAMProofChallengeContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMPrincipalIdentityIndex, contentType: CanonicalStateIAMPrincipalIdentityIndexContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMRotationPredecessorIndex, contentType: CanonicalStateIAMRotationPredecessorIndexContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMSubjectKeySet, contentType: CanonicalStateIAMSubjectKeySetContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMWriterLease, contentType: CanonicalStateIAMWriterLeaseContentType},
	{namespace: CanonicalStateIAM, kind: CanonicalStateIAMTransferProfileActivation, contentType: CanonicalStateIAMTransferProfileActivationContentType, validityWindow: true},
	{namespace: CanonicalStateGovernance, kind: CanonicalStateGovernancePolicyRegistry, contentType: CanonicalStateGovernancePolicyRegistryContentType},
	{namespace: CanonicalStateGovernance, kind: CanonicalStateGovernanceProfileActivation, contentType: CanonicalStateGovernanceProfileActivationContentType, validityWindow: true},
}

// CanonicalStateRecord is an owned exact head projection. StateDigest is the
// semantic codec's domain-separated state identity, not a generic raw SHA-256
// of CanonicalState. The coordinator must verify that relation before Apply.
type CanonicalStateRecord struct {
	Namespace          CanonicalStateNamespace
	Kind               CanonicalStateKind
	ObjectID           string
	Version            uint64
	StateDigest        [sha256.Size]byte
	ContentType        string
	CanonicalState     []byte
	Terminal           bool
	AuditEventID       string
	HasValidityWindow  bool
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
}

// CanonicalStateMutation is absent-to-version-one when Expected is nil.
// Otherwise Expected is the complete locked row used by the exact CAS.
type CanonicalStateMutation struct {
	Expected *CanonicalStateRecord
	Next     CanonicalStateRecord
}

type canonicalStateKey struct {
	namespace CanonicalStateNamespace
	kind      CanonicalStateKind
	objectID  string
}

const insertCanonicalStateHeadSQL = `
	INSERT INTO cph_aiinfra.canonical_state_head
		(state_namespace, object_kind, object_id, version, state_digest,
		 content_type, canonical_state, terminal, valid_from_unix_nano,
		 valid_until_unix_nano, audit_event_id,
		 uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		pg_current_xact_id())`

const updateCanonicalStateHeadSQL = `
	UPDATE cph_aiinfra.canonical_state_head
	SET version = $4, state_digest = $5, content_type = $6,
		canonical_state = $7, terminal = $8, valid_from_unix_nano = $9,
		valid_until_unix_nano = $10, audit_event_id = $11,
		uow_scope_sha256 = $12, uow_message_id = $13
	WHERE state_namespace = $1 AND object_kind = $2 AND object_id = $3
		AND version = $14 AND state_digest = $15 AND content_type = $16
		AND canonical_state = $17 AND terminal = $18
		AND valid_from_unix_nano IS NOT DISTINCT FROM $19
		AND valid_until_unix_nano IS NOT DISTINCT FROM $20
		AND audit_event_id = $21`

const insertCanonicalStateHistorySQL = `
	INSERT INTO cph_aiinfra.canonical_state_history
		(state_namespace, object_kind, object_id, version, state_digest,
		 content_type, canonical_state, terminal, valid_from_unix_nano,
		 valid_until_unix_nano, audit_event_id,
		 uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		pg_current_xact_id())`

// ApplyCanonicalStates validates and owns the complete batch before SQL, then
// preserves caller order. Cutover dependency order is semantic and must not be
// flattened into a key sort. Every head write has an exact immutable history.
func (uow *CanonicalUOW) ApplyCanonicalStates(ctx context.Context,
	mutations []CanonicalStateMutation) error {
	state, err := uow.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := prepareCanonicalStateMutations(uow.bound.receipt, mutations)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if int(uow.bound.canonicalStateWrites)+len(prepared) > MaxCanonicalStateMutations {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	additionalBytes := uint64(0)
	for _, mutation := range prepared {
		if !canonicalBudgetAllows(additionalBytes, len(mutation.Next.CanonicalState), v2MaxUOWCanonicalBytes) {
			return poisonCanonicalLocked(state, ErrCanonicalInvalid)
		}
		additionalBytes += uint64(len(mutation.Next.CanonicalState))
	}
	if additionalBytes > uint64(^uint(0)>>1) ||
		!canonicalBudgetAllows(uow.bound.canonicalBytes, int(additionalBytes), v2MaxUOWCanonicalBytes) {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	if uow.bound.canonicalStateHeads == nil {
		uow.bound.canonicalStateHeads = make(map[canonicalStateKey]CanonicalStateRecord)
	}
	batchHeads := make(map[canonicalStateKey]CanonicalStateRecord, len(prepared))
	for index, mutation := range prepared {
		key := canonicalStateRecordKey(mutation.Next)
		predecessor, chained := batchHeads[key]
		if !chained {
			predecessor, chained = uow.bound.canonicalStateHeads[key]
		}
		if chained && (mutation.Expected == nil ||
			!equalCanonicalStateRecords(*mutation.Expected, predecessor)) {
			return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
		}
		batchHeads[key] = mutation.Next
		prepared[index] = mutation
	}
	for _, mutation := range prepared {
		if err := applyCanonicalStateLocked(ctx, state, mutation); err != nil {
			return poisonCanonicalLocked(state, err)
		}
		key := canonicalStateRecordKey(mutation.Next)
		uow.bound.canonicalStateHeads[key] = mutation.Next
		uow.bound.canonicalStateWrites++
	}
	uow.bound.canonicalBytes += additionalBytes
	return nil
}

func prepareCanonicalStateMutations(receipt CanonicalUOWReceipt,
	input []CanonicalStateMutation) ([]CanonicalStateMutation, error) {
	if receipt.kind != CanonicalAuditedFinal || len(input) == 0 || len(input) > MaxCanonicalStateMutations {
		return nil, ErrCanonicalUOWPhase
	}
	prepared := make([]CanonicalStateMutation, len(input))
	heads := make(map[canonicalStateKey]CanonicalStateRecord, len(input))
	for index, mutation := range input {
		next, err := prepareCanonicalStateRecord(mutation.Next)
		if err != nil || next.AuditEventID != receipt.auditEventID {
			return nil, ErrCanonicalInvalid
		}
		prepared[index].Next = next
		key := canonicalStateRecordKey(next)
		predecessor, chained := heads[key]
		if mutation.Expected == nil {
			if chained || next.Version != 1 || !validCanonicalStateInsert(next) {
				return nil, ErrCanonicalInvalid
			}
			heads[key] = next
			continue
		}
		expected, err := prepareCanonicalStateRecord(*mutation.Expected)
		if err != nil || canonicalStateRecordKey(expected) != key || expected.Terminal ||
			expected.Version == ^uint64(0) || next.Version != expected.Version+1 ||
			next.StateDigest == expected.StateDigest || !validCanonicalStateTransition(expected, next) {
			return nil, ErrCanonicalInvalid
		}
		if chained && !equalCanonicalStateRecords(expected, predecessor) {
			return nil, ErrCanonicalInvalid
		}
		prepared[index].Expected = &expected
		heads[key] = next
	}
	return prepared, nil
}

func validCanonicalStateInsert(next CanonicalStateRecord) bool {
	switch next.Kind {
	case CanonicalStateIAMKeyMaterial, CanonicalStateIAMAcceptedOwnershipTransfer,
		CanonicalStateIAMRotationPredecessorIndex:
		return next.Terminal
	case CanonicalStateIAMProofChallenge, CanonicalStateIAMPrincipalIdentityIndex,
		CanonicalStateIAMSubjectKeySet, CanonicalStateIAMWriterLease,
		CanonicalStateIAMTransferProfileActivation, CanonicalStateGovernancePolicyRegistry,
		CanonicalStateGovernanceProfileActivation:
		return !next.Terminal
	default:
		return true
	}
}

func validCanonicalStateTransition(expected, next CanonicalStateRecord) bool {
	switch next.Kind {
	case CanonicalStateIAMKeyMaterial, CanonicalStateIAMAcceptedOwnershipTransfer,
		CanonicalStateIAMRotationPredecessorIndex:
		return false
	case CanonicalStateIAMProofChallenge:
		return !expected.Terminal && next.Terminal
	case CanonicalStateIAMPrincipalIdentityIndex, CanonicalStateIAMSubjectKeySet,
		CanonicalStateIAMWriterLease, CanonicalStateIAMTransferProfileActivation,
		CanonicalStateGovernancePolicyRegistry, CanonicalStateGovernanceProfileActivation:
		return !next.Terminal
	default:
		return true
	}
}

func prepareCanonicalStateRecord(record CanonicalStateRecord) (CanonicalStateRecord, error) {
	spec, ok := canonicalStateSpec(record.Namespace, record.Kind)
	if !ok || record.ContentType != spec.contentType || validateCanonicalText(record.ObjectID, 1024) != nil ||
		record.Version == 0 || !nonzeroDigest(record.StateDigest) ||
		len(record.CanonicalState) == 0 || len(record.CanonicalState) > v2CanonicalStateMaxBytes ||
		validateCanonicalText(record.AuditEventID, 1024) != nil {
		return CanonicalStateRecord{}, ErrCanonicalInvalid
	}
	if spec.validityWindow != record.HasValidityWindow ||
		(record.HasValidityWindow && (record.ValidFromUnixNano < 0 ||
			record.ValidUntilUnixNano <= record.ValidFromUnixNano)) ||
		(!record.HasValidityWindow && (record.ValidFromUnixNano != 0 || record.ValidUntilUnixNano != 0)) {
		return CanonicalStateRecord{}, ErrCanonicalInvalid
	}
	record.CanonicalState = bytes.Clone(record.CanonicalState)
	return record, nil
}

func canonicalStateSpec(namespace CanonicalStateNamespace,
	kind CanonicalStateKind) (canonicalStateKindSpec, bool) {
	for _, spec := range canonicalStateKindCatalog {
		if spec.namespace == namespace && spec.kind == kind {
			return spec, true
		}
	}
	return canonicalStateKindSpec{}, false
}

func canonicalStateRecordKey(record CanonicalStateRecord) canonicalStateKey {
	return canonicalStateKey{namespace: record.Namespace, kind: record.Kind, objectID: record.ObjectID}
}

func applyCanonicalStateLocked(ctx context.Context, state *transactionState,
	mutation CanonicalStateMutation) error {
	next := mutation.Next
	nextFrom, nextUntil := nullableCanonicalValidity(next)
	var result sql.Result
	var err error
	if mutation.Expected == nil {
		result, err = state.tx.ExecContext(ctx, insertCanonicalStateHeadSQL, int16(next.Namespace),
			string(next.Kind), next.ObjectID, strconv.FormatUint(next.Version, 10), next.StateDigest[:],
			next.ContentType, next.CanonicalState, next.Terminal, nextFrom, nextUntil,
			next.AuditEventID, state.scope[:], state.entry.MessageID[:])
	} else {
		expected := *mutation.Expected
		expectedFrom, expectedUntil := nullableCanonicalValidity(expected)
		result, err = state.tx.ExecContext(ctx, updateCanonicalStateHeadSQL, int16(next.Namespace),
			string(next.Kind), next.ObjectID, strconv.FormatUint(next.Version, 10), next.StateDigest[:],
			next.ContentType, next.CanonicalState, next.Terminal, nextFrom, nextUntil,
			next.AuditEventID, state.scope[:], state.entry.MessageID[:], strconv.FormatUint(expected.Version, 10),
			expected.StateDigest[:], expected.ContentType, expected.CanonicalState,
			expected.Terminal, expectedFrom, expectedUntil, expected.AuditEventID)
	}
	if err != nil {
		return fmt.Errorf("%w: write canonical state head: %v", ErrCanonicalCASMismatch, err)
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return err
	}
	result, err = state.tx.ExecContext(ctx, insertCanonicalStateHistorySQL, int16(next.Namespace),
		string(next.Kind), next.ObjectID, strconv.FormatUint(next.Version, 10), next.StateDigest[:],
		next.ContentType, next.CanonicalState, next.Terminal, nextFrom, nextUntil,
		next.AuditEventID, state.scope[:], state.entry.MessageID[:])
	if err != nil {
		return fmt.Errorf("%w: insert canonical state history: %v", ErrCanonicalCASMismatch, err)
	}
	return requireOneCanonicalRow(result)
}

func nullableCanonicalValidity(record CanonicalStateRecord) (interface{}, interface{}) {
	if !record.HasValidityWindow {
		return nil, nil
	}
	return record.ValidFromUnixNano, record.ValidUntilUnixNano
}

const selectCanonicalStateForUpdateSQL = `
	SELECT version, state_digest, content_type, canonical_state, terminal,
		valid_from_unix_nano, valid_until_unix_nano, audit_event_id
	FROM cph_aiinfra.canonical_state_head
	WHERE state_namespace = $1 AND object_kind = $2 AND object_id = $3
	FOR UPDATE`

const selectCanonicalStateVersionSQL = `
	SELECT state_digest, content_type, canonical_state, terminal,
		valid_from_unix_nano, valid_until_unix_nano, audit_event_id
	FROM cph_aiinfra.canonical_state_history
	WHERE state_namespace = $1 AND object_kind = $2 AND object_id = $3
		AND version = $4`

const selectActiveGovernanceProfileStateSQL = `
	SELECT object_id, version, state_digest, content_type, canonical_state,
		terminal, valid_from_unix_nano, valid_until_unix_nano, audit_event_id
	FROM cph_aiinfra.canonical_state_history
	WHERE state_namespace = $1 AND object_kind = $2
		AND valid_from_unix_nano <= $3 AND $3 < valid_until_unix_nano
	ORDER BY object_id, version
	LIMIT 2`

// LoadCanonicalState returns an owned exact row under the active transaction's
// row lock. Unknown namespace/kind pairs are rejected before SQL.
func (uow *CanonicalUOW) LoadCanonicalState(ctx context.Context, namespace CanonicalStateNamespace,
	kind CanonicalStateKind, objectID string) (CanonicalStateRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return CanonicalStateRecord{}, false, err
	}
	defer state.mu.Unlock()
	if _, ok := canonicalStateSpec(namespace, kind); !ok || validateCanonicalText(objectID, 1024) != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	record, found, err := loadCanonicalStateLocked(ctx, state, namespace, kind, objectID)
	if err != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, err)
	}
	return record, found, nil
}

// LoadCanonicalStateVersion resolves one immutable history row on the active
// SERIALIZABLE replay transaction. History rows cannot be updated or deleted,
// so the predicate read is sufficient and does not require UPDATE privilege.
func (uow *CanonicalUOW) LoadCanonicalStateVersion(ctx context.Context,
	namespace CanonicalStateNamespace, kind CanonicalStateKind, objectID string,
	version uint64) (CanonicalStateRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return CanonicalStateRecord{}, false, err
	}
	defer state.mu.Unlock()
	if _, ok := canonicalStateSpec(namespace, kind); !ok ||
		validateCanonicalText(objectID, 1024) != nil || version == 0 {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var digest, canonical []byte
	var contentType, eventID string
	var terminal bool
	var validFrom, validUntil sql.NullInt64
	err = state.tx.QueryRowContext(ctx, selectCanonicalStateVersionSQL, int16(namespace),
		string(kind), objectID, strconv.FormatUint(version, 10)).Scan(&digest, &contentType,
		&canonical, &terminal, &validFrom, &validUntil, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return CanonicalStateRecord{}, false, nil
	}
	if err != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read canonical state history: %v", ErrCanonicalStateCorrupt, err))
	}
	record, prepareErr := canonicalStateFromSQL(namespace, kind, objectID, version,
		digest, contentType, canonical, terminal, validFrom, validUntil, eventID)
	if prepareErr != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, prepareErr)
	}
	return record, true, nil
}

const selectCanonicalStateHistorySQL = `
	SELECT version, state_digest, content_type, canonical_state, terminal,
		valid_from_unix_nano, valid_until_unix_nano, audit_event_id
	FROM cph_aiinfra.canonical_state_history
	WHERE state_namespace = $1 AND object_kind = $2 AND object_id = $3
	ORDER BY version DESC
	LIMIT $4`

// LoadCanonicalStateHistory returns a bounded newest-first immutable history.
// The caller supplies the semantic effective-time predicate; `limit+1` is
// queried so truncation fails closed instead of silently choosing an old row.
func (uow *CanonicalUOW) LoadCanonicalStateHistory(ctx context.Context,
	namespace CanonicalStateNamespace, kind CanonicalStateKind, objectID string,
	limit uint16) ([]CanonicalStateRecord, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer state.mu.Unlock()
	if _, ok := canonicalStateSpec(namespace, kind); !ok ||
		validateCanonicalText(objectID, 1024) != nil || limit == 0 || limit > 4096 {
		return nil, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	rows, err := state.tx.QueryContext(ctx, selectCanonicalStateHistorySQL,
		int16(namespace), string(kind), objectID, int(limit)+1)
	if err != nil {
		return nil, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read canonical history: %v", ErrCanonicalStateCorrupt, err))
	}
	defer rows.Close()
	result := make([]CanonicalStateRecord, 0, limit)
	for rows.Next() {
		var versionText, contentType, eventID string
		var digest, canonical []byte
		var terminal bool
		var validFrom, validUntil sql.NullInt64
		if err := rows.Scan(&versionText, &digest, &contentType, &canonical, &terminal,
			&validFrom, &validUntil, &eventID); err != nil {
			return nil, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		version, parseErr := strconv.ParseUint(versionText, 10, 64)
		record, recordErr := canonicalStateFromSQL(namespace, kind, objectID, version,
			digest, contentType, canonical, terminal, validFrom, validUntil, eventID)
		if parseErr != nil || recordErr != nil {
			return nil, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		result = append(result, record)
		if len(result) > int(limit) {
			return nil, poisonCanonicalLocked(state, ErrCanonicalInvalid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return result, nil
}

// LoadActiveGovernanceProfileState returns the unique immutable Governance
// profile activation whose half-open validity interval contains atUnixNano.
// Zero matches mean no active profile; multiple matches are durable corruption.
func (uow *CanonicalUOW) LoadActiveGovernanceProfileState(ctx context.Context,
	atUnixNano int64) (CanonicalStateRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return CanonicalStateRecord{}, false, err
	}
	defer state.mu.Unlock()
	if atUnixNano < 0 {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	rows, err := state.tx.QueryContext(ctx, selectActiveGovernanceProfileStateSQL,
		int16(CanonicalStateGovernance), string(CanonicalStateGovernanceProfileActivation),
		atUnixNano)
	if err != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read active Governance profile: %v", ErrCanonicalStateCorrupt, err))
	}
	defer rows.Close()
	var records []CanonicalStateRecord
	for rows.Next() {
		var objectID, versionText, contentType, eventID string
		var digest, canonical []byte
		var terminal bool
		var validFrom, validUntil sql.NullInt64
		if err := rows.Scan(&objectID, &versionText, &digest, &contentType, &canonical,
			&terminal, &validFrom, &validUntil, &eventID); err != nil {
			return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		version, parseErr := strconv.ParseUint(versionText, 10, 64)
		if parseErr != nil {
			return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		record, prepareErr := canonicalStateFromSQL(CanonicalStateGovernance,
			CanonicalStateGovernanceProfileActivation, objectID, version, digest, contentType,
			canonical, terminal, validFrom, validUntil, eventID)
		if prepareErr != nil || atUnixNano < record.ValidFromUnixNano || atUnixNano >= record.ValidUntilUnixNano {
			return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read active Governance profile: %v", ErrCanonicalStateCorrupt, err))
	}
	if len(records) > 1 {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	if len(records) == 0 {
		return CanonicalStateRecord{}, false, nil
	}
	return records[0], true, nil
}

const selectActiveIAMTransferProfileStateSQL = `
	SELECT object_id, version, state_digest, content_type, canonical_state,
		terminal, valid_from_unix_nano, valid_until_unix_nano, audit_event_id
	FROM cph_aiinfra.canonical_state_head
	WHERE state_namespace = $1 AND object_kind = $2
	  AND valid_from_unix_nano <= $3 AND valid_until_unix_nano > $3
	ORDER BY object_id
	LIMIT 2`

// LoadActiveIAMTransferProfileState resolves the unique active transfer
// profile activation. A second active row is fail-closed durable corruption;
// deployments needing multiple subject-scoped profiles must introduce a
// versioned selector rather than make this query guess.
func (uow *CanonicalUOW) LoadActiveIAMTransferProfileState(ctx context.Context,
	atUnixNano int64) (CanonicalStateRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return CanonicalStateRecord{}, false, err
	}
	defer state.mu.Unlock()
	if atUnixNano < 0 {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	rows, err := state.tx.QueryContext(ctx, selectActiveIAMTransferProfileStateSQL,
		int16(CanonicalStateIAM), string(CanonicalStateIAMTransferProfileActivation), atUnixNano)
	if err != nil {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	defer rows.Close()
	var result CanonicalStateRecord
	count := 0
	for rows.Next() {
		var objectID, versionText, contentType, eventID string
		var digest, canonical []byte
		var terminal bool
		var validFrom, validUntil sql.NullInt64
		if err := rows.Scan(&objectID, &versionText, &digest, &contentType, &canonical,
			&terminal, &validFrom, &validUntil, &eventID); err != nil {
			return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		version, parseErr := strconv.ParseUint(versionText, 10, 64)
		record, recordErr := canonicalStateFromSQL(CanonicalStateIAM,
			CanonicalStateIAMTransferProfileActivation, objectID, version, digest,
			contentType, canonical, terminal, validFrom, validUntil, eventID)
		if parseErr != nil || recordErr != nil {
			return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
		}
		result, count = record, count+1
	}
	if err := rows.Err(); err != nil || count > 1 {
		return CanonicalStateRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return result, count == 1, nil
}

// AssertCanonicalState locks and byte-compares one complete authoritative
// row. Coordinators use it for CASIntent AssertExisting dependencies and for
// writer-lease/profile-activation fences that are read-only in this UoW.
func (uow *CanonicalUOW) AssertCanonicalState(ctx context.Context,
	expected CanonicalStateRecord) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := prepareCanonicalStateRecord(expected)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if int(uow.bound.canonicalStateAssertions)+1 > MaxCanonicalStateAssertions {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	actual, found, err := loadCanonicalStateLocked(ctx, state, prepared.Namespace,
		prepared.Kind, prepared.ObjectID)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if !found || !equalCanonicalStateRecords(actual, prepared) {
		return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
	}
	uow.bound.canonicalStateAssertions++
	return nil
}

// AssertCanonicalStateAbsent performs the predicate read for an exact closed
// key on the active SERIALIZABLE transaction. It is the absent half of IAM
// principal/predecessor reservations; the subsequent insert remains the
// authoritative one-row CAS.
func (uow *CanonicalUOW) AssertCanonicalStateAbsent(ctx context.Context,
	namespace CanonicalStateNamespace, kind CanonicalStateKind, objectID string) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	if _, ok := canonicalStateSpec(namespace, kind); !ok ||
		validateCanonicalText(objectID, 1024) != nil {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	if int(uow.bound.canonicalStateAssertions)+1 > MaxCanonicalStateAssertions {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	_, found, err := loadCanonicalStateLocked(ctx, state, namespace, kind, objectID)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if found {
		return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
	}
	uow.bound.canonicalStateAssertions++
	return nil
}

func loadCanonicalStateLocked(ctx context.Context, state *transactionState,
	namespace CanonicalStateNamespace, kind CanonicalStateKind,
	objectID string) (CanonicalStateRecord, bool, error) {
	var version string
	var digest, canonical []byte
	var contentType, eventID string
	var terminal bool
	var validFrom, validUntil sql.NullInt64
	err := state.tx.QueryRowContext(ctx, selectCanonicalStateForUpdateSQL, int16(namespace),
		string(kind), objectID).Scan(&version, &digest, &contentType, &canonical, &terminal,
		&validFrom, &validUntil, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return CanonicalStateRecord{}, false, nil
	}
	if err != nil {
		return CanonicalStateRecord{}, false,
			fmt.Errorf("%w: read canonical state: %v", ErrCanonicalStateCorrupt, err)
	}
	parsed, parseErr := strconv.ParseUint(version, 10, 64)
	if parseErr != nil {
		return CanonicalStateRecord{}, false, ErrCanonicalStateCorrupt
	}
	record, prepareErr := canonicalStateFromSQL(namespace, kind, objectID, parsed, digest,
		contentType, canonical, terminal, validFrom, validUntil, eventID)
	if prepareErr != nil {
		return CanonicalStateRecord{}, false, prepareErr
	}
	return record, true, nil
}

func canonicalStateFromSQL(namespace CanonicalStateNamespace, kind CanonicalStateKind,
	objectID string, version uint64, digest []byte, contentType string, canonical []byte,
	terminal bool, validFrom, validUntil sql.NullInt64, eventID string) (CanonicalStateRecord, error) {
	if len(digest) != sha256.Size || validFrom.Valid != validUntil.Valid {
		return CanonicalStateRecord{}, ErrCanonicalStateCorrupt
	}
	record := CanonicalStateRecord{Namespace: namespace, Kind: kind, ObjectID: objectID,
		Version: version, ContentType: contentType, CanonicalState: canonical,
		Terminal: terminal, AuditEventID: eventID,
		HasValidityWindow: validFrom.Valid && validUntil.Valid,
		ValidFromUnixNano: validFrom.Int64, ValidUntilUnixNano: validUntil.Int64}
	copy(record.StateDigest[:], digest)
	prepared, err := prepareCanonicalStateRecord(record)
	if err != nil {
		return CanonicalStateRecord{}, ErrCanonicalStateCorrupt
	}
	return prepared, nil
}

func equalCanonicalStateRecords(left, right CanonicalStateRecord) bool {
	return left.Namespace == right.Namespace && left.Kind == right.Kind &&
		left.ObjectID == right.ObjectID && left.Version == right.Version &&
		left.StateDigest == right.StateDigest && left.ContentType == right.ContentType &&
		bytes.Equal(left.CanonicalState, right.CanonicalState) &&
		left.Terminal == right.Terminal && left.AuditEventID == right.AuditEventID &&
		left.HasValidityWindow == right.HasValidityWindow &&
		left.ValidFromUnixNano == right.ValidFromUnixNano &&
		left.ValidUntilUnixNano == right.ValidUntilUnixNano
}
