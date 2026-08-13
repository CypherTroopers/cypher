// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

// BusinessIdempotencyMutation is one canonical, prevalidated X/Y/member write
// set. ExpectedAuditEventID belongs to these children, not necessarily to the
// outer UoW's actual AuditEvent.
type BusinessIdempotencyMutation struct {
	ExpectedAuditEventID string
	OutcomeDigest        [sha256.Size]byte
	Claims               []idempotency.Claim
	CompoundMembers      []idempotency.CompoundMemberClaim
}

type preparedBusinessWrite struct {
	rowKind          int16
	binding          idempotency.Binding
	parent           *idempotency.Binding
	mode             idempotency.ClaimMode
	memberMode       idempotency.CompoundMemberClaimMode
	expectedState    idempotency.State
	expectedVersion  uint64
	expectedProgress [sha256.Size]byte
	nextState        idempotency.State
	nextVersion      uint64
	nextProgress     [sha256.Size]byte
	outcome          [sha256.Size]byte
}

const insertBusinessHeadSQL = `
	INSERT INTO cph_aiinfra.business_idempotency_head
		(idempotency_key, row_kind, operation_domain, owner_id, request_digest,
		 binding_digest, parent_key, parent_operation_domain, parent_owner_id,
		 parent_request_digest, state, version, progress_digest, outcome_digest,
		 audit_event_id, uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		$14, $15, $16, $17, pg_current_xact_id())`

const updateOrdinaryBusinessHeadSQL = `
	UPDATE cph_aiinfra.business_idempotency_head
	SET state = $7, version = $8, progress_digest = $9, outcome_digest = $10,
		audit_event_id = $11, uow_scope_sha256 = $12, uow_message_id = $13
	WHERE idempotency_key = $1 AND row_kind = $2 AND operation_domain = $3
		AND owner_id = $4 AND request_digest = $5 AND binding_digest = $6
		AND parent_key IS NULL AND parent_operation_domain IS NULL
		AND parent_owner_id IS NULL AND parent_request_digest IS NULL
		AND state = $14 AND version = $15 AND progress_digest = $16
		AND outcome_digest IS NULL AND audit_event_id = $11`

const updateAliasBusinessHeadSQL = `
	UPDATE cph_aiinfra.business_idempotency_head
	SET state = $11, version = $12, progress_digest = $13, outcome_digest = $14,
		audit_event_id = $15, uow_scope_sha256 = $16, uow_message_id = $17
	WHERE idempotency_key = $1 AND row_kind = $2 AND operation_domain = $3
		AND owner_id = $4 AND request_digest = $5 AND binding_digest = $6
		AND parent_key = $7 AND parent_operation_domain = $8
		AND parent_owner_id = $9 AND parent_request_digest = $10
		AND state = $18 AND version = $19 AND progress_digest = $20
		AND outcome_digest IS NULL AND audit_event_id = $15`

const insertBusinessHistorySQL = `
	INSERT INTO cph_aiinfra.business_idempotency_history
		(idempotency_key, version, row_kind, operation_domain, owner_id,
		 request_digest, binding_digest, parent_key, parent_operation_domain,
		 parent_owner_id, parent_request_digest, state, progress_digest,
		 outcome_digest, audit_event_id, uow_scope_sha256, uow_message_id,
		 transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
		$13, $14, $15, $16, $17, pg_current_xact_id())`

// ApplyBusinessIdempotency validates and canonicalizes the complete input
// before issuing SQL, then performs exact one-row CAS updates and matching
// immutable history inserts.
func (uow *CanonicalUOW) ApplyBusinessIdempotency(ctx context.Context,
	mutation BusinessIdempotencyMutation) error {
	state, err := uow.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	writes, err := prepareBusinessWrites(mutation)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if err := validateBusinessMutationPhase(uow.bound.receipt, mutation, writes); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if int(uow.bound.businessClaimCount)+len(writes) > v2MaxUOWBusinessClaims {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	for _, write := range writes {
		if err := applyBusinessWriteLocked(ctx, state, mutation.ExpectedAuditEventID, write); err != nil {
			return poisonCanonicalLocked(state, err)
		}
	}
	uow.bound.businessClaimCount += uint16(len(writes))
	return nil
}

func validateBusinessMutationPhase(receipt CanonicalUOWReceipt,
	mutation BusinessIdempotencyMutation, writes []preparedBusinessWrite) error {
	if len(writes) == 0 {
		return ErrCanonicalInvalid
	}
	if writes[0].nextState == idempotency.StateCompleted {
		if receipt.kind != CanonicalAuditedFinal || mutation.ExpectedAuditEventID != receipt.auditEventID ||
			mutation.OutcomeDigest != receipt.result.Digest() {
			return ErrCanonicalUOWPhase
		}
		return nil
	}
	if writes[0].nextState != idempotency.StateCollecting ||
		(receipt.kind == CanonicalAuditedFinal && mutation.ExpectedAuditEventID == receipt.auditEventID) {
		return ErrCanonicalUOWPhase
	}
	return nil
}

func prepareBusinessWrites(mutation BusinessIdempotencyMutation) ([]preparedBusinessWrite, error) {
	if validateCanonicalText(mutation.ExpectedAuditEventID, 1024) != nil || len(mutation.Claims) == 0 {
		return nil, ErrCanonicalInvalid
	}
	claims, err := idempotency.NormalizeClaims(mutation.Claims)
	if err != nil {
		return nil, fmt.Errorf("%w: idempotency claims: %v", ErrCanonicalInvalid, err)
	}
	var members []idempotency.CompoundMemberClaim
	if len(mutation.CompoundMembers) != 0 {
		members, err = idempotency.NormalizeCompoundMemberClaims(mutation.CompoundMembers)
		if err != nil || len(claims)+len(members) > idempotency.MaxClaims ||
			idempotency.ValidateDisjointClaimKeys(claims, members) != nil {
			return nil, fmt.Errorf("%w: compound-member claims", ErrCanonicalInvalid)
		}
	}
	for _, claim := range claims {
		if idempotency.ValidateCommitOutcome(claim, mutation.OutcomeDigest) != nil {
			return nil, ErrCanonicalInvalid
		}
	}
	for _, member := range members {
		if idempotency.ValidateCompoundMemberOutcome(member, mutation.OutcomeDigest) != nil {
			return nil, ErrCanonicalInvalid
		}
	}

	byKey := make(map[[ccse.MessageIDSize]byte]idempotency.Claim, len(claims))
	joinedParents := make(map[[ccse.MessageIDSize]byte]idempotency.Binding)
	for _, claim := range claims {
		byKey[claim.Binding.Key] = claim
		if claim.Binding.Domain == idempotency.OperationJoinedAudit {
			continue
		}
		joined, joinErr := idempotency.JoinedAuditBinding(claim.Binding)
		if joinErr == nil {
			joinedParents[joined.Key] = claim.Binding
		}
	}
	for _, claim := range claims {
		if claim.Binding.Domain == idempotency.OperationJoinedAudit {
			parent, ok := joinedParents[claim.Binding.Key]
			if !ok || validateJoinedClaim(parent, claim, byKey[parent.Key]) != nil {
				return nil, ErrCanonicalInvalid
			}
			continue
		}
		joined, joinErr := idempotency.JoinedAuditBinding(claim.Binding)
		if joinErr == nil && claim.Mode != idempotency.AdvanceCollection {
			joinedClaim, ok := byKey[joined.Key]
			if !ok || validateJoinedClaim(claim.Binding, joinedClaim, claim) != nil {
				return nil, ErrCanonicalInvalid
			}
		}
	}
	if len(members) != 0 {
		parentClaim, ok := byKey[members[0].ParentBinding.Key]
		joined, joinErr := idempotency.JoinedAuditBinding(members[0].ParentBinding)
		joinedClaim, joinedOK := byKey[joined.Key]
		if !ok || joinErr != nil || !joinedOK || parentClaim.Binding != members[0].ParentBinding ||
			validateJoinedClaim(parentClaim.Binding, joinedClaim, parentClaim) != nil {
			return nil, ErrCanonicalInvalid
		}
		for _, member := range members {
			if (member.Mode == idempotency.ReserveCompoundMember && parentClaim.Mode != idempotency.ReserveCollection) ||
				(member.Mode == idempotency.CompleteCompoundMember && parentClaim.Mode != idempotency.CompleteCollection) {
				return nil, ErrCanonicalInvalid
			}
		}
	}

	writes := make([]preparedBusinessWrite, 0, len(claims)+len(members))
	for _, claim := range claims {
		write := preparedBusinessWrite{
			rowKind: 1, binding: claim.Binding, mode: claim.Mode,
			expectedState: claim.ExpectedState, expectedVersion: claim.ExpectedVersion,
			expectedProgress: claim.ExpectedProgressDigest, nextState: claim.NextState,
			nextVersion: claim.NextVersion, nextProgress: claim.NextProgressDigest,
			outcome: mutation.OutcomeDigest,
		}
		if claim.Binding.Domain == idempotency.OperationJoinedAudit {
			parent := joinedParents[claim.Binding.Key]
			write.rowKind, write.parent = 2, &parent
		}
		writes = append(writes, write)
	}
	for _, member := range members {
		parent := member.ParentBinding
		writes = append(writes, preparedBusinessWrite{
			rowKind: 3, binding: member.Binding, parent: &parent, memberMode: member.Mode,
			expectedState: member.ExpectedState, expectedVersion: member.ExpectedVersion,
			expectedProgress: member.ProgressDigest, nextState: member.NextState,
			nextVersion: member.NextVersion, nextProgress: member.ProgressDigest,
			outcome: mutation.OutcomeDigest,
		})
	}
	return writes, nil
}

func validateJoinedClaim(parent idempotency.Binding, joined, parentClaim idempotency.Claim) error {
	expected, err := idempotency.JoinedAuditBinding(parent)
	parentDigest, digestErr := idempotency.BindingDigest(parent)
	if err != nil || digestErr != nil || joined.Binding != expected || parentClaim.Binding != parent ||
		joined.Mode == idempotency.AdvanceCollection || joined.NextState != parentClaim.NextState ||
		joined.ExpectedState != parentClaim.ExpectedState || joined.NextProgressDigest != parentDigest {
		return ErrCanonicalInvalid
	}
	switch parentClaim.Mode {
	case idempotency.ReserveCollection:
		if joined.Mode != idempotency.ReserveCollection || joined.ExpectedVersion != 0 ||
			joined.NextVersion != 1 || parentClaim.ExpectedVersion != 0 || parentClaim.NextVersion != 1 {
			return ErrCanonicalInvalid
		}
	case idempotency.CompleteCollection:
		if joined.Mode != idempotency.CompleteCollection || joined.ExpectedVersion != 1 ||
			joined.NextVersion != 2 || joined.ExpectedProgressDigest != parentDigest ||
			parentClaim.ExpectedVersion == 0 || parentClaim.NextVersion < 2 {
			return ErrCanonicalInvalid
		}
	default:
		return ErrCanonicalInvalid
	}
	return nil
}

func applyBusinessWriteLocked(ctx context.Context, state *transactionState, eventID string,
	write preparedBusinessWrite) error {
	bindingDigest, err := idempotency.BindingDigest(write.binding)
	if err != nil {
		return ErrCanonicalInvalid
	}
	parentKey, parentDomain, parentOwner, parentRequest := businessParentArgs(write.parent)
	progress := nullableDigest(write.nextProgress)
	outcome := nullableDigest(write.outcome)
	insert := write.mode == idempotency.ReserveCompletion || write.mode == idempotency.ReserveCollection ||
		write.memberMode == idempotency.ReserveCompoundMember
	var result sql.Result
	if insert {
		result, err = state.tx.ExecContext(ctx, insertBusinessHeadSQL,
			write.binding.Key[:], write.rowKind, string(write.binding.Domain), write.binding.OwnerID,
			write.binding.RequestDigest[:], bindingDigest[:], parentKey, parentDomain, parentOwner,
			parentRequest, int16(write.nextState), strconv.FormatUint(write.nextVersion, 10), progress,
			outcome, eventID, state.scope[:], state.entry.MessageID[:])
	} else if write.parent == nil {
		result, err = state.tx.ExecContext(ctx, updateOrdinaryBusinessHeadSQL,
			write.binding.Key[:], write.rowKind, string(write.binding.Domain), write.binding.OwnerID,
			write.binding.RequestDigest[:], bindingDigest[:], int16(write.nextState),
			strconv.FormatUint(write.nextVersion, 10), progress, outcome, eventID, state.scope[:],
			state.entry.MessageID[:], int16(write.expectedState), strconv.FormatUint(write.expectedVersion, 10),
			write.expectedProgress[:])
	} else {
		result, err = state.tx.ExecContext(ctx, updateAliasBusinessHeadSQL,
			write.binding.Key[:], write.rowKind, string(write.binding.Domain), write.binding.OwnerID,
			write.binding.RequestDigest[:], bindingDigest[:], parentKey, parentDomain, parentOwner,
			parentRequest, int16(write.nextState), strconv.FormatUint(write.nextVersion, 10), progress,
			outcome, eventID, state.scope[:], state.entry.MessageID[:], int16(write.expectedState),
			strconv.FormatUint(write.expectedVersion, 10), write.expectedProgress[:])
	}
	if err != nil {
		return fmt.Errorf("%w: write business head: %v", ErrCanonicalCASMismatch, err)
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return err
	}
	result, err = state.tx.ExecContext(ctx, insertBusinessHistorySQL,
		write.binding.Key[:], strconv.FormatUint(write.nextVersion, 10), write.rowKind,
		string(write.binding.Domain), write.binding.OwnerID, write.binding.RequestDigest[:], bindingDigest[:],
		parentKey, parentDomain, parentOwner, parentRequest, int16(write.nextState), progress, outcome,
		eventID, state.scope[:], state.entry.MessageID[:])
	if err != nil {
		return fmt.Errorf("%w: insert business history: %v", ErrCanonicalCASMismatch, err)
	}
	return requireOneCanonicalRow(result)
}

func businessParentArgs(parent *idempotency.Binding) (interface{}, interface{}, interface{}, interface{}) {
	if parent == nil {
		return nil, nil, nil, nil
	}
	return parent.Key[:], string(parent.Domain), parent.OwnerID, parent.RequestDigest[:]
}

func nullableDigest(value [sha256.Size]byte) interface{} {
	if value == ([sha256.Size]byte{}) {
		return nil
	}
	return value[:]
}

const selectBusinessHeadForUpdateSQL = `
	SELECT row_kind, operation_domain, owner_id, request_digest, binding_digest,
		parent_key, parent_operation_domain, parent_owner_id, parent_request_digest,
		state, version, progress_digest, outcome_digest
	FROM cph_aiinfra.business_idempotency_head
	WHERE idempotency_key = $1
	FOR UPDATE`

type storedBusinessRow struct {
	rowKind  int16
	binding  idempotency.Binding
	parent   *idempotency.Binding
	state    idempotency.State
	version  uint64
	progress [sha256.Size]byte
	outcome  [sha256.Size]byte
}

func (uow *CanonicalUOW) LookupBusinessIdempotency(ctx context.Context,
	key [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return idempotency.Snapshot{}, false, err
	}
	defer state.mu.Unlock()
	row, found, err := lookupBusinessRowLocked(ctx, state, key)
	if err != nil {
		return idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	if !found {
		return idempotency.Snapshot{}, false, nil
	}
	if row.rowKind == 3 {
		return idempotency.Snapshot{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	snapshot, err := row.snapshot()
	if err != nil {
		return idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	return snapshot, true, nil
}

func (uow *CanonicalUOW) SnapshotBusinessIdempotencyPair(ctx context.Context,
	parentKey, joinedKey [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool,
	idempotency.Snapshot, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, err
	}
	defer state.mu.Unlock()
	parentRow, parentFound, err := lookupBusinessRowLocked(ctx, state, parentKey)
	if err != nil {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	joinedRow, joinedFound, err := lookupBusinessRowLocked(ctx, state, joinedKey)
	if err != nil {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	parent, err := snapshotIfFound(parentRow, parentFound, 1)
	if err != nil {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	joined, err := snapshotIfFound(joinedRow, joinedFound, 2)
	if err != nil {
		return idempotency.Snapshot{}, false, idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	return parent, parentFound, joined, joinedFound, nil
}

func (uow *CanonicalUOW) SnapshotCompoundMemberState(ctx context.Context,
	memberKey [ccse.MessageIDSize]byte) (idempotency.CompoundMemberSnapshot, bool,
	idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, err
	}
	defer state.mu.Unlock()
	memberRow, found, err := lookupBusinessRowLocked(ctx, state, memberKey)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	if !found || memberRow.rowKind != 3 {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, nil
	}
	if memberRow.parent == nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	member := idempotency.CompoundMemberSnapshot{
		Binding: memberRow.binding, ParentBinding: *memberRow.parent, State: memberRow.state,
		Version: memberRow.version, ProgressDigest: memberRow.progress, OutcomeDigest: memberRow.outcome,
	}
	if member.Validate() != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	parentRow, parentFound, err := lookupBusinessRowLocked(ctx, state, memberRow.parent.Key)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	joinedBinding, joinErr := idempotency.JoinedAuditBinding(*memberRow.parent)
	if joinErr != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	joinedRow, joinedFound, err := lookupBusinessRowLocked(ctx, state, joinedBinding.Key)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	parent, err := snapshotIfFound(parentRow, parentFound, 1)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	joined, err := snapshotIfFound(joinedRow, joinedFound, 2)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, poisonCanonicalLocked(state, err)
	}
	return member, true, parent, parentFound, joined, joinedFound, nil
}

func lookupBusinessRowLocked(ctx context.Context, state *transactionState,
	key [ccse.MessageIDSize]byte) (storedBusinessRow, bool, error) {
	var row storedBusinessRow
	var domain, owner, version string
	var request, bindingDigest, parentKey, parentRequest, progress, outcome []byte
	var parentDomain, parentOwner sql.NullString
	err := state.tx.QueryRowContext(ctx, selectBusinessHeadForUpdateSQL, key[:]).Scan(
		&row.rowKind, &domain, &owner, &request, &bindingDigest, &parentKey, &parentDomain,
		&parentOwner, &parentRequest, &row.state, &version, &progress, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return storedBusinessRow{}, false, nil
	}
	if err != nil {
		return storedBusinessRow{}, false, fmt.Errorf("%w: read business row: %v", ErrCanonicalStateCorrupt, err)
	}
	parsedVersion, parseErr := strconv.ParseUint(version, 10, 64)
	if parseErr != nil || len(request) != sha256.Size || len(bindingDigest) != sha256.Size ||
		(len(progress) != 0 && len(progress) != sha256.Size) || (len(outcome) != 0 && len(outcome) != sha256.Size) {
		return storedBusinessRow{}, false, ErrCanonicalStateCorrupt
	}
	row.binding = idempotency.Binding{Key: key, Domain: idempotency.OperationDomain(domain), OwnerID: owner}
	copy(row.binding.RequestDigest[:], request)
	wantBinding, digestErr := idempotency.BindingDigest(row.binding)
	if digestErr != nil || !equalDigestBytes(wantBinding, bindingDigest) {
		return storedBusinessRow{}, false, ErrCanonicalStateCorrupt
	}
	row.version = parsedVersion
	copy(row.progress[:], progress)
	copy(row.outcome[:], outcome)
	if row.rowKind == 1 {
		if len(parentKey) != 0 || parentDomain.Valid || parentOwner.Valid || len(parentRequest) != 0 {
			return storedBusinessRow{}, false, ErrCanonicalStateCorrupt
		}
	} else if row.rowKind == 2 || row.rowKind == 3 {
		if len(parentKey) != ccse.MessageIDSize || !parentDomain.Valid || !parentOwner.Valid ||
			len(parentRequest) != sha256.Size {
			return storedBusinessRow{}, false, ErrCanonicalStateCorrupt
		}
		parent := idempotency.Binding{Domain: idempotency.OperationDomain(parentDomain.String), OwnerID: parentOwner.String}
		copy(parent.Key[:], parentKey)
		copy(parent.RequestDigest[:], parentRequest)
		if parent.Validate() != nil {
			return storedBusinessRow{}, false, ErrCanonicalStateCorrupt
		}
		row.parent = &parent
	} else {
		return storedBusinessRow{}, false, ErrCanonicalStateCorrupt
	}
	return row, true, nil
}

func (row storedBusinessRow) snapshot() (idempotency.Snapshot, error) {
	snapshot := idempotency.Snapshot{Binding: row.binding, State: row.state, Version: row.version,
		ProgressDigest: row.progress, OutcomeDigest: row.outcome}
	if snapshot.Validate() != nil {
		return idempotency.Snapshot{}, ErrCanonicalStateCorrupt
	}
	return snapshot, nil
}

func snapshotIfFound(row storedBusinessRow, found bool, wantKind int16) (idempotency.Snapshot, error) {
	if !found {
		return idempotency.Snapshot{}, nil
	}
	if row.rowKind != wantKind {
		return idempotency.Snapshot{}, ErrCanonicalStateCorrupt
	}
	return row.snapshot()
}

func equalDigestBytes(digest [sha256.Size]byte, encoded []byte) bool {
	if len(encoded) != sha256.Size {
		return false
	}
	for index := range digest {
		if digest[index] != encoded[index] {
			return false
		}
	}
	return true
}

var (
	_ idempotency.View               = (*CanonicalUOW)(nil)
	_ idempotency.JoinedView         = (*CanonicalUOW)(nil)
	_ idempotency.CompoundMemberView = (*CanonicalUOW)(nil)
)
