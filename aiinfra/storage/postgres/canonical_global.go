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

	"github.com/cypherium/cypher/aiinfra/globalid"
)

// GlobalClaimMutation is one closed set of deployment-global identifier
// claims attributed to AuditEventID. AuditEventID may be a child's reserved
// future event; it is not implicitly the outer UoW's actual event.
type GlobalClaimMutation struct {
	AuditEventID string
	Claims       []globalid.Claim
}

const insertGlobalHeadSQL = `
	INSERT INTO cph_aiinfra.global_identifier_head
		(identifier, owner_domain, owner_id, version, transfer_evidence_digest,
		 audit_event_id, uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, pg_current_xact_id())`

const updateGlobalHeadSQL = `
	UPDATE cph_aiinfra.global_identifier_head
	SET owner_domain = $2, owner_id = $3, version = $4,
		transfer_evidence_digest = $5, audit_event_id = $6,
		uow_scope_sha256 = $7, uow_message_id = $8
	WHERE identifier = $1 AND owner_domain = $9 AND owner_id = $10
		AND version = $11`

const insertGlobalHistorySQL = `
	INSERT INTO cph_aiinfra.global_identifier_history
		(identifier, version, owner_domain, owner_id, transfer_evidence_digest,
		 audit_event_id, uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, pg_current_xact_id())`

const insertGlobalClaimSQL = `
	INSERT INTO cph_aiinfra.global_identifier_claim
		(audit_event_id, claim_ordinal, identifier, claim_mode,
		 expected_owner_domain, expected_owner_id, expected_version,
		 next_owner_domain, next_owner_id, next_version,
		 transfer_evidence_digest, uow_scope_sha256, uow_message_id,
		 transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		pg_current_xact_id())`

const selectGlobalHeadForUpdateSQL = `
	SELECT owner_domain, owner_id, version
	FROM cph_aiinfra.global_identifier_head
	WHERE identifier = $1
	FOR UPDATE`

// ApplyGlobalClaims normalizes the entire batch before SQL. Mutating claims
// use a one-row insert/CAS plus immutable history; assertions lock and compare
// the exact authoritative row without manufacturing an update.
func (uow *CanonicalUOW) ApplyGlobalClaims(ctx context.Context, mutation GlobalClaimMutation) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	claims, err := prepareGlobalClaims(uow.bound, mutation)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if int(uow.bound.globalClaimOrdinal)+len(claims) > v2MaxGlobalClaims {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	assertsActualEvent := false
	for _, claim := range claims {
		uow.bound.globalClaimOrdinal++
		if err := applyGlobalClaimLocked(ctx, state, mutation.AuditEventID,
			uow.bound.globalClaimOrdinal, claim); err != nil {
			return poisonCanonicalLocked(state, err)
		}
		if mutation.AuditEventID == uow.bound.receipt.auditEventID &&
			claim.Identifier == uow.bound.receipt.auditEventID &&
			claim.Owner.Domain == globalid.OwnerGovernanceAuditEvent &&
			claim.Owner.ID == uow.bound.receipt.auditEventID {
			assertsActualEvent = true
		}
	}
	if assertsActualEvent {
		if uow.bound.globalEventAsserted {
			return poisonCanonicalLocked(state, ErrCanonicalUOWDuplicate)
		}
		uow.bound.globalEventAsserted = true
	}
	return nil
}

func prepareGlobalClaims(bound *canonicalTransactionState,
	mutation GlobalClaimMutation) ([]globalid.Claim, error) {
	if bound == nil || validateCanonicalText(mutation.AuditEventID, globalid.MaxIdentifierBytes) != nil {
		return nil, ErrCanonicalInvalid
	}
	claims, err := globalid.NormalizeClaims(mutation.Claims)
	if err != nil {
		return nil, fmt.Errorf("%w: global identifier claims: %v", ErrCanonicalInvalid, err)
	}
	for _, claim := range claims {
		if claim.Mode == globalid.TransferExisting &&
			(bound.receipt.kind != CanonicalAuditedFinal || mutation.AuditEventID != bound.receipt.auditEventID) {
			return nil, ErrCanonicalUOWPhase
		}
	}
	return claims, nil
}

func applyGlobalClaimLocked(ctx context.Context, state *transactionState, eventID string,
	ordinal uint16, claim globalid.Claim) error {
	var result sql.Result
	var err error
	evidence := nullableDigest(claim.TransferEvidenceDigest)
	switch claim.Mode {
	case globalid.ReserveNew:
		result, err = state.tx.ExecContext(ctx, insertGlobalHeadSQL, claim.Identifier,
			string(claim.Owner.Domain), claim.Owner.ID, strconv.FormatUint(claim.NextVersion, 10),
			evidence, eventID, state.scope[:], state.entry.MessageID[:])
	case globalid.AssertExisting:
		var domain, owner, version string
		err = state.tx.QueryRowContext(ctx, selectGlobalHeadForUpdateSQL, claim.Identifier).
			Scan(&domain, &owner, &version)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCanonicalCASMismatch
		}
		if err != nil {
			return fmt.Errorf("%w: lock global identifier: %v", ErrCanonicalStateCorrupt, err)
		}
		parsed, parseErr := strconv.ParseUint(version, 10, 64)
		if parseErr != nil || domain != string(claim.ExpectedOwner.Domain) ||
			owner != claim.ExpectedOwner.ID || parsed != claim.ExpectedVersion {
			return ErrCanonicalCASMismatch
		}
	case globalid.TransferExisting:
		result, err = state.tx.ExecContext(ctx, updateGlobalHeadSQL, claim.Identifier,
			string(claim.Owner.Domain), claim.Owner.ID, strconv.FormatUint(claim.NextVersion, 10),
			evidence, eventID, state.scope[:], state.entry.MessageID[:],
			string(claim.ExpectedOwner.Domain), claim.ExpectedOwner.ID,
			strconv.FormatUint(claim.ExpectedVersion, 10))
	default:
		return ErrCanonicalInvalid
	}
	if err != nil {
		return fmt.Errorf("%w: write global identifier head: %v", ErrCanonicalCASMismatch, err)
	}
	if claim.Mode != globalid.AssertExisting {
		if err := requireOneCanonicalRow(result); err != nil {
			return err
		}
		result, err = state.tx.ExecContext(ctx, insertGlobalHistorySQL, claim.Identifier,
			strconv.FormatUint(claim.NextVersion, 10), string(claim.Owner.Domain), claim.Owner.ID,
			evidence, eventID, state.scope[:], state.entry.MessageID[:])
		if err != nil {
			return fmt.Errorf("%w: insert global identifier history: %v", ErrCanonicalCASMismatch, err)
		}
		if err := requireOneCanonicalRow(result); err != nil {
			return err
		}
	}
	expectedDomain, expectedOwner, expectedVersion := globalExpectedArgs(claim)
	result, err = state.tx.ExecContext(ctx, insertGlobalClaimSQL, eventID, int16(ordinal),
		claim.Identifier, int16(claim.Mode), expectedDomain, expectedOwner, expectedVersion,
		string(claim.Owner.Domain), claim.Owner.ID, strconv.FormatUint(claim.NextVersion, 10),
		evidence, state.scope[:], state.entry.MessageID[:])
	if err != nil {
		return fmt.Errorf("%w: insert global identifier claim: %v", ErrCanonicalCASMismatch, err)
	}
	return requireOneCanonicalRow(result)
}

func globalExpectedArgs(claim globalid.Claim) (interface{}, interface{}, interface{}) {
	if claim.Mode == globalid.ReserveNew {
		return nil, nil, nil
	}
	return string(claim.ExpectedOwner.Domain), claim.ExpectedOwner.ID,
		strconv.FormatUint(claim.ExpectedVersion, 10)
}

// LookupGlobalID implements globalid.View using the exact transaction
// connection and locks the authoritative row for subsequent claims.
func (uow *CanonicalUOW) LookupGlobalID(ctx context.Context,
	identifier string) (globalid.Snapshot, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return globalid.Snapshot{}, false, err
	}
	defer state.mu.Unlock()
	if validateCanonicalText(identifier, globalid.MaxIdentifierBytes) != nil {
		return globalid.Snapshot{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var domain, owner, version string
	err = state.tx.QueryRowContext(ctx, selectGlobalHeadForUpdateSQL, identifier).
		Scan(&domain, &owner, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return globalid.Snapshot{}, false, nil
	}
	if err != nil {
		return globalid.Snapshot{}, false,
			poisonCanonicalLocked(state, fmt.Errorf("%w: read global identifier: %v", ErrCanonicalStateCorrupt, err))
	}
	parsed, parseErr := strconv.ParseUint(version, 10, 64)
	snapshot := globalid.Snapshot{Identifier: identifier,
		Owner: globalid.Owner{Domain: globalid.OwnerDomain(domain), ID: owner}, Version: parsed}
	if parseErr != nil || snapshot.Validate() != nil {
		return globalid.Snapshot{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return snapshot, true, nil
}

var _ globalid.View = (*CanonicalUOW)(nil)

func nonzeroDigest(value [sha256.Size]byte) bool {
	return value != ([sha256.Size]byte{})
}
