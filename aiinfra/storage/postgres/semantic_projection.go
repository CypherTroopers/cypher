// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
)

const (
	SemanticProjectionCodecIAMV2               = "cph.aiinfra.iam.semantic-projection.v2"
	SemanticProjectionCodecGovernancePolicyV2  = "cph.aiinfra.governance.policy-registry-projection.v2"
	SemanticProjectionCodecGovernanceProfileV2 = "cph.aiinfra.governance.profile-activation-projection.v2"
)

// SemanticProjectionRecord is a lossless companion to one exact immutable
// canonical-state history row.  It is never a separately mutable head.
type SemanticProjectionRecord struct {
	State               CanonicalStateRecord
	Codec               string
	ProjectionDigest    [sha256.Size]byte
	CanonicalProjection []byte
	LookupDigest        [sha256.Size]byte
	HasLookupDigest     bool
}

// ApplySemanticStateMutation atomically writes a canonical row and its
// lossless semantic companion. It is a storage primitive, not an authority
// grant: owner packages must expose a capability-bound workflow before this
// can be used to bootstrap policy/profile state. A companion failure poisons
// the UoW, so callers cannot commit a half-written state.
func (uow *CanonicalUOW) ApplySemanticStateMutation(ctx context.Context,
	mutation CanonicalStateMutation, projection SemanticProjectionRecord) error {
	preparedProjection, err := prepareSemanticProjection(projection)
	if err != nil {
		return err
	}
	preparedNext, err := prepareCanonicalStateRecord(mutation.Next)
	if err != nil || !equalCanonicalStateRecords(preparedNext, preparedProjection.State) {
		return ErrCanonicalInvalid
	}
	if mutation.Expected != nil {
		preparedExpected, expectedErr := prepareCanonicalStateRecord(*mutation.Expected)
		if expectedErr != nil || preparedExpected.Namespace != preparedNext.Namespace ||
			preparedExpected.Kind != preparedNext.Kind || preparedExpected.ObjectID != preparedNext.ObjectID {
			return ErrCanonicalInvalid
		}
	}
	if err := uow.ApplyCanonicalStates(ctx, []CanonicalStateMutation{mutation}); err != nil {
		return err
	}
	return uow.AttachSemanticProjection(ctx, preparedProjection)
}

func cloneSemanticProjectionRecord(value SemanticProjectionRecord) SemanticProjectionRecord {
	value.State.CanonicalState = bytes.Clone(value.State.CanonicalState)
	value.CanonicalProjection = bytes.Clone(value.CanonicalProjection)
	return value
}

const insertSemanticProjectionSQL = `
	INSERT INTO cph_aiinfra.canonical_semantic_projection
		(state_namespace, object_kind, object_id, version, state_digest,
		 projection_codec, projection_digest, canonical_projection,
		 lookup_digest, audit_event_id, uow_scope_sha256, uow_message_id, transaction_id)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
		pg_current_xact_id())`

// AttachSemanticProjection writes the companion only after ApplyCanonicalStates
// has written the exact canonical row in this same bound UoW.  Both the Go
// capability check and migration-3 deferred triggers reject an independent
// writer or a projection attached to a historical/pre-existing row.
func (uow *CanonicalUOW) AttachSemanticProjection(ctx context.Context,
	input SemanticProjectionRecord) error {
	projection, err := prepareSemanticProjection(input)
	var semanticResultDigest [sha256.Size]byte
	if err == nil && projection.Codec == SemanticProjectionCodecGovernancePolicyV2 {
		semanticResultDigest, err = uow.validateGovernancePolicyProjectionContext(ctx, projection)
	}
	state, lockErr := uow.lockForWrite(ctx)
	if lockErr != nil {
		return lockErr
	}
	defer state.mu.Unlock()
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if projection.Codec == SemanticProjectionCodecGovernancePolicyV2 &&
		semanticResultDigest != uow.bound.receipt.ResultDigest() {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	key := canonicalStateRecordKey(projection.State)
	written, ok := uow.bound.canonicalStateHeads[key]
	if !ok || !equalCanonicalStateRecords(written, projection.State) {
		return poisonCanonicalLocked(state, ErrCanonicalUOWPhase)
	}
	if int(uow.bound.semanticProjectionWrites)+1 > MaxCanonicalStateMutations ||
		!canonicalBudgetAllows(uow.bound.canonicalBytes, len(projection.CanonicalProjection), v2MaxUOWCanonicalBytes) {
		return poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	result, err := state.tx.ExecContext(ctx, insertSemanticProjectionSQL,
		int16(projection.State.Namespace), string(projection.State.Kind), projection.State.ObjectID,
		strconv.FormatUint(projection.State.Version, 10), projection.State.StateDigest[:],
		projection.Codec, projection.ProjectionDigest[:], projection.CanonicalProjection,
		nullableSemanticLookupDigest(projection), projection.State.AuditEventID,
		state.scope[:], state.entry.MessageID[:])
	if err != nil {
		return poisonCanonicalLocked(state,
			fmt.Errorf("%w: insert semantic projection: %v", ErrCanonicalCASMismatch, err))
	}
	if err := requireOneCanonicalRow(result); err != nil {
		return poisonCanonicalLocked(state, err)
	}
	uow.bound.semanticProjectionWrites++
	uow.bound.canonicalBytes += uint64(len(projection.CanonicalProjection))
	return nil
}

// validateGovernancePolicyProjectionContext resolves the exact immutable
// profile activation named by a policy acceptance. Structural decoding alone
// cannot validate tenant/audience/protocol/replay/role policy, so policy rows
// are never attachable until their profile preimage is already row-backed.
func (uow *CanonicalUOW) validateGovernancePolicyProjectionContext(ctx context.Context,
	projection SemanticProjectionRecord) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	decoded, err := governance.DecodePolicyRegistrySemanticProjectionV2(
		toGovernanceState(projection.State), projection.CanonicalProjection)
	if err != nil {
		return zero, ErrCanonicalInvalid
	}
	policy, _, ok := decoded.PolicyRegistryRecord()
	if !ok {
		return zero, ErrCanonicalInvalid
	}
	acceptance := policy.AcceptanceEvidence
	activation := acceptance.GovernanceProfileActivation
	objectID := "governance-profile:" + hex.EncodeToString(activation.GovernanceProfileDigestSHA256[:])
	profileState, found, err := uow.LoadCanonicalStateVersion(ctx, CanonicalStateGovernance,
		CanonicalStateGovernanceProfileActivation, objectID, activation.Version)
	if err != nil || !found {
		return zero, ErrCanonicalInvalid
	}
	profileProjection, found, err := uow.LoadSemanticProjection(ctx, profileState)
	if err != nil || !found || profileProjection.Codec != SemanticProjectionCodecGovernanceProfileV2 {
		return zero, ErrCanonicalInvalid
	}
	profileDecoded, err := governance.DecodeGovernanceProfileSemanticProjectionV2(
		toGovernanceState(profileState), profileProjection.CanonicalProjection)
	if err != nil || profileDecoded.Projection().Digest() != profileProjection.ProjectionDigest {
		return zero, ErrCanonicalInvalid
	}
	profile, storedActivation, ok := profileDecoded.GovernanceProfile()
	if !ok || storedActivation != activation ||
		governance.ValidatePolicyRegistrySemanticProjectionV2ForProfile(decoded,
			profile, storedActivation) != nil {
		return zero, ErrCanonicalInvalid
	}
	return acceptance.DurableResultDigestSHA256, nil
}

func prepareSemanticProjection(input SemanticProjectionRecord) (SemanticProjectionRecord, error) {
	state, err := prepareCanonicalStateRecord(input.State)
	if err != nil || len(input.CanonicalProjection) == 0 ||
		len(input.CanonicalProjection) > v2CanonicalStateMaxBytes ||
		input.ProjectionDigest == ([sha256.Size]byte{}) ||
		sha256.Sum256(input.CanonicalProjection) != input.ProjectionDigest ||
		!semanticProjectionCodecMatches(state.Namespace, state.Kind, input.Codec) {
		return SemanticProjectionRecord{}, ErrCanonicalInvalid
	}
	requiresLookup := state.Namespace == CanonicalStateIAM &&
		state.Kind == CanonicalStateIAMAcceptedOwnershipTransfer
	if input.HasLookupDigest != requiresLookup ||
		(requiresLookup && input.LookupDigest == ([sha256.Size]byte{})) ||
		(!requiresLookup && input.LookupDigest != ([sha256.Size]byte{})) {
		return SemanticProjectionRecord{}, ErrCanonicalInvalid
	}
	// The public storage mutation path is a semantic trust boundary.  A caller
	// may not attach merely well-formed JSON (or a self-consistent SHA-256) to a
	// canonical row: the namespace owner must be able to decode the companion
	// and rederive the exact v1 row from its retained preimages first.
	if err := validateSemanticProjectionOwner(state, input); err != nil {
		return SemanticProjectionRecord{}, ErrCanonicalInvalid
	}
	input.State = state
	input.CanonicalProjection = bytes.Clone(input.CanonicalProjection)
	return input, nil
}

func validateSemanticProjectionOwner(state CanonicalStateRecord,
	input SemanticProjectionRecord) error {
	switch state.Namespace {
	case CanonicalStateIAM:
		decoded, err := iam.DecodeSemanticProjectionV2(string(state.Kind), state.ObjectID,
			state.Version, state.StateDigest, state.CanonicalState, input.CanonicalProjection)
		if err != nil || decoded.Projection().Digest() != input.ProjectionDigest {
			return ErrCanonicalInvalid
		}
		lookup, present := decoded.Projection().LookupDigest()
		if present != input.HasLookupDigest || (present && lookup != input.LookupDigest) {
			return ErrCanonicalInvalid
		}
		return nil
	case CanonicalStateGovernance:
		record := governance.CanonicalStateRecord{Namespace: uint8(state.Namespace),
			Kind: string(state.Kind), ObjectID: state.ObjectID, Version: state.Version,
			StateDigestSHA256: state.StateDigest, ContentType: state.ContentType,
			CanonicalState: bytes.Clone(state.CanonicalState), Terminal: state.Terminal,
			AuditEventID: state.AuditEventID, HasValidityWindow: state.HasValidityWindow,
			ValidFromUnixNano: state.ValidFromUnixNano, ValidUntilUnixNano: state.ValidUntilUnixNano}
		var decoded governance.DecodedSemanticProjectionV2
		var err error
		switch state.Kind {
		case CanonicalStateGovernancePolicyRegistry:
			decoded, err = governance.DecodePolicyRegistrySemanticProjectionV2(record,
				input.CanonicalProjection)
		case CanonicalStateGovernanceProfileActivation:
			decoded, err = governance.DecodeGovernanceProfileSemanticProjectionV2(record,
				input.CanonicalProjection)
		default:
			return ErrCanonicalInvalid
		}
		projection := decoded.Projection()
		if err != nil || projection.Digest() != input.ProjectionDigest ||
			projection.Codec != input.Codec {
			return ErrCanonicalInvalid
		}
		return nil
	default:
		return ErrCanonicalInvalid
	}
}

func semanticProjectionCodecMatches(namespace CanonicalStateNamespace,
	kind CanonicalStateKind, codec string) bool {
	if namespace == CanonicalStateIAM && codec == SemanticProjectionCodecIAMV2 {
		switch kind {
		case CanonicalStateIAMKeyMaterial, CanonicalStateIAMIdentity,
			CanonicalStateIAMKeyLifecycle, CanonicalStateIAMAcceptedOwnershipTransfer,
			CanonicalStateIAMSubjectKeySet, CanonicalStateIAMTransferProfileActivation:
			return true
		}
	}
	return namespace == CanonicalStateGovernance &&
		((kind == CanonicalStateGovernancePolicyRegistry && codec == SemanticProjectionCodecGovernancePolicyV2) ||
			(kind == CanonicalStateGovernanceProfileActivation && codec == SemanticProjectionCodecGovernanceProfileV2))
}

const selectSemanticProjectionForStateSQL = `
	SELECT projection_codec, projection_digest, canonical_projection, lookup_digest, audit_event_id
	FROM cph_aiinfra.canonical_semantic_projection
	WHERE state_namespace = $1 AND object_kind = $2 AND object_id = $3
		AND version = $4 AND state_digest = $5`

// LoadSemanticProjection is the transaction-bound history read. Absence is
// reported distinctly so callers can fail with their package's explicit
// unrehydratable error; no v1 synthesis/backfill is attempted.
func (uow *CanonicalUOW) LoadSemanticProjection(ctx context.Context,
	canonical CanonicalStateRecord) (SemanticProjectionRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return SemanticProjectionRecord{}, false, err
	}
	defer state.mu.Unlock()
	prepared, err := prepareCanonicalStateRecord(canonical)
	if err != nil {
		return SemanticProjectionRecord{}, false, poisonCanonicalLocked(state, err)
	}
	result, found, err := loadSemanticProjection(ctx, state.tx, prepared)
	if err != nil {
		return SemanticProjectionRecord{}, false, poisonCanonicalLocked(state, err)
	}
	return result, found, nil
}

type semanticProjectionQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadSemanticProjection(ctx context.Context, db semanticProjectionQuery,
	canonical CanonicalStateRecord) (SemanticProjectionRecord, bool, error) {
	var codec, eventID string
	var digest, content, lookup []byte
	err := db.QueryRowContext(ctx, selectSemanticProjectionForStateSQL,
		int16(canonical.Namespace), string(canonical.Kind), canonical.ObjectID,
		strconv.FormatUint(canonical.Version, 10), canonical.StateDigest[:]).Scan(
		&codec, &digest, &content, &lookup, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return SemanticProjectionRecord{}, false, nil
	}
	if err != nil || len(digest) != sha256.Size || (len(lookup) != 0 && len(lookup) != sha256.Size) ||
		eventID != canonical.AuditEventID {
		return SemanticProjectionRecord{}, false,
			fmt.Errorf("%w: read semantic projection", ErrCanonicalStateCorrupt)
	}
	result := SemanticProjectionRecord{State: canonical, Codec: codec,
		CanonicalProjection: content}
	copy(result.ProjectionDigest[:], digest)
	if len(lookup) != 0 {
		copy(result.LookupDigest[:], lookup)
		result.HasLookupDigest = true
	}
	prepared, prepareErr := prepareSemanticProjection(result)
	if prepareErr != nil {
		return SemanticProjectionRecord{}, false, ErrCanonicalStateCorrupt
	}
	return prepared, true, nil
}

func nullableSemanticLookupDigest(value SemanticProjectionRecord) any {
	if !value.HasLookupDigest {
		return nil
	}
	return value.LookupDigest[:]
}

const selectSemanticProjectionByLookupDigestSQL = `
	SELECT projection.object_id, projection.version, projection.state_digest,
		state.content_type, state.canonical_state, state.terminal,
		state.valid_from_unix_nano, state.valid_until_unix_nano,
		projection.projection_codec, projection.projection_digest,
		projection.canonical_projection, projection.audit_event_id
	FROM cph_aiinfra.canonical_semantic_projection projection
	JOIN cph_aiinfra.canonical_state_history state
	  ON state.state_namespace = projection.state_namespace
	 AND state.object_kind = projection.object_kind
	 AND state.object_id = projection.object_id
	 AND state.version = projection.version
	WHERE projection.state_namespace = $1 AND projection.object_kind = $2
	  AND projection.lookup_digest = $3`

// LoadSemanticProjectionByLookupDigest performs the one closed secondary-key
// lookup admitted by migration 3.  It is intentionally limited to immutable
// accepted ownership transfers; no unbounded JSON/history scan is possible.
func (uow *CanonicalUOW) LoadSemanticProjectionByLookupDigest(ctx context.Context,
	namespace CanonicalStateNamespace, kind CanonicalStateKind,
	lookup [sha256.Size]byte) (SemanticProjectionRecord, bool, error) {
	state, err := uow.lock(ctx)
	if err != nil {
		return SemanticProjectionRecord{}, false, err
	}
	defer state.mu.Unlock()
	if namespace != CanonicalStateIAM || kind != CanonicalStateIAMAcceptedOwnershipTransfer ||
		lookup == ([sha256.Size]byte{}) {
		return SemanticProjectionRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalInvalid)
	}
	var objectID, versionText, contentType, codec, eventID string
	var stateDigest, canonicalState, projectionDigest, projectionBytes []byte
	var terminal bool
	var validFrom, validUntil sql.NullInt64
	err = state.tx.QueryRowContext(ctx, selectSemanticProjectionByLookupDigestSQL,
		int16(namespace), string(kind), lookup[:]).Scan(&objectID, &versionText,
		&stateDigest, &contentType, &canonicalState, &terminal, &validFrom, &validUntil,
		&codec, &projectionDigest, &projectionBytes, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return SemanticProjectionRecord{}, false, nil
	}
	version, parseErr := strconv.ParseUint(versionText, 10, 64)
	if err != nil || parseErr != nil || len(projectionDigest) != sha256.Size {
		return SemanticProjectionRecord{}, false, poisonCanonicalLocked(state,
			fmt.Errorf("%w: read semantic lookup", ErrCanonicalStateCorrupt))
	}
	canonical, canonicalErr := canonicalStateFromSQL(namespace, kind, objectID, version,
		stateDigest, contentType, canonicalState, terminal, validFrom, validUntil, eventID)
	if canonicalErr != nil {
		return SemanticProjectionRecord{}, false, poisonCanonicalLocked(state, canonicalErr)
	}
	result := SemanticProjectionRecord{State: canonical, Codec: codec,
		CanonicalProjection: projectionBytes, LookupDigest: lookup, HasLookupDigest: true}
	copy(result.ProjectionDigest[:], projectionDigest)
	prepared, prepareErr := prepareSemanticProjection(result)
	if prepareErr != nil {
		return SemanticProjectionRecord{}, false, poisonCanonicalLocked(state, ErrCanonicalStateCorrupt)
	}
	return prepared, true, nil
}

// AssertSemanticProjection byte-compares a read companion in the same
// SERIALIZABLE UoW as its canonical-state assertion.
func (uow *CanonicalUOW) AssertSemanticProjection(ctx context.Context,
	expected SemanticProjectionRecord) error {
	state, err := uow.lock(ctx)
	if err != nil {
		return err
	}
	defer state.mu.Unlock()
	prepared, err := prepareSemanticProjection(expected)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	actual, found, err := loadSemanticProjection(ctx, state.tx, prepared.State)
	if err != nil {
		return poisonCanonicalLocked(state, err)
	}
	if !found || actual.Codec != prepared.Codec ||
		actual.ProjectionDigest != prepared.ProjectionDigest ||
		!bytes.Equal(actual.CanonicalProjection, prepared.CanonicalProjection) {
		return poisonCanonicalLocked(state, ErrCanonicalCASMismatch)
	}
	return nil
}
