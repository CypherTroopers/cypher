// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/iam"
)

// ProductionSemanticAdapter is the transaction-bound PostgreSQL IAM read
// model. Core IAM state is always restored from an exact canonical history
// row plus its mandatory v2 companion. Reversible sidecars are decoded by
// IAM's v1 codec. Ownership-transfer activations and durable collections are
// restored from PostgreSQL; the injected Profile supplies only deployment
// validation callbacks and is never used as a semantic state fallback.
type ProductionSemanticAdapter struct {
	*CanonicalUOW
	iam.Profile
}

func NewProductionSemanticAdapter(uow *CanonicalUOW,
	profile iam.Profile) (*ProductionSemanticAdapter, error) {
	if uow == nil || profile == nil {
		return nil, ErrCanonicalInvalid
	}
	return &ProductionSemanticAdapter{CanonicalUOW: uow, Profile: profile}, nil
}

func (adapter *ProductionSemanticAdapter) CanonicalTransactionBoundary() *CanonicalUOW {
	if adapter == nil {
		return nil
	}
	return adapter.CanonicalUOW
}

func (adapter *ProductionSemanticAdapter) OwnershipTransferProfile(ctx context.Context,
	request iam.OwnershipTransferProfileRequest) (iam.OwnershipTransferProfile, error) {
	record, found, err := adapter.LoadActiveIAMTransferProfileState(ctx, request.EffectiveAtUnixNano)
	if err != nil {
		return iam.OwnershipTransferProfile{}, err
	}
	if !found {
		return iam.OwnershipTransferProfile{}, iam.ErrCanonicalStateUnrehydratable
	}
	decoded, err := adapter.decodeIAMProjection(ctx, record)
	if err != nil {
		return iam.OwnershipTransferProfile{}, err
	}
	profile, ok := decoded.OwnershipTransferProfile()
	if !ok || request.SubjectKind < 1 || request.SubjectKind > 8 ||
		request.TransferAuthorizationID == "" || request.EffectiveAtUnixNano < profile.Activation.ValidFromUnixNano ||
		request.EffectiveAtUnixNano >= profile.Activation.ValidUntilUnixNano {
		return iam.OwnershipTransferProfile{}, iam.ErrTransferAuthorizationRequired
	}
	return profile, nil
}

func (adapter *ProductionSemanticAdapter) OwnershipTransferProfileAt(ctx context.Context,
	request iam.OwnershipTransferProfileHistoryRequest) (iam.OwnershipTransferProfile, error) {
	if request.ProfileID == "" || request.ProfileVersion == 0 || request.SubjectKind < 1 ||
		request.SubjectKind > 8 || request.ProfileDigest == ([sha256.Size]byte{}) ||
		request.ActivationVersion == 0 || request.ActivationSnapshotDigest == ([sha256.Size]byte{}) {
		return iam.OwnershipTransferProfile{}, iam.ErrTransferAuthorizationRequired
	}
	rows, err := adapter.LoadCanonicalStateHistory(ctx, CanonicalStateIAM,
		CanonicalStateIAMTransferProfileActivation, request.ProfileID, 4096)
	if err != nil {
		return iam.OwnershipTransferProfile{}, err
	}
	for _, row := range rows {
		decoded, decodeErr := adapter.decodeIAMProjection(ctx, row)
		if decodeErr != nil {
			return iam.OwnershipTransferProfile{}, decodeErr
		}
		profile, ok := decoded.OwnershipTransferProfile()
		if ok && profile.ProfileVersion == request.ProfileVersion &&
			profile.Activation.ActivationVersion == request.ActivationVersion &&
			profile.Activation.ProfileDigest == request.ProfileDigest &&
			profile.Activation.SnapshotDigest == request.ActivationSnapshotDigest {
			return profile, nil
		}
	}
	return iam.OwnershipTransferProfile{}, iam.ErrCanonicalStateUnrehydratable
}

func iamKind(kind string) (CanonicalStateKind, bool) {
	switch kind {
	case iam.CanonicalStateKindIAMKeyMaterial:
		return CanonicalStateIAMKeyMaterial, true
	case iam.CanonicalStateKindIAMIdentity:
		return CanonicalStateIAMIdentity, true
	case iam.CanonicalStateKindIAMKeyLifecycle:
		return CanonicalStateIAMKeyLifecycle, true
	case iam.CanonicalStateKindIAMAcceptedOwnershipTransfer:
		return CanonicalStateIAMAcceptedOwnershipTransfer, true
	case iam.CanonicalStateKindIAMProofChallenge:
		return CanonicalStateIAMProofChallenge, true
	case iam.CanonicalStateKindIAMPrincipalIdentityIndex:
		return CanonicalStateIAMPrincipalIdentityIndex, true
	case iam.CanonicalStateKindIAMRotationPredecessorIndex:
		return CanonicalStateIAMRotationPredecessorIndex, true
	case iam.CanonicalStateKindIAMSubjectKeySet:
		return CanonicalStateIAMSubjectKeySet, true
	case iam.CanonicalStateKindIAMWriterLease:
		return CanonicalStateIAMWriterLease, true
	case iam.CanonicalStateKindIAMTransferProfileActivation:
		return CanonicalStateIAMTransferProfileActivation, true
	default:
		return "", false
	}
}

func iamContentType(kind CanonicalStateKind) (string, bool) {
	switch kind {
	case CanonicalStateIAMKeyMaterial:
		return CanonicalStateIAMKeyMaterialContentType, true
	case CanonicalStateIAMIdentity:
		return CanonicalStateIAMIdentityContentType, true
	case CanonicalStateIAMKeyLifecycle:
		return CanonicalStateIAMKeyLifecycleContentType, true
	case CanonicalStateIAMAcceptedOwnershipTransfer:
		return CanonicalStateIAMAcceptedOwnershipTransferContentType, true
	case CanonicalStateIAMProofChallenge:
		return CanonicalStateIAMProofChallengeContentType, true
	case CanonicalStateIAMPrincipalIdentityIndex:
		return CanonicalStateIAMPrincipalIdentityIndexContentType, true
	case CanonicalStateIAMRotationPredecessorIndex:
		return CanonicalStateIAMRotationPredecessorIndexContentType, true
	case CanonicalStateIAMSubjectKeySet:
		return CanonicalStateIAMSubjectKeySetContentType, true
	case CanonicalStateIAMWriterLease:
		return CanonicalStateIAMWriterLeaseContentType, true
	case CanonicalStateIAMTransferProfileActivation:
		return CanonicalStateIAMTransferProfileActivationContentType, true
	default:
		return "", false
	}
}

func toIAMState(value CanonicalStateRecord) iam.CanonicalStateRecord {
	return iam.CanonicalStateRecord{Namespace: uint8(value.Namespace), Kind: string(value.Kind),
		ObjectID: value.ObjectID, Version: value.Version, StateDigestSHA256: value.StateDigest,
		ContentType: value.ContentType, CanonicalState: bytes.Clone(value.CanonicalState),
		Terminal: value.Terminal, AuditEventID: value.AuditEventID,
		HasValidityWindow: value.HasValidityWindow, ValidFromUnixNano: value.ValidFromUnixNano,
		ValidUntilUnixNano: value.ValidUntilUnixNano}
}

func fromIAMState(value iam.CanonicalStateRecord) (CanonicalStateRecord, error) {
	kind, ok := iamKind(value.Kind)
	if !ok || value.Namespace != iam.CanonicalStateNamespaceIAM {
		return CanonicalStateRecord{}, ErrCanonicalInvalid
	}
	return prepareCanonicalStateRecord(CanonicalStateRecord{Namespace: CanonicalStateIAM,
		Kind: kind, ObjectID: value.ObjectID, Version: value.Version,
		StateDigest: value.StateDigestSHA256, ContentType: value.ContentType,
		CanonicalState: bytes.Clone(value.CanonicalState), Terminal: value.Terminal,
		AuditEventID: value.AuditEventID, HasValidityWindow: value.HasValidityWindow,
		ValidFromUnixNano: value.ValidFromUnixNano, ValidUntilUnixNano: value.ValidUntilUnixNano})
}

func (adapter *ProductionSemanticAdapter) decodeIAMProjection(ctx context.Context,
	record CanonicalStateRecord) (iam.DecodedSemanticProjectionV2, error) {
	if adapter == nil || adapter.CanonicalUOW == nil {
		return iam.DecodedSemanticProjectionV2{}, ErrCanonicalUOWRequired
	}
	projection, found, err := adapter.LoadSemanticProjection(ctx, record)
	if err != nil {
		return iam.DecodedSemanticProjectionV2{}, err
	}
	if !found || projection.Codec != SemanticProjectionCodecIAMV2 {
		return iam.DecodedSemanticProjectionV2{}, iam.ErrCanonicalStateUnrehydratable
	}
	decoded, err := iam.DecodeSemanticProjectionV2(string(record.Kind), record.ObjectID,
		record.Version, record.StateDigest, record.CanonicalState, projection.CanonicalProjection)
	if err != nil || decoded.Projection().Digest() != projection.ProjectionDigest {
		return iam.DecodedSemanticProjectionV2{}, iam.ErrCanonicalStateInvalid
	}
	if lookup, present := decoded.Projection().LookupDigest(); present != projection.HasLookupDigest || (present && lookup != projection.LookupDigest) {
		return iam.DecodedSemanticProjectionV2{}, iam.ErrCanonicalStateInvalid
	}
	return decoded, nil
}

func (adapter *ProductionSemanticAdapter) LookupKeyMaterial(ctx context.Context,
	keyID string) (iam.KeyMaterialSnapshot, bool, error) {
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyMaterial, keyID)
	if err != nil || !found {
		return iam.KeyMaterialSnapshot{}, found, err
	}
	decoded, err := adapter.decodeIAMProjection(ctx, record)
	if err != nil {
		return iam.KeyMaterialSnapshot{}, false, err
	}
	value, ok := decoded.KeyMaterial()
	if !ok {
		return iam.KeyMaterialSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupIdentity(ctx context.Context,
	ref iam.EntityRef) (iam.IdentitySnapshot, bool, error) {
	if ref.Kind != iam.EntityIdentity || ref.ID == "" {
		return iam.IdentitySnapshot{}, false, iam.ErrInvalidInput
	}
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMIdentity, ref.ID)
	if err != nil || !found {
		return iam.IdentitySnapshot{}, found, err
	}
	decoded, err := adapter.decodeIAMProjection(ctx, record)
	if err != nil {
		return iam.IdentitySnapshot{}, false, err
	}
	value, ok := decoded.Identity()
	if !ok || value.Ref != ref {
		return iam.IdentitySnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupIdentityByPrincipal(ctx context.Context,
	kind uint32, principal string) (iam.IdentitySnapshot, bool, error) {
	objectID, err := iam.CanonicalPrincipalObjectID(kind, principal)
	if err != nil {
		return iam.IdentitySnapshot{}, false, err
	}
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMPrincipalIdentityIndex, objectID)
	if err != nil || !found {
		return iam.IdentitySnapshot{}, found, err
	}
	decoded, err := iam.DecodeCanonicalIAMStateRecord(toIAMState(record))
	if err != nil {
		return iam.IdentitySnapshot{}, false, err
	}
	index, ok := decoded.PrincipalIdentityIndex()
	if !ok || index.PrincipalKind != kind || index.PrincipalIdentity != principal {
		return iam.IdentitySnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	value, found, err := adapter.LookupIdentity(ctx, index.Owner)
	if err != nil || !found || value.StateVersion != index.IdentityStateVersion ||
		value.WriterEpoch != index.IdentityWriterEpoch || value.State != index.IdentityState {
		if err != nil {
			return iam.IdentitySnapshot{}, false, err
		}
		return iam.IdentitySnapshot{}, false, iam.ErrViewInconsistent
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupKeyLifecycle(ctx context.Context,
	keyID string) (iam.KeyLifecycleSnapshot, bool, error) {
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyLifecycle, keyID)
	if err != nil || !found {
		return iam.KeyLifecycleSnapshot{}, found, err
	}
	decoded, err := adapter.decodeIAMProjection(ctx, record)
	if err != nil {
		return iam.KeyLifecycleSnapshot{}, false, err
	}
	value, ok := decoded.KeyLifecycle()
	if !ok {
		return iam.KeyLifecycleSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupSubjectKeyLifecycles(ctx context.Context,
	kind uint32, principal string) ([]iam.KeyLifecycleSnapshot, error) {
	objectID, err := iam.CanonicalPrincipalObjectID(kind, principal)
	if err != nil {
		return nil, err
	}
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMSubjectKeySet, objectID)
	if err != nil {
		return nil, err
	}
	if !found {
		return []iam.KeyLifecycleSnapshot{}, nil
	}
	decoded, err := adapter.decodeIAMProjection(ctx, record)
	if err != nil {
		return nil, err
	}
	storedKind, storedPrincipal, members, ok := decoded.SubjectKeySet()
	if !ok || storedKind != kind || storedPrincipal != principal || len(members) > 256 {
		return nil, iam.ErrCanonicalStateInvalid
	}
	result := make([]iam.KeyLifecycleSnapshot, 0, len(members))
	for _, member := range members {
		row, rowFound, loadErr := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
			CanonicalStateIAMKeyLifecycle, member.Entity.ID, member.ExpectedStateVersion)
		if loadErr != nil {
			return nil, loadErr
		}
		if !rowFound || row.StateDigest != member.ExpectedSnapshotDigest {
			return nil, iam.ErrViewInconsistent
		}
		item, decodeErr := adapter.decodeIAMProjection(ctx, row)
		if decodeErr != nil {
			return nil, decodeErr
		}
		lifecycle, lifecycleOK := item.KeyLifecycle()
		if !lifecycleOK || member.Entity != (iam.EntityRef{Kind: iam.EntityKeyLifecycle,
			PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID}) ||
			lifecycle.WriterEpoch != member.ExpectedWriterEpoch ||
			lifecycle.State != member.ExpectedState {
			return nil, iam.ErrViewInconsistent
		}
		result = append(result, lifecycle)
	}
	return result, nil
}

func (adapter *ProductionSemanticAdapter) LookupRotationSuccessor(ctx context.Context,
	predecessor string) (iam.KeyLifecycleSnapshot, bool, error) {
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMRotationPredecessorIndex, predecessor)
	if err != nil || !found {
		return iam.KeyLifecycleSnapshot{}, found, err
	}
	decoded, err := iam.DecodeCanonicalIAMStateRecord(toIAMState(record))
	if err != nil {
		return iam.KeyLifecycleSnapshot{}, false, err
	}
	index, ok := decoded.RotationPredecessorIndex()
	if !ok || index.PredecessorKeyID != predecessor {
		return iam.KeyLifecycleSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return adapter.LookupKeyLifecycle(ctx, index.SuccessorKeyID)
}

func (adapter *ProductionSemanticAdapter) lookupAcceptedTransfer(ctx context.Context,
	evidence [sha256.Size]byte) (iam.DecodedSemanticProjectionV2, bool, error) {
	projection, found, err := adapter.LoadSemanticProjectionByLookupDigest(ctx,
		CanonicalStateIAM, CanonicalStateIAMAcceptedOwnershipTransfer, evidence)
	if err != nil || !found {
		return iam.DecodedSemanticProjectionV2{}, found, err
	}
	decoded, err := iam.DecodeSemanticProjectionV2(string(projection.State.Kind),
		projection.State.ObjectID, projection.State.Version, projection.State.StateDigest,
		projection.State.CanonicalState, projection.CanonicalProjection)
	if err != nil || projection.ProjectionDigest != decoded.Projection().Digest() {
		return iam.DecodedSemanticProjectionV2{}, false, iam.ErrCanonicalStateInvalid
	}
	lookup, ok := decoded.Projection().LookupDigest()
	if !ok || lookup != evidence || !projection.HasLookupDigest || projection.LookupDigest != evidence {
		return iam.DecodedSemanticProjectionV2{}, false, iam.ErrCanonicalStateInvalid
	}
	return decoded, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupAcceptedOwnershipTransfer(ctx context.Context,
	evidence [sha256.Size]byte) (iam.AcceptedOwnershipTransferSnapshot, bool, error) {
	decoded, found, err := adapter.lookupAcceptedTransfer(ctx, evidence)
	if err != nil || !found {
		return iam.AcceptedOwnershipTransferSnapshot{}, found, err
	}
	value, ok := decoded.AcceptedOwnershipTransfer()
	if !ok {
		return iam.AcceptedOwnershipTransferSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupOwnershipTransfer(ctx context.Context,
	evidence [sha256.Size]byte) (iam.OwnershipTransferSnapshot, bool, error) {
	decoded, found, err := adapter.lookupAcceptedTransfer(ctx, evidence)
	if err != nil || !found {
		return iam.OwnershipTransferSnapshot{}, found, err
	}
	value, ok := decoded.OwnershipTransferSnapshot()
	if !ok {
		return iam.OwnershipTransferSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupProofChallenge(ctx context.Context,
	challenge [sha256.Size]byte) (iam.ProofChallengeSnapshot, bool, error) {
	if challenge == ([sha256.Size]byte{}) {
		return iam.ProofChallengeSnapshot{}, false, iam.ErrInvalidInput
	}
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMProofChallenge, hex.EncodeToString(challenge[:]))
	if err != nil || !found {
		return iam.ProofChallengeSnapshot{}, found, err
	}
	decoded, err := iam.DecodeCanonicalIAMStateRecord(toIAMState(record))
	if err != nil {
		return iam.ProofChallengeSnapshot{}, false, err
	}
	value, ok := decoded.ProofChallenge()
	if !ok || value.Challenge != challenge {
		return iam.ProofChallengeSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupWriterLease(ctx context.Context,
	entity iam.EntityRef) (iam.WriterLeaseSnapshot, bool, error) {
	objectID, err := iam.CanonicalEntityObjectID(entity)
	if err != nil {
		return iam.WriterLeaseSnapshot{}, false, err
	}
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM,
		CanonicalStateIAMWriterLease, objectID)
	if err != nil || !found {
		return iam.WriterLeaseSnapshot{}, found, err
	}
	decoded, err := iam.DecodeCanonicalIAMStateRecord(toIAMState(record))
	if err != nil {
		return iam.WriterLeaseSnapshot{}, false, err
	}
	value, ok := decoded.WriterLease()
	if !ok || value.Entity != entity {
		return iam.WriterLeaseSnapshot{}, false, iam.ErrCanonicalStateInvalid
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupIdentityAt(ctx context.Context, ref iam.EntityRef,
	at int64) (iam.IdentitySnapshot, bool, error) {
	if ref.Kind != iam.EntityIdentity || at < 0 {
		return iam.IdentitySnapshot{}, false, iam.ErrInvalidInput
	}
	rows, err := adapter.LoadCanonicalStateHistory(ctx, CanonicalStateIAM,
		CanonicalStateIAMIdentity, ref.ID, 4096)
	if err != nil {
		return iam.IdentitySnapshot{}, false, err
	}
	for _, row := range rows {
		decoded, decodeErr := adapter.decodeIAMProjection(ctx, row)
		if decodeErr != nil {
			return iam.IdentitySnapshot{}, false, decodeErr
		}
		value, ok := decoded.Identity()
		if !ok || value.Ref != ref {
			return iam.IdentitySnapshot{}, false, iam.ErrCanonicalStateInvalid
		}
		if value.CreatedAtUnixNano <= at && value.ValidFromUnixNano <= at &&
			(value.ValidUntilUnixNano == 0 || at < value.ValidUntilUnixNano) {
			return value, true, nil
		}
	}
	return iam.IdentitySnapshot{}, false, nil
}

func (adapter *ProductionSemanticAdapter) LookupKeyLifecycleAt(ctx context.Context,
	keyID string, at int64) (iam.KeyLifecycleSnapshot, bool, error) {
	if keyID == "" || at < 0 {
		return iam.KeyLifecycleSnapshot{}, false, iam.ErrInvalidInput
	}
	rows, err := adapter.LoadCanonicalStateHistory(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyLifecycle, keyID, 4096)
	if err != nil {
		return iam.KeyLifecycleSnapshot{}, false, err
	}
	for _, row := range rows {
		decoded, decodeErr := adapter.decodeIAMProjection(ctx, row)
		if decodeErr != nil {
			return iam.KeyLifecycleSnapshot{}, false, decodeErr
		}
		value, ok := decoded.KeyLifecycle()
		if !ok {
			return iam.KeyLifecycleSnapshot{}, false, iam.ErrCanonicalStateInvalid
		}
		if value.CreatedAtUnixNano <= at && value.NotBeforeUnixNano <= at && at < value.NotAfterUnixNano &&
			(!value.HasRevokedAt || at < value.RevokedAtUnixNano) {
			return value, true, nil
		}
	}
	return iam.KeyLifecycleSnapshot{}, false, nil
}

func (adapter *ProductionSemanticAdapter) SnapshotOwnershipTransferApprovalCollection(ctx context.Context,
	key [ccse.MessageIDSize]byte) (iam.OwnershipTransferApprovalCollectionSnapshot, bool, error) {
	if adapter == nil || adapter.CanonicalUOW == nil {
		return iam.OwnershipTransferApprovalCollectionSnapshot{}, false, iam.ErrCanonicalStateUnrehydratable
	}
	stored, found, err := adapter.LoadDurablePending(ctx, key)
	if err != nil || !found {
		return iam.OwnershipTransferApprovalCollectionSnapshot{}, found, err
	}
	if stored.Kind != DurablePendingOwnershipTransferCollection ||
		stored.Codec != DurablePendingIAMCodec || stored.CodecVersion != 1 ||
		stored.Status != DurablePendingOpen || stored.EnvelopeDigest == ([sha256.Size]byte{}) {
		return iam.OwnershipTransferApprovalCollectionSnapshot{}, false, iam.ErrViewInconsistent
	}
	decoded, decodeErr := iam.DecodeDurablePendingEnvelope(stored.CanonicalEnvelope)
	if decodeErr != nil || decoded.Kind() != iam.DurablePendingOwnershipTransferCollection ||
		decoded.Digest() != stored.EnvelopeDigest {
		return iam.OwnershipTransferApprovalCollectionSnapshot{}, false, iam.ErrViewInconsistent
	}
	value, ok := decoded.OwnershipTransferApprovalCollection()
	if !ok || value.Binding.Key != key || value.Version != stored.Revision {
		return iam.OwnershipTransferApprovalCollectionSnapshot{}, false, iam.ErrViewInconsistent
	}
	return value, true, nil
}

func (adapter *ProductionSemanticAdapter) LookupIAMPendingAdmissionEvidence(ctx context.Context,
	digest [sha256.Size]byte) (iam.IAMPersistenceEvidenceRecord, bool, error) {
	stored, found, err := adapter.LoadDurableEvidence(ctx, digest)
	if err != nil || !found {
		return iam.IAMPersistenceEvidenceRecord{}, found, err
	}
	return iam.IAMPersistenceEvidenceRecord{DigestSHA256: stored.Digest, Kind: uint8(stored.Kind),
		ContentType: stored.ContentType, CanonicalContent: bytes.Clone(stored.CanonicalContent),
		ExpectedAuditEventID: stored.ExpectedAuditEventID}, true, nil
}

func (adapter *ProductionSemanticAdapter) CanonicalIAMStateAssertion(ctx context.Context,
	precondition iam.SnapshotPrecondition, _ string) (iam.CanonicalStateRecord, bool, error) {
	kind, ok := entityCanonicalKind(precondition.Entity)
	if !ok {
		return iam.CanonicalStateRecord{}, false, iam.ErrInvalidInput
	}
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM, kind,
		precondition.Entity.ID)
	if err != nil || !found {
		return iam.CanonicalStateRecord{}, found, err
	}
	if semanticProjectionKind(kind) {
		if _, err := adapter.decodeIAMProjection(ctx, record); err != nil {
			return iam.CanonicalStateRecord{}, false, err
		}
	} else if _, err := iam.DecodeCanonicalIAMStateRecord(toIAMState(record)); err != nil {
		return iam.CanonicalStateRecord{}, false, err
	}
	return toIAMState(record), true, nil
}

func entityCanonicalKind(entity iam.EntityRef) (CanonicalStateKind, bool) {
	switch entity.Kind {
	case iam.EntityIdentity:
		return CanonicalStateIAMIdentity, true
	case iam.EntityKeyMaterial:
		return CanonicalStateIAMKeyMaterial, true
	case iam.EntityKeyLifecycle:
		return CanonicalStateIAMKeyLifecycle, true
	case iam.EntityOwnershipTransfer:
		return CanonicalStateIAMAcceptedOwnershipTransfer, true
	case iam.EntityOwnershipTransferProfileActivation:
		return CanonicalStateIAMTransferProfileActivation, true
	default:
		return "", false
	}
}

func semanticProjectionKind(kind CanonicalStateKind) bool {
	switch kind {
	case CanonicalStateIAMKeyMaterial, CanonicalStateIAMIdentity, CanonicalStateIAMKeyLifecycle,
		CanonicalStateIAMAcceptedOwnershipTransfer, CanonicalStateIAMSubjectKeySet,
		CanonicalStateIAMTransferProfileActivation:
		return true
	default:
		return false
	}
}

func (adapter *ProductionSemanticAdapter) CanonicalIAMStateTransition(ctx context.Context,
	request iam.CanonicalIAMStateTransition) (iam.CanonicalStateRecord, bool,
	iam.CanonicalStateRecord, error) {
	kind, ok := entityCanonicalKind(request.Entity)
	contentType, typeOK := iamContentType(kind)
	if !ok || !typeOK {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, iam.ErrInvalidInput
	}
	expected, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM, kind, request.Entity.ID)
	if err != nil {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, err
	}
	next, err := prepareCanonicalStateRecord(CanonicalStateRecord{Namespace: CanonicalStateIAM,
		Kind: kind, ObjectID: request.Entity.ID, Version: request.NextVersion,
		StateDigest: request.SemanticStateDigestSHA256, ContentType: contentType,
		CanonicalState: bytes.Clone(request.CanonicalSemanticState), Terminal: request.Terminal,
		AuditEventID: request.AuditEventID, HasValidityWindow: request.HasValidityWindow,
		ValidFromUnixNano: request.ValidFromUnixNano, ValidUntilUnixNano: request.ValidUntilUnixNano})
	if err != nil {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, err
	}
	return toIAMState(expected), found, toIAMState(next), nil
}

func (adapter *ProductionSemanticAdapter) CanonicalIAMSidecarState(ctx context.Context,
	request iam.CanonicalIAMSidecarRequest) (iam.CanonicalStateRecord, bool,
	iam.CanonicalStateRecord, bool, error) {
	kind, ok := iamKind(request.Kind)
	contentType, typeOK := iamContentType(kind)
	if !ok || !typeOK {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, false, iam.ErrInvalidInput
	}
	expected, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateIAM, kind, request.ObjectID)
	if err != nil {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, false, err
	}
	if found && kind == CanonicalStateIAMSubjectKeySet {
		decoded, decodeErr := adapter.decodeIAMProjection(ctx, expected)
		if decodeErr != nil {
			return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, false, decodeErr
		}
		storedKind, storedPrincipal, members, memberOK := decoded.SubjectKeySet()
		if !memberOK || storedKind != request.ExpectedSubjectKind ||
			storedPrincipal != request.ExpectedSubjectIdentity ||
			!equalIAMPreconditions(members, request.ExpectedSubjectKeyMembers) {
			return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, false,
				iam.ErrViewInconsistent
		}
	}
	if !request.NextPresent {
		return toIAMState(expected), found, iam.CanonicalStateRecord{}, false, nil
	}
	version := request.NextVersion
	if version == 0 {
		version = 1
		if found {
			version = expected.Version + 1
		}
	}
	next, err := prepareCanonicalStateRecord(CanonicalStateRecord{Namespace: CanonicalStateIAM,
		Kind: kind, ObjectID: request.ObjectID, Version: version,
		StateDigest: request.NextStateDigestSHA256, ContentType: contentType,
		CanonicalState: bytes.Clone(request.NextCanonicalState), Terminal: request.NextTerminal,
		AuditEventID: request.AuditEventID})
	if err != nil {
		return iam.CanonicalStateRecord{}, false, iam.CanonicalStateRecord{}, false, err
	}
	return toIAMState(expected), found, toIAMState(next), true, nil
}

func equalIAMPreconditions(left, right []iam.SnapshotPrecondition) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (adapter *ProductionSemanticAdapter) SnapshotIAMPendingPersistence(ctx context.Context,
	key [ccse.MessageIDSize]byte, revision uint64, requested [][sha256.Size]byte) (
	iam.IAMPendingStoredRevision, []iam.IAMPersistenceEvidenceRecord, bool, error) {
	stored, found, err := adapter.LoadDurablePending(ctx, key)
	if err != nil || !found {
		return iam.IAMPendingStoredRevision{}, nil, found, err
	}
	if stored.Revision != revision || stored.Kind < DurablePendingMutation || stored.Kind > 5 {
		return iam.IAMPendingStoredRevision{}, nil, false, iam.ErrViewInconsistent
	}
	digests := append([][sha256.Size]byte(nil), stored.EvidenceDigests...)
	digests = append(digests, requested...)
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i][:], digests[j][:]) < 0 })
	records := make([]iam.IAMPersistenceEvidenceRecord, 0, len(digests))
	for index, digest := range digests {
		if index > 0 && digest == digests[index-1] {
			continue
		}
		evidence, exists, loadErr := adapter.LoadDurableEvidence(ctx, digest)
		if loadErr != nil {
			return iam.IAMPendingStoredRevision{}, nil, false, loadErr
		}
		if !exists {
			return iam.IAMPendingStoredRevision{}, nil, false, iam.ErrViewInconsistent
		}
		records = append(records, iam.IAMPersistenceEvidenceRecord{DigestSHA256: evidence.Digest,
			Kind: uint8(evidence.Kind), ContentType: evidence.ContentType,
			CanonicalContent:     bytes.Clone(evidence.CanonicalContent),
			ExpectedAuditEventID: evidence.ExpectedAuditEventID})
	}
	result := iam.IAMPendingStoredRevision{PendingKey: stored.PendingKey,
		Kind: iam.DurablePendingKind(stored.Kind), Codec: stored.Codec,
		CodecVersion: stored.CodecVersion, Revision: stored.Revision,
		PreviousEnvelopeDigestSHA256: stored.PreviousEnvelopeDigest,
		EnvelopeDigestSHA256:         stored.EnvelopeDigest,
		CanonicalEnvelope:            bytes.Clone(stored.CanonicalEnvelope),
		EvidenceDigestsSHA256:        append([][sha256.Size]byte(nil), stored.EvidenceDigests...),
		Status:                       uint8(stored.Status), CommitNotBeforeUnixNano: stored.CommitNotBeforeUnixNano,
		CommitNotAfterUnixNano:      stored.CommitNotAfterUnixNano,
		TerminalOutcomeDigestSHA256: stored.TerminalOutcomeDigest,
		ExpectedAuditEventID:        stored.ExpectedAuditEventID}
	return result, records, true, nil
}

var (
	_ iam.View                            = (*ProductionSemanticAdapter)(nil)
	_ iam.Profile                         = (*ProductionSemanticAdapter)(nil)
	_ iam.CanonicalIAMStateView           = (*ProductionSemanticAdapter)(nil)
	_ iam.CanonicalIAMSidecarStateView    = (*ProductionSemanticAdapter)(nil)
	_ iam.IAMPendingPersistenceView       = (*ProductionSemanticAdapter)(nil)
	_ iam.IAMPendingAdmissionEvidenceView = (*ProductionSemanticAdapter)(nil)
)

func (adapter *ProductionSemanticAdapter) String() string {
	return fmt.Sprintf("postgres production semantic adapter(%p)", adapter.CanonicalUOW)
}
