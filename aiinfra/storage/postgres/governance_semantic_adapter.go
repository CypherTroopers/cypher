// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
)

// GovernanceAuthorizationAssignment is the immutable deployment-policy half
// of a Governance key. Roles and organization membership do not exist in IAM
// v1 and therefore must never be inferred from an identity name. The catalog
// commits its assignment to the complete row-backed Governance key snapshot.
type GovernanceAuthorizationAssignment struct {
	KeyID                                 string
	OrganizationIdentity                  string
	Roles                                 []string
	AuthorizationSnapshotDigestSHA256     [sha256.Size]byte
	GovernanceProfileDigestSHA256         [sha256.Size]byte
	ProfileActivationVersion              uint64
	ProfileActivationSnapshotDigestSHA256 [sha256.Size]byte
}

// GovernanceAuthorizationCatalog is an explicit trusted production policy
// source. Implementations must be immutable/versioned. PostgreSQL remains the
// authority for every IAM semantic field and for the referenced profile
// activation; the catalog supplies only facts absent from IAM v1.
type GovernanceAuthorizationCatalog interface {
	ResolveGovernanceAuthorization(context.Context, string) (GovernanceAuthorizationAssignment, bool, error)
	ResolveGovernanceAuthorizationAt(context.Context, string, int64) (GovernanceAuthorizationAssignment, bool, error)
}

// GovernanceDocumentMediaCatalog supplies the media type omitted by the
// content-addressed durable-evidence row. Document bytes and their SHA-256 are
// always loaded from PostgreSQL and byte-verified by the adapter.
type GovernanceDocumentMediaCatalog interface {
	ResolveGovernanceDocumentMediaType(context.Context, [sha256.Size]byte) (string, bool, error)
}

type governanceDocumentMediaCatalogAt interface {
	ResolveGovernanceDocumentMediaTypeAt(context.Context, [sha256.Size]byte, int64) (string, bool, error)
}

// ProductionGovernanceSemanticAdapter restores Governance's durable views
// from one SERIALIZABLE CanonicalUOW. Its two injected catalogs are narrow,
// explicit authorities only for facts the frozen v1 rows never retained.
type ProductionGovernanceSemanticAdapter struct {
	*CanonicalUOW
	iam           *ProductionSemanticAdapter
	authority     GovernanceAuthorizationCatalog
	documentMedia GovernanceDocumentMediaCatalog
}

func NewProductionGovernanceSemanticAdapter(uow *CanonicalUOW,
	iamAdapter *ProductionSemanticAdapter, authority GovernanceAuthorizationCatalog,
	documentMedia GovernanceDocumentMediaCatalog) (*ProductionGovernanceSemanticAdapter, error) {
	if uow == nil || iamAdapter == nil || iamAdapter.CanonicalUOW != uow ||
		authority == nil || documentMedia == nil {
		return nil, ErrCanonicalInvalid
	}
	return &ProductionGovernanceSemanticAdapter{CanonicalUOW: uow, iam: iamAdapter,
		authority: authority, documentMedia: documentMedia}, nil
}

// NewProductionGovernanceSemanticAdapterFromSignedCatalog is the closed
// production composition for facts absent from v1 PostgreSQL rows. Both
// authorization and document metadata come from one verified immutable
// artifact rather than unrelated callbacks.
func NewProductionGovernanceSemanticAdapterFromSignedCatalog(uow *CanonicalUOW,
	iamAdapter *ProductionSemanticAdapter, catalog *SignedGovernanceSemanticCatalog) (
	*ProductionGovernanceSemanticAdapter, error) {
	if catalog == nil || catalog.ArtifactDigestSHA256() == ([sha256.Size]byte{}) {
		return nil, ErrCanonicalInvalid
	}
	return NewProductionGovernanceSemanticAdapter(uow, iamAdapter, catalog, catalog)
}

func toGovernanceState(value CanonicalStateRecord) governance.CanonicalStateRecord {
	return governance.CanonicalStateRecord{Namespace: uint8(value.Namespace), Kind: string(value.Kind),
		ObjectID: value.ObjectID, Version: value.Version, StateDigestSHA256: value.StateDigest,
		ContentType: value.ContentType, CanonicalState: bytes.Clone(value.CanonicalState),
		Terminal: value.Terminal, AuditEventID: value.AuditEventID,
		HasValidityWindow: value.HasValidityWindow, ValidFromUnixNano: value.ValidFromUnixNano,
		ValidUntilUnixNano: value.ValidUntilUnixNano}
}

func (adapter *ProductionGovernanceSemanticAdapter) decodeGovernanceProjection(ctx context.Context,
	record CanonicalStateRecord) (governance.DecodedSemanticProjectionV2, error) {
	projection, found, err := adapter.LoadSemanticProjection(ctx, record)
	if err != nil {
		return governance.DecodedSemanticProjectionV2{}, err
	}
	if !found {
		return governance.DecodedSemanticProjectionV2{}, governance.ErrSemanticUnrehydratable
	}
	var decoded governance.DecodedSemanticProjectionV2
	switch record.Kind {
	case CanonicalStateGovernancePolicyRegistry:
		if projection.Codec != SemanticProjectionCodecGovernancePolicyV2 {
			return decoded, governance.ErrSemanticUnrehydratable
		}
		decoded, err = governance.DecodePolicyRegistrySemanticProjectionV2(toGovernanceState(record),
			projection.CanonicalProjection)
	case CanonicalStateGovernanceProfileActivation:
		if projection.Codec != SemanticProjectionCodecGovernanceProfileV2 {
			return decoded, governance.ErrSemanticUnrehydratable
		}
		decoded, err = governance.DecodeGovernanceProfileSemanticProjectionV2(toGovernanceState(record),
			projection.CanonicalProjection)
	default:
		return decoded, governance.ErrSemanticUnrehydratable
	}
	if err != nil || decoded.Projection().Digest() != projection.ProjectionDigest {
		return governance.DecodedSemanticProjectionV2{}, governance.ErrSnapshotInconsistent
	}
	if record.Kind == CanonicalStateGovernancePolicyRegistry {
		if _, contextErr := adapter.validateGovernancePolicyProjectionContext(ctx, projection); contextErr != nil {
			return governance.DecodedSemanticProjectionV2{}, governance.ErrSnapshotInconsistent
		}
	}
	return decoded, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) ResolveGovernanceProfile(ctx context.Context,
	digest [ccse.DigestSize]byte) (governance.Profile, bool, error) {
	if digest == ([sha256.Size]byte{}) {
		return governance.Profile{}, false, governance.ErrSnapshotInconsistent
	}
	objectID := "governance-profile:" + hex.EncodeToString(digest[:])
	record, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateGovernance,
		CanonicalStateGovernanceProfileActivation, objectID)
	if err != nil || !found {
		return governance.Profile{}, found, err
	}
	decoded, err := adapter.decodeGovernanceProjection(ctx, record)
	if err != nil {
		return governance.Profile{}, false, err
	}
	profile, activation, ok := decoded.GovernanceProfile()
	if !ok || activation.GovernanceProfileDigestSHA256 != digest {
		return governance.Profile{}, false, governance.ErrSnapshotInconsistent
	}
	return profile, true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) ActiveGovernanceProfile(ctx context.Context,
	at int64) (governance.GovernanceProfileActivationSnapshot, bool, error) {
	record, found, err := adapter.LoadActiveGovernanceProfileState(ctx, at)
	if err != nil || !found {
		return governance.GovernanceProfileActivationSnapshot{}, found, err
	}
	decoded, err := adapter.decodeGovernanceProjection(ctx, record)
	if err != nil {
		return governance.GovernanceProfileActivationSnapshot{}, false, err
	}
	_, activation, ok := decoded.GovernanceProfile()
	if !ok || at < activation.ValidFromUnixNano || at >= activation.ValidUntilUnixNano {
		return governance.GovernanceProfileActivationSnapshot{}, false, governance.ErrSnapshotInconsistent
	}
	return activation, true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) CanonicalGovernanceProfileActivation(ctx context.Context,
	activation governance.GovernanceProfileActivationSnapshot) (governance.CanonicalStateRecord, bool, error) {
	objectID := "governance-profile:" + hex.EncodeToString(activation.GovernanceProfileDigestSHA256[:])
	record, found, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateGovernance,
		CanonicalStateGovernanceProfileActivation, objectID, activation.Version)
	if err != nil || !found {
		return governance.CanonicalStateRecord{}, found, err
	}
	decoded, err := adapter.decodeGovernanceProjection(ctx, record)
	if err != nil {
		return governance.CanonicalStateRecord{}, false, err
	}
	_, stored, ok := decoded.GovernanceProfile()
	if !ok || stored != activation {
		return governance.CanonicalStateRecord{}, false, governance.ErrSnapshotInconsistent
	}
	return toGovernanceState(record), true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) SnapshotPolicy(ctx context.Context,
	policyKind string) (governance.PolicyRegistrySnapshot, error) {
	rows, err := adapter.LoadCanonicalStateHistory(ctx, CanonicalStateGovernance,
		CanonicalStateGovernancePolicyRegistry, policyKind, 4096)
	if err != nil {
		return governance.PolicyRegistrySnapshot{}, err
	}
	if len(rows) == 0 {
		return governance.PolicyRegistrySnapshot{}, nil
	}
	records := make([]governance.PolicyRecordSnapshot, 0, len(rows))
	var headMetadata governance.PolicyRegistrySnapshot
	for index, row := range rows {
		decoded, decodeErr := adapter.decodeGovernanceProjection(ctx, row)
		if decodeErr != nil {
			return governance.PolicyRegistrySnapshot{}, decodeErr
		}
		record, metadata, ok := decoded.PolicyRegistryRecord()
		if !ok || record.PolicyKind != policyKind || record.Sequence != row.Version {
			return governance.PolicyRegistrySnapshot{}, governance.ErrSnapshotInconsistent
		}
		if index == 0 {
			headMetadata = metadata
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
	for index := range records {
		if records[index].Sequence != uint64(index+1) {
			return governance.PolicyRegistrySnapshot{}, governance.ErrSnapshotInconsistent
		}
	}
	headMetadata.HeadPresent = true
	headMetadata.Head = records[len(records)-1]
	headMetadata.Records = records
	return headMetadata, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) CanonicalGovernancePolicyRegistryTransition(ctx context.Context,
	request governance.CanonicalPolicyRegistryTransition) (governance.CanonicalStateRecord, bool,
	governance.CanonicalStateRecord, error) {
	expected, found, err := adapter.LoadCanonicalState(ctx, CanonicalStateGovernance,
		CanonicalStateGovernancePolicyRegistry, request.PolicyKind)
	if err != nil {
		return governance.CanonicalStateRecord{}, false, governance.CanonicalStateRecord{}, err
	}
	if found {
		if _, err := adapter.decodeGovernanceProjection(ctx, expected); err != nil {
			return governance.CanonicalStateRecord{}, false, governance.CanonicalStateRecord{}, err
		}
	}
	next := CanonicalStateRecord{Namespace: CanonicalStateGovernance,
		Kind: CanonicalStateGovernancePolicyRegistry, ObjectID: request.PolicyKind,
		Version: request.PolicySequence, StateDigest: request.PolicyBundleDigestSHA256,
		ContentType:    CanonicalStateGovernancePolicyRegistryContentType,
		CanonicalState: bytes.Clone(request.CanonicalPolicyBundle), AuditEventID: request.AuditEventID}
	prepared, err := prepareCanonicalStateRecord(next)
	if err != nil || sha256.Sum256(request.CanonicalPolicyBundle) != request.PolicyBundleDigestSHA256 {
		return governance.CanonicalStateRecord{}, false, governance.CanonicalStateRecord{},
			governance.ErrSnapshotInconsistent
	}
	return toGovernanceState(expected), found, toGovernanceState(prepared), nil
}

func (adapter *ProductionGovernanceSemanticAdapter) SnapshotPolicyApprovalCollection(ctx context.Context,
	key [ccse.MessageIDSize]byte) ([]governance.PolicyApprovalCollectionEntry, error) {
	stored, found, err := adapter.LoadDurablePending(ctx, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return []governance.PolicyApprovalCollectionEntry{}, nil
	}
	if stored.Kind != DurablePendingGovernancePolicyApprovalCollection ||
		stored.Codec != DurablePendingGovernanceCodec || stored.CodecVersion != 1 ||
		stored.Status != DurablePendingOpen {
		return nil, governance.ErrApprovalCollection
	}
	decoded, err := governance.DecodePolicyApprovalCollection(stored.CanonicalEnvelope)
	if err != nil || decoded.Digest() != stored.EnvelopeDigest || decoded.Binding().Key != key ||
		decoded.Revision() != stored.Revision || !equalDigestSlices(decoded.EvidenceDigests(), stored.EvidenceDigests) {
		return nil, governance.ErrApprovalCollection
	}
	return decoded.Entries(), nil
}

func equalDigestSlices(left, right [][sha256.Size]byte) bool {
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

func (adapter *ProductionGovernanceSemanticAdapter) SnapshotPolicyApprovalCollectionPersistence(ctx context.Context,
	key [ccse.MessageIDSize]byte) (governance.PolicyApprovalCollectionPersistenceSnapshot, bool, error) {
	stored, found, err := adapter.LoadDurablePending(ctx, key)
	if err != nil || !found {
		return governance.PolicyApprovalCollectionPersistenceSnapshot{}, found, err
	}
	if stored.Kind != DurablePendingGovernancePolicyApprovalCollection || stored.Codec != DurablePendingGovernanceCodec {
		return governance.PolicyApprovalCollectionPersistenceSnapshot{}, false, governance.ErrApprovalCollection
	}
	return governance.PolicyApprovalCollectionPersistenceSnapshot{PendingKey: stored.PendingKey,
		Kind: governance.DurablePendingKind(stored.Kind), Codec: stored.Codec,
		CodecVersion: stored.CodecVersion, Revision: stored.Revision,
		PreviousEnvelopeDigestSHA256: stored.PreviousEnvelopeDigest,
		EnvelopeDigestSHA256:         stored.EnvelopeDigest, CanonicalEnvelope: bytes.Clone(stored.CanonicalEnvelope),
		EvidenceDigestsSHA256:       append([][sha256.Size]byte(nil), stored.EvidenceDigests...),
		Status:                      governance.DurablePendingStatus(stored.Status),
		CommitNotBeforeUnixNano:     stored.CommitNotBeforeUnixNano,
		CommitNotAfterUnixNano:      stored.CommitNotAfterUnixNano,
		TerminalOutcomeDigestSHA256: stored.TerminalOutcomeDigest,
		ExpectedAuditEventID:        stored.ExpectedAuditEventID}, true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) ResolvePolicyDocument(ctx context.Context,
	digest [ccse.DigestSize]byte) (governance.PolicyDocumentSnapshot, error) {
	record, found, err := adapter.LoadDurableEvidence(ctx, digest)
	if err != nil {
		return governance.PolicyDocumentSnapshot{}, err
	}
	mediaType, mediaFound, mediaErr := "", false, error(nil)
	if contextual, ok := adapter.documentMedia.(governanceDocumentMediaCatalogAt); ok {
		clock, clockErr := adapter.SnapshotTransactionClock(ctx)
		if clockErr != nil {
			return governance.PolicyDocumentSnapshot{}, clockErr
		}
		mediaType, mediaFound, mediaErr = contextual.ResolveGovernanceDocumentMediaTypeAt(ctx,
			digest, clock.ObservedAtUnixNano())
	} else {
		mediaType, mediaFound, mediaErr = adapter.documentMedia.ResolveGovernanceDocumentMediaType(ctx, digest)
	}
	if !found || mediaErr != nil || !mediaFound || mediaType == "" ||
		record.Kind != DurableEvidenceContentSHA256 || sha256.Sum256(record.CanonicalContent) != digest {
		return governance.PolicyDocumentSnapshot{}, governance.ErrAuditEvidence
	}
	return governance.PolicyDocumentSnapshot{DigestSHA256: digest, MediaType: mediaType,
		CanonicalDocument: bytes.Clone(record.CanonicalContent)}, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) SnapshotAuditHead(ctx context.Context,
	streamID string) (governance.AuditHeadSnapshot, error) {
	record, found, err := adapter.LoadAuditHead(ctx, streamID)
	if err != nil {
		return governance.AuditHeadSnapshot{}, err
	}
	if !found {
		return governance.AuditHeadSnapshot{}, governance.ErrSemanticUnrehydratable
	}
	return governance.AuditHeadSnapshot{StreamID: record.StreamID,
		DeploymentAnchorSHA256: record.DeploymentAnchorDigest, Sequence: record.Sequence,
		LastRecordDigestSHA256:   record.LastRecordDigest,
		HeadWriterIdentity:       record.HeadWriterIdentity,
		AuthorizedWriterIdentity: record.AuthorizedWriterIdentity,
		HomeRegion:               record.HomeRegion, AuthorizedHomeRegion: record.AuthorizedHomeRegion,
		WriterEpoch: record.WriterEpoch, AuthorizedWriterEpoch: record.AuthorizedWriterEpoch,
		HeadGovernanceProfileDigestSHA256:       record.HeadGovernanceProfileDigest,
		AuthorizedGovernanceProfileDigestSHA256: record.AuthorizedGovernanceProfileDigest,
		WriterLeaseEvidenceDigestSHA256:         record.WriterLeaseEvidenceDigest,
		WriterLeaseNotBeforeUnixNano:            record.WriterLeaseNotBeforeUnixNano,
		WriterLeaseNotAfterUnixNano:             record.WriterLeaseNotAfterUnixNano}, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) LookupAuditEvent(ctx context.Context,
	eventID string) (governance.AuditEventSnapshot, bool, error) {
	record, found, err := adapter.LoadAuditEvent(ctx, eventID)
	if err != nil || !found {
		return governance.AuditEventSnapshot{}, found, err
	}
	return governance.AuditEventSnapshot{Sequence: record.Sequence,
		RecordDigestSHA256: record.RecordDigest}, true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) ResolveGovernanceKey(ctx context.Context,
	keyID string) (governance.GovernanceKeySnapshot, error) {
	clock, err := adapter.SnapshotTransactionClock(ctx)
	if err != nil {
		return governance.GovernanceKeySnapshot{}, err
	}
	at := clock.ObservedAtUnixNano()
	assignment, found, err := adapter.authority.ResolveGovernanceAuthorizationAt(ctx, keyID, at)
	if err != nil || !found {
		if err != nil {
			return governance.GovernanceKeySnapshot{}, err
		}
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	return adapter.composeGovernanceKey(ctx, keyID, &at, assignment)
}

func (adapter *ProductionGovernanceSemanticAdapter) ResolveGovernanceKeyAt(ctx context.Context,
	keyID string, at int64) (governance.GovernanceKeySnapshot, bool, error) {
	assignment, found, err := adapter.authority.ResolveGovernanceAuthorizationAt(ctx, keyID, at)
	if err != nil || !found {
		return governance.GovernanceKeySnapshot{}, found, err
	}
	result, err := adapter.composeGovernanceKey(ctx, keyID, &at, assignment)
	if err != nil {
		return governance.GovernanceKeySnapshot{}, false, err
	}
	return result, true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) composeGovernanceKey(ctx context.Context,
	keyID string, at *int64, assignment GovernanceAuthorizationAssignment) (governance.GovernanceKeySnapshot, error) {
	if assignment.KeyID != keyID || assignment.OrganizationIdentity == "" || len(assignment.Roles) == 0 ||
		assignment.AuthorizationSnapshotDigestSHA256 == ([sha256.Size]byte{}) ||
		assignment.GovernanceProfileDigestSHA256 == ([sha256.Size]byte{}) ||
		assignment.ProfileActivationVersion == 0 ||
		assignment.ProfileActivationSnapshotDigestSHA256 == ([sha256.Size]byte{}) {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	effectiveAt := int64(0)
	if at != nil {
		effectiveAt = *at
	} else {
		clock, clockErr := adapter.SnapshotTransactionClock(ctx)
		if clockErr != nil {
			return governance.GovernanceKeySnapshot{}, clockErr
		}
		effectiveAt = clock.ObservedAtUnixNano()
	}
	// Rebind the policy catalog to an immutable, row-backed v2 profile
	// activation in this same UoW. A catalog-only role substitution therefore
	// cannot silently select a nonexistent policy epoch.
	profileObjectID := "governance-profile:" + hex.EncodeToString(assignment.GovernanceProfileDigestSHA256[:])
	profileRow, profileFound, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateGovernance,
		CanonicalStateGovernanceProfileActivation, profileObjectID, assignment.ProfileActivationVersion)
	if err != nil || !profileFound {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	profileDecoded, err := adapter.decodeGovernanceProjection(ctx, profileRow)
	if err != nil {
		return governance.GovernanceKeySnapshot{}, err
	}
	_, activation, ok := profileDecoded.GovernanceProfile()
	if !ok || activation.GovernanceProfileDigestSHA256 != assignment.GovernanceProfileDigestSHA256 ||
		activation.EvidenceDigestSHA256 != assignment.ProfileActivationSnapshotDigestSHA256 ||
		activation.Version != assignment.ProfileActivationVersion ||
		effectiveAt < activation.ValidFromUnixNano || effectiveAt >= activation.ValidUntilUnixNano {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	material, materialFound, err := adapter.iam.LookupKeyMaterial(ctx, keyID)
	if err != nil || !materialFound {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	var lifecycle iam.KeyLifecycleSnapshot
	var identity iam.IdentitySnapshot
	if at == nil {
		lifecycle, materialFound, err = adapter.iam.LookupKeyLifecycle(ctx, keyID)
		if err == nil && materialFound {
			identity, materialFound, err = adapter.iam.LookupIdentity(ctx, material.TargetIdentity)
		}
	} else {
		lifecycle, materialFound, err = adapter.iam.LookupKeyLifecycleAt(ctx, keyID, *at)
		if err == nil && materialFound {
			identity, materialFound, err = adapter.iam.LookupIdentityAt(ctx, material.TargetIdentity, *at)
		}
	}
	if err != nil || !materialFound || material.KeyID != lifecycle.KeyID ||
		material.SubjectIdentity != lifecycle.SubjectIdentity || material.SubjectKind != lifecycle.SubjectKind ||
		material.Algorithm != lifecycle.Algorithm || identity.Ref != material.TargetIdentity ||
		identity.PrincipalIdentity != material.SubjectIdentity {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	materialRow, mf, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyMaterial, keyID, material.StateVersion)
	if err != nil || !mf {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	lifecycleRow, lf, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyLifecycle, keyID, lifecycle.StateVersion)
	if err != nil || !lf {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	identityRow, inf, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMIdentity, identity.Ref.ID, identity.StateVersion)
	if err != nil || !inf {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	for _, row := range []CanonicalStateRecord{materialRow, lifecycleRow, identityRow} {
		if _, err := adapter.iam.decodeIAMProjection(ctx, row); err != nil {
			return governance.GovernanceKeySnapshot{}, err
		}
	}
	roles := append([]string(nil), assignment.Roles...)
	sort.Strings(roles)
	for index := range roles {
		if roles[index] == "" || (index > 0 && roles[index] == roles[index-1]) {
			return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
		}
	}
	result := governance.GovernanceKeySnapshot{KeyID: keyID,
		SubjectIdentity: material.SubjectIdentity, TargetIdentityKind: uint32(material.TargetIdentity.Kind),
		TargetPrincipalKind: material.TargetIdentity.PrincipalKind, TargetIdentityID: material.TargetIdentity.ID,
		OrganizationIdentity: assignment.OrganizationIdentity, Algorithm: material.Algorithm,
		PublicKey: bytes.Clone(material.CanonicalPublicKey), LifecycleState: lifecycle.State,
		NotBeforeUnixNano: lifecycle.NotBeforeUnixNano, NotAfterUnixNano: lifecycle.NotAfterUnixNano,
		RevokedAtUnixNano:     lifecycle.RevokedAtUnixNano,
		AllowedMessageTypeIDs: append([]uint32(nil), lifecycle.AllowedMessageTypeIDs...), Roles: roles,
		AuthorizationPolicyDigestSHA256: lifecycle.AuthorizationPolicyDigestSHA256,
		KeyMaterialStateVersion:         material.StateVersion, KeyMaterialStateDigestSHA256: materialRow.StateDigest,
		StateVersion: lifecycle.StateVersion, WriterEpoch: lifecycle.WriterEpoch,
		SnapshotDigestSHA256: lifecycleRow.StateDigest,
		IdentityStateVersion: identity.StateVersion, IdentityWriterEpoch: identity.WriterEpoch,
		IdentitySnapshotDigestSHA256: identityRow.StateDigest,
		EnrollmentDomainID:           material.EnrollmentDomain.EnrollmentDomainID,
		EnrollmentEnvironment:        material.EnrollmentDomain.Environment,
		EnrollmentGenesisHash:        material.EnrollmentDomain.GenesisHash}
	if governance.GovernanceAuthorizationSnapshotDigest(result) != assignment.AuthorizationSnapshotDigestSHA256 {
		return governance.GovernanceKeySnapshot{}, governance.ErrSnapshotInconsistent
	}
	return result, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) CanonicalGovernanceKeyState(ctx context.Context,
	precondition governance.KeyStatePrecondition) (governance.CanonicalGovernanceKeyStateProjection, bool, error) {
	key, err := adapter.ResolveGovernanceKey(ctx, precondition.KeyID)
	if err != nil {
		return governance.CanonicalGovernanceKeyStateProjection{}, false, err
	}
	if key.StateVersion != precondition.StateVersion || key.WriterEpoch != precondition.WriterEpoch ||
		key.SnapshotDigestSHA256 != precondition.SnapshotDigestSHA256 ||
		key.IdentityStateVersion != precondition.IdentityStateVersion ||
		key.IdentityWriterEpoch != precondition.IdentityWriterEpoch ||
		key.IdentitySnapshotDigestSHA256 != precondition.IdentitySnapshotDigestSHA256 ||
		key.KeyMaterialStateVersion != precondition.KeyMaterialStateVersion ||
		key.KeyMaterialStateDigestSHA256 != precondition.KeyMaterialStateDigestSHA256 ||
		governance.GovernanceAuthorizationSnapshotDigest(key) != precondition.AuthorizationSnapshotDigestSHA256 ||
		key.TargetIdentityKind != precondition.IdentityKind ||
		key.TargetPrincipalKind != precondition.IdentityPrincipalKind || key.TargetIdentityID != precondition.IdentityObjectID {
		return governance.CanonicalGovernanceKeyStateProjection{}, false, governance.ErrSnapshotInconsistent
	}
	material, mf, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyMaterial, key.KeyID, key.KeyMaterialStateVersion)
	if err != nil || !mf {
		return governance.CanonicalGovernanceKeyStateProjection{}, false, err
	}
	lifecycle, lf, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMKeyLifecycle, key.KeyID, key.StateVersion)
	if err != nil || !lf {
		return governance.CanonicalGovernanceKeyStateProjection{}, false, err
	}
	identity, inf, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMIdentity, key.TargetIdentityID, key.IdentityStateVersion)
	if err != nil || !inf {
		return governance.CanonicalGovernanceKeyStateProjection{}, false, err
	}
	return governance.CanonicalGovernanceKeyStateProjection{KeyMaterial: toGovernanceState(material),
		Lifecycle: toGovernanceState(lifecycle), Identity: toGovernanceState(identity)}, true, nil
}

func (adapter *ProductionGovernanceSemanticAdapter) CanonicalAuditWriterLease(ctx context.Context,
	requirement governance.CanonicalAuditWriterLeaseRequirement) (governance.CanonicalStateRecord, bool, error) {
	entity := iam.EntityRef{Kind: iam.EntityKind(requirement.WriterLeaseEntityKind),
		PrincipalKind: requirement.WriterLeaseEntityPrincipalKind, ID: requirement.WriterLeaseEntityID}
	lease, found, err := adapter.iam.LookupWriterLease(ctx, entity)
	if err != nil || !found {
		return governance.CanonicalStateRecord{}, found, err
	}
	if lease.WriterIdentity != requirement.AuthorizedWriterIdentity || lease.HomeRegion != requirement.AuthorizedHomeRegion ||
		lease.WriterEpoch != requirement.AuthorizedWriterEpoch || lease.EvidenceDigest != requirement.WriterLeaseEvidenceDigestSHA256 ||
		lease.ValidFromUnixNano != requirement.WriterLeaseNotBeforeUnixNano ||
		lease.ValidUntilUnixNano != requirement.WriterLeaseNotAfterUnixNano {
		return governance.CanonicalStateRecord{}, false, governance.ErrSnapshotInconsistent
	}
	objectID, err := iam.CanonicalEntityObjectID(entity)
	if err != nil {
		return governance.CanonicalStateRecord{}, false, err
	}
	record, rowFound, err := adapter.LoadCanonicalStateVersion(ctx, CanonicalStateIAM,
		CanonicalStateIAMWriterLease, objectID, lease.WriterEpoch)
	if err != nil || !rowFound {
		return governance.CanonicalStateRecord{}, rowFound, err
	}
	return toGovernanceState(record), true, nil
}

// ResolveEvidence supports plain content immediately. Signed and semantic
// evidence are decoded by governance's strict storage codec; unsupported or
// malformed legacy content fails closed rather than being reclassified.
func (adapter *ProductionGovernanceSemanticAdapter) ResolveEvidence(ctx context.Context,
	digest [ccse.DigestSize]byte) (governance.EvidenceSnapshot, bool, error) {
	record, found, err := adapter.LoadDurableEvidence(ctx, digest)
	if err != nil || !found {
		return governance.EvidenceSnapshot{}, found, err
	}
	result, decodeErr := governance.DecodeDurableEvidenceSnapshot(uint8(record.Kind), record.ContentType,
		digest, record.CanonicalContent)
	if decodeErr != nil {
		return governance.EvidenceSnapshot{}, false, decodeErr
	}
	return result, true, nil
}

var (
	_ governance.IAMView                                  = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.CanonicalGovernanceKeyStateView          = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.PolicyView                               = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.GovernanceProfileCatalog                 = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.CanonicalGovernanceProfileActivationView = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.CanonicalGovernancePolicyRegistryView    = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.ApprovalCollectionView                   = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.PolicyApprovalCollectionPersistenceView  = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.PolicyDocumentView                       = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.EvidenceView                             = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.AuditView                                = (*ProductionGovernanceSemanticAdapter)(nil)
	_ governance.CanonicalAuditWriterLeaseView            = (*ProductionGovernanceSemanticAdapter)(nil)
)
