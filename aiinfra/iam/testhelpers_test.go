// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	testNow       = int64(1_800_000_000_000_000_000)
	testNotBefore = int64(1_799_999_000_000_000_000)
	testNotAfter  = int64(1_800_010_000_000_000_000)
)

type memoryView struct {
	mu                  sync.RWMutex
	identities          map[EntityRef]IdentitySnapshot
	materials           map[string]KeyMaterialSnapshot
	lifecycles          map[string]KeyLifecycleSnapshot
	challenges          map[[32]byte]ProofChallengeSnapshot
	leases              map[EntityRef]WriterLeaseSnapshot
	transfers           map[[32]byte]OwnershipTransferSnapshot
	globalIDs           map[string]globalid.Snapshot
	idempotency         map[[16]byte]idempotency.Snapshot
	transferCollections map[[16]byte]OwnershipTransferApprovalCollectionSnapshot
	acceptedTransfers   map[[32]byte]AcceptedOwnershipTransferSnapshot
	compoundMembers     map[[16]byte]idempotency.CompoundMemberSnapshot
}

func newMemoryView() *memoryView {
	return &memoryView{
		identities: make(map[EntityRef]IdentitySnapshot), materials: make(map[string]KeyMaterialSnapshot),
		lifecycles: make(map[string]KeyLifecycleSnapshot), challenges: make(map[[32]byte]ProofChallengeSnapshot),
		leases: make(map[EntityRef]WriterLeaseSnapshot), transfers: make(map[[32]byte]OwnershipTransferSnapshot),
		globalIDs: make(map[string]globalid.Snapshot), idempotency: make(map[[16]byte]idempotency.Snapshot),
		transferCollections: make(map[[16]byte]OwnershipTransferApprovalCollectionSnapshot),
		acceptedTransfers:   make(map[[32]byte]AcceptedOwnershipTransferSnapshot),
		compoundMembers:     make(map[[16]byte]idempotency.CompoundMemberSnapshot),
	}
}

func (view *memoryView) SnapshotCompoundMemberState(_ context.Context, key [16]byte) (
	idempotency.CompoundMemberSnapshot, bool, idempotency.Snapshot, bool,
	idempotency.Snapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	member, found := view.compoundMembers[key]
	if !found {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, nil
	}
	parent, parentFound := view.idempotency[member.ParentBinding.Key]
	joined, err := idempotency.JoinedAuditBinding(member.ParentBinding)
	if err != nil {
		return idempotency.CompoundMemberSnapshot{}, false, idempotency.Snapshot{}, false,
			idempotency.Snapshot{}, false, err
	}
	audit, auditFound := view.idempotency[joined.Key]
	return member, true, parent, parentFound, audit, auditFound, nil
}

func (view *memoryView) LookupBusinessIdempotency(_ context.Context, key [16]byte) (idempotency.Snapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.idempotency[key]
	return item, ok, nil
}
func (view *memoryView) SnapshotBusinessIdempotencyPair(_ context.Context,
	parentKey, auditKey [16]byte) (idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	parent, parentFound := view.idempotency[parentKey]
	audit, auditFound := view.idempotency[auditKey]
	return parent, parentFound, audit, auditFound, nil
}
func (view *memoryView) LookupGlobalID(_ context.Context, identifier string) (globalid.Snapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.globalIDs[identifier]
	return item, ok, nil
}
func (view *memoryView) LookupIdentityByPrincipal(_ context.Context, kind uint32, principal string) (IdentitySnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	var result IdentitySnapshot
	found := false
	for _, item := range view.identities {
		if item.Ref.PrincipalKind == kind && item.PrincipalIdentity == principal {
			if found {
				return IdentitySnapshot{}, false, ErrViewInconsistent
			}
			result, found = cloneIdentity(item), true
		}
	}
	return result, found, nil
}

func (view *memoryView) LookupIdentity(_ context.Context, ref EntityRef) (IdentitySnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.identities[ref]
	return cloneIdentity(item), ok, nil
}
func (view *memoryView) LookupKeyMaterial(_ context.Context, keyID string) (KeyMaterialSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.materials[keyID]
	return cloneKeyMaterial(item), ok, nil
}
func (view *memoryView) LookupKeyLifecycle(_ context.Context, keyID string) (KeyLifecycleSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.lifecycles[keyID]
	return cloneLifecycle(item), ok, nil
}
func (view *memoryView) LookupSubjectKeyLifecycles(_ context.Context, kind uint32, principal string) ([]KeyLifecycleSnapshot, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	result := make([]KeyLifecycleSnapshot, 0)
	for _, item := range view.lifecycles {
		if item.SubjectKind == kind && item.SubjectIdentity == principal {
			result = append(result, cloneLifecycle(item))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].KeyID < result[j].KeyID })
	return result, nil
}
func (view *memoryView) LookupRotationSuccessor(_ context.Context, predecessor string) (KeyLifecycleSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	var result KeyLifecycleSnapshot
	found := false
	for _, item := range view.lifecycles {
		if item.HasRotationPredecessor && item.RotationPredecessorKeyID == predecessor {
			if found {
				return KeyLifecycleSnapshot{}, false, ErrViewInconsistent
			}
			result, found = cloneLifecycle(item), true
		}
	}
	return result, found, nil
}
func (view *memoryView) LookupOwnershipTransfer(_ context.Context, evidence [32]byte) (OwnershipTransferSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.transfers[evidence]
	return item, ok, nil
}
func (view *memoryView) LookupIdentityAt(_ context.Context, ref EntityRef, at int64) (IdentitySnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.identities[ref]
	if !ok || item.CreatedAtUnixNano > at {
		return IdentitySnapshot{}, false, nil
	}
	return cloneIdentity(item), true, nil
}
func (view *memoryView) LookupKeyLifecycleAt(_ context.Context, keyID string, at int64) (KeyLifecycleSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.lifecycles[keyID]
	if !ok || item.CreatedAtUnixNano > at {
		return KeyLifecycleSnapshot{}, false, nil
	}
	return cloneLifecycle(item), true, nil
}
func (view *memoryView) SnapshotOwnershipTransferApprovalCollection(_ context.Context, key [16]byte) (OwnershipTransferApprovalCollectionSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.transferCollections[key]
	return cloneTransferCollection(item), ok, nil
}
func (view *memoryView) LookupAcceptedOwnershipTransfer(_ context.Context, evidence [32]byte) (AcceptedOwnershipTransferSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.acceptedTransfers[evidence]
	return cloneAcceptedTransfer(item), ok, nil
}
func (view *memoryView) LookupProofChallenge(_ context.Context, challenge [32]byte) (ProofChallengeSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.challenges[challenge]
	return item, ok, nil
}
func (view *memoryView) LookupWriterLease(_ context.Context, ref EntityRef) (WriterLeaseSnapshot, bool, error) {
	view.mu.RLock()
	defer view.mu.RUnlock()
	item, ok := view.leases[ref]
	return item, ok, nil
}

type allowProfile struct {
	authorityErr          error
	identityErr           error
	messageErr            error
	transferProfile       *OwnershipTransferProfile
	transferErr           error
	transferCurrentErr    error
	transferHistoricalErr error
}

func (profile *allowProfile) ValidateAuthority(context.Context, AuthorityRequest) error {
	return profile.authorityErr
}
func (profile *allowProfile) ValidateEnrollmentAuthority(context.Context, EnrollmentAuthorityRequest) error {
	return profile.authorityErr
}
func (profile *allowProfile) ValidateIdentityTransition(context.Context, IdentityTransitionRequest) error {
	return profile.identityErr
}
func (profile *allowProfile) ValidateAllowedMessageTypes(context.Context, AllowedMessageTypesRequest) error {
	return profile.messageErr
}
func (profile *allowProfile) OwnershipTransferProfile(_ context.Context, _ OwnershipTransferProfileRequest) (OwnershipTransferProfile, error) {
	if profile.transferErr != nil || profile.transferProfile == nil {
		return OwnershipTransferProfile{}, profile.transferErr
	}
	return activatedTestTransferProfile(cloneTransferProfile(*profile.transferProfile)), nil
}
func (profile *allowProfile) OwnershipTransferProfileAt(_ context.Context,
	request OwnershipTransferProfileHistoryRequest) (OwnershipTransferProfile, error) {
	if profile.transferErr != nil || profile.transferProfile == nil {
		return OwnershipTransferProfile{}, profile.transferErr
	}
	value := activatedTestTransferProfile(cloneTransferProfile(*profile.transferProfile))
	if value.ProfileID != request.ProfileID || value.ProfileVersion != request.ProfileVersion ||
		value.Activation.ActivationVersion != request.ActivationVersion ||
		value.Activation.SnapshotDigest != request.ActivationSnapshotDigest ||
		value.Activation.ProfileDigest != request.ProfileDigest {
		return OwnershipTransferProfile{}, ErrTransferAuthorizationRequired
	}
	return value, nil
}

func activatedTestTransferProfile(profile OwnershipTransferProfile) OwnershipTransferProfile {
	if profile.Activation.SnapshotDigest != ([32]byte{}) {
		return profile
	}
	copy := cloneTransferProfile(profile)
	sortTransferRequirements(copy.OldAuthorities)
	sortTransferRequirements(copy.NewAuthorities)
	encoded, err := encodeTransferProfilePolicy(copy)
	if err != nil {
		return profile
	}
	copy.Activation = OwnershipTransferProfileActivation{
		ProfileDigest: domainDigest(transferProfileDigestDomain, encoded), ActivationVersion: 1,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter,
		EvidenceDigest: digest(0xfa), StateVersion: 1, WriterEpoch: 7,
	}
	copy.Activation.SnapshotDigest, _ = transferProfileActivationDigest(copy.ProfileID,
		copy.ProfileVersion, copy.Activation)
	return copy
}
func (profile *allowProfile) ValidateOwnershipTransferEvidence(context.Context, OwnershipTransferEvidenceRequest) error {
	if profile.transferCurrentErr != nil {
		return profile.transferCurrentErr
	}
	return profile.transferErr
}
func (profile *allowProfile) ValidateOwnershipTransferEvidenceAt(_ context.Context,
	request OwnershipTransferEvidenceHistoryRequest) error {
	if profile.transferHistoricalErr != nil {
		return profile.transferHistoricalErr
	}
	if profile.transferErr != nil {
		return profile.transferErr
	}
	if request.PolicyDecisionDigest == ([32]byte{}) ||
		request.EvidenceRequest.ProfileDigest == ([32]byte{}) ||
		request.EvidenceRequest.Activation.SnapshotDigest == ([32]byte{}) ||
		request.EvidenceRequest.RecordDigest == ([32]byte{}) {
		return ErrTransferAuthorizationRequired
	}
	return nil
}
func (profile *allowProfile) ReceiverProfile(_ context.Context, messageTypeID uint32) (ReceiverProfile, error) {
	registry, err := schema.LoadDefault()
	if err != nil {
		return ReceiverProfile{}, err
	}
	message, ok := registry.LookupMessage(messageTypeID)
	if !ok {
		return ReceiverProfile{}, ErrUnknownMessageType
	}
	return ReceiverProfile{ProtocolVersion: ccse.Version{Major: 1}, SchemaVersion: ccse.Version{Major: 1},
		Purpose: message.Purpose, Audience: []string{"service:iam"}, Environment: "testnet",
		EnrollmentDomainID: "iam-enrollment:testnet",
		ChainID:            digest(0x91), GenesisHash: digest(0x92), ReplayDomainID: "iam.test",
		CounterKind: ccse.CounterExpectedGeneration, MaxClockSkewNanos: 1_000_000,
		MaxValidityWindowNanos: 1_000_000_000, MaxPlanCommitLatencyNanos: 100_000_000}, nil
}

func testPlanner(t testing.TB, view *memoryView, profile *allowProfile) *Planner {
	t.Helper()
	planner, err := NewDefaultPlanner(view, profile)
	if err != nil {
		t.Fatal(err)
	}
	return planner
}

func planKeyMaterialForTest(planner *Planner, ctx context.Context,
	command KeyMaterialCommand) (PendingMutationPlan, error) {
	mutation, audit, err := planner.planKeyMaterial(ctx, command)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	return newPendingMutationPlan(mutation, audit)
}

func planKeyEnrollmentForTest(planner *Planner, ctx context.Context,
	command KeyEnrollmentCommand) (PendingKeyEnrollmentPlan, error) {
	return planner.planKeyEnrollment(ctx, command, true)
}

func planIdentityTransferForTest(planner *Planner, ctx context.Context,
	command IdentityCommand) (PendingMutationPlan, error) {
	mutation, audit, err := planner.planIdentity(ctx, command, true)
	if err != nil {
		return PendingMutationPlan{}, err
	}
	return newPendingMutationPlan(mutation, audit)
}

func digest(seed byte) [32]byte {
	var value [32]byte
	for i := range value {
		value[i] = seed
	}
	return value
}

func id16(seed byte) [16]byte {
	var value [16]byte
	for i := range value {
		value[i] = seed
	}
	return value
}

func testKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seedBytes := make([]byte, ed25519.SeedSize)
	for i := range seedBytes {
		seedBytes[i] = seed
	}
	private := ed25519.NewKeyFromSeed(seedBytes)
	return append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...), append(ed25519.PrivateKey(nil), private...)
}

func materialSnapshot(t testing.TB, seed byte, subject string, kind uint32) KeyMaterialSnapshot {
	return materialSnapshotForTarget(t, seed, subject,
		EntityRef{Kind: EntityIdentity, PrincipalKind: kind, ID: subject})
}

func materialSnapshotForTarget(t testing.TB, seed byte, subject string, target EntityRef) KeyMaterialSnapshot {
	return materialSnapshotForTargetAndTransfer(t, seed, subject, target, [32]byte{})
}

func materialSnapshotForTargetAndTransfer(t testing.TB, seed byte, subject string, target EntityRef,
	transferEvidence [32]byte) KeyMaterialSnapshot {
	t.Helper()
	kind := target.PrincipalKind
	public, private := testKey(seed)
	keyID, err := DeriveKeyID(ccse.SignatureAlgorithmEd25519, public)
	if err != nil {
		t.Fatal(err)
	}
	challenge := digest(seed + 1)
	expires := testNow + 1_000_000_000
	domain := testEnrollmentDomain()
	proofDigest, err := ProofOfPossessionDigest(keyID, subject, kind, target, transferEvidence, domain, challenge, expires)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, proofDigest[:])
	material := KeyMaterialSnapshot{
		KeyID: keyID, Algorithm: ccse.SignatureAlgorithmEd25519, CanonicalPublicKey: public,
		SubjectIdentity: subject, SubjectKind: kind, ProofChallenge: challenge,
		TargetIdentity:         target,
		TransferEvidenceDigest: transferEvidence,
		EnrollmentDomain:       domain,
		ProofExpiresAtUnixNano: expires, ProofSignature: signature, ProofDigest: proofDigest,
		ChallengeEvidenceDigest: digest(seed + 2), EnrollmentAuthorityIdentity: "spiffe://cph.example/service/enroller",
		EnrollmentPolicyDigestsSHA256: [][32]byte{digest(seed + 3)},
		WriterIdentity:                "spiffe://cph.example/service/iam-writer",
		HomeRegion:                    "eu-central-1", WriterEpoch: 7, StateVersion: 1, IdempotencyKey: id16(seed),
	}
	material.EnrollmentBindingDigest, err = enrollmentBindingDigest(material)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func testEnrollmentDomain() EnrollmentDomain {
	return EnrollmentDomain{EnrollmentDomainID: "iam-enrollment:testnet", Environment: "testnet", GenesisHash: digest(0x92)}
}

func installAuthorizationKey(t testing.TB, view *memoryView, messageTypeIDs ...uint32) KeyMaterialSnapshot {
	t.Helper()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: "service-iam-writer"}
	material := materialSnapshotForTarget(t, 0xe1, "spiffe://cph.example/service/iam-writer", target)
	projection := lifecycleProjection(material, 2, 1, 7)
	projection.AllowedMessageTypeIDs = append([]uint32(nil), messageTypeIDs...)
	snapshot, err := NormalizeKeyLifecycle(projection)
	if err != nil {
		t.Fatal(err)
	}
	view.materials[material.KeyID] = material
	view.lifecycles[material.KeyID] = snapshot
	identityProjection := foundationv1.ServiceIdentitySigningProjection{
		Metadata: metadata(1, 7, 0xe7), ServiceID: target.ID, ServiceName: "iam-writer",
		SPIFFEID: material.SubjectIdentity, DeploymentEnvironment: "testnet", KeyID: material.KeyID,
		CredentialGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2,
	}
	identity, err := NormalizeIdentity(identityProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.identities[target] = identity
	view.globalIDs[material.KeyID] = globalid.Snapshot{Identifier: material.KeyID, Owner: keyGlobalOwner(material.KeyID), Version: 1}
	owner := identityGlobalOwner(target)
	view.globalIDs[target.ID] = globalid.Snapshot{Identifier: target.ID, Owner: owner, Version: 1}
	view.globalIDs[material.SubjectIdentity] = globalid.Snapshot{Identifier: material.SubjectIdentity, Owner: owner, Version: 1}
	return material
}

func installActiveServiceMaterial(t testing.TB, view *memoryView, material KeyMaterialSnapshot,
	messageTypeIDs ...uint32) {
	t.Helper()
	projection := lifecycleProjection(material, 2, 1, 7)
	projection.AllowedMessageTypeIDs = append([]uint32(nil), messageTypeIDs...)
	lifecycle, err := NormalizeKeyLifecycle(projection)
	if err != nil {
		t.Fatal(err)
	}
	identityProjection := foundationv1.ServiceIdentitySigningProjection{
		Metadata: metadata(1, 7, 0xf8), ServiceID: material.TargetIdentity.ID,
		ServiceName: "transfer-evidence-signer", SPIFFEID: material.SubjectIdentity,
		DeploymentEnvironment: "testnet", KeyID: material.KeyID, CredentialGeneration: 1,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2,
	}
	identity, err := NormalizeIdentity(identityProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.materials[material.KeyID] = material
	view.lifecycles[material.KeyID] = lifecycle
	view.identities[material.TargetIdentity] = identity
	installGlobalID(view, material.KeyID, keyGlobalOwner(material.KeyID), 1)
	installIdentityOwnership(view, identity)
}

func installGlobalID(view *memoryView, identifier string, owner globalid.Owner, version uint64) {
	view.globalIDs[identifier] = globalid.Snapshot{Identifier: identifier, Owner: owner, Version: version}
}

func verifiedAuthorization(t testing.TB, view *memoryView, messageTypeID uint32, payload []byte,
	replayEntity EntityRef, counter uint64, correlation [16]byte) VerifiedAuthorization {
	t.Helper()
	writer := installAuthorizationKey(t, view, messageTypeID)
	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	message, ok := registry.LookupMessage(messageTypeID)
	if !ok {
		t.Fatal("message type missing")
	}
	version := ccse.Version{Major: 1}
	replayDomain, err := DeriveEntityReplayDomainID("iam.test", replayEntity)
	if err != nil {
		t.Fatal(err)
	}
	domain := ccse.Domain{Purpose: message.Purpose, SenderIdentity: writer.SubjectIdentity,
		Audience: []string{"service:iam"}, Environment: "testnet", ChainID: digest(0x91), GenesisHash: digest(0x92),
		ProtocolVersion: version, SchemaVersion: version, SignatureAlgorithm: ccse.SignatureAlgorithmEd25519,
		SignatureKeyID: writer.KeyID, IssuedAtUnixNano: testNow - 10, ExpiresAtUnixNano: testNow + 100,
		CounterKind: ccse.CounterExpectedGeneration, Counter: counter, ReplayDomainID: replayDomain}
	envelope := ccse.Envelope{ProtocolVersion: version, SchemaVersion: version, MessageID: id16(0xd1),
		CorrelationID: correlation, SenderIdentity: writer.SubjectIdentity, ChainID: digest(0x91), Environment: "testnet",
		IssuedAtUnixNano: testNow - 10, ExpiresAtUnixNano: testNow + 100,
		CounterKind: ccse.CounterExpectedGeneration, Counter: counter,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: writer.KeyID}
	record, err := ccse.NewRecord(messageTypeID, version, domain, envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, private := testKey(0xe1)
	if err := record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	recordDigest, err := record.Digest(ccse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return VerifiedAuthorization{messageTypeID: messageTypeID, schemaVersion: version,
		senderIdentity: writer.SubjectIdentity, signatureKeyID: writer.KeyID, payload: append([]byte(nil), payload...),
		recordDigest: recordDigest, messageID: envelope.MessageID, correlationID: correlation,
		issuedAtUnixNano: domain.IssuedAtUnixNano, expiresAtUnixNano: domain.ExpiresAtUnixNano, protocolVersion: version,
		purpose: message.Purpose, audience: []string{"service:iam"}, environment: "testnet", chainID: domain.ChainID,
		genesisHash: domain.GenesisHash, replayDomainID: domain.ReplayDomainID,
		counterKind: domain.CounterKind, counter: counter, sourceRecord: cloneCCSERecord(*record), hasSourceRecord: true}
}

func authorizationWithReplayDomain(t testing.TB, source VerifiedAuthorization,
	replayDomain string) VerifiedAuthorization {
	t.Helper()
	result := source
	result.replayDomainID = replayDomain
	result.sourceRecord = cloneCCSERecord(source.sourceRecord)
	result.sourceRecord.Domain.ReplayDomainID = replayDomain
	var err error
	result.recordDigest, err = result.sourceRecord.Digest(ccse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func metadata(version, epoch uint64, seed byte) foundationv1.RecordMetadataSigningProjection {
	return foundationv1.RecordMetadataSigningProjection{
		SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1},
		RecordID:      "record-id", CreatedAtUnixNano: testNow - 20, IntegrityDigest: digest(seed),
		HomeRegion: "eu-central-1", WriterEpoch: epoch, StateVersion: version,
		IdempotencyKey: id16(seed), PolicyDigestsSHA256: [][32]byte{digest(seed + 1)},
	}
}

func lifecycleProjection(material KeyMaterialSnapshot, state, version uint32, epoch uint64) foundationv1.KeyLifecycleSigningProjection {
	return foundationv1.KeyLifecycleSigningProjection{
		Metadata: metadata(uint64(version), epoch, byte(version+20)), KeyID: material.KeyID,
		SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		Algorithm: uint32(material.Algorithm), State: state, NotBeforeUnixNano: testNotBefore,
		NotAfterUnixNano: testNotAfter, AllowedMessageTypeIDs: []uint32{schema.MessageTypeAgentIdentity},
		AuthorizationPolicyDigestSHA256: digest(0x55),
	}
}

func lifecycleSnapshot(t testing.TB, material KeyMaterialSnapshot, state, version uint32, epoch uint64) KeyLifecycleSnapshot {
	t.Helper()
	projection := lifecycleProjection(material, state, version, epoch)
	if state == 4 {
		projection.RevokedAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testNow}
	}
	snapshot, err := NormalizeKeyLifecycle(projection)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func agentProjection(material KeyMaterialSnapshot, state uint32, version, epoch uint64) foundationv1.AgentIdentitySigningProjection {
	return foundationv1.AgentIdentitySigningProjection{
		Metadata: metadata(version, epoch, byte(version+40)), AgentID: "agent-01", ProviderID: "provider-01",
		HostID: "host-01", SPIFFEID: material.SubjectIdentity, KeyID: material.KeyID,
		OwnershipGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter,
		State: state,
	}
}

func lease(ref EntityRef, writer string, epoch uint64, evidence byte) WriterLeaseSnapshot {
	return WriterLeaseSnapshot{Entity: ref, WriterIdentity: writer, HomeRegion: "eu-central-1", WriterEpoch: epoch,
		ValidFromUnixNano: testNow - 1, ValidUntilUnixNano: testNow + 1_000_000_000, EvidenceDigest: digest(evidence)}
}

func fence(ref EntityRef, writer string, epoch, version uint64, evidence byte) WriterFence {
	return WriterFence{Entity: ref, WriterIdentity: writer, HomeRegion: "eu-central-1", WriterEpoch: epoch,
		ExpectedStateVersion: version, EvidenceDigest: digest(evidence)}
}

func requireErrorIs(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}

func hashBytes(value []byte) [32]byte { return sha256.Sum256(value) }
