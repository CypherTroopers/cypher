// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

type transferCollectionFixture struct {
	view          *memoryView
	profile       *allowProfile
	projection    foundationv1.OwnershipTransferAuthorizationSigningProjection
	payload       []byte
	oldApproval   ccse.VerifiedRecord
	newApproval   ccse.VerifiedRecord
	previous      IdentitySnapshot
	oldAuthority  KeyMaterialSnapshot
	newAuthority  KeyMaterialSnapshot
	closures      []ccse.VerifiedRecord
	evidence      []ccse.VerifiedRecord
	transferLease WriterLeaseSnapshot
}

func installActiveTransferAuthority(t testing.TB, view *memoryView, seed byte, serviceID,
	principal string, authorizationPolicy [32]byte) KeyMaterialSnapshot {
	t.Helper()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: serviceID}
	material := materialSnapshotForTarget(t, seed, principal, target)
	lifecycleProjection := lifecycleProjection(material, 2, 1, 7)
	lifecycleProjection.Metadata.RecordID = serviceID + "-key-active"
	lifecycleProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeOwnershipTransferAuthorization}
	lifecycleProjection.AuthorizationPolicyDigestSHA256 = authorizationPolicy
	lifecycle, err := NormalizeKeyLifecycle(lifecycleProjection)
	if err != nil {
		t.Fatal(err)
	}
	identityProjection := foundationv1.ServiceIdentitySigningProjection{
		Metadata: metadata(1, 7, seed+10), ServiceID: serviceID, ServiceName: serviceID,
		SPIFFEID: principal, DeploymentEnvironment: "testnet", KeyID: material.KeyID,
		CredentialGeneration: 1, ValidFromUnixNano: testNotBefore,
		ValidUntilUnixNano: testNotAfter, State: 2,
	}
	identityProjection.Metadata.RecordID = serviceID + "-identity-active"
	identity, err := NormalizeIdentity(identityProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.materials[material.KeyID] = material
	view.lifecycles[material.KeyID] = lifecycle
	view.identities[target] = identity
	installGlobalID(view, material.KeyID, keyGlobalOwner(material.KeyID), 1)
	installIdentityOwnership(view, identity)
	return material
}

func verifiedFoundationRecord(t testing.TB, material KeyMaterialSnapshot, privateSeed byte,
	messageTypeID uint32, payload []byte, replayEntity EntityRef, counter uint64,
	messageID, correlationID [16]byte, providerOrganization string,
	replay *ccse.MemoryReplayStore) ccse.VerifiedRecord {
	t.Helper()
	public, private := testKey(privateSeed)
	if !ed25519.PublicKey(material.CanonicalPublicKey).Equal(public) {
		t.Fatal("record signing key does not match installed material")
	}
	registry, err := schema.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	message, ok := registry.LookupMessage(messageTypeID)
	if !ok {
		t.Fatal("message type absent")
	}
	replayDomain, err := DeriveEntityReplayDomainID("iam.test", replayEntity)
	if err != nil {
		t.Fatal(err)
	}
	version := ccse.Version{Major: 1}
	provider := ccse.OptionalString{}
	if providerOrganization != "" {
		provider = ccse.OptionalString{Present: true, Value: providerOrganization}
	}
	domain := ccse.Domain{Purpose: message.Purpose, SenderIdentity: material.SubjectIdentity,
		Audience: []string{"service:iam"}, ProviderOrganization: provider,
		Environment: "testnet", ChainID: digest(0x91), GenesisHash: digest(0x92),
		ProtocolVersion: version, SchemaVersion: version,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: material.KeyID,
		IssuedAtUnixNano: testNow - 10, ExpiresAtUnixNano: testNow + 500_000_000,
		CounterKind: ccse.CounterExpectedGeneration, Counter: counter, ReplayDomainID: replayDomain}
	envelope := ccse.Envelope{ProtocolVersion: version, SchemaVersion: version,
		MessageID: messageID, CorrelationID: correlationID, SenderIdentity: material.SubjectIdentity,
		ChainID: domain.ChainID, Environment: domain.Environment,
		IssuedAtUnixNano: domain.IssuedAtUnixNano, ExpiresAtUnixNano: domain.ExpiresAtUnixNano,
		CounterKind: domain.CounterKind, Counter: counter,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: material.KeyID}
	record, err := ccse.NewRecord(messageTypeID, version, domain, envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	keys := ccse.NewMemoryKeyRegistry()
	if err := keys.Add(ccse.KeyRecord{KeyID: material.KeyID, SubjectIdentity: material.SubjectIdentity,
		Algorithm: ccse.SignatureAlgorithmEd25519, PublicKey: public,
		NotBeforeUnixNano: testNotBefore, NotAfterUnixNano: testNotAfter,
		AllowedMessageTypes: []uint32{messageTypeID}}); err != nil {
		t.Fatal(err)
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		t.Fatal(err)
	}
	if replay == nil {
		replay = ccse.NewMemoryReplayStore()
	}
	verifier := ccse.Verifier{Expectations: ccse.Expectations{
		MessageTypeID: messageTypeID, SchemaVersion: version, ProtocolVersion: version,
		Purpose: message.Purpose, SenderIdentity: ccse.OptionalString{Present: true, Value: material.SubjectIdentity},
		Audience: []string{"service:iam"}, ProviderOrganization: provider,
		Environment: "testnet", ChainID: domain.ChainID, GenesisHash: domain.GenesisHash,
		ReplayDomainID: replayDomain, CounterKind: ccse.CounterExpectedGeneration,
		MaxClockSkew: time.Millisecond, MaxValidityWindow: time.Second,
	}, Limits: ccse.DefaultLimits(), Clock: ccse.ClockFunc(func() time.Time { return time.Unix(0, testNow) }),
		Keys: keys, Replay: replay, Schema: validator,
		Handle: func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
			return sha256.Sum256([]byte("verified transfer fixture")), nil
		}}
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	return result.Verified
}

func ownershipTransferEvidenceProjection(seed byte, kind uint32) foundationv1.EvidenceRecordSigningProjection {
	projection := foundationv1.EvidenceRecordSigningProjection{
		Metadata: metadata(1, 7, seed), EvidenceID: "transfer-evidence-" + string(rune('a'+kind)),
		ExperimentPlanID: "transfer-evidence-plan", CapabilityID: "CAP-OWNERSHIP-TRANSFER",
		Component: "iam", OwnerIdentity: "spiffe://cph.example/evidence/owner",
		SoftwareVersion: "CPH-AIIE-0.2", HardwareScope: []string{"host:transfer"},
		WorkloadScope: []string{"iam:ownership-transfer"}, RegionScope: []string{"eu-central-1"},
		TestStartedAtUnixNano: testNow - 50, TestEndedAtUnixNano: testNow - 40,
		SampleSize: 1, EvidenceArtifactDigestsSHA256: [][32]byte{digest(seed + 1)},
		Observations: []foundationv1.MetricObservationSigningProjection{{MetricID: "transfer.readiness",
			ObservedNumerator: 1, ObservedDenominator: 1, SampleSize: 1,
			ConfidenceLowerNumerator: 1, ConfidenceLowerDenominator: 1,
			ConfidenceUpperNumerator: 1, ConfidenceUpperDenominator: 1, CriterionPassed: true}},
		ApprovingRole:       "transfer-evidence-reviewer",
		ApprovingIdentities: []string{"spiffe://cph.example/evidence/reviewer"},
		ApprovedAtUnixNano:  testNow - 30, ExpiresAtUnixNano: testNow + 900_000_000,
		RevalidationTriggers: []string{"ownership-transfer-retry"}, AchievedLevel: 4, Status: 2,
	}
	projection.Metadata.RecordID = "transfer-evidence-record-" + string(rune('a'+kind))
	return projection
}

func newTransferCollectionFixture(t testing.TB) transferCollectionFixture {
	t.Helper()
	view := newMemoryView()
	sharedAuthorityPolicy := digest(0xc1)
	oldAuthority := installActiveTransferAuthority(t, view, 0xc2, "old-transfer-authority",
		"spiffe://cph.example/old/transfer-authority", sharedAuthorityPolicy)
	newAuthority := installActiveTransferAuthority(t, view, 0xc3, "new-transfer-authority",
		"spiffe://cph.example/new/transfer-authority", sharedAuthorityPolicy)

	previousRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-transfer-old"}
	previousPrincipal := "spiffe://cph.example/old/agent-transfer"
	oldMaterial := materialSnapshotForTarget(t, 0xc4, previousPrincipal, previousRef)
	oldLifecycleProjection := lifecycleProjection(oldMaterial, 2, 1, 7)
	oldLifecycleProjection.Metadata.RecordID = "agent-transfer-old-key-active"
	oldLifecycleProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeAgentIdentity}
	oldLifecycle, err := NormalizeKeyLifecycle(oldLifecycleProjection)
	if err != nil {
		t.Fatal(err)
	}
	previousProjection := foundationv1.AgentIdentitySigningProjection{
		Metadata: metadata(1, 7, 0xc5), AgentID: previousRef.ID, ProviderID: "provider-old",
		HostID: "host-old", SPIFFEID: previousPrincipal, KeyID: oldMaterial.KeyID,
		OwnershipGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2,
	}
	previousProjection.Metadata.RecordID = "agent-transfer-old-active"
	previous, err := NormalizeIdentity(previousProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.materials[oldMaterial.KeyID] = oldMaterial
	view.lifecycles[oldMaterial.KeyID] = oldLifecycle
	view.identities[previousRef] = previous
	installGlobalID(view, oldMaterial.KeyID, keyGlobalOwner(oldMaterial.KeyID), 1)
	installIdentityOwnership(view, previous)

	terminalProjection := previousProjection
	terminalProjection.Metadata = metadata(2, 8, 0xc6)
	terminalProjection.Metadata.RecordID = "agent-transfer-old-terminal"
	terminalProjection.State = 5
	terminal, err := NormalizeIdentity(terminalProjection)
	if err != nil {
		t.Fatal(err)
	}
	newRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-transfer-new"}
	newPrincipal := "spiffe://cph.example/new/agent-transfer"
	newMaterial := materialSnapshotForTarget(t, 0xc7, newPrincipal, newRef)
	nextProjection := foundationv1.AgentIdentitySigningProjection{
		Metadata: metadata(1, 7, 0xc8), AgentID: newRef.ID, ProviderID: "provider-new",
		HostID: "host-new", SPIFFEID: newPrincipal, KeyID: newMaterial.KeyID,
		OwnershipGeneration: 2, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1,
	}
	nextProjection.Metadata.RecordID = "agent-transfer-new-pending"
	next, err := NormalizeIdentity(nextProjection)
	if err != nil {
		t.Fatal(err)
	}

	closureProjection := oldLifecycleProjection
	closureProjection.Metadata = metadata(2, 8, 0xc9)
	closureProjection.Metadata.RecordID = "agent-transfer-old-key-revoked"
	closureProjection.State = 4
	closureProjection.RevokedAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testNow}
	closureProjection.TransitionReasonCode = foundationv1.OptionalString{Present: true, Value: "ownership-transfer"}
	closurePayload, err := closureProjection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	closureSigner := installAuthorizationKey(t, view, schema.MessageTypeKeyLifecycle)
	closureRecord := verifiedFoundationRecord(t, closureSigner, 0xe1, schema.MessageTypeKeyLifecycle,
		closurePayload, EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: 2, ID: oldMaterial.KeyID},
		1, id16(0xca), id16(0xcb), "", nil)

	evidenceSigner := materialSnapshotForTarget(t, 0xcc, "spiffe://cph.example/evidence/signer",
		EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: "transfer-evidence-signer"})
	installActiveServiceMaterial(t, view, evidenceSigner, schema.MessageTypeEvidenceRecord)
	evidenceKinds := []uint32{foundationv1.TransferEvidenceOldProviderAuthority,
		foundationv1.TransferEvidenceNewProviderAuthority,
		foundationv1.TransferEvidenceDescendantIdentityClosure,
		foundationv1.TransferEvidenceLeaseOfferWorkloadClosure}
	evidenceRecords := make([]ccse.VerifiedRecord, 0, len(evidenceKinds))
	commitments := make([]foundationv1.TransferEvidenceCommitmentSigningProjection, 0, len(evidenceKinds))
	for index, kind := range evidenceKinds {
		evidenceProjection := ownershipTransferEvidenceProjection(byte(0xd0+index), kind)
		evidencePayload, payloadErr := evidenceProjection.CanonicalBytes()
		if payloadErr != nil {
			t.Fatal(payloadErr)
		}
		record := verifiedFoundationRecord(t, evidenceSigner, 0xcc, schema.MessageTypeEvidenceRecord,
			evidencePayload, EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: evidenceProjection.EvidenceID},
			1, id16(byte(0xd5+index)), id16(byte(0xda+index)), "", nil)
		evidenceRecords = append(evidenceRecords, record)
		commitments = append(commitments, foundationv1.TransferEvidenceCommitmentSigningProjection{
			EvidenceKind: kind, CCSERecordDigestSHA256: record.Digest()})
		installGlobalID(view, evidenceProjection.Metadata.RecordID,
			globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: evidenceProjection.EvidenceID}, 1)
	}

	profilePolicy := digest(0xe0)
	transferMetadata := metadata(1, 7, 0xe1)
	transferMetadata.RecordID = "agent-transfer-authorization-record"
	transferMetadata.PolicyDigestsSHA256 = [][32]byte{profilePolicy, sharedAuthorityPolicy}
	projection := foundationv1.OwnershipTransferAuthorizationSigningProjection{
		Metadata: transferMetadata, TransferAuthorizationID: "agent-transfer-authorization",
		SubjectKind: 2, PreviousEntityID: previousRef.ID, NextEntityID: newRef.ID,
		PreviousPrincipalIdentity: previousPrincipal, NextPrincipalIdentity: newPrincipal,
		PreviousProviderID: "provider-old", NextProviderID: "provider-new",
		ExpectedGeneration: 1, NextGeneration: 2,
		PreviousTerminalIdentityPayloadDigestSHA256: sha256.Sum256(terminal.CanonicalPayload),
		NextPendingIdentityPayloadDigestSHA256:      sha256.Sum256(next.CanonicalPayload),
		OldKeyClosures: []foundationv1.KeyClosureSigningProjection{{KeyID: oldMaterial.KeyID,
			TerminalKeyLifecyclePayloadDigestSHA256: sha256.Sum256(closurePayload)}},
		NewKeyID: newMaterial.KeyID, EvidenceCommitments: commitments,
		EffectiveAtUnixNano: testNow, ExpiresAtUnixNano: testNow + 500_000_000,
		OldAuthorities: []foundationv1.TransferAuthoritySigningProjection{{
			Identity: oldAuthority.SubjectIdentity, KeyID: oldAuthority.KeyID}},
		NewAuthorities: []foundationv1.TransferAuthoritySigningProjection{{
			Identity: newAuthority.SubjectIdentity, KeyID: newAuthority.KeyID}},
	}
	payload, err := projection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	profile := OwnershipTransferProfile{ProfileID: "agent-transfer-profile", ProfileVersion: 1,
		PolicyDigest: profilePolicy, RecordIntegrityDigestSHA256: transferMetadata.IntegrityDigest,
		OldAuthorities: []OwnershipTransferAuthorityRequirement{{Identity: oldAuthority.SubjectIdentity,
			KeyID: oldAuthority.KeyID, ProviderID: projection.PreviousProviderID, OrganizationID: "org-old",
			Role: "old-provider-transfer", AuthorizationPolicyDigestSHA256: sharedAuthorityPolicy}},
		NewAuthorities: []OwnershipTransferAuthorityRequirement{{Identity: newAuthority.SubjectIdentity,
			KeyID: newAuthority.KeyID, ProviderID: projection.NextProviderID, OrganizationID: "org-new",
			Role: "transfer-coordinator", AuthorizationPolicyDigestSHA256: sharedAuthorityPolicy, Coordinator: true}},
	}
	previousReplay := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: previousRef.ID}
	correlation := id16(0xef)
	oldApproval := verifiedFoundationRecord(t, oldAuthority, 0xc2,
		schema.MessageTypeOwnershipTransferAuthorization, payload, previousReplay, 1,
		id16(0xf0), correlation, "org-old", nil)
	newApproval := verifiedFoundationRecord(t, newAuthority, 0xc3,
		schema.MessageTypeOwnershipTransferAuthorization, payload, previousReplay, 1,
		id16(0xf1), correlation, "org-new", nil)
	transferEntity := EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: 2, ID: projection.TransferAuthorizationID}
	transferLease := lease(transferEntity, "spiffe://cph.example/service/transfer-collector", 7, 0xf2)
	view.leases[transferEntity] = transferLease
	return transferCollectionFixture{view: view, profile: &allowProfile{transferProfile: &profile},
		projection: projection, payload: payload, oldApproval: oldApproval, newApproval: newApproval,
		previous: previous, oldAuthority: oldAuthority, newAuthority: newAuthority,
		closures: []ccse.VerifiedRecord{closureRecord}, evidence: evidenceRecords, transferLease: transferLease}
}

func expandTransferFixtureClosures(t testing.TB, fixture transferCollectionFixture,
	closureCount int) transferCollectionFixture {
	t.Helper()
	if closureCount < len(fixture.projection.OldKeyClosures) || closureCount > 256 {
		t.Fatal("invalid closure expansion")
	}
	writer := installAuthorizationKey(t, fixture.view, schema.MessageTypeKeyLifecycle)
	for index := len(fixture.projection.OldKeyClosures); index < closureCount; index++ {
		material := materialSnapshotForIndexedClosure(t, index,
			fixture.projection.PreviousPrincipalIdentity, fixture.previous.Ref)
		activeProjection := lifecycleProjection(material, 2, 1, 7)
		activeProjection.Metadata.RecordID = fmt.Sprintf("agent-transfer-old-key-%03d-active", index)
		activeProjection.Metadata.IdempotencyKey = indexedID16(0x40, index)
		activeProjection.Metadata.IntegrityDigest = sha256.Sum256([]byte(activeProjection.Metadata.RecordID))
		activeProjection.Metadata.PolicyDigestsSHA256 = [][32]byte{digest(0x54)}
		activeProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeAgentIdentity}
		active, err := NormalizeKeyLifecycle(activeProjection)
		if err != nil {
			t.Fatal(err)
		}
		fixture.view.materials[material.KeyID] = material
		fixture.view.lifecycles[material.KeyID] = active
		installGlobalID(fixture.view, material.KeyID, keyGlobalOwner(material.KeyID), 1)

		terminalProjection := activeProjection
		terminalProjection.Metadata.StateVersion = 2
		terminalProjection.Metadata.WriterEpoch = 8
		terminalProjection.Metadata.RecordID = fmt.Sprintf("agent-transfer-old-key-%03d-revoked", index)
		terminalProjection.Metadata.IdempotencyKey = indexedID16(0x80, index)
		terminalProjection.Metadata.IntegrityDigest = sha256.Sum256([]byte(terminalProjection.Metadata.RecordID))
		terminalProjection.State = 4
		terminalProjection.RevokedAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testNow}
		terminalProjection.TransitionReasonCode = foundationv1.OptionalString{Present: true, Value: "ownership-transfer"}
		payload, err := terminalProjection.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		messageID := indexedID16(0xa0, index)
		correlationID := indexedID16(0xb0, index)
		record := verifiedFoundationRecord(t, writer, 0xe1, schema.MessageTypeKeyLifecycle,
			payload, EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: material.SubjectKind, ID: material.KeyID},
			1, messageID, correlationID, "", nil)
		fixture.projection.OldKeyClosures = append(fixture.projection.OldKeyClosures,
			foundationv1.KeyClosureSigningProjection{KeyID: material.KeyID,
				TerminalKeyLifecyclePayloadDigestSHA256: sha256.Sum256(payload)})
		fixture.closures = append(fixture.closures, record)
	}
	payload, err := fixture.projection.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fixture.payload = payload
	previousReplay := EntityRef{Kind: EntityIdentity, PrincipalKind: 2,
		ID: fixture.projection.PreviousEntityID}
	correlation := id16(0xef)
	fixture.oldApproval = verifiedFoundationRecord(t, fixture.oldAuthority, 0xc2,
		schema.MessageTypeOwnershipTransferAuthorization, payload, previousReplay, 1,
		id16(0xf0), correlation, "org-old", nil)
	fixture.newApproval = verifiedFoundationRecord(t, fixture.newAuthority, 0xc3,
		schema.MessageTypeOwnershipTransferAuthorization, payload, previousReplay, 1,
		id16(0xf1), correlation, "org-new", nil)
	return fixture
}

func indexedID16(prefix byte, index int) [16]byte {
	var result [16]byte
	result[0] = prefix
	result[14] = byte(index >> 8)
	result[15] = byte(index)
	return result
}

func (fixture transferCollectionFixture) command(approval ccse.VerifiedRecord, expected uint64) OwnershipTransferApprovalIngestionCommand {
	return OwnershipTransferApprovalIngestionCommand{Approval: approval,
		PreviousTerminalIdentityPayload: fixture.projectionPayload(fixture.projection.PreviousTerminalIdentityPayloadDigestSHA256, true),
		NextPendingIdentityPayload:      fixture.projectionPayload(fixture.projection.NextPendingIdentityPayloadDigestSHA256, false),
		KeyClosureRecords:               fixture.closures, EvidenceRecords: fixture.evidence,
		EvaluatedAtUnixNano: testNow, Fence: WriterFence{Entity: fixture.transferLease.Entity,
			WriterIdentity: fixture.transferLease.WriterIdentity, HomeRegion: fixture.transferLease.HomeRegion,
			WriterEpoch: fixture.transferLease.WriterEpoch, ExpectedStateVersion: expected,
			EvidenceDigest: fixture.transferLease.EvidenceDigest}}
}

func (fixture transferCollectionFixture) projectionPayload(want [32]byte, previous bool) []byte {
	if previous {
		for _, identity := range fixture.view.identities {
			if identity.Ref.ID == fixture.projection.PreviousEntityID {
				projection := foundationv1.AgentIdentitySigningProjection{
					Metadata: metadata(identity.StateVersion+1, identity.WriterEpoch+1, 0xc6),
					AgentID:  identity.Ref.ID, ProviderID: identity.Bindings.ProviderID,
					HostID: identity.Bindings.HostID, SPIFFEID: identity.PrincipalIdentity, KeyID: identity.KeyID,
					OwnershipGeneration: identity.Generation, ValidFromUnixNano: identity.ValidFromUnixNano,
					ValidUntilUnixNano: identity.ValidUntilUnixNano, State: 5}
				projection.Metadata.RecordID = "agent-transfer-old-terminal"
				payload, _ := projection.CanonicalBytes()
				if sha256.Sum256(payload) == want {
					return payload
				}
			}
		}
	}
	newMaterial := fixture.projection.NewKeyID
	projection := foundationv1.AgentIdentitySigningProjection{Metadata: metadata(1, 7, 0xc8),
		AgentID: fixture.projection.NextEntityID, ProviderID: fixture.projection.NextProviderID,
		HostID: "host-new", SPIFFEID: fixture.projection.NextPrincipalIdentity, KeyID: newMaterial,
		OwnershipGeneration: fixture.projection.NextGeneration, ValidFromUnixNano: testNotBefore,
		ValidUntilUnixNano: testNotAfter, State: 1}
	projection.Metadata.RecordID = "agent-transfer-new-pending"
	payload, _ := projection.CanonicalBytes()
	return payload
}

func applyTransferCollectionPlan(t testing.TB, view *memoryView, plan OwnershipTransferApprovalCollectionPlan) {
	t.Helper()
	for _, claim := range plan.IdempotencyClaims() {
		view.idempotency[claim.Binding.Key] = idempotency.Snapshot{Binding: claim.Binding,
			State: claim.NextState, Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest}
	}
	for _, claim := range plan.IdentifierClaims() {
		if claim.Mode == globalid.ReserveNew {
			view.globalIDs[claim.Identifier] = globalid.Snapshot{Identifier: claim.Identifier,
				Owner: claim.Owner, Version: claim.NextVersion}
		}
	}
	next := plan.NextCollection()
	view.transferCollections[next.Binding.Key] = next
}

func seedPendingAdmissionRevision(t testing.TB, view *memoryView,
	capability IAMPendingAdmissionCapability) {
	t.Helper()
	revision := capability.PendingRevision().Record()
	records := make([]IAMPersistenceEvidenceRecord, 0,
		len(capability.EvidenceStorageCapabilities()))
	for _, action := range capability.EvidenceStorageCapabilities() {
		if action.VerifyDigest() != nil {
			t.Fatal("invalid admission evidence action")
		}
		record := action.Evidence().Record()
		records = append(records, record)
		view.admissionEvidence[record.DigestSHA256] = cloneIAMPersistenceEvidenceRecord(record)
	}
	view.pendingPersistence[revision.PendingKey] = memoryPendingPersistence{
		revision: IAMPendingStoredRevision{
			PendingKey: revision.PendingKey, Kind: revision.Kind, Codec: revision.Codec,
			CodecVersion: revision.CodecVersion, Revision: revision.Revision,
			PreviousEnvelopeDigestSHA256: revision.PreviousEnvelopeDigestSHA256,
			EnvelopeDigestSHA256:         revision.EnvelopeDigestSHA256,
			CanonicalEnvelope:            append([]byte(nil), revision.CanonicalEnvelope...),
			EvidenceDigestsSHA256: append([][sha256.Size]byte(nil),
				revision.EvidenceDigestsSHA256...),
			Status: revision.Status, CommitNotBeforeUnixNano: revision.CommitNotBeforeUnixNano,
			CommitNotAfterUnixNano:      revision.CommitNotAfterUnixNano,
			TerminalOutcomeDigestSHA256: revision.TerminalOutcomeDigestSHA256,
			ExpectedAuditEventID:        revision.ExpectedAuditEventID,
		},
		evidence: records,
	}
}

func TestOwnershipTransferApprovalCollectionAcceptsExactQuorum(t *testing.T) {
	fixture := newTransferCollectionFixture(t)
	planner := testPlanner(t, fixture.view, fixture.profile)
	first, err := planner.PlanOwnershipTransferApproval(context.Background(), fixture.command(fixture.oldApproval, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.CommitReady() || first.QuorumSatisfied() || first.VerifyDigest() != nil ||
		first.Disposition() != OwnershipTransferCollectionAppend {
		t.Fatalf("first collection plan invalid: %#v / %v", first, first.VerifyDigest())
	}
	firstEnvelope, err := first.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	firstAdmission, err := planner.BindPendingAdmissionCapability(context.Background(), firstEnvelope)
	if err != nil || firstAdmission.VerifyFor(firstEnvelope) != nil ||
		firstAdmission.PendingRevision().Record().Kind != DurablePendingOwnershipTransferCollection ||
		firstAdmission.PendingRevision().Record().Revision != 1 ||
		len(firstAdmission.EvidenceStorageCapabilities()) < 3 ||
		len(firstAdmission.CanonicalStateReads().Assertions()) < 2 {
		t.Fatalf("transfer collection first admission capability: %v", err)
	}
	firstOuter, outerOK := firstAdmission.OuterRecord()
	firstOuterDigest, outerErr := firstOuter.Digest(ccse.DefaultLimits())
	if !outerOK || outerErr != nil || firstOuterDigest != fixture.oldApproval.Digest() ||
		firstOuterDigest != firstAdmission.OuterRecordDigest() {
		t.Fatal("first collection admission did not bind the exact ingested approval")
	}
	assertDurableEnvelopeRoundTrip(t, firstEnvelope)
	if _, err := first.JoinedAuditRequest(); !errors.Is(err, ErrPendingPlanInvalid) {
		t.Fatalf("non-quorum collection exposed joined success request: %v", err)
	}
	if !hasIdentifierClaim(first.IdentifierClaims(), fixture.projection.NewKeyID, globalid.ReserveNew) ||
		!hasIdentifierClaim(first.IdentifierClaims(), "agent-transfer-old-key-revoked", globalid.ReserveNew) {
		t.Fatal("future key/lifecycle record IDs were not reserved at admission")
	}
	seedPendingAdmissionRevision(t, fixture.view, firstAdmission)
	applyTransferCollectionPlan(t, fixture.view, first)
	decodedFirst, err := DecodeDurablePendingEnvelope(firstEnvelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	revalidatedFirst, err := planner.RevalidateDurablePending(
		context.Background(), decodedFirst, testNow+1)
	revalidatedPlan, revalidatedOK := revalidatedFirst.OwnershipTransferCollectionPlan()
	if err != nil || !revalidatedOK || revalidatedFirst.VerifyDigest() != nil ||
		revalidatedFirst.Digest() != firstEnvelope.Digest() ||
		revalidatedPlan.Digest() != first.Digest() {
		t.Fatalf("stored transfer collection revalidation = %v / ok=%v / envelope=%v",
			err, revalidatedOK, revalidatedFirst.VerifyDigest())
	}
	if _, joinedErr := revalidatedPlan.JoinedAuditRequest(); !errors.Is(joinedErr, ErrPendingPlanInvalid) {
		t.Fatalf("revalidated non-quorum collection exposed joined success: %v", joinedErr)
	}
	claims := first.IdentifierClaims()
	if len(claims) == 0 {
		t.Fatal("transfer collection has no admitted global identifiers")
	}
	storedGlobal := fixture.view.globalIDs[claims[0].Identifier]
	mutatedGlobal := storedGlobal
	mutatedGlobal.Version++
	fixture.view.globalIDs[claims[0].Identifier] = mutatedGlobal
	if _, err := planner.RevalidateDurablePending(context.Background(), decodedFirst,
		testNow+1); !errors.Is(err, ErrPendingPlanInvalid) {
		t.Fatalf("stored transfer collection accepted global-id drift: %v", err)
	}
	fixture.view.globalIDs[claims[0].Identifier] = storedGlobal
	second, err := planner.PlanOwnershipTransferApproval(context.Background(), fixture.command(fixture.newApproval, 1))
	if err != nil {
		t.Fatal(err)
	}
	_, accepted := second.AcceptedSnapshot()
	_, audit := second.AuditIntent()
	if !second.QuorumSatisfied() || !second.ReadyForAcceptance() || accepted || audit ||
		second.CommitReady() || second.VerifyDigest() != nil ||
		second.Disposition() != OwnershipTransferCollectionReplace ||
		len(second.IdempotencyCompletionClaims()) != 0 {
		t.Fatalf("quorum collection leaked acceptance: accepted=%v audit=%v verify=%v",
			accepted, audit, second.VerifyDigest())
	}
	secondEnvelope, err := second.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if _, bindErr := planner.BindPendingAdmissionCapability(context.Background(), secondEnvelope); !errors.Is(bindErr, ErrPendingPlanInvalid) {
		t.Fatalf("collection continuation minted absent-row admission: %v", bindErr)
	}
	advance, err := planner.BindCollectionAdvanceCapability(context.Background(), secondEnvelope)
	if err != nil || advance.VerifyDigest() != nil || advance.VerifyFor(secondEnvelope) != nil {
		t.Fatalf("collection continuation capability: %v / %v / %v", err,
			advance.VerifyDigest(), advance.VerifyFor(secondEnvelope))
	}
	source := advance.Source()
	nextRevision := advance.NextRevision().Record()
	if source.Revision != 1 || source.EnvelopeDigestSHA256 != firstEnvelope.Digest() ||
		!bytes.Equal(source.CanonicalEnvelope, firstEnvelope.Bytes()) ||
		nextRevision.Revision != 2 ||
		nextRevision.PreviousEnvelopeDigestSHA256 != firstEnvelope.Digest() ||
		!bytes.Equal(nextRevision.PreviousCanonicalEnvelope, firstEnvelope.Bytes()) ||
		nextRevision.EnvelopeDigestSHA256 != secondEnvelope.Digest() ||
		!bytes.Equal(nextRevision.CanonicalEnvelope, secondEnvelope.Bytes()) ||
		nextRevision.Status != IAMPendingStatusOpen {
		t.Fatal("collection continuation did not bind the exact predecessor and next revision")
	}
	joinedExpected, joinedPresent := second.JoinedAuditSnapshot()
	if len(advance.SourceEvidence()) != len(firstAdmission.EvidenceStorageCapabilities()) ||
		len(advance.EvidenceStorageCapabilities()) <= len(advance.SourceEvidence()) ||
		len(advance.CanonicalStateReads().Assertions()) < 2 ||
		len(advance.IdempotencyAdvanceClaims()) != 1 ||
		!joinedPresent || advance.JoinedExpectedSnapshot() != joinedExpected ||
		!sameGlobalClaims(advance.IdentifierClaims(), second.IdentifierClaims()) {
		t.Fatal("collection continuation capability omitted a required storage action")
	}
	outer, outerOK := advance.OuterRecord()
	outerDigest, outerErr := outer.Digest(ccse.DefaultLimits())
	if !outerOK || outerErr != nil || outerDigest != fixture.newApproval.Digest() ||
		outerDigest != advance.OuterRecordDigest() || advance.VerifyOuter(fixture.newApproval) != nil ||
		advance.VerifyOuter(fixture.oldApproval) == nil {
		t.Fatal("collection continuation did not bind the exact newly ingested approval")
	}
	outer.Signature[0] ^= 0xff
	returnedAgain, _ := advance.OuterRecord()
	if returnedDigest, digestErr := returnedAgain.Digest(ccse.DefaultLimits()); digestErr != nil || returnedDigest != fixture.newApproval.Digest() {
		t.Fatal("collection continuation outer getter aliases internal state")
	}
	forgedOuter := advance
	forgedOuter.outerRecord = cloneCCSERecord(advance.outerRecord)
	forgedOuter.outerRecord.Signature[0] ^= 1
	if forgedDigest, digestErr := digestIAMCollectionAdvanceCapability(forgedOuter); digestErr == nil && forgedDigest == advance.Digest() {
		t.Fatal("collection continuation capability digest omitted the exact outer signature")
	}
	source.CanonicalEnvelope[0] ^= 0xff
	if advance.VerifyFor(secondEnvelope) != nil {
		t.Fatal("collection continuation source getter aliases internal state")
	}
	for _, action := range advance.EvidenceStorageCapabilities() {
		_, _, linked := action.PendingLink()
		if linked && action.Disposition() != IAMEvidenceStorageAssertExisting {
			t.Fatal("source evidence was not frozen as an exact linked assertion")
		}
	}
	actions := advance.EvidenceStorageCapabilities()
	actions[0].evidence.record.CanonicalContent[0] ^= 0xff
	if advance.VerifyFor(secondEnvelope) != nil {
		t.Fatal("collection continuation evidence getter aliases internal state")
	}
	forgedIncomplete := advance
	forgedIncomplete.state = cloneIAMPendingAdmissionStateCapability(advance.state)
	forgedIncomplete.state.assertions = forgedIncomplete.state.assertions[1:]
	forgedIncomplete.state.digest, _ = digestIAMPendingAdmissionState(
		forgedIncomplete.state.assertions, forgedIncomplete.state.absences,
		forgedIncomplete.state.auditEventID, forgedIncomplete.state.coverageDigest)
	forgedIncomplete.digest, _ = digestIAMCollectionAdvanceCapability(forgedIncomplete)
	if forgedIncomplete.VerifyDigest() != nil || forgedIncomplete.VerifyFor(secondEnvelope) == nil {
		t.Fatal("self-consistent incomplete collection continuation state accepted")
	}
	stored := fixture.view.pendingPersistence[source.PendingKey]
	mutated := stored
	mutated.revision = cloneIAMPendingStoredRevision(stored.revision)
	mutated.revision.CommitNotAfterUnixNano--
	fixture.view.pendingPersistence[source.PendingKey] = mutated
	if _, bindErr := planner.BindCollectionAdvanceCapability(context.Background(), secondEnvelope); !errors.Is(bindErr, ErrViewInconsistent) {
		t.Fatalf("collection continuation accepted source window drift: %v", bindErr)
	}
	fixture.view.pendingPersistence[source.PendingKey] = stored
	mutated = stored
	mutated.evidence = append([]IAMPersistenceEvidenceRecord(nil), stored.evidence...)
	mutated.evidence[0] = cloneIAMPersistenceEvidenceRecord(mutated.evidence[0])
	mutated.evidence[0].CanonicalContent[0] ^= 0xff
	fixture.view.pendingPersistence[source.PendingKey] = mutated
	if _, bindErr := planner.BindCollectionAdvanceCapability(context.Background(), secondEnvelope); !errors.Is(bindErr, ErrViewInconsistent) {
		t.Fatalf("collection continuation accepted source evidence drift: %v", bindErr)
	}
	fixture.view.pendingPersistence[source.PendingKey] = stored
	mutated = stored
	mutated.revision = cloneIAMPendingStoredRevision(stored.revision)
	mutated.evidence = append([]IAMPersistenceEvidenceRecord(nil), stored.evidence...)
	extraContent := []byte("unrelated-but-self-consistent-evidence")
	extraDigest := sha256.Sum256(extraContent)
	mutated.evidence = append(mutated.evidence, IAMPersistenceEvidenceRecord{
		DigestSHA256: extraDigest, Kind: IAMEvidenceContentSHA256,
		ContentType: "application/octet-stream", CanonicalContent: extraContent,
		ExpectedAuditEventID: advance.AuditEventID(),
	})
	mutated.revision.EvidenceDigestsSHA256 = append(
		mutated.revision.EvidenceDigestsSHA256, extraDigest)
	sort.Slice(mutated.revision.EvidenceDigestsSHA256, func(i, j int) bool {
		return bytes.Compare(mutated.revision.EvidenceDigestsSHA256[i][:],
			mutated.revision.EvidenceDigestsSHA256[j][:]) < 0
	})
	fixture.view.pendingPersistence[source.PendingKey] = mutated
	if _, bindErr := planner.BindCollectionAdvanceCapability(context.Background(), secondEnvelope); !errors.Is(bindErr, ErrViewInconsistent) {
		t.Fatalf("collection continuation accepted unrelated source evidence: %v", bindErr)
	}
	fixture.view.pendingPersistence[source.PendingKey] = stored
	assertDurableEnvelopeRoundTrip(t, secondEnvelope)
	if _, err := second.JoinedAuditRequest(); !errors.Is(err, ErrPendingPlanInvalid) {
		t.Fatalf("quorum vote exposed acceptance joined request: %v", err)
	}
	if !hasIdentifierClaim(second.IdentifierClaims(), fixture.projection.NewKeyID, globalid.AssertExisting) ||
		!hasIdentifierClaim(second.IdentifierClaims(), "agent-transfer-old-key-revoked", globalid.AssertExisting) {
		t.Fatal("continuation did not assert admission tombstones")
	}
}

func TestOwnershipTransferCollectionCanReconcileAfterDeadline(t *testing.T) {
	fixture := newTransferCollectionFixture(t)
	planner := testPlanner(t, fixture.view, fixture.profile)
	plan, err := planner.PlanOwnershipTransferApproval(context.Background(),
		fixture.command(fixture.oldApproval, 0))
	if err != nil {
		t.Fatal(err)
	}
	applyTransferCollectionPlan(t, fixture.view, plan)
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDurablePendingEnvelope(envelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// Terminal recovery resolves the exact retained decision under its frozen
	// activation. A later live policy change must not reinterpret or strand it.
	fixture.profile.transferCurrentErr = errors.New("live evidence policy replaced")
	reconciliation, err := planner.PlanReconciliationFromDecoded(context.Background(), decoded,
		PendingReconciliationCommand{Disposition: PendingDispositionExpired,
			EvaluatedAtUnixNano: plan.CommitNotAfterUnixNano(),
			Evidence: reconciliationEvidence(t, PendingDispositionExpired, plan.CommitNotAfterUnixNano(),
				plan.CommitNotAfterUnixNano(), plan.Digest(), 0xdd)})
	if err != nil {
		t.Fatalf("collection reconciliation = %v", err)
	}
	request, err := reconciliation.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	fragment, ok := request.ExecutionFragment()
	if !ok || reconciliation.VerifyDigest() != nil || request.VerifyDigest() != nil ||
		fragment.VerifyDigest() != nil || len(fragment.Mutations()) != 0 ||
		len(fragment.IdempotencyCompletionClaims()) != 2 ||
		len(fragment.CompoundMemberCompletionClaims()) != 0 ||
		len(fragment.IdentifierAssertions()) == 0 {
		t.Fatalf("invalid collection reconciliation: plan=%v request=%v fragment=%v",
			reconciliation.VerifyDigest(), request.VerifyDigest(), fragment.VerifyDigest())
	}
	if _, err := planner.PlanReconciliationFromDecoded(context.Background(), decoded,
		PendingReconciliationCommand{Disposition: PendingDispositionFailed,
			EvaluatedAtUnixNano: plan.CommitNotAfterUnixNano() - 1,
			Evidence: reconciliationEvidence(t, PendingDispositionExpired, plan.CommitNotAfterUnixNano(),
				plan.CommitNotAfterUnixNano(), plan.Digest(), 0xde)}); !errors.Is(err, ErrInvalidCommitWindow) {
		t.Fatalf("pre-deadline collection failure accepted: %v", err)
	}
}

func TestOwnershipTransferQuorumRejectsAuthorityRevokedAfterVote(t *testing.T) {
	fixture := newTransferCollectionFixture(t)
	planner := testPlanner(t, fixture.view, fixture.profile)
	first, err := planner.PlanOwnershipTransferApproval(context.Background(), fixture.command(fixture.oldApproval, 0))
	if err != nil {
		t.Fatal(err)
	}
	applyTransferCollectionPlan(t, fixture.view, first)
	revokedProjection := lifecycleProjection(fixture.oldAuthority, 4, 2, 8)
	revokedProjection.Metadata.RecordID = "old-transfer-authority-revoked"
	revokedProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeOwnershipTransferAuthorization}
	revokedProjection.AuthorizationPolicyDigestSHA256 = fixture.profile.transferProfile.OldAuthorities[0].AuthorizationPolicyDigestSHA256
	revokedProjection.RevokedAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testNow}
	revokedProjection.TransitionReasonCode = foundationv1.OptionalString{Present: true, Value: "revoked-before-quorum"}
	revoked, err := NormalizeKeyLifecycle(revokedProjection)
	if err != nil {
		t.Fatal(err)
	}
	fixture.view.lifecycles[fixture.oldAuthority.KeyID] = revoked
	if _, err := planner.PlanOwnershipTransferApproval(context.Background(), fixture.command(fixture.newApproval, 1)); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("revoked old authority completed quorum: %v", err)
	}
}

func TestOwnershipTransferInitialFenceMatchesSignedMetadata(t *testing.T) {
	fixture := newTransferCollectionFixture(t)
	command := fixture.command(fixture.oldApproval, 0)
	command.Fence.HomeRegion = "eu-west-1"
	command.Fence.WriterEpoch++
	fixture.view.leases[command.Fence.Entity] = WriterLeaseSnapshot{Entity: command.Fence.Entity,
		WriterIdentity: command.Fence.WriterIdentity, HomeRegion: command.Fence.HomeRegion,
		WriterEpoch: command.Fence.WriterEpoch, ValidFromUnixNano: testNow - 1,
		ValidUntilUnixNano: testNow + 1_000_000_000, EvidenceDigest: command.Fence.EvidenceDigest}
	if _, err := testPlanner(t, fixture.view, fixture.profile).PlanOwnershipTransferApproval(context.Background(), command); !errors.Is(err, ErrWriterFenceMismatch) {
		t.Fatalf("unsigned initial writer metadata accepted: %v", err)
	}
}

func TestOwnershipTransferEvidenceRecordOwnerIsExact(t *testing.T) {
	fixture := newTransferCollectionFixture(t)
	recordID := "transfer-evidence-record-" + string(rune('a'+foundationv1.TransferEvidenceOldProviderAuthority))
	fixture.view.globalIDs[recordID] = globalid.Snapshot{Identifier: recordID,
		Owner: globalid.Owner{Domain: globalid.OwnerIAMIdentity, ID: fixture.projection.PreviousEntityID}, Version: 1}
	if _, err := testPlanner(t, fixture.view, fixture.profile).PlanOwnershipTransferApproval(
		context.Background(), fixture.command(fixture.oldApproval, 0)); !errors.Is(err, ErrGlobalIdentifier) {
		t.Fatalf("evidence RecordID with unrelated owner accepted: %v", err)
	}
}

func TestOwnershipTransferRejectsNonPreviousEntityReplayScopes(t *testing.T) {
	for name, replayEntity := range map[string]EntityRef{
		"transfer-authorization-id": {Kind: EntityOwnershipTransfer, PrincipalKind: 2, ID: "agent-transfer-authorization"},
		"next-entity":               {Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-transfer-new"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newTransferCollectionFixture(t)
			wrong := verifiedFoundationRecord(t, fixture.oldAuthority, 0xc2,
				schema.MessageTypeOwnershipTransferAuthorization, fixture.payload, replayEntity, 1,
				id16(0xa7), fixture.oldApproval.Envelope().CorrelationID, "org-old", nil)
			if _, err := testPlanner(t, fixture.view, fixture.profile).PlanOwnershipTransferApproval(
				context.Background(), fixture.command(wrong, 0)); !errors.Is(err, ErrAuthorizationMismatch) {
				t.Fatalf("wrong transfer replay scope accepted: %v", err)
			}
		})
	}
}

func hasIdentifierClaim(claims []globalid.Claim, identifier string, mode globalid.ClaimMode) bool {
	for _, claim := range claims {
		if claim.Identifier == identifier && claim.Mode == mode {
			return true
		}
	}
	return false
}
