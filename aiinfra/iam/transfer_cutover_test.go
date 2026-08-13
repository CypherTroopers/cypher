// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func authenticatedCutoverEvidence(t testing.TB, view *memoryView,
	authorization VerifiedAuthorization) ccse.AuthenticatedEvidenceRecord {
	t.Helper()
	record := authorization.sourceRecord
	material := view.materials[record.Envelope.SignatureKeyID]
	keys := ccse.NewMemoryKeyRegistry()
	if err := keys.Add(ccse.KeyRecord{KeyID: material.KeyID,
		SubjectIdentity: material.SubjectIdentity, Algorithm: material.Algorithm,
		PublicKey:         append([]byte(nil), material.CanonicalPublicKey...),
		NotBeforeUnixNano: testNotBefore, NotAfterUnixNano: testNotAfter,
		AllowedMessageTypes: []uint32{record.MessageTypeID}}); err != nil {
		t.Fatal(err)
	}
	validator, err := foundationCanonicalValidator()
	if err != nil {
		t.Fatal(err)
	}
	authenticator := ccse.EvidenceAuthenticator{Expectations: ccse.Expectations{
		MessageTypeID: record.MessageTypeID, SchemaVersion: record.SchemaVersion,
		ProtocolVersion: record.Domain.ProtocolVersion, Purpose: record.Domain.Purpose,
		SenderIdentity:       ccse.OptionalString{Present: true, Value: record.Domain.SenderIdentity},
		Audience:             append([]string(nil), record.Domain.Audience...),
		TenantOrganization:   record.Domain.TenantOrganization,
		ProviderOrganization: record.Domain.ProviderOrganization,
		Environment:          record.Domain.Environment, ChainID: record.Domain.ChainID,
		GenesisHash: record.Domain.GenesisHash, ReplayDomainID: record.Domain.ReplayDomainID,
		CounterKind: record.Domain.CounterKind, MaxClockSkew: time.Millisecond,
		MaxValidityWindow: time.Second,
	}, Limits: ccse.DefaultLimits(), Clock: ccse.ClockFunc(func() time.Time {
		return time.Unix(0, testNow)
	}), Keys: keys, Schema: validator}
	evidence, err := authenticator.Authenticate(context.Background(), &record)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func installCutoverAgentParents(t testing.TB, view *memoryView, providerID, hostID,
	keyID string, generation uint64, seed byte) {
	t.Helper()
	providerProjection := foundationv1.ProviderIdentitySigningProjection{
		Metadata: metadata(1, 7, seed), ProviderID: providerID,
		OrganizationIdentity: "spiffe://cph.example/" + providerID,
		PayoutIdentity:       "cph:" + providerID, Jurisdictions: []string{"DE"},
		PolicyDigestsSHA256: [][32]byte{digest(seed + 1)}, OwnershipGeneration: generation,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2}
	providerProjection.Metadata.RecordID = providerID + "-active"
	provider, err := NormalizeIdentity(providerProjection)
	if err != nil {
		t.Fatal(err)
	}
	hostProjection := foundationv1.HostIdentitySigningProjection{Metadata: metadata(1, 7, seed+2),
		HostID: hostID, ProviderID: providerID, ProviderSiteID: hostID + "-site",
		AttestationIdentity: "urn:tpm:" + hostID, KeyID: keyID,
		OwnershipGeneration: generation, ValidFromUnixNano: testNotBefore,
		ValidUntilUnixNano: testNotAfter, State: 2}
	hostProjection.Metadata.RecordID = hostID + "-active"
	host, err := NormalizeIdentity(hostProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.identities[provider.Ref] = provider
	view.identities[host.Ref] = host
}

func acceptedTransferFixture(t testing.TB) (transferCollectionFixture,
	OwnershipTransferApprovalCollectionPlan, AcceptedOwnershipTransferSnapshot) {
	t.Helper()
	fixture := newTransferCollectionFixture(t)
	return acceptedTransferFromFixture(t, fixture)
}

func acceptedTransferFromFixture(t testing.TB, fixture transferCollectionFixture) (transferCollectionFixture,
	OwnershipTransferApprovalCollectionPlan, AcceptedOwnershipTransferSnapshot) {
	t.Helper()
	planner := testPlanner(t, fixture.view, fixture.profile)
	first, err := planner.PlanOwnershipTransferApproval(context.Background(),
		fixture.command(fixture.oldApproval, 0))
	if err != nil {
		t.Fatal(err)
	}
	applyTransferCollectionPlan(t, fixture.view, first)
	second, err := planner.PlanOwnershipTransferApproval(context.Background(),
		fixture.command(fixture.newApproval, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReadyForAcceptance() {
		t.Fatal("quorum collection not ready for acceptance")
	}
	applyTransferCollectionPlan(t, fixture.view, second)
	return fixture, second, acceptedTransferCandidateFromPlan(t, second)
}

func acceptedTransferCandidateFromPlan(t testing.TB,
	second OwnershipTransferApprovalCollectionPlan) AcceptedOwnershipTransferSnapshot {
	t.Helper()
	collection := second.NextCollection()
	projection, canonical, transferDigest, err := normalizeOwnershipTransferPayload(collection.CanonicalPayload)
	if err != nil {
		t.Fatal(err)
	}
	candidate := AcceptedOwnershipTransferSnapshot{Projection: projection, CanonicalPayload: canonical,
		TransferEvidenceDigest: transferDigest, Profile: collection.Profile,
		ProfileDigest: collection.ProfileDigest, Approvals: collection.Approvals,
		FixedEvidence: collection.FixedEvidence, AcceptedAtUnixNano: testNow,
		StateVersion: collection.Version, WriterEpoch: collection.WriterEpoch}
	candidate.SnapshotDigest, err = acceptedTransferDigest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func cutoverCommandFixture(t testing.TB, fixture transferCollectionFixture,
	accepted AcceptedOwnershipTransferSnapshot) OwnershipTransferCutoverCommand {
	t.Helper()
	transferDigest := accepted.TransferEvidenceDigest
	previous := accepted.FixedEvidence.PreviousTerminalIdentity
	next := accepted.FixedEvidence.NextPendingIdentity
	previousProjection, err := decodeIdentitySnapshotProjection(previous)
	if err != nil {
		t.Fatal(err)
	}
	nextProjection, err := decodeIdentitySnapshotProjection(next)
	if err != nil {
		t.Fatal(err)
	}
	previousAuth := verifiedAuthorization(t, fixture.view, schema.MessageTypeAgentIdentity,
		previous.CanonicalPayload, previous.Ref, fixture.previous.StateVersion, id16(0x31))
	nextAuth := verifiedAuthorization(t, fixture.view, schema.MessageTypeAgentIdentity,
		next.CanonicalPayload, next.Ref, 0, id16(0x32))

	newMaterial := materialSnapshotForTargetAndTransfer(t, 0xc7,
		accepted.Projection.NextPrincipalIdentity, next.Ref, transferDigest)
	installCutoverAgentParents(t, fixture.view, accepted.Projection.PreviousProviderID,
		"host-old", fixture.view.lifecycles[accepted.FixedEvidence.KeyClosureSnapshots[0].KeyID].KeyID,
		accepted.Projection.ExpectedGeneration, 0x51)
	installCutoverAgentParents(t, fixture.view, accepted.Projection.NextProviderID,
		"host-new", newMaterial.KeyID, accepted.Projection.NextGeneration, 0x55)
	lifecycleProjection := lifecycleProjection(newMaterial, 1, 1, newMaterial.WriterEpoch)
	lifecycleProjection.Metadata.RecordID = "agent-transfer-new-key-preactive"
	lifecycleProjection.Metadata.IdempotencyKey = newMaterial.IdempotencyKey
	lifecycleProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeAgentIdentity}
	lifecycle, err := NormalizeKeyLifecycle(lifecycleProjection)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleAuth := verifiedAuthorization(t, fixture.view, schema.MessageTypeKeyLifecycle,
		lifecycle.CanonicalPayload,
		EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind, ID: lifecycle.KeyID},
		0, id16(0x33))
	// All three new commands use the same service writer. Reinstall its current
	// lifecycle with the union of message types after the fixture helpers have
	// generated their independently scoped signed records.
	writer := installAuthorizationKey(t, fixture.view,
		schema.MessageTypeAgentIdentity, schema.MessageTypeKeyLifecycle)

	closureFences := make([]WriterFence, 0, len(accepted.FixedEvidence.KeyClosureSnapshots))
	for index, closure := range accepted.FixedEvidence.KeyClosureSnapshots {
		var closureRecord ccse.Record
		for _, retained := range accepted.FixedEvidence.KeyClosureRecords {
			candidate := retained.Record()
			if sha256.Sum256(candidate.Payload) == sha256.Sum256(closure.CanonicalPayload) {
				closureRecord = candidate
				break
			}
		}
		closureAuth, closureErr := authorizationFromSignedRecord(closureRecord)
		if closureErr != nil {
			t.Fatal(closureErr)
		}
		closureEntity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: closure.SubjectKind,
			ID: closure.KeyID}
		fixture.view.leases[closureEntity] = lease(closureEntity,
			closureAuth.senderIdentity, closure.WriterEpoch, byte(0x41+index%128))
		closureFences = append(closureFences, WriterFence{Entity: closureEntity,
			WriterIdentity: closureAuth.senderIdentity, HomeRegion: closure.HomeRegion,
			WriterEpoch: closure.WriterEpoch, ExpectedStateVersion: closure.StateVersion - 1,
			EvidenceDigest: fixture.view.leases[closureEntity].EvidenceDigest})
	}
	fixture.view.leases[previous.Ref] = lease(previous.Ref,
		previousAuth.senderIdentity, previous.WriterEpoch, 0x42)
	materialEntity := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: newMaterial.SubjectKind,
		ID: newMaterial.KeyID}
	lifecycleEntity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: lifecycle.SubjectKind,
		ID: lifecycle.KeyID}
	fixture.view.leases[materialEntity] = lease(materialEntity,
		newMaterial.WriterIdentity, newMaterial.WriterEpoch, 0x43)
	fixture.view.leases[lifecycleEntity] = lease(lifecycleEntity,
		lifecycleAuth.senderIdentity, lifecycle.WriterEpoch, 0x44)
	fixture.view.leases[next.Ref] = lease(next.Ref, nextAuth.senderIdentity, next.WriterEpoch, 0x45)
	fixture.view.challenges[newMaterial.ProofChallenge] = ProofChallengeSnapshot{
		Challenge: newMaterial.ProofChallenge, SubjectIdentity: newMaterial.SubjectIdentity,
		SubjectKind: newMaterial.SubjectKind, TargetIdentity: newMaterial.TargetIdentity,
		TransferEvidenceDigest: transferDigest, Domain: newMaterial.EnrollmentDomain,
		ExpiresAtUnixNano: newMaterial.ProofExpiresAtUnixNano, Consumed: false,
		IssuerIdentity:      newMaterial.EnrollmentAuthorityIdentity,
		PolicyDigestsSHA256: newMaterial.EnrollmentPolicyDigestsSHA256,
		EvidenceDigest:      newMaterial.ChallengeEvidenceDigest}

	command := OwnershipTransferCutoverCommand{TransferEvidenceDigest: transferDigest,
		EvaluatedAtUnixNano:    testNow,
		KeyClosureWriterFences: closureFences,
		PreviousTerminalIdentity: IdentityCommand{Projection: previousProjection,
			ActorIdentity: previousAuth.senderIdentity, EvaluatedAtUnixNano: testNow,
			CorrelationID: previousAuth.correlationID, CausationID: previousAuth.causationID,
			CauseCode: "ownership-transfer-cutover", Authorization: previousAuth,
			TransferEvidenceDigest: transferDigest,
			Fence: WriterFence{Entity: previous.Ref, WriterIdentity: previousAuth.senderIdentity,
				HomeRegion: previous.HomeRegion, WriterEpoch: previous.WriterEpoch,
				ExpectedStateVersion: previous.StateVersion - 1,
				EvidenceDigest:       fixture.view.leases[previous.Ref].EvidenceDigest}},
		NewKeyEnrollment: KeyEnrollmentCommand{Material: KeyMaterialCommand{
			Algorithm: newMaterial.Algorithm, CanonicalPublicKey: newMaterial.CanonicalPublicKey,
			ClaimedKeyID: newMaterial.KeyID, SubjectIdentity: newMaterial.SubjectIdentity,
			SubjectKind: newMaterial.SubjectKind, TargetIdentity: newMaterial.TargetIdentity,
			TransferEvidenceDigest: transferDigest, EnrollmentDomain: newMaterial.EnrollmentDomain,
			Challenge:                         newMaterial.ProofChallenge,
			ChallengeExpiresAtUnixNano:        newMaterial.ProofExpiresAtUnixNano,
			ProofSignature:                    newMaterial.ProofSignature,
			EnrollmentAuthorityIdentity:       newMaterial.EnrollmentAuthorityIdentity,
			EnrollmentAuthorityEvidenceDigest: newMaterial.ChallengeEvidenceDigest,
			EnrollmentPolicyDigestsSHA256:     newMaterial.EnrollmentPolicyDigestsSHA256,
			EvaluatedAtUnixNano:               testNow, CorrelationID: lifecycleAuth.correlationID,
			IdempotencyKey: newMaterial.IdempotencyKey, CauseCode: "ownership-transfer-cutover",
			Fence: WriterFence{Entity: materialEntity, WriterIdentity: newMaterial.WriterIdentity,
				HomeRegion: newMaterial.HomeRegion, WriterEpoch: newMaterial.WriterEpoch,
				ExpectedStateVersion: 0,
				EvidenceDigest:       fixture.view.leases[materialEntity].EvidenceDigest}},
			Lifecycle: KeyLifecycleCommand{Projection: lifecycleProjection,
				ActorIdentity: lifecycleAuth.senderIdentity, EvaluatedAtUnixNano: testNow,
				CorrelationID: lifecycleAuth.correlationID, CausationID: lifecycleAuth.causationID,
				CauseCode: "ownership-transfer-cutover", Authorization: lifecycleAuth,
				TransferEvidenceDigest: transferDigest,
				Fence: WriterFence{Entity: lifecycleEntity, WriterIdentity: lifecycleAuth.senderIdentity,
					HomeRegion: lifecycle.HomeRegion, WriterEpoch: lifecycle.WriterEpoch,
					ExpectedStateVersion: 0,
					EvidenceDigest:       fixture.view.leases[lifecycleEntity].EvidenceDigest}}},
		NextPendingIdentity: IdentityCommand{Projection: nextProjection,
			ActorIdentity: nextAuth.senderIdentity, EvaluatedAtUnixNano: testNow,
			CorrelationID: nextAuth.correlationID, CausationID: nextAuth.causationID,
			CauseCode: "ownership-transfer-cutover", Authorization: nextAuth,
			TransferEvidenceDigest: transferDigest,
			Fence: WriterFence{Entity: next.Ref, WriterIdentity: nextAuth.senderIdentity,
				HomeRegion: next.HomeRegion, WriterEpoch: next.WriterEpoch,
				ExpectedStateVersion: 0,
				EvidenceDigest:       fixture.view.leases[next.Ref].EvidenceDigest}}}
	_ = writer

	for _, authorization := range []VerifiedAuthorization{previousAuth, lifecycleAuth, nextAuth} {
		command.AuthenticatedEvidence = append(command.AuthenticatedEvidence,
			authenticatedCutoverEvidence(t, fixture.view, authorization))
	}
	return command
}

func TestOwnershipTransferCutoverIsOneAtomicDurablePlan(t *testing.T) {
	fixture, quorum, candidate := acceptedTransferFixture(t)
	command := cutoverCommandFixture(t, fixture, candidate)
	collection := quorum.NextCollection()
	fence := fixture.command(fixture.newApproval, 1).Fence
	fence.ExpectedStateVersion = collection.Version
	acceptance, err := testPlanner(t, fixture.view, fixture.profile).
		PlanOwnershipTransferAcceptance(context.Background(), OwnershipTransferAcceptanceCommand{
			CollectionKey: collection.Binding.Key, Cutover: command,
			EvaluatedAtUnixNano: testNow, Fence: fence})
	if err != nil {
		t.Fatal(err)
	}
	plan := clonePendingOwnershipTransferCutoverPlan(acceptance.cutover)
	if acceptance.VerifyDigest() != nil || acceptance.CommitReady() ||
		acceptance.AcceptedTransfer().SnapshotDigest != plan.AcceptedTransfer().SnapshotDigest ||
		acceptance.CutoverDigest() != plan.Digest() {
		t.Fatal("acceptance/cutover compound mismatch")
	}
	if plan.CommitReady() || plan.VerifyDigest() != nil || len(plan.Steps()) != 5 ||
		len(plan.EvidenceRecords()) != 3 || len(plan.CompoundMemberAdmissionClaims()) != 4 ||
		len(plan.CompoundMemberCompletionClaims()) != 4 || len(plan.IdempotencyCompletionClaims()) != 2 {
		t.Fatalf("invalid cutover plan: verify=%v steps=%d evidence=%d members=%d",
			plan.VerifyDigest(), len(plan.Steps()), len(plan.EvidenceRecords()),
			len(plan.CompoundMemberAdmissionClaims()))
	}
	if _, err := plan.DurableEnvelope(); !errors.Is(err, ErrTransferAuthorizationRequired) {
		t.Fatalf("nested cutover must not expose standalone admission: %v", err)
	}
	if _, err := testPlanner(t, fixture.view, fixture.profile).
		PlanOwnershipTransferCutover(context.Background(), command); !errors.Is(err, ErrTransferAuthorizationRequired) {
		t.Fatalf("public cutover admission must fail closed: %v", err)
	}
	envelope, err := acceptance.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	assertDurableEnvelopeRoundTrip(t, envelope)
	acceptanceEnvelope, err := acceptance.DurableEnvelope()
	if err != nil {
		t.Fatalf("maximum acceptance durable envelope: %v", err)
	}
	request, err := acceptanceEnvelope.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	collectionEnvelope, err := quorum.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	seedPendingPersistenceFromEnvelope(t, fixture.view, request,
		DurablePendingOwnershipTransferCollection, collectionEnvelope, acceptance.cutover.AuditIntent())
	planner := testPlanner(t, fixture.view, fixture.profile)
	request, err = planner.BindPendingPersistenceCapability(context.Background(), request)
	if err != nil {
		t.Fatalf("acceptance pending persistence bind: %v", err)
	}
	persistence, ok := request.PendingPersistenceCapability()
	if !ok || persistence.VerifyFor(request) != nil {
		t.Fatal("acceptance pending persistence capability missing")
	}
	template, err := persistence.SuccessTerminalTemplate(request)
	if err != nil || template.VerifyFor(request) != nil {
		t.Fatalf("acceptance terminal template: %v", err)
	}
	acceptanceOutcome := digest(0xb7)
	pendingRevisions, err := template.Finalize(request, acceptanceOutcome)
	if err != nil || len(pendingRevisions) != 2 || pendingRevisions[0].VerifyDigest() != nil ||
		pendingRevisions[1].VerifyDigest() != nil {
		t.Fatalf("acceptance terminal/create revisions: %#v / %v", pendingRevisions, err)
	}
	closedCollection, childCutover := pendingRevisions[0].Record(), pendingRevisions[1].Record()
	if closedCollection.ExpectedKind != DurablePendingOwnershipTransferCollection ||
		closedCollection.Kind != DurablePendingOwnershipTransferCollection ||
		closedCollection.TerminalOutcomeDigestSHA256 != acceptanceOutcome ||
		childCutover.ExpectedKind != 0 || childCutover.Kind != DurablePendingOwnershipTransferCutover ||
		childCutover.Revision != 1 || childCutover.Status != IAMPendingStatusOpen ||
		!bytes.Equal(childCutover.CanonicalEnvelope, request.execution.PendingEnvelopeBytes()) {
		t.Fatalf("acceptance persistence sequence mismatch: close=%#v child=%#v",
			closedCollection, childCutover)
	}
	fragment, ok := request.ExecutionFragment()
	if !ok || request.VerifyDigest() != nil || fragment.VerifyDigest() != nil ||
		len(fragment.IdempotencyAdmissionClaims()) != 2 ||
		len(fragment.CompoundMemberAdmissionClaims()) != 4 ||
		len(fragment.IdentifierReservations()) == 0 || len(fragment.PendingEnvelopeBytes()) == 0 {
		t.Fatalf("invalid acceptance execution bridge: request=%v fragment=%v",
			request.VerifyDigest(), fragment.VerifyDigest())
	}

	// Apply only the acceptance transaction's staged state. The business
	// mutations remain unapplied; a restart must recover the nested cutover
	// capability from its inert durable bytes and these exact reservations.
	accepted := acceptance.AcceptedTransfer()
	fixture.view.acceptedTransfers[accepted.TransferEvidenceDigest] = accepted
	for _, claim := range fragment.IdempotencyAdmissionClaims() {
		fixture.view.idempotency[claim.Binding.Key] = idempotency.Snapshot{
			Binding: claim.Binding, State: claim.NextState, Version: claim.NextVersion,
			ProgressDigest: claim.NextProgressDigest}
	}
	childEvidence := make([]IAMPersistenceEvidenceRecord, len(persistence.Evidence()))
	for index, evidence := range persistence.Evidence() {
		childEvidence[index] = evidence.Record()
	}
	fixture.view.pendingPersistence[childCutover.PendingKey] = memoryPendingPersistence{
		revision: IAMPendingStoredRevision{PendingKey: childCutover.PendingKey,
			Kind: childCutover.Kind, Codec: childCutover.Codec, CodecVersion: childCutover.CodecVersion,
			Revision: childCutover.Revision, EnvelopeDigestSHA256: childCutover.EnvelopeDigestSHA256,
			CanonicalEnvelope:     childCutover.CanonicalEnvelope,
			EvidenceDigestsSHA256: childCutover.EvidenceDigestsSHA256, Status: childCutover.Status,
			CommitNotBeforeUnixNano: childCutover.CommitNotBeforeUnixNano,
			CommitNotAfterUnixNano:  childCutover.CommitNotAfterUnixNano,
			ExpectedAuditEventID:    childCutover.ExpectedAuditEventID}, evidence: childEvidence}
	for _, claim := range fragment.CompoundMemberAdmissionClaims() {
		fixture.view.compoundMembers[claim.Binding.Key] = idempotency.CompoundMemberSnapshot{
			Binding: claim.Binding, ParentBinding: claim.ParentBinding,
			State: claim.NextState, Version: claim.NextVersion, ProgressDigest: claim.ProgressDigest}
	}
	applyGlobalClaims(t, fixture.view, fragment.IdentifierReservations())
	decodedCutover, err := DecodeDurablePendingEnvelope(fragment.PendingEnvelopeBytes())
	if err != nil {
		t.Fatal(err)
	}
	revalidated, err := testPlanner(t, fixture.view, fixture.profile).RevalidateDurablePending(
		context.Background(), decodedCutover, testNow+1)
	if err != nil {
		t.Fatalf("stored cutover revalidation = %v", err)
	}
	cutoverRequest, err := revalidated.JoinedAuditRequest()
	if err != nil {
		t.Fatalf("stored cutover joined request = %v", err)
	}
	cutoverRequest, err = planner.BindPendingPersistenceCapability(context.Background(), cutoverRequest)
	if err != nil {
		t.Fatalf("stored cutover persistence bind = %v", err)
	}
	cutoverPersistence, ok := cutoverRequest.PendingPersistenceCapability()
	if !ok || cutoverPersistence.VerifyFor(cutoverRequest) != nil ||
		cutoverPersistence.Source().ExpectedAuditEventID != childCutover.ExpectedAuditEventID {
		t.Fatal("stored cutover did not preserve child link and original evidence provenance")
	}
	cutoverExecution, ok := cutoverRequest.ExecutionFragment()
	if !ok || cutoverRequest.VerifyDigest() != nil || cutoverExecution.VerifyDigest() != nil ||
		len(cutoverExecution.OwnershipTransferCutoverWrites()) != 5 ||
		len(cutoverExecution.PreStateDependencies()) == 0 ||
		len(cutoverExecution.IdempotencyCompletionClaims()) != 2 ||
		len(cutoverExecution.CompoundMemberCompletionClaims()) != 4 ||
		len(cutoverExecution.IdentifierAssertions()) == 0 {
		t.Fatalf("invalid recovered cutover bridge: request=%v fragment=%v writes=%d members=%d",
			cutoverRequest.VerifyDigest(), cutoverExecution.VerifyDigest(),
			len(cutoverExecution.OwnershipTransferCutoverWrites()),
			len(cutoverExecution.CompoundMemberCompletionClaims()))
	}
	// Terminal recovery must remain reachable when the success pre-state has
	// changed. These conditions would correctly reject a successful resume, but
	// are also legitimate reasons for the admitted operation to time out.
	challenge := fixture.view.challenges[command.NewKeyEnrollment.Material.Challenge]
	challenge.Consumed = true
	fixture.view.challenges[command.NewKeyEnrollment.Material.Challenge] = challenge
	for _, step := range plan.Steps() {
		delete(fixture.view.leases, step.Mutation.CAS().Entity)
	}
	previousRef := accepted.FixedEvidence.PreviousTerminalIdentity.Ref
	delete(fixture.view.identities, previousRef)
	if _, err := testPlanner(t, fixture.view, fixture.profile).RevalidateDurablePending(
		context.Background(), decodedCutover, testNow+2); err == nil {
		t.Fatal("successful cutover resume ignored changed business/challenge/lease state")
	}
	reconciliation, err := testPlanner(t, fixture.view, fixture.profile).
		PlanReconciliationFromDecoded(context.Background(), decodedCutover,
			PendingReconciliationCommand{Disposition: PendingDispositionExpired,
				EvaluatedAtUnixNano: plan.CommitNotAfterUnixNano(),
				Evidence: reconciliationEvidence(t, PendingDispositionExpired, plan.CommitNotAfterUnixNano(),
					plan.CommitNotAfterUnixNano(), plan.Digest(), 0xee)})
	if err != nil {
		t.Fatalf("expired cutover reconciliation = %v", err)
	}
	reconciliationRequest, err := reconciliation.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	reconciliationExecution, ok := reconciliationRequest.ExecutionFragment()
	if !ok || reconciliation.VerifyDigest() != nil || reconciliationRequest.VerifyDigest() != nil ||
		reconciliationExecution.VerifyDigest() != nil || len(reconciliationExecution.Mutations()) != 0 ||
		len(reconciliationExecution.IdempotencyCompletionClaims()) != 2 ||
		len(reconciliationExecution.CompoundMemberCompletionClaims()) != 4 ||
		len(reconciliationExecution.IdentifierAssertions()) == 0 {
		t.Fatalf("invalid cutover reconciliation bridge: plan=%v request=%v fragment=%v members=%d",
			reconciliation.VerifyDigest(), reconciliationRequest.VerifyDigest(),
			reconciliationExecution.VerifyDigest(),
			len(reconciliationExecution.CompoundMemberCompletionClaims()))
	}
	if _, err := testPlanner(t, fixture.view, fixture.profile).
		PlanReconciliationFromDecoded(context.Background(), decodedCutover,
			PendingReconciliationCommand{Disposition: PendingDispositionFailed,
				EvaluatedAtUnixNano: plan.CommitNotAfterUnixNano() - 1,
				Evidence: reconciliationEvidence(t, PendingDispositionExpired, plan.CommitNotAfterUnixNano(),
					plan.CommitNotAfterUnixNano(), plan.Digest(), 0xef)}); !errors.Is(err, ErrInvalidCommitWindow) {
		t.Fatalf("pre-deadline FAILED reconciliation accepted: %v", err)
	}
}

func TestOwnershipTransfer256ClosuresDurableRehydrateJoinedExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs the maximum signed ownership-transfer closure set")
	}
	fixture := expandTransferFixtureClosures(t, newTransferCollectionFixture(t), 256)
	planner := testPlanner(t, fixture.view, fixture.profile)
	first, err := planner.PlanOwnershipTransferApproval(context.Background(),
		fixture.command(fixture.oldApproval, 0))
	if err != nil {
		t.Fatal(err)
	}
	firstEnvelope, err := first.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	firstAdmission, err := planner.BindPendingAdmissionCapability(context.Background(), firstEnvelope)
	if err != nil || firstAdmission.VerifyFor(firstEnvelope) != nil {
		t.Fatalf("maximum collection admission capability: %v", err)
	}
	seedPendingAdmissionRevision(t, fixture.view, firstAdmission)
	applyTransferCollectionPlan(t, fixture.view, first)
	quorum, err := planner.PlanOwnershipTransferApproval(context.Background(),
		fixture.command(fixture.newApproval, 1))
	if err != nil {
		t.Fatal(err)
	}
	quorumEnvelope, err := quorum.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	advance, err := planner.BindCollectionAdvanceCapability(context.Background(), quorumEnvelope)
	if err != nil || advance.VerifyFor(quorumEnvelope) != nil ||
		len(advance.SourceEvidence()) >= len(advance.EvidenceStorageCapabilities()) {
		t.Fatalf("maximum collection advance capability: %v", err)
	}
	applyTransferCollectionPlan(t, fixture.view, quorum)
	candidate := acceptedTransferCandidateFromPlan(t, quorum)
	command := cutoverCommandFixture(t, fixture, candidate)
	collection := quorum.NextCollection()
	fence := fixture.command(fixture.newApproval, 1).Fence
	fence.ExpectedStateVersion = collection.Version
	acceptanceCommand := OwnershipTransferAcceptanceCommand{CollectionKey: collection.Binding.Key,
		Cutover: command, EvaluatedAtUnixNano: testNow, Fence: fence}
	acceptance, err := planner.PlanOwnershipTransferAcceptance(context.Background(), acceptanceCommand)
	if err != nil {
		t.Fatal(err)
	}
	plan := acceptance.cutover
	if plan.VerifyDigest() != nil || len(plan.Steps()) != 260 ||
		len(plan.CompoundMemberAdmissionClaims()) != 259 ||
		len(plan.CompoundMemberCompletionClaims()) != 259 {
		t.Fatalf("maximum cutover shape: verify=%v steps=%d members=%d", plan.VerifyDigest(),
			len(plan.Steps()), len(plan.CompoundMemberAdmissionClaims()))
	}
	acceptanceEnvelope, err := acceptance.DurableEnvelope()
	if err != nil {
		t.Fatalf("maximum acceptance durable envelope: %v", err)
	}
	request, err := acceptanceEnvelope.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	assertJoinedAuditRequestTamperResistance(t, request)
	fragment, ok := request.ExecutionFragment()
	if !ok || fragment.VerifyDigest() != nil || len(fragment.CompoundMemberAdmissionClaims()) != 259 {
		t.Fatal("maximum acceptance execution fragment invalid")
	}
	reservedIdentifiers := fragment.IdentifierReservations()

	accepted := acceptance.AcceptedTransfer()
	fixture.view.acceptedTransfers[accepted.TransferEvidenceDigest] = accepted
	for _, claim := range fragment.IdempotencyAdmissionClaims() {
		fixture.view.idempotency[claim.Binding.Key] = idempotency.Snapshot{Binding: claim.Binding,
			State: claim.NextState, Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest}
	}
	for _, claim := range fragment.CompoundMemberAdmissionClaims() {
		fixture.view.compoundMembers[claim.Binding.Key] = idempotency.CompoundMemberSnapshot{
			Binding: claim.Binding, ParentBinding: claim.ParentBinding, State: claim.NextState,
			Version: claim.NextVersion, ProgressDigest: claim.ProgressDigest}
	}
	applyGlobalClaims(t, fixture.view, fragment.IdentifierReservations())
	decoded, err := DecodeDurablePendingEnvelope(fragment.PendingEnvelopeBytes())
	if err != nil {
		t.Fatal(err)
	}
	rehydrated, err := planner.RevalidateDurablePending(context.Background(), decoded, testNow+1)
	if err != nil {
		t.Fatal(err)
	}
	rehydratedRequest, err := rehydrated.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	rehydratedExecution, ok := rehydratedRequest.ExecutionFragment()
	if !ok || rehydratedRequest.VerifyDigest() != nil || rehydratedExecution.VerifyDigest() != nil ||
		len(rehydratedExecution.OwnershipTransferCutoverWrites()) != 260 ||
		len(rehydratedExecution.CompoundMemberCompletionClaims()) != 259 {
		t.Fatal("maximum durable cutover did not rehydrate to the exact joined execution")
	}
	for _, reservation := range reservedIdentifiers {
		expected, assertionErr := globalid.Assert(reservation.Identifier, globalid.Snapshot{
			Identifier: reservation.Identifier, Owner: reservation.Owner,
			Version: reservation.NextVersion}, reservation.Owner)
		if assertionErr != nil || !containsGlobalClaim(rehydratedExecution.IdentifierAssertions(), expected) {
			t.Fatalf("maximum cutover global final assertion missing for %q: %v",
				reservation.Identifier, assertionErr)
		}
	}
	rehydratedRequest, err = planner.BindCanonicalStateCapabilities(context.Background(), rehydratedRequest)
	if err != nil || rehydratedRequest.VerifyDigest() != nil {
		t.Fatalf("maximum cutover canonical state binding: %v / %v", err,
			rehydratedRequest.VerifyDigest())
	}
	rehydratedExecution, ok = rehydratedRequest.ExecutionFragment()
	stateBundle, hasState := rehydratedRequest.CanonicalStateBundle()
	if !ok || !hasState || stateBundle.VerifyDigest() != nil ||
		stateBundle.VerifyForExecution(rehydratedExecution) != nil ||
		len(stateBundle.Assertions())+len(stateBundle.Absences()) > iamCanonicalStateMaxAssertions ||
		len(stateBundle.Mutations()) > iamCanonicalStateMaxMutations ||
		len(stateBundle.Mutations()) < len(rehydratedExecution.OwnershipTransferCutoverWrites()) {
		t.Fatalf("maximum cutover canonical state bounds: reads=%d writes=%d verify=%v",
			len(stateBundle.Assertions())+len(stateBundle.Absences()), len(stateBundle.Mutations()),
			stateBundle.VerifyDigest())
	}
	bundle, ok := rehydratedRequest.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(rehydratedRequest) != nil || len(bundle.AuditSourceDigestsSHA256()) > 2 {
		t.Fatal("maximum cutover typed evidence aggregate invalid")
	}

	overflow := command
	overflow.KeyClosureWriterFences = append(append([]WriterFence(nil), command.KeyClosureWriterFences...),
		command.KeyClosureWriterFences[0])
	acceptanceCommand.Cutover = overflow
	if _, err := planner.PlanOwnershipTransferAcceptance(context.Background(), acceptanceCommand); !errors.Is(err, ErrTransferCollectionMismatch) {
		t.Fatalf("257 closure command accepted: %v", err)
	}
}
