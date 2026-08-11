// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
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
	return fixture, second, candidate
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

	closure := accepted.FixedEvidence.KeyClosureSnapshots[0]
	closureRecord := accepted.FixedEvidence.KeyClosureRecords[0].Record()
	closureAuth, err := authorizationFromSignedRecord(closureRecord)
	if err != nil {
		t.Fatal(err)
	}
	closureEntity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: closure.SubjectKind,
		ID: closure.KeyID}
	fixture.view.leases[closureEntity] = lease(closureEntity,
		closureAuth.senderIdentity, closure.WriterEpoch, 0x41)
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
		EvaluatedAtUnixNano: testNow,
		KeyClosureWriterFences: []WriterFence{{Entity: closureEntity,
			WriterIdentity: closureAuth.senderIdentity, HomeRegion: closure.HomeRegion,
			WriterEpoch: closure.WriterEpoch, ExpectedStateVersion: closure.StateVersion - 1,
			EvidenceDigest: fixture.view.leases[closureEntity].EvidenceDigest}},
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

	_ = closureAuth // Closure evidence is retained once in the accepted snapshot.
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
	request, err := acceptance.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
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
				EvaluatedAtUnixNano:   plan.CommitNotAfterUnixNano(),
				FailureEvidenceDigest: digest(0xee)})
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
				EvaluatedAtUnixNano:   plan.CommitNotAfterUnixNano() - 1,
				FailureEvidenceDigest: digest(0xef)}); !errors.Is(err, ErrInvalidCommitWindow) {
		t.Fatalf("pre-deadline FAILED reconciliation accepted: %v", err)
	}
}
