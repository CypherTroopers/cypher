// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func installIdentityOwnership(view *memoryView, identity IdentitySnapshot) {
	owner := identityGlobalOwner(identity.Ref)
	installGlobalID(view, identity.Ref.ID, owner, 1)
	if identity.PrincipalIdentity != identity.Ref.ID {
		installGlobalID(view, identity.PrincipalIdentity, owner, 1)
	}
}

func installMaterialBootstrapIDs(view *memoryView, material KeyMaterialSnapshot) {
	installGlobalID(view, material.KeyID, keyGlobalOwner(material.KeyID), 1)
	owner := identityGlobalOwner(material.TargetIdentity)
	installGlobalID(view, material.TargetIdentity.ID, owner, 1)
	if material.SubjectIdentity != material.TargetIdentity.ID {
		installGlobalID(view, material.SubjectIdentity, owner, 1)
	}
}

func applyGlobalClaims(t testing.TB, view *memoryView, claims []globalid.Claim) {
	t.Helper()
	for _, claim := range claims {
		switch claim.Mode {
		case globalid.ReserveNew, globalid.TransferExisting:
			view.globalIDs[claim.Identifier] = globalid.Snapshot{Identifier: claim.Identifier,
				Owner: claim.Owner, Version: claim.NextVersion}
		case globalid.AssertExisting:
		default:
			t.Fatalf("unknown global claim mode %d", claim.Mode)
		}
	}
}

func activeProvider(t testing.TB) IdentitySnapshot {
	return activeProviderGeneration(t, 1)
}

func activeProviderGeneration(t testing.TB, generation uint64) IdentitySnapshot {
	t.Helper()
	projection := foundationv1.ProviderIdentitySigningProjection{
		Metadata: metadata(1, 7, 0x11), ProviderID: "provider-01",
		OrganizationIdentity: "spiffe://cph.example/provider/01", PayoutIdentity: "cph:provider:01",
		Jurisdictions: []string{"DE"}, PolicyDigestsSHA256: [][32]byte{digest(0x12)},
		OwnershipGeneration: generation, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2,
	}
	projection.Metadata.RecordID = "provider-active-record"
	snapshot, err := NormalizeIdentity(projection)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func activeHost(t testing.TB, keyID string) IdentitySnapshot {
	t.Helper()
	projection := foundationv1.HostIdentitySigningProjection{
		Metadata: metadata(1, 7, 0x13), HostID: "host-01", ProviderID: "provider-01",
		ProviderSiteID: "site-01", AttestationIdentity: "urn:tpm:host:01", KeyID: keyID,
		OwnershipGeneration: 1, ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2,
	}
	projection.Metadata.RecordID = "host-active-record"
	snapshot, err := NormalizeIdentity(projection)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestPlanIdentityBootstrapBindsTargetGlobalIDsAndAuthorizationIdentity(t *testing.T) {
	view := newMemoryView()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-01"}
	material := materialSnapshotForTarget(t, 0x21, "spiffe://cph.example/agent/01", target)
	lifecycle := lifecycleSnapshot(t, material, 1, 1, 7)
	view.materials[material.KeyID] = material
	view.lifecycles[material.KeyID] = lifecycle
	installMaterialBootstrapIDs(view, material)
	provider := activeProvider(t)
	host := activeHost(t, material.KeyID)
	view.identities[provider.Ref] = provider
	view.identities[host.Ref] = host

	projection := agentProjection(material, 1, 1, 7)
	projection.Metadata.RecordID = "agent-pending-record"
	next, err := NormalizeIdentity(projection)
	if err != nil {
		t.Fatal(err)
	}
	authorization := verifiedAuthorization(t, view, schema.MessageTypeAgentIdentity,
		next.CanonicalPayload, next.Ref, 0, id16(0x31))
	view.leases[next.Ref] = lease(next.Ref, authorization.SenderIdentity(), 7, 0x32)
	command := IdentityCommand{Projection: projection, ActorIdentity: authorization.SenderIdentity(),
		EvaluatedAtUnixNano: testNow, CorrelationID: id16(0x31), CauseCode: "bootstrap",
		Fence: fence(next.Ref, authorization.SenderIdentity(), 7, 0, 0x32), Authorization: authorization}

	plan, err := testPlanner(t, view, &allowProfile{}).PlanIdentity(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CommitReady() || plan.VerifyDigest() != nil {
		t.Fatalf("pending plan readiness/digest = %v/%v", plan.CommitReady(), plan.VerifyDigest())
	}
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	assertDurableEnvelopeRoundTrip(t, envelope)
	joinedRequest, err := envelope.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	assertJoinedAuditRequestTamperResistance(t, joinedRequest)
	cas := plan.CAS()
	admission := plan.AdmissionIntent()
	if len(cas.IdempotencyClaims) != 0 || len(admission.IdempotencyReservations()) != 2 ||
		admission.IdempotencyReservations()[0].Binding.Domain != idempotency.OperationIAMIdentity ||
		len(cas.IdentifierClaims) != 4 || cas.ExpectedEntityWriterEpoch != 0 || cas.AuthorizedWriterEpoch != 7 {
		t.Fatalf("unexpected CAS: %#v", cas)
	}
	var parentBinding idempotency.Binding
	for _, claim := range admission.IdempotencyReservations() {
		if claim.Binding.Domain != idempotency.OperationJoinedAudit {
			parentBinding = claim.Binding
		}
	}
	expectedAuditEventID, err := idempotency.JoinedAuditEventID(parentBinding)
	if err != nil || plan.AuditIntent().AuditEventID() != expectedAuditEventID {
		t.Fatalf("joined AuditEvent ID = %q / %v", plan.AuditIntent().AuditEventID(), err)
	}
	eventReservation, err := joinedAuditEventReservation(parentBinding, expectedAuditEventID)
	if err != nil || !containsGlobalClaim(admission.IdentifierReservations(), eventReservation) {
		t.Fatal("joined AuditEvent global reservation missing")
	}
	eventAssertion, _ := joinedAuditEventAssertion(eventReservation)
	if !containsGlobalClaim(cas.IdentifierClaims, eventAssertion) {
		t.Fatal("joined AuditEvent final assertion missing")
	}
	if plan.AuditIntent().MessageID() != authorization.MessageID() ||
		plan.AuditIntent().IdempotencyKey() != next.IdempotencyKey ||
		plan.AuditIntent().ActorKeyID() != authorization.SignatureKeyID() ||
		plan.AuditIntent().CausationID() != directAuditCausation(authorization.MessageID()) ||
		plan.AuditIntent().SourceCausationID() != authorization.CausationID() {
		t.Fatal("audit transport/business identity binding missing")
	}
	if source, ok := plan.AuditIntent().SourceAuthorizationRecord(); !ok ||
		source.Envelope.MessageID != authorization.MessageID() ||
		plan.AuditIntent().SourceAuthorizationDigest() != authorization.RecordDigest() {
		t.Fatal("full signed source authorization is not retained")
	} else {
		source.Signature[0] ^= 1
		detached, _ := plan.AuditIntent().SourceAuthorizationRecord()
		if detached.Signature[0] == source.Signature[0] {
			t.Fatal("source authorization getter aliases retained signature")
		}
	}
	foundAuthorizationIdentity := false
	for _, dependency := range cas.Dependencies {
		if dependency.Entity == (EntityRef{Kind: EntityIdentity, PrincipalKind: 8, ID: "service-iam-writer"}) &&
			dependency.ExpectedState == 2 && dependency.ExpectedSnapshotDigest != ([32]byte{}) {
			foundAuthorizationIdentity = true
		}
	}
	if !foundAuthorizationIdentity {
		t.Fatal("authorization identity commit-time dependency missing")
	}
	wrongScope := command
	wrongScope.Authorization = command.Authorization
	wrongScope.Authorization.replayDomainID = "iam.test"
	wrongScope.Authorization.sourceRecord = cloneCCSERecord(command.Authorization.sourceRecord)
	wrongScope.Authorization.sourceRecord.Domain.ReplayDomainID = "iam.test"
	wrongScope.Authorization.recordDigest, err = wrongScope.Authorization.sourceRecord.Digest(ccse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPlanner(t, view, &allowProfile{}).PlanIdentity(context.Background(), wrongScope); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("type-wide replay scope accepted: %v", err)
	}
	wrongResolverKey := command
	wrongResolverKey.Authorization = command.Authorization
	wrongResolverKey.Authorization.sourceRecord = cloneCCSERecord(command.Authorization.sourceRecord)
	_, attackerPrivate := testKey(0xaa)
	if err := wrongResolverKey.Authorization.sourceRecord.SignEd25519(attackerPrivate, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := testPlanner(t, view, &allowProfile{}).PlanIdentity(context.Background(), wrongResolverKey); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("upstream resolver key substitution accepted: %v", err)
	}
	if _, err := plan.PlanReconciliation(PendingReconciliationCommand{Disposition: PendingDispositionExpired,
		EvaluatedAtUnixNano: plan.CommitNotAfterUnixNano() - 1, FailureEvidenceDigest: digest(0x34)}); !errors.Is(err, ErrInvalidCommitWindow) {
		t.Fatalf("early expiry reconciliation = %v", err)
	}
	reconciliation, err := plan.PlanReconciliation(PendingReconciliationCommand{
		Disposition: PendingDispositionExpired, EvaluatedAtUnixNano: plan.CommitNotAfterUnixNano(),
		FailureEvidenceDigest: digest(0x34)})
	if err != nil || reconciliation.CommitReady() || reconciliation.VerifyDigest() != nil ||
		len(reconciliation.IdempotencyCompletionClaims()) != 2 ||
		len(reconciliation.IdentifierTombstoneAssertions()) != len(admission.IdentifierReservations()) ||
		reconciliation.AuditRequirement().EventType() != "iam.pending.expired" ||
		reconciliation.AuditRequirement().AuditEventID() != expectedAuditEventID ||
		reconciliation.AuditRequirement().AuditIdempotencyKey() != plan.AuditIntent().ExpectedAuditIdempotencyKey() {
		t.Fatalf("expiry reconciliation boundary = %#v / %v", reconciliation, err)
	}
	reconciliationEnvelope, err := reconciliation.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	assertDurableEnvelopeRoundTrip(t, reconciliationEnvelope)
	reconciliationRequest, err := reconciliation.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	assertJoinedAuditRequestTamperResistance(t, reconciliationRequest)
	failureOutcome, known := reconciliationRequest.FailureOutcomeDigest()
	reconciliationExecution, hasExecution := reconciliationRequest.ExecutionFragment()
	executionOutcome, executionKnown := reconciliationExecution.FailureOutcomeDigest()
	if !known || !hasExecution || !executionKnown || failureOutcome != reconciliation.FailureOutcomeDigest() ||
		executionOutcome != failureOutcome {
		t.Fatal("reconciliation exact failure outcome is not bound through joined execution")
	}
	for _, reservation := range admission.IdempotencyReservations() {
		view.idempotency[reservation.Binding.Key] = idempotency.Snapshot{Binding: reservation.Binding,
			State: reservation.NextState, Version: reservation.NextVersion,
			ProgressDigest: reservation.NextProgressDigest}
	}
	applyGlobalClaims(t, view, admission.IdentifierReservations())
	decodedPending, err := DecodeDurablePendingEnvelope(envelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	revalidated, err := testPlanner(t, view, &allowProfile{}).RevalidateDurablePending(
		context.Background(), decodedPending, testNow)
	if err != nil || revalidated.Digest() != envelope.Digest() {
		t.Fatalf("durable pending revalidation = %v", err)
	}
	if request, err := revalidated.JoinedAuditRequest(); err != nil || request.VerifyDigest() != nil {
		t.Fatalf("revalidated joined request = %v / %v", err, request.VerifyDigest())
	}
	_, err = testPlanner(t, view, &allowProfile{}).PlanIdentity(context.Background(), command)
	var collecting IdempotencyCollectingError
	if !errors.As(err, &collecting) || collecting.ParentSnapshot().State != idempotency.StateCollecting ||
		collecting.AuditSnapshot().State != idempotency.StateCollecting ||
		collecting.AuditEventID() != expectedAuditEventID {
		t.Fatalf("durable pending reload signal = %v", err)
	}
	badCommand := command
	badCommand.Authorization.payload = append([]byte(nil), command.Authorization.payload...)
	badCommand.Authorization.payload[0] ^= 1
	_, err = testPlanner(t, view, &allowProfile{}).PlanIdentity(context.Background(), badCommand)
	if !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("invalid authorization probed collecting outcome: %v", err)
	}
	replannedReconciliation, err := testPlanner(t, view, &allowProfile{}).
		PlanReconciliationFromDecoded(context.Background(), decodedPending,
			PendingReconciliationCommand{Disposition: PendingDispositionExpired,
				EvaluatedAtUnixNano:   plan.CommitNotAfterUnixNano(),
				FailureEvidenceDigest: digest(0x34)})
	if err != nil || replannedReconciliation.Digest() != reconciliation.Digest() {
		t.Fatalf("decoded pending terminal replan = %v", err)
	}
	for _, claim := range replannedReconciliation.IdempotencyCompletionClaims() {
		view.idempotency[claim.Binding.Key] = idempotency.Snapshot{Binding: claim.Binding,
			State: claim.NextState, Version: claim.NextVersion,
			ProgressDigest: claim.NextProgressDigest,
			OutcomeDigest:  replannedReconciliation.FailureOutcomeDigest()}
	}
	decodedReconciliation, err := DecodeDurablePendingEnvelope(reconciliationEnvelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	_, err = testPlanner(t, view, &allowProfile{}).RevalidateDurablePending(context.Background(),
		decodedReconciliation, replannedReconciliation.CommitNotAfterUnixNano()+1)
	var completed IdempotencyCompletedError
	if !errors.As(err, &completed) || completed.Outcome != replannedReconciliation.FailureOutcomeDigest() {
		t.Fatalf("terminal reconciliation reload = %v", err)
	}
	completionClaims := replannedReconciliation.IdempotencyCompletionClaims()
	tampered := view.idempotency[completionClaims[0].Binding.Key]
	tampered.Version++
	view.idempotency[completionClaims[0].Binding.Key] = tampered
	if _, err := testPlanner(t, view, &allowProfile{}).RevalidateDurablePending(context.Background(),
		decodedReconciliation, replannedReconciliation.CommitNotAfterUnixNano()+1); !errors.Is(err, ErrPendingPlanInvalid) {
		t.Fatalf("terminal reconciliation accepted modified completed snapshot: %v", err)
	}
	tampered.Version--
	view.idempotency[completionClaims[0].Binding.Key] = tampered
	delete(view.idempotency, collecting.AuditSnapshot().Binding.Key)
	_, err = testPlanner(t, view, &allowProfile{}).PlanIdentity(context.Background(), command)
	if !errors.Is(err, idempotency.ErrJoinedStateMismatch) || errors.Is(err, ErrIdempotencyInProgress) {
		t.Fatalf("mixed crash state did not fail closed: %v", err)
	}
}

func TestPlanKeyEnrollmentReservesJoinedAuditEventAndBindsAdmission(t *testing.T) {
	view := newMemoryView()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-enrollment"}
	material := materialSnapshotForTarget(t, 0x39, "spiffe://cph.example/agent/enrollment", target)
	view.challenges[material.ProofChallenge] = ProofChallengeSnapshot{
		Challenge: material.ProofChallenge, SubjectIdentity: material.SubjectIdentity,
		SubjectKind: material.SubjectKind, TargetIdentity: target, Domain: material.EnrollmentDomain,
		ExpiresAtUnixNano: material.ProofExpiresAtUnixNano,
		IssuerIdentity:    material.EnrollmentAuthorityIdentity, PolicyDigestsSHA256: material.EnrollmentPolicyDigestsSHA256,
		EvidenceDigest: material.ChallengeEvidenceDigest,
	}
	materialEntity := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: material.SubjectKind, ID: material.KeyID}
	view.leases[materialEntity] = lease(materialEntity, material.WriterIdentity, 7, 0x3a)
	materialCommand := KeyMaterialCommand{
		Algorithm: material.Algorithm, CanonicalPublicKey: material.CanonicalPublicKey, ClaimedKeyID: material.KeyID,
		SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind, TargetIdentity: target,
		EnrollmentDomain: material.EnrollmentDomain, Challenge: material.ProofChallenge,
		ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano, ProofSignature: material.ProofSignature,
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
		EvaluatedAtUnixNano:               testNow, CorrelationID: id16(0x3b), IdempotencyKey: material.IdempotencyKey,
		CauseCode: "initial-enrollment", Fence: fence(materialEntity, material.WriterIdentity, 7, 0, 0x3a),
	}
	projection := lifecycleProjection(material, 1, 1, 7)
	projection.Metadata.RecordID = "initial-enrollment-lifecycle"
	projection.Metadata.IdempotencyKey = material.IdempotencyKey
	lifecycle, err := NormalizeKeyLifecycle(projection)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleEntity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: material.SubjectKind, ID: material.KeyID}
	authorization := verifiedAuthorization(t, view, schema.MessageTypeKeyLifecycle,
		lifecycle.CanonicalPayload, lifecycleEntity, 0, id16(0x3b))
	view.leases[lifecycleEntity] = lease(lifecycleEntity, authorization.SenderIdentity(), 7, 0x3c)
	lifecycleCommand := KeyLifecycleCommand{Projection: projection, ActorIdentity: authorization.SenderIdentity(),
		EvaluatedAtUnixNano: testNow, CorrelationID: id16(0x3b), CauseCode: "initial-enrollment",
		Fence: fence(lifecycleEntity, authorization.SenderIdentity(), 7, 0, 0x3c), Authorization: authorization}

	plan, err := testPlanner(t, view, &allowProfile{}).PlanKeyEnrollment(context.Background(),
		KeyEnrollmentCommand{Material: materialCommand, Lifecycle: lifecycleCommand})
	if err != nil {
		t.Fatal(err)
	}
	if plan.CommitReady() || plan.VerifyDigest() != nil ||
		plan.AdmissionIntent().EvaluatedAtUnixNano() != plan.EvaluatedAtUnixNano() ||
		plan.AdmissionIntent().CommitNotBeforeUnixNano() != plan.CommitNotBeforeUnixNano() ||
		plan.AdmissionIntent().CommitNotAfterUnixNano() != plan.CommitNotAfterUnixNano() {
		t.Fatal("compound enrollment admission/window binding is invalid")
	}
	enrollmentEnvelope, err := plan.DurableEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	assertDurableEnvelopeRoundTrip(t, enrollmentEnvelope)
	enrollmentRequest, err := plan.JoinedAuditRequest()
	if err != nil {
		t.Fatal(err)
	}
	assertJoinedAuditRequestTamperResistance(t, enrollmentRequest)
	var parent idempotency.Binding
	for _, claim := range plan.AdmissionIntent().IdempotencyReservations() {
		if claim.Binding.Domain != idempotency.OperationJoinedAudit {
			parent = claim.Binding
		}
	}
	eventID, err := idempotency.JoinedAuditEventID(parent)
	if err != nil || plan.AuditIntent().AuditEventID() != eventID {
		t.Fatalf("joined event ID = %q / %v", plan.AuditIntent().AuditEventID(), err)
	}
	eventReservation, err := joinedAuditEventReservation(parent, eventID)
	if err != nil || !containsGlobalClaim(plan.AdmissionIntent().IdentifierReservations(), eventReservation) {
		t.Fatal("joined event was not reserved during enrollment admission")
	}
	eventAssertion, _ := joinedAuditEventAssertion(eventReservation)
	finalClaims := append(plan.CASIntents()[0].IdentifierClaims, plan.CASIntents()[1].IdentifierClaims...)
	if !containsGlobalClaim(finalClaims, eventAssertion) {
		t.Fatal("joined event final assertion missing")
	}
	wrongReplay := KeyEnrollmentCommand{Material: materialCommand, Lifecycle: lifecycleCommand}
	wrongReplay.Lifecycle.Authorization = authorizationWithReplayDomain(t, authorization, "iam.test")
	if _, err := testPlanner(t, view, &allowProfile{}).PlanKeyEnrollment(context.Background(), wrongReplay); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("KeyEnrollment accepted type-wide replay domain: %v", err)
	}

	tamperedAudit := plan
	tamperedAudit.audit.auditEventID += "-tampered"
	if tamperedAudit.VerifyDigest() == nil {
		t.Fatal("tampered joined AuditEvent ID accepted")
	}
	tamperedAdmission := plan
	tamperedAdmission.admission = plan.admission.detached()
	tamperedAdmission.admission.commitNotAfterUnixNano--
	if tamperedAdmission.VerifyDigest() == nil {
		t.Fatal("tampered admission time fence accepted")
	}
	tamperedCompletion := plan
	tamperedCompletion.idempotencyCompletion = append([]idempotency.Claim(nil), plan.idempotencyCompletion...)
	tamperedCompletion.idempotencyCompletion[0].NextVersion++
	if tamperedCompletion.VerifyDigest() == nil {
		t.Fatal("tampered completion claim accepted")
	}
	for _, reservation := range plan.AdmissionIntent().IdempotencyReservations() {
		view.idempotency[reservation.Binding.Key] = idempotency.Snapshot{Binding: reservation.Binding,
			State: reservation.NextState, Version: reservation.NextVersion,
			ProgressDigest: reservation.NextProgressDigest}
	}
	applyGlobalClaims(t, view, plan.AdmissionIntent().IdentifierReservations())
	decodedEnrollment, err := DecodeDurablePendingEnvelope(enrollmentEnvelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPlanner(t, view, &allowProfile{}).RevalidateDurablePending(
		context.Background(), decodedEnrollment, testNow); err != nil {
		t.Fatalf("durable enrollment revalidation = %v", err)
	}
}

func TestPlanLifecyclePreactiveCanBeRevokedBeforeNotBeforeWithoutIdentity(t *testing.T) {
	view := newMemoryView()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-future"}
	material := materialSnapshotForTarget(t, 0x41, "spiffe://cph.example/agent/future", target)
	currentProjection := lifecycleProjection(material, 1, 1, 7)
	currentProjection.Metadata.RecordID = "future-key-preactive"
	currentProjection.NotBeforeUnixNano = testNow + 10_000
	currentProjection.NotAfterUnixNano = testNow + 20_000
	current, err := NormalizeKeyLifecycle(currentProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.materials[material.KeyID] = material
	view.lifecycles[material.KeyID] = current
	installMaterialBootstrapIDs(view, material)

	nextProjection := currentProjection
	nextProjection.Metadata = metadata(2, 8, 0x42)
	nextProjection.Metadata.RecordID = "future-key-revoked"
	nextProjection.State = 4
	nextProjection.RevokedAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testNow}
	nextProjection.TransitionReasonCode = foundationv1.OptionalString{Present: true, Value: "cancelled"}
	next, err := NormalizeKeyLifecycle(nextProjection)
	if err != nil {
		t.Fatal(err)
	}
	entity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: material.SubjectKind, ID: material.KeyID}
	authorization := verifiedAuthorization(t, view, schema.MessageTypeKeyLifecycle,
		next.CanonicalPayload, entity, 1, id16(0x43))
	view.leases[entity] = lease(entity, authorization.SenderIdentity(), 8, 0x44)
	command := KeyLifecycleCommand{Projection: nextProjection, ActorIdentity: authorization.SenderIdentity(),
		EvaluatedAtUnixNano: testNow, CorrelationID: id16(0x43), CauseCode: "cancelled",
		Fence: fence(entity, authorization.SenderIdentity(), 8, 1, 0x44), Authorization: authorization}
	plan, err := testPlanner(t, view, &allowProfile{}).PlanKeyLifecycle(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CAS().ExpectedSubjectAbsent || plan.CommitReady() || plan.VerifyDigest() != nil {
		t.Fatalf("preactive cancellation plan invalid: %#v", plan.CAS())
	}
	wrongEntityDomain, err := DeriveEntityReplayDomainID("iam.test", target)
	if err != nil {
		t.Fatal(err)
	}
	wrong := command
	wrong.Authorization = authorizationWithReplayDomain(t, authorization, wrongEntityDomain)
	if _, err := testPlanner(t, view, &allowProfile{}).PlanKeyLifecycle(context.Background(), wrong); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("KeyLifecycle accepted identity-scoped replay domain: %v", err)
	}
}

func TestResolverRequiresCurrentActiveIdentityAndReturnsCASFingerprint(t *testing.T) {
	view := newMemoryView()
	material := installAuthorizationKey(t, view, schema.MessageTypeAgentIdentity)
	resolver, err := NewDefaultKeySnapshotResolver(view)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveKeySnapshot(context.Background(), material.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.StateVersion == 0 || resolved.WriterEpoch == 0 || resolved.SnapshotDigest == ([32]byte{}) ||
		resolved.IdentityStateVersion == 0 || resolved.IdentityWriterEpoch == 0 || resolved.IdentitySnapshotDigest == ([32]byte{}) {
		t.Fatalf("missing resolver fingerprints: %#v", resolved)
	}
	identity := view.identities[material.TargetIdentity]
	projection := foundationv1.ServiceIdentitySigningProjection{
		Metadata: metadata(identity.StateVersion+1, identity.WriterEpoch, 0x51), ServiceID: identity.Ref.ID,
		ServiceName: "iam-writer", SPIFFEID: identity.PrincipalIdentity, DeploymentEnvironment: "testnet",
		KeyID: identity.KeyID, CredentialGeneration: identity.Generation, ValidFromUnixNano: identity.ValidFromUnixNano,
		ValidUntilUnixNano: identity.ValidUntilUnixNano, State: 3,
	}
	projection.Metadata.RecordID = "writer-suspended"
	suspended, err := NormalizeIdentity(projection)
	if err != nil {
		t.Fatal(err)
	}
	view.identities[material.TargetIdentity] = suspended
	_, err = resolver.ResolveKeySnapshot(context.Background(), material.KeyID)
	requireErrorIs(t, err, ErrIdentityConflict)
}

func TestHostTransferEnrollmentStagesKeyThenMovesPrincipalAtomically(t *testing.T) {
	view := newMemoryView()
	principal := "urn:tpm:host:transfer"
	oldRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 3, ID: "host-old"}
	newRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 3, ID: "host-new"}
	transferDigest := digest(0x71)
	material := materialSnapshotForTargetAndTransfer(t, 0x72, principal, newRef, transferDigest)
	oldProjection := foundationv1.HostIdentitySigningProjection{
		Metadata: metadata(1, 7, 0x73), HostID: oldRef.ID, ProviderID: "provider-01", ProviderSiteID: "site-old",
		AttestationIdentity: principal, KeyID: material.KeyID, OwnershipGeneration: 1,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 5,
	}
	oldProjection.Metadata.RecordID = "host-old-transferred"
	oldIdentity, err := NormalizeIdentity(oldProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.identities[oldRef] = oldIdentity
	installIdentityOwnership(view, oldIdentity)
	transfer := OwnershipTransferSnapshot{PreviousEntity: oldRef, NextEntity: newRef,
		PreviousPrincipal: principal, NextPrincipal: principal, PreviousGeneration: 1, NextGeneration: 2,
		CompletedAtUnixNano: testNow - 1, EvidenceDigest: transferDigest}
	view.transfers[transferDigest] = transfer

	challenge := ProofChallengeSnapshot{Challenge: material.ProofChallenge, SubjectIdentity: principal,
		SubjectKind: 3, TargetIdentity: newRef, TransferEvidenceDigest: transferDigest,
		Domain: material.EnrollmentDomain, ExpiresAtUnixNano: material.ProofExpiresAtUnixNano,
		IssuerIdentity:      material.EnrollmentAuthorityIdentity,
		PolicyDigestsSHA256: material.EnrollmentPolicyDigestsSHA256, EvidenceDigest: material.ChallengeEvidenceDigest}
	view.challenges[material.ProofChallenge] = challenge
	materialEntity := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: 3, ID: material.KeyID}
	view.leases[materialEntity] = lease(materialEntity, material.WriterIdentity, 7, 0x7b)
	materialCommand := KeyMaterialCommand{Algorithm: material.Algorithm, CanonicalPublicKey: material.CanonicalPublicKey,
		ClaimedKeyID: material.KeyID, SubjectIdentity: principal, SubjectKind: 3, TargetIdentity: newRef,
		TransferEvidenceDigest: transferDigest, EnrollmentDomain: material.EnrollmentDomain,
		Challenge: material.ProofChallenge, ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano,
		ProofSignature: material.ProofSignature, EnrollmentAuthorityIdentity: material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
		EvaluatedAtUnixNano:               testNow, CorrelationID: id16(0x75), IdempotencyKey: material.IdempotencyKey,
		CauseCode: "ownership-transfer", Fence: fence(materialEntity, material.WriterIdentity, 7, 0, 0x7b)}
	lifecycleProjection := lifecycleProjection(material, 1, 1, 7)
	lifecycleProjection.Metadata.RecordID = "transfer-key-preactive"
	lifecycleProjection.Metadata.IdempotencyKey = material.IdempotencyKey
	lifecycleProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeHostIdentity}
	lifecycle, err := NormalizeKeyLifecycle(lifecycleProjection)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleEntity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: 3, ID: material.KeyID}
	authorization := verifiedAuthorization(t, view, schema.MessageTypeKeyLifecycle,
		lifecycle.CanonicalPayload, lifecycleEntity, 0, id16(0x75))
	view.leases[lifecycleEntity] = lease(lifecycleEntity, authorization.SenderIdentity(), 7, 0x77)
	lifecycleCommand := KeyLifecycleCommand{Projection: lifecycleProjection,
		ActorIdentity: authorization.SenderIdentity(), EvaluatedAtUnixNano: testNow,
		CorrelationID: id16(0x75), CauseCode: "ownership-transfer",
		Fence: fence(lifecycleEntity, authorization.SenderIdentity(), 7, 0, 0x77), Authorization: authorization,
		TransferEvidenceDigest: transferDigest}
	planner := testPlanner(t, view, &allowProfile{})
	enrollmentCommand := KeyEnrollmentCommand{Material: materialCommand, Lifecycle: lifecycleCommand}
	if _, publicErr := planner.PlanKeyEnrollment(context.Background(), enrollmentCommand); !errors.Is(publicErr, ErrTransferAuthorizationRequired) {
		t.Fatalf("public unverified transfer enrollment = %v", publicErr)
	}
	enrollmentPlan, err := planKeyEnrollmentForTest(planner, context.Background(), enrollmentCommand)
	if err != nil {
		t.Fatal(err)
	}
	if enrollmentPlan.CommitReady() || enrollmentPlan.VerifyDigest() != nil ||
		enrollmentPlan.AuditIntent().CausationID() != directAuditCausation(authorization.MessageID()) {
		t.Fatal("compound enrollment audit/digest boundary is invalid")
	}
	casIntents := enrollmentPlan.CASIntents()
	if len(casIntents) != 2 || len(casIntents[0].Dependencies) != 1 ||
		casIntents[0].Dependencies[0].Entity != oldRef {
		t.Fatal("old terminal identity is not fenced during transfer enrollment")
	}
	applyGlobalClaims(t, view, enrollmentPlan.AdmissionIntent().IdentifierReservations())
	storedMaterial, _ := enrollmentPlan.KeyMaterial()
	storedLifecycle, _ := enrollmentPlan.KeyLifecycle()
	view.materials[material.KeyID] = storedMaterial
	view.lifecycles[material.KeyID] = storedLifecycle

	provider := activeProviderGeneration(t, 2)
	view.identities[provider.Ref] = provider
	newProjection := foundationv1.HostIdentitySigningProjection{
		Metadata: metadata(1, 7, 0x78), HostID: newRef.ID, ProviderID: "provider-01", ProviderSiteID: "site-new",
		AttestationIdentity: principal, KeyID: material.KeyID, OwnershipGeneration: 2,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1,
	}
	newProjection.Metadata.RecordID = "host-new-pending"
	newIdentity, err := NormalizeIdentity(newProjection)
	if err != nil {
		t.Fatal(err)
	}
	identityAuthorization := verifiedAuthorization(t, view, schema.MessageTypeHostIdentity,
		newIdentity.CanonicalPayload, newIdentity.Ref, 0, id16(0x79))
	view.leases[newRef] = lease(newRef, identityAuthorization.SenderIdentity(), 7, 0x7a)
	identityCommand := IdentityCommand{Projection: newProjection, ActorIdentity: identityAuthorization.SenderIdentity(),
		EvaluatedAtUnixNano: testNow, CorrelationID: id16(0x79), CauseCode: "ownership-transfer",
		Fence: fence(newRef, identityAuthorization.SenderIdentity(), 7, 0, 0x7a), Authorization: identityAuthorization,
		TransferEvidenceDigest: transferDigest}
	if _, publicErr := planner.PlanIdentity(context.Background(), identityCommand); !errors.Is(publicErr, ErrTransferAuthorizationRequired) {
		t.Fatalf("public unverified transfer identity = %v", publicErr)
	}
	identityPlan, err := planIdentityTransferForTest(planner, context.Background(), identityCommand)
	if err != nil {
		t.Fatal(err)
	}
	cas := identityPlan.CAS()
	if cas.PrincipalIndex.Mode != globalid.TransferExisting || cas.PrincipalIndex.ExpectedOwner != oldRef ||
		cas.PrincipalIndex.NextOwner != newRef {
		t.Fatalf("principal index transfer missing: %#v", cas.PrincipalIndex)
	}
	transfers := 0
	for _, claim := range cas.IdentifierClaims {
		if claim.Mode == globalid.TransferExisting && claim.Identifier == principal && claim.Owner == identityGlobalOwner(newRef) {
			transfers++
		}
	}
	if transfers != 1 || identityPlan.VerifyDigest() != nil {
		t.Fatalf("global principal transfer count/digest = %d/%v", transfers, identityPlan.VerifyDigest())
	}
}

func TestAgentTransferRotatesPrincipalAndProviderThroughCompoundEnrollment(t *testing.T) {
	view := newMemoryView()
	oldPrincipal := "spiffe://cph.example/agent/old"
	newPrincipal := "spiffe://cph.example/agent/new"
	oldRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-old"}
	newRef := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-new"}
	transferDigest := digest(0x81)
	oldKey := materialSnapshotForTarget(t, 0x82, oldPrincipal, oldRef)
	oldProjection := foundationv1.AgentIdentitySigningProjection{
		Metadata: metadata(1, 7, 0x83), AgentID: oldRef.ID, ProviderID: "provider-old", HostID: "host-old",
		SPIFFEID: oldPrincipal, KeyID: oldKey.KeyID, OwnershipGeneration: 1,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 5,
	}
	oldProjection.Metadata.RecordID = "agent-old-transferred"
	oldIdentity, err := NormalizeIdentity(oldProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.identities[oldRef] = oldIdentity
	installIdentityOwnership(view, oldIdentity)
	view.transfers[transferDigest] = OwnershipTransferSnapshot{PreviousEntity: oldRef, NextEntity: newRef,
		PreviousPrincipal: oldPrincipal, NextPrincipal: newPrincipal, PreviousGeneration: 1, NextGeneration: 2,
		CompletedAtUnixNano: testNow - 1, EvidenceDigest: transferDigest}

	material := materialSnapshotForTargetAndTransfer(t, 0x84, newPrincipal, newRef, transferDigest)
	view.challenges[material.ProofChallenge] = ProofChallengeSnapshot{Challenge: material.ProofChallenge,
		SubjectIdentity: newPrincipal, SubjectKind: 2, TargetIdentity: newRef,
		TransferEvidenceDigest: transferDigest, Domain: material.EnrollmentDomain,
		ExpiresAtUnixNano: material.ProofExpiresAtUnixNano, IssuerIdentity: material.EnrollmentAuthorityIdentity,
		PolicyDigestsSHA256: material.EnrollmentPolicyDigestsSHA256, EvidenceDigest: material.ChallengeEvidenceDigest}
	materialEntity := EntityRef{Kind: EntityKeyMaterial, PrincipalKind: 2, ID: material.KeyID}
	view.leases[materialEntity] = lease(materialEntity, material.WriterIdentity, 7, 0x85)
	materialCommand := KeyMaterialCommand{Algorithm: material.Algorithm,
		CanonicalPublicKey: material.CanonicalPublicKey, ClaimedKeyID: material.KeyID,
		SubjectIdentity: newPrincipal, SubjectKind: 2, TargetIdentity: newRef,
		TransferEvidenceDigest: transferDigest, EnrollmentDomain: material.EnrollmentDomain,
		Challenge: material.ProofChallenge, ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano,
		ProofSignature: material.ProofSignature, EnrollmentAuthorityIdentity: material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
		EvaluatedAtUnixNano:               testNow, CorrelationID: id16(0x86), IdempotencyKey: material.IdempotencyKey,
		CauseCode: "agent-ownership-transfer", Fence: fence(materialEntity, material.WriterIdentity, 7, 0, 0x85)}
	lifecycleProjection := lifecycleProjection(material, 1, 1, 7)
	lifecycleProjection.Metadata.RecordID = "agent-transfer-key-preactive"
	lifecycleProjection.Metadata.IdempotencyKey = material.IdempotencyKey
	lifecycleProjection.AllowedMessageTypeIDs = []uint32{schema.MessageTypeAgentIdentity}
	lifecycle, err := NormalizeKeyLifecycle(lifecycleProjection)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleEntity := EntityRef{Kind: EntityKeyLifecycle, PrincipalKind: 2, ID: material.KeyID}
	authorization := verifiedAuthorization(t, view, schema.MessageTypeKeyLifecycle,
		lifecycle.CanonicalPayload, lifecycleEntity, 0, id16(0x86))
	view.leases[lifecycleEntity] = lease(lifecycleEntity, authorization.SenderIdentity(), 7, 0x87)
	lifecycleCommand := KeyLifecycleCommand{Projection: lifecycleProjection,
		ActorIdentity: authorization.SenderIdentity(), EvaluatedAtUnixNano: testNow,
		CorrelationID: id16(0x86), CauseCode: "agent-ownership-transfer",
		Fence: fence(lifecycleEntity, authorization.SenderIdentity(), 7, 0, 0x87), Authorization: authorization,
		TransferEvidenceDigest: transferDigest}
	planner := testPlanner(t, view, &allowProfile{})
	enrollmentCommand := KeyEnrollmentCommand{Material: materialCommand, Lifecycle: lifecycleCommand}
	if _, publicErr := planner.PlanKeyEnrollment(context.Background(), enrollmentCommand); !errors.Is(publicErr, ErrTransferAuthorizationRequired) {
		t.Fatalf("public unverified Agent transfer enrollment = %v", publicErr)
	}
	enrollment, err := planKeyEnrollmentForTest(planner, context.Background(), enrollmentCommand)
	if err != nil {
		t.Fatal(err)
	}
	if requiredDigest, required := enrollment.RequiredTransferAuthorization(); !required || requiredDigest != transferDigest {
		t.Fatal("unverified dedicated transfer authorization is not a finalization blocker")
	}
	applyGlobalClaims(t, view, enrollment.AdmissionIntent().IdentifierReservations())
	storedMaterial, _ := enrollment.KeyMaterial()
	storedLifecycle, _ := enrollment.KeyLifecycle()
	view.materials[material.KeyID] = storedMaterial
	view.lifecycles[material.KeyID] = storedLifecycle

	providerProjection := foundationv1.ProviderIdentitySigningProjection{Metadata: metadata(1, 7, 0x88),
		ProviderID: "provider-new", OrganizationIdentity: "spiffe://cph.example/provider/new",
		PayoutIdentity: "cph:provider:new", Jurisdictions: []string{"DE"},
		PolicyDigestsSHA256: [][32]byte{digest(0x89)}, OwnershipGeneration: 2,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2}
	providerProjection.Metadata.RecordID = "provider-new-active"
	provider, err := NormalizeIdentity(providerProjection)
	if err != nil {
		t.Fatal(err)
	}
	hostProjection := foundationv1.HostIdentitySigningProjection{Metadata: metadata(1, 7, 0x8a),
		HostID: "host-new", ProviderID: provider.Ref.ID, ProviderSiteID: "site-new",
		AttestationIdentity: "urn:tpm:host:new", KeyID: oldKey.KeyID, OwnershipGeneration: 2,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 2}
	hostProjection.Metadata.RecordID = "host-new-active"
	host, err := NormalizeIdentity(hostProjection)
	if err != nil {
		t.Fatal(err)
	}
	view.identities[provider.Ref] = provider
	view.identities[host.Ref] = host
	newProjection := foundationv1.AgentIdentitySigningProjection{Metadata: metadata(1, 7, 0x8b),
		AgentID: newRef.ID, ProviderID: provider.Ref.ID, HostID: host.Ref.ID,
		SPIFFEID: newPrincipal, KeyID: material.KeyID, OwnershipGeneration: 2,
		ValidFromUnixNano: testNotBefore, ValidUntilUnixNano: testNotAfter, State: 1}
	newProjection.Metadata.RecordID = "agent-new-pending"
	newIdentity, err := NormalizeIdentity(newProjection)
	if err != nil {
		t.Fatal(err)
	}
	identityAuthorization := verifiedAuthorization(t, view, schema.MessageTypeAgentIdentity,
		newIdentity.CanonicalPayload, newIdentity.Ref, 0, id16(0x8c))
	view.leases[newRef] = lease(newRef, identityAuthorization.SenderIdentity(), 7, 0x8d)
	identityCommand := IdentityCommand{Projection: newProjection,
		ActorIdentity: identityAuthorization.SenderIdentity(), EvaluatedAtUnixNano: testNow,
		CorrelationID: id16(0x8c), CauseCode: "agent-ownership-transfer",
		Fence:         fence(newRef, identityAuthorization.SenderIdentity(), 7, 0, 0x8d),
		Authorization: identityAuthorization, TransferEvidenceDigest: transferDigest}
	if _, publicErr := planner.PlanIdentity(context.Background(), identityCommand); !errors.Is(publicErr, ErrTransferAuthorizationRequired) {
		t.Fatalf("public unverified Agent transfer identity = %v", publicErr)
	}
	identityPlan, err := planIdentityTransferForTest(planner, context.Background(), identityCommand)
	if err != nil {
		t.Fatal(err)
	}
	if identityPlan.CAS().PrincipalIndex.Mode != globalid.ReserveNew {
		t.Fatal("rotated Agent principal was not reserved for its successor")
	}
	oldPrincipalAsserted := false
	for _, claim := range identityPlan.CAS().IdentifierClaims {
		if claim.Identifier == oldPrincipal && claim.Mode == globalid.AssertExisting &&
			claim.Owner == identityGlobalOwner(oldRef) {
			oldPrincipalAsserted = true
		}
	}
	if requiredDigest, required := identityPlan.RequiredTransferAuthorization(); !required || requiredDigest != transferDigest || !oldPrincipalAsserted || identityPlan.VerifyDigest() != nil {
		t.Fatal("Agent transfer fencing/finalization blocker is incomplete")
	}
}

func TestIdempotencyCompletedReturnsStoredOutcomeBeforeSemanticLookup(t *testing.T) {
	view := newMemoryView()
	target := EntityRef{Kind: EntityIdentity, PrincipalKind: 2, ID: "agent-idempotent"}
	material := materialSnapshotForTarget(t, 0x61, "spiffe://cph.example/agent/idempotent", target)
	requestDigest, err := keyMaterialRequestDigest(KeyMaterialCommand{
		Algorithm: material.Algorithm, CanonicalPublicKey: material.CanonicalPublicKey, ClaimedKeyID: material.KeyID,
		SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind, TargetIdentity: target,
		EnrollmentDomain: material.EnrollmentDomain, Challenge: material.ProofChallenge,
		ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano, ProofSignature: material.ProofSignature,
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
	}, material.CanonicalPublicKey, material.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	binding := mutationIdempotencyBinding(material.IdempotencyKey, idempotency.OperationIAMKeyEnrollment,
		material.KeyID, requestDigest)
	joined, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	parentDigest, err := idempotency.BindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	view.idempotency[material.IdempotencyKey] = idempotency.Snapshot{Binding: binding,
		State: idempotency.StateCompleted, Version: 2, ProgressDigest: digest(0x64), OutcomeDigest: digest(0x62)}
	view.idempotency[joined.Key] = idempotency.Snapshot{Binding: joined,
		State: idempotency.StateCompleted, Version: 2, ProgressDigest: parentDigest, OutcomeDigest: digest(0x62)}
	command := KeyMaterialCommand{Algorithm: material.Algorithm, CanonicalPublicKey: material.CanonicalPublicKey,
		ClaimedKeyID: material.KeyID, SubjectIdentity: material.SubjectIdentity, SubjectKind: material.SubjectKind,
		TargetIdentity: target, EnrollmentDomain: material.EnrollmentDomain, Challenge: material.ProofChallenge,
		ChallengeExpiresAtUnixNano: material.ProofExpiresAtUnixNano, ProofSignature: material.ProofSignature,
		EnrollmentAuthorityIdentity:       material.EnrollmentAuthorityIdentity,
		EnrollmentAuthorityEvidenceDigest: material.ChallengeEvidenceDigest,
		EnrollmentPolicyDigestsSHA256:     material.EnrollmentPolicyDigestsSHA256,
		EvaluatedAtUnixNano:               testNow, CorrelationID: id16(0x63), IdempotencyKey: material.IdempotencyKey,
		CauseCode: "retry"}
	_, err = planKeyMaterialForTest(testPlanner(t, view, &allowProfile{}), context.Background(), command)
	if !errors.Is(err, ErrIdempotencyCompleted) {
		t.Fatalf("duplicate error = %v", err)
	}
	var completed IdempotencyCompletedError
	if !errors.As(err, &completed) || completed.OutcomeDigest() != digest(0x62) {
		t.Fatalf("completed outcome = %#v", completed)
	}
}

func TestGlobalClaimsRemainDetached(t *testing.T) {
	claim, err := globalid.Reserve("id", globalid.Owner{Domain: globalid.OwnerIAMIdentity, ID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	cas := CASIntent{IdentifierClaims: []globalid.Claim{claim}}
	plan := MutationPlan{cas: cas}
	copyCAS := plan.CAS()
	copyCAS.IdentifierClaims[0].Identifier = "tampered"
	if plan.CAS().IdentifierClaims[0].Identifier != "id" {
		t.Fatal("CAS getter aliases global claims")
	}
}
