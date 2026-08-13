// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

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

func TestApprovalIngestionAtomicallyReservesJoinedOperationAndGlobalIDs(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	fixture.clearPolicyAdmission(policy)

	first, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
	})
	if err != nil {
		t.Fatalf("first ingestion: %v", err)
	}
	got := first.Snapshot()
	if !first.CommitReady() || first.VerifyDigest() != nil || got.Disposition != ApprovalCollectionAppend ||
		len(got.Claims) != 2 || len(got.IdentifierClaims) != 3 || got.JoinedAuditIdempotencySnapshot != (idempotency.Snapshot{}) ||
		got.NextAdmissionProfileActivation != got.GovernanceProfileActivation {
		t.Fatalf("bad first ingestion plan: %+v", got)
	}
	if got.DurablePendingRevision.VerifyDigest() != nil || got.DurablePendingRevision.Revision() != 1 ||
		got.DurablePendingRevision.Kind() != DurablePendingGovernancePolicyApprovalCollection ||
		got.DurablePendingRevision.Status() != DurablePendingOpen ||
		got.DurablePendingRevision.ExpectedKind() != 0 ||
		got.NextEvidenceStorageCapability.VerifyDigest() != nil ||
		got.NextEvidenceStorageCapability.Disposition() != DurableEvidenceStorageReserveNew {
		t.Fatalf("first durable persistence closure: pending=%#v evidence=%#v",
			got.DurablePendingRevision, got.NextEvidenceStorageCapability)
	}
	if len(got.CanonicalStateAssertions) != 1 || got.CanonicalStateAssertions[0].VerifyDigest() != nil ||
		got.CanonicalStateAssertions[0].Record().Kind != CanonicalStateKindGovernanceProfileActivation ||
		len(got.CanonicalKeyStateAssertions) != 1 || got.CanonicalKeyStateAssertions[0].VerifyDigest() != nil ||
		got.CanonicalKeyStateAssertions[0].KeyPrecondition() != got.NextKeyPrecondition ||
		len(got.CanonicalKeyStateAssertions[0].Records()) != 3 {
		t.Fatalf("first admission canonical read set = %#v / %#v",
			got.CanonicalStateAssertions, got.CanonicalKeyStateAssertions)
	}
	if decoded, decodeErr := DecodePolicyApprovalCollection(got.DurablePendingRevision.CanonicalEnvelope()); decodeErr != nil || decoded.Digest() != got.DurablePendingRevision.EnvelopeDigest() ||
		decoded.Revision() != 1 || decoded.Binding() != got.Binding {
		t.Fatalf("first pending codec = %#v / %v", decoded, decodeErr)
	}
	mutatedActivation := got
	mutatedActivation.NextAdmissionProfileActivation.Version++
	if _, err := newApprovalCollectionPlan(mutatedActivation); err == nil {
		t.Fatal("approval collection plan accepted substituted activation version")
	}
	tamperedProfileRow := first.Snapshot()
	tamperedProfileRow.CanonicalStateAssertions[0].record.CanonicalState[0] ^= 1
	if _, err := newApprovalCollectionPlan(tamperedProfileRow); err == nil {
		t.Fatal("approval collection plan accepted tampered profile row")
	}
	tamperedSignerRow := first.Snapshot()
	tamperedSignerRow.CanonicalKeyStateAssertions[0].records[0].record.CanonicalState[0] ^= 1
	if _, err := newApprovalCollectionPlan(tamperedSignerRow); err == nil {
		t.Fatal("approval collection plan accepted tampered signer row")
	}
	missingReadSet := first.Snapshot()
	missingReadSet.CanonicalKeyStateAssertions = nil
	if _, err := newApprovalCollectionPlan(missingReadSet); err == nil {
		t.Fatal("approval collection plan accepted missing signer read assertion")
	}
	var parentReserved, auditReserved bool
	for _, claim := range got.Claims {
		if claim.Mode != idempotency.ReserveCollection {
			t.Fatalf("unexpected first claim: %+v", claim)
		}
		switch claim.Binding.Domain {
		case idempotency.OperationGovernancePolicy:
			parentReserved = true
		case idempotency.OperationJoinedAudit:
			auditReserved = true
		}
	}
	if !parentReserved || !auditReserved {
		t.Fatalf("X/Y were not reserved together: %+v", got.Claims)
	}
	fixture.applyApprovalCollectionPlan(t, got, command.Approvals[0])

	if _, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
	}); !errors.As(err, new(DuplicateApprovalError)) {
		t.Fatalf("exact retry error = %v", err)
	}

	second, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: command.Approvals[1],
	})
	if err != nil {
		t.Fatalf("second ingestion: %v", err)
	}
	secondValue := second.Snapshot()
	if len(secondValue.Claims) != 1 || secondValue.Claims[0].Mode != idempotency.AdvanceCollection ||
		len(secondValue.NextCollectionRecordDigestsSHA256) != 2 || secondValue.JoinedAuditIdempotencySnapshot.State != idempotency.StateCollecting {
		t.Fatalf("bad second ingestion plan: %+v", secondValue)
	}
	if secondValue.DurablePendingRevision.VerifyDigest() != nil ||
		secondValue.DurablePendingRevision.Revision() != 2 ||
		secondValue.DurablePendingRevision.ExpectedKind() != DurablePendingGovernancePolicyApprovalCollection ||
		secondValue.DurablePendingRevision.PreviousEnvelopeDigest() != got.DurablePendingRevision.EnvelopeDigest() ||
		!bytes.Equal(secondValue.DurablePendingRevision.PreviousCanonicalEnvelope(), got.DurablePendingRevision.CanonicalEnvelope()) {
		t.Fatalf("advance durable persistence closure = %#v", secondValue.DurablePendingRevision)
	}
	sourcePrevious, sourcePresent := secondValue.DurablePendingRevision.SourcePreviousEnvelopeDigest()
	sourceEvidence, evidencePresent := secondValue.DurablePendingRevision.SourceEvidenceDigests()
	if !sourcePresent || !evidencePresent || sourcePrevious != ([ccse.DigestSize]byte{}) ||
		!equalDigestSets(sourceEvidence, got.DurablePendingRevision.EvidenceDigests()) {
		t.Fatalf("advance source fence previous=%x evidence=%x", sourcePrevious, sourceEvidence)
	}
	sourceEvidence[0][0] ^= 1
	retainedEvidence, _ := secondValue.DurablePendingRevision.SourceEvidenceDigests()
	if sourceEvidence[0] == retainedEvidence[0] {
		t.Fatal("source evidence getter aliases retained capability")
	}
	tamperedSource := secondValue.DurablePendingRevision
	tamperedSource.sourceEvidenceDigests = append([][ccse.DigestSize]byte(nil),
		tamperedSource.sourceEvidenceDigests...)
	tamperedSource.sourceEvidenceDigests[0][0] ^= 1
	if tamperedSource.VerifyDigest() == nil {
		t.Fatal("tampered source pending evidence accepted")
	}

	// Policy Sequence and per-sender CCSE replay counters are intentionally
	// independent. A fresh record by the same sender/key replaces one vote.
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	replacement := fixture.signedRecord(t, schema.MessageTypePolicyBundle, policyPurpose, fixture.profile.PolicyReplayDomainID,
		payload, fixture.keys["key-a"], testBaseTime+int64(time.Minute), 99, testID(0xe1), testID(0x61), foundationv1.OptionalFixedBytes16{})
	replaced, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: replacement,
	})
	if err != nil {
		t.Fatalf("fresh replay-counter replacement: %v", err)
	}
	replacedValue := replaced.Snapshot()
	if replacedValue.Disposition != ApprovalCollectionReplace || len(replacedValue.NextCollectionRecordDigestsSHA256) != 1 ||
		replacedValue.ExpectedReplacedRecordDigestSHA256 == ([ccse.DigestSize]byte{}) {
		t.Fatalf("bad replacement plan: %+v", replacedValue)
	}
}

func TestApprovalCollectionJoinedPairFailsClosedOnMixedState(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	joined, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	delete(fixture.idempotency.snapshots, joined.Key)
	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), command); !errors.Is(err, idempotency.ErrJoinedStateMismatch) {
		t.Fatalf("mixed pair error = %v", err)
	}
}

func TestApprovalCollectionAdmissionFingerprintRejectsRetainedIAMSubstitution(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	entry := fixture.collections.collections[binding.Key][0]
	entry.AdmissionKey.Roles = append(entry.AdmissionKey.Roles, "forged.role")
	fixture.collections.collections[binding.Key][0] = entry
	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), command); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("retained admission substitution error = %v", err)
	}
}

func TestApprovalCollectionRejectsSameDigestReactivationCarryover(t *testing.T) {
	fixture := newGovernanceFixture(t)
	cutover := testBaseTime + int64(15*time.Minute)
	oldActivation := GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: fixture.profileDigest, Version: 11,
		ValidFromUnixNano: 0, ValidUntilUnixNano: cutover, EvidenceDigestSHA256: testDigest(0xd1),
	}
	newActivation := GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: fixture.profileDigest, Version: 12,
		ValidFromUnixNano: cutover, ValidUntilUnixNano: testBaseTime + int64(24*time.Hour), EvidenceDigestSHA256: testDigest(0xd2),
	}
	fixture.profiles.activationAt = func(at int64) GovernanceProfileActivationSnapshot {
		if at < cutover {
			return oldActivation
		}
		return newActivation
	}
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), command); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("same-digest activation carryover error = %v", err)
	}
	if _, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
	}); !errors.Is(err, ErrKeyNotAuthorized) && !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("same-digest reactivation ingestion error = %v", err)
	}
}

func TestLegacyAdmissionCannotSucceedButCanTerminallyReconcile(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	entry := fixture.collections.collections[binding.Key][0]
	snapshot, err := bindVerifiedSignedRecord(entry.Signed, maxPayloadBytesFor(schema.MessageTypePolicyBundle))
	if err != nil {
		t.Fatal(err)
	}
	legacy := policyApproval{
		record: snapshot, admissionKey: cloneKeySnapshot(entry.AdmissionKey),
		admissionProfileDigest: entry.GovernanceProfileDigestSHA256, admissionValidatedAt: entry.ValidatedAtUnixNano,
		legacyAdmission: true,
	}
	entry.GovernanceProfileActivation = GovernanceProfileActivationSnapshot{}
	entry.AdmissionFingerprintSHA256, err = legacyPolicyApprovalAdmissionFingerprint(legacy)
	if err != nil {
		t.Fatal(err)
	}
	fixture.collections.collections[binding.Key][0] = entry

	retained := make([]policyApproval, 0, len(fixture.collections.collections[binding.Key]))
	for _, raw := range fixture.collections.collections[binding.Key] {
		approval, _, validateErr := fixture.planner.validatePolicyApprovalAdmission(context.Background(), raw)
		if validateErr != nil {
			t.Fatal(validateErr)
		}
		retained = append(retained, approval)
	}
	// Simulate the exact progress digest already stored by the V1 adapter. The
	// V2 success and terminal paths must reject it rather than pretending that
	// an activation row and canonical kind-7 pending predecessor were retained.
	progress, err := legacyApprovalCollectionDigest(binding, retained)
	if err != nil {
		t.Fatal(err)
	}
	parent := fixture.idempotency.snapshots[binding.Key]
	parent.ProgressDigest = progress
	fixture.idempotency.snapshots[binding.Key] = parent

	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), command); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("legacy admission success-path error = %v", err)
	}
	at := command.Approvals[0].Record.Domain.ExpiresAtUnixNano
	intent := fixture.reconciliationIntent(t, policy, command.Approvals, binding, at, 4)
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	_, err = fixture.planner.ReconcilePolicyOperation(context.Background(), PolicyReconcileCommand{
		AtUnixNano: at, Binding: binding, Outcome: 4, AuditEvent: audit.Event,
	})
	if !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("legacy terminal reconciliation error = %v", err)
	}
}

func TestApproversMayShareOneAuthorizationPolicyDigest(t *testing.T) {
	fixture := newGovernanceFixture(t)
	key := fixture.iam.keys["key-b"]
	key.AuthorizationPolicyDigestSHA256 = fixture.authA
	fixture.iam.keys["key-b"] = key
	privateKey := fixture.keys["key-b"]
	privateKey.snapshot.AuthorizationPolicyDigestSHA256 = fixture.authA
	fixture.keys["key-b"] = privateKey
	policy := fixture.normalPolicy()
	policy.Metadata.PolicyDigestsSHA256 = [][ccse.DigestSize]byte{fixture.authA, fixture.profileDigest}
	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy)); err != nil {
		t.Fatalf("shared authorization policy digest rejected: %v", err)
	}
}

func TestCompletedPolicyRetryReturnsStoredOutcomeWithinAuthorizationValidity(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	joined, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	outcome := testDigest(0xf7)
	parent := fixture.idempotency.snapshots[binding.Key]
	parent.State, parent.Version, parent.OutcomeDigest = idempotency.StateCompleted, parent.Version+1, outcome
	audit := fixture.idempotency.snapshots[joined.Key]
	audit.State, audit.Version, audit.OutcomeDigest = idempotency.StateCompleted, 2, outcome
	fixture.idempotency.snapshots[binding.Key] = parent
	fixture.idempotency.snapshots[joined.Key] = audit

	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), command); err == nil {
		t.Fatal("completed retry unexpectedly returned a new plan")
	} else {
		var duplicate DuplicateCompletedError
		if !errors.As(err, &duplicate) || duplicate.OutcomeDigestSHA256 != outcome {
			t.Fatalf("completed retry error = %v", err)
		}
	}
	if _, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
	}); err == nil {
		t.Fatal("completed ingestion retry unexpectedly returned a write plan")
	} else {
		var duplicate DuplicateCompletedError
		if !errors.As(err, &duplicate) || duplicate.OutcomeDigestSHA256 != outcome {
			t.Fatalf("completed ingestion retry error = %v", err)
		}
	}
}

func (f *governanceFixture) clearPolicyAdmission(policy foundationv1.PolicyBundleSigningProjection) {
	payload, _ := policy.CanonicalBytes()
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	joined, _ := idempotency.JoinedAuditBinding(binding)
	eventID, _ := idempotency.JoinedAuditEventID(binding)
	delete(f.collections.collections, binding.Key)
	delete(f.collections.persistence, binding.Key)
	delete(f.idempotency.snapshots, binding.Key)
	delete(f.idempotency.snapshots, joined.Key)
	delete(f.ids.ids, policy.PolicyBundleID)
	delete(f.ids.ids, policy.Metadata.RecordID)
	delete(f.ids.ids, eventID)
}

func (f *governanceFixture) applyApprovalCollectionPlan(t testing.TB, plan ApprovalCollectionPlanSnapshot, signed SignedRecord) {
	t.Helper()
	for _, claim := range plan.Claims {
		f.idempotency.snapshots[claim.Binding.Key] = idempotency.Snapshot{
			Binding: claim.Binding, State: claim.NextState, Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest,
		}
	}
	for _, claim := range plan.IdentifierClaims {
		if claim.Mode != globalid.ReserveNew {
			t.Fatalf("first admission claim is not a reservation: %+v", claim)
		}
		f.ids.ids[claim.Identifier] = globalid.Snapshot{Identifier: claim.Identifier, Owner: claim.Owner, Version: claim.NextVersion}
	}
	record := cloneCCSERecord(signed.Record)
	f.iam.historical[plan.NextAdmissionKey.KeyID] = cloneKeySnapshot(plan.NextAdmissionKey)
	f.collections.collections[plan.Binding.Key] = []PolicyApprovalCollectionEntry{{
		Signed: SignedRecord{Record: &record, Verified: signed.Verified}, AdmissionKey: cloneKeySnapshot(plan.NextAdmissionKey),
		GovernanceProfileDigestSHA256: plan.NextAdmissionProfileDigestSHA256,
		GovernanceProfileActivation:   plan.NextAdmissionProfileActivation,
		ValidatedAtUnixNano:           plan.NextAdmissionValidatedAtUnixNano,
		AdmissionFingerprintSHA256:    plan.NextAdmissionFingerprintSHA256,
	}}
	pending := plan.DurablePendingRevision
	if pending.VerifyDigest() != nil {
		t.Fatal("invalid durable pending revision")
	}
	commitNotBefore, commitNotAfter := pending.CommitWindow()
	outcome, _ := pending.TerminalOutcomeDigest()
	f.collections.persistence[plan.Binding.Key] = PolicyApprovalCollectionPersistenceSnapshot{
		PendingKey: pending.PendingKey(), Kind: pending.Kind(), Codec: pending.Codec(),
		CodecVersion: pending.CodecVersion(), Revision: pending.Revision(),
		PreviousEnvelopeDigestSHA256: pending.PreviousEnvelopeDigest(),
		EnvelopeDigestSHA256:         pending.EnvelopeDigest(), CanonicalEnvelope: pending.CanonicalEnvelope(),
		EvidenceDigestsSHA256: pending.EvidenceDigests(), Status: pending.Status(),
		CommitNotBeforeUnixNano: commitNotBefore, CommitNotAfterUnixNano: commitNotAfter,
		TerminalOutcomeDigestSHA256: outcome, ExpectedAuditEventID: pending.ExpectedAuditEventID(),
	}
}
