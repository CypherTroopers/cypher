// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func TestReconcilePolicyOperationClosesJoinedPairWithoutPolicyMutation(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	rotated := fixture.iam.keys["key-a"]
	rotated.RevokedAtUnixNano = testBaseTime + int64(45*time.Minute)
	rotated.LifecycleState = 3
	rotated.StateVersion++
	rotated.SnapshotDigestSHA256 = testDigest(0xf5)
	fixture.iam.keys["key-a"] = rotated
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	at := command.Approvals[0].Record.Domain.ExpiresAtUnixNano
	intent := fixture.reconciliationIntent(t, policy, command.Approvals, binding, at, 4)
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)

	plan, err := fixture.planner.ReconcilePolicyOperation(context.Background(), PolicyReconcileCommand{
		AtUnixNano: at, Binding: binding, Outcome: 4, AuditEvent: audit.Event,
	})
	if err != nil {
		t.Fatalf("ReconcilePolicyOperation: %v", err)
	}
	got := plan.Snapshot()
	if !plan.CommitReady() || plan.VerifyDigest() != nil || got.Kind != MutationPolicyAbort ||
		got.ExpectedPolicyHeadPresent || got.ExpectedPolicyHeadSequence != 0 || got.ExpectedPolicyHeadDigest != ([ccse.DigestSize]byte{}) ||
		len(got.IdempotencyClaims) != 2 || got.IdempotencyOutcome != 4 || got.AuditEventID != intent.AuditEventID {
		t.Fatalf("unexpected reconciliation plan: %+v", got)
	}
	for _, claim := range got.IdempotencyClaims {
		if claim.Mode != idempotency.CompleteCollection {
			t.Fatalf("reconciliation did not complete both rows: %+v", got.IdempotencyClaims)
		}
	}

	_, err = fixture.planner.ReconcilePolicyOperation(context.Background(), PolicyReconcileCommand{
		AtUnixNano: at - 1, Binding: binding, Outcome: 4, AuditEvent: audit.Event,
	})
	if !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("early reconciliation error = %v", err)
	}
}

func TestReconcileUsesProfileActiveWhenApprovalWasIssued(t *testing.T) {
	fixture := newGovernanceFixture(t)
	oldProfile := cloneProfile(fixture.profile)
	oldProfile.MinActivationDelayNanos = int64(30 * time.Minute)
	oldDigest, err := ProfileDigest(oldProfile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.profiles.profiles[oldDigest] = oldProfile
	cutover := testBaseTime + int64(time.Hour)
	oldActivation := GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: oldDigest, Version: 3, ValidFromUnixNano: 0, ValidUntilUnixNano: cutover,
		EvidenceDigestSHA256: testDigest(0xe1),
	}
	currentActivation := GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: fixture.profileDigest, Version: 4, ValidFromUnixNano: cutover, ValidUntilUnixNano: math.MaxInt64,
		EvidenceDigestSHA256: testDigest(0xe2),
	}
	fixture.profiles.activationAt = func(at int64) GovernanceProfileActivationSnapshot {
		if at < cutover {
			return oldActivation
		}
		return currentActivation
	}

	policy := fixture.normalPolicy()
	policy.Metadata.PolicyDigestsSHA256 = [][ccse.DigestSize]byte{fixture.authA, fixture.authB, oldDigest}
	command := fixture.policyCommand(t, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	at := cutover
	intent := fixture.reconciliationIntent(t, policy, command.Approvals, binding, at, 4)
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	if _, err := fixture.planner.ReconcilePolicyOperation(context.Background(), PolicyReconcileCommand{
		AtUnixNano: at, Binding: binding, Outcome: 4, AuditEvent: audit.Event,
	}); err != nil {
		t.Fatalf("profile rotation stranded reconciliation: %v", err)
	}

	// Reinterpreting the old signature under the new profile at its issuance
	// time is forbidden even though the current audit writer remains valid.
	fixture.profiles.activationAt = func(int64) GovernanceProfileActivationSnapshot { return currentActivation }
	if _, err := fixture.planner.ReconcilePolicyOperation(context.Background(), PolicyReconcileCommand{
		AtUnixNano: at, Binding: binding, Outcome: 4, AuditEvent: audit.Event,
	}); !errors.Is(err, ErrApprovalSetMismatch) && !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("profile timeline splice error = %v", err)
	}
}

func (f *governanceFixture) reconciliationIntent(t testing.TB, projection foundationv1.PolicyBundleSigningProjection,
	records []SignedRecord, binding idempotency.Binding, at int64, outcome uint32) AuditIntentSnapshot {
	t.Helper()
	sources := make([][ccse.DigestSize]byte, 0, len(records)+2)
	for _, record := range records {
		digest, digestErr := record.Record.Digest(ccse.DefaultLimits())
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		sources = append(sources, digest)
	}
	sources = uniqueSortedDigests(append(sources, binding.RequestDigest, projection.PolicyDocumentDigestSHA256))
	joined, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := idempotency.JoinedAuditEventID(binding)
	if err != nil {
		t.Fatal(err)
	}
	eventType, cause := "PolicyMutationFailed", "policy-mutation-failed"
	if outcome == 4 {
		eventType, cause = "PolicyMutationTimedOut", "policy-operation-deadline-exceeded"
	}
	return AuditIntentSnapshot{
		Required: true, StreamID: f.profile.AuditReplayDomainID, EventType: eventType, AuditEventID: eventID,
		ActorIdentity: f.profile.AuditWriterIdentity, ActorKeyID: f.profile.AuditWriterKeyID,
		SubjectIDs: uniqueSortedStrings([]string{projection.PolicyBundleID, projection.Metadata.RecordID}), CauseCode: cause,
		OccurredAtUnixNano: at, Outcome: outcome, IdempotencyKey: joined.Key,
		CorrelationID: records[0].Record.Envelope.CorrelationID, CausationID: records[0].Record.Envelope.CausationID,
		AppliedPolicyDigestsSHA256: uniqueSortedDigests(append(append([][ccse.DigestSize]byte(nil), projection.Metadata.PolicyDigestsSHA256...), f.profileDigest)),
		EvidenceDigestsSHA256:      sources,
	}
}
