// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func TestPolicyStateMachineSupportsRegionFailoverActivateAndExpire(t *testing.T) {
	fixture := newGovernanceFixture(t)
	delayed := fixture.normalPolicy()
	delayed.EffectiveAtUnixNano = testBaseTime + int64(time.Hour)
	delayed.ExpiresAtUnixNano = testBaseTime + int64(5*time.Hour)
	delayed.Metadata.HomeRegion = "us-old-1"
	delayed.Metadata.WriterEpoch = 1
	delayedRecord := fixture.policyRecordFromProjection(t, delayed, nil)
	fixture.setPolicyHistory(delayedRecord)

	// An authoritative lease moves to a new region/epoch while the immutable
	// head remains in its original region and epoch.
	fixture.policies.snapshot.AuthorizedHomeRegion = fixture.profile.PolicyHomeRegion
	fixture.policies.snapshot.AuthorizedWriterEpoch = 2
	fixture.policies.snapshot.WriterLeaseEvidenceDigestSHA256 = testDigest(0x47)

	active := policyTransition(t, delayed, PolicyStateActive, 2, "policy-record-2", delayed.EffectiveAtUnixNano, 2, fixture.profile.PolicyHomeRegion)
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommandAt(t, active, active.EffectiveAtUnixNano, active.EffectiveAtUnixNano))
	if err != nil {
		t.Fatalf("activate after writer failover: %v", err)
	}
	activation := pending.PolicySnapshot()
	if activation.Kind != MutationPolicyActivate || activation.ExpectedPolicyHeadWriterEpoch != 1 ||
		activation.AuthorizedPolicyWriterEpoch != 2 || activation.ExpectedPolicyHeadHomeRegion != "us-old-1" ||
		activation.AuthorizedPolicyHomeRegion != fixture.profile.PolicyHomeRegion {
		t.Fatalf("bad failover fence: %+v", activation)
	}

	activeRecord := fixture.policyRecordFromProjection(t, active, nil)
	fixture.setPolicyHistory(delayedRecord, activeRecord)
	expired := policyTransition(t, active, PolicyStateExpired, 3, "policy-record-3", active.ExpiresAtUnixNano, 2, fixture.profile.PolicyHomeRegion)
	pending, err = fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommandAt(t, expired, expired.ExpiresAtUnixNano, expired.ExpiresAtUnixNano))
	if err != nil {
		t.Fatalf("signed expiry transition: %v", err)
	}
	if got := pending.PolicySnapshot(); got.Kind != MutationPolicyExpire || got.CommitNotBeforeUnixNano < expired.ExpiresAtUnixNano {
		t.Fatalf("bad expiry plan: %+v", got)
	}
}

func TestDelayedPolicyCanBeRevokedBeforeEffectiveTime(t *testing.T) {
	fixture := newGovernanceFixture(t)
	delayed := fixture.normalPolicy()
	delayedRecord := fixture.policyRecordFromProjection(t, delayed, nil)
	fixture.setPolicyHistory(delayedRecord)
	revokedAt := delayed.ApprovedAtUnixNano + int64(30*time.Minute)
	revoked := policyTransition(t, delayed, PolicyStateRevoked, 2, "policy-record-2", revokedAt, 1, fixture.profile.PolicyHomeRegion)
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommandAt(t, revoked, revokedAt, revokedAt))
	if err != nil {
		t.Fatalf("pre-effective revocation: %v", err)
	}
	if got := pending.PolicySnapshot(); got.Kind != MutationPolicyRevoke || got.CommitNotBeforeUnixNano > revokedAt {
		t.Fatalf("bad pre-effective revocation plan: %+v", got)
	}

	rolledBack := policyTransition(t, delayed, PolicyStateRolledBack, 2, "policy-record-rollback", delayed.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	rolledBack.Metadata.IdempotencyKey = testID(0x6e)
	rolledBack.RollbackTargetDigestSHA256 = foundationv1.OptionalFixedBytes32{Present: true, Value: testDigest(0xed)}
	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommandAt(t, rolledBack,
		rolledBack.EffectiveAtUnixNano, rolledBack.EffectiveAtUnixNano)); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("delayed-to-rollback transition error = %v", err)
	}
}

func TestPolicyHistoryRejectsRegionChangeWithoutEpochAdvance(t *testing.T) {
	fixture := newGovernanceFixture(t)
	delayed := fixture.normalPolicy()
	delayed.EffectiveAtUnixNano = testBaseTime + int64(time.Hour)
	delayed.Metadata.HomeRegion = "us-old-1"
	delayedRecord := fixture.policyRecordFromProjection(t, delayed, nil)
	active := policyTransition(t, delayed, PolicyStateActive, 2, "policy-record-2", delayed.EffectiveAtUnixNano, 1, "eu-new-1")
	activeRecord := fixture.policyRecordFromProjection(t, active, nil)
	fixture.setPolicyHistory(delayedRecord, activeRecord)
	fixture.policies.snapshot.AuthorizedWriterEpoch = 2
	fixture.policies.snapshot.AuthorizedHomeRegion = fixture.profile.PolicyHomeRegion
	if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), delayed.PolicyKind, fixture.policies.snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
		t.Fatalf("same-epoch region change error = %v", err)
	}
}

func TestRollbackTargetEligibilityAndCommitDeadline(t *testing.T) {
	fixture := newGovernanceFixture(t)
	targetDelayed := fixture.normalPolicy()
	targetDelayed.EffectiveAtUnixNano = testBaseTime + int64(time.Hour)
	targetDelayed.ExpiresAtUnixNano = testBaseTime + int64(2*time.Hour+5*time.Minute)
	targetDelayedRecord := fixture.policyRecordFromProjection(t, targetDelayed, nil)
	targetActive := policyTransition(t, targetDelayed, PolicyStateActive, 2, "policy-record-2", targetDelayed.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	targetActiveRecord := fixture.policyRecordFromProjection(t, targetActive, nil)

	nextDelayed := fixture.normalPolicy()
	nextDelayed.PolicyBundleID = "policy-bundle-2"
	nextDelayed.Metadata.RecordID = "policy-record-3"
	nextDelayed.Metadata.IdempotencyKey = testID(0x53)
	nextDelayed.Metadata.StateVersion = 3
	nextDelayed.Sequence = 3
	nextDelayed.PredecessorDigestSHA256 = foundationv1.OptionalFixedBytes32{Present: true, Value: targetActiveRecord.BundleDigestSHA256}
	nextDelayed.PolicyVersion.Minor = 1
	nextDelayed.ApprovedAtUnixNano = testBaseTime + int64(time.Hour)
	nextDelayed.EffectiveAtUnixNano = testBaseTime + int64(2*time.Hour)
	nextDelayed.ExpiresAtUnixNano = testBaseTime + int64(8*time.Hour)
	nextDelayed.Metadata.CreatedAtUnixNano = nextDelayed.ApprovedAtUnixNano
	nextDelayedRecord := fixture.policyRecordFromProjection(t, nextDelayed, nil)
	nextActive := policyTransition(t, nextDelayed, PolicyStateActive, 4, "policy-record-4", nextDelayed.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	nextActiveRecord := fixture.policyRecordFromProjection(t, nextActive, nil)
	fixture.setPolicyHistory(targetDelayedRecord, targetActiveRecord, nextDelayedRecord, nextActiveRecord)

	rollback := policyTransition(t, nextActive, PolicyStateRolledBack, 5, "policy-record-5", nextActive.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	rollback.RollbackTargetDigestSHA256 = foundationv1.OptionalFixedBytes32{Present: true, Value: targetActiveRecord.BundleDigestSHA256}
	command := fixture.policyCommandAt(t, rollback, rollback.EffectiveAtUnixNano, rollback.EffectiveAtUnixNano)
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := pending.PolicySnapshot(); got.Kind != MutationPolicyRollback || got.CommitNotAfterUnixNano != targetActive.ExpiresAtUnixNano {
		t.Fatalf("rollback target deadline not fenced: %+v", got)
	}

	late := fixture.policyCommandAt(t, rollback, targetActive.ExpiresAtUnixNano, targetActive.ExpiresAtUnixNano)
	if _, err := fixture.planner.PlanPolicyApproval(context.Background(), late); !errors.Is(err, ErrRollbackTarget) {
		t.Fatalf("expired rollback target error = %v", err)
	}
}

func TestPolicySnapshotRejectsGapPayloadSubstitutionAndReusedTerminalRollback(t *testing.T) {
	fixture := newGovernanceFixture(t)
	delayed := fixture.normalPolicy()
	delayed.EffectiveAtUnixNano = testBaseTime + int64(time.Hour)
	delayed.ExpiresAtUnixNano = testBaseTime + int64(6*time.Hour)
	r1 := fixture.policyRecordFromProjection(t, delayed, nil)
	active := policyTransition(t, delayed, PolicyStateActive, 2, "policy-record-2", delayed.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	r2 := fixture.policyRecordFromProjection(t, active, nil)
	fixture.setPolicyHistory(r1, r2)

	t.Run("canonical payload substitution", func(t *testing.T) {
		snapshot := clonePolicyRegistrySnapshot(fixture.policies.snapshot)
		snapshot.Records[0].CanonicalPayload[0] ^= 0xff
		if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), delayed.PolicyKind, snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("sequence gap", func(t *testing.T) {
		snapshot := clonePolicyRegistrySnapshot(fixture.policies.snapshot)
		snapshot.Records[1].Sequence = 3
		snapshot.Head = snapshot.Records[1]
		if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), delayed.PolicyKind, snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("error = %v", err)
		}
	})

	// An ACTIVE target made terminal before a later lifecycle cannot be
	// selected again by a fabricated historical rollback.
	revoked := policyTransition(t, active, PolicyStateRevoked, 3, "policy-record-3", testBaseTime+int64(90*time.Minute), 1, fixture.profile.PolicyHomeRegion)
	r3 := fixture.policyRecordFromProjection(t, revoked, nil)
	next := fixture.normalPolicy()
	next.PolicyBundleID, next.Metadata.RecordID = "policy-bundle-2", "policy-record-4"
	next.Metadata.IdempotencyKey, next.Metadata.StateVersion = testID(0x54), 4
	next.Sequence = 4
	next.PredecessorDigestSHA256 = foundationv1.OptionalFixedBytes32{Present: true, Value: r3.BundleDigestSHA256}
	next.PolicyVersion.Minor = 1
	next.ApprovedAtUnixNano = testBaseTime + int64(2*time.Hour)
	next.EffectiveAtUnixNano = testBaseTime + int64(3*time.Hour)
	next.ExpiresAtUnixNano = testBaseTime + int64(8*time.Hour)
	next.Metadata.CreatedAtUnixNano = next.ApprovedAtUnixNano
	r4 := fixture.policyRecordFromProjection(t, next, nil)
	nextActive := policyTransition(t, next, PolicyStateActive, 5, "policy-record-5", next.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	r5 := fixture.policyRecordFromProjection(t, nextActive, nil)
	rollback := policyTransition(t, nextActive, PolicyStateRolledBack, 6, "policy-record-6", nextActive.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	rollback.RollbackTargetDigestSHA256 = foundationv1.OptionalFixedBytes32{Present: true, Value: r2.BundleDigestSHA256}
	r6 := fixture.policyRecordFromProjection(t, rollback, nil)
	fixture.setPolicyHistory(r1, r2, r3, r4, r5, r6)
	if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), delayed.PolicyKind, fixture.policies.snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
		t.Fatalf("terminal rollback target history error = %v", err)
	}
}

func policyTransition(t testing.TB, previous foundationv1.PolicyBundleSigningProjection, state uint32, sequence uint64,
	recordID string, createdAt int64, writerEpoch uint64, homeRegion string) foundationv1.PolicyBundleSigningProjection {
	t.Helper()
	payload, err := previous.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	next := previous
	next.Metadata.RecordID = recordID
	next.Metadata.CreatedAtUnixNano = createdAt
	next.Metadata.HomeRegion = homeRegion
	next.Metadata.WriterEpoch = writerEpoch
	next.Metadata.StateVersion = sequence
	next.Metadata.IdempotencyKey = testID(byte(0x50 + sequence))
	next.Sequence = sequence
	next.PredecessorDigestSHA256 = foundationv1.OptionalFixedBytes32{Present: true, Value: sha256Digest(payload)}
	next.RollbackTargetDigestSHA256 = foundationv1.OptionalFixedBytes32{}
	next.State = state
	return next
}

func sha256Digest(value []byte) [ccse.DigestSize]byte {
	return sha256.Sum256(value)
}
