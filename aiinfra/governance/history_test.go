// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func TestPolicyHistoryUsesAuthoritativeProfileTimeline(t *testing.T) {
	fixture := newGovernanceFixture(t)
	oldProfile := cloneProfile(fixture.profile)
	oldProfile.MinActivationDelayNanos = int64(30 * time.Minute)
	oldDigest, err := ProfileDigest(oldProfile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.profiles.profiles[oldDigest] = oldProfile
	cutover := testBaseTime + int64(time.Hour)
	fixture.profiles.activeAt = func(at int64) [ccse.DigestSize]byte {
		if at < cutover {
			return oldDigest
		}
		return fixture.profileDigest
	}

	policy := fixture.normalPolicy()
	policy.EffectiveAtUnixNano = policy.ApprovedAtUnixNano + int64(45*time.Minute)
	policy.Metadata.PolicyDigestsSHA256 = [][ccse.DigestSize]byte{fixture.authA, fixture.authB, oldDigest}
	record := fixture.policyRecordFromProjection(t, policy, nil)
	record.GovernanceProfileDigestSHA256 = oldDigest
	record.AcceptanceEvidence.GovernanceProfileDigestSHA256 = oldDigest
	fixture.setPolicyHistory(record)
	if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, fixture.policies.snapshot); err != nil {
		t.Fatalf("valid old-profile history rejected after tightening: %v", err)
	}

	fixture.profiles.activeAt = func(int64) [ccse.DigestSize]byte { return fixture.profileDigest }
	if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, fixture.policies.snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
		t.Fatalf("self-selected historical profile error = %v", err)
	}
}

func TestPolicyHistoryBindsExactActivationRows(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	record := fixture.policyRecordFromProjection(t, policy, nil)
	fixture.setPolicyHistory(record)
	if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, fixture.policies.snapshot); err != nil {
		t.Fatal(err)
	}

	t.Run("acceptance reactivation", func(t *testing.T) {
		snapshot := clonePolicyRegistrySnapshot(fixture.policies.snapshot)
		snapshot.Records[0].AcceptanceEvidence.GovernanceProfileActivation.Version++
		snapshot.Records[0].AcceptanceEvidence.GovernanceProfileActivation.EvidenceDigestSHA256 = testDigest(0xe8)
		snapshot.Head = snapshot.Records[0]
		if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("same-digest acceptance reactivation error = %v", err)
		}
	})

	t.Run("approval activation", func(t *testing.T) {
		snapshot := clonePolicyRegistrySnapshot(fixture.policies.snapshot)
		snapshot.Records[0].ApprovalEvidence[0].GovernanceProfileActivation.Version++
		snapshot.Records[0].ApprovalEvidence[0].GovernanceProfileActivation.EvidenceDigestSHA256 = testDigest(0xe9)
		snapshot.Head = snapshot.Records[0]
		if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("approval activation substitution error = %v", err)
		}
	})
}

func TestHistoricalBreakGlassScopeUsesProfileActiveAtAcceptance(t *testing.T) {
	fixture := newGovernanceFixture(t)
	oldProfile := cloneProfile(fixture.profile)
	oldDigest := fixture.profileDigest
	currentProfile := cloneProfile(oldProfile)
	currentProfile.AllowedBreakGlassScopes = []string{"new-mining.disable"}
	currentDigest, err := ProfileDigest(currentProfile)
	if err != nil {
		t.Fatal(err)
	}
	cutover := testBaseTime + int64(time.Hour)
	fixture.profile, fixture.profileDigest = currentProfile, currentDigest
	fixture.policies.snapshot.GovernanceProfileDigestSHA256 = currentDigest
	fixture.audit.head.AuthorizedGovernanceProfileDigestSHA256 = currentDigest
	fixture.profiles.profiles = map[[ccse.DigestSize]byte]Profile{oldDigest: oldProfile, currentDigest: currentProfile}
	fixture.profiles.activeAt = func(at int64) [ccse.DigestSize]byte {
		if at < cutover {
			return oldDigest
		}
		return currentDigest
	}
	fixture.planner, err = NewPlanner(fixture.iam, fixture.policies, fixture.profiles, fixture.collections, fixture.ids,
		fixture.idempotency, fixture.documents, fixture.evidence, fixture.audit, currentProfile)
	if err != nil {
		t.Fatal(err)
	}
	policy := fixture.normalPolicy()
	policy.Metadata.PolicyDigestsSHA256 = [][ccse.DigestSize]byte{fixture.authA, fixture.authB, oldDigest}
	policy.State, policy.Emergency, policy.EffectiveAtUnixNano = PolicyStateActive, true, testBaseTime
	policy.ExpiresAtUnixNano = testBaseTime + int64(2*time.Hour)
	policy.BreakGlassExpiresAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: policy.ExpiresAtUnixNano}
	record := fixture.policyRecordFromProjection(t, policy, []string{"market.pause"})
	record.GovernanceProfileDigestSHA256 = oldDigest
	record.AcceptanceEvidence.GovernanceProfileDigestSHA256 = oldDigest
	fixture.setPolicyHistory(record)
	if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, fixture.policies.snapshot); err != nil {
		t.Fatalf("historical emergency was reinterpreted under tightened scopes: %v", err)
	}
}

func TestPolicyHistoryReplaysStateSpecificAcceptanceWindows(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PolicyRecordSnapshot)
	}{
		{"delayed accepted at effective time", func(record *PolicyRecordSnapshot) {
			record.AcceptanceEvidence.AcceptedAtUnixNano = record.EffectiveAtUnixNano
		}},
		{"delayed accepted after expiry", func(record *PolicyRecordSnapshot) {
			record.AcceptanceEvidence.AcceptedAtUnixNano = record.ExpiresAtUnixNano
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGovernanceFixture(t)
			policy := fixture.normalPolicy()
			record := fixture.policyRecordFromProjection(t, policy, nil)
			test.mutate(&record)
			fixture.setPolicyHistory(record)
			if err := fixture.planner.validatePolicyRegistrySnapshot(context.Background(), policy.PolicyKind, fixture.policies.snapshot); !errors.Is(err, ErrSnapshotInconsistent) {
				t.Fatalf("invalid acceptance window error = %v", err)
			}
		})
	}
}

func TestHistoricalAcceptanceWindowTable(t *testing.T) {
	record := PolicyRecordSnapshot{
		ApprovedAtUnixNano: 100, EffectiveAtUnixNano: 200, ExpiresAtUnixNano: 300,
		BreakGlassExpiresAtUnixNano: 300,
	}
	tests := []struct {
		state uint32
		at    int64
		want  bool
	}{
		{PolicyStateApprovedDelayed, 199, true}, {PolicyStateApprovedDelayed, 200, false},
		{PolicyStateActive, 199, false}, {PolicyStateActive, 200, true}, {PolicyStateActive, 300, false},
		{PolicyStateRolledBack, 200, true}, {PolicyStateRolledBack, 300, false},
		{PolicyStateRevoked, 100, true}, {PolicyStateRevoked, 199, true}, {PolicyStateRevoked, 300, false},
		{PolicyStateExpired, 299, false}, {PolicyStateExpired, 300, true},
	}
	for _, test := range tests {
		record.State = test.state
		if got := validHistoricalAcceptanceTime(record, test.at); got != test.want {
			t.Fatalf("state=%d at=%d got=%v want=%v", test.state, test.at, got, test.want)
		}
	}
}

func TestPolicyRegistryPreflightBoundsAggregateHistoricalApprovals(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	base := fixture.policyRecordFromProjection(t, policy, nil)
	retained := base.ApprovalEvidence[0]
	base.ApprovalEvidence = make([]HistoricalPolicyApprovalEvidence, maxApprovals)
	for index := range base.ApprovalEvidence {
		base.ApprovalEvidence[index] = retained
	}
	snapshot := fixture.policies.snapshot
	snapshot.HeadPresent = true
	snapshot.Head = base
	snapshot.Records = make([]PolicyRecordSnapshot, 129)
	for index := range snapshot.Records {
		snapshot.Records[index] = base
	}
	if fixture.planner.preflightPolicyRegistrySnapshot(snapshot) {
		t.Fatal("aggregate history evidence above the fixed bound passed preflight")
	}
}
