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
)

type semanticOnlyProfileCatalog struct{ source *testProfileCatalog }

type substitutingProfileCatalog struct{ source *testProfileCatalog }

type semanticOnlyIAMView struct{ source *testIAMView }

func (v semanticOnlyIAMView) ResolveGovernanceKey(ctx context.Context, keyID string) (GovernanceKeySnapshot, error) {
	return v.source.ResolveGovernanceKey(ctx, keyID)
}
func (v semanticOnlyIAMView) ResolveGovernanceKeyAt(ctx context.Context, keyID string,
	at int64) (GovernanceKeySnapshot, bool, error) {
	return v.source.ResolveGovernanceKeyAt(ctx, keyID, at)
}

func (v semanticOnlyProfileCatalog) ResolveGovernanceProfile(ctx context.Context,
	digest [ccse.DigestSize]byte) (Profile, bool, error) {
	return v.source.ResolveGovernanceProfile(ctx, digest)
}
func (v semanticOnlyProfileCatalog) ActiveGovernanceProfile(ctx context.Context,
	at int64) (GovernanceProfileActivationSnapshot, bool, error) {
	return v.source.ActiveGovernanceProfile(ctx, at)
}

func (v substitutingProfileCatalog) ResolveGovernanceProfile(ctx context.Context,
	digest [ccse.DigestSize]byte) (Profile, bool, error) {
	return v.source.ResolveGovernanceProfile(ctx, digest)
}
func (v substitutingProfileCatalog) ActiveGovernanceProfile(ctx context.Context,
	at int64) (GovernanceProfileActivationSnapshot, bool, error) {
	return v.source.ActiveGovernanceProfile(ctx, at)
}
func (v substitutingProfileCatalog) CanonicalGovernanceProfileActivation(ctx context.Context,
	activation GovernanceProfileActivationSnapshot) (CanonicalStateRecord, bool, error) {
	record, found, err := v.source.CanonicalGovernanceProfileActivation(ctx, activation)
	if err == nil && found {
		record.CanonicalState = append(record.CanonicalState, 0)
		record.StateDigestSHA256 = domainSeparatedContentDigest(canonicalProfileActivationDomain,
			record.CanonicalState)
	}
	return record, found, err
}

type semanticOnlyPolicyView struct{ source *testPolicyView }

type substitutingPolicyView struct{ source *testPolicyView }

func (v semanticOnlyPolicyView) SnapshotPolicy(ctx context.Context, kind string) (PolicyRegistrySnapshot, error) {
	return v.source.SnapshotPolicy(ctx, kind)
}

func (v substitutingPolicyView) SnapshotPolicy(ctx context.Context, kind string) (PolicyRegistrySnapshot, error) {
	return v.source.SnapshotPolicy(ctx, kind)
}
func (v substitutingPolicyView) CanonicalGovernancePolicyRegistryTransition(ctx context.Context,
	request CanonicalPolicyRegistryTransition) (CanonicalStateRecord, bool, CanonicalStateRecord, error) {
	expected, found, next, err := v.source.CanonicalGovernancePolicyRegistryTransition(ctx, request)
	if err == nil {
		next.CanonicalState = append(next.CanonicalState, 0)
		next.StateDigestSHA256 = sha256.Sum256(next.CanonicalState)
	}
	return expected, found, next, err
}

type semanticOnlyAuditView struct{ source *testAuditView }

func (v semanticOnlyAuditView) SnapshotAuditHead(ctx context.Context, streamID string) (AuditHeadSnapshot, error) {
	return v.source.SnapshotAuditHead(ctx, streamID)
}
func (v semanticOnlyAuditView) LookupAuditEvent(ctx context.Context,
	eventID string) (AuditEventSnapshot, bool, error) {
	return v.source.LookupAuditEvent(ctx, eventID)
}

type substitutingAuditLeaseView struct{ source *testAuditView }

func (v substitutingAuditLeaseView) SnapshotAuditHead(ctx context.Context, streamID string) (AuditHeadSnapshot, error) {
	return v.source.SnapshotAuditHead(ctx, streamID)
}
func (v substitutingAuditLeaseView) LookupAuditEvent(ctx context.Context,
	eventID string) (AuditEventSnapshot, bool, error) {
	return v.source.LookupAuditEvent(ctx, eventID)
}
func (v substitutingAuditLeaseView) CanonicalAuditWriterLease(ctx context.Context,
	requirement CanonicalAuditWriterLeaseRequirement) (CanonicalStateRecord, bool, error) {
	requirement.WriterLeaseEntityID += "-unrelated"
	return v.source.CanonicalAuditWriterLease(ctx, requirement)
}

type semanticOnlyApprovalCollectionView struct{ source *testApprovalCollectionView }

func (v semanticOnlyApprovalCollectionView) SnapshotPolicyApprovalCollection(ctx context.Context,
	key [ccse.MessageIDSize]byte) ([]PolicyApprovalCollectionEntry, error) {
	return v.source.SnapshotPolicyApprovalCollection(ctx, key)
}

func TestCanonicalStateCapabilitiesAreExactOwnedAndTamperEvident(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
		pending.AuditIntent().Snapshot())
	plan, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending,
		PolicyFinalizeCommand{AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event})
	if err != nil || plan.VerifyDigest() != nil {
		t.Fatalf("finalize = %v / %v", err, plan.VerifyDigest())
	}
	snapshot := plan.Snapshot()
	if len(snapshot.CanonicalStateAssertions) != 1 || len(snapshot.CanonicalStateMutations) != 1 {
		t.Fatalf("canonical state capabilities = %#v / %#v",
			snapshot.CanonicalStateAssertions, snapshot.CanonicalStateMutations)
	}
	if len(snapshot.CanonicalKeyStateAssertions) == 0 {
		t.Fatal("canonical key read set is absent")
	}
	for _, keyAssertion := range snapshot.CanonicalKeyStateAssertions {
		if keyAssertion.VerifyDigest() != nil || len(keyAssertion.Records()) != 3 {
			t.Fatalf("canonical key assertion = %#v", keyAssertion)
		}
	}
	writerLease := snapshot.CanonicalAuditWriterLeaseAssertion
	if writerLease.VerifyDigest() != nil || writerLease.Requirement() !=
		auditWriterLeaseRequirement(fixture.audit.head, fixture.keys["key-audit"].snapshot) {
		t.Fatal("canonical audit writer lease assertion is invalid")
	}
	writerLeaseRecord := writerLease.Record()
	if writerLeaseRecord.Namespace != CanonicalStateNamespaceIAM ||
		writerLeaseRecord.Kind != CanonicalStateKindIAMWriterLease ||
		writerLeaseRecord.Version != fixture.audit.head.AuthorizedWriterEpoch {
		t.Fatalf("canonical audit writer lease row = %#v", writerLeaseRecord)
	}
	assertion := snapshot.CanonicalStateAssertions[0]
	if assertion.VerifyDigest() != nil || assertion.Record().Kind != CanonicalStateKindGovernanceProfileActivation {
		t.Fatal("profile activation assertion is invalid")
	}
	mutation := snapshot.CanonicalStateMutations[0]
	if mutation.VerifyDigest() != nil {
		t.Fatal("policy mutation is invalid")
	}
	if _, present := mutation.Expected(); present {
		t.Fatal("initial policy mutation unexpectedly has an expected row")
	}
	next := mutation.Next()
	if next.Kind != CanonicalStateKindGovernancePolicyRegistry || next.ObjectID != fixture.normalPolicy().PolicyKind ||
		next.Version != 1 || next.AuditEventID != snapshot.AuditEventID {
		t.Fatalf("next canonical policy row = %#v", next)
	}
	next.CanonicalState[0] ^= 1
	if next.CanonicalState[0] == mutation.Next().CanonicalState[0] {
		t.Fatal("canonical mutation getter aliases retained bytes")
	}

	tamperedAssertion := plan.Snapshot()
	tamperedAssertion.CanonicalStateAssertions[0].record.CanonicalState[0] ^= 1
	if (MutationPlan{value: tamperedAssertion, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered canonical assertion retained the plan capability")
	}
	tamperedMutation := plan.Snapshot()
	tamperedMutation.CanonicalStateMutations[0].next.CanonicalState[0] ^= 1
	if (MutationPlan{value: tamperedMutation, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered canonical mutation retained the plan capability")
	}
	tamperedKey := plan.Snapshot()
	tamperedKey.CanonicalKeyStateAssertions[0].records[1].record.CanonicalState[0] ^= 1
	if (MutationPlan{value: tamperedKey, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered canonical key row retained the plan capability")
	}
	tamperedIdentityKey := plan.Snapshot()
	tamperedIdentityKey.CanonicalKeyStateAssertions[0].records[2].record.ObjectID += "-other"
	if (MutationPlan{value: tamperedIdentityKey, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("substituted canonical identity row key retained the plan capability")
	}
	tamperedMaterialDigest := plan.Snapshot()
	tamperedMaterialDigest.CanonicalKeyStateAssertions[0].records[0].record.StateDigestSHA256[0] ^= 1
	if (MutationPlan{value: tamperedMaterialDigest, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("substituted canonical key-material digest retained the plan capability")
	}
	tamperedTerminal := plan.Snapshot()
	tamperedTerminal.CanonicalKeyStateAssertions[0].records[1].record.Terminal = true
	if (MutationPlan{value: tamperedTerminal, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("terminal current lifecycle row retained an active key capability")
	}
	missingKey := plan.Snapshot()
	missingKey.CanonicalKeyStateAssertions = missingKey.CanonicalKeyStateAssertions[1:]
	if (MutationPlan{value: missingKey, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("missing canonical key assertion retained the complete read set")
	}
	tamperedLeaseRow := plan.Snapshot()
	tamperedLeaseRow.CanonicalAuditWriterLeaseAssertion.record.record.CanonicalState[0] ^= 1
	if (MutationPlan{value: tamperedLeaseRow, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered canonical audit writer lease row retained the plan capability")
	}
	tamperedLeaseRequirement := plan.Snapshot()
	tamperedLeaseRequirement.CanonicalAuditWriterLeaseAssertion.requirement.AuthorizedWriterEpoch++
	if (MutationPlan{value: tamperedLeaseRequirement, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered canonical audit writer lease requirement retained the plan capability")
	}
	missingLease := plan.Snapshot()
	missingLease.CanonicalAuditWriterLeaseAssertion = CanonicalAuditWriterLeaseAssertion{}
	if (MutationPlan{value: missingLease, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("missing canonical audit writer lease assertion retained the plan capability")
	}
	writerLeaseRecord.CanonicalState[0] ^= 1
	if bytes.Equal(writerLeaseRecord.CanonicalState, snapshot.CanonicalAuditWriterLeaseAssertion.Record().CanonicalState) {
		t.Fatal("canonical audit writer lease getter aliases retained bytes")
	}
	rows := snapshot.CanonicalKeyStateAssertions[0].Records()
	rows[0].CanonicalState[0] ^= 1
	if bytes.Equal(rows[0].CanonicalState, snapshot.CanonicalKeyStateAssertions[0].Records()[0].CanonicalState) {
		t.Fatal("canonical key row getter aliases retained bytes")
	}
}

func TestCanonicalPolicyMutationRetainsCompleteExpectedToNextCAS(t *testing.T) {
	fixture := newGovernanceFixture(t)
	delayed := fixture.normalPolicy()
	delayed.EffectiveAtUnixNano = testBaseTime + int64(time.Hour)
	delayedRecord := fixture.policyRecordFromProjection(t, delayed, nil)
	fixture.setPolicyHistory(delayedRecord)
	active := policyTransition(t, delayed, PolicyStateActive, 2, "policy-record-2",
		delayed.EffectiveAtUnixNano, 1, fixture.profile.PolicyHomeRegion)
	command := fixture.policyCommandAt(t, active, active.EffectiveAtUnixNano, active.EffectiveAtUnixNano)
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
		pending.AuditIntent().Snapshot())
	plan, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending,
		PolicyFinalizeCommand{AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event})
	if err != nil {
		t.Fatal(err)
	}
	mutations := plan.Snapshot().CanonicalStateMutations
	if len(mutations) != 1 {
		t.Fatalf("canonical mutations = %d", len(mutations))
	}
	expected, present := mutations[0].Expected()
	next := mutations[0].Next()
	if !present || expected.Version != delayed.Sequence || expected.StateDigestSHA256 != delayedRecord.BundleDigestSHA256 ||
		next.Version != active.Sequence || next.StateDigestSHA256 == expected.StateDigestSHA256 ||
		next.AuditEventID != plan.Snapshot().AuditEventID {
		t.Fatalf("expected -> next = %#v -> %#v", expected, next)
	}
}

func TestCanonicalStateOptionalViewsFailClosed(t *testing.T) {
	t.Run("profile activation read assertion", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		content := []byte{0xd1}
		source := sha256.Sum256(content)
		fixture.evidence.evidence[source] = EvidenceSnapshot{Kind: EvidenceContentSHA256,
			DigestSHA256: source, Content: content}
		fixture.planner.profiles = semanticOnlyProfileCatalog{source: fixture.profiles}
		command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			[][ccse.DigestSize]byte{source})
		if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditAnchor) {
			t.Fatalf("missing canonical profile view error = %v", err)
		}
	})

	t.Run("policy registry mutation codec", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		command := fixture.policyCommand(t, fixture.normalPolicy())
		pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			pending.AuditIntent().Snapshot())
		fixture.planner.policies = semanticOnlyPolicyView{source: fixture.policies}
		if _, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending,
			PolicyFinalizeCommand{AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event}); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("missing canonical policy codec error = %v", err)
		}
	})

	t.Run("key state read assertions", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		fixture.planner.iam = semanticOnlyIAMView{source: fixture.iam}
		content := []byte{0xd2}
		source := sha256.Sum256(content)
		fixture.evidence.evidence[source] = EvidenceSnapshot{Kind: EvidenceContentSHA256,
			DigestSHA256: source, Content: content}
		command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			[][ccse.DigestSize]byte{source})
		if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("missing canonical key view error = %v", err)
		}
	})

	t.Run("approval admission profile assertion", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		policy := fixture.normalPolicy()
		command := fixture.policyCommand(t, policy)
		fixture.clearPolicyAdmission(policy)
		fixture.planner.profiles = semanticOnlyProfileCatalog{source: fixture.profiles}
		if _, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
			AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
		}); !errors.Is(err, ErrApprovalCollection) {
			t.Fatalf("missing admission profile assertion error = %v", err)
		}
	})

	t.Run("approval admission signer key assertions", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		policy := fixture.normalPolicy()
		command := fixture.policyCommand(t, policy)
		fixture.clearPolicyAdmission(policy)
		fixture.planner.iam = semanticOnlyIAMView{source: fixture.iam}
		if _, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
			AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
		}); !errors.Is(err, ErrApprovalCollection) {
			t.Fatalf("missing admission signer key assertions error = %v", err)
		}
	})

	t.Run("audit writer lease read assertion", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		fixture.planner.audit = semanticOnlyAuditView{source: fixture.audit}
		content := []byte{0xd3}
		source := sha256.Sum256(content)
		fixture.evidence.evidence[source] = EvidenceSnapshot{Kind: EvidenceContentSHA256,
			DigestSHA256: source, Content: content}
		command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			[][ccse.DigestSize]byte{source})
		if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditAnchor) {
			t.Fatalf("missing canonical audit writer lease view error = %v", err)
		}
	})

	t.Run("unrelated valid audit writer lease row", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		fixture.planner.audit = substitutingAuditLeaseView{source: fixture.audit}
		content := []byte{0xd4}
		source := sha256.Sum256(content)
		fixture.evidence.evidence[source] = EvidenceSnapshot{Kind: EvidenceContentSHA256,
			DigestSHA256: source, Content: content}
		command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			[][ccse.DigestSize]byte{source})
		if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditAnchor) {
			t.Fatalf("unrelated canonical audit writer lease error = %v", err)
		}
	})
}

func TestCanonicalGovernanceRowsRejectSelfConsistentSemanticSubstitution(t *testing.T) {
	t.Run("profile activation", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		fixture.planner.profiles = substitutingProfileCatalog{source: fixture.profiles}
		content := []byte{0xd1}
		source := sha256.Sum256(content)
		fixture.evidence.evidence[source] = EvidenceSnapshot{Kind: EvidenceContentSHA256,
			DigestSHA256: source, Content: content}
		command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			[][ccse.DigestSize]byte{source})
		if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditAnchor) {
			t.Fatalf("substituted profile error = %v", err)
		}
	})

	t.Run("policy transition", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		command := fixture.policyCommand(t, fixture.normalPolicy())
		pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256,
			pending.AuditIntent().Snapshot())
		fixture.planner.policies = substitutingPolicyView{source: fixture.policies}
		if _, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending,
			PolicyFinalizeCommand{AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event}); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("substituted policy error = %v", err)
		}
	})
}

func TestDurablePendingOptionalPersistenceViewFailsClosed(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(t, policy)
	fixture.clearPolicyAdmission(policy)
	fixture.collections = &testApprovalCollectionView{
		collections: fixture.collections.collections,
		persistence: fixture.collections.persistence,
	}
	fixture.planner.collections = semanticOnlyApprovalCollectionView{source: fixture.collections}
	if _, err := fixture.planner.PlanPolicyApprovalIngestion(context.Background(), PolicyApprovalIngestionCommand{
		AtUnixNano: command.AtUnixNano, Approval: command.Approvals[0],
	}); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("missing kind-7 persistence view error = %v", err)
	}
}
