// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"encoding/json"
	"errors"
	"testing"
)

func semanticProjectionFinalPlan(t *testing.T) (MutationPlan, Profile) {
	t.Helper()
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	pending, err := fixture.planner.PlanPolicyApproval(t.Context(), command)
	if err != nil {
		t.Fatal(err)
	}
	intent := pending.AuditIntent().Snapshot()
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	final, err := fixture.planner.FinalizePolicyMutation(t.Context(), pending, PolicyFinalizeCommand{
		AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event,
	})
	if err != nil {
		t.Fatal(err)
	}
	return final, fixture.profile
}

func TestPolicyRegistrySemanticProjectionV2RoundTripAndAcceptanceTamper(t *testing.T) {
	plan, profile := semanticProjectionFinalPlan(t)
	resultDigest := testDigest(0xd1)
	projection, err := BuildPolicyRegistrySemanticProjectionV2(plan, resultDigest)
	if err != nil {
		t.Fatal(err)
	}
	record := plan.Snapshot().CanonicalStateMutations[0].Next()
	decoded, err := DecodePolicyRegistrySemanticProjectionV2(record, projection.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	policy, metadata, ok := decoded.PolicyRegistryRecord()
	if !ok || policy.AcceptanceEvidence.DurableResultDigestSHA256 != resultDigest ||
		metadata.AuthorizedHomeRegion != policy.AcceptanceEvidence.HomeRegion ||
		metadata.WriterLeaseEvidenceDigestSHA256 != policy.AcceptanceEvidence.WriterLeaseEvidenceDigestSHA256 {
		t.Fatal("policy semantic projection did not restore its exact acceptance binding")
	}
	if err := ValidatePolicyRegistrySemanticProjectionV2ForProfile(decoded, profile,
		policy.AcceptanceEvidence.GovernanceProfileActivation); err != nil {
		t.Fatalf("contextual profile verification: %v", err)
	}
	wrongContext := cloneProfile(profile)
	wrongContext.PolicyReplayDomainID += "/other"
	if err := ValidatePolicyRegistrySemanticProjectionV2ForProfile(decoded, wrongContext,
		policy.AcceptanceEvidence.GovernanceProfileActivation); !errors.Is(err, ErrSnapshotInconsistent) {
		t.Fatalf("wrong signed-record context accepted: %v", err)
	}

	mutations := map[string]func(*policyRegistryProjectionV2Wire){
		"top-level-lease": func(wire *policyRegistryProjectionV2Wire) {
			wire.WriterLeaseNotAfterUnixNano++
		},
		"accepted-at": func(wire *policyRegistryProjectionV2Wire) {
			wire.Record.AcceptanceEvidence.AcceptedAtUnixNano = wire.Record.AcceptanceEvidence.WriterLeaseNotAfterUnixNano
		},
		"approval-activation": func(wire *policyRegistryProjectionV2Wire) {
			wire.Approvals[0].Activation.Version++
		},
		"approval-set": func(wire *policyRegistryProjectionV2Wire) {
			wire.Record.ApproverKeyIDs[0] += "-other"
		},
		"result-digest": func(wire *policyRegistryProjectionV2Wire) {
			wire.Record.AcceptanceEvidence.DurableResultDigestSHA256 = [32]byte{}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var wire policyRegistryProjectionV2Wire
			if err := json.Unmarshal(projection.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			mutate(&wire)
			input, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePolicyRegistrySemanticProjectionV2(record, input); !errors.Is(err, ErrSnapshotInconsistent) {
				t.Fatalf("self-consistent semantic tamper accepted: %v", err)
			}
		})
	}
}
