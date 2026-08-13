// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func TestPolicyApprovalPendingAndAtomicFinalize(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatalf("PlanPolicyApproval: %v", err)
	}
	if err := pending.VerifyDigest(); err != nil {
		t.Fatalf("pending digest: %v", err)
	}
	policy := pending.PolicySnapshot()
	intent := pending.AuditIntent().Snapshot()
	if policy.CommitReady || policy.Kind != MutationPolicyPublish || policy.PolicyBundleID != "policy-bundle-1" ||
		policy.PolicyRecordID != "policy-record-1" || len(policy.ApprovalEvidence) != 2 ||
		len(policy.ApprovalAdmissionEvidence) != 2 || len(policy.IdentifierClaims) != 3 {
		t.Fatalf("unexpected pending policy: %+v", policy)
	}
	if policy.CommitNotBeforeUnixNano >= policy.CommitNotAfterUnixNano {
		t.Fatalf("invalid commit window")
	}
	template := policy.DurablePolicyApprovalTerminalTemplate
	if template.VerifyDigest() != nil || template.PendingKey() != policy.PolicyIdempotencySnapshot.Binding.Key ||
		template.Revision() != policy.PolicyIdempotencySnapshot.Version+1 ||
		template.ExpectedAuditEventID() != intent.AuditEventID || isZeroDigest(template.BaseDigest()) {
		t.Fatalf("terminal template = %#v", template)
	}
	resultDigest := testDigest(0x73)
	terminal, finalizeErr := template.Finalize(resultDigest)
	if finalizeErr != nil || terminal.VerifyDigest() != nil || terminal.Status() != DurablePendingTerminal ||
		terminal.Revision() != template.Revision() {
		t.Fatalf("terminal capability = %#v / %v", terminal, finalizeErr)
	}
	if outcome, present := terminal.TerminalOutcomeDigest(); !present || outcome != resultDigest {
		t.Fatalf("terminal outcome = %x/%t", outcome, present)
	}
	if base, present := terminal.TerminalTemplateBaseDigest(); !present || base != template.BaseDigest() {
		t.Fatalf("terminal base = %x/%t", base, present)
	}
	detachedEnvelope := terminal.CanonicalEnvelope()
	detachedEnvelope[0] ^= 1
	if bytes.Equal(detachedEnvelope, terminal.CanonicalEnvelope()) {
		t.Fatal("terminal capability canonical envelope getter aliases retained bytes")
	}
	tamperedTemplate := template
	tamperedTemplate.base.canonicalEnvelope[0] ^= 1
	if tamperedTemplate.VerifyDigest() == nil {
		t.Fatal("terminal template accepted mutated retained envelope")
	}
	tamperedTerminal := terminal
	tamperedTerminal.terminalOutcomeDigest[0] ^= 1
	if tamperedTerminal.VerifyDigest() == nil {
		t.Fatal("terminal capability accepted substituted replay result digest")
	}
	tamperedPendingPolicy := policy
	tamperedPendingPolicy.DurablePolicyApprovalTerminalTemplate.base.expectedAuditEventID += "-other"
	if (MutationPlan{value: tamperedPendingPolicy, digest: pending.policy.Digest()}).VerifyDigest() == nil {
		t.Fatal("pending policy plan accepted a substituted terminal template")
	}
	if _, err := template.Finalize([ccse.DigestSize]byte{}); err == nil {
		t.Fatal("terminal template accepted zero replay result digest")
	}
	if !intent.Required || intent.Outcome != 1 || intent.OccurredAtUnixNano != command.AtUnixNano ||
		!containsString(intent.SubjectIDs, policy.PolicyBundleID) || !containsString(intent.SubjectIDs, policy.PolicyRecordID) {
		t.Fatalf("unexpected audit intent: %+v", intent)
	}

	// Mutating every caller-owned input after planning cannot change retained
	// evidence, the pending plan, or its domain-separated digest.
	beforeDigest := pending.Digest()
	command.Approvals[0].Record.Payload[0] ^= 0xff
	command.Approvals[0].Record.Signature[0] ^= 0xff
	command.Approvals[0].Record.Domain.Audience[0] = "mutated"
	policy.ApprovalEvidence[0].Record().Payload[0] ^= 0xff
	policy.IdentifierClaims[0].Identifier = "mutated"
	if pending.Digest() != beforeDigest || pending.VerifyDigest() != nil || pending.PolicySnapshot().IdentifierClaims[0].Identifier == "mutated" {
		t.Fatal("pending plan aliases caller or snapshot memory")
	}

	auditCommand := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	final, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{
		AtUnixNano: command.AtUnixNano, AuditEvent: auditCommand.Event,
	})
	if err != nil {
		t.Fatalf("FinalizePolicyMutation: %v", err)
	}
	if !final.CommitReady() || final.VerifyDigest() != nil {
		t.Fatalf("final plan is not commit ready")
	}
	finalSnapshot := final.Snapshot()
	if !finalSnapshot.CommitReady || finalSnapshot.ExpectedAuditSequence != 0 || finalSnapshot.NextAuditSequence != 1 ||
		finalSnapshot.ExpectedAuditHeadWriterEpoch != 0 || finalSnapshot.AuthorizedAuditWriterEpoch != 7 || finalSnapshot.AuditEventID != intent.AuditEventID ||
		finalSnapshot.NextAuditRecordDigestSHA256 == ([ccse.DigestSize]byte{}) || len(finalSnapshot.IdentifierClaims) != 3 {
		t.Fatalf("unexpected compound plan: %+v", finalSnapshot)
	}
	if finalSnapshot.CommitNotBeforeUnixNano >= finalSnapshot.CommitNotAfterUnixNano {
		t.Fatal("compound commit window is empty")
	}
	if finalSnapshot.DurablePolicyApprovalTerminalTemplate.VerifyDigest() != nil ||
		finalSnapshot.DurablePolicyApprovalTerminalTemplate.BaseDigest() != template.BaseDigest() {
		t.Fatal("final plan changed the bound kind-7 terminal template")
	}
	for _, capability := range finalSnapshot.AuditSourceStorageCapabilities {
		isApproval := containsDigest(finalSnapshot.ApprovalRecordDigestsSHA256, capability.EvidenceDigest())
		key, revision, linked := capability.PendingLink()
		if isApproval {
			if capability.Disposition() != DurableEvidenceStorageAssertExisting || !linked ||
				key != finalSnapshot.PolicyIdempotencySnapshot.Binding.Key ||
				revision != finalSnapshot.PolicyIdempotencySnapshot.Version {
				t.Fatalf("approval persistence closure = %#v", capability)
			}
		} else if capability.Disposition() != DurableEvidenceStorageReserveNew || linked {
			t.Fatalf("fresh policy evidence persistence closure = %#v", capability)
		}
	}
}

func TestPolicyPlanBindsAuthoritativeProfileActivationCutover(t *testing.T) {
	fixture := newGovernanceFixture(t)
	commandAt := testBaseTime + int64(30*time.Minute)
	cutover := commandAt + int64(5*time.Minute)
	activation := GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: fixture.profileDigest,
		Version:                       9,
		ValidFromUnixNano:             testBaseTime - int64(time.Hour),
		ValidUntilUnixNano:            cutover,
		EvidenceDigestSHA256:          testDigest(0xd4),
	}
	fixture.profiles.activationAt = func(int64) GovernanceProfileActivationSnapshot { return activation }
	command := fixture.policyCommandAt(t, fixture.normalPolicy(), commandAt, testBaseTime)
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatalf("PlanPolicyApproval: %v", err)
	}
	snapshot := pending.PolicySnapshot()
	if snapshot.GovernanceProfileActivation != activation || snapshot.CommitNotAfterUnixNano != cutover {
		t.Fatalf("activation CAS/deadline not retained: %+v", snapshot)
	}

	changed := activation
	changed.Version++
	changed.EvidenceDigestSHA256 = testDigest(0xd5)
	fixture.profiles.activationAt = func(int64) GovernanceProfileActivationSnapshot { return changed }
	intent := pending.AuditIntent().Snapshot()
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	if _, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{
		AtUnixNano: commandAt, AuditEvent: audit.Event,
	}); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("changed activation timeline error = %v", err)
	}
}

func TestCompoundPlanDigestBindsActivationAndEveryIdempotencyField(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	intent := pending.AuditIntent().Snapshot()
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	plan, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{
		AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := plan.Digest()
	assertBound := func(name string, mutate func(*MutationPlanSnapshot)) {
		t.Helper()
		value := plan.Snapshot()
		mutate(&value)
		digest, digestErr := digestMutationPlan(value)
		if digestErr == nil && digest == base {
			t.Fatalf("%s is not plan-digest bound", name)
		}
	}
	mutations := []struct {
		name   string
		mutate func(*MutationPlanSnapshot)
	}{
		{"activation digest", func(v *MutationPlanSnapshot) { v.GovernanceProfileActivation.GovernanceProfileDigestSHA256[0] ^= 1 }},
		{"activation version", func(v *MutationPlanSnapshot) { v.GovernanceProfileActivation.Version++ }},
		{"activation from", func(v *MutationPlanSnapshot) { v.GovernanceProfileActivation.ValidFromUnixNano++ }},
		{"activation until", func(v *MutationPlanSnapshot) { v.GovernanceProfileActivation.ValidUntilUnixNano-- }},
		{"activation evidence", func(v *MutationPlanSnapshot) { v.GovernanceProfileActivation.EvidenceDigestSHA256[0] ^= 1 }},
		{"parent key", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.Binding.Key[0] ^= 1 }},
		{"parent domain", func(v *MutationPlanSnapshot) {
			v.PolicyIdempotencySnapshot.Binding.Domain = idempotency.OperationGovernanceAudit
		}},
		{"parent owner", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.Binding.OwnerID += "-changed" }},
		{"parent request", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.Binding.RequestDigest[0] ^= 1 }},
		{"parent state", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.State = idempotency.StateCompleted }},
		{"parent version", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.Version++ }},
		{"parent progress", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.ProgressDigest[0] ^= 1 }},
		{"parent outcome", func(v *MutationPlanSnapshot) { v.PolicyIdempotencySnapshot.OutcomeDigest[0] ^= 1 }},
		{"joined key", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.Binding.Key[0] ^= 1 }},
		{"joined domain", func(v *MutationPlanSnapshot) {
			v.JoinedAuditIdempotencySnapshot.Binding.Domain = idempotency.OperationGovernanceAudit
		}},
		{"joined owner", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.Binding.OwnerID += "-changed" }},
		{"joined request", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.Binding.RequestDigest[0] ^= 1 }},
		{"joined state", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.State = idempotency.StateCompleted }},
		{"joined version", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.Version++ }},
		{"joined progress", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.ProgressDigest[0] ^= 1 }},
		{"joined outcome", func(v *MutationPlanSnapshot) { v.JoinedAuditIdempotencySnapshot.OutcomeDigest[0] ^= 1 }},
		{"claim binding", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].Binding.Key[0] ^= 1 }},
		{"claim expected state", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].ExpectedState = idempotency.StateCompleted }},
		{"claim expected version", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].ExpectedVersion++ }},
		{"claim expected progress", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].ExpectedProgressDigest[0] ^= 1 }},
		{"claim next state", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].NextState = idempotency.StateCollecting }},
		{"claim next version", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].NextVersion++ }},
		{"claim next progress", func(v *MutationPlanSnapshot) { v.IdempotencyClaims[0].NextProgressDigest[0] ^= 1 }},
		{"outcome", func(v *MutationPlanSnapshot) { v.IdempotencyOutcome++ }},
		{"X equals Y", func(v *MutationPlanSnapshot) {
			v.JoinedAuditIdempotencySnapshot.Binding.Key = v.PolicyIdempotencySnapshot.Binding.Key
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) { assertBound(mutation.name, mutation.mutate) })
	}
}

func TestPolicyApprovalRejectsAuthorizationAndSetFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *governanceFixture, *PolicyApprovalCommand)
		want   error
	}{
		{"missing exact approver", func(_ *testing.T, _ *governanceFixture, command *PolicyApprovalCommand) {
			command.Approvals = command.Approvals[:1]
		}, ErrApprovalSetMismatch},
		{"duplicate approval", func(_ *testing.T, _ *governanceFixture, command *PolicyApprovalCommand) {
			command.Approvals[1] = command.Approvals[0]
		}, ErrDuplicateApprover},
		{"revoked key", func(_ *testing.T, fixture *governanceFixture, _ *PolicyApprovalCommand) {
			key := fixture.iam.keys["key-a"]
			key.RevokedAtUnixNano = testBaseTime
			key.StateVersion++
			key.SnapshotDigestSHA256 = testDigest(0xf1)
			fixture.iam.keys["key-a"] = key
		}, ErrKeyRevoked},
		{"expired key", func(_ *testing.T, fixture *governanceFixture, command *PolicyApprovalCommand) {
			key := fixture.iam.keys["key-a"]
			key.NotAfterUnixNano = command.AtUnixNano
			fixture.iam.keys["key-a"] = key
		}, ErrKeyExpired},
		{"unauthorized type", func(_ *testing.T, fixture *governanceFixture, _ *PolicyApprovalCommand) {
			key := fixture.iam.keys["key-a"]
			key.AllowedMessageTypeIDs = []uint32{schema.MessageTypeAuditEvent}
			fixture.iam.keys["key-a"] = key
		}, ErrKeyNotAuthorized},
		{"wrong enrollment", func(_ *testing.T, fixture *governanceFixture, _ *PolicyApprovalCommand) {
			key := fixture.iam.keys["key-a"]
			key.EnrollmentDomainID = "other"
			fixture.iam.keys["key-a"] = key
		}, ErrKeyNotAuthorized},
		{"role separation", func(_ *testing.T, fixture *governanceFixture, _ *PolicyApprovalCommand) {
			key := fixture.iam.keys["key-b"]
			key.Roles = []string{"emergency.security"}
			fixture.iam.keys["key-b"] = key
		}, ErrRoleSeparation},
		{"organization separation", func(_ *testing.T, fixture *governanceFixture, _ *PolicyApprovalCommand) {
			key := fixture.iam.keys["key-b"]
			key.OrganizationIdentity = fixture.iam.keys["key-a"].OrganizationIdentity
			fixture.iam.keys["key-b"] = key
		}, ErrRoleSeparation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGovernanceFixture(t)
			command := fixture.policyCommand(t, fixture.normalPolicy())
			test.mutate(t, fixture, &command)
			_, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestPolicyPayloadContextAndTimingFailures(t *testing.T) {
	t.Run("payload mismatch", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		command := fixture.policyCommand(t, fixture.normalPolicy())
		other := fixture.normalPolicy()
		other.PolicyBundleID = "policy-bundle-other"
		other.Metadata.RecordID = "policy-record-other"
		otherCommand := fixture.policyCommand(t, other)
		command.Approvals[1] = otherCommand.Approvals[1]
		_, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
		if !errors.Is(err, ErrApprovalPayloadMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("causation mismatch", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		policy := fixture.normalPolicy()
		command := fixture.policyCommand(t, policy)
		payload, _ := policy.CanonicalBytes()
		command.Approvals[1] = fixture.signedRecord(t, schema.MessageTypePolicyBundle, policyPurpose, fixture.profile.PolicyReplayDomainID,
			payload, fixture.keys["key-b"], testBaseTime, 1, testID(0x63), testID(0x61), foundationv1.OptionalFixedBytes16{Present: true, Value: testID(0x66)})
		_, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
		if !errors.Is(err, ErrApprovalSetMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("short activation delay", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		policy := fixture.normalPolicy()
		policy.EffectiveAtUnixNano = testBaseTime + int64(45*time.Minute)
		_, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy))
		if !errors.Is(err, ErrActivationDelay) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("normal direct active", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		policy := fixture.normalPolicy()
		policy.State = PolicyStateActive
		policy.ApprovedAtUnixNano = testBaseTime - int64(2*time.Hour)
		policy.EffectiveAtUnixNano = testBaseTime + int64(15*time.Minute)
		_, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy))
		if !errors.Is(err, ErrPolicyConflict) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestBreakGlassDirectActiveAndScopeControls(t *testing.T) {
	fixture := newGovernanceFixture(t)
	policy := fixture.normalPolicy()
	policy.State = PolicyStateActive
	policy.Emergency = true
	policy.EffectiveAtUnixNano = testBaseTime
	policy.ExpiresAtUnixNano = testBaseTime + int64(2*time.Hour)
	policy.BreakGlassExpiresAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testBaseTime + int64(2*time.Hour)}
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy))
	if err != nil {
		t.Fatalf("break-glass plan: %v", err)
	}
	if snapshot := pending.PolicySnapshot(); !snapshot.Emergency || len(snapshot.BreakGlassScopes) != 1 || snapshot.BreakGlassScopes[0] != "market.pause" {
		t.Fatalf("bad break-glass plan: %+v", snapshot)
	}

	fixture = newGovernanceFixture(t)
	badDocument := []byte(`{"break_glass_scopes":["hardware.seize"],"policy_kind":"provider-eligibility"}`)
	badDigest := sha256.Sum256(badDocument)
	fixture.documents.documents[badDigest] = PolicyDocumentSnapshot{
		DigestSHA256: badDigest, MediaType: "application/json", CanonicalDocument: badDocument,
	}
	policy = fixture.normalPolicy()
	policy.State, policy.Emergency, policy.EffectiveAtUnixNano = PolicyStateActive, true, testBaseTime
	policy.PolicyDocumentDigestSHA256 = badDigest
	policy.ExpiresAtUnixNano = testBaseTime + int64(2*time.Hour)
	policy.BreakGlassExpiresAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: testBaseTime + int64(2*time.Hour)}
	_, err = fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy))
	if !errors.Is(err, ErrBreakGlassScope) {
		t.Fatalf("got %v", err)
	}
}

func TestPolicyDocumentIsContentAddressedForEveryPolicy(t *testing.T) {
	t.Run("normal document must exist", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		delete(fixture.documents.documents, fixture.document)
		if _, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, fixture.normalPolicy())); err == nil {
			t.Fatal("missing normal policy document was accepted")
		}
	})
	t.Run("normal document bytes must match digest", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		document := fixture.documents.documents[fixture.document]
		document.CanonicalDocument = []byte("substituted")
		fixture.documents.documents[fixture.document] = document
		if _, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, fixture.normalPolicy())); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("normal json document must be canonical", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		documentBytes := []byte(`{ "policy_kind": "provider-eligibility", "break_glass_scopes": ["market.pause"] }`)
		digest := sha256.Sum256(documentBytes)
		fixture.documents.documents[digest] = PolicyDocumentSnapshot{DigestSHA256: digest, MediaType: "application/json", CanonicalDocument: documentBytes}
		policy := fixture.normalPolicy()
		policy.PolicyDocumentDigestSHA256 = digest
		if _, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy)); !errors.Is(err, ErrSnapshotInconsistent) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("emergency parser rejects noncanonical json", func(t *testing.T) {
		fixture := newGovernanceFixture(t)
		documentBytes := []byte(`{ "policy_kind": "provider-eligibility", "break_glass_scopes": ["market.pause"] }`)
		digest := sha256.Sum256(documentBytes)
		fixture.documents.documents[digest] = PolicyDocumentSnapshot{DigestSHA256: digest, MediaType: "application/json", CanonicalDocument: documentBytes}
		policy := fixture.normalPolicy()
		policy.State, policy.Emergency, policy.EffectiveAtUnixNano = PolicyStateActive, true, testBaseTime
		policy.ExpiresAtUnixNano = testBaseTime + int64(2*time.Hour)
		policy.BreakGlassExpiresAtUnixNano = foundationv1.OptionalInt64{Present: true, Value: policy.ExpiresAtUnixNano}
		policy.PolicyDocumentDigestSHA256 = digest
		if _, err := fixture.planner.PlanPolicyApproval(context.Background(), fixture.policyCommand(t, policy)); !errors.Is(err, ErrBreakGlassScope) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestFinalizeRequiresExactSuccessfulAuditIntent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*foundationv1.AuditEventSigningProjection)
	}{
		{"outcome", func(event *foundationv1.AuditEventSigningProjection) { event.Outcome = 2 }},
		{"occurred at", func(event *foundationv1.AuditEventSigningProjection) { event.OccurredAtUnixNano-- }},
		{"subjects", func(event *foundationv1.AuditEventSigningProjection) {
			event.SubjectIDs = append(event.SubjectIDs, "unrelated")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGovernanceFixture(t)
			command := fixture.policyCommand(t, fixture.normalPolicy())
			pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, pending.AuditIntent().Snapshot())
			audit.Event = fixture.mutateAndResignAudit(t, audit.Event, test.mutate)
			if _, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event}); !errors.Is(err, ErrAuditRequired) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestFinalizeRechecksRevocationExpiryAndKeyCAS(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	intent := pending.AuditIntent().Snapshot()
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)

	key := fixture.iam.keys["key-a"]
	key.RevokedAtUnixNano = command.AtUnixNano
	key.StateVersion++
	key.SnapshotDigestSHA256 = testDigest(0xfa)
	fixture.iam.keys["key-a"] = key
	_, err = fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event})
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revocation got %v", err)
	}

	fixture = newGovernanceFixture(t)
	command = fixture.policyCommand(t, fixture.normalPolicy())
	pending, err = fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	intent = pending.AuditIntent().Snapshot()
	audit = fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, intent)
	late := pending.PolicySnapshot().CommitNotAfterUnixNano
	_, err = fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{AtUnixNano: late, AuditEvent: audit.Event})
	if !errors.Is(err, ErrPolicyExpired) && !errors.Is(err, ErrWrongRecordContext) {
		t.Fatalf("expiry got %v", err)
	}
}

func TestFinalizeRechecksAtomicJoinedCollectionSnapshot(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	audit := fixture.auditCommandForIntent(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, pending.AuditIntent().Snapshot())
	policy := pending.PolicySnapshot()
	advanced := fixture.idempotency.snapshots[policy.PolicyIdempotencySnapshot.Binding.Key]
	advanced.Version++
	advanced.ProgressDigest = testDigest(0xf8)
	fixture.idempotency.snapshots[advanced.Binding.Key] = advanced
	if _, err := fixture.planner.FinalizePolicyMutation(context.Background(), pending, PolicyFinalizeCommand{
		AtUnixNano: command.AtUnixNano, AuditEvent: audit.Event,
	}); !errors.Is(err, ErrApprovalCollection) {
		t.Fatalf("advanced X/Y snapshot error = %v", err)
	}
}

func TestPlannerConcurrentDeterminism(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	const workers = 24
	digests := make(chan [ccse.DigestSize]byte, workers)
	errs := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			pending, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
			if err != nil {
				errs <- err
				return
			}
			digests <- pending.Digest()
		}()
	}
	group.Wait()
	close(errs)
	close(digests)
	for err := range errs {
		t.Fatal(err)
	}
	var first [ccse.DigestSize]byte
	for digest := range digests {
		if first == ([ccse.DigestSize]byte{}) {
			first = digest
		} else if digest != first {
			t.Fatal("nondeterministic pending digest")
		}
	}
}

func TestPolicyApprovalPermutationHasOnePendingDigest(t *testing.T) {
	fixture := newGovernanceFixture(t)
	command := fixture.policyCommand(t, fixture.normalPolicy())
	first, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	command.Approvals[0], command.Approvals[1] = command.Approvals[1], command.Approvals[0]
	second, err := fixture.planner.PlanPolicyApproval(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() {
		t.Fatal("approval-set permutation changed pending plan digest")
	}
}
