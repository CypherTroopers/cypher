// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func TestSignedRecordRebindingRejectsSignatureAndScalarSubstitution(t *testing.T) {
	fixture := newGovernanceFixture(t)
	original := fixture.policyCommand(t, fixture.normalPolicy()).Approvals[0]
	tests := []struct {
		name   string
		mutate func(*ccse.Record)
	}{
		{"signature", func(record *ccse.Record) { record.Signature[0] ^= 0x80 }},
		{"message type", func(record *ccse.Record) { record.MessageTypeID = schema.MessageTypeAuditEvent }},
		{"schema version", func(record *ccse.Record) { record.SchemaVersion.Minor++ }},
		{"digest preimage", func(record *ccse.Record) { record.Payload[0] ^= 0x80 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := cloneCCSERecord(original.Record)
			test.mutate(&record)
			if _, err := bindVerifiedSignedRecord(SignedRecord{Record: &record, Verified: original.Verified},
				maxPayloadBytesFor(schema.MessageTypePolicyBundle)); !errors.Is(err, ErrInvalidSignedRecord) {
				t.Fatalf("rebinding error = %v", err)
			}
		})
	}
}

func TestHistoricalEvidenceComparisonRebindsDetachedSignature(t *testing.T) {
	fixture := newGovernanceFixture(t)
	record := fixture.policyRecordFromProjection(t, fixture.normalPolicy(), nil)
	record.ApprovalEvidence[0].Signed.Record.Signature[0] ^= 0x40
	if _, err := historicalApprovalEvidenceDigests(record.ApprovalEvidence); err == nil {
		t.Fatal("historical comparison accepted raw signature differing from VerifiedRecord")
	}
}

func TestHistoricalEvidencePreflightBudgetsRawAndVerifiedRepresentations(t *testing.T) {
	fixture := newGovernanceFixture(t)
	evidence := fixture.policyRecordFromProjection(t, fixture.normalPolicy(), nil).ApprovalEvidence[0]
	record := evidence.Signed.Record
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = maxPayloadBytesFor(schema.MessageTypePolicyBundle)
	verifiedSize, err := evidence.Signed.Verified.PreflightSize(limits)
	if err != nil {
		t.Fatal(err)
	}
	rawSize := len(record.Payload) + len(record.Signature) + len(evidence.Key.PublicKey) +
		4*len(evidence.Key.AllowedMessageTypeIDs)
	for _, value := range []string{
		record.Domain.Purpose, record.Domain.SenderIdentity, record.Domain.TenantOrganization.Value,
		record.Domain.ProviderOrganization.Value, record.Domain.Environment, record.Domain.SignatureKeyID,
		record.Domain.ReplayDomainID, record.Envelope.SenderIdentity, record.Envelope.Environment,
		record.Envelope.SignatureKeyID, evidence.Key.KeyID, evidence.Key.SubjectIdentity,
		evidence.Key.TargetIdentityID, evidence.Key.OrganizationIdentity, evidence.Key.EnrollmentDomainID,
		evidence.Key.EnrollmentEnvironment,
	} {
		rawSize += len(value)
	}
	for _, value := range append(append([]string(nil), record.Domain.Audience...), evidence.Key.Roles...) {
		rawSize += len(value)
	}
	for _, extension := range record.Envelope.Extensions {
		rawSize += len(extension.Value)
	}
	if rawSize <= 0 || verifiedSize == 0 {
		t.Fatal("fixture did not produce retained evidence bytes")
	}
	total := 0
	if preflightHistoricalApprovalEvidence(evidence, &total, rawSize+int(verifiedSize)-1) {
		t.Fatal("aggregate preflight accepted a budget one byte below the two retained representations")
	}
	total = 0
	if !preflightHistoricalApprovalEvidence(evidence, &total, rawSize+int(verifiedSize)) ||
		total != rawSize+int(verifiedSize) {
		t.Fatalf("exact aggregate preflight = %d, want %d", total, rawSize+int(verifiedSize))
	}

	// A durable reload cannot and must not recreate the replay verifier
	// capability. Its complete raw record remains bounded and is authenticated
	// by the historical IAM lookup after preflight.
	evidence.Signed.Verified = ccse.VerifiedRecord{}
	total = 0
	if preflightHistoricalApprovalEvidence(evidence, &total, rawSize-1) {
		t.Fatal("raw durable history passed a budget one byte below its retained representation")
	}
	total = 0
	if !preflightHistoricalApprovalEvidence(evidence, &total, rawSize) || total != rawSize {
		t.Fatalf("raw durable history preflight = %d, want %d", total, rawSize)
	}
}

func TestAuditAppliedPoliciesExactlyBindEverySignedSourceAuthorization(t *testing.T) {
	fixture := newGovernanceFixture(t)
	approval := fixture.policyCommand(t, fixture.normalPolicy()).Approvals[0]
	digest, err := approval.Record.Digest(ccse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	fixture.evidence.evidence[digest] = EvidenceSnapshot{
		Kind: EvidenceSignedCCSERecord, DigestSHA256: digest, Signed: approval,
	}
	command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{digest})
	plan, intent, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	required := [][ccse.DigestSize]byte{fixture.authA, fixture.authAudit, fixture.profileDigest}
	if !equalDigestSets(intent.Snapshot().AppliedPolicyDigestsSHA256, required) {
		t.Fatalf("applied policies = %x, want %x", intent.Snapshot().AppliedPolicyDigestsSHA256, required)
	}
	evidence := plan.Snapshot().AuditSourceEvidence
	if len(evidence) != 1 || !equalDigestSets(evidence[0].AuthorizationPolicyDigests(),
		[][ccse.DigestSize]byte{fixture.authA, fixture.profileDigest}) {
		t.Fatalf("signed source authorization binding = %+v", evidence)
	}

	for _, test := range []struct {
		name   string
		mutate func(*foundationv1.AuditEventSigningProjection)
	}{
		{"omit source policy", func(event *foundationv1.AuditEventSigningProjection) {
			event.AppliedPolicyDigestsSHA256 = [][ccse.DigestSize]byte{fixture.authAudit, fixture.profileDigest}
			event.Metadata.PolicyDigestsSHA256 = append([][ccse.DigestSize]byte(nil), event.AppliedPolicyDigestsSHA256...)
		}},
		{"add unbound policy", func(event *foundationv1.AuditEventSigningProjection) {
			event.AppliedPolicyDigestsSHA256 = append(event.AppliedPolicyDigestsSHA256, testDigest(0xfa))
			event.Metadata.PolicyDigestsSHA256 = append([][ccse.DigestSize]byte(nil), event.AppliedPolicyDigestsSHA256...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := command
			mutated.Event = fixture.mutateAndResignAudit(t, command.Event, test.mutate)
			if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), mutated); !errors.Is(err, ErrKeyNotAuthorized) {
				t.Fatalf("exact applied-policy error = %v", err)
			}
		})
	}
}

func TestTransactionSignedEvidenceRetainsSourceKeyCASAndDeadline(t *testing.T) {
	fixture := newGovernanceFixture(t)
	input := fixture.policyCommand(t, fixture.normalPolicy()).Approvals[0]
	signed, err := bindVerifiedSignedRecord(input, maxPayloadBytesFor(schema.MessageTypePolicyBundle))
	if err != nil {
		t.Fatal(err)
	}
	key := fixture.keys["key-a"].snapshot
	evidence := newSignedDurableEvidenceWithKey(signed, key, fixture.authA, fixture.profileDigest)
	retained, preconditions, policies, deadline, err := fixture.planner.validateAuditSources(context.Background(),
		[][ccse.DigestSize]byte{signed.digest}, map[[ccse.DigestSize]byte]DurableEvidence{signed.digest: evidence},
		testBaseTime+1,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantDeadline := signed.record.Domain.ExpiresAtUnixNano
	if key.NotAfterUnixNano < wantDeadline {
		wantDeadline = key.NotAfterUnixNano
	}
	if len(retained) != 1 || len(preconditions) != 1 || preconditions[0] != keyPrecondition(key) ||
		deadline != wantDeadline || !equalDigestSets(policies, [][ccse.DigestSize]byte{fixture.authA, fixture.profileDigest}) {
		t.Fatalf("transaction source = retained:%d preconditions:%+v policies:%x deadline:%d",
			len(retained), preconditions, policies, deadline)
	}
	retainedKey, present := retained[0].KeyPrecondition()
	if !present || retainedKey != keyPrecondition(key) || retained[0].AuthorizationNotAfterUnixNano() != key.NotAfterUnixNano {
		t.Fatalf("retained key fence = %+v, %t, %d", retainedKey, present, retained[0].AuthorizationNotAfterUnixNano())
	}

	tampered := cloneDurableEvidence(evidence)
	tampered.keyPrecondition.KeyID = "different-key"
	if _, _, _, _, err := fixture.planner.validateAuditSources(context.Background(),
		[][ccse.DigestSize]byte{signed.digest}, map[[ccse.DigestSize]byte]DurableEvidence{signed.digest: tampered},
		testBaseTime+1,
	); !errors.Is(err, ErrAuditEvidence) {
		t.Fatalf("tampered transaction key fence error = %v", err)
	}
}
