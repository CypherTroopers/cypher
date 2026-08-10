// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package foundationv1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
)

func TestGovernanceProjectionsPositive(t *testing.T) {
	policy, err := validPolicyBundle().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	audit, err := validAuditEvent().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(policy) == 0 || len(audit) == 0 {
		t.Fatal("empty governance projection")
	}
	if (PolicyBundleSigningProjection{}).MessageTypeID() != schema.MessageTypePolicyBundle ||
		(AuditEventSigningProjection{}).MessageTypeID() != schema.MessageTypeAuditEvent {
		t.Fatal("governance message type mismatch")
	}
}

func TestGovernanceOneFieldMutationsFailClosed(t *testing.T) {
	policy := validPolicyBundle()
	policy.PolicyKind = ""
	if _, err := policy.CanonicalBytes(); err == nil {
		t.Fatal("empty policy_kind accepted")
	}
	audit := validAuditEvent()
	audit.CauseCode = ""
	if _, err := audit.CanonicalBytes(); err == nil {
		t.Fatal("empty audit cause accepted")
	}
}

func TestPolicyLifecycleAndOptionalRules(t *testing.T) {
	policy := validPolicyBundle()
	policy.Sequence = 2
	if _, err := policy.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("missing predecessor error = %v", err)
	}
	policy = validPolicyBundle()
	policy.PredecessorDigestSHA256 = OptionalFixedBytes32{Value: digest32(0x41)}
	if _, err := policy.CanonicalBytes(); !errors.Is(err, ccse.ErrNonCanonicalAbsent) {
		t.Fatalf("hidden predecessor error = %v", err)
	}
	policy = validPolicyBundle()
	policy.EffectiveAtUnixNano = policy.ApprovedAtUnixNano - 1
	if _, err := policy.CanonicalBytes(); !errors.Is(err, ErrInvalidTimeRange) {
		t.Fatalf("backdated activation error = %v", err)
	}
	policy = validPolicyBundle()
	policy.State = 99
	if _, err := policy.CanonicalBytes(); !errors.Is(err, ErrInvalidEnumValue) {
		t.Fatalf("unknown policy state error = %v", err)
	}
	policy = validPolicyBundle()
	policy.MinimumApprovals = 2
	if _, err := policy.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("impossible approval threshold error = %v", err)
	}

	emergency := validPolicyBundle()
	emergency.Emergency = true
	emergency.BreakGlassExpiresAtUnixNano = OptionalInt64{Present: true, Value: emergency.EffectiveAtUnixNano + 1}
	if _, err := emergency.CanonicalBytes(); err != nil {
		t.Fatalf("valid emergency rejected: %v", err)
	}
	emergency.BreakGlassExpiresAtUnixNano.Value = emergency.ExpiresAtUnixNano + 1
	if _, err := emergency.CanonicalBytes(); !errors.Is(err, ErrInvalidTimeRange) {
		t.Fatalf("unbounded break-glass expiry error = %v", err)
	}
}

func TestPolicyApproverSetsAreCanonicalAndUnique(t *testing.T) {
	first := validPolicyBundle()
	first.ApproverIdentities = []string{"approver-b", "approver-a"}
	first.ApproverKeyIDs = []string{"key-b", "key-a"}
	first.MinimumApprovals = 2
	second := first
	second.ApproverIdentities = []string{"approver-a", "approver-b"}
	second.ApproverKeyIDs = []string{"key-a", "key-b"}
	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("approver set order changed policy projection")
	}
	first.ApproverIdentities = []string{"approver-a", "approver-a"}
	if _, err := first.CanonicalBytes(); !errors.Is(err, ccse.ErrDuplicateSetValue) {
		t.Fatalf("duplicate approver error = %v", err)
	}
}

func TestAuditValidationAndOptionalHiddenValues(t *testing.T) {
	audit := validAuditEvent()
	audit.Outcome = 5
	if _, err := audit.CanonicalBytes(); !errors.Is(err, ErrInvalidEnumValue) {
		t.Fatalf("unknown audit outcome error = %v", err)
	}
	audit = validAuditEvent()
	audit.CausationID = OptionalFixedBytes16{Value: id16(0x51)}
	if _, err := audit.CanonicalBytes(); !errors.Is(err, ccse.ErrNonCanonicalAbsent) {
		t.Fatalf("hidden causation error = %v", err)
	}
	audit = validAuditEvent()
	audit.RedactedDetailsDigestSHA256 = OptionalFixedBytes32{Present: true}
	if _, err := audit.CanonicalBytes(); !errors.Is(err, ErrInvalidProjectionValue) {
		t.Fatalf("present zero details digest error = %v", err)
	}
	audit = validAuditEvent()
	audit.AppliedPolicyDigestsSHA256 = append(audit.AppliedPolicyDigestsSHA256, audit.AppliedPolicyDigestsSHA256[0])
	if _, err := audit.CanonicalBytes(); !errors.Is(err, ccse.ErrDuplicateSetValue) {
		t.Fatalf("duplicate audit policy digest error = %v", err)
	}
}

func validPolicyBundle() PolicyBundleSigningProjection {
	return PolicyBundleSigningProjection{
		Metadata:                   validMetadata(),
		PolicyBundleID:             "policy-01",
		PolicyKind:                 "provider-eligibility",
		PolicyVersion:              SchemaVersionSigningProjection{Major: 1},
		Sequence:                   1,
		ApprovedAtUnixNano:         1_799_999_000_000_000_000,
		EffectiveAtUnixNano:        1_800_000_000_000_000_000,
		ExpiresAtUnixNano:          1_900_000_000_000_000_000,
		PolicyDocumentDigestSHA256: digest32(0x61),
		PolicyDocumentMediaType:    "application/json",
		ApproverIdentities:         []string{"spiffe://cph.example/user/approver-01"},
		ApproverKeyIDs:             []string{"key-approver-01"},
		MinimumApprovals:           1,
		State:                      3,
	}
}

func validAuditEvent() AuditEventSigningProjection {
	return AuditEventSigningProjection{
		Metadata:                   validMetadata(),
		AuditEventID:               "audit-01",
		EventType:                  "PolicyActivated",
		ActorIdentity:              "spiffe://cph.example/service/policy-registry",
		ActorKeyID:                 "key-policy-registry-01",
		SubjectIDs:                 []string{"policy-01"},
		CauseCode:                  "scheduled-activation",
		CorrelationID:              id16(0x62),
		OccurredAtUnixNano:         1_800_000_000_000_000_000,
		Outcome:                    1,
		AppliedPolicyDigestsSHA256: [][32]byte{digest32(0x63)},
		EvidenceDigestsSHA256:      [][32]byte{digest32(0x64)},
		PreviousEventDigestSHA256:  digest32(0x65),
		AuditSequence:              1,
	}
}
