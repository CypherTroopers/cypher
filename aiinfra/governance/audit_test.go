// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

func TestAuditAppendAnchorsCompleteCCSERecordAndGlobalID(t *testing.T) {
	fixture := newGovernanceFixture(t)
	source := fixture.addDurableEvidence([]byte("durable-source-record"))
	command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{source})

	plan, intent, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatalf("PlanAuditAppend: %v", err)
	}
	if !plan.CommitReady() || plan.VerifyDigest() != nil || intent.VerifyDigest() != nil {
		t.Fatal("audit output is not commit-ready and digest-bound")
	}
	snapshot := plan.Snapshot()
	recordDigest, err := command.Event.Record.Digest(ccse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ExpectedAuditSequence != 0 || snapshot.NextAuditSequence != 1 ||
		snapshot.ExpectedAuditHeadWriterEpoch != 0 || snapshot.AuthorizedAuditWriterEpoch != 7 ||
		snapshot.NextAuditRecordDigestSHA256 != recordDigest || snapshot.DeploymentAnchorSHA256 != fixture.profile.AuditDeploymentAnchorSHA256 {
		t.Fatalf("unexpected audit CAS: %+v", snapshot)
	}
	if len(snapshot.IdentifierClaims) != 1 || snapshot.IdentifierClaims[0].Identifier != "audit-1" ||
		snapshot.IdentifierClaims[0].Owner.Domain != globalid.OwnerGovernanceAuditEvent {
		t.Fatalf("unexpected global ID claim: %+v", snapshot.IdentifierClaims)
	}

	before := plan.Digest()
	command.Event.Record.Payload[0] ^= 0xff
	command.SourceRecordDigestsSHA256[0] = testDigest(0xfe)
	copy := plan.Snapshot()
	copy.AuditSourceDigestsSHA256[0] = testDigest(0xfd)
	copy.AuditEventEvidence.Record().Signature[0] ^= 0xff
	if plan.Digest() != before || plan.VerifyDigest() != nil || plan.Snapshot().AuditSourceDigestsSHA256[0] != source {
		t.Fatal("audit plan aliases caller-owned data")
	}
}

func TestStandaloneAuditCannotUseJoinedEventNamespace(t *testing.T) {
	fixture := newGovernanceFixture(t)
	source := fixture.addDurableEvidence([]byte("standalone-reserved-event-id"))
	command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{source})
	reservedID := globalid.JoinedAuditEventIDPrefix + "0123456789abcdef0123456789abcdef"
	command.Event = fixture.mutateAndResignAudit(t, command.Event, func(event *foundationv1.AuditEventSigningProjection) {
		event.AuditEventID = reservedID
		event.Metadata.RecordID = reservedID
	})
	if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("reserved joined-audit namespace error = %v", err)
	}
}

func TestAuditSourceSetIsExactDurableAndOrderIndependent(t *testing.T) {
	fixture := newGovernanceFixture(t)
	first := fixture.addDurableEvidence([]byte("source-a"))
	second := fixture.addDurableEvidence([]byte("source-b"))
	command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{second, first})
	planA, _, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	command.SourceRecordDigestsSHA256 = [][ccse.DigestSize]byte{first, second}
	planB, _, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if planA.Digest() != planB.Digest() {
		t.Fatal("semantic source-set permutation changed plan digest")
	}

	delete(fixture.evidence.evidence, first)
	if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditEvidence) {
		t.Fatalf("missing durable evidence error = %v", err)
	}

	fixture = newGovernanceFixture(t)
	first = fixture.addDurableEvidence([]byte("source-a"))
	command = fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{first})
	bad := fixture.evidence.evidence[first]
	bad.Content = []byte("substituted")
	fixture.evidence.evidence[first] = bad
	if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditEvidence) {
		t.Fatalf("content-address mismatch error = %v", err)
	}
}

func TestAuditRetainsAndReauthorizesSignedSourceEvidence(t *testing.T) {
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
	plan, _, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatalf("signed source: %v", err)
	}
	snapshot := plan.Snapshot()
	if len(snapshot.AuditSourceEvidence) != 1 || snapshot.AuditSourceEvidence[0].Kind() != EvidenceSignedCCSERecord ||
		snapshot.AuditSourceEvidence[0].Digest() != digest || snapshot.AuditSourceEvidence[0].SignedEvidence().Record() == nil ||
		len(snapshot.AuditSourceKeyPreconditions) != 1 || snapshot.AuditSourceKeyPreconditions[0].KeyID != "key-a" {
		t.Fatalf("signed evidence not retained: %+v", snapshot)
	}

	key := fixture.iam.keys["key-a"]
	key.RevokedAtUnixNano = command.AtUnixNano
	key.StateVersion++
	key.SnapshotDigestSHA256 = testDigest(0xf4)
	fixture.iam.keys["key-a"] = key
	if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditEvidence) {
		t.Fatalf("revoked signed source error = %v", err)
	}
}

func TestAuditSeparatesTechnicalWriterFromLogicalActor(t *testing.T) {
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
	command.Event = fixture.mutateAndResignAudit(t, command.Event, func(event *foundationv1.AuditEventSigningProjection) {
		event.ActorIdentity = fixture.keys["key-a"].snapshot.SubjectIdentity
		event.ActorKeyID = "key-a"
	})
	plan, intent, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatalf("logical source actor rejected: %v", err)
	}
	if got := intent.Snapshot(); got.ActorIdentity != fixture.keys["key-a"].snapshot.SubjectIdentity || got.ActorKeyID != "key-a" ||
		plan.Snapshot().AuditWriterKeyPrecondition.KeyID != "key-audit" {
		t.Fatalf("writer/actor projection collapsed: intent=%+v plan=%+v", got, plan.Snapshot())
	}

	fixture = newGovernanceFixture(t)
	content := fixture.addDurableEvidence([]byte("unsigned-logical-actor-source"))
	command = fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{content})
	command.Event = fixture.mutateAndResignAudit(t, command.Event, func(event *foundationv1.AuditEventSigningProjection) {
		event.ActorIdentity = fixture.keys["key-a"].snapshot.SubjectIdentity
		event.ActorKeyID = "key-a"
	})
	if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditEvidence) {
		t.Fatalf("logical actor without exact signed source error = %v", err)
	}
}

func TestAuditWriterRequiresProfileRole(t *testing.T) {
	fixture := newGovernanceFixture(t)
	key := fixture.iam.keys["key-audit"]
	key.Roles = []string{"governance.reviewer"}
	fixture.iam.keys["key-audit"] = key
	source := fixture.addDurableEvidence([]byte("audit-writer-role-source"))
	command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{source})
	if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, ErrAuditWriter) {
		t.Fatalf("audit writer role error = %v", err)
	}
}

func TestAuditRejectsForkGapSpliceAndStaleWriter(t *testing.T) {
	makeCommand := func(t *testing.T) (*governanceFixture, AuditAppendCommand, [ccse.DigestSize]byte) {
		fixture := newGovernanceFixture(t)
		source := fixture.addDurableEvidence([]byte("source"))
		previous := testDigest(0x39)
		fixture.audit.head.Sequence = 1
		fixture.audit.head.LastRecordDigestSHA256 = previous
		fixture.audit.head.HeadGovernanceProfileDigestSHA256 = fixture.profileDigest
		fixture.audit.head.HeadWriterIdentity = fixture.profile.AuditWriterIdentity
		fixture.audit.head.HomeRegion = "us-old-1"
		fixture.audit.head.WriterEpoch = 6
		return fixture, fixture.auditCommand(t, 2, previous, [][ccse.DigestSize]byte{source}), previous
	}

	t.Run("authorized failover epoch can advance immutable head", func(t *testing.T) {
		fixture, command, _ := makeCommand(t)
		plan, _, err := fixture.planner.PlanAuditAppend(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		got := plan.Snapshot()
		if got.ExpectedAuditHeadWriterEpoch != 6 || got.AuthorizedAuditWriterEpoch != 7 {
			t.Fatalf("writer fence = %+v", got)
		}
	})

	tests := []struct {
		name   string
		mutate func(*governanceFixture, *AuditAppendCommand, [ccse.DigestSize]byte)
		want   error
	}{
		{"gap", func(f *governanceFixture, c *AuditAppendCommand, previous [32]byte) {
			*c = f.auditCommand(t, 3, previous, c.SourceRecordDigestsSHA256)
		}, ErrAuditSequence},
		{"splice", func(f *governanceFixture, c *AuditAppendCommand, _ [32]byte) {
			*c = f.auditCommand(t, 2, testDigest(0x38), c.SourceRecordDigestsSHA256)
		}, ErrAuditLink},
		{"stale writer epoch", func(f *governanceFixture, _ *AuditAppendCommand, _ [32]byte) {
			f.audit.head.AuthorizedWriterEpoch = 8
		}, ErrAuditWriter},
		{"expired writer lease", func(f *governanceFixture, _ *AuditAppendCommand, _ [32]byte) {
			f.audit.head.WriterLeaseNotAfterUnixNano = testBaseTime
		}, ErrAuditAnchor},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, command, previous := makeCommand(t)
			test.mutate(fixture, &command, previous)
			if _, _, err := fixture.planner.PlanAuditAppend(context.Background(), command); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuditAppendAllowsKnownHistoricalHeadProfileAfterMigration(t *testing.T) {
	fixture := newGovernanceFixture(t)
	oldProfile := cloneProfile(fixture.profile)
	oldProfile.MinActivationDelayNanos /= 2
	oldProfile.AuditWriterIdentity = "spiffe://cph.test/service/old-audit-writer"
	oldProfile.AuditWriterKeyID = "key-old-audit"
	oldDigest, err := ProfileDigest(oldProfile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.profiles.profiles[oldDigest] = oldProfile
	previous := testDigest(0x3a)
	fixture.audit.head.Sequence = 1
	fixture.audit.head.LastRecordDigestSHA256 = previous
	fixture.audit.head.HeadGovernanceProfileDigestSHA256 = oldDigest
	fixture.audit.head.HeadWriterIdentity = oldProfile.AuditWriterIdentity
	fixture.audit.head.HomeRegion = fixture.profile.AuditHomeRegion
	fixture.audit.head.WriterEpoch = fixture.audit.head.AuthorizedWriterEpoch
	source := fixture.addDurableEvidence([]byte("post-profile-migration-source"))
	command := fixture.auditCommand(t, 2, previous, [][ccse.DigestSize]byte{source})
	plan, _, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatalf("post-profile-migration append: %v", err)
	}
	if got := plan.Snapshot(); got.ExpectedAuditHeadGovernanceProfileDigestSHA256 != oldDigest ||
		got.AuthorizedAuditGovernanceProfileDigestSHA256 != fixture.profileDigest {
		t.Fatalf("profile CAS not split: %+v", got)
	}
}

func (f *governanceFixture) addDurableEvidence(preimage []byte) [ccse.DigestSize]byte {
	digest := sha256.Sum256(preimage)
	f.evidence.evidence[digest] = EvidenceSnapshot{Kind: EvidenceContentSHA256, DigestSHA256: digest, Content: append([]byte(nil), preimage...)}
	return digest
}
