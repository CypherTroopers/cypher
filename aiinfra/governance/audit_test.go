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
	"github.com/cypherium/cypher/aiinfra/schema"
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
	appendCapability := snapshot.CanonicalAuditAppend
	previous, hasPrevious := appendCapability.PreviousEventDigest()
	if appendCapability.VerifyDigest() != nil || appendCapability.EventID() != snapshot.AuditEventID ||
		appendCapability.StreamID() != snapshot.AuditStreamID || appendCapability.Sequence() != snapshot.NextAuditSequence ||
		hasPrevious || previous != ([ccse.DigestSize]byte{}) ||
		appendCapability.EventDigest() != command.Event.Record.Envelope.PayloadDigest ||
		appendCapability.RecordDigest() != snapshot.NextAuditRecordDigestSHA256 ||
		!bytes.Equal(appendCapability.CanonicalEvent(), command.Event.Record.Payload) ||
		appendCapability.DeploymentAnchorDigest() != snapshot.DeploymentAnchorSHA256 ||
		appendCapability.AuthorizedWriterIdentity() != snapshot.AuthorizedAuditWriterIdentity ||
		appendCapability.AuthorizedHomeRegion() != snapshot.AuthorizedAuditHomeRegion ||
		appendCapability.AuthorizedWriterEpoch() != snapshot.AuthorizedAuditWriterEpoch ||
		appendCapability.AuthorizedGovernanceProfileDigest() != snapshot.AuthorizedAuditGovernanceProfileDigestSHA256 ||
		appendCapability.WriterLeaseEvidenceDigest() != snapshot.ExpectedAuditWriterLeaseEvidenceDigestSHA256 {
		t.Fatalf("canonical audit append capability = %#v", appendCapability)
	}
	detachedEvent := appendCapability.CanonicalEvent()
	detachedEvent[0] ^= 1
	if bytes.Equal(detachedEvent, appendCapability.CanonicalEvent()) {
		t.Fatal("canonical audit append getter aliases retained payload")
	}
	tamperedAppend := plan.Snapshot()
	tamperedAppend.CanonicalAuditAppend.authorizedWriterEpoch++
	if (MutationPlan{value: tamperedAppend, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered canonical audit append retained the plan")
	}
	if len(snapshot.AuditSourceStorageCapabilities) != 1 {
		t.Fatalf("storage capabilities = %#v", snapshot.AuditSourceStorageCapabilities)
	}
	storage := snapshot.AuditSourceStorageCapabilities[0]
	if storage.VerifyDigest() != nil || storage.EvidenceDigest() != source ||
		storage.Kind() != DurableEvidenceStorageContentSHA256 ||
		storage.ContentType() != DurableEvidenceContentSHA256ContentType ||
		storage.ExpectedAuditEventID() != snapshot.AuditEventID ||
		!bytes.Equal(storage.CanonicalContent(), []byte("durable-source-record")) {
		t.Fatalf("content storage capability = %#v", storage)
	}
	if storage.Disposition() != DurableEvidenceStorageReserveNew {
		t.Fatalf("standalone evidence disposition = %d", storage.Disposition())
	}
	if key, revision, present := storage.PendingLink(); present || key != ([ccse.MessageIDSize]byte{}) || revision != 0 {
		t.Fatalf("standalone evidence pending link = %x/%d/%t", key, revision, present)
	}
	detachedContent := storage.CanonicalContent()
	detachedContent[0] ^= 1
	if bytes.Equal(detachedContent, storage.CanonicalContent()) {
		t.Fatal("storage capability content getter aliases retained bytes")
	}
	tamperedStorage := plan.Snapshot()
	tamperedStorage.AuditSourceStorageCapabilities[0].canonicalContent[0] ^= 1
	if (MutationPlan{value: tamperedStorage, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered storage capability retained the mutation plan")
	}
	tamperedDisposition := plan.Snapshot()
	tamperedDisposition.AuditSourceStorageCapabilities[0].disposition = DurableEvidenceStorageAssertExisting
	if (MutationPlan{value: tamperedDisposition, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered storage disposition retained the mutation plan")
	}
	tamperedLink := plan.Snapshot()
	tamperedLink.AuditSourceStorageCapabilities[0].pendingKey = testID(0x82)
	tamperedLink.AuditSourceStorageCapabilities[0].pendingRevision = 1
	tamperedLink.AuditSourceStorageCapabilities[0].hasPendingLink = true
	if (MutationPlan{value: tamperedLink, digest: plan.Digest()}).VerifyDigest() == nil {
		t.Fatal("tampered evidence pending link retained the mutation plan")
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

func TestCanonicalAuditAppendBindsExistingHeadCAS(t *testing.T) {
	fixture := newGovernanceFixture(t)
	fixture.audit.head = AuditHeadSnapshot{
		StreamID: fixture.profile.AuditReplayDomainID, DeploymentAnchorSHA256: fixture.profile.AuditDeploymentAnchorSHA256,
		Sequence: 6, LastRecordDigestSHA256: testDigest(0x91),
		HeadWriterIdentity: fixture.profile.AuditWriterIdentity, AuthorizedWriterIdentity: fixture.profile.AuditWriterIdentity,
		HomeRegion: fixture.profile.AuditHomeRegion, AuthorizedHomeRegion: fixture.profile.AuditHomeRegion,
		WriterEpoch: 7, AuthorizedWriterEpoch: 7,
		HeadGovernanceProfileDigestSHA256:       fixture.profileDigest,
		AuthorizedGovernanceProfileDigestSHA256: fixture.profileDigest,
		WriterLeaseEvidenceDigestSHA256:         testDigest(0x92), WriterLeaseNotBeforeUnixNano: 0,
		WriterLeaseNotAfterUnixNano: testBaseTime + int64(24*time.Hour),
	}
	source := fixture.addDurableEvidence([]byte("existing-head-source"))
	command := fixture.auditCommand(t, 7, fixture.audit.head.LastRecordDigestSHA256, [][ccse.DigestSize]byte{source})
	plan, _, err := fixture.planner.PlanAuditAppend(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	capability := plan.Snapshot().CanonicalAuditAppend
	previous, present := capability.PreviousEventDigest()
	if capability.VerifyDigest() != nil || !present || previous != fixture.audit.head.LastRecordDigestSHA256 ||
		capability.ExpectedHeadWriterIdentity() != fixture.audit.head.HeadWriterIdentity ||
		capability.ExpectedHeadHomeRegion() != fixture.audit.head.HomeRegion ||
		capability.ExpectedHeadWriterEpoch() != fixture.audit.head.WriterEpoch ||
		capability.ExpectedHeadGovernanceProfileDigest() != fixture.audit.head.HeadGovernanceProfileDigestSHA256 {
		t.Fatalf("existing-head append capability = %#v", capability)
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

func TestAuditAuthorizationPolicySetExact64Boundary(t *testing.T) {
	fixture := newGovernanceFixture(t)
	approval := fixture.policyCommand(t, fixture.normalPolicy()).Approvals[0]
	signed, err := bindVerifiedSignedRecord(approval, maxPayloadBytesFor(schema.MessageTypePolicyBundle))
	if err != nil {
		t.Fatal(err)
	}
	key := fixture.keys["key-a"].snapshot
	sourcePolicies := make([][ccse.DigestSize]byte, 0, 62)
	sourcePolicies = append(sourcePolicies, fixture.authA)
	for index := byte(1); len(sourcePolicies) < 62; index++ {
		digest := sha256.Sum256([]byte{0x7f, index})
		if digest != fixture.profileDigest && digest != fixture.authAudit && !containsDigest(sourcePolicies, digest) {
			sourcePolicies = append(sourcePolicies, digest)
		}
	}
	required := uniqueSortedDigests(append(append([][ccse.DigestSize]byte(nil), sourcePolicies...), fixture.authAudit, fixture.profileDigest))
	if len(required) != maxAuditPolicyDigests {
		t.Fatalf("test policy set = %d", len(required))
	}
	command := fixture.auditCommand(t, 1, fixture.profile.AuditDeploymentAnchorSHA256, [][ccse.DigestSize]byte{signed.digest})
	command.Event = fixture.mutateAndResignAudit(t, command.Event, func(event *foundationv1.AuditEventSigningProjection) {
		event.Metadata.PolicyDigestsSHA256 = append([][ccse.DigestSize]byte(nil), required...)
		event.AppliedPolicyDigestsSHA256 = append([][ccse.DigestSize]byte(nil), required...)
	})
	evidence := newSignedDurableEvidenceWithKey(signed, key, sourcePolicies...)
	plan, _, err := fixture.planner.planAuditAppend(context.Background(), command,
		map[[ccse.DigestSize]byte]DurableEvidence{signed.digest: evidence}, nil, nil, nil)
	if err != nil || !plan.CommitReady() {
		t.Fatalf("exact 64 policies: plan=%+v err=%v", plan.Snapshot(), err)
	}

	overflowPolicies := append(append([][ccse.DigestSize]byte(nil), sourcePolicies...), testDigest(0xee))
	overflow := newSignedDurableEvidenceWithKey(signed, key, overflowPolicies...)
	if _, _, err := fixture.planner.planAuditAppend(context.Background(), command,
		map[[ccse.DigestSize]byte]DurableEvidence{signed.digest: overflow}, nil, nil, nil); !errors.Is(err, ErrKeyNotAuthorized) {
		t.Fatalf("65-policy overflow error = %v", err)
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
	if len(snapshot.AuditSourceStorageCapabilities) != 1 {
		t.Fatalf("signed storage capabilities = %#v", snapshot.AuditSourceStorageCapabilities)
	}
	storage := snapshot.AuditSourceStorageCapabilities[0]
	if storage.VerifyDigest() != nil || storage.EvidenceDigest() != digest ||
		storage.Kind() != DurableEvidenceStorageSignedCCSE ||
		storage.ContentType() != DurableEvidenceSignedCCSEContentType ||
		storage.ExpectedAuditEventID() != snapshot.AuditEventID {
		t.Fatalf("signed storage capability = %#v", storage)
	}
	var (
		codecPreimage  []byte
		codecSignature []byte
	)
	if err := ccse.Unmarshal(storage.CanonicalContent(), durableEvidenceStorageMaxBytes, func(in *ccse.Decoder) error {
		version, decodeErr := in.Uint32()
		if decodeErr != nil || version != durableEvidenceStorageCodecVersion {
			return ErrAuditEvidence
		}
		codec, decodeErr := in.String(255)
		if decodeErr != nil || codec != durableSignedCCSEStorageCodec {
			return ErrAuditEvidence
		}
		codecPreimage, decodeErr = in.Bytes(2 << 20)
		if decodeErr != nil {
			return decodeErr
		}
		codecSignature, decodeErr = in.FixedBytes(64)
		return decodeErr
	}); err != nil {
		t.Fatal(err)
	}
	wantRecord := snapshot.AuditSourceEvidence[0].SignedEvidence().Record()
	wantPreimage, err := wantRecord.Preimage(ccse.DefaultLimits())
	if err != nil || !bytes.Equal(codecPreimage, wantPreimage) || !bytes.Equal(codecSignature, wantRecord.Signature) {
		t.Fatal("signed storage codec did not retain the exact CCSE preimage and signature")
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
