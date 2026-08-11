// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	"github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const testBaseTime int64 = 1_800_000_000_000_000_000

type testKey struct {
	snapshot GovernanceKeySnapshot
	private  ed25519.PrivateKey
}

type testIAMView struct {
	keys       map[string]GovernanceKeySnapshot
	historical map[string]GovernanceKeySnapshot
}

func (v *testIAMView) ResolveGovernanceKey(_ context.Context, keyID string) (GovernanceKeySnapshot, error) {
	key, ok := v.keys[keyID]
	if !ok {
		return GovernanceKeySnapshot{}, fmt.Errorf("missing key")
	}
	return key, nil
}

func (v *testIAMView) ResolveGovernanceKeyAt(_ context.Context, keyID string, _ int64) (GovernanceKeySnapshot, bool, error) {
	key, ok := v.historical[keyID]
	if !ok {
		return GovernanceKeySnapshot{}, false, nil
	}
	return cloneKeySnapshot(key), true, nil
}

type testPolicyView struct{ snapshot PolicyRegistrySnapshot }

func (v *testPolicyView) SnapshotPolicy(_ context.Context, _ string) (PolicyRegistrySnapshot, error) {
	return v.snapshot, nil
}

type testProfileCatalog struct {
	profiles     map[[ccse.DigestSize]byte]Profile
	activeDigest [ccse.DigestSize]byte
	activeAt     func(int64) [ccse.DigestSize]byte
	activationAt func(int64) GovernanceProfileActivationSnapshot
}

func (v *testProfileCatalog) ResolveGovernanceProfile(_ context.Context, digest [ccse.DigestSize]byte) (Profile, bool, error) {
	profile, ok := v.profiles[digest]
	return cloneProfile(profile), ok, nil
}

func (v *testProfileCatalog) ActiveGovernanceProfile(_ context.Context, at int64) (GovernanceProfileActivationSnapshot, bool, error) {
	if v.activationAt != nil {
		activation := v.activationAt(at)
		return activation, activation != (GovernanceProfileActivationSnapshot{}), nil
	}
	digest := v.activeDigest
	if v.activeAt != nil {
		digest = v.activeAt(at)
	}
	if digest == ([ccse.DigestSize]byte{}) {
		return GovernanceProfileActivationSnapshot{}, false, nil
	}
	return GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: digest, Version: 1, ValidFromUnixNano: 0, ValidUntilUnixNano: math.MaxInt64,
		EvidenceDigestSHA256: sha256.Sum256(append([]byte("test-governance-profile-activation\x00"), digest[:]...)),
	}, true, nil
}

type testApprovalCollectionView struct {
	collections map[[ccse.MessageIDSize]byte][]PolicyApprovalCollectionEntry
}

func (v *testApprovalCollectionView) SnapshotPolicyApprovalCollection(_ context.Context, key [ccse.MessageIDSize]byte) ([]PolicyApprovalCollectionEntry, error) {
	stored := v.collections[key]
	result := make([]PolicyApprovalCollectionEntry, 0, len(stored))
	for _, entry := range stored {
		copyRecord := cloneCCSERecord(entry.Signed.Record)
		entry.Signed = SignedRecord{Record: &copyRecord, Verified: entry.Signed.Verified}
		entry.AdmissionKey = cloneKeySnapshot(entry.AdmissionKey)
		result = append(result, entry)
	}
	return result, nil
}

type testIdempotencyView struct {
	snapshots map[[ccse.MessageIDSize]byte]idempotency.Snapshot
}

func (v *testIdempotencyView) LookupBusinessIdempotency(_ context.Context, key [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool, error) {
	snapshot, ok := v.snapshots[key]
	return snapshot, ok, nil
}

func (v *testIdempotencyView) SnapshotBusinessIdempotencyPair(_ context.Context, parentKey, auditKey [ccse.MessageIDSize]byte) (idempotency.Snapshot, bool, idempotency.Snapshot, bool, error) {
	parent, parentOK := v.snapshots[parentKey]
	audit, auditOK := v.snapshots[auditKey]
	return parent, parentOK, audit, auditOK, nil
}

type testGlobalIDView struct{ ids map[string]globalid.Snapshot }

func (v *testGlobalIDView) LookupGlobalID(_ context.Context, id string) (globalid.Snapshot, bool, error) {
	value, ok := v.ids[id]
	return value, ok, nil
}

type testDocumentView struct {
	documents map[[ccse.DigestSize]byte]PolicyDocumentSnapshot
}

type testEvidenceView struct {
	evidence map[[ccse.DigestSize]byte]EvidenceSnapshot
}

func (v *testEvidenceView) ResolveEvidence(_ context.Context, digest [ccse.DigestSize]byte) (EvidenceSnapshot, bool, error) {
	evidence, ok := v.evidence[digest]
	return evidence, ok, nil
}

func (v *testDocumentView) ResolvePolicyDocument(_ context.Context, digest [ccse.DigestSize]byte) (PolicyDocumentSnapshot, error) {
	document, ok := v.documents[digest]
	if !ok {
		return PolicyDocumentSnapshot{}, fmt.Errorf("missing document")
	}
	return document, nil
}

type testAuditView struct {
	head   AuditHeadSnapshot
	events map[string]AuditEventSnapshot
}

func (v *testAuditView) SnapshotAuditHead(_ context.Context, _ string) (AuditHeadSnapshot, error) {
	return v.head, nil
}

func (v *testAuditView) LookupAuditEvent(_ context.Context, eventID string) (AuditEventSnapshot, bool, error) {
	event, ok := v.events[eventID]
	return event, ok, nil
}

type governanceFixture struct {
	profile       Profile
	iam           *testIAMView
	policies      *testPolicyView
	profiles      *testProfileCatalog
	collections   *testApprovalCollectionView
	ids           *testGlobalIDView
	idempotency   *testIdempotencyView
	documents     *testDocumentView
	evidence      *testEvidenceView
	audit         *testAuditView
	planner       *Planner
	keys          map[string]testKey
	authA         [ccse.DigestSize]byte
	authB         [ccse.DigestSize]byte
	authAudit     [ccse.DigestSize]byte
	profileDigest [ccse.DigestSize]byte
	document      [ccse.DigestSize]byte
}

func newGovernanceFixture(t testing.TB) *governanceFixture {
	t.Helper()
	authA := testDigest(0xa1)
	authB := testDigest(0xb1)
	authAudit := testDigest(0xc1)
	documentBytes := []byte(`{"break_glass_scopes":["market.pause"],"policy_kind":"provider-eligibility"}`)
	document := sha256.Sum256(documentBytes)
	keys := map[string]testKey{
		"key-a":     newTestKey("key-a", "spiffe://cph.test/user/approver-a", "spiffe://cph.test/org/operator-a", 0x11, []string{"governance.proposer", "emergency.operations"}, []uint32{schema.MessageTypePolicyBundle}, authA),
		"key-b":     newTestKey("key-b", "spiffe://cph.test/user/approver-b", "spiffe://cph.test/org/operator-b", 0x22, []string{"governance.reviewer", "emergency.security"}, []uint32{schema.MessageTypePolicyBundle}, authB),
		"key-audit": newTestKey("key-audit", "spiffe://cph.test/service/audit-writer", "spiffe://cph.test/org/platform", 0x33, []string{"audit.writer"}, []uint32{schema.MessageTypeAuditEvent}, authAudit),
	}
	iamKeys := make(map[string]GovernanceKeySnapshot, len(keys))
	historicalIAMKeys := make(map[string]GovernanceKeySnapshot, len(keys))
	for id, key := range keys {
		iamKeys[id] = cloneKeySnapshot(key.snapshot)
		historicalIAMKeys[id] = cloneKeySnapshot(key.snapshot)
	}
	profile := Profile{
		ProtocolVersion:                        ccse.Version{Major: 1},
		SchemaVersion:                          ccse.Version{Major: 1},
		Audience:                               []string{"spiffe://cph.test/service/policy-registry"},
		Environment:                            "test",
		ChainID:                                testDigest(0x41),
		GenesisHash:                            testDigest(0x42),
		PolicyReplayDomainID:                   "governance/policy/test",
		AuditReplayDomainID:                    "governance/audit/test",
		AuditWriterIdentity:                    "spiffe://cph.test/service/audit-writer",
		AuditWriterKeyID:                       "key-audit",
		AuditWriterRole:                        "audit.writer",
		PolicyHomeRegion:                       "eu-test-1",
		AuditHomeRegion:                        "eu-test-1",
		AuditDeploymentAnchorSHA256:            testDigest(0x43),
		EnrollmentDomainID:                     "cph-test-enrollment",
		MinimumApprovals:                       2,
		MinimumDistinctApprovalOrganizations:   2,
		RequiredApprovalRoles:                  []string{"governance.proposer", "governance.reviewer"},
		BreakGlassMinimumApprovals:             2,
		BreakGlassMinimumDistinctOrganizations: 2,
		BreakGlassRequiredRoles:                []string{"emergency.operations", "emergency.security"},
		AllowedBreakGlassScopes:                []string{"market.pause", "new-lease.disable", "new-mining.disable"},
		MinActivationDelayNanos:                int64(time.Hour),
		MaxBreakGlassDurationNanos:             int64(4 * time.Hour),
		MaxRecordValidityNanos:                 int64(2 * time.Hour),
		MaxClockSkewNanos:                      int64(time.Second),
		MaxPlanCommitLatencyNanos:              int64(10 * time.Minute),
		MaxPolicyRecords:                       128,
	}
	profileDigest, err := ProfileDigest(profile)
	if err != nil {
		t.Fatalf("ProfileDigest: %v", err)
	}
	fixture := &governanceFixture{
		profile: profile,
		iam:     &testIAMView{keys: iamKeys, historical: historicalIAMKeys},
		policies: &testPolicyView{snapshot: PolicyRegistrySnapshot{
			AuthorizedHomeRegion: "eu-test-1", AuthorizedWriterEpoch: 1,
			GovernanceProfileDigestSHA256:   profileDigest,
			WriterLeaseEvidenceDigestSHA256: testDigest(0x44),
			WriterLeaseNotBeforeUnixNano:    testBaseTime - int64(time.Hour),
			WriterLeaseNotAfterUnixNano:     testBaseTime + int64(12*time.Hour),
		}},
		profiles: &testProfileCatalog{
			profiles: map[[ccse.DigestSize]byte]Profile{profileDigest: cloneProfile(profile)}, activeDigest: profileDigest,
		},
		collections: &testApprovalCollectionView{collections: map[[ccse.MessageIDSize]byte][]PolicyApprovalCollectionEntry{}},
		idempotency: &testIdempotencyView{snapshots: map[[ccse.MessageIDSize]byte]idempotency.Snapshot{}},
		documents:   &testDocumentView{documents: map[[ccse.DigestSize]byte]PolicyDocumentSnapshot{}},
		evidence:    &testEvidenceView{evidence: map[[ccse.DigestSize]byte]EvidenceSnapshot{}},
		audit: &testAuditView{head: AuditHeadSnapshot{
			StreamID: profile.AuditReplayDomainID, DeploymentAnchorSHA256: profile.AuditDeploymentAnchorSHA256,
			AuthorizedWriterIdentity: profile.AuditWriterIdentity, AuthorizedHomeRegion: profile.AuditHomeRegion, AuthorizedWriterEpoch: 7,
			AuthorizedGovernanceProfileDigestSHA256: profileDigest,
			WriterLeaseEvidenceDigestSHA256:         testDigest(0x45),
			WriterLeaseNotBeforeUnixNano:            testBaseTime - int64(time.Hour),
			WriterLeaseNotAfterUnixNano:             testBaseTime + int64(12*time.Hour),
		}, events: map[string]AuditEventSnapshot{}},
		keys: keys, authA: authA, authB: authB, authAudit: authAudit, profileDigest: profileDigest, document: document,
	}
	fixture.documents.documents[document] = PolicyDocumentSnapshot{
		DigestSHA256: document, MediaType: "application/json", CanonicalDocument: append([]byte(nil), documentBytes...),
	}
	fixture.ids = &testGlobalIDView{ids: map[string]globalid.Snapshot{}}
	planner, err := NewPlanner(fixture.iam, fixture.policies, fixture.profiles, fixture.collections, fixture.ids, fixture.idempotency,
		fixture.documents, fixture.evidence, fixture.audit, profile)
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	fixture.planner = planner
	return fixture
}

func newTestKey(id, subject, organization string, seedByte byte, roles []string, allowed []uint32, policy [ccse.DigestSize]byte) testKey {
	var seed [ed25519.SeedSize]byte
	for index := range seed {
		seed[index] = seedByte
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	return testKey{
		private: private,
		snapshot: GovernanceKeySnapshot{
			KeyID: id, SubjectIdentity: subject, TargetIdentityKind: 1, TargetPrincipalKind: 2,
			TargetIdentityID: "identity-" + id, OrganizationIdentity: organization, Algorithm: ccse.SignatureAlgorithmEd25519,
			PublicKey: append([]byte(nil), private.Public().(ed25519.PublicKey)...), LifecycleState: KeyLifecycleStateActive,
			NotBeforeUnixNano: testBaseTime - int64(24*time.Hour), NotAfterUnixNano: testBaseTime + int64(30*24*time.Hour),
			AllowedMessageTypeIDs: append([]uint32(nil), allowed...), Roles: append([]string(nil), roles...),
			AuthorizationPolicyDigestSHA256: policy, StateVersion: 1, WriterEpoch: 1,
			SnapshotDigestSHA256: testDigest(seedByte + 1),
			IdentityStateVersion: 1, IdentityWriterEpoch: 1, IdentitySnapshotDigestSHA256: testDigest(seedByte + 2),
			EnrollmentDomainID: "cph-test-enrollment", EnrollmentEnvironment: "test", EnrollmentGenesisHash: testDigest(0x42),
		},
	}
}

func (f *governanceFixture) normalPolicy() foundationv1.PolicyBundleSigningProjection {
	return foundationv1.PolicyBundleSigningProjection{
		Metadata: foundationv1.RecordMetadataSigningProjection{
			SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, RecordID: "policy-record-1",
			CreatedAtUnixNano: testBaseTime, IntegrityDigest: testDigest(0x51), HomeRegion: "eu-test-1",
			WriterEpoch: 1, StateVersion: 1, IdempotencyKey: testID(0x52),
			PolicyDigestsSHA256: [][ccse.DigestSize]byte{f.authA, f.authB, f.profileDigest},
		},
		PolicyBundleID: "policy-bundle-1", PolicyKind: "provider-eligibility",
		PolicyVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, Sequence: 1,
		ApprovedAtUnixNano: testBaseTime, EffectiveAtUnixNano: testBaseTime + int64(2*time.Hour),
		ExpiresAtUnixNano: testBaseTime + int64(24*time.Hour), PolicyDocumentDigestSHA256: f.document,
		PolicyDocumentMediaType: "application/json",
		ApproverIdentities:      []string{f.keys["key-a"].snapshot.SubjectIdentity, f.keys["key-b"].snapshot.SubjectIdentity},
		ApproverKeyIDs:          []string{"key-a", "key-b"}, MinimumApprovals: 2, State: PolicyStateApprovedDelayed,
	}
}

func (f *governanceFixture) policyCommand(t testing.TB, policy foundationv1.PolicyBundleSigningProjection) PolicyApprovalCommand {
	return f.policyCommandAt(t, policy, testBaseTime+int64(30*time.Minute), testBaseTime)
}

func (f *governanceFixture) policyCommandAt(t testing.TB, policy foundationv1.PolicyBundleSigningProjection, at, issuedAt int64) PolicyApprovalCommand {
	t.Helper()
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatalf("policy CanonicalBytes: %v", err)
	}
	correlation := testID(0x61)
	command := PolicyApprovalCommand{
		AtUnixNano: at,
		Approvals: []SignedRecord{
			f.signedRecord(t, schema.MessageTypePolicyBundle, policyPurpose, f.profile.PolicyReplayDomainID, payload, f.keys["key-a"], issuedAt, policy.Sequence, testID(0x62), correlation, foundationv1.OptionalFixedBytes16{}),
			f.signedRecord(t, schema.MessageTypePolicyBundle, policyPurpose, f.profile.PolicyReplayDomainID, payload, f.keys["key-b"], issuedAt, policy.Sequence, testID(0x63), correlation, foundationv1.OptionalFixedBytes16{}),
		},
	}
	f.seedPolicyApprovalCollection(t, policy, command.Approvals)
	return command
}

func (f *governanceFixture) seedPolicyApprovalCollection(t testing.TB, policy foundationv1.PolicyBundleSigningProjection, records []SignedRecord) {
	t.Helper()
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	approvals := make([]policyApproval, 0, len(records))
	stored := make([]PolicyApprovalCollectionEntry, 0, len(records))
	for _, signed := range records {
		digest, digestErr := signed.Record.Digest(ccse.DefaultLimits())
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		copyRecord := cloneCCSERecord(signed.Record)
		key := cloneKeySnapshot(f.keys[signed.Record.Domain.SignatureKeyID].snapshot)
		f.iam.historical[key.KeyID] = cloneKeySnapshot(key)
		activation, active, profileErr := f.profiles.ActiveGovernanceProfile(context.Background(), signed.Record.Domain.IssuedAtUnixNano)
		if profileErr != nil || !active {
			t.Fatalf("active admission profile: %v", profileErr)
		}
		profileDigest := activation.GovernanceProfileDigestSHA256
		approval := policyApproval{
			record:                 signedRecordSnapshot{record: copyRecord, digest: digest},
			key:                    key,
			bundle:                 policy,
			admissionKey:           key,
			admissionProfileDigest: profileDigest,
			admissionActivation:    activation,
			admissionValidatedAt:   signed.Record.Domain.IssuedAtUnixNano,
		}
		approval.admissionFingerprint, err = policyApprovalAdmissionFingerprint(approval)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
		storedRecord := cloneCCSERecord(signed.Record)
		stored = append(stored, PolicyApprovalCollectionEntry{
			Signed: SignedRecord{Record: &storedRecord, Verified: signed.Verified}, AdmissionKey: key,
			GovernanceProfileDigestSHA256: profileDigest, ValidatedAtUnixNano: signed.Record.Domain.IssuedAtUnixNano,
			GovernanceProfileActivation: activation,
			AdmissionFingerprintSHA256:  approval.admissionFingerprint,
		})
	}
	progress, err := approvalCollectionDigest(binding, approvals)
	if err != nil {
		t.Fatal(err)
	}
	f.collections.collections[binding.Key] = stored
	f.idempotency.snapshots[binding.Key] = idempotency.Snapshot{
		Binding: binding, State: idempotency.StateCollecting, Version: uint64(len(stored)), ProgressDigest: progress,
	}
	joined, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	f.idempotency.snapshots[joined.Key] = idempotency.Snapshot{
		Binding: joined, State: idempotency.StateCollecting, Version: 1, ProgressDigest: joined.RequestDigest,
	}
	bundleOwnerDigest := policyBundleOwnerDigest(policy.PolicyKind, policy.PolicyBundleID)
	f.ids.ids[policy.PolicyBundleID] = globalid.Snapshot{
		Identifier: policy.PolicyBundleID,
		Owner:      globalid.Owner{Domain: globalid.OwnerGovernancePolicyBundle, ID: hex.EncodeToString(bundleOwnerDigest[:])},
		Version:    1,
	}
	f.ids.ids[policy.Metadata.RecordID] = globalid.Snapshot{
		Identifier: policy.Metadata.RecordID,
		Owner:      globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: hex.EncodeToString(binding.RequestDigest[:])},
		Version:    1,
	}
	eventID, err := idempotency.JoinedAuditEventID(binding)
	if err != nil {
		t.Fatal(err)
	}
	f.ids.ids[eventID] = globalid.Snapshot{
		Identifier: eventID, Owner: globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID}, Version: 1,
	}
}

func (f *governanceFixture) setPolicyHistory(records ...PolicyRecordSnapshot) {
	f.policies.snapshot.HeadPresent = len(records) != 0
	f.policies.snapshot.Records = append([]PolicyRecordSnapshot(nil), records...)
	if len(records) == 0 {
		f.policies.snapshot.Head = PolicyRecordSnapshot{}
		return
	}
	f.policies.snapshot.Head = records[len(records)-1]
	for _, record := range records {
		recordOwner := globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: hex.EncodeToString(record.BundleDigestSHA256[:])}
		f.ids.ids[record.RecordID] = globalid.Snapshot{Identifier: record.RecordID, Owner: recordOwner, Version: 1}
		ownerDigest := policyBundleOwnerDigest(record.PolicyKind, record.PolicyBundleID)
		bundleOwner := globalid.Owner{Domain: globalid.OwnerGovernancePolicyBundle, ID: hex.EncodeToString(ownerDigest[:])}
		if _, exists := f.ids.ids[record.PolicyBundleID]; !exists {
			f.ids.ids[record.PolicyBundleID] = globalid.Snapshot{Identifier: record.PolicyBundleID, Owner: bundleOwner, Version: 1}
		}
	}
}

func (f *governanceFixture) auditCommand(t testing.TB, sequence uint64, previous [ccse.DigestSize]byte, sources [][ccse.DigestSize]byte) AuditAppendCommand {
	t.Helper()
	correlation := testID(byte(0x70 + sequence))
	applied := [][ccse.DigestSize]byte{f.authAudit, f.profileDigest}
	for _, source := range sources {
		if evidence, ok := f.evidence.evidence[source]; ok && evidence.Kind == EvidenceSignedCCSERecord && evidence.Signed.Record != nil {
			if key, found := f.iam.keys[evidence.Signed.Record.Domain.SignatureKeyID]; found {
				applied = append(applied, key.AuthorizationPolicyDigestSHA256)
			}
		}
	}
	applied = uniqueSortedDigests(applied)
	event := foundationv1.AuditEventSigningProjection{
		Metadata: foundationv1.RecordMetadataSigningProjection{
			SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, RecordID: fmt.Sprintf("audit-%d", sequence),
			CreatedAtUnixNano: testBaseTime + int64(30*time.Minute), IntegrityDigest: testDigest(byte(0x80 + sequence)),
			HomeRegion: "eu-test-1", WriterEpoch: 7, StateVersion: sequence, IdempotencyKey: testID(byte(0x90 + sequence)),
			PolicyDigestsSHA256: append([][ccse.DigestSize]byte(nil), applied...),
		},
		AuditEventID: fmt.Sprintf("audit-%d", sequence), EventType: "PolicyActivated",
		ActorIdentity: f.profile.AuditWriterIdentity, ActorKeyID: "key-audit", SubjectIDs: []string{"policy-bundle-1"},
		CauseCode: "approved-change-control", CorrelationID: correlation,
		OccurredAtUnixNano: testBaseTime + int64(30*time.Minute), Outcome: 1,
		AppliedPolicyDigestsSHA256: append([][ccse.DigestSize]byte(nil), applied...),
		EvidenceDigestsSHA256:      append([][ccse.DigestSize]byte(nil), sources...),
		PreviousEventDigestSHA256:  previous, AuditSequence: sequence,
	}
	payload, err := event.CanonicalBytes()
	if err != nil {
		t.Fatalf("audit CanonicalBytes: %v", err)
	}
	signed := f.signedRecord(t, schema.MessageTypeAuditEvent, auditPurpose, f.profile.AuditReplayDomainID, payload,
		f.keys["key-audit"], event.OccurredAtUnixNano, sequence, testID(byte(0xa0+sequence)), correlation, event.CausationID)
	return AuditAppendCommand{AtUnixNano: testBaseTime + int64(30*time.Minute), Event: signed, SourceRecordDigestsSHA256: append([][ccse.DigestSize]byte(nil), sources...)}
}

func (f *governanceFixture) auditCommandForIntent(t testing.TB, sequence uint64, previous [ccse.DigestSize]byte, intent AuditIntentSnapshot) AuditAppendCommand {
	t.Helper()
	if intent.AuditEventID == "" {
		t.Fatal("audit intent event ID is empty")
	}
	applied := append([][ccse.DigestSize]byte(nil), intent.AppliedPolicyDigestsSHA256...)
	applied = uniqueSortedDigests(append(applied, f.authAudit))
	event := foundationv1.AuditEventSigningProjection{
		Metadata: foundationv1.RecordMetadataSigningProjection{
			SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, RecordID: intent.AuditEventID,
			CreatedAtUnixNano: intent.OccurredAtUnixNano, IntegrityDigest: testDigest(byte(0xb0 + sequence)),
			HomeRegion: "eu-test-1", WriterEpoch: 7, StateVersion: sequence, IdempotencyKey: intent.IdempotencyKey,
			PolicyDigestsSHA256: applied,
		},
		AuditEventID: intent.AuditEventID, EventType: intent.EventType,
		ActorIdentity: intent.ActorIdentity, ActorKeyID: intent.ActorKeyID, SubjectIDs: append([]string(nil), intent.SubjectIDs...),
		CauseCode: intent.CauseCode, CorrelationID: intent.CorrelationID,
		CausationID:        foundationv1.OptionalFixedBytes16{Present: intent.CausationID.Present, Value: intent.CausationID.Value},
		OccurredAtUnixNano: intent.OccurredAtUnixNano, Outcome: intent.Outcome,
		AppliedPolicyDigestsSHA256: applied, EvidenceDigestsSHA256: append([][ccse.DigestSize]byte(nil), intent.EvidenceDigestsSHA256...),
		PreviousEventDigestSHA256: previous, AuditSequence: sequence,
	}
	payload, err := event.CanonicalBytes()
	if err != nil {
		t.Fatalf("audit intent CanonicalBytes: %v", err)
	}
	signed := f.signedRecord(t, schema.MessageTypeAuditEvent, auditPurpose, f.profile.AuditReplayDomainID, payload,
		f.keys["key-audit"], event.OccurredAtUnixNano, sequence, testID(byte(0xd0+sequence)), intent.CorrelationID, event.CausationID)
	return AuditAppendCommand{
		AtUnixNano: intent.OccurredAtUnixNano, Event: signed,
		SourceRecordDigestsSHA256: append([][ccse.DigestSize]byte(nil), intent.EvidenceDigestsSHA256...),
	}
}

func (f *governanceFixture) mutateAndResignAudit(t testing.TB, signed SignedRecord, mutate func(*foundationv1.AuditEventSigningProjection)) SignedRecord {
	t.Helper()
	decoded, err := f.planner.canonical.Decode(schema.MessageTypeAuditEvent, f.profile.SchemaVersion, signed.Record.Payload)
	if err != nil {
		t.Fatal(err)
	}
	event, ok := decoded.(foundationv1.AuditEventSigningProjection)
	if !ok {
		t.Fatal("decoded audit projection has wrong type")
	}
	mutate(&event)
	payload, err := event.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return f.signedRecord(t, schema.MessageTypeAuditEvent, auditPurpose, f.profile.AuditReplayDomainID, payload,
		f.keys["key-audit"], signed.Record.Domain.IssuedAtUnixNano, event.AuditSequence, signed.Record.Envelope.MessageID,
		event.CorrelationID, event.CausationID)
}

func (f *governanceFixture) policyRecordFromProjection(t testing.TB, policy foundationv1.PolicyBundleSigningProjection, scopes []string) PolicyRecordSnapshot {
	t.Helper()
	payload, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatalf("policy record CanonicalBytes: %v", err)
	}
	record := PolicyRecordSnapshot{
		BundleDigestSHA256: sha256.Sum256(payload), CanonicalPayload: append([]byte(nil), payload...),
		GovernanceProfileDigestSHA256: f.profileDigest, RecordID: policy.Metadata.RecordID,
		HomeRegion: policy.Metadata.HomeRegion, WriterEpoch: policy.Metadata.WriterEpoch, StateVersion: policy.Metadata.StateVersion,
		PolicyBundleID: policy.PolicyBundleID, PolicyKind: policy.PolicyKind,
		PolicyVersion: ccse.Version{Major: policy.PolicyVersion.Major, Minor: policy.PolicyVersion.Minor}, Sequence: policy.Sequence,
		PredecessorPresent: policy.PredecessorDigestSHA256.Present, PredecessorDigestSHA256: policy.PredecessorDigestSHA256.Value,
		RollbackTargetPresent: policy.RollbackTargetDigestSHA256.Present, RollbackTargetDigestSHA256: policy.RollbackTargetDigestSHA256.Value,
		State: policy.State, ApprovedAtUnixNano: policy.ApprovedAtUnixNano, EffectiveAtUnixNano: policy.EffectiveAtUnixNano,
		ExpiresAtUnixNano: policy.ExpiresAtUnixNano, PolicyDocumentDigestSHA256: policy.PolicyDocumentDigestSHA256,
		PolicyDocumentMediaType: policy.PolicyDocumentMediaType, ApproverIdentities: append([]string(nil), policy.ApproverIdentities...),
		ApproverKeyIDs: append([]string(nil), policy.ApproverKeyIDs...), MinimumApprovals: policy.MinimumApprovals,
		Emergency: policy.Emergency, BreakGlassScopes: append([]string(nil), scopes...),
	}
	if policy.BreakGlassExpiresAtUnixNano.Present {
		record.BreakGlassExpiresAtUnixNano = policy.BreakGlassExpiresAtUnixNano.Value
	}
	issuedAt := policy.Metadata.CreatedAtUnixNano
	if policy.State == PolicyStateApprovedDelayed || (policy.State == PolicyStateActive && policy.Emergency) {
		issuedAt = policy.ApprovedAtUnixNano
	}
	record.AcceptanceEvidence = PolicyAcceptanceEvidenceSnapshot{
		AcceptedAtUnixNano: issuedAt, HomeRegion: policy.Metadata.HomeRegion, WriterEpoch: policy.Metadata.WriterEpoch,
		WriterLeaseEvidenceDigestSHA256: testDigest(byte(0x70 + policy.Sequence)),
		WriterLeaseNotBeforeUnixNano:    issuedAt - int64(time.Minute), WriterLeaseNotAfterUnixNano: issuedAt + int64(time.Hour),
		GovernanceProfileDigestSHA256: f.profileDigest, MutationPlanDigestSHA256: testDigest(byte(0x80 + policy.Sequence)),
		DurableResultDigestSHA256: testDigest(byte(0x90 + policy.Sequence)),
	}
	activation, active, activationErr := f.profiles.ActiveGovernanceProfile(context.Background(), issuedAt)
	if activationErr != nil || !active {
		t.Fatalf("historical acceptance activation: %v", activationErr)
	}
	record.AcceptanceEvidence.GovernanceProfileActivation = activation
	correlation := testID(byte(0x20 + policy.Sequence))
	for index, keyID := range policy.ApproverKeyIDs {
		key := f.keys[keyID]
		signed := f.signedRecord(t, schema.MessageTypePolicyBundle, policyPurpose, f.profile.PolicyReplayDomainID, payload, key,
			issuedAt, policy.Sequence+uint64(index), testID(byte(0x30+policy.Sequence+uint64(index))), correlation, foundationv1.OptionalFixedBytes16{})
		record.ApprovalEvidence = append(record.ApprovalEvidence, HistoricalPolicyApprovalEvidence{
			Signed: signed, Key: cloneKeySnapshot(key.snapshot), GovernanceProfileActivation: activation,
		})
	}
	return record
}

func (f *governanceFixture) signedRecord(t testing.TB, messageTypeID uint32, purpose, replayDomain string, payload []byte, key testKey,
	issuedAt int64, counter uint64, messageID, correlationID [ccse.MessageIDSize]byte, causation foundationv1.OptionalFixedBytes16) SignedRecord {
	t.Helper()
	domain := ccse.Domain{
		Purpose: purpose, SenderIdentity: key.snapshot.SubjectIdentity, Audience: append([]string(nil), f.profile.Audience...),
		ChainID: f.profile.ChainID, GenesisHash: f.profile.GenesisHash, Environment: f.profile.Environment,
		ProtocolVersion: f.profile.ProtocolVersion, SchemaVersion: f.profile.SchemaVersion,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: key.snapshot.KeyID,
		IssuedAtUnixNano: issuedAt, ExpiresAtUnixNano: issuedAt + int64(90*time.Minute),
		CounterKind: ccse.CounterSequence, Counter: counter, ReplayDomainID: replayDomain,
	}
	envelope := ccse.Envelope{
		ProtocolVersion: f.profile.ProtocolVersion, SchemaVersion: f.profile.SchemaVersion, MessageID: messageID, CorrelationID: correlationID,
		SenderIdentity: key.snapshot.SubjectIdentity, ChainID: f.profile.ChainID, Environment: f.profile.Environment,
		IssuedAtUnixNano: domain.IssuedAtUnixNano, ExpiresAtUnixNano: domain.ExpiresAtUnixNano,
		CounterKind: ccse.CounterSequence, Counter: counter, SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: key.snapshot.KeyID,
	}
	if causation.Present {
		envelope.CausationID = ccse.OptionalMessageID{Present: true, Value: causation.Value}
	}
	record, err := ccse.NewRecord(messageTypeID, f.profile.SchemaVersion, domain, envelope, payload)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	if err := record.SignEd25519(key.private, ccse.DefaultLimits()); err != nil {
		t.Fatalf("SignEd25519: %v", err)
	}
	registry := ccse.NewMemoryKeyRegistry()
	if err := registry.Add(ccse.KeyRecord{
		KeyID: key.snapshot.KeyID, SubjectIdentity: key.snapshot.SubjectIdentity, Algorithm: key.snapshot.Algorithm,
		PublicKey: append([]byte(nil), key.snapshot.PublicKey...), NotBeforeUnixNano: key.snapshot.NotBeforeUnixNano,
		NotAfterUnixNano: key.snapshot.NotAfterUnixNano, AllowedMessageTypes: append([]uint32(nil), key.snapshot.AllowedMessageTypeIDs...),
	}); err != nil {
		t.Fatalf("registry Add: %v", err)
	}
	validator, err := canonical.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	verifier := ccse.Verifier{
		Expectations: ccse.Expectations{
			MessageTypeID: messageTypeID, SchemaVersion: f.profile.SchemaVersion, ProtocolVersion: f.profile.ProtocolVersion,
			Purpose: purpose, Audience: append([]string(nil), f.profile.Audience...), Environment: f.profile.Environment,
			ChainID: f.profile.ChainID, GenesisHash: f.profile.GenesisHash, ReplayDomainID: replayDomain,
			CounterKind: ccse.CounterSequence, MaxValidityWindow: 2 * time.Hour,
		},
		Clock: ccse.ClockFunc(func() time.Time { return time.Unix(0, issuedAt) }),
		Keys:  registry, Replay: ccse.NewMemoryReplayStore(), Schema: validator,
		Handle: func(context.Context, ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
			return testDigest(0xee), nil
		},
	}
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return SignedRecord{Record: record, Verified: result.Verified}
}

func testDigest(fill byte) (result [ccse.DigestSize]byte) {
	for index := range result {
		result[index] = fill
	}
	return result
}

func testID(fill byte) (result [ccse.MessageIDSize]byte) {
	for index := range result {
		result[index] = fill
	}
	return result
}
