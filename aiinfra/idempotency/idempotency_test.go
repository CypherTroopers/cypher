// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

type memoryView struct {
	snapshot Snapshot
	found    bool
	err      error
}

func (view memoryView) LookupBusinessIdempotency(context.Context, [16]byte) (Snapshot, bool, error) {
	return view.snapshot, view.found, view.err
}

type pairView struct {
	parent      Snapshot
	parentFound bool
	audit       Snapshot
	auditFound  bool
	err         error
}

func (view pairView) LookupBusinessIdempotency(_ context.Context, key [16]byte) (Snapshot, bool, error) {
	if view.parent.Binding.Key == key {
		return view.parent, view.parentFound, view.err
	}
	return view.audit, view.auditFound, view.err
}

func (view pairView) SnapshotBusinessIdempotencyPair(context.Context, [16]byte, [16]byte) (Snapshot, bool, Snapshot, bool, error) {
	return view.parent, view.parentFound, view.audit, view.auditFound, view.err
}

func testBinding(seed byte) Binding {
	var key [16]byte
	key[0] = seed
	request := sha256.Sum256([]byte{seed, 0xa5})
	return Binding{Key: key, Domain: OperationIAMIdentity, OwnerID: "identity-1", RequestDigest: request}
}

func TestPrecheckAbsentCollectingCompletedAndConflict(t *testing.T) {
	binding := testBinding(1)
	decision, err := Precheck(context.Background(), memoryView{}, binding)
	if err != nil || decision.Kind() != Proceed {
		t.Fatalf("absent decision=%v error=%v", decision.Kind(), err)
	}

	progress := sha256.Sum256([]byte("two approvals retained"))
	collecting := Snapshot{Binding: binding, State: StateCollecting, Version: 2, ProgressDigest: progress}
	decision, err = Precheck(context.Background(), memoryView{snapshot: collecting, found: true}, binding)
	if err != nil || decision.Kind() != ContinueCollection || decision.Snapshot() != collecting {
		t.Fatalf("collecting decision=%v error=%v", decision.Kind(), err)
	}

	outcome := sha256.Sum256([]byte("durable result"))
	completed := Snapshot{Binding: binding, State: StateCompleted, Version: 3, ProgressDigest: progress, OutcomeDigest: outcome}
	decision, err = Precheck(context.Background(), memoryView{snapshot: completed, found: true}, binding)
	if err != nil || decision.Kind() != DuplicateCompleted || decision.OutcomeDigest() != outcome {
		t.Fatalf("completed decision=%v error=%v", decision.Kind(), err)
	}

	other := binding
	other.RequestDigest = sha256.Sum256([]byte("different request"))
	if _, err := Precheck(context.Background(), memoryView{snapshot: completed, found: true}, other); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("conflict error=%v", err)
	}
}

func TestPrecheckJoinedRequiresAtomicReachablePair(t *testing.T) {
	parentBinding := testBinding(0x31)
	auditBinding, err := JoinedAuditBinding(parentBinding)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := PrecheckJoined(context.Background(), pairView{}, parentBinding)
	if err != nil || decision.Kind() != Proceed {
		t.Fatalf("absent decision=%v error=%v", decision.Kind(), err)
	}

	parentProgress := sha256.Sum256([]byte("pending mutation and exact audit intent"))
	parentDigest, err := BindingDigest(parentBinding)
	if err != nil {
		t.Fatal(err)
	}
	parent := Snapshot{Binding: parentBinding, State: StateCollecting, Version: 3, ProgressDigest: parentProgress}
	audit := Snapshot{Binding: auditBinding, State: StateCollecting, Version: 1, ProgressDigest: parentDigest}
	decision, err = PrecheckJoined(context.Background(), pairView{parent: parent, parentFound: true, audit: audit, auditFound: true}, parentBinding)
	if err != nil || decision.Kind() != ContinueCollection || decision.ParentSnapshot() != parent || decision.AuditSnapshot() != audit {
		t.Fatalf("collecting decision=%v error=%v", decision.Kind(), err)
	}

	outcome := sha256.Sum256([]byte("atomic mutation and audit result"))
	parent.State, parent.Version, parent.OutcomeDigest = StateCompleted, 4, outcome
	audit.State, audit.Version, audit.OutcomeDigest = StateCompleted, 2, outcome
	decision, err = PrecheckJoined(context.Background(), pairView{parent: parent, parentFound: true, audit: audit, auditFound: true}, parentBinding)
	if err != nil || decision.Kind() != DuplicateCompleted || decision.OutcomeDigest() != outcome {
		t.Fatalf("completed decision=%v outcome=%x error=%v", decision.Kind(), decision.OutcomeDigest(), err)
	}
}

func TestPrecheckJoinedRejectsMixedMissingAndMismatchedPairs(t *testing.T) {
	parentBinding := testBinding(0x32)
	auditBinding, err := JoinedAuditBinding(parentBinding)
	if err != nil {
		t.Fatal(err)
	}
	parentProgress := sha256.Sum256([]byte("pending"))
	parentDigest, err := BindingDigest(parentBinding)
	if err != nil {
		t.Fatal(err)
	}
	parent := Snapshot{Binding: parentBinding, State: StateCollecting, Version: 1, ProgressDigest: parentProgress}
	audit := Snapshot{Binding: auditBinding, State: StateCollecting, Version: 1, ProgressDigest: parentDigest}
	cases := map[string]pairView{
		"missing audit":        {parent: parent, parentFound: true},
		"missing parent":       {audit: audit, auditFound: true},
		"mixed state":          {parent: parent, parentFound: true, audit: Snapshot{Binding: auditBinding, State: StateCompleted, Version: 2, ProgressDigest: parentDigest, OutcomeDigest: sha256.Sum256([]byte("outcome"))}, auditFound: true},
		"wrong audit progress": {parent: parent, parentFound: true, audit: Snapshot{Binding: auditBinding, State: StateCollecting, Version: 1, ProgressDigest: sha256.Sum256([]byte("wrong"))}, auditFound: true},
	}
	for name, view := range cases {
		if _, err := PrecheckJoined(context.Background(), view, parentBinding); !errors.Is(err, ErrJoinedStateMismatch) {
			t.Fatalf("%s error=%v", name, err)
		}
	}

	firstOutcome := sha256.Sum256([]byte("first"))
	secondOutcome := sha256.Sum256([]byte("second"))
	parent.State, parent.Version, parent.OutcomeDigest = StateCompleted, 2, firstOutcome
	audit.State, audit.Version, audit.OutcomeDigest = StateCompleted, 2, secondOutcome
	if _, err := PrecheckJoined(context.Background(), pairView{parent: parent, parentFound: true, audit: audit, auditFound: true}, parentBinding); !errors.Is(err, ErrJoinedStateMismatch) {
		t.Fatalf("different completed outcomes error=%v", err)
	}
	parent.Version, parent.ProgressDigest, parent.OutcomeDigest = 1, [32]byte{}, secondOutcome
	if _, err := PrecheckJoined(context.Background(), pairView{parent: parent, parentFound: true, audit: audit, auditFound: true}, parentBinding); !errors.Is(err, ErrJoinedStateMismatch) {
		t.Fatalf("one-shot parent bypass error=%v", err)
	}
}

func TestClaimsCoverOneShotAndCollectionStateMachine(t *testing.T) {
	binding := testBinding(2)
	outcome := sha256.Sum256([]byte("outcome"))
	progress1 := sha256.Sum256([]byte("approval-a"))
	progress2 := sha256.Sum256([]byte("approval-a+approval-b"))

	oneShot, err := NewReserveCompletion(binding)
	if err != nil || ValidateCommitOutcome(oneShot, outcome) != nil || ValidateCommitOutcome(oneShot, [32]byte{}) == nil {
		t.Fatalf("one-shot claim=%+v err=%v", oneShot, err)
	}
	collect, err := NewReserveCollection(binding, progress1)
	if err != nil || ValidateCommitOutcome(collect, [32]byte{}) != nil || ValidateCommitOutcome(collect, outcome) == nil {
		t.Fatalf("collect claim=%+v err=%v", collect, err)
	}
	snapshot := Snapshot{Binding: binding, State: StateCollecting, Version: 1, ProgressDigest: progress1}
	advance, err := NewAdvanceCollection(snapshot, progress2)
	if err != nil || advance.NextVersion != 2 || advance.NextProgressDigest != progress2 {
		t.Fatalf("advance claim=%+v err=%v", advance, err)
	}
	snapshot.Version = 2
	snapshot.ProgressDigest = progress2
	complete, err := NewCompleteCollection(snapshot)
	if err != nil || complete.NextState != StateCompleted || complete.NextVersion != 3 || ValidateCommitOutcome(complete, outcome) != nil {
		t.Fatalf("complete claim=%+v err=%v", complete, err)
	}
}

func TestCanonicalClaimsIgnoreOrderAndRejectSameKeyConflict(t *testing.T) {
	first, err := NewReserveCompletion(testBinding(3))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewReserveCompletion(testBinding(4))
	if err != nil {
		t.Fatal(err)
	}
	left, err := Digest([]Claim{first, second, first})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Digest([]Claim{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatal("claim order or exact duplicate changed digest")
	}
	conflict := first
	conflict.Binding.Domain = OperationGovernancePolicy
	if _, err := NormalizeClaims([]Claim{first, conflict}); !errors.Is(err, ErrConflictingClaim) {
		t.Fatalf("same raw key cross-domain error=%v", err)
	}
}

func TestMalformedSnapshotsAndClaimsFailClosed(t *testing.T) {
	binding := testBinding(5)
	if _, err := Precheck(context.Background(), memoryView{snapshot: Snapshot{Binding: binding}}, binding); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("nonzero absent snapshot error=%v", err)
	}
	bad := Snapshot{Binding: binding, State: StateCollecting, Version: 1}
	if err := bad.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("collecting without progress error=%v", err)
	}
	outcome := sha256.Sum256([]byte("outcome"))
	progress := sha256.Sum256([]byte("approval collection"))
	for name, snapshot := range map[string]Snapshot{
		"one-shot with collection progress": {Binding: binding, State: StateCompleted, Version: 1, ProgressDigest: progress, OutcomeDigest: outcome},
		"collection without progress":       {Binding: binding, State: StateCompleted, Version: 2, OutcomeDigest: outcome},
	} {
		if err := snapshot.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for name, snapshot := range map[string]Snapshot{
		"one-shot completion":   {Binding: binding, State: StateCompleted, Version: 1, OutcomeDigest: outcome},
		"collection completion": {Binding: binding, State: StateCompleted, Version: 2, ProgressDigest: progress, OutcomeDigest: outcome},
	} {
		if err := snapshot.Validate(); err != nil {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	claim, err := NewReserveCompletion(binding)
	if err != nil {
		t.Fatal(err)
	}
	claim.NextVersion = 2
	if err := claim.Validate(); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("version drift error=%v", err)
	}
}

func TestOperationDomainCatalogIsClosedAndDetached(t *testing.T) {
	want := []struct {
		domain  OperationDomain
		literal string
	}{
		{OperationIAMKeyEnrollment, "cph.aiinfra.iam.key-enrollment.v1"},
		{OperationIAMIdentity, "cph.aiinfra.iam.identity.v1"},
		{OperationIAMKeyLifecycle, "cph.aiinfra.iam.key-lifecycle.v1"},
		{OperationIAMOwnershipTransfer, "cph.aiinfra.iam.ownership-transfer.v1"},
		{OperationIAMOwnershipTransferCutover, "cph.aiinfra.iam.ownership-transfer-cutover.v1"},
		{OperationGovernancePolicy, "cph.aiinfra.governance.policy.v1"},
		{OperationGovernanceAudit, "cph.aiinfra.governance.audit.v1"},
		{OperationJoinedAudit, "cph.aiinfra.joined-audit.v1"},
	}
	got := KnownOperationDomains()
	if len(got) != len(want) {
		t.Fatalf("domains=%v", got)
	}
	for index := range want {
		if string(want[index].domain) != want[index].literal {
			t.Fatalf("constant %d=%q want durable literal %q", index, want[index].domain, want[index].literal)
		}
		if got[index] != want[index].domain {
			t.Fatalf("domain %d=%q want=%q", index, got[index], want[index].domain)
		}
	}
	got[0] = "mutated"
	if KnownOperationDomains()[0] != want[0].domain {
		t.Fatal("domain catalog aliases caller")
	}
}

func TestOwnershipTransferCutoverBindingIsClosedAndSensitive(t *testing.T) {
	authorization := testBinding(0x91)
	authorization.Domain = OperationIAMOwnershipTransfer
	cutover, err := OwnershipTransferCutoverBinding(authorization)
	if err != nil {
		t.Fatal(err)
	}
	parentDigest, err := BindingDigest(authorization)
	if err != nil || cutover.Domain != OperationIAMOwnershipTransferCutover ||
		cutover.OwnerID != authorization.OwnerID || cutover.RequestDigest != parentDigest ||
		cutover.Key == authorization.Key || cutover.Key == ([16]byte{}) {
		t.Fatalf("cutover=%+v parent=%x error=%v", cutover, parentDigest, err)
	}
	joined, err := JoinedAuditBinding(cutover)
	if err != nil || joined.Key == cutover.Key || joined.Key == authorization.Key {
		t.Fatalf("joined=%+v error=%v", joined, err)
	}

	mutations := []Binding{authorization, authorization, authorization, authorization}
	mutations[0].Key[1]++
	mutations[1].OwnerID += "-other"
	mutations[2].RequestDigest[0]++
	mutations[3].Domain = OperationIAMIdentity
	for index, mutation := range mutations {
		derived, deriveErr := OwnershipTransferCutoverBinding(mutation)
		if index == 3 {
			if !errors.Is(deriveErr, ErrInvalidBinding) {
				t.Fatalf("wrong parent domain error=%v", deriveErr)
			}
			continue
		}
		if deriveErr != nil || derived.Key == cutover.Key {
			t.Fatalf("mutation %d cutover=%+v error=%v", index, derived, deriveErr)
		}
	}
}

func TestOwnershipTransferCutoverDerivationGolden(t *testing.T) {
	authorization := testBinding(0x91)
	authorization.Domain = OperationIAMOwnershipTransfer
	parentDigest, err := BindingDigest(authorization)
	if err != nil {
		t.Fatal(err)
	}
	cutover, err := OwnershipTransferCutoverBinding(authorization)
	if err != nil {
		t.Fatal(err)
	}
	cutoverDigest, err := BindingDigest(cutover)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := JoinedAuditBinding(cutover)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := JoinedAuditEventID(cutover)
	if err != nil {
		t.Fatal(err)
	}
	const (
		wantParentDigest  = "26768ff2840033960b6feaccb7bf7425bd610217b231768ffed549fa9e070d34"
		wantCutoverKey    = "661d6a8971d2c5949d228f134dc6058a"
		wantCutoverDigest = "6edb9d4d0705d99948f6a60311bc4a3bf777ba365c912d63c33abf209a2b7352"
		wantJoinedKey     = "ea5f331addfa64d141963be4af8e7ef5"
		wantEventID       = "cph-audit-v1:" + wantJoinedKey
	)
	if hex.EncodeToString(parentDigest[:]) != wantParentDigest ||
		hex.EncodeToString(cutover.Key[:]) != wantCutoverKey ||
		cutover.Domain != OperationIAMOwnershipTransferCutover ||
		cutover.OwnerID != authorization.OwnerID ||
		hex.EncodeToString(cutover.RequestDigest[:]) != wantParentDigest ||
		hex.EncodeToString(cutoverDigest[:]) != wantCutoverDigest ||
		hex.EncodeToString(joined.Key[:]) != wantJoinedKey || eventID != wantEventID {
		t.Fatalf("cutover derivation drift: parent=%x cutover=%+v digest=%x joined=%+v event=%q", parentDigest, cutover, cutoverDigest, joined, eventID)
	}
}

func TestMaximumCompoundClaimBoundary(t *testing.T) {
	claims := make([]Claim, MaxClaims)
	for index := range claims {
		binding := testBinding(byte(index))
		binding.Key[0] = byte(index >> 8)
		binding.Key[1] = byte(index)
		binding.Key[2] = 0xa5
		binding.OwnerID = strings.Repeat("o", MaxOwnerIDBytes)
		claim, err := NewReserveCompletion(binding)
		if err != nil {
			t.Fatalf("claim %d: %v", index, err)
		}
		claims[index] = claim
	}
	encoded, err := CanonicalBytes(claims)
	if err != nil || len(encoded) > MaxCanonicalClaimBytes {
		t.Fatalf("maximum compound shape bytes=%d error=%v", len(encoded), err)
	}
	if _, err := CanonicalBytes(append(claims, claims[0])); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("claim %d boundary error=%v", MaxClaims+1, err)
	}
}

func TestJoinedAuditKeyIsDeterministicDistinctAndBindingSensitive(t *testing.T) {
	binding := testBinding(0x61)
	firstBinding, err := JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	first := firstBinding.Key
	secondBinding, err := JoinedAuditBinding(binding)
	if err != nil || secondBinding != firstBinding || first == binding.Key || first == ([16]byte{}) ||
		firstBinding.Domain != OperationJoinedAudit || firstBinding.RequestDigest == ([32]byte{}) {
		t.Fatalf("derived first=%+v second=%+v error=%v", firstBinding, secondBinding, err)
	}
	digest, err := BindingDigest(binding)
	if err != nil || firstBinding.RequestDigest != digest {
		t.Fatalf("parent binding digest=%x want=%x error=%v", firstBinding.RequestDigest, digest, err)
	}

	mutations := []Binding{binding, binding, binding, binding}
	mutations[0].Key[1]++
	mutations[1].Domain = OperationIAMKeyLifecycle
	mutations[2].OwnerID += "-other"
	mutations[3].RequestDigest[0]++
	for index, mutation := range mutations {
		derived, deriveErr := JoinedAuditBinding(mutation)
		if deriveErr != nil {
			t.Fatalf("mutation %d error=%v", index, deriveErr)
		}
		if derived.Key == first {
			t.Fatalf("mutation %d did not change joined audit key", index)
		}
	}
}

func TestJoinedAuditDerivationGolden(t *testing.T) {
	parent := testBinding(0x61)
	parentDigest, err := BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := JoinedAuditEventID(parent)
	if err != nil {
		t.Fatal(err)
	}
	const (
		wantParentDigest = "710ae4ef5dfc6b1df38ed46072c4087a8e771d8c5262bb3919bf9fd19c5095da"
		wantJoinedKey    = "a9531bdc3c254ea73ae44b38f6301a5f"
		wantOwnerID      = "joined-audit:" + wantParentDigest
		wantEventID      = "cph-audit-v1:" + wantJoinedKey
	)
	if hex.EncodeToString(parentDigest[:]) != wantParentDigest ||
		hex.EncodeToString(joined.Key[:]) != wantJoinedKey ||
		joined.Domain != OperationJoinedAudit || joined.OwnerID != wantOwnerID ||
		hex.EncodeToString(joined.RequestDigest[:]) != wantParentDigest || eventID != wantEventID {
		t.Fatalf("derivation drift: parent=%x joined=%+v event=%q", parentDigest, joined, eventID)
	}
}

func TestClaimDigestGolden(t *testing.T) {
	binding := testBinding(0x61)
	claim, err := NewReserveCollection(binding, sha256.Sum256([]byte("pending mutation and exact audit intent")))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest([]Claim{claim})
	if err != nil {
		t.Fatal(err)
	}
	const want = "2e682e24947a683f96149eda0e78afa342724b1a74ed8d9792ab823983201d0d"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("idempotency claim digest drift: got=%s want=%s", got, want)
	}
}

func TestJoinedAuditEventIDIsDeterministicDistinctAndBindingSensitive(t *testing.T) {
	binding := testBinding(0x71)
	first, err := JoinedAuditEventID(binding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := JoinedAuditEventID(binding)
	if err != nil || first != second || first == "" || first == binding.OwnerID {
		t.Fatalf("derived first=%q second=%q error=%v", first, second, err)
	}

	mutations := []Binding{binding, binding, binding, binding}
	mutations[0].Key[1]++
	mutations[1].Domain = OperationIAMKeyLifecycle
	mutations[2].OwnerID += "-other"
	mutations[3].RequestDigest[0]++
	for index, mutation := range mutations {
		derived, deriveErr := JoinedAuditEventID(mutation)
		if deriveErr != nil {
			t.Fatalf("mutation %d error=%v", index, deriveErr)
		}
		if derived == first {
			t.Fatalf("mutation %d did not change joined audit event ID", index)
		}
	}
}

func TestJoinedAuditRejectsStandaloneAndRecursiveParentDomains(t *testing.T) {
	for _, domain := range []OperationDomain{OperationGovernanceAudit, OperationJoinedAudit} {
		binding := testBinding(byte(len(domain)))
		binding.Domain = domain
		if _, err := JoinedAuditBinding(binding); !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("domain %q error=%v", domain, err)
		}
		if _, err := JoinedAuditEventID(binding); !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("event ID domain %q error=%v", domain, err)
		}
	}
}

func TestJoinedAuditAcceptsEveryMandatoryParentDomain(t *testing.T) {
	for index, domain := range []OperationDomain{
		OperationIAMKeyEnrollment,
		OperationIAMIdentity,
		OperationIAMKeyLifecycle,
		OperationIAMOwnershipTransfer,
		OperationIAMOwnershipTransferCutover,
		OperationGovernancePolicy,
	} {
		binding := testBinding(byte(0x80 + index))
		binding.Domain = domain
		joined, err := JoinedAuditBinding(binding)
		if err != nil || joined.Domain != OperationJoinedAudit {
			t.Fatalf("domain %q binding=%+v error=%v", domain, joined, err)
		}
		if eventID, eventErr := JoinedAuditEventID(binding); eventErr != nil || eventID == "" {
			t.Fatalf("domain %q event ID=%q error=%v", domain, eventID, eventErr)
		}
	}
}

func FuzzClaimCanonicalization(f *testing.F) {
	f.Add(byte(1), "owner-1", byte(ReserveCompletion), uint64(1))
	f.Fuzz(func(t *testing.T, seed byte, ownerID string, rawMode byte, version uint64) {
		binding := testBinding(seed)
		binding.OwnerID = ownerID
		mode := ClaimMode(rawMode%4 + 1)
		progress := sha256.Sum256([]byte{seed, 9})
		claim := Claim{Mode: mode, Binding: binding}
		switch mode {
		case ReserveCompletion:
			claim.NextState, claim.NextVersion = StateCompleted, 1
		case ReserveCollection:
			claim.NextState, claim.NextVersion, claim.NextProgressDigest = StateCollecting, 1, progress
		case AdvanceCollection:
			claim.ExpectedState, claim.ExpectedVersion, claim.ExpectedProgressDigest = StateCollecting, version, progress
			if version != ^uint64(0) {
				claim.NextVersion = version + 1
			}
			claim.NextState = StateCollecting
			claim.NextProgressDigest = sha256.Sum256([]byte{seed, 10})
		case CompleteCollection:
			claim.ExpectedState, claim.ExpectedVersion, claim.ExpectedProgressDigest = StateCollecting, version, progress
			if version != ^uint64(0) {
				claim.NextVersion = version + 1
			}
			claim.NextState, claim.NextProgressDigest = StateCompleted, progress
		}
		canonical, err := CanonicalBytes([]Claim{claim, claim})
		if err != nil {
			return
		}
		again, err := CanonicalBytes([]Claim{claim})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical, again) {
			t.Fatal("canonicalization is not idempotent")
		}
	})
}
