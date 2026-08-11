// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type compoundMemoryView struct {
	snapshot    CompoundMemberSnapshot
	found       bool
	parent      Snapshot
	parentFound bool
	audit       Snapshot
	auditFound  bool
	err         error
}

func (view compoundMemoryView) SnapshotCompoundMemberState(context.Context,
	[16]byte) (CompoundMemberSnapshot, bool, Snapshot, bool, Snapshot, bool, error) {
	return view.snapshot, view.found, view.parent, view.parentFound,
		view.audit, view.auditFound, view.err
}

func compoundBindings() (Binding, Binding) {
	authorization := testBinding(0x91)
	authorization.Domain = OperationIAMOwnershipTransfer
	parent, _ := OwnershipTransferCutoverBinding(authorization)
	member := testBinding(0xa1)
	member.Domain = OperationIAMKeyLifecycle
	member.OwnerID = "key-1"
	return parent, member
}

func TestCompoundMemberStateMachineAndRecovery(t *testing.T) {
	parent, member := compoundBindings()
	progress := sha256.Sum256([]byte("exact child mutation plus umbrella core"))
	parentProgress := sha256.Sum256([]byte("umbrella pending core"))
	parentDigest, err := BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	auditBinding, err := JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := NewReserveCompoundMember(parent, member, progress)
	if err != nil || ValidateCompoundMemberOutcome(reserve, [32]byte{}) != nil {
		t.Fatalf("reserve=%+v error=%v", reserve, err)
	}
	collecting := CompoundMemberSnapshot{Binding: member, ParentBinding: parent,
		State: StateCollecting, Version: 1, ProgressDigest: progress}
	parentSnapshot := Snapshot{Binding: parent, State: StateCollecting, Version: 1,
		ProgressDigest: parentProgress}
	auditSnapshot := Snapshot{Binding: auditBinding, State: StateCollecting, Version: 1,
		ProgressDigest: parentDigest}
	decision, err := PrecheckCompoundMemberForParent(context.Background(),
		compoundMemoryView{snapshot: collecting, found: true, parent: parentSnapshot,
			parentFound: true, audit: auditSnapshot, auditFound: true}, parent, member)
	if err != nil || decision.Kind() != ContinueCollection || decision.Snapshot() != collecting {
		t.Fatalf("collecting decision=%+v error=%v", decision, err)
	}
	complete, err := NewCompleteCompoundMember(collecting)
	outcome := sha256.Sum256([]byte("umbrella durable outcome"))
	if err != nil || ValidateCompoundMemberOutcome(complete, outcome) != nil ||
		ValidateCompoundMemberOutcome(complete, [32]byte{}) == nil {
		t.Fatalf("complete=%+v error=%v", complete, err)
	}
	completed := collecting
	completed.State, completed.Version, completed.OutcomeDigest = StateCompleted, 2, outcome
	parentSnapshot.State, parentSnapshot.Version, parentSnapshot.OutcomeDigest = StateCompleted, 2, outcome
	auditSnapshot.State, auditSnapshot.Version, auditSnapshot.OutcomeDigest = StateCompleted, 2, outcome
	decision, err = PrecheckCompoundMember(context.Background(),
		compoundMemoryView{snapshot: completed, found: true, parent: parentSnapshot,
			parentFound: true, audit: auditSnapshot, auditFound: true}, member)
	if err != nil || decision.Kind() != DuplicateCompleted || decision.OutcomeDigest() != outcome {
		t.Fatalf("completed decision=%+v error=%v", decision, err)
	}
}

func TestCompoundMemberRejectsWrongParentBindingAndRawKeyConflict(t *testing.T) {
	parent, member := compoundBindings()
	progress := sha256.Sum256([]byte("progress"))
	collecting := CompoundMemberSnapshot{Binding: member, ParentBinding: parent,
		State: StateCollecting, Version: 1, ProgressDigest: progress}
	parentProgress := sha256.Sum256([]byte("parent progress"))
	parentDigest, err := BindingDigest(parent)
	if err != nil {
		t.Fatal(err)
	}
	auditBinding, err := JoinedAuditBinding(parent)
	if err != nil {
		t.Fatal(err)
	}
	view := compoundMemoryView{snapshot: collecting, found: true,
		parent: Snapshot{Binding: parent, State: StateCollecting, Version: 1,
			ProgressDigest: parentProgress}, parentFound: true,
		audit: Snapshot{Binding: auditBinding, State: StateCollecting, Version: 1,
			ProgressDigest: parentDigest}, auditFound: true}
	otherParent := parent
	otherParent.RequestDigest[0]++
	if _, err := PrecheckCompoundMemberForParent(context.Background(),
		view, otherParent, member); !errors.Is(err, ErrCompoundParentMismatch) {
		t.Fatalf("wrong parent error=%v", err)
	}
	memberConflict := member
	memberConflict.RequestDigest[0]++
	if _, err := PrecheckCompoundMember(context.Background(),
		view, memberConflict); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("member conflict error=%v", err)
	}
	ordinary, err := NewReserveCompletion(member)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := NewReserveCompoundMember(parent, member, progress)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDisjointClaimKeys([]Claim{ordinary}, []CompoundMemberClaim{alias}); !errors.Is(err, ErrConflictingClaim) {
		t.Fatalf("cross-kind raw key conflict error=%v", err)
	}
}

func TestCompoundMemberRejectsOrphanAndOutcomeDrift(t *testing.T) {
	parent, member := compoundBindings()
	progress := sha256.Sum256([]byte("progress"))
	memberSnapshot := CompoundMemberSnapshot{Binding: member, ParentBinding: parent,
		State: StateCollecting, Version: 1, ProgressDigest: progress}
	if _, err := PrecheckCompoundMember(context.Background(),
		compoundMemoryView{snapshot: memberSnapshot, found: true}, member); !errors.Is(err, ErrCompoundStateMismatch) {
		t.Fatalf("orphan error=%v", err)
	}
	parentDigest, _ := BindingDigest(parent)
	auditBinding, _ := JoinedAuditBinding(parent)
	firstOutcome := sha256.Sum256([]byte("first"))
	secondOutcome := sha256.Sum256([]byte("second"))
	memberSnapshot.State, memberSnapshot.Version, memberSnapshot.OutcomeDigest = StateCompleted, 2, firstOutcome
	view := compoundMemoryView{snapshot: memberSnapshot, found: true,
		parent: Snapshot{Binding: parent, State: StateCompleted, Version: 2,
			ProgressDigest: sha256.Sum256([]byte("parent")), OutcomeDigest: firstOutcome}, parentFound: true,
		audit: Snapshot{Binding: auditBinding, State: StateCompleted, Version: 2,
			ProgressDigest: parentDigest, OutcomeDigest: secondOutcome}, auditFound: true}
	if _, err := PrecheckCompoundMember(context.Background(), view, member); !errors.Is(err, ErrCompoundStateMismatch) {
		t.Fatalf("outcome drift error=%v", err)
	}
}

func TestCompoundMemberCanonicalizationAndGolden(t *testing.T) {
	parent, member := compoundBindings()
	progress := sha256.Sum256([]byte("exact child mutation plus umbrella core"))
	first, err := NewReserveCompoundMember(parent, member, progress)
	if err != nil {
		t.Fatal(err)
	}
	secondMember := member
	secondMember.Key[1]++
	secondMember.OwnerID = "key-2"
	second, err := NewReserveCompoundMember(parent, secondMember,
		sha256.Sum256([]byte("second child")))
	if err != nil {
		t.Fatal(err)
	}
	left, err := CompoundMemberDigest([]CompoundMemberClaim{first, second, first})
	if err != nil {
		t.Fatal(err)
	}
	right, err := CompoundMemberDigest([]CompoundMemberClaim{second, first})
	if err != nil || left != right {
		t.Fatalf("canonical digest mismatch left=%x right=%x error=%v", left, right, err)
	}
	const want = "a607aaf0b0129fd6259e04f89a2b6f077f8a62bb1be49da9534096ac334272a6"
	if got := hex.EncodeToString(left[:]); got != want {
		t.Fatalf("compound-member digest drift: got=%s want=%s", got, want)
	}
}

func TestCompoundMemberClaimBatchRequiresOneParent(t *testing.T) {
	parent, member := compoundBindings()
	first, err := NewReserveCompoundMember(parent, member, sha256.Sum256([]byte("first")))
	if err != nil {
		t.Fatal(err)
	}
	otherParent := parent
	otherParent.RequestDigest[0]++
	otherMember := member
	otherMember.Key[1]++
	second, err := NewReserveCompoundMember(otherParent, otherMember,
		sha256.Sum256([]byte("second")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeCompoundMemberClaims([]CompoundMemberClaim{first, second}); !errors.Is(err, ErrCompoundParentMismatch) {
		t.Fatalf("mixed parent error=%v", err)
	}
}

func TestCompoundMemberDomainCatalogIsClosed(t *testing.T) {
	for _, domain := range []OperationDomain{
		OperationIAMKeyEnrollment, OperationIAMIdentity, OperationIAMKeyLifecycle,
	} {
		if !IsCompoundMemberDomain(domain) {
			t.Fatalf("member domain %q rejected", domain)
		}
	}
	for _, domain := range []OperationDomain{
		OperationIAMOwnershipTransfer, OperationIAMOwnershipTransferCutover,
		OperationGovernancePolicy, OperationGovernanceAudit, OperationJoinedAudit,
	} {
		if IsCompoundMemberDomain(domain) {
			t.Fatalf("non-member domain %q accepted", domain)
		}
	}
}

func TestCompoundMemberMaximumBoundary(t *testing.T) {
	parent, template := compoundBindings()
	claims := make([]CompoundMemberClaim, MaxCompoundMemberClaims)
	for index := range claims {
		member := template
		member.Key[0] = byte(index >> 8)
		member.Key[1] = byte(index)
		member.Key[2] = 0xb5
		member.OwnerID = strings.Repeat("m", MaxOwnerIDBytes)
		member.RequestDigest = sha256.Sum256([]byte(fmt.Sprintf("member-%d", index)))
		claim, err := NewReserveCompoundMember(parent, member,
			sha256.Sum256([]byte(fmt.Sprintf("progress-%d", index))))
		if err != nil {
			t.Fatalf("claim %d: %v", index, err)
		}
		claims[index] = claim
	}
	encoded, err := CompoundMemberCanonicalBytes(claims)
	if err != nil || len(encoded) > MaxCompoundMemberCanonicalBytes {
		t.Fatalf("maximum compound-member shape bytes=%d error=%v", len(encoded), err)
	}
	if _, err := CompoundMemberCanonicalBytes(append(claims, claims[0])); !errors.Is(err, ErrInvalidCompoundMemberClaim) {
		t.Fatalf("claim %d boundary error=%v", MaxCompoundMemberClaims+1, err)
	}
}

func FuzzCompoundMemberClaimCanonicalization(f *testing.F) {
	f.Add(byte(1), byte(2), "member-1")
	f.Fuzz(func(t *testing.T, parentSeed, memberSeed byte, owner string) {
		authorization := testBinding(parentSeed)
		authorization.Domain = OperationIAMOwnershipTransfer
		parent, err := OwnershipTransferCutoverBinding(authorization)
		if err != nil {
			return
		}
		member := testBinding(memberSeed)
		member.Domain = OperationIAMIdentity
		member.OwnerID = owner
		progress := sha256.Sum256([]byte{parentSeed, memberSeed, 0xc7})
		claim, err := NewReserveCompoundMember(parent, member, progress)
		if err != nil {
			return
		}
		left, err := CompoundMemberCanonicalBytes([]CompoundMemberClaim{claim, claim})
		if err != nil {
			t.Fatal(err)
		}
		right, err := CompoundMemberCanonicalBytes([]CompoundMemberClaim{claim})
		if err != nil || !bytes.Equal(left, right) {
			t.Fatalf("non-canonical duplicate left=%x right=%x error=%v", left, right, err)
		}
	})
}
