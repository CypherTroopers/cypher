// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

const (
	MaxCompoundMemberClaims         = 384
	MaxCompoundMemberCanonicalBytes = 2 << 20

	compoundMemberClaimsDigestDomain = "CPH-AIIE-BUSINESS-IDEMPOTENCY-COMPOUND-MEMBER-CLAIMS-V1\x00"
)

var (
	ErrInvalidCompoundMemberSnapshot = errors.New("aiinfra idempotency: invalid compound-member snapshot")
	ErrInvalidCompoundMemberClaim    = errors.New("aiinfra idempotency: invalid compound-member claim")
	ErrCompoundParentMismatch        = errors.New("aiinfra idempotency: compound member is bound to a different parent")
	ErrCompoundStateMismatch         = errors.New("aiinfra idempotency: compound member and parent audit are not an atomic state")
)

// CompoundMemberSnapshot is a globally unique business-key alias owned by one
// atomic umbrella operation. It is deliberately not a normal Snapshot: no
// independently derived joined-audit Y exists for a compound member. The
// umbrella parent owns the one canonical audit and durable outcome.
//
// Version 1 is COLLECTING and version 2 is COMPLETED. ProgressDigest commits
// the member mutation and complete umbrella core. A completed row copies the
// umbrella outcome digest and storage must enforce that equality in the same
// transaction.
type CompoundMemberSnapshot struct {
	Binding        Binding
	ParentBinding  Binding
	State          State
	Version        uint64
	ProgressDigest [sha256.Size]byte
	OutcomeDigest  [sha256.Size]byte
}

func (snapshot CompoundMemberSnapshot) Validate() error {
	if !validCompoundMemberBindings(snapshot.ParentBinding, snapshot.Binding) ||
		snapshot.ProgressDigest == ([sha256.Size]byte{}) {
		return ErrInvalidCompoundMemberSnapshot
	}
	switch snapshot.State {
	case StateCollecting:
		if snapshot.Version != 1 || snapshot.OutcomeDigest != ([sha256.Size]byte{}) {
			return ErrInvalidCompoundMemberSnapshot
		}
	case StateCompleted:
		if snapshot.Version != 2 || snapshot.OutcomeDigest == ([sha256.Size]byte{}) {
			return ErrInvalidCompoundMemberSnapshot
		}
	default:
		return ErrInvalidCompoundMemberSnapshot
	}
	return nil
}

// CompoundMemberView reads the member plus its umbrella X/Y rows from one
// transactionally consistent snapshot. Implementations return memberFound
// false for a normal row; the database unique key still makes both row kinds
// mutually exclusive. Composing this method from independent reads is not
// equivalent.
type CompoundMemberView interface {
	SnapshotCompoundMemberState(context.Context, [ccse.MessageIDSize]byte) (
		CompoundMemberSnapshot, bool, Snapshot, bool, Snapshot, bool, error)
}

type CompoundMemberDecision struct {
	kind     DecisionKind
	snapshot CompoundMemberSnapshot
}

func (decision CompoundMemberDecision) Kind() DecisionKind { return decision.kind }
func (decision CompoundMemberDecision) Snapshot() CompoundMemberSnapshot {
	return decision.snapshot
}
func (decision CompoundMemberDecision) OutcomeDigest() [sha256.Size]byte {
	if decision.kind != DuplicateCompleted {
		return [sha256.Size]byte{}
	}
	return decision.snapshot.OutcomeDigest
}

// PrecheckCompoundMember runs before a normal joined-pair precheck. It lets an
// exact child retry recover the umbrella outcome without inventing a missing
// child audit row. A binding mismatch remains a global raw-key conflict.
func PrecheckCompoundMember(ctx context.Context, view CompoundMemberView,
	binding Binding) (CompoundMemberDecision, error) {
	if view == nil {
		return CompoundMemberDecision{}, ErrViewRequired
	}
	if err := ctx.Err(); err != nil {
		return CompoundMemberDecision{}, err
	}
	if err := binding.Validate(); err != nil || !IsCompoundMemberDomain(binding.Domain) {
		return CompoundMemberDecision{}, ErrInvalidBinding
	}
	snapshot, found, parentSnapshot, parentFound, auditSnapshot, auditFound, err :=
		view.SnapshotCompoundMemberState(ctx, binding.Key)
	if err != nil {
		return CompoundMemberDecision{}, fmt.Errorf("aiinfra idempotency: compound-member lookup: %w", err)
	}
	if !found {
		if snapshot != (CompoundMemberSnapshot{}) || parentFound || auditFound ||
			parentSnapshot != (Snapshot{}) || auditSnapshot != (Snapshot{}) {
			return CompoundMemberDecision{}, ErrInvalidCompoundMemberSnapshot
		}
		return CompoundMemberDecision{kind: Proceed}, nil
	}
	if err := snapshot.Validate(); err != nil {
		return CompoundMemberDecision{}, err
	}
	if snapshot.Binding != binding {
		return CompoundMemberDecision{}, ErrBindingConflict
	}
	auditBinding, err := JoinedAuditBinding(snapshot.ParentBinding)
	if err != nil || !parentFound || !auditFound || parentSnapshot.Validate() != nil ||
		auditSnapshot.Validate() != nil || parentSnapshot.Binding != snapshot.ParentBinding ||
		auditSnapshot.Binding != auditBinding {
		return CompoundMemberDecision{}, ErrCompoundStateMismatch
	}
	parentDigest, err := BindingDigest(snapshot.ParentBinding)
	if err != nil || auditSnapshot.ProgressDigest != parentDigest {
		return CompoundMemberDecision{}, ErrCompoundStateMismatch
	}
	if snapshot.State == StateCollecting {
		if parentSnapshot.State != StateCollecting || parentSnapshot.Version != 1 ||
			auditSnapshot.State != StateCollecting ||
			auditSnapshot.Version != 1 || parentSnapshot.OutcomeDigest != ([sha256.Size]byte{}) ||
			auditSnapshot.OutcomeDigest != ([sha256.Size]byte{}) {
			return CompoundMemberDecision{}, ErrCompoundStateMismatch
		}
		return CompoundMemberDecision{kind: ContinueCollection, snapshot: snapshot}, nil
	}
	if parentSnapshot.State != StateCompleted || auditSnapshot.State != StateCompleted ||
		parentSnapshot.Version != 2 || parentSnapshot.ProgressDigest == ([sha256.Size]byte{}) ||
		auditSnapshot.Version != 2 || snapshot.OutcomeDigest != parentSnapshot.OutcomeDigest ||
		snapshot.OutcomeDigest != auditSnapshot.OutcomeDigest {
		return CompoundMemberDecision{}, ErrCompoundStateMismatch
	}
	return CompoundMemberDecision{kind: DuplicateCompleted, snapshot: snapshot}, nil
}

// PrecheckCompoundMemberForParent additionally pins the exact umbrella
// binding. It is used while reloading a pending cutover and never treats a
// member collected by another compound operation as resumable.
func PrecheckCompoundMemberForParent(ctx context.Context, view CompoundMemberView,
	parent, member Binding) (CompoundMemberDecision, error) {
	if !validCompoundMemberBindings(parent, member) {
		return CompoundMemberDecision{}, ErrInvalidBinding
	}
	decision, err := PrecheckCompoundMember(ctx, view, member)
	if err != nil || decision.kind == Proceed {
		return decision, err
	}
	if decision.snapshot.ParentBinding != parent {
		return CompoundMemberDecision{}, ErrCompoundParentMismatch
	}
	return decision, nil
}

type CompoundMemberClaimMode uint8

const (
	ReserveCompoundMember CompoundMemberClaimMode = iota + 1
	CompleteCompoundMember
)

// CompoundMemberClaim is separate from Claim so a storage adapter cannot
// accidentally create an ordinary X row with no Y. Binding.Key remains the
// sole global uniqueness key across both claim types.
type CompoundMemberClaim struct {
	Mode            CompoundMemberClaimMode
	Binding         Binding
	ParentBinding   Binding
	ExpectedState   State
	ExpectedVersion uint64
	NextState       State
	NextVersion     uint64
	ProgressDigest  [sha256.Size]byte
}

func NewReserveCompoundMember(parent, member Binding,
	progress [sha256.Size]byte) (CompoundMemberClaim, error) {
	claim := CompoundMemberClaim{Mode: ReserveCompoundMember, Binding: member,
		ParentBinding: parent, NextState: StateCollecting, NextVersion: 1,
		ProgressDigest: progress}
	if err := claim.Validate(); err != nil {
		return CompoundMemberClaim{}, err
	}
	return claim, nil
}

func NewCompleteCompoundMember(snapshot CompoundMemberSnapshot) (CompoundMemberClaim, error) {
	if err := snapshot.Validate(); err != nil || snapshot.State != StateCollecting {
		return CompoundMemberClaim{}, ErrInvalidCompoundMemberSnapshot
	}
	claim := CompoundMemberClaim{Mode: CompleteCompoundMember, Binding: snapshot.Binding,
		ParentBinding: snapshot.ParentBinding, ExpectedState: StateCollecting,
		ExpectedVersion: 1, NextState: StateCompleted, NextVersion: 2,
		ProgressDigest: snapshot.ProgressDigest}
	if err := claim.Validate(); err != nil {
		return CompoundMemberClaim{}, err
	}
	return claim, nil
}

func (claim CompoundMemberClaim) Validate() error {
	if !validCompoundMemberBindings(claim.ParentBinding, claim.Binding) ||
		claim.ProgressDigest == ([sha256.Size]byte{}) {
		return ErrInvalidCompoundMemberClaim
	}
	switch claim.Mode {
	case ReserveCompoundMember:
		if claim.ExpectedState != 0 || claim.ExpectedVersion != 0 ||
			claim.NextState != StateCollecting || claim.NextVersion != 1 {
			return ErrInvalidCompoundMemberClaim
		}
	case CompleteCompoundMember:
		if claim.ExpectedState != StateCollecting || claim.ExpectedVersion != 1 ||
			claim.NextState != StateCompleted || claim.NextVersion != 2 {
			return ErrInvalidCompoundMemberClaim
		}
	default:
		return ErrInvalidCompoundMemberClaim
	}
	return nil
}

func ValidateCompoundMemberOutcome(claim CompoundMemberClaim,
	outcome [sha256.Size]byte) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	if claim.Mode == CompleteCompoundMember {
		if outcome == ([sha256.Size]byte{}) {
			return ErrInvalidDisposition
		}
		return nil
	}
	if outcome != ([sha256.Size]byte{}) {
		return ErrInvalidDisposition
	}
	return nil
}

func NormalizeCompoundMemberClaims(input []CompoundMemberClaim) ([]CompoundMemberClaim, error) {
	if len(input) == 0 || len(input) > MaxCompoundMemberClaims {
		return nil, ErrInvalidCompoundMemberClaim
	}
	claims := append([]CompoundMemberClaim(nil), input...)
	for index := range claims {
		if err := claims[index].Validate(); err != nil {
			return nil, fmt.Errorf("%w at index %d", ErrInvalidCompoundMemberClaim, index)
		}
	}
	sort.Slice(claims, func(i, j int) bool {
		return bytes.Compare(claims[i].Binding.Key[:], claims[j].Binding.Key[:]) < 0
	})
	result := claims[:0]
	parent := claims[0].ParentBinding
	for _, claim := range claims {
		if claim.ParentBinding != parent {
			return nil, ErrCompoundParentMismatch
		}
		if len(result) == 0 || result[len(result)-1].Binding.Key != claim.Binding.Key {
			result = append(result, claim)
			continue
		}
		if result[len(result)-1] != claim {
			return nil, ErrConflictingClaim
		}
	}
	return append([]CompoundMemberClaim(nil), result...), nil
}

func CompoundMemberCanonicalBytes(input []CompoundMemberClaim) ([]byte, error) {
	claims, err := NormalizeCompoundMemberClaims(input)
	if err != nil {
		return nil, err
	}
	elements := make([][]byte, len(claims))
	for index, claim := range claims {
		member, memberErr := canonicalBinding(claim.Binding)
		parent, parentErr := canonicalBinding(claim.ParentBinding)
		if memberErr != nil || parentErr != nil {
			return nil, ErrInvalidCompoundMemberClaim
		}
		elements[index], err = ccse.Marshal(16<<10, func(out *ccse.Encoder) {
			out.Uint32(uint32(claim.Mode))
			out.Bytes(member)
			out.Bytes(parent)
			out.Uint32(uint32(claim.ExpectedState))
			out.Uint64(claim.ExpectedVersion)
			out.Uint32(uint32(claim.NextState))
			out.Uint64(claim.NextVersion)
			out.FixedBytes(claim.ProgressDigest[:], sha256.Size)
		})
		if err != nil {
			return nil, fmt.Errorf("%w: encode claim %d: %v", ErrInvalidCompoundMemberClaim, index, err)
		}
	}
	return ccse.Marshal(MaxCompoundMemberCanonicalBytes,
		func(out *ccse.Encoder) { out.EncodedList(elements) })
}

func CompoundMemberDigest(input []CompoundMemberClaim) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	encoded, err := CompoundMemberCanonicalBytes(input)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(compoundMemberClaimsDigestDomain))
	_, _ = hash.Write(encoded)
	copy(result[:], hash.Sum(nil))
	return result, nil
}

// ValidateDisjointClaimKeys enforces the storage invariant before a compound
// transaction is handed to an adapter. A raw key cannot be both an ordinary
// idempotency row and a compound-member alias.
func ValidateDisjointClaimKeys(ordinary []Claim, members []CompoundMemberClaim) error {
	normalizedOrdinary, err := NormalizeClaims(ordinary)
	if err != nil {
		return err
	}
	normalizedMembers, err := NormalizeCompoundMemberClaims(members)
	if err != nil {
		return err
	}
	ordinaryKeys := make(map[[ccse.MessageIDSize]byte]struct{}, len(normalizedOrdinary))
	for _, claim := range normalizedOrdinary {
		ordinaryKeys[claim.Binding.Key] = struct{}{}
	}
	for _, claim := range normalizedMembers {
		if _, exists := ordinaryKeys[claim.Binding.Key]; exists {
			return ErrConflictingClaim
		}
	}
	return nil
}

func validCompoundMemberBindings(parent, member Binding) bool {
	if parent.Validate() != nil || member.Validate() != nil ||
		parent.Domain != OperationIAMOwnershipTransferCutover ||
		!IsCompoundMemberDomain(member.Domain) || parent.Key == member.Key {
		return false
	}
	return true
}

// IsCompoundMemberDomain reports the closed v1 set of child operation domains
// which may be represented by an ownership-cutover alias. Callers use it to
// route ordinary cutover X through the normal joined-pair precheck.
func IsCompoundMemberDomain(domain OperationDomain) bool {
	switch domain {
	case OperationIAMKeyEnrollment, OperationIAMIdentity, OperationIAMKeyLifecycle:
		return true
	default:
		return false
	}
}
