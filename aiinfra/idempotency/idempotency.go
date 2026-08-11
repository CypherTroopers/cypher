// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"golang.org/x/text/unicode/norm"
)

const (
	// MaxClaims includes every member operation of the largest closed
	// compound workflow.  An ownership cutover can close 256 predecessor
	// keys, two identity records, one key enrollment, its parent and joined
	// audit rows, plus a small fixed set of coordinator assertions.  Keep a
	// bounded margin without making this an unbounded batch API.
	MaxClaims              = 384
	MaxOwnerIDBytes        = 1024
	MaxCanonicalClaimBytes = 1 << 20

	claimDigestDomain                 = "CPH-AIIE-BUSINESS-IDEMPOTENCY-CLAIMS-V1\x00"
	bindingDigestDomain               = "CPH-AIIE-BUSINESS-IDEMPOTENCY-BINDING-V1\x00"
	joinedAuditKeyDomain              = "CPH-AIIE-JOINED-AUDIT-IDEMPOTENCY-KEY-V1\x00"
	ownershipTransferCutoverKeyDomain = "CPH-AIIE-IAM-OWNERSHIP-TRANSFER-CUTOVER-IDEMPOTENCY-KEY-V1\x00"
	joinedAuditEventIDPrefix          = globalid.JoinedAuditEventIDPrefix
)

var (
	ErrViewRequired        = errors.New("aiinfra idempotency: view is required")
	ErrInvalidBinding      = errors.New("aiinfra idempotency: invalid binding")
	ErrInvalidSnapshot     = errors.New("aiinfra idempotency: invalid snapshot")
	ErrBindingConflict     = errors.New("aiinfra idempotency: key is bound to a different request")
	ErrInvalidClaim        = errors.New("aiinfra idempotency: invalid claim")
	ErrConflictingClaim    = errors.New("aiinfra idempotency: conflicting claim")
	ErrInvalidDisposition  = errors.New("aiinfra idempotency: decision does not support requested transition")
	ErrDerivedKeyCollision = errors.New("aiinfra idempotency: derived key collides with a reserved value")
	ErrJoinedStateMismatch = errors.New("aiinfra idempotency: parent and joined-audit rows are not an atomic pair")
)

// OperationDomain is binding metadata, never a uniqueness namespace. Durable
// storage MUST use Binding.Key alone as its unique key.
type OperationDomain string

const (
	OperationIAMKeyEnrollment            OperationDomain = "cph.aiinfra.iam.key-enrollment.v1"
	OperationIAMIdentity                 OperationDomain = "cph.aiinfra.iam.identity.v1"
	OperationIAMKeyLifecycle             OperationDomain = "cph.aiinfra.iam.key-lifecycle.v1"
	OperationIAMOwnershipTransfer        OperationDomain = "cph.aiinfra.iam.ownership-transfer.v1"
	OperationIAMOwnershipTransferCutover OperationDomain = "cph.aiinfra.iam.ownership-transfer-cutover.v1"
	OperationGovernancePolicy            OperationDomain = "cph.aiinfra.governance.policy.v1"
	OperationGovernanceAudit             OperationDomain = "cph.aiinfra.governance.audit.v1"
	OperationJoinedAudit                 OperationDomain = "cph.aiinfra.joined-audit.v1"
)

var operationDomains = [...]OperationDomain{
	OperationIAMKeyEnrollment,
	OperationIAMIdentity,
	OperationIAMKeyLifecycle,
	OperationIAMOwnershipTransfer,
	OperationIAMOwnershipTransferCutover,
	OperationGovernancePolicy,
	OperationGovernanceAudit,
	OperationJoinedAudit,
}

// Binding identifies one logical business request independently of CCSE
// MessageID. A retry may carry a newly signed MessageID but MUST preserve this
// key, owner and canonical request digest.
type Binding struct {
	Key           [ccse.MessageIDSize]byte
	Domain        OperationDomain
	OwnerID       string
	RequestDigest [sha256.Size]byte
}

type State uint8

const (
	StateCollecting State = iota + 1
	StateCompleted
)

// Snapshot is the authoritative durable row. COLLECTING is used for bounded
// multi-authorization workflows; COMPLETED binds the stored durable outcome.
type Snapshot struct {
	Binding        Binding
	State          State
	Version        uint64
	ProgressDigest [sha256.Size]byte
	OutcomeDigest  [sha256.Size]byte
}

type View interface {
	LookupBusinessIdempotency(context.Context, [ccse.MessageIDSize]byte) (Snapshot, bool, error)
}

// JoinedView returns one transactionally consistent snapshot of a parent
// operation and its mandatory joined-audit reservation. Implementations MUST
// NOT compose this method from two independently committed reads.
type JoinedView interface {
	View
	SnapshotBusinessIdempotencyPair(context.Context, [ccse.MessageIDSize]byte, [ccse.MessageIDSize]byte) (Snapshot, bool, Snapshot, bool, error)
}

type DecisionKind uint8

const (
	Proceed DecisionKind = iota + 1
	ContinueCollection
	DuplicateCompleted
)

// Decision is immutable and contains no caller-owned slices.
type Decision struct {
	kind     DecisionKind
	snapshot Snapshot
}

// JoinedDecision is the only valid admission result for a mutation that
// requires a mandatory audit append. ParentSnapshot and AuditSnapshot are
// detached value types returned from one authoritative pair snapshot.
type JoinedDecision struct {
	kind   DecisionKind
	parent Snapshot
	audit  Snapshot
}

func (decision JoinedDecision) Kind() DecisionKind       { return decision.kind }
func (decision JoinedDecision) ParentSnapshot() Snapshot { return decision.parent }
func (decision JoinedDecision) AuditSnapshot() Snapshot  { return decision.audit }
func (decision JoinedDecision) OutcomeDigest() [sha256.Size]byte {
	if decision.kind != DuplicateCompleted {
		return [sha256.Size]byte{}
	}
	return decision.parent.OutcomeDigest
}

func (decision Decision) Kind() DecisionKind { return decision.kind }
func (decision Decision) Snapshot() Snapshot { return decision.snapshot }
func (decision Decision) OutcomeDigest() [sha256.Size]byte {
	if decision.kind != DuplicateCompleted {
		return [sha256.Size]byte{}
	}
	return decision.snapshot.OutcomeDigest
}

// Precheck must run before semantic state lookup. An exact completed request
// returns its durable outcome without invoking a planner against advanced
// state. Binding mismatch always fails closed.
func Precheck(ctx context.Context, view View, binding Binding) (Decision, error) {
	if view == nil {
		return Decision{}, ErrViewRequired
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if err := binding.Validate(); err != nil {
		return Decision{}, err
	}
	snapshot, found, err := view.LookupBusinessIdempotency(ctx, binding.Key)
	if err != nil {
		return Decision{}, fmt.Errorf("aiinfra idempotency: lookup: %w", err)
	}
	if !found {
		if snapshot != (Snapshot{}) {
			return Decision{}, ErrInvalidSnapshot
		}
		return Decision{kind: Proceed}, nil
	}
	if err := snapshot.Validate(); err != nil {
		return Decision{}, err
	}
	if snapshot.Binding != binding {
		return Decision{}, ErrBindingConflict
	}
	switch snapshot.State {
	case StateCollecting:
		return Decision{kind: ContinueCollection, snapshot: snapshot}, nil
	case StateCompleted:
		return Decision{kind: DuplicateCompleted, snapshot: snapshot}, nil
	default:
		return Decision{}, ErrInvalidSnapshot
	}
}

// PrecheckJoined validates a mutation row and its pre-reserved audit row as one
// state machine. Mixed presence/state/outcome is never treated as retryable.
func PrecheckJoined(ctx context.Context, view JoinedView, parent Binding) (JoinedDecision, error) {
	if view == nil {
		return JoinedDecision{}, ErrViewRequired
	}
	if err := ctx.Err(); err != nil {
		return JoinedDecision{}, err
	}
	auditBinding, err := JoinedAuditBinding(parent)
	if err != nil {
		return JoinedDecision{}, err
	}
	parentSnapshot, parentFound, auditSnapshot, auditFound, err := view.SnapshotBusinessIdempotencyPair(ctx, parent.Key, auditBinding.Key)
	if err != nil {
		return JoinedDecision{}, fmt.Errorf("aiinfra idempotency: joined lookup: %w", err)
	}
	if !parentFound && !auditFound {
		if parentSnapshot != (Snapshot{}) || auditSnapshot != (Snapshot{}) {
			return JoinedDecision{}, ErrInvalidSnapshot
		}
		return JoinedDecision{kind: Proceed}, nil
	}
	if !parentFound || !auditFound || parentSnapshot.Validate() != nil || auditSnapshot.Validate() != nil ||
		parentSnapshot.Binding != parent || auditSnapshot.Binding != auditBinding {
		return JoinedDecision{}, ErrJoinedStateMismatch
	}
	parentDigest, err := BindingDigest(parent)
	if err != nil {
		return JoinedDecision{}, err
	}
	if auditSnapshot.ProgressDigest != parentDigest {
		return JoinedDecision{}, ErrJoinedStateMismatch
	}
	switch {
	case parentSnapshot.State == StateCollecting && auditSnapshot.State == StateCollecting:
		if auditSnapshot.Version != 1 || auditSnapshot.OutcomeDigest != ([sha256.Size]byte{}) {
			return JoinedDecision{}, ErrJoinedStateMismatch
		}
		return JoinedDecision{kind: ContinueCollection, parent: parentSnapshot, audit: auditSnapshot}, nil
	case parentSnapshot.State == StateCompleted && auditSnapshot.State == StateCompleted:
		if parentSnapshot.Version < 2 || parentSnapshot.ProgressDigest == ([sha256.Size]byte{}) ||
			auditSnapshot.Version != 2 || parentSnapshot.OutcomeDigest != auditSnapshot.OutcomeDigest {
			return JoinedDecision{}, ErrJoinedStateMismatch
		}
		return JoinedDecision{kind: DuplicateCompleted, parent: parentSnapshot, audit: auditSnapshot}, nil
	default:
		return JoinedDecision{}, ErrJoinedStateMismatch
	}
}

type ClaimMode uint8

const (
	ReserveCompletion ClaimMode = iota + 1
	ReserveCollection
	AdvanceCollection
	CompleteCollection
)

// Claim describes only business idempotency row state. A completed outcome is
// supplied separately by the durable result writer, avoiding a plan-digest /
// outcome-digest cycle.
type Claim struct {
	Mode                   ClaimMode
	Binding                Binding
	ExpectedState          State
	ExpectedVersion        uint64
	ExpectedProgressDigest [sha256.Size]byte
	NextState              State
	NextVersion            uint64
	NextProgressDigest     [sha256.Size]byte
}

func NewReserveCompletion(binding Binding) (Claim, error) {
	claim := Claim{Mode: ReserveCompletion, Binding: binding, NextState: StateCompleted, NextVersion: 1}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

func NewReserveCollection(binding Binding, progress [sha256.Size]byte) (Claim, error) {
	claim := Claim{Mode: ReserveCollection, Binding: binding, NextState: StateCollecting, NextVersion: 1, NextProgressDigest: progress}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

func NewAdvanceCollection(snapshot Snapshot, nextProgress [sha256.Size]byte) (Claim, error) {
	if err := snapshot.Validate(); err != nil || snapshot.State != StateCollecting || snapshot.Version == math.MaxUint64 {
		return Claim{}, ErrInvalidSnapshot
	}
	claim := Claim{
		Mode: AdvanceCollection, Binding: snapshot.Binding, ExpectedState: snapshot.State,
		ExpectedVersion: snapshot.Version, ExpectedProgressDigest: snapshot.ProgressDigest,
		NextState: StateCollecting, NextVersion: snapshot.Version + 1, NextProgressDigest: nextProgress,
	}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

func NewCompleteCollection(snapshot Snapshot) (Claim, error) {
	if err := snapshot.Validate(); err != nil || snapshot.State != StateCollecting || snapshot.Version == math.MaxUint64 {
		return Claim{}, ErrInvalidSnapshot
	}
	claim := Claim{
		Mode: CompleteCollection, Binding: snapshot.Binding, ExpectedState: snapshot.State,
		ExpectedVersion: snapshot.Version, ExpectedProgressDigest: snapshot.ProgressDigest,
		NextState: StateCompleted, NextVersion: snapshot.Version + 1, NextProgressDigest: snapshot.ProgressDigest,
	}
	if err := claim.Validate(); err != nil {
		return Claim{}, err
	}
	return claim, nil
}

func (binding Binding) Validate() error {
	if binding.Key == ([ccse.MessageIDSize]byte{}) || !knownOperationDomain(binding.Domain) ||
		validateOwnerID(binding.OwnerID) != nil || binding.RequestDigest == ([sha256.Size]byte{}) {
		return ErrInvalidBinding
	}
	return nil
}

// BindingDigest is the stable content identity used to relate a compound
// operation to its mandatory audit reservation.
func BindingDigest(binding Binding) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	encoded, err := canonicalBinding(binding)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(bindingDigestDomain))
	_, _ = hash.Write(encoded)
	copy(result[:], hash.Sum(nil))
	return result, nil
}

// JoinedAuditBinding derives the distinct business reservation of the
// mandatory audit append joined to one state mutation. The parent planner
// reserves this binding atomically with the mutation's binding, before the
// final AuditEvent exists. That closes the interval in which another valid
// operation could squat the predictable raw key. The audit event signs the
// returned key; its complete payload is constrained separately by the parent's
// AuditIntent and the canonical audit planner.
func JoinedAuditBinding(parent Binding) (Binding, error) {
	var result Binding
	if !supportsJoinedAudit(parent.Domain) {
		return result, ErrInvalidBinding
	}
	parentDigest, err := BindingDigest(parent)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(joinedAuditKeyDomain))
	_, _ = hash.Write(parentDigest[:])
	keyDigest := hash.Sum(nil)
	copy(result.Key[:], keyDigest[:ccse.MessageIDSize])
	result.Domain = OperationJoinedAudit
	result.OwnerID = fmt.Sprintf("joined-audit:%x", parentDigest)
	result.RequestDigest = parentDigest
	if result.Key == ([ccse.MessageIDSize]byte{}) || result.Key == parent.Key {
		return Binding{}, ErrDerivedKeyCollision
	}
	if err := result.Validate(); err != nil {
		return Binding{}, err
	}
	return result, nil
}

// OwnershipTransferCutoverBinding derives the distinct business operation
// which atomically applies an already-accepted ownership-transfer
// authorization. Authorization collection and state cutover have different
// durable outcomes and must never reuse one raw idempotency key. The derived
// request digest commits the complete accepted-authorization Binding.
func OwnershipTransferCutoverBinding(authorization Binding) (Binding, error) {
	var result Binding
	if authorization.Domain != OperationIAMOwnershipTransfer {
		return result, ErrInvalidBinding
	}
	parentDigest, err := BindingDigest(authorization)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(ownershipTransferCutoverKeyDomain))
	_, _ = hash.Write(parentDigest[:])
	keyDigest := hash.Sum(nil)
	copy(result.Key[:], keyDigest[:ccse.MessageIDSize])
	result.Domain = OperationIAMOwnershipTransferCutover
	result.OwnerID = authorization.OwnerID
	result.RequestDigest = parentDigest
	if result.Key == ([ccse.MessageIDSize]byte{}) || result.Key == authorization.Key {
		return Binding{}, ErrDerivedKeyCollision
	}
	joined, joinedErr := JoinedAuditBinding(result)
	if joinedErr != nil || result.Key == joined.Key || authorization.Key == joined.Key {
		return Binding{}, ErrDerivedKeyCollision
	}
	if err := result.Validate(); err != nil {
		return Binding{}, err
	}
	return result, nil
}

func supportsJoinedAudit(domain OperationDomain) bool {
	switch domain {
	case OperationIAMKeyEnrollment, OperationIAMIdentity, OperationIAMKeyLifecycle,
		OperationIAMOwnershipTransfer, OperationIAMOwnershipTransferCutover, OperationGovernancePolicy:
		return true
	default:
		return false
	}
}

// JoinedAuditKey is a convenience accessor for JoinedAuditBinding.
func JoinedAuditKey(binding Binding) ([ccse.MessageIDSize]byte, error) {
	joined, err := JoinedAuditBinding(binding)
	if err != nil {
		return [ccse.MessageIDSize]byte{}, err
	}
	return joined.Key, nil
}

// JoinedAuditEventID derives the globally unique canonical AuditEvent ID that
// must be reserved with the parent and joined-audit idempotency rows.  The ID
// is known before an Audit Writer assigns the stream sequence, so pending and
// failed operations cannot leave a squatting window.  Callers reserve this ID
// against its final audit-event owner and retain that reservation as a
// tombstone if the operation is later rejected or expires.
func JoinedAuditEventID(parent Binding) (string, error) {
	joined, err := JoinedAuditBinding(parent)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%x", joinedAuditEventIDPrefix, joined.Key), nil
}

func canonicalBinding(binding Binding) ([]byte, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	encoded, err := ccse.Marshal(8192, func(out *ccse.Encoder) {
		out.FixedBytes(binding.Key[:], ccse.MessageIDSize)
		out.String(string(binding.Domain))
		out.String(binding.OwnerID)
		out.FixedBytes(binding.RequestDigest[:], sha256.Size)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode binding: %v", ErrInvalidBinding, err)
	}
	return encoded, nil
}

func (snapshot Snapshot) Validate() error {
	if snapshot.Binding.Validate() != nil || snapshot.Version == 0 {
		return ErrInvalidSnapshot
	}
	zero := [sha256.Size]byte{}
	switch snapshot.State {
	case StateCollecting:
		if snapshot.ProgressDigest == zero || snapshot.OutcomeDigest != zero {
			return ErrInvalidSnapshot
		}
	case StateCompleted:
		if snapshot.OutcomeDigest == zero ||
			(snapshot.Version == 1 && snapshot.ProgressDigest != zero) ||
			(snapshot.Version > 1 && snapshot.ProgressDigest == zero) {
			return ErrInvalidSnapshot
		}
	default:
		return ErrInvalidSnapshot
	}
	return nil
}

func (claim Claim) Validate() error {
	if claim.Binding.Validate() != nil {
		return ErrInvalidClaim
	}
	zero := [sha256.Size]byte{}
	switch claim.Mode {
	case ReserveCompletion:
		if claim.ExpectedState != 0 || claim.ExpectedVersion != 0 || claim.ExpectedProgressDigest != zero ||
			claim.NextState != StateCompleted || claim.NextVersion != 1 || claim.NextProgressDigest != zero {
			return ErrInvalidClaim
		}
	case ReserveCollection:
		if claim.ExpectedState != 0 || claim.ExpectedVersion != 0 || claim.ExpectedProgressDigest != zero ||
			claim.NextState != StateCollecting || claim.NextVersion != 1 || claim.NextProgressDigest == zero {
			return ErrInvalidClaim
		}
	case AdvanceCollection:
		if claim.ExpectedState != StateCollecting || claim.ExpectedVersion == 0 || claim.ExpectedVersion == math.MaxUint64 ||
			claim.ExpectedProgressDigest == zero || claim.NextState != StateCollecting || claim.NextVersion != claim.ExpectedVersion+1 ||
			claim.NextProgressDigest == zero || claim.NextProgressDigest == claim.ExpectedProgressDigest {
			return ErrInvalidClaim
		}
	case CompleteCollection:
		if claim.ExpectedState != StateCollecting || claim.ExpectedVersion == 0 || claim.ExpectedVersion == math.MaxUint64 ||
			claim.ExpectedProgressDigest == zero || claim.NextState != StateCompleted || claim.NextVersion != claim.ExpectedVersion+1 ||
			claim.NextProgressDigest != claim.ExpectedProgressDigest {
			return ErrInvalidClaim
		}
	default:
		return ErrInvalidClaim
	}
	return nil
}

// ValidateCommitOutcome keeps the outcome outside Claim while still making
// the adapter's disposition fail closed.
func ValidateCommitOutcome(claim Claim, outcome [sha256.Size]byte) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	if claim.NextState == StateCompleted {
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

// NormalizeClaims orders the raw 16-byte global key, removes only exact
// duplicates and rejects two dispositions for the same business operation.
func NormalizeClaims(input []Claim) ([]Claim, error) {
	if len(input) == 0 || len(input) > MaxClaims {
		return nil, ErrInvalidClaim
	}
	claims := append([]Claim(nil), input...)
	for index := range claims {
		if err := claims[index].Validate(); err != nil {
			return nil, fmt.Errorf("%w at index %d", ErrInvalidClaim, index)
		}
	}
	sort.Slice(claims, func(i, j int) bool { return bytes.Compare(claims[i].Binding.Key[:], claims[j].Binding.Key[:]) < 0 })
	result := claims[:0]
	for _, claim := range claims {
		if len(result) == 0 || result[len(result)-1].Binding.Key != claim.Binding.Key {
			result = append(result, claim)
			continue
		}
		if result[len(result)-1] != claim {
			return nil, ErrConflictingClaim
		}
	}
	return append([]Claim(nil), result...), nil
}

func CanonicalBytes(input []Claim) ([]byte, error) {
	claims, err := NormalizeClaims(input)
	if err != nil {
		return nil, err
	}
	elements := make([][]byte, len(claims))
	for index, claim := range claims {
		elements[index], err = ccse.Marshal(8192, func(out *ccse.Encoder) {
			out.Uint32(uint32(claim.Mode))
			out.FixedBytes(claim.Binding.Key[:], ccse.MessageIDSize)
			out.String(string(claim.Binding.Domain))
			out.String(claim.Binding.OwnerID)
			out.FixedBytes(claim.Binding.RequestDigest[:], sha256.Size)
			out.Uint32(uint32(claim.ExpectedState))
			out.Uint64(claim.ExpectedVersion)
			out.FixedBytes(claim.ExpectedProgressDigest[:], sha256.Size)
			out.Uint32(uint32(claim.NextState))
			out.Uint64(claim.NextVersion)
			out.FixedBytes(claim.NextProgressDigest[:], sha256.Size)
		})
		if err != nil {
			return nil, fmt.Errorf("%w: encode claim %d: %v", ErrInvalidClaim, index, err)
		}
	}
	return ccse.Marshal(MaxCanonicalClaimBytes, func(out *ccse.Encoder) { out.EncodedList(elements) })
}

func Digest(input []Claim) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	encoded, err := CanonicalBytes(input)
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(claimDigestDomain))
	_, _ = hash.Write(encoded)
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func KnownOperationDomains() []OperationDomain {
	return append([]OperationDomain(nil), operationDomains[:]...)
}

func knownOperationDomain(domain OperationDomain) bool {
	for _, candidate := range operationDomains {
		if domain == candidate {
			return true
		}
	}
	return false
}

func validateOwnerID(value string) error {
	if value == "" || len(value) > MaxOwnerIDBytes || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return ErrInvalidBinding
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return ErrInvalidBinding
		}
	}
	return nil
}
