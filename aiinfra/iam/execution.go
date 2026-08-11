// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	iamExecutionFragmentDomain                 = "CPH-AIIE-IAM-EXECUTION-FRAGMENT-V2\x00"
	transferCollectionAssertionDigestDomain    = "CPH-AIIE-IAM-TRANSFER-COLLECTION-ASSERTION-V1\x00"
	acceptedOwnershipTransferWriteDigestDomain = "CPH-AIIE-IAM-ACCEPTED-TRANSFER-WRITE-V1\x00"
)

// IAMMutationWrite is one detached authoritative write value and its exact
// compare-and-swap fence. Exactly one snapshot pointer matches Kind.
type IAMMutationWrite struct {
	Kind      MutationKind
	CAS       CASIntent
	Material  *KeyMaterialSnapshot
	Identity  *IdentitySnapshot
	Lifecycle *KeyLifecycleSnapshot
}

// IAMOwnershipTransferCutoverWrite preserves the cutover's ordered execution
// phase. PreStateDependencies are checked once before any write; each
// PlannedPredecessor is checked only after every earlier write has been
// applied in the same transaction. Keeping this edge set separate prevents an
// adapter from flattening pre-state and planned-post-state assertions.
type IAMOwnershipTransferCutoverWrite struct {
	Kind                OwnershipTransferCutoverStepKind
	Write               IAMMutationWrite
	PlannedPredecessors []SnapshotPrecondition
}

func cloneOwnershipTransferCutoverWrite(source IAMOwnershipTransferCutoverWrite) IAMOwnershipTransferCutoverWrite {
	return IAMOwnershipTransferCutoverWrite{Kind: source.Kind,
		Write:               cloneMutationWrite(source.Write),
		PlannedPredecessors: append([]SnapshotPrecondition(nil), source.PlannedPredecessors...)}
}

func cloneMutationWrite(source IAMMutationWrite) IAMMutationWrite {
	result := source
	result.CAS = cloneCASIntent(source.CAS)
	if source.Material != nil {
		value := cloneKeyMaterial(*source.Material)
		result.Material = &value
	}
	if source.Identity != nil {
		value := cloneIdentity(*source.Identity)
		result.Identity = &value
	}
	if source.Lifecycle != nil {
		value := cloneLifecycle(*source.Lifecycle)
		result.Lifecycle = &value
	}
	return result
}

// OwnershipTransferCollectionAssertion is an exact assertion over the
// already-admitted final approval collection. The joined transaction must not
// replay the approval-ingestion CAS that produced this snapshot.
type OwnershipTransferCollectionAssertion struct {
	Expected    OwnershipTransferApprovalCollectionSnapshot
	WriterFence WriterFence
	digest      [32]byte
}

func cloneTransferCollectionAssertion(source OwnershipTransferCollectionAssertion) OwnershipTransferCollectionAssertion {
	return OwnershipTransferCollectionAssertion{Expected: cloneTransferCollection(source.Expected),
		WriterFence: source.WriterFence, digest: source.digest}
}
func (assertion OwnershipTransferCollectionAssertion) Digest() [32]byte { return assertion.digest }
func (assertion OwnershipTransferCollectionAssertion) VerifyDigest() error {
	digest, err := ownershipTransferCollectionAssertionDigest(assertion)
	if err != nil || digest != assertion.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// AcceptedOwnershipTransferWrite creates the immutable accepted-transfer row.
// It is deliberately separate from the approval collection assertion so a
// storage adapter cannot accidentally replay the collection transition.
type AcceptedOwnershipTransferWrite struct {
	Entity         EntityRef
	ExpectedAbsent bool
	Next           AcceptedOwnershipTransferSnapshot
	digest         [32]byte
}

func cloneAcceptedTransferWrite(source AcceptedOwnershipTransferWrite) AcceptedOwnershipTransferWrite {
	result := source
	result.Next = cloneAcceptedTransfer(source.Next)
	return result
}
func (write AcceptedOwnershipTransferWrite) Digest() [32]byte { return write.digest }
func (write AcceptedOwnershipTransferWrite) VerifyDigest() error {
	digest, err := acceptedOwnershipTransferWriteDigest(write)
	if err != nil || digest != write.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// IAMExecutionFragment exposes only a capability-derived, detached write set.
// It is never commit-ready by itself; the WS0.2b coordinator must atomically
// join it with Governance's canonical AuditEvent/head fragment.
type IAMExecutionFragment struct {
	kind                      DurablePendingKind
	mutations                 []IAMMutationWrite
	transferCollection        *OwnershipTransferCollectionAssertion
	acceptedTransfer          *AcceptedOwnershipTransferWrite
	cutoverWrites             []IAMOwnershipTransferCutoverWrite
	preStateDependencies      []SnapshotPrecondition
	idempotencyCompletions    []idempotency.Claim
	idempotencyAdmissions     []idempotency.Claim
	compoundMemberAdmissions  []idempotency.CompoundMemberClaim
	compoundMemberCompletions []idempotency.CompoundMemberClaim
	identifierReservations    []globalid.Claim
	identifierAssertions      []globalid.Claim
	pendingEnvelopeBytes      []byte
	nestedEnvelopeDigest      [32]byte
	nestedPendingDigest       [32]byte
	auditEventAssertion       globalid.Claim
	evaluatedAtUnixNano       int64
	commitNotBeforeUnixNano   int64
	commitNotAfterUnixNano    int64
	pendingDigest             [32]byte
	envelopeDigest            [32]byte
	stateCommitment           [32]byte
	failureOutcomeDigest      [32]byte
	digest                    [32]byte
}

func cloneIAMExecutionFragment(source IAMExecutionFragment) IAMExecutionFragment {
	result := source
	result.mutations = source.Mutations()
	result.idempotencyCompletions = source.IdempotencyCompletionClaims()
	result.idempotencyAdmissions = source.IdempotencyAdmissionClaims()
	result.compoundMemberAdmissions = source.CompoundMemberAdmissionClaims()
	result.compoundMemberCompletions = source.CompoundMemberCompletionClaims()
	result.preStateDependencies = source.PreStateDependencies()
	result.cutoverWrites = source.OwnershipTransferCutoverWrites()
	result.identifierReservations = source.IdentifierReservations()
	result.identifierAssertions = source.IdentifierAssertions()
	result.pendingEnvelopeBytes = source.PendingEnvelopeBytes()
	if source.transferCollection != nil {
		assertion := cloneTransferCollectionAssertion(*source.transferCollection)
		result.transferCollection = &assertion
	}
	if source.acceptedTransfer != nil {
		write := cloneAcceptedTransferWrite(*source.acceptedTransfer)
		result.acceptedTransfer = &write
	}
	return result
}

func (fragment IAMExecutionFragment) Kind() DurablePendingKind { return fragment.kind }
func (IAMExecutionFragment) CommitReady() bool                 { return false }
func (fragment IAMExecutionFragment) Mutations() []IAMMutationWrite {
	result := make([]IAMMutationWrite, len(fragment.mutations))
	for index := range fragment.mutations {
		result[index] = cloneMutationWrite(fragment.mutations[index])
	}
	return result
}
func (fragment IAMExecutionFragment) OwnershipTransferCollectionAssertion() (OwnershipTransferCollectionAssertion, bool) {
	if fragment.transferCollection == nil {
		return OwnershipTransferCollectionAssertion{}, false
	}
	return cloneTransferCollectionAssertion(*fragment.transferCollection), true
}
func (fragment IAMExecutionFragment) AcceptedOwnershipTransferWrite() (AcceptedOwnershipTransferWrite, bool) {
	if fragment.acceptedTransfer == nil {
		return AcceptedOwnershipTransferWrite{}, false
	}
	return cloneAcceptedTransferWrite(*fragment.acceptedTransfer), true
}
func (fragment IAMExecutionFragment) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), fragment.idempotencyCompletions...)
}
func (fragment IAMExecutionFragment) IdempotencyAdmissionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), fragment.idempotencyAdmissions...)
}
func (fragment IAMExecutionFragment) CompoundMemberAdmissionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), fragment.compoundMemberAdmissions...)
}
func (fragment IAMExecutionFragment) CompoundMemberCompletionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), fragment.compoundMemberCompletions...)
}
func (fragment IAMExecutionFragment) PreStateDependencies() []SnapshotPrecondition {
	return append([]SnapshotPrecondition(nil), fragment.preStateDependencies...)
}
func (fragment IAMExecutionFragment) OwnershipTransferCutoverWrites() []IAMOwnershipTransferCutoverWrite {
	result := make([]IAMOwnershipTransferCutoverWrite, len(fragment.cutoverWrites))
	for index := range fragment.cutoverWrites {
		result[index] = cloneOwnershipTransferCutoverWrite(fragment.cutoverWrites[index])
	}
	return result
}
func (fragment IAMExecutionFragment) IdentifierReservations() []globalid.Claim {
	return append([]globalid.Claim(nil), fragment.identifierReservations...)
}
func (fragment IAMExecutionFragment) IdentifierAssertions() []globalid.Claim {
	return append([]globalid.Claim(nil), fragment.identifierAssertions...)
}
func (fragment IAMExecutionFragment) JoinedAuditEventIdentifierAssertion() globalid.Claim {
	return fragment.auditEventAssertion
}
func (fragment IAMExecutionFragment) PendingEnvelopeBytes() []byte {
	return append([]byte(nil), fragment.pendingEnvelopeBytes...)
}
func (fragment IAMExecutionFragment) NestedPendingDigest() ([32]byte, bool) {
	return fragment.nestedPendingDigest, fragment.nestedPendingDigest != ([32]byte{})
}
func (fragment IAMExecutionFragment) NestedDurableEnvelopeDigest() ([32]byte, bool) {
	return fragment.nestedEnvelopeDigest, fragment.nestedEnvelopeDigest != ([32]byte{})
}
func (fragment IAMExecutionFragment) EvaluatedAtUnixNano() int64 { return fragment.evaluatedAtUnixNano }
func (fragment IAMExecutionFragment) CommitNotBeforeUnixNano() int64 {
	return fragment.commitNotBeforeUnixNano
}
func (fragment IAMExecutionFragment) CommitNotAfterUnixNano() int64 {
	return fragment.commitNotAfterUnixNano
}
func (fragment IAMExecutionFragment) PendingDigest() [32]byte         { return fragment.pendingDigest }
func (fragment IAMExecutionFragment) DurableEnvelopeDigest() [32]byte { return fragment.envelopeDigest }
func (fragment IAMExecutionFragment) StateAndGlobalCASCommitment() [32]byte {
	return fragment.stateCommitment
}

// FailureOutcomeDigest is known only for reconciliation. Successful joined
// execution receives its final combined outcome from the coordinator.
func (fragment IAMExecutionFragment) FailureOutcomeDigest() ([32]byte, bool) {
	return fragment.failureOutcomeDigest, fragment.failureOutcomeDigest != ([32]byte{})
}
func (fragment IAMExecutionFragment) Digest() [32]byte { return fragment.digest }

func (fragment IAMExecutionFragment) VerifyDigest() error {
	digest, err := iamExecutionFragmentDigest(fragment)
	if err != nil || digest != fragment.digest || fragment.commitNotBeforeUnixNano < 0 ||
		fragment.commitNotBeforeUnixNano > fragment.evaluatedAtUnixNano ||
		fragment.commitNotAfterUnixNano <= fragment.evaluatedAtUnixNano ||
		fragment.pendingDigest == ([32]byte{}) || fragment.envelopeDigest == ([32]byte{}) ||
		fragment.stateCommitment == ([32]byte{}) ||
		(fragment.kind == DurablePendingReconciliation) != (fragment.failureOutcomeDigest != ([32]byte{})) {
		return ErrPendingPlanInvalid
	}
	return nil
}

func executionFragmentFromRequest(request JoinedAuditRequest) (IAMExecutionFragment, error) {
	fragment := IAMExecutionFragment{kind: request.Kind(),
		idempotencyCompletions: append([]idempotency.Claim(nil), request.completion...),
		compoundMemberCompletions: append([]idempotency.CompoundMemberClaim(nil),
			request.compoundMemberCompletion...),
		preStateDependencies: append([]SnapshotPrecondition(nil), request.dependencies...),
		identifierAssertions: append([]globalid.Claim(nil), request.identifierAssertions...),
		auditEventAssertion:  request.auditEventAssertion, evaluatedAtUnixNano: request.evaluatedAtUnixNano,
		commitNotBeforeUnixNano: request.commitNotBeforeUnixNano,
		commitNotAfterUnixNano:  request.commitNotAfterUnixNano,
		pendingDigest:           request.PendingDigest(), envelopeDigest: request.DurableEnvelopeDigest(),
		stateCommitment: request.stateCommitment, failureOutcomeDigest: request.failureOutcomeDigest}
	var err error
	switch request.Kind() {
	case DurablePendingMutation:
		fragment.mutations = []IAMMutationWrite{mutationWrite(request.envelope.mutation.mutation)}
	case DurablePendingKeyEnrollment:
		fragment.mutations = []IAMMutationWrite{mutationWrite(request.envelope.enrollment.material),
			mutationWrite(request.envelope.enrollment.lifecycle)}
	case DurablePendingOwnershipTransferCollection:
		plan := request.envelope.transfer
		if plan.accepted == nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		assertion := OwnershipTransferCollectionAssertion{Expected: cloneTransferCollection(plan.next)}
		assertion.digest, err = ownershipTransferCollectionAssertionDigest(assertion)
		if err != nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		accepted := cloneAcceptedTransfer(*plan.accepted)
		write := AcceptedOwnershipTransferWrite{Entity: accepted.Precondition().Entity,
			ExpectedAbsent: true, Next: accepted}
		write.digest, err = acceptedOwnershipTransferWriteDigest(write)
		if err != nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		fragment.transferCollection = &assertion
		fragment.acceptedTransfer = &write
	case DurablePendingOwnershipTransferAcceptance:
		plan := request.envelope.acceptance
		if plan == nil || plan.VerifyDigest() != nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		assertion := OwnershipTransferCollectionAssertion{
			Expected: cloneTransferCollection(plan.collection), WriterFence: plan.writerFence}
		assertion.digest, err = ownershipTransferCollectionAssertionDigest(assertion)
		if err != nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		accepted := cloneAcceptedTransfer(plan.accepted)
		write := AcceptedOwnershipTransferWrite{Entity: accepted.Precondition().Entity,
			ExpectedAbsent: true, Next: accepted}
		write.digest, err = acceptedOwnershipTransferWriteDigest(write)
		if err != nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		fragment.transferCollection = &assertion
		fragment.acceptedTransfer = &write
		fragment.idempotencyAdmissions = plan.cutover.AdmissionIntent().IdempotencyReservations()
		fragment.compoundMemberAdmissions = plan.cutover.CompoundMemberAdmissionClaims()
		fragment.identifierReservations = plan.cutover.AdmissionIntent().IdentifierReservations()
		nestedEnvelope, nestedErr := durableEnvelopeForAcceptedCutover(plan.cutover)
		if nestedErr != nil {
			return IAMExecutionFragment{}, nestedErr
		}
		fragment.pendingEnvelopeBytes = nestedEnvelope.Bytes()
		fragment.nestedEnvelopeDigest = nestedEnvelope.Digest()
		fragment.nestedPendingDigest = plan.cutover.Digest()
	case DurablePendingOwnershipTransferCutover:
		plan := request.envelope.cutover
		if plan == nil || plan.VerifyDigest() != nil {
			return IAMExecutionFragment{}, ErrPendingPlanInvalid
		}
		fragment.cutoverWrites = make([]IAMOwnershipTransferCutoverWrite, len(plan.steps))
		for index, step := range plan.steps {
			fragment.cutoverWrites[index] = IAMOwnershipTransferCutoverWrite{
				Kind: step.Kind, Write: mutationWrite(step.Mutation),
				PlannedPredecessors: append([]SnapshotPrecondition(nil), step.PlannedPredecessors...)}
		}
	case DurablePendingReconciliation:
		// Reconciliation intentionally has no business mutation. Its exact X/Y
		// completions and permanent identifier assertions are still exposed.
	default:
		return IAMExecutionFragment{}, ErrPendingPlanInvalid
	}
	fragment.digest, err = iamExecutionFragmentDigest(fragment)
	if err != nil || fragment.VerifyDigest() != nil {
		return IAMExecutionFragment{}, ErrPendingPlanInvalid
	}
	return fragment, nil
}

func mutationWrite(plan MutationPlan) IAMMutationWrite {
	write := IAMMutationWrite{Kind: plan.Kind(), CAS: plan.CAS()}
	if value, ok := plan.KeyMaterial(); ok {
		write.Material = &value
	}
	if value, ok := plan.Identity(); ok {
		write.Identity = &value
	}
	if value, ok := plan.KeyLifecycle(); ok {
		write.Lifecycle = &value
	}
	return write
}

func iamExecutionFragmentDigest(fragment IAMExecutionFragment) ([32]byte, error) {
	var zero [32]byte
	completion, err := idempotency.CanonicalBytes(fragment.idempotencyCompletions)
	if err != nil {
		return zero, err
	}
	identifiers, err := globalid.CanonicalBytes(fragment.identifierAssertions)
	if err != nil {
		return zero, err
	}
	var admissions []byte
	if len(fragment.idempotencyAdmissions) != 0 {
		admissions, err = idempotency.CanonicalBytes(fragment.idempotencyAdmissions)
		if err != nil {
			return zero, err
		}
	}
	var memberAdmissions []byte
	if len(fragment.compoundMemberAdmissions) != 0 {
		memberAdmissions, err = idempotency.CompoundMemberCanonicalBytes(fragment.compoundMemberAdmissions)
		if err != nil {
			return zero, err
		}
	}
	var memberCompletions []byte
	if len(fragment.compoundMemberCompletions) != 0 {
		memberCompletions, err = idempotency.CompoundMemberCanonicalBytes(fragment.compoundMemberCompletions)
		if err != nil {
			return zero, err
		}
	}
	preStateDependencies, err := canonicalSnapshotPreconditions(fragment.preStateDependencies)
	if err != nil {
		return zero, err
	}
	var identifierReservations []byte
	if len(fragment.identifierReservations) != 0 {
		identifierReservations, err = globalid.CanonicalBytes(fragment.identifierReservations)
		if err != nil {
			return zero, err
		}
	}
	auditAssertion, err := globalid.CanonicalBytes([]globalid.Claim{fragment.auditEventAssertion})
	if err != nil {
		return zero, err
	}
	mutationElements := make([][]byte, 0, len(fragment.mutations))
	for _, write := range fragment.mutations {
		cas, encodeErr := canonicalCASIntent(write.CAS)
		if encodeErr != nil {
			return zero, encodeErr
		}
		body, encodeErr := canonicalMutationWrite(write)
		if encodeErr != nil {
			return zero, encodeErr
		}
		element, encodeErr := ccse.Marshal(1<<20, func(out *ccse.Encoder) {
			out.Uint32(uint32(write.Kind))
			out.Bytes(cas)
			out.Bytes(body)
		})
		if encodeErr != nil {
			return zero, encodeErr
		}
		mutationElements = append(mutationElements, element)
	}
	cutoverElements := make([][]byte, len(fragment.cutoverWrites))
	for index, step := range fragment.cutoverWrites {
		cas, encodeErr := canonicalCASIntent(step.Write.CAS)
		if encodeErr != nil {
			return zero, encodeErr
		}
		body, encodeErr := canonicalMutationWrite(step.Write)
		if encodeErr != nil {
			return zero, encodeErr
		}
		planned, encodeErr := canonicalSnapshotPreconditions(step.PlannedPredecessors)
		if encodeErr != nil {
			return zero, encodeErr
		}
		cutoverElements[index], encodeErr = ccse.Marshal(2<<20, func(out *ccse.Encoder) {
			out.Uint32(uint32(step.Kind))
			out.Bytes(cas)
			out.Bytes(body)
			out.Bytes(planned)
		})
		if encodeErr != nil {
			return zero, encodeErr
		}
	}
	transferAssertionBytes := []byte(nil)
	acceptedTransferBytes := []byte(nil)
	if (fragment.transferCollection == nil) != (fragment.acceptedTransfer == nil) {
		return zero, ErrPendingPlanInvalid
	}
	if fragment.transferCollection != nil {
		if fragment.transferCollection.VerifyDigest() != nil || fragment.acceptedTransfer.VerifyDigest() != nil {
			return zero, ErrPendingPlanInvalid
		}
		transferAssertionDigest := fragment.transferCollection.Digest()
		acceptedTransferDigest := fragment.acceptedTransfer.Digest()
		transferAssertionBytes = append([]byte(nil), transferAssertionDigest[:]...)
		acceptedTransferBytes = append([]byte(nil), acceptedTransferDigest[:]...)
	}
	if fragment.kind == DurablePendingOwnershipTransferCollection ||
		fragment.kind == DurablePendingOwnershipTransferAcceptance {
		if len(fragment.mutations) != 0 || fragment.transferCollection == nil {
			return zero, ErrPendingPlanInvalid
		}
	} else if fragment.transferCollection != nil {
		return zero, ErrPendingPlanInvalid
	}
	if fragment.kind == DurablePendingOwnershipTransferCutover {
		if len(fragment.mutations) != 0 || len(fragment.cutoverWrites) < 5 ||
			len(fragment.cutoverWrites) > 260 || len(fragment.idempotencyCompletions) != 2 ||
			len(fragment.compoundMemberCompletions) == 0 || len(fragment.preStateDependencies) == 0 ||
			idempotency.ValidateDisjointClaimKeys(fragment.idempotencyCompletions,
				fragment.compoundMemberCompletions) != nil ||
			verifyExecutionCutoverPhases(fragment.cutoverWrites, fragment.preStateDependencies) != nil {
			return zero, ErrPendingPlanInvalid
		}
	} else if fragment.kind == DurablePendingReconciliation {
		if len(fragment.cutoverWrites) != 0 {
			return zero, ErrPendingPlanInvalid
		}
		if len(fragment.compoundMemberCompletions) != 0 {
			for _, claim := range fragment.compoundMemberCompletions {
				if idempotency.ValidateCompoundMemberOutcome(claim,
					fragment.failureOutcomeDigest) != nil {
					return zero, ErrPendingPlanInvalid
				}
			}
		}
	} else if len(fragment.cutoverWrites) != 0 || len(fragment.compoundMemberCompletions) != 0 {
		return zero, ErrPendingPlanInvalid
	}
	if fragment.kind == DurablePendingReconciliation {
		if len(fragment.mutations) != 0 || fragment.failureOutcomeDigest == ([32]byte{}) ||
			len(fragment.idempotencyCompletions) != 2 {
			return zero, ErrPendingPlanInvalid
		}
		for _, claim := range fragment.idempotencyCompletions {
			if idempotency.ValidateCommitOutcome(claim, fragment.failureOutcomeDigest) != nil {
				return zero, ErrPendingPlanInvalid
			}
		}
	} else if fragment.failureOutcomeDigest != ([32]byte{}) {
		return zero, ErrPendingPlanInvalid
	}
	if fragment.kind == DurablePendingOwnershipTransferAcceptance {
		if len(fragment.idempotencyAdmissions) != 2 || len(fragment.compoundMemberAdmissions) == 0 ||
			len(fragment.identifierReservations) == 0 || len(fragment.pendingEnvelopeBytes) == 0 ||
			fragment.nestedEnvelopeDigest == ([32]byte{}) || fragment.nestedPendingDigest == ([32]byte{}) ||
			domainDigest(durablePendingEnvelopeDigestDomain, fragment.pendingEnvelopeBytes) != fragment.nestedEnvelopeDigest ||
			idempotency.ValidateDisjointClaimKeys(fragment.idempotencyAdmissions,
				fragment.compoundMemberAdmissions) != nil {
			return zero, ErrPendingPlanInvalid
		}
		nested, decodeErr := decodeDurablePendingEnvelope(fragment.pendingEnvelopeBytes)
		if decodeErr != nil || nested.Kind() != DurablePendingOwnershipTransferCutover ||
			nested.Digest() != fragment.nestedEnvelopeDigest || nested.PendingDigest() != fragment.nestedPendingDigest ||
			nested.cutover == nil ||
			!sameIdempotencyClaims(fragment.idempotencyAdmissions,
				nested.cutover.admission.idempotencyReservations) ||
			!sameCompoundMemberClaims(fragment.compoundMemberAdmissions, nested.cutover.memberAdmission) ||
			!sameGlobalClaimSet(fragment.identifierReservations,
				nested.cutover.admission.identifierReservations) ||
			fragment.acceptedTransfer == nil ||
			fragment.acceptedTransfer.Next.SnapshotDigest != nested.cutover.accepted.SnapshotDigest {
			return zero, ErrPendingPlanInvalid
		}
	} else if len(fragment.idempotencyAdmissions) != 0 || len(fragment.compoundMemberAdmissions) != 0 ||
		len(fragment.identifierReservations) != 0 || len(fragment.pendingEnvelopeBytes) != 0 ||
		fragment.nestedEnvelopeDigest != ([32]byte{}) || fragment.nestedPendingDigest != ([32]byte{}) {
		return zero, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(16<<20, func(out *ccse.Encoder) {
		out.Uint32(uint32(fragment.kind))
		out.EncodedList(mutationElements)
		out.EncodedList(cutoverElements)
		out.Bytes(preStateDependencies)
		out.Bytes(transferAssertionBytes)
		out.Bytes(acceptedTransferBytes)
		out.Bytes(completion)
		out.Bytes(admissions)
		out.Bytes(memberAdmissions)
		out.Bytes(memberCompletions)
		out.Bytes(identifierReservations)
		out.Bytes(identifiers)
		out.Bytes(auditAssertion)
		out.Uint64(uint64(len(fragment.pendingEnvelopeBytes)))
		out.FixedBytes(fragment.nestedEnvelopeDigest[:], 32)
		out.FixedBytes(fragment.nestedPendingDigest[:], 32)
		out.Int64(fragment.evaluatedAtUnixNano)
		out.Int64(fragment.commitNotBeforeUnixNano)
		out.Int64(fragment.commitNotAfterUnixNano)
		out.FixedBytes(fragment.pendingDigest[:], 32)
		out.FixedBytes(fragment.envelopeDigest[:], 32)
		out.FixedBytes(fragment.stateCommitment[:], 32)
		out.Bool(fragment.failureOutcomeDigest != ([32]byte{}))
		out.FixedBytes(fragment.failureOutcomeDigest[:], 32)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(iamExecutionFragmentDomain, encoded), nil
}

func verifyExecutionCutoverPhases(writes []IAMOwnershipTransferCutoverWrite,
	preState []SnapshotPrecondition) error {
	steps := make([]OwnershipTransferCutoverStep, len(writes))
	closureCount := len(writes) - 4
	if closureCount < 1 {
		return ErrPendingPlanInvalid
	}
	for index, write := range writes {
		expectedKind := CutoverClosePreviousKey
		switch index {
		case closureCount:
			expectedKind = CutoverTerminalPreviousIdentity
		case closureCount + 1:
			expectedKind = CutoverCreateNextKeyMaterial
		case closureCount + 2:
			expectedKind = CutoverCreateNextKeyLifecycle
		case closureCount + 3:
			expectedKind = CutoverCreateNextIdentity
		}
		if write.Kind != expectedKind {
			return ErrPendingPlanInvalid
		}
		plan, err := mutationPlanFromExecutionWrite(write.Write)
		if err != nil {
			return err
		}
		steps[index] = OwnershipTransferCutoverStep{Kind: write.Kind, Mutation: plan,
			PlannedPredecessors: append([]SnapshotPrecondition(nil), write.PlannedPredecessors...)}
	}
	return verifyCutoverDependencyPhases(steps, preState)
}

func mutationPlanFromExecutionWrite(write IAMMutationWrite) (MutationPlan, error) {
	window := planWindow{EvaluatedAtUnixNano: 0, CommitNotBeforeUnixNano: 0, CommitNotAfterUnixNano: 1}
	switch write.Kind {
	case MutationCreateKeyMaterial:
		if write.Material == nil || write.Identity != nil || write.Lifecycle != nil {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		return newMaterialPlan(write.CAS, cloneKeyMaterial(*write.Material), window)
	case MutationAppendIdentity:
		if write.Material != nil || write.Identity == nil || write.Lifecycle != nil {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		return newIdentityPlan(write.CAS, cloneIdentity(*write.Identity), window)
	case MutationAppendKeyLifecycle:
		if write.Material != nil || write.Identity != nil || write.Lifecycle == nil {
			return MutationPlan{}, ErrPendingPlanInvalid
		}
		return newLifecyclePlan(write.CAS, cloneLifecycle(*write.Lifecycle), window)
	default:
		return MutationPlan{}, ErrPendingPlanInvalid
	}
}

func sameGlobalClaimSet(left, right []globalid.Claim) bool {
	leftBytes, leftErr := globalid.CanonicalBytes(left)
	rightBytes, rightErr := globalid.CanonicalBytes(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func canonicalMutationWrite(write IAMMutationWrite) ([]byte, error) {
	switch write.Kind {
	case MutationCreateKeyMaterial:
		if write.Material == nil || write.Identity != nil || write.Lifecycle != nil {
			return nil, ErrPendingPlanInvalid
		}
		return canonicalMaterialSnapshot(*write.Material)
	case MutationAppendIdentity:
		if write.Material != nil || write.Identity == nil || write.Lifecycle != nil {
			return nil, ErrPendingPlanInvalid
		}
		if _, err := decodeIdentitySnapshotProjection(*write.Identity); err != nil {
			return nil, err
		}
		return append([]byte(nil), write.Identity.CanonicalPayload...), nil
	case MutationAppendKeyLifecycle:
		if write.Material != nil || write.Identity != nil || write.Lifecycle == nil {
			return nil, ErrPendingPlanInvalid
		}
		if _, err := decodeLifecycleSnapshotProjection(*write.Lifecycle); err != nil {
			return nil, err
		}
		return append([]byte(nil), write.Lifecycle.CanonicalPayload...), nil
	default:
		return nil, ErrPendingPlanInvalid
	}
}

func canonicalTransferCollectionAssertion(assertion OwnershipTransferCollectionAssertion) ([]byte, error) {
	expectedDigest, err := transferCollectionDigest(assertion.Expected)
	if err != nil || expectedDigest != assertion.Expected.ProgressDigest {
		return nil, ErrPendingPlanInvalid
	}
	bindingDigest, err := idempotency.BindingDigest(assertion.Expected.Binding)
	if err != nil {
		return nil, ErrPendingPlanInvalid
	}
	projection, _, _, err := normalizeOwnershipTransferPayload(assertion.Expected.CanonicalPayload)
	expectedEntity := EntityRef{Kind: EntityOwnershipTransfer, PrincipalKind: projection.SubjectKind,
		ID: projection.TransferAuthorizationID}
	if err != nil || assertion.WriterFence.Entity != expectedEntity ||
		assertion.WriterFence.ExpectedStateVersion != assertion.Expected.Version ||
		assertion.WriterFence.WriterIdentity == "" || assertion.WriterFence.HomeRegion == "" ||
		assertion.WriterFence.WriterEpoch < assertion.Expected.WriterEpoch ||
		(assertion.WriterFence.HomeRegion != assertion.Expected.HomeRegion &&
			assertion.WriterFence.WriterEpoch <= assertion.Expected.WriterEpoch) ||
		assertion.WriterFence.EvidenceDigest == ([32]byte{}) {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.FixedBytes(bindingDigest[:], 32)
		out.Uint64(assertion.Expected.Version)
		out.FixedBytes(expectedDigest[:], 32)
		encodeEntity(out, assertion.WriterFence.Entity)
		out.String(assertion.WriterFence.WriterIdentity)
		out.String(assertion.WriterFence.HomeRegion)
		out.Uint64(assertion.WriterFence.WriterEpoch)
		out.Uint64(assertion.WriterFence.ExpectedStateVersion)
		out.FixedBytes(assertion.WriterFence.EvidenceDigest[:], 32)
	})
}

func ownershipTransferCollectionAssertionDigest(assertion OwnershipTransferCollectionAssertion) ([32]byte, error) {
	var zero [32]byte
	encoded, err := canonicalTransferCollectionAssertion(assertion)
	if err != nil {
		return zero, err
	}
	return domainDigest(transferCollectionAssertionDigestDomain, encoded), nil
}

func canonicalAcceptedOwnershipTransferWrite(write AcceptedOwnershipTransferWrite) ([]byte, error) {
	if !write.ExpectedAbsent || write.Entity != write.Next.Precondition().Entity {
		return nil, ErrPendingPlanInvalid
	}
	acceptedDigest, err := acceptedTransferDigest(write.Next)
	if err != nil || acceptedDigest != write.Next.SnapshotDigest {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(128, func(out *ccse.Encoder) {
		out.Bool(write.ExpectedAbsent)
		out.FixedBytes(acceptedDigest[:], 32)
	})
}

func acceptedOwnershipTransferWriteDigest(write AcceptedOwnershipTransferWrite) ([32]byte, error) {
	var zero [32]byte
	encoded, err := canonicalAcceptedOwnershipTransferWrite(write)
	if err != nil {
		return zero, err
	}
	return domainDigest(acceptedOwnershipTransferWriteDigestDomain, encoded), nil
}
