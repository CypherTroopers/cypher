// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
)

const (
	CanonicalStateNamespaceIAM uint8 = 1

	CanonicalStateKindIAMKeyMaterial               = "cph.aiinfra.iam.key-material.v1"
	CanonicalStateKindIAMIdentity                  = "cph.aiinfra.iam.identity.v1"
	CanonicalStateKindIAMKeyLifecycle              = "cph.aiinfra.iam.key-lifecycle.v1"
	CanonicalStateKindIAMAcceptedOwnershipTransfer = "cph.aiinfra.iam.accepted-ownership-transfer.v1"
	CanonicalStateKindIAMProofChallenge            = "cph.aiinfra.iam.proof-challenge.v1"
	CanonicalStateKindIAMPrincipalIdentityIndex    = "cph.aiinfra.iam.principal-identity-index.v1"
	CanonicalStateKindIAMRotationPredecessorIndex  = "cph.aiinfra.iam.rotation-predecessor-index.v1"
	CanonicalStateKindIAMSubjectKeySet             = "cph.aiinfra.iam.subject-key-set.v1"
	CanonicalStateKindIAMWriterLease               = "cph.aiinfra.iam.writer-lease.v1"
	CanonicalStateKindIAMTransferProfileActivation = "cph.aiinfra.iam.ownership-transfer-profile-activation.v1"

	CanonicalStateContentTypeIAMKeyMaterial               = "application/cph.aiinfra.iam.key-material-state.v1"
	CanonicalStateContentTypeIAMIdentity                  = "application/cph.aiinfra.iam.identity-state.v1"
	CanonicalStateContentTypeIAMKeyLifecycle              = "application/cph.aiinfra.iam.key-lifecycle-state.v1"
	CanonicalStateContentTypeIAMAcceptedOwnershipTransfer = "application/cph.aiinfra.iam.accepted-ownership-transfer-state.v1"
	CanonicalStateContentTypeIAMProofChallenge            = "application/cph.aiinfra.iam.proof-challenge-state.v1"
	CanonicalStateContentTypeIAMPrincipalIdentityIndex    = "application/cph.aiinfra.iam.principal-identity-index-state.v1"
	CanonicalStateContentTypeIAMRotationPredecessorIndex  = "application/cph.aiinfra.iam.rotation-predecessor-index-state.v1"
	CanonicalStateContentTypeIAMSubjectKeySet             = "application/cph.aiinfra.iam.subject-key-set-state.v1"
	CanonicalStateContentTypeIAMWriterLease               = "application/cph.aiinfra.iam.writer-lease-state.v1"
	CanonicalStateContentTypeIAMTransferProfileActivation = "application/cph.aiinfra.iam.ownership-transfer-profile-activation-state.v1"

	iamCanonicalStateAssertionDomain = "CPH-AIIE-IAM-CANONICAL-STATE-ASSERTION-V1\x00"
	iamCanonicalStateAbsenceDomain   = "CPH-AIIE-IAM-CANONICAL-STATE-ABSENCE-V1\x00"
	iamCanonicalStateMutationDomain  = "CPH-AIIE-IAM-CANONICAL-STATE-MUTATION-V1\x00"
	iamCanonicalStateBundleDomain    = "CPH-AIIE-IAM-CANONICAL-STATE-BUNDLE-V1\x00"
	iamCanonicalStateCoverageDomain  = "CPH-AIIE-IAM-CANONICAL-STATE-COVERAGE-V1\x00"
	iamProofChallengeStateDomain     = "CPH-AIIE-IAM-PROOF-CHALLENGE-STATE-V1\x00"
	iamPrincipalIndexStateDomain     = "CPH-AIIE-IAM-PRINCIPAL-INDEX-STATE-V1\x00"
	iamPredecessorIndexStateDomain   = "CPH-AIIE-IAM-PREDECESSOR-INDEX-STATE-V1\x00"
	iamWriterLeaseStateDomain        = "CPH-AIIE-IAM-WRITER-LEASE-STATE-V1\x00"
	iamWriterLeaseRequirementDomain  = "CPH-AIIE-IAM-WRITER-LEASE-REQUIREMENT-V1\x00"
	iamCanonicalStateMaxBytes        = 64 << 20
	// A maximum 256-closure cutover carries the closure lifecycle/material
	// pre-state plus one writer-lease assertion per ordered write. Reads and
	// writes are bounded independently; 1024 leaves a closed margin for the
	// principal/predecessor/subject/profile sidecars while writes remain capped
	// by the 260-step cutover plus their bounded index transitions.
	iamCanonicalStateMaxAssertions = 1024
	iamCanonicalStateMaxMutations  = 384
)

// CanonicalPrincipalObjectID exposes the IAM-owned stable address used by
// principal-index and subject-key-set rows. Storage adapters must call this
// helper rather than reproduce the private digest domain.
func CanonicalPrincipalObjectID(kind uint32, principal string) (string, error) {
	if kind < 1 || kind > 8 || principal == "" {
		return "", ErrCanonicalStateInvalid
	}
	return principalIndexObjectID(kind, principal), nil
}

// CanonicalEntityObjectID exposes the IAM-owned writer-lease row address.
func CanonicalEntityObjectID(entity EntityRef) (string, error) {
	if entity.Kind == 0 || entity.PrincipalKind < 1 || entity.PrincipalKind > 8 || entity.ID == "" {
		return "", ErrCanonicalStateInvalid
	}
	return canonicalEntityObjectID(entity), nil
}

// CanonicalStateRecord is the exact storage-neutral row. StateDigestSHA256 is
// owned by the IAM semantic codec; adapters must never replace it with a hash
// of CanonicalState.
type CanonicalStateRecord struct {
	Namespace          uint8
	Kind               string
	ObjectID           string
	Version            uint64
	StateDigestSHA256  [sha256.Size]byte
	ContentType        string
	CanonicalState     []byte
	Terminal           bool
	AuditEventID       string
	HasValidityWindow  bool
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
}

// CanonicalWriterLeaseRequirement is an owned, immutable description of one
// exact IAM writer-lease row. It lets a package that already has an
// authoritative semantic lease compare a storage-neutral row without
// reimplementing IAM's private canonical codec or digest domain.
type CanonicalWriterLeaseRequirement struct {
	lease        WriterLeaseSnapshot
	auditEventID string
	digest       [sha256.Size]byte
}

func NewCanonicalWriterLeaseRequirement(lease WriterLeaseSnapshot,
	auditEventID string) (CanonicalWriterLeaseRequirement, error) {
	lease = cloneWriterLeaseSnapshot(lease)
	canonical, err := canonicalWriterLeaseState(lease)
	if err != nil || auditEventID == "" || len(auditEventID) > 1024 {
		return CanonicalWriterLeaseRequirement{}, ErrPendingPlanInvalid
	}
	digest := domainDigest(iamWriterLeaseRequirementDomain, mustMarshalWriterLeaseRequirement(
		lease, auditEventID, canonical))
	return CanonicalWriterLeaseRequirement{lease: lease, auditEventID: auditEventID,
		digest: digest}, nil
}

func (value CanonicalWriterLeaseRequirement) Lease() WriterLeaseSnapshot {
	return cloneWriterLeaseSnapshot(value.lease)
}
func (value CanonicalWriterLeaseRequirement) AuditEventID() string { return value.auditEventID }
func (value CanonicalWriterLeaseRequirement) Digest() [sha256.Size]byte {
	return value.digest
}
func (value CanonicalWriterLeaseRequirement) ExpectedRecord() (CanonicalStateRecord, error) {
	if value.VerifyDigest() != nil {
		return CanonicalStateRecord{}, ErrPendingPlanInvalid
	}
	canonical, err := canonicalWriterLeaseState(value.lease)
	if err != nil {
		return CanonicalStateRecord{}, ErrPendingPlanInvalid
	}
	return CanonicalStateRecord{Namespace: CanonicalStateNamespaceIAM,
		Kind:     CanonicalStateKindIAMWriterLease,
		ObjectID: canonicalEntityObjectID(value.lease.Entity), Version: value.lease.WriterEpoch,
		StateDigestSHA256: domainDigest(iamWriterLeaseStateDomain, canonical),
		ContentType:       CanonicalStateContentTypeIAMWriterLease,
		CanonicalState:    append([]byte(nil), canonical...), AuditEventID: value.auditEventID}, nil
}
func (value CanonicalWriterLeaseRequirement) VerifyDigest() error {
	canonical, err := canonicalWriterLeaseState(value.lease)
	if err != nil || value.auditEventID == "" || len(value.auditEventID) > 1024 ||
		domainDigest(iamWriterLeaseRequirementDomain, mustMarshalWriterLeaseRequirement(
			value.lease, value.auditEventID, canonical)) != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// VerifyCanonicalWriterLeaseRecord checks the complete row, including its
// codec-owned semantic digest and canonical bytes. The requirement's Entity
// must come from the authoritative lease namespace; this function deliberately
// does not guess an audit-stream EntityRef from an AuditEventID.
func VerifyCanonicalWriterLeaseRecord(requirement CanonicalWriterLeaseRequirement,
	record CanonicalStateRecord) error {
	if requirement.VerifyDigest() != nil {
		return ErrPendingPlanInvalid
	}
	canonical, err := canonicalWriterLeaseState(requirement.lease)
	if err != nil || !validCanonicalStateRecord(record) ||
		record.Namespace != CanonicalStateNamespaceIAM ||
		record.Kind != CanonicalStateKindIAMWriterLease ||
		record.ContentType != CanonicalStateContentTypeIAMWriterLease ||
		record.ObjectID != canonicalEntityObjectID(requirement.lease.Entity) ||
		record.Version != requirement.lease.WriterEpoch ||
		record.StateDigestSHA256 != domainDigest(iamWriterLeaseStateDomain, canonical) ||
		!bytes.Equal(record.CanonicalState, canonical) || record.Terminal ||
		record.AuditEventID != requirement.auditEventID || record.HasValidityWindow ||
		record.ValidFromUnixNano != 0 || record.ValidUntilUnixNano != 0 {
		return ErrViewInconsistent
	}
	return nil
}

func cloneWriterLeaseSnapshot(value WriterLeaseSnapshot) WriterLeaseSnapshot { return value }

func mustMarshalWriterLeaseRequirement(lease WriterLeaseSnapshot, auditEventID string,
	canonical []byte) []byte {
	encoded, _ := ccse.Marshal(8192, func(out *ccse.Encoder) {
		out.Bytes(canonical)
		out.String(auditEventID)
	})
	return encoded
}

// CanonicalIAMStateTransition requests one exact codec-owned expected->next
// row from an optimistic pre-sign snapshot. The final coordinator later
// byte-compares Expected and writes Next in its authoritative UoW.
type CanonicalIAMStateTransition struct {
	Order                     uint32
	MutationKind              MutationKind
	Entity                    EntityRef
	ExpectedAbsent            bool
	ExpectedVersion           uint64
	ExpectedWriterEpoch       uint64
	ExpectedStateDigestSHA256 [sha256.Size]byte
	NextVersion               uint64
	NextWriterEpoch           uint64
	NextState                 uint32
	Terminal                  bool
	AuditEventID              string
	HasValidityWindow         bool
	ValidFromUnixNano         int64
	ValidUntilUnixNano        int64
	CanonicalSemanticState    []byte
	SemanticStateDigestSHA256 [sha256.Size]byte
}

// CanonicalIAMStateView is a fail-closed optional extension. It supplies exact
// storage rows and private codec digests; the planner checks every public
// semantic field before minting a capability.
type CanonicalIAMStateView interface {
	CanonicalIAMStateAssertion(context.Context, SnapshotPrecondition, string) (CanonicalStateRecord, bool, error)
	CanonicalIAMStateTransition(context.Context, CanonicalIAMStateTransition) (
		expected CanonicalStateRecord, expectedPresent bool, next CanonicalStateRecord, err error)
}

// CanonicalIAMSidecarRequest is an IAM-owned semantic row requirement for a
// CASIntent sidecar. Expected/Next canonical bytes and semantic digests are
// derived by IAM; a view may only resolve the exact authoritative row version
// and historical audit identifier.
type CanonicalIAMSidecarRequest struct {
	Order                     uint32
	Kind                      string
	ObjectID                  string
	ExpectedPresent           bool
	ExpectedVersion           uint64
	ExpectedStateDigestSHA256 [sha256.Size]byte
	ExpectedCanonicalState    []byte
	ExpectedTerminal          bool
	NextPresent               bool
	NextVersion               uint64
	NextStateDigestSHA256     [sha256.Size]byte
	NextCanonicalState        []byte
	NextTerminal              bool
	AuditEventID              string
	// ExpectedSubjectKeyMembers is populated only for subject-key-set.v1.
	// It is the lossless v2 companion that must be asserted with the v1 row.
	ExpectedSubjectKeyMembers []SnapshotPrecondition
	NextSubjectKeyMembers     []SnapshotPrecondition
	ExpectedSubjectKind       uint32
	ExpectedSubjectIdentity   string
}

// CanonicalIAMSidecarStateView is required whenever CASIntent reads or writes
// proof-challenge, principal, predecessor, subject-set, or writer-lease rows.
// Missing this extension fails closed before outer AuditEvent signing.
type CanonicalIAMSidecarStateView interface {
	CanonicalIAMSidecarState(context.Context, CanonicalIAMSidecarRequest) (
		expected CanonicalStateRecord, expectedPresent bool,
		next CanonicalStateRecord, nextPresent bool, err error)
}

type CanonicalStateAssertion struct {
	record     CanonicalStateRecord
	semanticV2 *SemanticProjectionV2
	digest     [sha256.Size]byte
}

// CanonicalStateAbsence is an exact predicate-read capability for a closed
// namespace/kind/object key. It is separate from an absent-to-v1 mutation so
// read-only absence checks cannot be silently dropped.
type CanonicalStateAbsence struct {
	namespace uint8
	kind      string
	objectID  string
	digest    [sha256.Size]byte
}

func (value CanonicalStateAbsence) Namespace() uint8          { return value.namespace }
func (value CanonicalStateAbsence) Kind() string              { return value.kind }
func (value CanonicalStateAbsence) ObjectID() string          { return value.objectID }
func (value CanonicalStateAbsence) Digest() [sha256.Size]byte { return value.digest }
func (value CanonicalStateAbsence) VerifyDigest() error {
	digest, err := digestCanonicalStateAbsence(value.namespace, value.kind, value.objectID)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

func (value CanonicalStateAssertion) Record() CanonicalStateRecord {
	return cloneCanonicalStateRecord(value.record)
}

// SemanticProjectionV2 returns the exact lossless companion that is part of
// this read capability.  It is currently mandatory for subject-key-set.v1,
// whose frozen v1 bytes omit the member preimage.
func (value CanonicalStateAssertion) SemanticProjectionV2() (SemanticProjectionV2, bool) {
	if value.semanticV2 == nil {
		return SemanticProjectionV2{}, false
	}
	copy := *value.semanticV2
	copy.Canonical = append([]byte(nil), value.semanticV2.Canonical...)
	return copy, true
}
func (value CanonicalStateAssertion) Digest() [sha256.Size]byte { return value.digest }
func (value CanonicalStateAssertion) VerifyDigest() error {
	digest, err := digestCanonicalStateAssertion(value.record, value.semanticV2)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

type CanonicalStateMutation struct {
	expected   *CanonicalStateRecord
	next       CanonicalStateRecord
	semanticV2 *SemanticProjectionV2
	digest     [sha256.Size]byte
}

func (value CanonicalStateMutation) Expected() (CanonicalStateRecord, bool) {
	if value.expected == nil {
		return CanonicalStateRecord{}, false
	}
	return cloneCanonicalStateRecord(*value.expected), true
}
func (value CanonicalStateMutation) Next() CanonicalStateRecord {
	return cloneCanonicalStateRecord(value.next)
}
func (value CanonicalStateMutation) SemanticProjectionV2() (SemanticProjectionV2, bool) {
	if value.semanticV2 == nil {
		return SemanticProjectionV2{}, false
	}
	copy := *value.semanticV2
	copy.Canonical = append([]byte(nil), copy.Canonical...)
	return copy, true
}
func (value CanonicalStateMutation) Digest() [sha256.Size]byte { return value.digest }
func (value CanonicalStateMutation) VerifyDigest() error {
	digest, err := digestCanonicalStateMutation(value.expected, value.next, value.semanticV2)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// IAMCanonicalStateBundle preserves read assertions and ordered writes.
type IAMCanonicalStateBundle struct {
	assertions     []CanonicalStateAssertion
	absences       []CanonicalStateAbsence
	mutations      []CanonicalStateMutation
	auditEventID   string
	coverageDigest [sha256.Size]byte
	digest         [sha256.Size]byte
}

func (value IAMCanonicalStateBundle) Assertions() []CanonicalStateAssertion {
	return cloneCanonicalStateAssertions(value.assertions)
}
func (value IAMCanonicalStateBundle) Mutations() []CanonicalStateMutation {
	return cloneCanonicalStateMutations(value.mutations)
}
func (value IAMCanonicalStateBundle) Absences() []CanonicalStateAbsence {
	return append([]CanonicalStateAbsence(nil), value.absences...)
}
func equalIAMCanonicalStateBundles(left, right *IAMCanonicalStateBundle) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if left.auditEventID != right.auditEventID || left.coverageDigest != right.coverageDigest ||
		left.digest != right.digest || len(left.assertions) != len(right.assertions) ||
		len(left.absences) != len(right.absences) || len(left.mutations) != len(right.mutations) {
		return false
	}
	for index := range left.assertions {
		if left.assertions[index].digest != right.assertions[index].digest ||
			!equalCanonicalStateRecords(left.assertions[index].record, right.assertions[index].record) ||
			!equalSemanticProjectionPointers(left.assertions[index].semanticV2,
				right.assertions[index].semanticV2) {
			return false
		}
	}
	for index := range left.absences {
		if left.absences[index] != right.absences[index] {
			return false
		}
	}
	for index := range left.mutations {
		if left.mutations[index].digest != right.mutations[index].digest ||
			!equalCanonicalStateRecords(left.mutations[index].next, right.mutations[index].next) ||
			!equalSemanticProjectionPointers(left.mutations[index].semanticV2,
				right.mutations[index].semanticV2) ||
			(left.mutations[index].expected == nil) != (right.mutations[index].expected == nil) {
			return false
		}
		if left.mutations[index].expected != nil &&
			!equalCanonicalStateRecords(*left.mutations[index].expected, *right.mutations[index].expected) {
			return false
		}
	}
	return true
}

func equalCanonicalStateRecords(left, right CanonicalStateRecord) bool {
	return left.Namespace == right.Namespace && left.Kind == right.Kind &&
		left.ObjectID == right.ObjectID && left.Version == right.Version &&
		left.StateDigestSHA256 == right.StateDigestSHA256 && left.ContentType == right.ContentType &&
		bytes.Equal(left.CanonicalState, right.CanonicalState) && left.Terminal == right.Terminal &&
		left.AuditEventID == right.AuditEventID && left.HasValidityWindow == right.HasValidityWindow &&
		left.ValidFromUnixNano == right.ValidFromUnixNano && left.ValidUntilUnixNano == right.ValidUntilUnixNano
}
func (value IAMCanonicalStateBundle) AuditEventID() string              { return value.auditEventID }
func (value IAMCanonicalStateBundle) CoverageDigest() [sha256.Size]byte { return value.coverageDigest }
func (value IAMCanonicalStateBundle) Digest() [sha256.Size]byte         { return value.digest }
func (value IAMCanonicalStateBundle) VerifyDigest() error {
	digest, err := digestCanonicalStateBundle(value.assertions, value.absences, value.mutations,
		value.auditEventID, value.coverageDigest)
	if err != nil || digest != value.digest {
		return ErrPendingPlanInvalid
	}
	return nil
}

// VerifyForExecution is the fail-closed completeness marker: it binds the
// opaque row capabilities to the exact semantic read/write set.
func (value IAMCanonicalStateBundle) VerifyForExecution(fragment IAMExecutionFragment) error {
	semantic := cloneIAMExecutionFragment(fragment)
	semantic.canonicalState = nil
	semantic.persistence = nil
	semantic.digest = [sha256.Size]byte{}
	coverage, err := canonicalStateCoverageDigest(semantic)
	if err != nil || value.VerifyDigest() != nil || coverage != value.coverageDigest ||
		value.auditEventID != fragment.auditEventAssertion.Identifier {
		return ErrPendingPlanInvalid
	}
	return nil
}

func cloneIAMCanonicalStateBundle(value IAMCanonicalStateBundle) IAMCanonicalStateBundle {
	return IAMCanonicalStateBundle{assertions: cloneCanonicalStateAssertions(value.assertions),
		absences:  append([]CanonicalStateAbsence(nil), value.absences...),
		mutations: cloneCanonicalStateMutations(value.mutations), auditEventID: value.auditEventID,
		coverageDigest: value.coverageDigest, digest: value.digest}
}

// BindCanonicalStateCapabilities asks the authoritative IAM state view
// for complete expected rows and codec-owned next rows, validates them against
// the already-derived semantic write set, and returns a new joined request
// whose state commitment and execution digest include the opaque capability.
func (p *Planner) BindCanonicalStateCapabilities(ctx context.Context,
	request JoinedAuditRequest) (JoinedAuditRequest, error) {
	if err := p.ready(); err != nil {
		return JoinedAuditRequest{}, err
	}
	if err := ctx.Err(); err != nil {
		return JoinedAuditRequest{}, err
	}
	if request.VerifyDigest() != nil || request.canonicalState != nil || request.execution == nil {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	view, ok := p.view.(CanonicalIAMStateView)
	if !ok {
		return JoinedAuditRequest{}, ErrViewRequired
	}
	bundle, err := buildIAMCanonicalStateBundle(ctx, p.view, view, *request.execution, request.auditEventID)
	if err != nil {
		return JoinedAuditRequest{}, fmt.Errorf("bind canonical state: %w", err)
	}
	request.canonicalState = &bundle
	request.stateCommitment, err = joinedAuditStateCommitment(request)
	if err != nil {
		return JoinedAuditRequest{}, fmt.Errorf("bind canonical state commitment: %w", err)
	}
	execution, err := executionFragmentFromRequest(request)
	if err != nil {
		return JoinedAuditRequest{}, fmt.Errorf("bind canonical execution: %w", err)
	}
	request.execution = &execution
	request.digest, err = joinedAuditRequestDigest(request)
	if err != nil || request.VerifyDigest() != nil {
		return JoinedAuditRequest{}, fmt.Errorf("bind canonical request: digest=%v verify=%v", err, request.VerifyDigest())
	}
	return request, nil
}

func buildIAMCanonicalStateBundle(ctx context.Context, semantic View, view CanonicalIAMStateView,
	fragment IAMExecutionFragment, auditEventID string) (IAMCanonicalStateBundle, error) {
	sidecarView, ok := semantic.(CanonicalIAMSidecarStateView)
	if !ok {
		return IAMCanonicalStateBundle{}, ErrViewRequired
	}
	assertions := make([]CanonicalStateAssertion, 0, len(fragment.preStateDependencies))
	for _, dependency := range fragment.preStateDependencies {
		record, found, err := view.CanonicalIAMStateAssertion(ctx, dependency, auditEventID)
		if err != nil {
			return IAMCanonicalStateBundle{}, err
		}
		if !found || !canonicalStateRecordMatchesPrecondition(record, dependency) {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		assertion, err := newCanonicalStateAssertion(record)
		if err != nil {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		assertions = append(assertions, assertion)
	}

	writes := make([]IAMMutationWrite, 0, len(fragment.mutations)+len(fragment.cutoverWrites))
	writes = append(writes, fragment.mutations...)
	for _, step := range fragment.cutoverWrites {
		writes = append(writes, step.Write)
	}
	mutations := make([]CanonicalStateMutation, 0, len(writes)+1)
	for order, write := range writes {
		requirement, err := canonicalTransitionForMutationWrite(uint32(order+1), write, auditEventID)
		if err != nil {
			return IAMCanonicalStateBundle{}, err
		}
		if err := bindExpectedCanonicalTransitionDigest(ctx, semantic, write,
			&requirement); err != nil {
			return IAMCanonicalStateBundle{}, err
		}
		expected, present, next, err := view.CanonicalIAMStateTransition(ctx, requirement)
		if err != nil {
			return IAMCanonicalStateBundle{}, err
		}
		if !canonicalTransitionResolutionMatches(requirement, expected, present, next) {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		var expectedPointer *CanonicalStateRecord
		if present {
			expectedPointer = &expected
		}
		mutation, err := newCanonicalStateMutation(expectedPointer, next)
		if err != nil {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		mutations = append(mutations, mutation)
	}
	if fragment.acceptedTransfer != nil {
		requirement, err := canonicalTransitionForAcceptedTransfer(
			uint32(len(mutations)+1), *fragment.acceptedTransfer, auditEventID)
		if err != nil {
			return IAMCanonicalStateBundle{}, err
		}
		stored, found, lookupErr := semantic.LookupAcceptedOwnershipTransfer(ctx,
			fragment.acceptedTransfer.Next.TransferEvidenceDigest)
		if lookupErr != nil || found || stored.SnapshotDigest != ([32]byte{}) {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		expected, present, next, err := view.CanonicalIAMStateTransition(ctx, requirement)
		if err != nil {
			return IAMCanonicalStateBundle{}, err
		}
		if !canonicalTransitionResolutionMatches(requirement, expected, present, next) {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		mutation, err := newCanonicalStateMutation(nil, next)
		if err != nil {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		mutations = append(mutations, mutation)
	}

	absences := make([]CanonicalStateAbsence, 0, len(writes))
	sidecarHeads := make(map[string]CanonicalStateRecord)
	assertionKeys := make(map[string][sha256.Size]byte, len(assertions))
	for _, assertion := range assertions {
		assertionKeys[canonicalStateRecordKey(assertion.record)] = assertion.digest
	}
	absenceKeys := make(map[string]struct{})
	sidecarOrder := uint32(len(mutations) + 1)
	for _, write := range writes {
		requests, requestErr := canonicalSidecarRequests(ctx, semantic, write, auditEventID)
		if requestErr != nil {
			return IAMCanonicalStateBundle{}, requestErr
		}
		for _, request := range requests {
			request.Order = sidecarOrder
			sidecarOrder++
			assertion, absence, mutation, capabilityKind, bindErr := bindCanonicalSidecar(
				ctx, sidecarView, request, sidecarHeads)
			if bindErr != nil {
				return IAMCanonicalStateBundle{}, bindErr
			}
			switch capabilityKind {
			case 1:
				key := canonicalStateRecordKey(assertion.record)
				if digest, duplicate := assertionKeys[key]; duplicate {
					if digest != assertion.digest {
						return IAMCanonicalStateBundle{}, ErrViewInconsistent
					}
					continue
				}
				assertionKeys[key] = assertion.digest
				assertions = append(assertions, assertion)
			case 2:
				key := canonicalStateKeyString(absence.namespace, absence.kind, absence.objectID)
				if _, duplicate := absenceKeys[key]; duplicate {
					continue
				}
				absenceKeys[key] = struct{}{}
				absences = append(absences, absence)
			case 3:
				mutations = append(mutations, mutation)
			default:
				return IAMCanonicalStateBundle{}, ErrPendingPlanInvalid
			}
		}
	}
	// Subject-key-set.v1 is updated once per principal after all lifecycle
	// writes have been collected. A 256-key cutover therefore adds one exact
	// sidecar mutation, not 256 duplicate rewrites of the same head.
	subjectRequests, subjectErr := canonicalSubjectKeySetMutationRequests(ctx, semantic,
		writes, auditEventID)
	if subjectErr != nil {
		return IAMCanonicalStateBundle{}, subjectErr
	}
	for _, request := range subjectRequests {
		request.Order = sidecarOrder
		sidecarOrder++
		assertion, absence, mutation, capabilityKind, bindErr := bindCanonicalSidecar(
			ctx, sidecarView, request, sidecarHeads)
		if bindErr != nil {
			return IAMCanonicalStateBundle{}, bindErr
		}
		switch capabilityKind {
		case 1:
			key := canonicalStateRecordKey(assertion.record)
			if digest, duplicate := assertionKeys[key]; duplicate {
				if digest != assertion.digest {
					return IAMCanonicalStateBundle{}, ErrViewInconsistent
				}
			} else {
				assertionKeys[key] = assertion.digest
				assertions = append(assertions, assertion)
			}
		case 2:
			key := canonicalStateKeyString(absence.namespace, absence.kind, absence.objectID)
			if _, duplicate := absenceKeys[key]; !duplicate {
				absenceKeys[key] = struct{}{}
				absences = append(absences, absence)
			}
		case 3:
			mutations = append(mutations, mutation)
		default:
			return IAMCanonicalStateBundle{}, ErrPendingPlanInvalid
		}
	}
	if fragment.transferCollection != nil {
		request, requestErr := canonicalWriterLeaseSidecarRequest(ctx, semantic,
			fragment.transferCollection.WriterFence, auditEventID)
		if requestErr != nil {
			return IAMCanonicalStateBundle{}, requestErr
		}
		request.Order = sidecarOrder
		assertion, _, _, capabilityKind, bindErr := bindCanonicalSidecar(ctx,
			sidecarView, request, sidecarHeads)
		if bindErr != nil || capabilityKind != 1 {
			return IAMCanonicalStateBundle{}, ErrViewInconsistent
		}
		key := canonicalStateRecordKey(assertion.record)
		if digest, duplicate := assertionKeys[key]; duplicate {
			if digest != assertion.digest {
				return IAMCanonicalStateBundle{}, ErrViewInconsistent
			}
		} else {
			assertionKeys[key] = assertion.digest
			assertions = append(assertions, assertion)
		}
	}
	if len(assertions)+len(absences)+len(mutations) == 0 {
		return IAMCanonicalStateBundle{}, ErrPendingPlanInvalid
	}
	coverageDigest, err := canonicalStateCoverageDigest(fragment)
	if err != nil {
		return IAMCanonicalStateBundle{}, err
	}
	bundle := IAMCanonicalStateBundle{assertions: assertions, mutations: mutations,
		absences: absences, auditEventID: auditEventID, coverageDigest: coverageDigest}
	bundle.digest, _ = digestCanonicalStateBundle(assertions, absences, mutations,
		auditEventID, coverageDigest)
	if verifyErr := bundle.VerifyDigest(); verifyErr != nil {
		return IAMCanonicalStateBundle{}, fmt.Errorf("canonical bundle digest: %w", verifyErr)
	}
	if coverageErr := bundle.VerifyForExecution(fragment); coverageErr != nil {
		return IAMCanonicalStateBundle{}, fmt.Errorf("canonical bundle coverage: %w", coverageErr)
	}
	return bundle, nil
}

func canonicalSidecarRequests(ctx context.Context, view View, write IAMMutationWrite,
	auditEventID string) ([]CanonicalIAMSidecarRequest, error) {
	requests := make([]CanonicalIAMSidecarRequest, 0, 6)
	writer, err := canonicalWriterLeaseSidecarRequest(ctx, view, WriterFence{
		Entity: write.CAS.Entity, WriterEpoch: write.CAS.AuthorizedWriterEpoch,
		WriterIdentity: write.CAS.AuthorizedWriterIdentity,
		HomeRegion:     write.CAS.AuthorizedWriterHomeRegion,
		EvidenceDigest: write.CAS.WriterEvidenceDigest}, auditEventID)
	if err != nil {
		return nil, err
	}
	requests = append(requests, writer)
	if write.CAS.ConsumeChallenge {
		challenge, found, lookupErr := view.LookupProofChallenge(ctx, write.CAS.Challenge)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if !found || challenge.Challenge != write.CAS.Challenge || challenge.Consumed ||
			challenge.EvidenceDigest != write.CAS.ChallengeEvidenceDigest {
			return nil, ErrViewInconsistent
		}
		expectedCanonical, canonicalErr := canonicalProofChallengeState(challenge)
		if canonicalErr != nil {
			return nil, canonicalErr
		}
		nextChallenge := challenge
		nextChallenge.Consumed = true
		nextCanonical, canonicalErr := canonicalProofChallengeState(nextChallenge)
		if canonicalErr != nil {
			return nil, canonicalErr
		}
		requests = append(requests, CanonicalIAMSidecarRequest{
			Kind: CanonicalStateKindIAMProofChallenge, ObjectID: hex.EncodeToString(challenge.Challenge[:]),
			ExpectedPresent: true, ExpectedVersion: 1,
			ExpectedStateDigestSHA256: domainDigest(iamProofChallengeStateDomain, expectedCanonical),
			ExpectedCanonicalState:    expectedCanonical, NextPresent: true, NextVersion: 2,
			NextStateDigestSHA256: domainDigest(iamProofChallengeStateDomain, nextCanonical),
			NextCanonicalState:    nextCanonical, NextTerminal: true, AuditEventID: auditEventID})
	}
	if write.CAS.PrincipalIndex.Mode != 0 {
		if write.Identity == nil {
			return nil, ErrPendingPlanInvalid
		}
		principal := write.CAS.PrincipalIndex
		request := CanonicalIAMSidecarRequest{Kind: CanonicalStateKindIAMPrincipalIdentityIndex,
			ObjectID:        principalIndexObjectID(principal.PrincipalKind, principal.PrincipalIdentity),
			ExpectedPresent: principal.Mode != globalid.ReserveNew, NextPresent: true,
			AuditEventID: auditEventID}
		if request.ExpectedPresent {
			request.ExpectedCanonicalState, err = canonicalPrincipalIndexState(principal.PrincipalKind,
				principal.PrincipalIdentity, principal.ExpectedOwner, principal.ExpectedStateVersion,
				principal.ExpectedEntityWriterEpoch, principal.ExpectedState,
				principal.TransferEvidenceDigest)
			if err != nil {
				return nil, err
			}
			request.ExpectedStateDigestSHA256 = domainDigest(iamPrincipalIndexStateDomain,
				request.ExpectedCanonicalState)
		}
		request.NextCanonicalState, err = canonicalPrincipalIndexState(principal.PrincipalKind,
			principal.PrincipalIdentity, principal.NextOwner, write.Identity.StateVersion,
			write.Identity.WriterEpoch, write.Identity.State, principal.TransferEvidenceDigest)
		if err != nil {
			return nil, err
		}
		request.NextStateDigestSHA256 = domainDigest(iamPrincipalIndexStateDomain,
			request.NextCanonicalState)
		requests = append(requests, request)
	}
	if write.CAS.PredecessorIndexMode != 0 {
		if write.Lifecycle == nil || write.CAS.RotationPredecessorKeyID == "" {
			return nil, ErrPendingPlanInvalid
		}
		canonical, canonicalErr := canonicalPredecessorIndexState(
			write.CAS.RotationPredecessorKeyID, write.Lifecycle.KeyID)
		if canonicalErr != nil {
			return nil, canonicalErr
		}
		request := CanonicalIAMSidecarRequest{Kind: CanonicalStateKindIAMRotationPredecessorIndex,
			ObjectID:        write.CAS.RotationPredecessorKeyID,
			ExpectedPresent: write.CAS.PredecessorIndexMode == PredecessorAssertExisting,
			ExpectedVersion: 1, ExpectedStateDigestSHA256: domainDigest(iamPredecessorIndexStateDomain, canonical),
			ExpectedCanonicalState: canonical, ExpectedTerminal: true, AuditEventID: auditEventID}
		if write.CAS.PredecessorIndexMode == PredecessorReserveNew {
			request.ExpectedVersion = 0
			request.ExpectedStateDigestSHA256 = [sha256.Size]byte{}
			request.ExpectedCanonicalState = nil
			request.ExpectedTerminal = false
			request.NextPresent = true
			request.NextVersion = 1
			request.NextStateDigestSHA256 = domainDigest(iamPredecessorIndexStateDomain, canonical)
			request.NextCanonicalState = canonical
			request.NextTerminal = true
		}
		requests = append(requests, request)
	}
	if write.CAS.ExpectedSubjectAbsent {
		if write.CAS.SubjectKind == 0 || write.CAS.SubjectIdentity == "" {
			return nil, ErrPendingPlanInvalid
		}
		requests = append(requests, CanonicalIAMSidecarRequest{
			Kind:            CanonicalStateKindIAMPrincipalIdentityIndex,
			ObjectID:        principalIndexObjectID(write.CAS.SubjectKind, write.CAS.SubjectIdentity),
			ExpectedPresent: false, NextPresent: false, AuditEventID: auditEventID})
	}
	return requests, nil
}

type subjectKeySetMutationGroup struct {
	kind      uint32
	principal string
	writes    []KeyLifecycleSnapshot
	explicit  []SnapshotPrecondition
	digest    [sha256.Size]byte
}

func canonicalSubjectKeySetMutationRequests(ctx context.Context, view View,
	writes []IAMMutationWrite, auditEventID string) ([]CanonicalIAMSidecarRequest, error) {
	groups := make(map[string]*subjectKeySetMutationGroup)
	groupFor := func(kind uint32, principal string) (*subjectKeySetMutationGroup, error) {
		objectID := principalIndexObjectID(kind, principal)
		if objectID == "" {
			return nil, ErrPendingPlanInvalid
		}
		group := groups[objectID]
		if group == nil {
			group = &subjectKeySetMutationGroup{kind: kind, principal: principal}
			groups[objectID] = group
		}
		if group.kind != kind || group.principal != principal {
			return nil, ErrPendingPlanInvalid
		}
		return group, nil
	}
	for _, write := range writes {
		if write.Lifecycle != nil {
			group, err := groupFor(write.Lifecycle.SubjectKind, write.Lifecycle.SubjectIdentity)
			if err != nil {
				return nil, err
			}
			group.writes = append(group.writes, cloneLifecycle(*write.Lifecycle))
		}
		if write.CAS.SubjectKeySetDigest != ([sha256.Size]byte{}) {
			if write.Identity == nil || len(write.CAS.SubjectKeySetMembers) == 0 {
				return nil, ErrPendingPlanInvalid
			}
			group, err := groupFor(write.Identity.Ref.PrincipalKind, write.Identity.PrincipalIdentity)
			if err != nil || group.digest != ([sha256.Size]byte{}) {
				return nil, ErrPendingPlanInvalid
			}
			group.explicit = append([]SnapshotPrecondition(nil), write.CAS.SubjectKeySetMembers...)
			group.digest = write.CAS.SubjectKeySetDigest
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	requests := make([]CanonicalIAMSidecarRequest, 0, len(keys))
	for _, objectID := range keys {
		group := groups[objectID]
		current, err := view.LookupSubjectKeyLifecycles(ctx, group.kind, group.principal)
		if err != nil || len(current) > 256 {
			return nil, ErrViewInconsistent
		}
		currentMembers := make([]SnapshotPrecondition, len(current))
		for index, lifecycle := range current {
			normalized, normalizeErr := normalizeViewLifecycle(lifecycle)
			if normalizeErr != nil || normalized.SubjectKind != group.kind || normalized.SubjectIdentity != group.principal {
				return nil, ErrViewInconsistent
			}
			currentMembers[index] = lifecyclePrecondition(normalized)
		}
		currentMembers, currentDigest, digestErr := canonicalSubjectKeySetMembersV2(group.kind,
			group.principal, currentMembers)
		if digestErr != nil {
			return nil, ErrViewInconsistent
		}
		nextByID := make(map[string]SnapshotPrecondition, len(currentMembers)+len(group.writes))
		for _, member := range currentMembers {
			nextByID[member.Entity.ID] = member
		}
		for _, lifecycle := range group.writes {
			nextByID[lifecycle.KeyID] = lifecyclePrecondition(lifecycle)
		}
		nextMembers := make([]SnapshotPrecondition, 0, len(nextByID))
		for _, member := range nextByID {
			nextMembers = append(nextMembers, member)
		}
		nextMembers, nextDigest, digestErr := canonicalSubjectKeySetMembersV2(group.kind,
			group.principal, nextMembers)
		if digestErr != nil {
			return nil, ErrViewInconsistent
		}
		if group.digest != ([sha256.Size]byte{}) && (group.digest != nextDigest ||
			!sameSnapshotPreconditions(group.explicit, nextMembers)) {
			return nil, ErrViewInconsistent
		}
		expectedPresent := len(currentMembers) != 0
		request := CanonicalIAMSidecarRequest{Kind: CanonicalStateKindIAMSubjectKeySet,
			ObjectID: objectID, ExpectedPresent: expectedPresent, NextPresent: currentDigest != nextDigest,
			AuditEventID: auditEventID, ExpectedSubjectKind: group.kind,
			ExpectedSubjectIdentity:   group.principal,
			ExpectedSubjectKeyMembers: currentMembers, NextSubjectKeyMembers: nextMembers,
			NextStateDigestSHA256: nextDigest}
		request.NextCanonicalState, err = canonicalSubjectKeySetState(group.kind, group.principal, nextDigest)
		if err != nil {
			return nil, err
		}
		if expectedPresent {
			request.ExpectedStateDigestSHA256 = currentDigest
			request.ExpectedCanonicalState, err = canonicalSubjectKeySetState(group.kind, group.principal, currentDigest)
			if err != nil {
				return nil, err
			}
		}
		if !request.NextPresent {
			request.NextStateDigestSHA256, request.NextCanonicalState, request.NextSubjectKeyMembers =
				[sha256.Size]byte{}, nil, nil
		}
		requests = append(requests, request)
	}
	return requests, nil
}

func canonicalWriterLeaseSidecarRequest(ctx context.Context, view View, fence WriterFence,
	auditEventID string) (CanonicalIAMSidecarRequest, error) {
	lease, found, err := view.LookupWriterLease(ctx, fence.Entity)
	if err != nil {
		return CanonicalIAMSidecarRequest{}, err
	}
	if !found || !sameEntityRef(lease.Entity, fence.Entity) || lease.WriterEpoch == 0 ||
		lease.WriterEpoch != fence.WriterEpoch || lease.EvidenceDigest == ([sha256.Size]byte{}) ||
		lease.EvidenceDigest != fence.EvidenceDigest || lease.WriterIdentity != fence.WriterIdentity ||
		lease.HomeRegion != fence.HomeRegion {
		return CanonicalIAMSidecarRequest{}, ErrViewInconsistent
	}
	canonical, err := canonicalWriterLeaseState(lease)
	if err != nil {
		return CanonicalIAMSidecarRequest{}, err
	}
	return CanonicalIAMSidecarRequest{Kind: CanonicalStateKindIAMWriterLease,
		ObjectID: canonicalEntityObjectID(fence.Entity), ExpectedPresent: true,
		ExpectedVersion:           lease.WriterEpoch,
		ExpectedStateDigestSHA256: domainDigest(iamWriterLeaseStateDomain, canonical),
		ExpectedCanonicalState:    canonical, AuditEventID: auditEventID}, nil
}

func bindCanonicalSidecar(ctx context.Context, view CanonicalIAMSidecarStateView,
	request CanonicalIAMSidecarRequest, heads map[string]CanonicalStateRecord) (
	CanonicalStateAssertion, CanonicalStateAbsence, CanonicalStateMutation, uint8, error) {
	key := canonicalStateKeyString(CanonicalStateNamespaceIAM, request.Kind, request.ObjectID)
	expected, present, next, nextPresent, err := view.CanonicalIAMSidecarState(ctx, cloneCanonicalSidecarRequest(request))
	if err != nil {
		return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, err
	}
	if planned, ok := heads[key]; ok {
		expected, present = cloneCanonicalStateRecord(planned), true
		if !request.ExpectedPresent || request.ExpectedStateDigestSHA256 != planned.StateDigestSHA256 ||
			!bytes.Equal(request.ExpectedCanonicalState, planned.CanonicalState) {
			return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
		}
		if request.NextPresent {
			next = canonicalStateRecordForSidecar(request, planned.Version+1, true)
			nextPresent = true
		} else {
			next, nextPresent = CanonicalStateRecord{}, false
		}
	}
	if present != request.ExpectedPresent || nextPresent != request.NextPresent {
		return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
	}
	if present && !canonicalSidecarRecordMatches(expected, request, false, 0) {
		return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
	}
	if !present && nonzeroCanonicalStateRecord(expected) {
		return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
	}
	if nextPresent {
		expectedNextVersion := uint64(1)
		if present {
			if expected.Version == ^uint64(0) {
				return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
			}
			expectedNextVersion = expected.Version + 1
		}
		if !canonicalSidecarRecordMatches(next, request, true, expectedNextVersion) {
			return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
		}
		var expectedPointer *CanonicalStateRecord
		if present {
			expectedCopy := cloneCanonicalStateRecord(expected)
			expectedPointer = &expectedCopy
		}
		mutation, mutationErr := newCanonicalStateMutation(expectedPointer, next)
		if mutationErr == nil && request.Kind == CanonicalStateKindIAMSubjectKeySet {
			projection, projectionErr := NewSubjectKeySetSemanticProjectionV2(next,
				request.ExpectedSubjectKind, request.ExpectedSubjectIdentity,
				request.NextSubjectKeyMembers)
			if projectionErr != nil {
				return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0,
					ErrViewInconsistent
			}
			mutation.semanticV2 = &projection
			mutation.digest, mutationErr = digestCanonicalStateMutation(mutation.expected,
				mutation.next, mutation.semanticV2)
		}
		if mutationErr != nil {
			return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0, ErrViewInconsistent
		}
		heads[key] = cloneCanonicalStateRecord(next)
		return CanonicalStateAssertion{}, CanonicalStateAbsence{}, mutation, 3, nil
	}
	if present {
		assertion, assertionErr := newCanonicalStateAssertion(expected)
		if assertionErr == nil && request.Kind == CanonicalStateKindIAMSubjectKeySet {
			projection, projectionErr := NewSubjectKeySetSemanticProjectionV2(expected,
				request.ExpectedSubjectKind, request.ExpectedSubjectIdentity,
				request.ExpectedSubjectKeyMembers)
			if projectionErr != nil {
				return CanonicalStateAssertion{}, CanonicalStateAbsence{}, CanonicalStateMutation{}, 0,
					ErrViewInconsistent
			}
			assertion.semanticV2 = &projection
			assertion.digest, assertionErr = digestCanonicalStateAssertion(assertion.record,
				assertion.semanticV2)
		}
		return assertion, CanonicalStateAbsence{}, CanonicalStateMutation{}, 1, assertionErr
	}
	absence, absenceErr := newCanonicalStateAbsence(CanonicalStateNamespaceIAM,
		request.Kind, request.ObjectID)
	return CanonicalStateAssertion{}, absence, CanonicalStateMutation{}, 2, absenceErr
}

func nonzeroCanonicalStateRecord(value CanonicalStateRecord) bool {
	return value.Namespace != 0 || value.Kind != "" || value.ObjectID != "" || value.Version != 0 ||
		value.StateDigestSHA256 != ([sha256.Size]byte{}) || value.ContentType != "" ||
		len(value.CanonicalState) != 0 || value.Terminal || value.AuditEventID != "" ||
		value.HasValidityWindow || value.ValidFromUnixNano != 0 || value.ValidUntilUnixNano != 0
}

func canonicalSidecarRecordMatches(record CanonicalStateRecord, request CanonicalIAMSidecarRequest,
	next bool, derivedVersion uint64) bool {
	digest, canonical, terminal, version, eventID := request.ExpectedStateDigestSHA256,
		request.ExpectedCanonicalState, request.ExpectedTerminal, request.ExpectedVersion, ""
	if next {
		digest, canonical, terminal, version, eventID = request.NextStateDigestSHA256,
			request.NextCanonicalState, request.NextTerminal, request.NextVersion, request.AuditEventID
		if version == 0 {
			version = derivedVersion
		}
	}
	return validCanonicalStateRecord(record) && record.Namespace == CanonicalStateNamespaceIAM &&
		record.Kind == request.Kind && record.ObjectID == request.ObjectID &&
		(version == 0 || record.Version == version) && record.StateDigestSHA256 == digest &&
		bytes.Equal(record.CanonicalState, canonical) && record.Terminal == terminal &&
		(eventID == "" || record.AuditEventID == eventID) && !record.HasValidityWindow
}

func canonicalStateRecordForSidecar(request CanonicalIAMSidecarRequest, version uint64,
	next bool) CanonicalStateRecord {
	contentType, _ := canonicalStateSpec(request.Kind)
	digest, canonical, terminal, eventID := request.ExpectedStateDigestSHA256,
		request.ExpectedCanonicalState, request.ExpectedTerminal, "historical:"+request.ObjectID
	if next {
		digest, canonical, terminal, eventID = request.NextStateDigestSHA256,
			request.NextCanonicalState, request.NextTerminal, request.AuditEventID
	}
	return CanonicalStateRecord{Namespace: CanonicalStateNamespaceIAM, Kind: request.Kind,
		ObjectID: request.ObjectID, Version: version, StateDigestSHA256: digest,
		ContentType: contentType, CanonicalState: append([]byte(nil), canonical...),
		Terminal: terminal, AuditEventID: eventID}
}

func canonicalProofChallengeState(value ProofChallengeSnapshot) ([]byte, error) {
	policies, err := canonicalDigests(value.PolicyDigestsSHA256)
	if err != nil || value.Challenge == ([sha256.Size]byte{}) || value.SubjectIdentity == "" ||
		value.SubjectKind == 0 || value.ExpiresAtUnixNano <= 0 || value.IssuerIdentity == "" ||
		value.EvidenceDigest == ([sha256.Size]byte{}) {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(16<<10, func(out *ccse.Encoder) {
		out.FixedBytes(value.Challenge[:], sha256.Size)
		out.String(value.SubjectIdentity)
		out.Uint32(value.SubjectKind)
		encodeEntity(out, value.TargetIdentity)
		out.FixedBytes(value.TransferEvidenceDigest[:], sha256.Size)
		out.String(value.Domain.EnrollmentDomainID)
		out.String(value.Domain.Environment)
		out.FixedBytes(value.Domain.GenesisHash[:], sha256.Size)
		out.Int64(value.ExpiresAtUnixNano)
		out.Bool(value.Consumed)
		out.String(value.IssuerIdentity)
		out.Uint32(uint32(len(policies)))
		for _, digest := range policies {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.FixedBytes(value.EvidenceDigest[:], sha256.Size)
	})
}

func canonicalWriterLeaseState(value WriterLeaseSnapshot) ([]byte, error) {
	if value.Entity.Kind == 0 || value.Entity.ID == "" || value.WriterIdentity == "" ||
		value.HomeRegion == "" || value.WriterEpoch == 0 || value.ValidFromUnixNano < 0 ||
		value.ValidUntilUnixNano <= value.ValidFromUnixNano || value.EvidenceDigest == ([sha256.Size]byte{}) {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		encodeEntity(out, value.Entity)
		out.String(value.WriterIdentity)
		out.String(value.HomeRegion)
		out.Uint64(value.WriterEpoch)
		out.Int64(value.ValidFromUnixNano)
		out.Int64(value.ValidUntilUnixNano)
		out.FixedBytes(value.EvidenceDigest[:], sha256.Size)
	})
}

func canonicalPrincipalIndexState(kind uint32, principal string, owner EntityRef,
	stateVersion, writerEpoch uint64, state uint32, transferDigest [sha256.Size]byte) ([]byte, error) {
	if kind == 0 || principal == "" || owner.Kind != EntityIdentity || owner.ID == "" ||
		owner.PrincipalKind != kind || stateVersion == 0 || writerEpoch == 0 || state == 0 {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.Uint32(kind)
		out.String(principal)
		encodeEntity(out, owner)
		out.Uint64(stateVersion)
		out.Uint64(writerEpoch)
		out.Uint32(state)
		out.FixedBytes(transferDigest[:], sha256.Size)
	})
}

func canonicalPredecessorIndexState(predecessor, successor string) ([]byte, error) {
	if predecessor == "" || successor == "" || predecessor == successor {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.String(predecessor)
		out.String(successor)
	})
}

func canonicalSubjectKeySetState(kind uint32, principal string,
	digest [sha256.Size]byte) ([]byte, error) {
	if kind == 0 || principal == "" || digest == ([sha256.Size]byte{}) {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.Uint32(kind)
		out.String(principal)
		out.FixedBytes(digest[:], sha256.Size)
	})
}

func canonicalEntityObjectID(entity EntityRef) string {
	return strconv.FormatUint(uint64(entity.Kind), 10) + ":" +
		strconv.FormatUint(uint64(entity.PrincipalKind), 10) + ":" + entity.ID
}

func principalIndexObjectID(kind uint32, principal string) string {
	return strconv.FormatUint(uint64(kind), 10) + ":" + principal
}

func canonicalStateKeyString(namespace uint8, kind, objectID string) string {
	return strconv.FormatUint(uint64(namespace), 10) + "\x00" + kind + "\x00" + objectID
}

func canonicalStateRecordKey(record CanonicalStateRecord) string {
	return canonicalStateKeyString(record.Namespace, record.Kind, record.ObjectID)
}

func cloneCanonicalSidecarRequest(value CanonicalIAMSidecarRequest) CanonicalIAMSidecarRequest {
	value.ExpectedCanonicalState = append([]byte(nil), value.ExpectedCanonicalState...)
	value.NextCanonicalState = append([]byte(nil), value.NextCanonicalState...)
	value.ExpectedSubjectKeyMembers = append([]SnapshotPrecondition(nil), value.ExpectedSubjectKeyMembers...)
	value.NextSubjectKeyMembers = append([]SnapshotPrecondition(nil), value.NextSubjectKeyMembers...)
	return value
}

func canonicalStateCoverageDigest(fragment IAMExecutionFragment) ([sha256.Size]byte, error) {
	preState, err := canonicalSnapshotPreconditions(fragment.preStateDependencies)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	writes := make([]IAMMutationWrite, 0, len(fragment.mutations)+len(fragment.cutoverWrites))
	writes = append(writes, fragment.mutations...)
	for _, step := range fragment.cutoverWrites {
		writes = append(writes, step.Write)
	}
	elements := make([][]byte, len(writes))
	for index, write := range writes {
		cas, encodeErr := canonicalCASIntent(write.CAS)
		if encodeErr != nil {
			return [sha256.Size]byte{}, encodeErr
		}
		body, encodeErr := canonicalMutationWrite(write)
		if encodeErr != nil {
			return [sha256.Size]byte{}, encodeErr
		}
		elements[index], encodeErr = ccse.Marshal(16<<20, func(out *ccse.Encoder) {
			out.Bytes(cas)
			out.Bytes(body)
			cutoverIndex := index - len(fragment.mutations)
			if cutoverIndex >= 0 && cutoverIndex < len(fragment.cutoverWrites) {
				out.Uint32(uint32(fragment.cutoverWrites[cutoverIndex].Kind))
				planned, _ := canonicalSnapshotPreconditions(fragment.cutoverWrites[cutoverIndex].PlannedPredecessors)
				out.Bytes(planned)
			} else {
				out.Uint32(0)
				out.Bytes(nil)
			}
		})
		if encodeErr != nil {
			return [sha256.Size]byte{}, encodeErr
		}
	}
	var transferDigest, acceptedDigest [sha256.Size]byte
	if fragment.transferCollection != nil {
		transferDigest = fragment.transferCollection.Digest()
		acceptedDigest = fragment.acceptedTransfer.Digest()
	}
	encoded, err := ccse.Marshal(32<<20, func(out *ccse.Encoder) {
		out.Uint32(uint32(fragment.kind))
		out.String(fragment.auditEventAssertion.Identifier)
		out.Bytes(preState)
		out.EncodedList(elements)
		out.FixedBytes(transferDigest[:], sha256.Size)
		out.FixedBytes(acceptedDigest[:], sha256.Size)
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return domainDigest(iamCanonicalStateCoverageDomain, encoded), nil
}

func bindExpectedCanonicalTransitionDigest(ctx context.Context, view View, write IAMMutationWrite,
	requirement *CanonicalIAMStateTransition) error {
	if requirement == nil {
		return ErrPendingPlanInvalid
	}
	switch write.Kind {
	case MutationCreateKeyMaterial:
		stored, found, err := view.LookupKeyMaterial(ctx, write.CAS.Entity.ID)
		if err != nil || found || stored.EnrollmentBindingDigest != ([32]byte{}) ||
			!write.CAS.ExpectedAbsent {
			return ErrViewInconsistent
		}
	case MutationAppendIdentity:
		stored, found, err := view.LookupIdentity(ctx, write.CAS.Entity)
		if err != nil {
			return err
		}
		if write.CAS.ExpectedAbsent {
			if found {
				return ErrViewInconsistent
			}
			return nil
		}
		if !found || stored.StateVersion != write.CAS.ExpectedStateVersion ||
			stored.WriterEpoch != write.CAS.ExpectedEntityWriterEpoch {
			return ErrViewInconsistent
		}
		requirement.ExpectedStateDigestSHA256 = domainDigest(resolvedIdentitySnapshotDomain,
			stored.CanonicalPayload)
	case MutationAppendKeyLifecycle:
		stored, found, err := view.LookupKeyLifecycle(ctx, write.CAS.Entity.ID)
		if err != nil {
			return err
		}
		if write.CAS.ExpectedAbsent {
			if found {
				return ErrViewInconsistent
			}
			return nil
		}
		if !found || stored.StateVersion != write.CAS.ExpectedStateVersion ||
			stored.WriterEpoch != write.CAS.ExpectedEntityWriterEpoch {
			return ErrViewInconsistent
		}
		requirement.ExpectedStateDigestSHA256 = domainDigest(resolvedLifecycleSnapshotDomain,
			stored.CanonicalPayload)
	default:
		return ErrPendingPlanInvalid
	}
	return nil
}

func canonicalStateKindForEntity(entity EntityRef) (string, bool) {
	switch entity.Kind {
	case EntityIdentity:
		return CanonicalStateKindIAMIdentity, true
	case EntityKeyMaterial:
		return CanonicalStateKindIAMKeyMaterial, true
	case EntityKeyLifecycle:
		return CanonicalStateKindIAMKeyLifecycle, true
	case EntityOwnershipTransfer:
		return CanonicalStateKindIAMAcceptedOwnershipTransfer, true
	case EntityOwnershipTransferProfileActivation:
		return CanonicalStateKindIAMTransferProfileActivation, true
	default:
		return "", false
	}
}

func canonicalStateRecordMatchesPrecondition(record CanonicalStateRecord,
	precondition SnapshotPrecondition) bool {
	kind, ok := canonicalStateKindForEntity(precondition.Entity)
	return ok && validCanonicalStateRecord(record) && record.Kind == kind &&
		record.ObjectID == precondition.Entity.ID && record.Version == precondition.ExpectedStateVersion &&
		record.StateDigestSHA256 == precondition.ExpectedSnapshotDigest
}

func canonicalTransitionForMutationWrite(order uint32, write IAMMutationWrite,
	auditEventID string) (CanonicalIAMStateTransition, error) {
	request := CanonicalIAMStateTransition{Order: order, MutationKind: write.Kind,
		Entity: write.CAS.Entity, ExpectedAbsent: write.CAS.ExpectedAbsent,
		ExpectedVersion:     write.CAS.ExpectedStateVersion,
		ExpectedWriterEpoch: write.CAS.ExpectedEntityWriterEpoch,
		AuditEventID:        auditEventID}
	switch write.Kind {
	case MutationCreateKeyMaterial:
		if write.Material == nil {
			return CanonicalIAMStateTransition{}, ErrPendingPlanInvalid
		}
		canonical, err := canonicalMaterialSnapshot(*write.Material)
		if err != nil {
			return CanonicalIAMStateTransition{}, err
		}
		request.NextVersion = write.Material.StateVersion
		request.NextWriterEpoch = write.Material.WriterEpoch
		request.CanonicalSemanticState = canonical
		request.SemanticStateDigestSHA256 = write.Material.EnrollmentBindingDigest
		request.Terminal = true
	case MutationAppendIdentity:
		if write.Identity == nil {
			return CanonicalIAMStateTransition{}, ErrPendingPlanInvalid
		}
		request.NextVersion = write.Identity.StateVersion
		request.NextWriterEpoch = write.Identity.WriterEpoch
		request.NextState = write.Identity.State
		request.CanonicalSemanticState = append([]byte(nil), write.Identity.CanonicalPayload...)
		request.SemanticStateDigestSHA256 = domainDigest(resolvedIdentitySnapshotDomain,
			write.Identity.CanonicalPayload)
		request.Terminal = terminalIdentityState(write.Identity.State)
	case MutationAppendKeyLifecycle:
		if write.Lifecycle == nil {
			return CanonicalIAMStateTransition{}, ErrPendingPlanInvalid
		}
		request.NextVersion = write.Lifecycle.StateVersion
		request.NextWriterEpoch = write.Lifecycle.WriterEpoch
		request.NextState = write.Lifecycle.State
		request.CanonicalSemanticState = append([]byte(nil), write.Lifecycle.CanonicalPayload...)
		request.SemanticStateDigestSHA256 = domainDigest(resolvedLifecycleSnapshotDomain,
			write.Lifecycle.CanonicalPayload)
		request.Terminal = terminalLifecycleState(write.Lifecycle.State)
	default:
		return CanonicalIAMStateTransition{}, ErrPendingPlanInvalid
	}
	return request, nil
}

func canonicalTransitionForAcceptedTransfer(order uint32, write AcceptedOwnershipTransferWrite,
	auditEventID string) (CanonicalIAMStateTransition, error) {
	canonical, digest, err := canonicalAcceptedTransferState(write.Next)
	if err != nil || digest != write.Next.SnapshotDigest || !write.ExpectedAbsent {
		return CanonicalIAMStateTransition{}, ErrPendingPlanInvalid
	}
	return CanonicalIAMStateTransition{Order: order, Entity: write.Entity,
		ExpectedAbsent: true, NextVersion: write.Next.StateVersion,
		NextWriterEpoch: write.Next.WriterEpoch, Terminal: true, AuditEventID: auditEventID,
		CanonicalSemanticState: canonical, SemanticStateDigestSHA256: digest}, nil
}

func canonicalTransitionResolutionMatches(requirement CanonicalIAMStateTransition,
	expected CanonicalStateRecord, present bool, next CanonicalStateRecord) bool {
	kind, ok := canonicalStateKindForEntity(requirement.Entity)
	if !ok || present == requirement.ExpectedAbsent || !validCanonicalStateRecord(next) ||
		next.Kind != kind || next.ObjectID != requirement.Entity.ID ||
		next.Version != requirement.NextVersion || next.StateDigestSHA256 != requirement.SemanticStateDigestSHA256 ||
		!bytes.Equal(next.CanonicalState, requirement.CanonicalSemanticState) ||
		next.Terminal != requirement.Terminal || next.AuditEventID != requirement.AuditEventID {
		return false
	}
	if !present {
		return next.Version == 1
	}
	return validCanonicalStateRecord(expected) && expected.Kind == kind &&
		expected.ObjectID == requirement.Entity.ID && expected.Version == requirement.ExpectedVersion &&
		expected.StateDigestSHA256 == requirement.ExpectedStateDigestSHA256 &&
		next.Version == expected.Version+1 && !expected.Terminal
}

func cloneCanonicalStateRecord(value CanonicalStateRecord) CanonicalStateRecord {
	value.CanonicalState = append([]byte(nil), value.CanonicalState...)
	return value
}

func canonicalStateSpec(kind string) (string, bool) {
	switch kind {
	case CanonicalStateKindIAMKeyMaterial:
		return CanonicalStateContentTypeIAMKeyMaterial, true
	case CanonicalStateKindIAMIdentity:
		return CanonicalStateContentTypeIAMIdentity, true
	case CanonicalStateKindIAMKeyLifecycle:
		return CanonicalStateContentTypeIAMKeyLifecycle, true
	case CanonicalStateKindIAMAcceptedOwnershipTransfer:
		return CanonicalStateContentTypeIAMAcceptedOwnershipTransfer, true
	case CanonicalStateKindIAMProofChallenge:
		return CanonicalStateContentTypeIAMProofChallenge, true
	case CanonicalStateKindIAMPrincipalIdentityIndex:
		return CanonicalStateContentTypeIAMPrincipalIdentityIndex, true
	case CanonicalStateKindIAMRotationPredecessorIndex:
		return CanonicalStateContentTypeIAMRotationPredecessorIndex, true
	case CanonicalStateKindIAMSubjectKeySet:
		return CanonicalStateContentTypeIAMSubjectKeySet, true
	case CanonicalStateKindIAMWriterLease:
		return CanonicalStateContentTypeIAMWriterLease, true
	case CanonicalStateKindIAMTransferProfileActivation:
		return CanonicalStateContentTypeIAMTransferProfileActivation, true
	default:
		return "", false
	}
}

func validCanonicalStateRecord(value CanonicalStateRecord) bool {
	contentType, ok := canonicalStateSpec(value.Kind)
	if !ok || value.Namespace != CanonicalStateNamespaceIAM || value.ContentType != contentType ||
		value.ObjectID == "" || len(value.ObjectID) > 1024 || value.Version == 0 ||
		value.StateDigestSHA256 == ([sha256.Size]byte{}) || len(value.CanonicalState) == 0 ||
		len(value.CanonicalState) > iamCanonicalStateMaxBytes || value.AuditEventID == "" || len(value.AuditEventID) > 1024 {
		return false
	}
	hasValidity := value.Kind == CanonicalStateKindIAMTransferProfileActivation
	return value.HasValidityWindow == hasValidity && ((!hasValidity && value.ValidFromUnixNano == 0 && value.ValidUntilUnixNano == 0) ||
		(hasValidity && value.ValidFromUnixNano >= 0 && value.ValidUntilUnixNano > value.ValidFromUnixNano))
}

func canonicalStateRecordBytes(value CanonicalStateRecord) ([]byte, error) {
	if !validCanonicalStateRecord(value) {
		return nil, ErrPendingPlanInvalid
	}
	return ccse.Marshal(iamCanonicalStateMaxBytes, func(out *ccse.Encoder) {
		out.Uint32(uint32(value.Namespace))
		out.String(value.Kind)
		out.String(value.ObjectID)
		out.Uint64(value.Version)
		out.FixedBytes(value.StateDigestSHA256[:], 32)
		out.String(value.ContentType)
		out.Bytes(value.CanonicalState)
		out.Bool(value.Terminal)
		out.String(value.AuditEventID)
		out.Bool(value.HasValidityWindow)
		out.Int64(value.ValidFromUnixNano)
		out.Int64(value.ValidUntilUnixNano)
	})
}

func digestCanonicalStateAssertion(value CanonicalStateRecord,
	semantic *SemanticProjectionV2) ([32]byte, error) {
	encoded, err := canonicalStateRecordBytes(value)
	if err != nil {
		return [32]byte{}, err
	}
	var semanticBytes []byte
	if semantic != nil {
		decoded, decodeErr := DecodeSemanticProjectionV2(value.Kind, value.ObjectID, value.Version,
			value.StateDigestSHA256, value.CanonicalState, semantic.Canonical)
		if decodeErr != nil || decoded.Projection().DigestSHA256 != semantic.DigestSHA256 {
			return [32]byte{}, ErrPendingPlanInvalid
		}
		semanticBytes, err = ccse.Marshal(semanticProjectionV2Max, func(out *ccse.Encoder) {
			out.String(semantic.Codec())
			out.FixedBytes(semantic.DigestSHA256[:], sha256.Size)
			out.Bytes(semantic.Canonical)
		})
		if err != nil {
			return [32]byte{}, err
		}
	}
	joined, err := ccse.Marshal(iamCanonicalStateMaxBytes+semanticProjectionV2Max, func(out *ccse.Encoder) {
		out.Bytes(encoded)
		out.Bytes(semanticBytes)
	})
	if err != nil {
		return [32]byte{}, err
	}
	return domainDigest(iamCanonicalStateAssertionDomain, joined), nil
}
func newCanonicalStateAssertion(value CanonicalStateRecord) (CanonicalStateAssertion, error) {
	value = cloneCanonicalStateRecord(value)
	digest, err := digestCanonicalStateAssertion(value, nil)
	if err != nil {
		return CanonicalStateAssertion{}, err
	}
	return CanonicalStateAssertion{record: value, digest: digest}, nil
}
func digestCanonicalStateAbsence(namespace uint8, kind, objectID string) ([32]byte, error) {
	if namespace != CanonicalStateNamespaceIAM || objectID == "" || len(objectID) > 1024 {
		return [32]byte{}, ErrPendingPlanInvalid
	}
	if _, ok := canonicalStateSpec(kind); !ok {
		return [32]byte{}, ErrPendingPlanInvalid
	}
	encoded, err := ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.Uint32(uint32(namespace))
		out.String(kind)
		out.String(objectID)
	})
	if err != nil {
		return [32]byte{}, err
	}
	return domainDigest(iamCanonicalStateAbsenceDomain, encoded), nil
}
func newCanonicalStateAbsence(namespace uint8, kind, objectID string) (CanonicalStateAbsence, error) {
	digest, err := digestCanonicalStateAbsence(namespace, kind, objectID)
	if err != nil {
		return CanonicalStateAbsence{}, err
	}
	return CanonicalStateAbsence{namespace: namespace, kind: kind, objectID: objectID,
		digest: digest}, nil
}
func digestCanonicalStateMutation(expected *CanonicalStateRecord, next CanonicalStateRecord,
	semantic *SemanticProjectionV2) ([32]byte, error) {
	nextBytes, err := canonicalStateRecordBytes(next)
	if err != nil {
		return [32]byte{}, err
	}
	var expectedBytes []byte
	if expected != nil {
		expectedBytes, err = canonicalStateRecordBytes(*expected)
		if err != nil {
			return [32]byte{}, err
		}
		if expected.Namespace != next.Namespace || expected.Kind != next.Kind || expected.ObjectID != next.ObjectID || expected.Terminal ||
			expected.Version == ^uint64(0) || next.Version != expected.Version+1 || expected.StateDigestSHA256 == next.StateDigestSHA256 || bytes.Equal(expected.CanonicalState, next.CanonicalState) {
			return [32]byte{}, ErrPendingPlanInvalid
		}
	} else if next.Version != 1 {
		return [32]byte{}, ErrPendingPlanInvalid
	}
	var semanticBytes []byte
	if semantic != nil {
		decoded, decodeErr := DecodeSemanticProjectionV2(next.Kind, next.ObjectID, next.Version,
			next.StateDigestSHA256, next.CanonicalState, semantic.Canonical)
		if decodeErr != nil || decoded.Projection().Digest() != semantic.Digest() {
			return [32]byte{}, ErrPendingPlanInvalid
		}
		semanticBytes, err = ccse.Marshal(semanticProjectionV2Max, func(out *ccse.Encoder) {
			out.String(semantic.Codec())
			out.FixedBytes(semantic.DigestSHA256[:], sha256.Size)
			out.Bytes(semantic.Canonical)
		})
		if err != nil {
			return [32]byte{}, err
		}
	}
	encoded, err := ccse.Marshal(iamCanonicalStateMaxBytes+semanticProjectionV2Max, func(out *ccse.Encoder) {
		out.Bool(expected != nil)
		out.Bytes(expectedBytes)
		out.Bytes(nextBytes)
		out.Bytes(semanticBytes)
	})
	if err != nil {
		return [32]byte{}, err
	}
	return domainDigest(iamCanonicalStateMutationDomain, encoded), nil
}
func newCanonicalStateMutation(expected *CanonicalStateRecord, next CanonicalStateRecord) (CanonicalStateMutation, error) {
	var owned *CanonicalStateRecord
	if expected != nil {
		copy := cloneCanonicalStateRecord(*expected)
		owned = &copy
	}
	next = cloneCanonicalStateRecord(next)
	digest, err := digestCanonicalStateMutation(owned, next, nil)
	if err != nil {
		return CanonicalStateMutation{}, err
	}
	return CanonicalStateMutation{expected: owned, next: next, digest: digest}, nil
}
func digestCanonicalStateBundle(assertions []CanonicalStateAssertion, absences []CanonicalStateAbsence,
	mutations []CanonicalStateMutation, eventID string, coverageDigest [sha256.Size]byte) ([32]byte, error) {
	if eventID == "" || coverageDigest == ([sha256.Size]byte{}) ||
		len(assertions)+len(absences)+len(mutations) == 0 ||
		len(assertions)+len(absences) > iamCanonicalStateMaxAssertions ||
		len(mutations) > iamCanonicalStateMaxMutations {
		return [32]byte{}, ErrPendingPlanInvalid
	}
	ad := make([][32]byte, len(assertions))
	for i := range assertions {
		if assertions[i].VerifyDigest() != nil {
			return [32]byte{}, ErrPendingPlanInvalid
		}
		ad[i] = assertions[i].digest
	}
	sort.Slice(ad, func(i, j int) bool { return bytes.Compare(ad[i][:], ad[j][:]) < 0 })
	for i := 1; i < len(ad); i++ {
		if ad[i] == ad[i-1] {
			return [32]byte{}, ErrPendingPlanInvalid
		}
	}
	absenceDigests := make([][32]byte, len(absences))
	for i := range absences {
		if absences[i].VerifyDigest() != nil {
			return [32]byte{}, ErrPendingPlanInvalid
		}
		absenceDigests[i] = absences[i].digest
	}
	sort.Slice(absenceDigests, func(i, j int) bool {
		return bytes.Compare(absenceDigests[i][:], absenceDigests[j][:]) < 0
	})
	for i := 1; i < len(absenceDigests); i++ {
		if absenceDigests[i] == absenceDigests[i-1] {
			return [32]byte{}, ErrPendingPlanInvalid
		}
	}
	md := make([][32]byte, len(mutations))
	for i := range mutations {
		if mutations[i].VerifyDigest() != nil {
			return [32]byte{}, ErrPendingPlanInvalid
		}
		md[i] = mutations[i].digest
	}
	encoded, err := ccse.Marshal(128<<10, func(out *ccse.Encoder) {
		out.String(eventID)
		out.FixedBytes(coverageDigest[:], sha256.Size)
		out.Uint32(uint32(len(ad)))
		for _, d := range ad {
			out.FixedBytes(d[:], 32)
		}
		out.Uint32(uint32(len(absenceDigests)))
		for _, d := range absenceDigests {
			out.FixedBytes(d[:], 32)
		}
		out.Uint32(uint32(len(md)))
		for _, d := range md {
			out.FixedBytes(d[:], 32)
		}
	})
	if err != nil {
		return [32]byte{}, err
	}
	return domainDigest(iamCanonicalStateBundleDomain, encoded), nil
}
func cloneCanonicalStateAssertions(values []CanonicalStateAssertion) []CanonicalStateAssertion {
	result := make([]CanonicalStateAssertion, len(values))
	for i := range values {
		result[i] = CanonicalStateAssertion{record: cloneCanonicalStateRecord(values[i].record),
			digest: values[i].digest}
		if values[i].semanticV2 != nil {
			projection := *values[i].semanticV2
			projection.Canonical = append([]byte(nil), projection.Canonical...)
			result[i].semanticV2 = &projection
		}
	}
	return result
}

func equalSemanticProjectionPointers(left, right *SemanticProjectionV2) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Kind == right.Kind && left.ObjectID == right.ObjectID &&
		left.Version == right.Version && left.StateDigestSHA256 == right.StateDigestSHA256 &&
		left.Codec() == right.Codec() && left.DigestSHA256 == right.DigestSHA256 &&
		bytes.Equal(left.Canonical, right.Canonical)
}
func cloneCanonicalStateMutations(values []CanonicalStateMutation) []CanonicalStateMutation {
	result := make([]CanonicalStateMutation, len(values))
	for i := range values {
		result[i].next = cloneCanonicalStateRecord(values[i].next)
		result[i].digest = values[i].digest
		if values[i].semanticV2 != nil {
			projection := *values[i].semanticV2
			projection.Canonical = append([]byte(nil), projection.Canonical...)
			result[i].semanticV2 = &projection
		}
		if values[i].expected != nil {
			v := cloneCanonicalStateRecord(*values[i].expected)
			result[i].expected = &v
		}
	}
	return result
}
