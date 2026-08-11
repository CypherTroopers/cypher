// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"encoding/json"
	"reflect"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	joinedAuditRequestDigestDomain = "CPH-AIIE-IAM-JOINED-AUDIT-REQUEST-V2\x00"
	joinedAuditStateDigestDomain   = "CPH-AIIE-IAM-JOINED-AUDIT-STATE-COMMITMENT-V1\x00"
)

// ContentAddressedEvidenceReference makes every AuditIntent evidence digest
// mechanically resolvable. Embedded is true only when the durable envelope
// itself contains the complete signed preimage (currently the direct source
// authorization); other references must be resolved and digest-checked by the
// WS0.2b EvidenceView before a canonical audit append is accepted.
type ContentAddressedEvidenceReference struct {
	Digest   [32]byte
	Domain   string
	Embedded bool
}

// JoinedAuditRequest is the opaque IAM -> Governance bridge. Its fields are
// private so a caller cannot manufacture an expected AuditIntent or X/Y CAS.
// Governance receives this concrete type, calls VerifyDigest, rechecks the
// durable current X/Y/EventID state, and returns its own non-committable joined
// fragment. Only the WS0.2b coordinator may combine both fragments.
type JoinedAuditRequest struct {
	envelope                 DurablePendingEnvelope
	parentBinding            idempotency.Binding
	joinedBinding            idempotency.Binding
	parentExpected           idempotency.Snapshot
	joinedExpected           idempotency.Snapshot
	admissionIdempotency     []idempotency.Claim
	compoundMemberAdmission  []idempotency.CompoundMemberClaim
	compoundMemberCompletion []idempotency.CompoundMemberClaim
	completion               []idempotency.Claim
	admissionIdentifiers     []globalid.Claim
	identifierAssertions     []globalid.Claim
	dependencies             []SnapshotPrecondition
	casIntents               []CASIntent
	audit                    *AuditIntent
	reconciliation           *ReconciliationAuditRequirement
	auditEventID             string
	auditEventAssertion      globalid.Claim
	evaluatedAtUnixNano      int64
	commitNotBeforeUnixNano  int64
	commitNotAfterUnixNano   int64
	stateCommitment          [32]byte
	failureOutcomeDigest     [32]byte
	evidenceReferences       []ContentAddressedEvidenceReference
	execution                *IAMExecutionFragment
	digest                   [32]byte
}

func (request JoinedAuditRequest) Kind() DurablePendingKind { return request.envelope.Kind() }
func (request JoinedAuditRequest) CodecVersion() uint32     { return durablePendingCodecVersion }
func (request JoinedAuditRequest) PendingDigest() [32]byte  { return request.envelope.PendingDigest() }
func (request JoinedAuditRequest) DurableEnvelopeDigest() [32]byte {
	return request.envelope.Digest()
}
func (request JoinedAuditRequest) DurableEnvelopeBytes() []byte { return request.envelope.Bytes() }
func (request JoinedAuditRequest) ParentBinding() idempotency.Binding {
	return request.parentBinding
}
func (request JoinedAuditRequest) JoinedBinding() idempotency.Binding {
	return request.joinedBinding
}
func (request JoinedAuditRequest) ParentExpectedSnapshot() idempotency.Snapshot {
	return request.parentExpected
}
func (request JoinedAuditRequest) JoinedExpectedSnapshot() idempotency.Snapshot {
	return request.joinedExpected
}
func (request JoinedAuditRequest) AdmissionIdempotencyClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), request.admissionIdempotency...)
}
func (request JoinedAuditRequest) CompoundMemberAdmissionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), request.compoundMemberAdmission...)
}
func (request JoinedAuditRequest) CompoundMemberCompletionClaims() []idempotency.CompoundMemberClaim {
	return append([]idempotency.CompoundMemberClaim(nil), request.compoundMemberCompletion...)
}
func (request JoinedAuditRequest) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), request.completion...)
}
func (request JoinedAuditRequest) AdmissionIdentifierClaims() []globalid.Claim {
	return append([]globalid.Claim(nil), request.admissionIdentifiers...)
}
func (request JoinedAuditRequest) IdentifierAssertions() []globalid.Claim {
	return append([]globalid.Claim(nil), request.identifierAssertions...)
}
func (request JoinedAuditRequest) Dependencies() []SnapshotPrecondition {
	return append([]SnapshotPrecondition(nil), request.dependencies...)
}
func (request JoinedAuditRequest) CASIntents() []CASIntent {
	result := make([]CASIntent, len(request.casIntents))
	for index := range request.casIntents {
		result[index] = cloneCASIntent(request.casIntents[index])
	}
	return result
}
func (request JoinedAuditRequest) ExpectedAuditIntent() (AuditIntent, bool) {
	if request.audit == nil {
		return AuditIntent{}, false
	}
	return cloneAuditIntent(*request.audit), true
}
func (request JoinedAuditRequest) ReconciliationAuditRequirement() (ReconciliationAuditRequirement, bool) {
	if request.reconciliation == nil {
		return ReconciliationAuditRequirement{}, false
	}
	value := *request.reconciliation
	value.sourceAuthorizationRecord = cloneCCSERecord(value.sourceAuthorizationRecord)
	value.policyDigestsSHA256 = cloneDigests(value.policyDigestsSHA256)
	return value, true
}
func (request JoinedAuditRequest) JoinedAuditEventID() string { return request.auditEventID }
func (request JoinedAuditRequest) JoinedAuditEventIdentifierAssertion() globalid.Claim {
	return request.auditEventAssertion
}
func (request JoinedAuditRequest) EvaluatedAtUnixNano() int64 { return request.evaluatedAtUnixNano }
func (request JoinedAuditRequest) CommitNotBeforeUnixNano() int64 {
	return request.commitNotBeforeUnixNano
}
func (request JoinedAuditRequest) CommitNotAfterUnixNano() int64 {
	return request.commitNotAfterUnixNano
}
func (request JoinedAuditRequest) StateAndGlobalCASCommitment() [32]byte {
	return request.stateCommitment
}

// FailureOutcomeDigest is the exact X/Y completion outcome for a
// reconciliation. A successful request returns zero,false because the joined
// coordinator, not IAM alone, produces the combined success outcome.
func (request JoinedAuditRequest) FailureOutcomeDigest() ([32]byte, bool) {
	return request.failureOutcomeDigest, request.failureOutcomeDigest != ([32]byte{})
}
func (request JoinedAuditRequest) EvidenceReferences() []ContentAddressedEvidenceReference {
	return append([]ContentAddressedEvidenceReference(nil), request.evidenceReferences...)
}
func (request JoinedAuditRequest) Digest() [32]byte { return request.digest }
func (JoinedAuditRequest) CommitReady() bool        { return false }
func (request JoinedAuditRequest) ExecutionFragment() (IAMExecutionFragment, bool) {
	if request.execution == nil {
		return IAMExecutionFragment{}, false
	}
	return cloneIAMExecutionFragment(*request.execution), true
}

// ExpectedOutcome is the exact canonical AuditOutcome that Governance must
// bind to the joined AuditEvent. Ordinary IAM transitions succeed; audited
// reconciliation closes the pair as FAILED or TIMED_OUT.
func (request JoinedAuditRequest) ExpectedOutcome() uint32 {
	if request.reconciliation == nil {
		return 1
	}
	if request.envelope.reconciliation != nil &&
		request.envelope.reconciliation.disposition == PendingDispositionExpired {
		return 4
	}
	return 3
}

func (request JoinedAuditRequest) VerifyDigest() error {
	if err := request.envelope.VerifyDigest(); err != nil {
		return err
	}
	rebuilt, err := joinedAuditRequestFromEnvelope(request.envelope)
	currentState, stateErr := joinedAuditStateCommitment(request)
	currentDigest, digestErr := joinedAuditRequestDigest(request)
	if err != nil || stateErr != nil || digestErr != nil ||
		currentState != request.stateCommitment || currentDigest != request.digest ||
		rebuilt.digest != request.digest || rebuilt.stateCommitment != request.stateCommitment ||
		rebuilt.auditEventID != request.auditEventID || rebuilt.parentBinding != request.parentBinding ||
		rebuilt.auditEventAssertion != request.auditEventAssertion ||
		rebuilt.joinedBinding != request.joinedBinding || rebuilt.parentExpected != request.parentExpected ||
		rebuilt.joinedExpected != request.joinedExpected ||
		rebuilt.failureOutcomeDigest != request.failureOutcomeDigest ||
		!sameIdempotencyClaims(rebuilt.admissionIdempotency, request.admissionIdempotency) ||
		!sameCompoundMemberClaims(rebuilt.compoundMemberAdmission, request.compoundMemberAdmission) ||
		!sameCompoundMemberClaims(rebuilt.compoundMemberCompletion, request.compoundMemberCompletion) ||
		!sameIdempotencyClaims(rebuilt.completion, request.completion) ||
		!reflect.DeepEqual(rebuilt.admissionIdentifiers, request.admissionIdentifiers) ||
		!reflect.DeepEqual(rebuilt.identifierAssertions, request.identifierAssertions) ||
		!reflect.DeepEqual(rebuilt.dependencies, request.dependencies) ||
		!reflect.DeepEqual(rebuilt.casIntents, request.casIntents) ||
		!reflect.DeepEqual(rebuilt.audit, request.audit) ||
		!reflect.DeepEqual(rebuilt.reconciliation, request.reconciliation) ||
		!reflect.DeepEqual(rebuilt.execution, request.execution) ||
		!sameEvidenceReferences(rebuilt.evidenceReferences, request.evidenceReferences) {
		return ErrPendingPlanInvalid
	}
	return nil
}

func (plan PendingMutationPlan) JoinedAuditRequest() (JoinedAuditRequest, error) {
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	return joinedAuditRequestFromEnvelope(envelope)
}

func (plan PendingKeyEnrollmentPlan) JoinedAuditRequest() (JoinedAuditRequest, error) {
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	return joinedAuditRequestFromEnvelope(envelope)
}

func (plan OwnershipTransferApprovalCollectionPlan) JoinedAuditRequest() (JoinedAuditRequest, error) {
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	return joinedAuditRequestFromEnvelope(envelope)
}

func (plan PendingReconciliationPlan) JoinedAuditRequest() (JoinedAuditRequest, error) {
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	return joinedAuditRequestFromEnvelope(envelope)
}

func (plan PendingOwnershipTransferAcceptancePlan) JoinedAuditRequest() (JoinedAuditRequest, error) {
	envelope, err := plan.DurableEnvelope()
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	return joinedAuditRequestFromEnvelope(envelope)
}

func (envelope DurablePendingEnvelope) JoinedAuditRequest() (JoinedAuditRequest, error) {
	return joinedAuditRequestFromEnvelope(envelope)
}

func joinedAuditRequestFromEnvelope(envelope DurablePendingEnvelope) (JoinedAuditRequest, error) {
	if !envelope.capability {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	if err := envelope.VerifyDigest(); err != nil {
		return JoinedAuditRequest{}, err
	}
	request := JoinedAuditRequest{envelope: envelope}
	switch envelope.Kind() {
	case DurablePendingMutation:
		plan, _ := envelope.PendingMutationPlan()
		request.audit = auditPointer(plan.AuditIntent())
		request.evaluatedAtUnixNano = plan.EvaluatedAtUnixNano()
		request.commitNotBeforeUnixNano = plan.CommitNotBeforeUnixNano()
		request.commitNotAfterUnixNano = plan.CommitNotAfterUnixNano()
		request.casIntents = []CASIntent{plan.CAS()}
		request.admissionIdentifiers = plan.AdmissionIntent().IdentifierReservations()
		request.identifierAssertions = plan.CAS().IdentifierClaims
		request.dependencies = plan.CAS().Dependencies
		if err := fillPendingPair(&request, plan.AdmissionIntent().IdempotencyReservations(),
			plan.IdempotencyCompletionClaims()); err != nil {
			return JoinedAuditRequest{}, err
		}
	case DurablePendingKeyEnrollment:
		plan, _ := envelope.PendingKeyEnrollmentPlan()
		request.audit = auditPointer(plan.AuditIntent())
		request.evaluatedAtUnixNano = plan.EvaluatedAtUnixNano()
		request.commitNotBeforeUnixNano = plan.CommitNotBeforeUnixNano()
		request.commitNotAfterUnixNano = plan.CommitNotAfterUnixNano()
		request.casIntents = plan.CASIntents()
		request.admissionIdentifiers = plan.AdmissionIntent().IdentifierReservations()
		for _, cas := range request.casIntents {
			request.identifierAssertions = append(request.identifierAssertions, cas.IdentifierClaims...)
			request.dependencies = append(request.dependencies, cas.Dependencies...)
		}
		if err := fillPendingPair(&request, plan.AdmissionIntent().IdempotencyReservations(),
			plan.IdempotencyCompletionClaims()); err != nil {
			return JoinedAuditRequest{}, err
		}
	case DurablePendingOwnershipTransferCollection:
		plan, _ := envelope.OwnershipTransferCollectionPlan()
		if !plan.QuorumSatisfied() {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
		audit, ok := plan.AuditIntent()
		if !ok {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
		request.audit = auditPointer(audit)
		request.evaluatedAtUnixNano = plan.EvaluatedAtUnixNano()
		request.commitNotBeforeUnixNano = plan.CommitNotBeforeUnixNano()
		request.commitNotAfterUnixNano = plan.CommitNotAfterUnixNano()
		request.admissionIdempotency = plan.IdempotencyClaims()
		request.completion = plan.IdempotencyCompletionClaims()
		request.identifierAssertions = plan.IdentifierClaims()
		request.dependencies = plan.Dependencies()
		request.parentBinding = plan.next.Binding
		joined, err := idempotency.JoinedAuditBinding(request.parentBinding)
		if err != nil {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
		request.joinedBinding = joined
		request.parentExpected = idempotency.Snapshot{Binding: request.parentBinding,
			State: idempotency.StateCollecting, Version: plan.next.Version,
			ProgressDigest: plan.next.ProgressDigest}
		if plan.disposition == OwnershipTransferCollectionAppend {
			parentDigest, digestErr := idempotency.BindingDigest(request.parentBinding)
			if digestErr != nil {
				return JoinedAuditRequest{}, digestErr
			}
			request.joinedExpected = idempotency.Snapshot{Binding: joined,
				State: idempotency.StateCollecting, Version: 1, ProgressDigest: parentDigest}
		} else {
			request.joinedExpected = plan.joinedAuditSnapshot
		}
	case DurablePendingReconciliation:
		plan, _ := envelope.PendingReconciliationPlan()
		requirement := plan.AuditRequirement()
		request.reconciliation = &requirement
		request.evaluatedAtUnixNano = plan.EvaluatedAtUnixNano()
		request.commitNotBeforeUnixNano = plan.CommitNotBeforeUnixNano()
		request.commitNotAfterUnixNano = plan.CommitNotAfterUnixNano()
		request.identifierAssertions = plan.IdentifierTombstoneAssertions()
		request.completion = plan.IdempotencyCompletionClaims()
		request.compoundMemberCompletion = plan.CompoundMemberCompletionClaims()
		request.failureOutcomeDigest = plan.FailureOutcomeDigest()
		parent, joined, err := pendingCompletionBindings(request.completion)
		if err != nil {
			return JoinedAuditRequest{}, err
		}
		request.parentBinding, request.joinedBinding = parent, joined
		for _, claim := range request.completion {
			snapshot := idempotency.Snapshot{Binding: claim.Binding, State: claim.ExpectedState,
				Version: claim.ExpectedVersion, ProgressDigest: claim.ExpectedProgressDigest}
			if claim.Binding == parent {
				request.parentExpected = snapshot
			} else if claim.Binding == joined {
				request.joinedExpected = snapshot
			}
		}
	case DurablePendingOwnershipTransferAcceptance:
		plan, _ := envelope.PendingOwnershipTransferAcceptancePlan()
		request.audit = auditPointer(plan.AuditIntent())
		request.evaluatedAtUnixNano = plan.EvaluatedAtUnixNano()
		request.commitNotBeforeUnixNano = plan.CommitNotBeforeUnixNano()
		request.commitNotAfterUnixNano = plan.CommitNotAfterUnixNano()
		request.admissionIdempotency = plan.cutover.AdmissionIntent().IdempotencyReservations()
		request.compoundMemberAdmission = plan.cutover.CompoundMemberAdmissionClaims()
		request.admissionIdentifiers = plan.cutover.AdmissionIntent().IdentifierReservations()
		request.identifierAssertions = plan.IdentifierAssertions()
		request.dependencies = plan.Dependencies()
		request.completion = plan.TransferCompletionClaims()
		parent, joined, completionErr := pendingCompletionBindings(request.completion)
		if completionErr != nil {
			return JoinedAuditRequest{}, completionErr
		}
		request.parentBinding, request.joinedBinding = parent, joined
		for _, claim := range request.completion {
			snapshot := idempotency.Snapshot{Binding: claim.Binding, State: claim.ExpectedState,
				Version: claim.ExpectedVersion, ProgressDigest: claim.ExpectedProgressDigest}
			if claim.Binding == parent {
				request.parentExpected = snapshot
			} else if claim.Binding == joined {
				request.joinedExpected = snapshot
			}
		}
	case DurablePendingOwnershipTransferCutover:
		plan, _ := envelope.PendingOwnershipTransferCutoverPlan()
		request.audit = auditPointer(plan.AuditIntent())
		request.evaluatedAtUnixNano = plan.EvaluatedAtUnixNano()
		request.commitNotBeforeUnixNano = plan.CommitNotBeforeUnixNano()
		request.commitNotAfterUnixNano = plan.CommitNotAfterUnixNano()
		request.completion = plan.IdempotencyCompletionClaims()
		request.compoundMemberCompletion = plan.CompoundMemberCompletionClaims()
		request.identifierAssertions = plan.IdentifierAssertions()
		request.dependencies = plan.Dependencies()
		for _, step := range plan.Steps() {
			request.casIntents = append(request.casIntents, step.Mutation.CAS())
		}
		parent, joined, completionErr := pendingCompletionBindings(request.completion)
		if completionErr != nil {
			return JoinedAuditRequest{}, completionErr
		}
		request.parentBinding, request.joinedBinding = parent, joined
		for _, claim := range request.completion {
			snapshot := idempotency.Snapshot{Binding: claim.Binding, State: claim.ExpectedState,
				Version: claim.ExpectedVersion, ProgressDigest: claim.ExpectedProgressDigest}
			if claim.Binding == parent {
				request.parentExpected = snapshot
			} else if claim.Binding == joined {
				request.joinedExpected = snapshot
			}
		}
	default:
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	var err error
	if len(request.admissionIdentifiers) != 0 {
		request.admissionIdentifiers, err = normalizeGlobalClaims(request.admissionIdentifiers)
		if err != nil {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
	}
	if len(request.identifierAssertions) != 0 {
		request.identifierAssertions, err = normalizeGlobalClaims(request.identifierAssertions)
		if err != nil {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
	}
	if len(request.compoundMemberAdmission) != 0 {
		request.compoundMemberAdmission, err = idempotency.NormalizeCompoundMemberClaims(
			request.compoundMemberAdmission)
		if err != nil || idempotency.ValidateDisjointClaimKeys(request.admissionIdempotency,
			request.compoundMemberAdmission) != nil {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
	}
	if len(request.compoundMemberCompletion) != 0 {
		request.compoundMemberCompletion, err = idempotency.NormalizeCompoundMemberClaims(
			request.compoundMemberCompletion)
		if err != nil || idempotency.ValidateDisjointClaimKeys(request.completion,
			request.compoundMemberCompletion) != nil {
			return JoinedAuditRequest{}, ErrPendingPlanInvalid
		}
	}
	request.dependencies, err = canonicalPreconditions(request.dependencies)
	if err != nil {
		return JoinedAuditRequest{}, ErrPendingPlanInvalid
	}
	if request.audit != nil {
		request.auditEventID = request.audit.AuditEventID()
		request.evidenceReferences = auditEvidenceReferences(*request.audit)
	} else {
		request.auditEventID = request.reconciliation.AuditEventID()
		reference := ContentAddressedEvidenceReference{Digest: request.reconciliation.SourceAuthorizationDigest(),
			Domain: "iam.source-authorization.v1", Embedded: true}
		request.evidenceReferences = []ContentAddressedEvidenceReference{reference}
	}
	request.auditEventAssertion, err = deriveJoinedAuditEventAssertion(request)
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	state, err := joinedAuditStateCommitment(request)
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	request.stateCommitment = state
	execution, err := executionFragmentFromRequest(request)
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	request.execution = &execution
	request.digest, err = joinedAuditRequestDigest(request)
	if err != nil {
		return JoinedAuditRequest{}, err
	}
	return request, nil
}

func deriveJoinedAuditEventAssertion(request JoinedAuditRequest) (globalid.Claim, error) {
	for _, claim := range append(append([]globalid.Claim(nil), request.identifierAssertions...),
		request.admissionIdentifiers...) {
		if claim.Identifier != request.auditEventID {
			continue
		}
		switch claim.Mode {
		case globalid.AssertExisting:
			if claim.Owner.Domain == globalid.OwnerGovernanceAuditEvent &&
				claim.Owner.ID == request.auditEventID {
				return claim, nil
			}
		case globalid.ReserveNew:
			assertion, err := globalid.Assert(claim.Identifier, globalid.Snapshot{
				Identifier: claim.Identifier, Owner: claim.Owner, Version: claim.NextVersion}, claim.Owner)
			if err == nil && claim.Owner.Domain == globalid.OwnerGovernanceAuditEvent &&
				claim.Owner.ID == request.auditEventID {
				return assertion, nil
			}
		}
	}
	return globalid.Claim{}, ErrPendingPlanInvalid
}

func fillPendingPair(request *JoinedAuditRequest, reservations,
	completions []idempotency.Claim) error {
	parent, joined, err := pendingIdempotencyBindings(reservations)
	if err != nil {
		return err
	}
	request.parentBinding, request.joinedBinding = parent, joined
	request.admissionIdempotency = append([]idempotency.Claim(nil), reservations...)
	request.completion = append([]idempotency.Claim(nil), completions...)
	for _, claim := range reservations {
		snapshot := idempotency.Snapshot{Binding: claim.Binding, State: claim.NextState,
			Version: claim.NextVersion, ProgressDigest: claim.NextProgressDigest}
		if claim.Binding == parent {
			request.parentExpected = snapshot
		} else if claim.Binding == joined {
			request.joinedExpected = snapshot
		}
	}
	return nil
}

func auditPointer(audit AuditIntent) *AuditIntent {
	copy := cloneAuditIntent(audit)
	return &copy
}

func cloneAuditIntent(source AuditIntent) AuditIntent {
	result := source
	result.subjectIDs = append([]string(nil), source.subjectIDs...)
	result.sourceAuthorizationRecord = cloneCCSERecord(source.sourceAuthorizationRecord)
	result.policyDigestsSHA256 = cloneDigests(source.policyDigestsSHA256)
	result.evidenceDigestsSHA256 = cloneDigests(source.evidenceDigestsSHA256)
	return result
}

func cloneCASIntent(source CASIntent) CASIntent {
	result := source
	result.Dependencies = append([]SnapshotPrecondition(nil), source.Dependencies...)
	result.IdentifierClaims = append([]globalid.Claim(nil), source.IdentifierClaims...)
	result.IdempotencyClaims = append([]idempotency.Claim(nil), source.IdempotencyClaims...)
	return result
}

func auditEvidenceReferences(audit AuditIntent) []ContentAddressedEvidenceReference {
	values := audit.EvidenceDigestsSHA256()
	sourceDigest := audit.SourceAuthorizationDigest()
	result := make([]ContentAddressedEvidenceReference, 0, len(values)+1)
	seen := make(map[[32]byte]struct{}, len(values)+1)
	if sourceDigest != ([32]byte{}) {
		result = append(result, ContentAddressedEvidenceReference{Digest: sourceDigest,
			Domain: "iam.source-authorization.v1", Embedded: true})
		seen[sourceDigest] = struct{}{}
	}
	for _, digest := range values {
		if digest == ([32]byte{}) {
			continue
		}
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		result = append(result, ContentAddressedEvidenceReference{Digest: digest,
			Domain: "iam.audit-evidence.v1", Embedded: false})
	}
	return result
}

func joinedAuditStateCommitment(request JoinedAuditRequest) ([32]byte, error) {
	var zero [32]byte
	var admissionIdentifierBytes []byte
	var err error
	if len(request.admissionIdentifiers) != 0 {
		admissionIdentifierBytes, err = globalid.CanonicalBytes(request.admissionIdentifiers)
		if err != nil {
			return zero, err
		}
	}
	var identifierBytes []byte
	if len(request.identifierAssertions) != 0 {
		identifierBytes, err = globalid.CanonicalBytes(request.identifierAssertions)
		if err != nil {
			return zero, err
		}
	}
	dependencies, err := canonicalSnapshotPreconditions(request.dependencies)
	if err != nil {
		return zero, err
	}
	var admissionIdempotency []byte
	if len(request.admissionIdempotency) != 0 {
		admissionIdempotency, err = idempotency.CanonicalBytes(request.admissionIdempotency)
		if err != nil {
			return zero, err
		}
	}
	var completion []byte
	if len(request.completion) != 0 {
		completion, err = idempotency.CanonicalBytes(request.completion)
		if err != nil {
			return zero, err
		}
	}
	var compoundMembers []byte
	if len(request.compoundMemberAdmission) != 0 {
		compoundMembers, err = idempotency.CompoundMemberCanonicalBytes(request.compoundMemberAdmission)
		if err != nil {
			return zero, err
		}
	}
	var compoundMemberCompletions []byte
	if len(request.compoundMemberCompletion) != 0 {
		compoundMemberCompletions, err = idempotency.CompoundMemberCanonicalBytes(
			request.compoundMemberCompletion)
		if err != nil {
			return zero, err
		}
	}
	casElements := make([][]byte, 0, len(request.casIntents))
	for _, cas := range request.casIntents {
		encoded, encodeErr := canonicalCASIntent(cas)
		if encodeErr != nil {
			return zero, encodeErr
		}
		casElements = append(casElements, encoded)
	}
	encoded, err := ccse.Marshal(16<<20, func(out *ccse.Encoder) {
		envelopeDigest := request.envelope.Digest()
		out.FixedBytes(envelopeDigest[:], 32)
		out.Bytes(admissionIdentifierBytes)
		out.Bytes(identifierBytes)
		out.Bytes(dependencies)
		out.Bytes(admissionIdempotency)
		out.Bytes(completion)
		out.Bytes(compoundMembers)
		out.Bytes(compoundMemberCompletions)
		out.EncodedList(casElements)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(joinedAuditStateDigestDomain, encoded), nil
}

// canonicalCASIntent commits every storage fence carried by a mutation. The
// durable envelope also binds these values, but the joined bridge exposes one
// independently verifiable commitment for the WS0.2b transaction adapter.
func canonicalCASIntent(cas CASIntent) ([]byte, error) {
	dependencies, err := canonicalSnapshotPreconditions(cas.Dependencies)
	if err != nil {
		return nil, err
	}
	var identifiers []byte
	if len(cas.IdentifierClaims) != 0 {
		identifiers, err = globalid.CanonicalBytes(cas.IdentifierClaims)
		if err != nil {
			return nil, err
		}
	}
	var idempotencyClaims []byte
	if len(cas.IdempotencyClaims) != 0 {
		idempotencyClaims, err = idempotency.CanonicalBytes(cas.IdempotencyClaims)
		if err != nil {
			return nil, err
		}
	}
	return ccse.Marshal(8<<20, func(out *ccse.Encoder) {
		encodeEntity(out, cas.Entity)
		out.Bool(cas.ExpectedAbsent)
		out.Uint64(cas.ExpectedStateVersion)
		out.Uint64(cas.ExpectedEntityWriterEpoch)
		out.Uint64(cas.AuthorizedWriterEpoch)
		out.Bool(cas.ConsumeChallenge)
		out.FixedBytes(cas.Challenge[:], 32)
		out.FixedBytes(cas.ChallengeEvidenceDigest[:], 32)
		out.FixedBytes(cas.WriterEvidenceDigest[:], 32)
		out.Bytes(dependencies)
		out.Uint32(uint32(cas.PredecessorIndexMode))
		out.String(cas.RotationPredecessorKeyID)
		out.FixedBytes(cas.TransferEvidenceDigest[:], 32)
		out.FixedBytes(cas.EnrollmentEvidenceDigest[:], 32)
		out.FixedBytes(cas.AuthorizationDigest[:], 32)
		out.Uint32(uint32(cas.PrincipalIndex.Mode))
		out.Uint32(cas.PrincipalIndex.PrincipalKind)
		out.String(cas.PrincipalIndex.PrincipalIdentity)
		encodeEntity(out, cas.PrincipalIndex.ExpectedOwner)
		encodeEntity(out, cas.PrincipalIndex.NextOwner)
		out.Uint64(cas.PrincipalIndex.ExpectedStateVersion)
		out.Uint64(cas.PrincipalIndex.ExpectedEntityWriterEpoch)
		out.Uint32(cas.PrincipalIndex.ExpectedState)
		out.FixedBytes(cas.PrincipalIndex.TransferEvidenceDigest[:], 32)
		out.Bytes(identifiers)
		out.Bool(cas.ExpectedSubjectAbsent)
		out.Uint32(cas.SubjectKind)
		out.String(cas.SubjectIdentity)
		out.FixedBytes(cas.SubjectKeySetDigest[:], 32)
		out.Bytes(idempotencyClaims)
	})
}

func joinedAuditRequestDigest(request JoinedAuditRequest) ([32]byte, error) {
	var zero [32]byte
	parentDigest, err := idempotency.BindingDigest(request.parentBinding)
	if err != nil {
		return zero, err
	}
	joinedDigest, err := idempotency.BindingDigest(request.joinedBinding)
	if err != nil {
		return zero, err
	}
	parentSnapshot, err := canonicalIdempotencySnapshot(request.parentExpected)
	if err != nil {
		return zero, err
	}
	joinedSnapshot, err := canonicalIdempotencySnapshot(request.joinedExpected)
	if err != nil {
		return zero, err
	}
	completion, err := idempotency.CanonicalBytes(request.completion)
	if err != nil {
		return zero, err
	}
	auditAssertion, err := globalid.CanonicalBytes([]globalid.Claim{request.auditEventAssertion})
	if err != nil {
		return zero, err
	}
	auditDigest := [32]byte{}
	if request.audit != nil {
		auditDigest = request.audit.Digest()
	} else if request.reconciliation != nil {
		auditDigest = request.reconciliation.OriginalAuditIntentDigest()
	}
	if request.execution == nil || request.execution.VerifyDigest() != nil {
		return zero, ErrPendingPlanInvalid
	}
	executionDigest := request.execution.Digest()
	encoded, err := ccse.Marshal(4<<20, func(out *ccse.Encoder) {
		out.Uint32(uint32(request.Kind()))
		out.Uint32(request.CodecVersion())
		envelopeDigest := request.envelope.Digest()
		out.FixedBytes(envelopeDigest[:], 32)
		pendingDigest := request.PendingDigest()
		out.FixedBytes(pendingDigest[:], 32)
		out.FixedBytes(parentDigest[:], 32)
		out.FixedBytes(joinedDigest[:], 32)
		out.Bytes(parentSnapshot)
		out.Bytes(joinedSnapshot)
		out.Bytes(completion)
		out.String(request.auditEventID)
		out.Bytes(auditAssertion)
		out.FixedBytes(auditDigest[:], 32)
		out.Uint32(request.ExpectedOutcome())
		out.Int64(request.evaluatedAtUnixNano)
		out.Int64(request.commitNotBeforeUnixNano)
		out.Int64(request.commitNotAfterUnixNano)
		out.FixedBytes(request.stateCommitment[:], 32)
		out.Bool(request.failureOutcomeDigest != ([32]byte{}))
		out.FixedBytes(request.failureOutcomeDigest[:], 32)
		out.FixedBytes(executionDigest[:], 32)
	})
	if err != nil {
		return zero, err
	}
	return domainDigest(joinedAuditRequestDigestDomain, encoded), nil
}

func sameEvidenceReferences(left, right []ContentAddressedEvidenceReference) bool {
	if len(left) != len(right) {
		return false
	}
	return bytes.Equal(mustJSON(left), mustJSON(right))
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
