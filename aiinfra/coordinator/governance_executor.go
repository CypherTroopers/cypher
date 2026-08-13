// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"context"
	"crypto/sha256"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

// NewGovernanceApprovalAdmissionHandler persists one verified policy approval
// collection revision under the replay transaction of that same signed
// PolicyBundle. Admission has no AuditEvent; it reserves the future joined
// EventID and retains the complete evidence/pending state needed by finalization.
func NewGovernanceApprovalAdmissionHandler(plan governance.ApprovalCollectionPlan) (
	ccse.ReplayHandler, error) {
	if !plan.CommitReady() || plan.VerifyDigest() != nil {
		return nil, ErrInvalidCompoundResult
	}
	view := plan.Snapshot()
	if len(view.CanonicalStateAssertions) != 1 || len(view.CanonicalKeyStateAssertions) != 1 ||
		len(view.Claims) == 0 || len(view.IdentifierClaims) == 0 ||
		view.DurablePendingRevision.VerifyDigest() != nil ||
		view.NextEvidenceStorageCapability.VerifyDigest() != nil ||
		view.NextEvidenceStorageCapability.Disposition() != governance.DurableEvidenceStorageReserveNew ||
		view.NextEvidenceStorageCapability.AuditAssertionEventID() != view.JoinedAuditEventID ||
		view.NextEvidenceStorageCapability.ExpectedAuditEventID() != view.JoinedAuditEventID ||
		view.CommitNotBeforeUnixNano > view.EvaluatedAtUnixNano ||
		view.CommitNotAfterUnixNano <= view.EvaluatedAtUnixNano {
		return nil, ErrInvalidCompoundResult
	}
	pending, err := mapGovernancePendingRevision(view.DurablePendingRevision)
	if err != nil || pending.Status != postgres.DurablePendingOpen || pending.Revision == 0 ||
		pending.ExpectedAuditEventID != view.JoinedAuditEventID {
		return nil, ErrInvalidCompoundResult
	}
	var staticBytes uint64
	if addCanonicalWriteBytes(&staticBytes,
		len(view.NextEvidenceStorageCapability.CanonicalContent())) != nil ||
		addCanonicalWriteBytes(&staticBytes, len(pending.CanonicalEnvelope)) != nil {
		return nil, ErrInvalidCompoundResult
	}
	var parentExpected, joinedExpected idempotency.Snapshot
	if pending.Revision > 1 {
		_, parentExpected, joinedExpected, err = validateGovernanceCollectionAdvanceIdempotency(view)
		if err != nil {
			return nil, ErrInvalidCompoundResult
		}
	}

	return func(ctx context.Context, outer ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
		if !exactGovernanceOuter(outer, view.NextEvidence) {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		uow, err := postgres.OpenCanonicalUOW(ctx, outer, postgres.CanonicalAdmission, "", 0)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		result, err := buildGovernanceAdmissionResult(ctx, uow, plan, outer)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceStateAssertions(ctx, uow, view.CanonicalStateAssertions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceKeyStateAssertions(ctx, uow, view.CanonicalKeyStateAssertions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if pending.Revision > 1 {
			if err := assertGovernancePendingSource(ctx, uow, view.DurablePendingRevision); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
			if err := assertCollectionAdvanceIdempotency(ctx, uow, parentExpected, joinedExpected); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
		}
		if err := uow.ApplyBusinessIdempotency(ctx, postgres.BusinessIdempotencyMutation{
			ExpectedAuditEventID: view.JoinedAuditEventID, Claims: view.Claims,
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyGlobalClaims(ctx, postgres.GlobalClaimMutation{
			AuditEventID: view.JoinedAuditEventID, Claims: view.IdentifierClaims,
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceAdmissionEvidence(ctx, uow,
			view.NextEvidenceStorageCapability); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyDurablePendingRevision(ctx, pending); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AssertCommitDeadline(ctx, view.CommitNotAfterUnixNano); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		transaction, ok := postgres.Transaction(ctx)
		if !ok {
			return [ccse.DigestSize]byte{}, ErrTransactionBoundaryRequired
		}
		completion, err := result.Completion()
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		digest, err := transaction.Complete(ctx, completion)
		if err != nil || digest != result.Digest() {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		return digest, nil
	}, nil
}

func validateGovernanceCollectionAdvanceIdempotency(view governance.ApprovalCollectionPlanSnapshot) (
	idempotency.Claim, idempotency.Snapshot, idempotency.Snapshot, error) {
	claims, err := idempotency.NormalizeClaims(view.Claims)
	if err != nil || len(claims) != 1 || claims[0].Mode != idempotency.AdvanceCollection ||
		claims[0].Binding != view.Binding {
		return idempotency.Claim{}, idempotency.Snapshot{}, idempotency.Snapshot{}, ErrInvalidCompoundResult
	}
	claim := claims[0]
	parent := idempotency.Snapshot{Binding: claim.Binding, State: claim.ExpectedState,
		Version: claim.ExpectedVersion, ProgressDigest: claim.ExpectedProgressDigest}
	joined := view.JoinedAuditIdempotencySnapshot
	joinedBinding, joinErr := idempotency.JoinedAuditBinding(claim.Binding)
	parentDigest, digestErr := idempotency.BindingDigest(claim.Binding)
	if joinErr != nil || digestErr != nil || parent.Validate() != nil || joined.Validate() != nil ||
		joined.Binding != joinedBinding || joined.State != idempotency.StateCollecting ||
		joined.Version != 1 || joined.ProgressDigest != parentDigest ||
		joined.OutcomeDigest != ([ccse.DigestSize]byte{}) {
		return idempotency.Claim{}, idempotency.Snapshot{}, idempotency.Snapshot{}, ErrInvalidCompoundResult
	}
	return claim, parent, joined, nil
}

// NewGovernancePolicyFinalHandler applies one commit-ready policy transition
// or Abort. Non-legacy plans close the retained kind-7 collection to the same
// durable result digest; a legacy Abort has no canonical pending row to infer.
func NewGovernancePolicyFinalHandler(plan governance.MutationPlan) (ccse.ReplayHandler, error) {
	view := plan.Snapshot()
	if view.Kind < governance.MutationPolicyPublish || view.Kind > governance.MutationPolicyAbort {
		return nil, ErrInvalidCompoundResult
	}
	return newGovernanceAuditedFinalHandler(plan)
}

// NewGovernanceAuditAppendHandler is the standalone immutable AuditEvent
// append path. It has no policy-state or durable-pending mutation.
func NewGovernanceAuditAppendHandler(plan governance.MutationPlan) (ccse.ReplayHandler, error) {
	if plan.Snapshot().Kind != governance.MutationAuditAppend {
		return nil, ErrInvalidCompoundResult
	}
	return newGovernanceAuditedFinalHandler(plan)
}

func newGovernanceAuditedFinalHandler(plan governance.MutationPlan) (ccse.ReplayHandler, error) {
	if !plan.CommitReady() || plan.VerifyDigest() != nil {
		return nil, ErrInvalidCompoundResult
	}
	view := plan.Snapshot()
	policyMutation := view.Kind >= governance.MutationPolicyPublish && view.Kind <= governance.MutationPolicyExpire
	policyAbort := view.Kind == governance.MutationPolicyAbort
	auditOnly := view.Kind == governance.MutationAuditAppend
	pendingPresent := view.DurablePolicyApprovalTerminalTemplate.BaseDigest() != ([ccse.DigestSize]byte{})
	if (!policyMutation && !policyAbort && !auditOnly) ||
		len(view.CanonicalStateAssertions) == 0 || len(view.CanonicalKeyStateAssertions) == 0 ||
		view.CanonicalAuditWriterLeaseAssertion.VerifyDigest() != nil ||
		(policyMutation != (len(view.CanonicalStateMutations) == 1)) ||
		len(view.IdempotencyClaims) == 0 ||
		len(view.IdentifierClaims) == 0 || len(view.AuditSourceStorageCapabilities) == 0 ||
		view.CanonicalAuditAppend.VerifyDigest() != nil ||
		(pendingPresent && (view.DurablePolicyApprovalTerminalTemplate.VerifyDigest() != nil ||
			view.DurablePolicyApprovalTerminalTemplate.ExpectedAuditEventID() != view.AuditEventID)) ||
		((policyMutation || policyAbort) && !pendingPresent) || (auditOnly && pendingPresent) ||
		view.CommitNotBeforeUnixNano > view.EvaluatedAtUnixNano ||
		view.CommitNotAfterUnixNano <= view.EvaluatedAtUnixNano {
		return nil, ErrInvalidCompoundResult
	}
	stateAssertions := len(view.CanonicalStateAssertions) + 3*len(view.CanonicalKeyStateAssertions) + 1
	if stateAssertions > postgres.MaxCanonicalStateAssertions ||
		len(view.CanonicalStateMutations) > postgres.MaxCanonicalStateMutations ||
		len(view.AuditSourceStorageCapabilities) > int(^uint16(0)) {
		return nil, ErrInvalidCompoundResult
	}
	for _, capability := range view.AuditSourceStorageCapabilities {
		if capability.VerifyDigest() != nil || capability.AuditAssertionEventID() != view.AuditEventID {
			return nil, ErrInvalidCompoundResult
		}
	}

	return func(ctx context.Context, outer ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
		if !exactGovernanceOuter(outer, view.AuditEventEvidence) {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		uow, err := postgres.OpenCanonicalUOW(ctx, outer, postgres.CanonicalAuditedFinal,
			view.AuditEventID, uint16(len(view.AuditSourceStorageCapabilities)))
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		result, err := buildGovernanceAuditedFinalResult(ctx, uow, plan, outer)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		var terminal governance.DurablePendingRevisionCapability
		if pendingPresent {
			terminal, err = view.DurablePolicyApprovalTerminalTemplate.Finalize(result.Digest())
			if err != nil {
				return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
			}
		}
		policyProjection, projectionErr := governance.BuildPolicyRegistrySemanticProjectionV2(plan,
			result.Digest())
		if projectionErr != nil {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		if preflightGovernanceFinalWriteBudget(view, terminal, pendingPresent,
			policyProjection) != nil {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		if pendingPresent {
			if err := assertGovernancePendingSource(ctx, uow, terminal); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
		}
		if err := applyGovernanceStateAssertions(ctx, uow, view.CanonicalStateAssertions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceKeyStateAssertions(ctx, uow, view.CanonicalKeyStateAssertions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceAuditWriterLeaseAssertion(ctx, uow,
			view.CanonicalAuditWriterLeaseAssertion); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if len(view.CanonicalStateMutations) != 0 {
			if err := applyGovernanceStateMutations(ctx, uow, view.CanonicalStateMutations,
				policyProjection); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
		}
		if err := uow.ApplyBusinessIdempotency(ctx, postgres.BusinessIdempotencyMutation{
			ExpectedAuditEventID: view.AuditEventID, OutcomeDigest: result.Digest(),
			Claims: view.IdempotencyClaims,
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.ApplyGlobalClaims(ctx, postgres.GlobalClaimMutation{
			AuditEventID: view.AuditEventID, Claims: view.IdentifierClaims,
		}); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceEvidence(ctx, uow, view.AuditEventID,
			view.AuditSourceStorageCapabilities); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if pendingPresent {
			if err := applyGovernancePendingRevision(ctx, uow, terminal); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
		}
		audit, err := mapCanonicalAuditAppend(view.CanonicalAuditAppend)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AppendAuditEvent(ctx, audit); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AssertCommitDeadline(ctx, view.CommitNotAfterUnixNano); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		transaction, ok := postgres.Transaction(ctx)
		if !ok {
			return [ccse.DigestSize]byte{}, ErrTransactionBoundaryRequired
		}
		completion, err := result.Completion()
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		digest, err := transaction.Complete(ctx, completion)
		if err != nil || digest != result.Digest() {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		return digest, nil
	}, nil
}

func assertGovernancePendingSource(ctx context.Context, uow *postgres.CanonicalUOW,
	value governance.DurablePendingRevisionCapability) error {
	if uow == nil || value.VerifyDigest() != nil || value.Revision() < 2 ||
		value.ExpectedKind() != governance.DurablePendingGovernancePolicyApprovalCollection {
		return ErrInvalidCompoundResult
	}
	previousPrevious, digestPresent := value.SourcePreviousEnvelopeDigest()
	evidence, evidencePresent := value.SourceEvidenceDigests()
	previousNotBefore, previousNotAfter := value.PreviousCommitWindow()
	if !digestPresent || !evidencePresent || len(evidence) == 0 {
		return ErrInvalidCompoundResult
	}
	expected := postgres.DurablePendingRevision{
		PendingKey: value.PendingKey(), Kind: postgres.DurablePendingGovernancePolicyApprovalCollection,
		Codec: value.Codec(), CodecVersion: value.CodecVersion(), Revision: value.Revision() - 1,
		PreviousEnvelopeDigest: previousPrevious, EnvelopeDigest: value.PreviousEnvelopeDigest(),
		CanonicalEnvelope: value.PreviousCanonicalEnvelope(), EvidenceDigests: evidence,
		Status: postgres.DurablePendingOpen, CommitNotBeforeUnixNano: previousNotBefore,
		CommitNotAfterUnixNano: previousNotAfter, ExpectedAuditEventID: value.ExpectedAuditEventID(),
	}
	return uow.AssertDurablePendingOpen(ctx, expected)
}

func buildGovernanceAdmissionResult(ctx context.Context, uow *postgres.CanonicalUOW,
	plan governance.ApprovalCollectionPlan, outer ccse.VerifiedRecord) (GovernanceResult, error) {
	view := plan.Snapshot()
	if uow == nil || plan.VerifyDigest() != nil || !exactGovernanceOuter(outer, view.NextEvidence) {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	if err := uow.AssertOuterVerifiedRecord(ctx, outer); err != nil {
		return GovernanceResult{}, err
	}
	clock, err := uow.SnapshotTransactionClock(ctx)
	if err != nil {
		return GovernanceResult{}, err
	}
	result, err := newGovernanceResult(GovernanceApprovalAdmissionResultContentType,
		governanceResultProjection{phase: governanceResultAdmission, planDigest: plan.Digest(),
			pendingCapabilityDigest: view.DurablePendingRevision.Digest(),
			outerRecordDigest:       outer.Digest(), outerPayloadDigest: outer.Envelope().PayloadDigest,
			evaluatedAtUnixNano:     view.EvaluatedAtUnixNano,
			commitNotBeforeUnixNano: view.CommitNotBeforeUnixNano,
			commitNotAfterUnixNano:  view.CommitNotAfterUnixNano,
			transactionID:           clock.TransactionID(), transactionObservedAtNano: clock.ObservedAtUnixNano()})
	if err != nil {
		return GovernanceResult{}, err
	}
	receipt, err := postgres.NewAdmissionUOWReceipt(result.ContentType(), result.Payload())
	if err != nil || receipt.ResultDigest() != result.Digest() {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		return GovernanceResult{}, err
	}
	return result, nil
}

func buildGovernanceAuditedFinalResult(ctx context.Context, uow *postgres.CanonicalUOW,
	plan governance.MutationPlan, outer ccse.VerifiedRecord) (GovernanceResult, error) {
	view := plan.Snapshot()
	if uow == nil || plan.VerifyDigest() != nil || !exactGovernanceOuter(outer, view.AuditEventEvidence) {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	if err := uow.AssertOuterVerifiedRecord(ctx, outer); err != nil {
		return GovernanceResult{}, err
	}
	clock, err := uow.SnapshotTransactionClock(ctx)
	if err != nil {
		return GovernanceResult{}, err
	}
	phase, contentType := governanceResultFinal, GovernancePolicyFinalResultContentType
	if view.Kind == governance.MutationAuditAppend {
		phase, contentType = governanceResultAudit, GovernanceAuditAppendResultContentType
	}
	result, err := newGovernanceResult(contentType,
		governanceResultProjection{phase: phase, planDigest: plan.Digest(),
			pendingCapabilityDigest: view.DurablePolicyApprovalTerminalTemplate.BaseDigest(),
			auditAppendDigest:       view.CanonicalAuditAppend.Digest(), outerRecordDigest: outer.Digest(),
			outerPayloadDigest: outer.Envelope().PayloadDigest, eventID: view.AuditEventID,
			operationKind: uint32(view.Kind), evaluatedAtUnixNano: view.EvaluatedAtUnixNano,
			commitNotBeforeUnixNano: view.CommitNotBeforeUnixNano,
			commitNotAfterUnixNano:  view.CommitNotAfterUnixNano,
			transactionID:           clock.TransactionID(), transactionObservedAtNano: clock.ObservedAtUnixNano()})
	if err != nil {
		return GovernanceResult{}, err
	}
	receipt, err := postgres.NewAuditedFinalUOWReceipt(result.ContentType(), result.Payload(),
		view.AuditEventID, uint16(len(view.AuditSourceStorageCapabilities)))
	if err != nil || receipt.ResultDigest() != result.Digest() {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	if err := uow.BindResult(ctx, receipt); err != nil {
		return GovernanceResult{}, err
	}
	return result, nil
}

func applyGovernanceAdmissionEvidence(ctx context.Context, uow *postgres.CanonicalUOW,
	value governance.DurableEvidenceStorageCapability) error {
	if uow == nil || value.VerifyDigest() != nil ||
		value.Disposition() != governance.DurableEvidenceStorageReserveNew {
		return ErrInvalidCompoundResult
	}
	record, assertion, _, err := mapGovernanceEvidence(value)
	if err != nil || assertion.HasPending {
		return ErrInvalidCompoundResult
	}
	return uow.ReserveDurableEvidence(ctx, record)
}

func applyGovernanceStateMutations(ctx context.Context, uow *postgres.CanonicalUOW,
	values []governance.CanonicalStateMutation,
	projection governance.SemanticProjectionV2) error {
	if uow == nil || len(values) == 0 || len(values) > postgres.MaxCanonicalStateMutations {
		return ErrInvalidCompoundResult
	}
	mutations := make([]postgres.CanonicalStateMutation, len(values))
	for index, value := range values {
		mapped, err := mapGovernanceStateMutation(value)
		if err != nil {
			return err
		}
		mutations[index] = mapped
	}
	if projection.Codec != postgres.SemanticProjectionCodecGovernancePolicyV2 ||
		projection.Digest() == ([sha256.Size]byte{}) {
		return ErrInvalidCompoundResult
	}
	var projectionState *postgres.CanonicalStateRecord
	for index := range mutations {
		next := &mutations[index].Next
		if string(next.Kind) == projection.Kind && next.ObjectID == projection.ObjectID &&
			next.Version == projection.Version && next.StateDigest == projection.StateDigestSHA256 {
			if projectionState != nil {
				return ErrInvalidCompoundResult
			}
			projectionState = next
		}
	}
	if projectionState == nil {
		return ErrInvalidCompoundResult
	}
	if err := uow.ApplyCanonicalStates(ctx, mutations); err != nil {
		return err
	}
	return uow.AttachSemanticProjection(ctx, postgres.SemanticProjectionRecord{State: *projectionState,
		Codec: projection.Codec, ProjectionDigest: projection.Digest(),
		CanonicalProjection: projection.Bytes()})
}

func preflightGovernanceFinalWriteBudget(view governance.MutationPlanSnapshot,
	terminal governance.DurablePendingRevisionCapability, pendingPresent bool,
	projection governance.SemanticProjectionV2) error {
	var total uint64
	if projection.Codec != postgres.SemanticProjectionCodecGovernancePolicyV2 ||
		projection.Digest() == ([sha256.Size]byte{}) ||
		addCanonicalWriteBytes(&total, len(projection.Bytes())) != nil {
		return ErrInvalidCompoundResult
	}
	for _, mutation := range view.CanonicalStateMutations {
		if mutation.VerifyDigest() != nil ||
			addCanonicalWriteBytes(&total, len(mutation.Next().CanonicalState)) != nil {
			return ErrInvalidCompoundResult
		}
	}
	for _, capability := range view.AuditSourceStorageCapabilities {
		if capability.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		if capability.Disposition() == governance.DurableEvidenceStorageReserveNew &&
			addCanonicalWriteBytes(&total, len(capability.CanonicalContent())) != nil {
			return ErrInvalidCompoundResult
		}
	}
	if pendingPresent {
		if terminal.VerifyDigest() != nil ||
			addCanonicalWriteBytes(&total, len(terminal.CanonicalEnvelope())) != nil {
			return ErrInvalidCompoundResult
		}
	}
	return nil
}
