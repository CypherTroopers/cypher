// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"context"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

// NewAuditedFinalHandler closes the only production write path for one
// pre-signed IAM/Governance joined operation. The semantic capabilities are
// optimistic pre-sign snapshots: the returned ReplayHandler byte-compares and
// CAS-applies every one of them on the exact SERIALIZABLE transaction opened
// by verification of the outer signed AuditEvent.
//
// The handler performs no external effect. A caller installs it as the CCSE
// Verifier handler for that exact outer AuditEvent; ReplayStore owns commit and
// rollback. Missing persistence/state capabilities are rejected before a
// result can enable writes.
func NewAuditedFinalHandler(request iam.JoinedAuditRequest,
	fragment governance.JoinedAuditFragment) (ccse.ReplayHandler, error) {
	execution, ok := request.ExecutionFragment()
	if !ok || request.CommitReady() || fragment.CommitReady() || request.VerifyDigest() != nil ||
		execution.VerifyDigest() != nil || fragment.VerifyDigest() != nil ||
		requireStorageBoundRequest(request, execution) != nil {
		return nil, ErrInvalidCompoundResult
	}
	view := fragment.Snapshot()
	if view.JoinedAuditEventID != request.JoinedAuditEventID() ||
		len(view.AuditSourceStorageCapabilities) == 0 ||
		len(view.AuditSourceStorageCapabilities) > int(^uint16(0)) ||
		view.CanonicalAuditAppend.VerifyDigest() != nil ||
		view.CanonicalAuditWriterLeaseAssertion.VerifyDigest() != nil ||
		len(view.CanonicalStateAssertions) == 0 || len(view.CanonicalKeyStateAssertions) == 0 {
		return nil, ErrInvalidCompoundResult
	}
	stateAssertions := len(view.CanonicalStateAssertions) + 3*len(view.CanonicalKeyStateAssertions) + 1
	stateMutations := 0
	if state, present := request.CanonicalStateBundle(); present {
		stateAssertions += len(state.Assertions()) + len(state.Absences())
		stateMutations += len(state.Mutations())
	}
	if stateAssertions > postgres.MaxCanonicalStateAssertions ||
		stateMutations > postgres.MaxCanonicalStateMutations {
		return nil, ErrInvalidCompoundResult
	}
	for _, capability := range view.AuditSourceStorageCapabilities {
		if capability.VerifyDigest() != nil ||
			capability.AuditAssertionEventID() != request.JoinedAuditEventID() {
			return nil, ErrInvalidCompoundResult
		}
	}
	persistence, ok := request.PendingPersistenceCapability()
	if !ok || persistence.VerifyFor(request) != nil {
		return nil, ErrInvalidCompoundResult
	}
	terminalTemplate, err := persistence.TerminalTemplate(request)
	if err != nil || terminalTemplate.VerifyFor(request) != nil {
		return nil, ErrInvalidCompoundResult
	}
	if request.ExpectedOutcome() != 1 {
		if _, ok := request.FailureResult(); !ok {
			return nil, ErrInvalidCompoundResult
		}
	} else if _, ok := request.FailureResult(); ok {
		return nil, ErrInvalidCompoundResult
	}

	return func(ctx context.Context, outer ccse.VerifiedRecord) ([ccse.DigestSize]byte, error) {
		uow, err := postgres.OpenCanonicalUOW(ctx, outer, postgres.CanonicalAuditedFinal,
			request.JoinedAuditEventID(), uint16(len(view.AuditSourceStorageCapabilities)))
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		result, err := buildAuditedResult(ctx, uow, request, fragment, outer)
		if err != nil || result.VerifyFor(request, fragment, outer) != nil {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		revisions, err := terminalTemplate.Finalize(request, result.Digest())
		if err != nil || len(revisions) == 0 ||
			preflightAuditedFinalWriteBudget(request, execution, view, persistence, revisions) != nil {
			return [ccse.DigestSize]byte{}, ErrInvalidCompoundResult
		}
		if err := assertIAMPendingSource(ctx, uow, persistence); err != nil {
			return [ccse.DigestSize]byte{}, err
		}

		if err := applyGovernanceStateAssertions(ctx, uow, view.CanonicalStateAssertions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceKeyStateAssertions(ctx, uow,
			view.CanonicalKeyStateAssertions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceAuditWriterLeaseAssertion(ctx, uow,
			view.CanonicalAuditWriterLeaseAssertion); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if state, present := request.CanonicalStateBundle(); present {
			if err := assertIAMStateBundle(ctx, uow, state); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
			if err := applyIAMStateMutations(ctx, uow, state, execution); err != nil {
				return [ccse.DigestSize]byte{}, err
			}
		}
		if err := applyBusinessClaims(ctx, uow, request, execution, result.Digest()); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGlobalClaims(ctx, uow, request, execution); err != nil {
			return [ccse.DigestSize]byte{}, err
		}

		if err := applyIAMEvidenceStorage(ctx, uow, request.JoinedAuditEventID(), persistence); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyIAMPendingRevisions(ctx, uow, revisions); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := applyGovernanceEvidence(ctx, uow, request.JoinedAuditEventID(),
			view.AuditSourceStorageCapabilities); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		audit, err := mapCanonicalAuditAppend(view.CanonicalAuditAppend)
		if err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		if err := uow.AppendAuditEvent(ctx, audit); err != nil {
			return [ccse.DigestSize]byte{}, err
		}
		transaction, ok := postgres.Transaction(ctx)
		if !ok {
			return [ccse.DigestSize]byte{}, ErrTransactionBoundaryRequired
		}
		if err := uow.AssertCommitDeadline(ctx, view.CommitNotAfterUnixNano); err != nil {
			return [ccse.DigestSize]byte{}, err
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
