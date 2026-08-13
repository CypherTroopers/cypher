// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"context"
	"errors"

	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

var ErrTransactionBoundaryRequired = errors.New("aiinfra coordinator: transaction-bound view is required")

// TransactionBoundIAMStateView is the trusted application adapter contract.
// Every IAM lookup must use the same CanonicalUOW connection named by
// CanonicalTransactionBoundary; a cache, process-memory view, or a different
// database transaction does not satisfy this interface's semantic contract.
type TransactionBoundIAMStateView interface {
	iam.View
	iam.CanonicalIAMStateView
	iam.CanonicalIAMSidecarStateView
	iam.IAMPendingPersistenceView
	iam.IAMPendingAdmissionEvidenceView
	CanonicalTransactionBoundary() *postgres.CanonicalUOW
}

// TransactionBoundIAMView decorates an already transaction-bound IAM state
// adapter with the clock observation from that exact PostgreSQL SERIALIZABLE
// transaction. It does not make an arbitrary IAM View transaction-bound.
//
// A value is useful only inside the ReplayStore.Execute handler that owns UOW.
// SnapshotReconciliationTransactionClock fails closed after that context is
// sealed, poisoned, or used from another transaction.
type TransactionBoundIAMView struct {
	TransactionBoundIAMStateView
	uow *postgres.CanonicalUOW
}

func NewTransactionBoundIAMView(view TransactionBoundIAMStateView,
	uow *postgres.CanonicalUOW) (*TransactionBoundIAMView, error) {
	if view == nil || uow == nil || view.CanonicalTransactionBoundary() != uow {
		return nil, ErrTransactionBoundaryRequired
	}
	return &TransactionBoundIAMView{TransactionBoundIAMStateView: view, uow: uow}, nil
}

func (view *TransactionBoundIAMView) SnapshotReconciliationTransactionClock(ctx context.Context,
	pendingDigest [32]byte, originalDeadline int64) (iam.ReconciliationTransactionClockSnapshot, error) {
	if view == nil || view.TransactionBoundIAMStateView == nil || view.uow == nil ||
		view.TransactionBoundIAMStateView.CanonicalTransactionBoundary() != view.uow {
		return iam.ReconciliationTransactionClockSnapshot{}, ErrTransactionBoundaryRequired
	}
	clock, err := view.uow.SnapshotTransactionClock(ctx)
	if err != nil {
		return iam.ReconciliationTransactionClockSnapshot{}, err
	}
	return iam.NewReconciliationTransactionClockSnapshot(clock.TransactionID(),
		clock.ObservedAtUnixNano(), pendingDigest, originalDeadline)
}

var _ iam.View = (*TransactionBoundIAMView)(nil)
var _ iam.CanonicalIAMStateView = (*TransactionBoundIAMView)(nil)
var _ iam.CanonicalIAMSidecarStateView = (*TransactionBoundIAMView)(nil)
var _ iam.IAMPendingPersistenceView = (*TransactionBoundIAMView)(nil)
var _ iam.IAMPendingAdmissionEvidenceView = (*TransactionBoundIAMView)(nil)
var _ iam.ReconciliationTransactionClockView = (*TransactionBoundIAMView)(nil)
var _ TransactionBoundIAMStateView = (*postgres.ProductionSemanticAdapter)(nil)
