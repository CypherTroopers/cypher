// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"context"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/iam"
)

func TestTransactionBoundIAMViewRejectsMissingBoundary(t *testing.T) {
	if _, err := NewTransactionBoundIAMView(nil, nil); !errors.Is(err, ErrTransactionBoundaryRequired) {
		t.Fatalf("nil constructor error = %v", err)
	}
	var view *TransactionBoundIAMView
	if _, err := view.SnapshotReconciliationTransactionClock(context.Background(), [32]byte{1}, 1); !errors.Is(err, ErrTransactionBoundaryRequired) {
		t.Fatalf("nil view error = %v", err)
	}
	var _ iam.ReconciliationTransactionClockView = view
}
