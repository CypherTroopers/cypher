// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

func TestAuditedFinalHandlerRejectsUnboundCapabilities(t *testing.T) {
	if _, err := NewAuditedFinalHandler(iam.JoinedAuditRequest{},
		governance.JoinedAuditFragment{}); !errors.Is(err, ErrInvalidCompoundResult) {
		t.Fatalf("unbound handler error = %v", err)
	}
}

func TestGovernanceCollectionAdvanceRequiresExactJoinedSnapshot(t *testing.T) {
	binding := idempotency.Binding{Key: [ccse.MessageIDSize]byte{1},
		Domain: idempotency.OperationGovernancePolicy, OwnerID: "policy-1",
		RequestDigest: [sha256.Size]byte{2}}
	parent := idempotency.Snapshot{Binding: binding, State: idempotency.StateCollecting,
		Version: 1, ProgressDigest: [sha256.Size]byte{3}}
	claim, err := idempotency.NewAdvanceCollection(parent, [sha256.Size]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	parentDigest, err := idempotency.BindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	joined := idempotency.Snapshot{Binding: joinedBinding, State: idempotency.StateCollecting,
		Version: 1, ProgressDigest: parentDigest}
	view := governance.ApprovalCollectionPlanSnapshot{Binding: binding, Claims: []idempotency.Claim{claim},
		JoinedAuditIdempotencySnapshot: joined}
	if _, actualParent, actualJoined, err := validateGovernanceCollectionAdvanceIdempotency(view); err != nil ||
		actualParent != parent || actualJoined != joined {
		t.Fatalf("exact pair parent=%+v joined=%+v err=%v", actualParent, actualJoined, err)
	}
	view.JoinedAuditIdempotencySnapshot.ProgressDigest[0] ^= 1
	if _, _, _, err := validateGovernanceCollectionAdvanceIdempotency(view); err == nil {
		t.Fatal("joined snapshot drift was accepted")
	}
}
