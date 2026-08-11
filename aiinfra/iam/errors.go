// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"errors"

	"github.com/cypherium/cypher/aiinfra/idempotency"
)

var (
	ErrInvalidInput                  = errors.New("aiinfra iam: invalid input")
	ErrUnsupportedAlgorithm          = errors.New("aiinfra iam: unsupported signature algorithm")
	ErrKeyIDMismatch                 = errors.New("aiinfra iam: content-addressed key identifier mismatch")
	ErrInvalidProofOfPossession      = errors.New("aiinfra iam: invalid proof of possession")
	ErrAuthorizationMismatch         = errors.New("aiinfra iam: verified authorization does not bind the semantic command")
	ErrProofChallengeUnknown         = errors.New("aiinfra iam: proof challenge is unknown")
	ErrProofChallengeConsumed        = errors.New("aiinfra iam: proof challenge was already consumed")
	ErrProofChallengeExpired         = errors.New("aiinfra iam: proof challenge is expired")
	ErrKeyMaterialExists             = errors.New("aiinfra iam: key material identifier is already registered")
	ErrKeyMaterialUnknown            = errors.New("aiinfra iam: key material is unknown")
	ErrKeyMaterialMismatch           = errors.New("aiinfra iam: key material binding mismatch")
	ErrIdentityUnknown               = errors.New("aiinfra iam: identity is unknown")
	ErrIdentityConflict              = errors.New("aiinfra iam: identity reference conflicts with stored state")
	ErrTerminalIdentity              = errors.New("aiinfra iam: terminal identity cannot transition")
	ErrLifecycleUnknown              = errors.New("aiinfra iam: key lifecycle is unknown")
	ErrLifecycleExists               = errors.New("aiinfra iam: key lifecycle already exists")
	ErrInvalidTransition             = errors.New("aiinfra iam: invalid lifecycle transition")
	ErrTerminalLifecycle             = errors.New("aiinfra iam: terminal key lifecycle cannot transition")
	ErrInvalidPredecessor            = errors.New("aiinfra iam: invalid rotation predecessor")
	ErrPredecessorCycle              = errors.New("aiinfra iam: rotation predecessor cycle")
	ErrUnknownMessageType            = errors.New("aiinfra iam: allowed message type is not registered")
	ErrStateVersionConflict          = errors.New("aiinfra iam: state version is not the exact successor")
	ErrWriterFenceUnknown            = errors.New("aiinfra iam: writer fence evidence is unknown")
	ErrWriterFenceMismatch           = errors.New("aiinfra iam: writer fence evidence mismatch")
	ErrWriterFenceExpired            = errors.New("aiinfra iam: writer fence is not active")
	ErrViewRequired                  = errors.New("aiinfra iam: read-only view is required")
	ErrProfileRequired               = errors.New("aiinfra iam: policy profile is required")
	ErrViewInconsistent              = errors.New("aiinfra iam: read-only view returned inconsistent state")
	ErrLookupLimit                   = errors.New("aiinfra iam: predecessor lookup limit exceeded")
	ErrInvalidCommitWindow           = errors.New("aiinfra iam: invalid or expired commit window")
	ErrPendingPlanInvalid            = errors.New("aiinfra iam: pending mutation plan is invalid")
	ErrGlobalIdentifier              = errors.New("aiinfra iam: global identifier registry conflict")
	ErrIdempotencyInProgress         = errors.New("aiinfra iam: business mutation is already collecting")
	ErrIdempotencyCompleted          = errors.New("aiinfra iam: business mutation already completed")
	ErrTransferAuthorizationRequired = errors.New("aiinfra iam: signed ownership-transfer authorization is required")
	ErrTransferApprovalDuplicate     = errors.New("aiinfra iam: ownership-transfer approval is already collected")
	ErrTransferCollectionMismatch    = errors.New("aiinfra iam: ownership-transfer approval collection is inconsistent")
)

// IdempotencyCompletedError returns the durable outcome without re-running
// semantic planning against state advanced by the original mutation.
type IdempotencyCompletedError struct{ Outcome [32]byte }

func (err IdempotencyCompletedError) Error() string           { return ErrIdempotencyCompleted.Error() }
func (err IdempotencyCompletedError) Unwrap() error           { return ErrIdempotencyCompleted }
func (err IdempotencyCompletedError) OutcomeDigest() [32]byte { return err.Outcome }

// IdempotencyCollectingError directs the WS0.2b coordinator to reload the
// durable pending plan and signed evidence associated with this exact atomic
// parent/audit pair. The semantic planner must not be run against advanced
// state while the pair is COLLECTING.
type IdempotencyCollectingError struct {
	Parent             idempotency.Snapshot
	Audit              idempotency.Snapshot
	JoinedAuditEventID string
}

func (err IdempotencyCollectingError) Error() string { return ErrIdempotencyInProgress.Error() }
func (err IdempotencyCollectingError) Unwrap() error { return ErrIdempotencyInProgress }
func (err IdempotencyCollectingError) ParentSnapshot() idempotency.Snapshot {
	return err.Parent
}
func (err IdempotencyCollectingError) AuditSnapshot() idempotency.Snapshot { return err.Audit }
func (err IdempotencyCollectingError) AuditEventID() string                { return err.JoinedAuditEventID }
