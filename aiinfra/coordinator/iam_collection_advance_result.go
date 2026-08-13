// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"crypto/sha256"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/replayresult"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

const (
	IAMCollectionAdvanceResultContentType = "application/vnd.cph.aiinfra.iam.collection-advance-result.v1+ccse"
	iamCollectionAdvanceResultVersion     = uint32(1)
)

type iamCollectionAdvanceResultProjection struct {
	pendingDigest                   [sha256.Size]byte
	envelopeDigest                  [sha256.Size]byte
	capabilityDigest                [sha256.Size]byte
	stateReadDigest                 [sha256.Size]byte
	nextRevisionDigest              [sha256.Size]byte
	sourceEnvelopeDigest            [sha256.Size]byte
	outerRecordDigest               [sha256.Size]byte
	outerPayloadDigest              [sha256.Size]byte
	auditEventID                    string
	sourceRevision                  uint64
	nextRevision                    uint64
	previousCommitNotBeforeUnixNano int64
	previousCommitNotAfterUnixNano  int64
	commitNotBeforeUnixNano         int64
	commitNotAfterUnixNano          int64
	transactionID                   string
	transactionObservedAtUnixNano   int64
}

// IAMCollectionAdvanceResult is the exact durable replay result for one
// predecessor-bound kind-3 OPEN revision advance. It is intentionally
// distinct from first admission so duplicate restore cannot reinterpret an
// update as an absent-row insertion.
type IAMCollectionAdvanceResult struct {
	result replayresult.Result
	value  iamCollectionAdvanceResultProjection
}

func (value IAMCollectionAdvanceResult) Digest() [sha256.Size]byte { return value.result.Digest() }
func (value IAMCollectionAdvanceResult) ContentType() string       { return value.result.ContentType() }
func (value IAMCollectionAdvanceResult) Payload() []byte           { return value.result.Payload() }
func (value IAMCollectionAdvanceResult) Verify() error {
	if value.result.Verify() != nil || value.result.ContentType() != IAMCollectionAdvanceResultContentType {
		return ErrInvalidCompoundResult
	}
	encoded, err := encodeIAMCollectionAdvanceResult(value.value)
	if err != nil || !bytes.Equal(encoded, value.result.Payload()) {
		return ErrInvalidCompoundResult
	}
	return nil
}
func (value IAMCollectionAdvanceResult) Completion() (postgres.DurableCompletion, error) {
	if value.Verify() != nil {
		return postgres.DurableCompletion{}, ErrInvalidCompoundResult
	}
	return postgres.DurableCompletion{ContentType: value.ContentType(), Payload: value.Payload(),
		ExternalEffects: postgres.NoExternalEffects}, nil
}

// IAMCollectionAdvanceResultSnapshot is inert duplicate/restore evidence. It
// never recreates a pending or idempotency write capability.
type IAMCollectionAdvanceResultSnapshot struct {
	value        iamCollectionAdvanceResultProjection
	resultDigest [sha256.Size]byte
}

func (value IAMCollectionAdvanceResultSnapshot) PendingDigest() [sha256.Size]byte {
	return value.value.pendingDigest
}
func (value IAMCollectionAdvanceResultSnapshot) DurableEnvelopeDigest() [sha256.Size]byte {
	return value.value.envelopeDigest
}
func (value IAMCollectionAdvanceResultSnapshot) CapabilityDigest() [sha256.Size]byte {
	return value.value.capabilityDigest
}
func (value IAMCollectionAdvanceResultSnapshot) SourceRevision() uint64 {
	return value.value.sourceRevision
}
func (value IAMCollectionAdvanceResultSnapshot) NextRevision() uint64 {
	return value.value.nextRevision
}
func (value IAMCollectionAdvanceResultSnapshot) TransactionID() string {
	return value.value.transactionID
}
func (value IAMCollectionAdvanceResultSnapshot) TransactionObservedAtUnixNano() int64 {
	return value.value.transactionObservedAtUnixNano
}
func (value IAMCollectionAdvanceResultSnapshot) ResultDigest() [sha256.Size]byte {
	return value.resultDigest
}

func DecodeIAMCollectionAdvanceResult(result replayresult.Result) (IAMCollectionAdvanceResultSnapshot, error) {
	if result.Verify() != nil || result.ContentType() != IAMCollectionAdvanceResultContentType {
		return IAMCollectionAdvanceResultSnapshot{}, ErrInvalidCompoundResult
	}
	value, err := decodeIAMCollectionAdvanceResult(result.Payload())
	if err != nil {
		return IAMCollectionAdvanceResultSnapshot{}, err
	}
	return IAMCollectionAdvanceResultSnapshot{value: value, resultDigest: result.Digest()}, nil
}

func newIAMCollectionAdvanceResult(value iamCollectionAdvanceResultProjection) (IAMCollectionAdvanceResult, error) {
	payload, err := encodeIAMCollectionAdvanceResult(value)
	if err != nil {
		return IAMCollectionAdvanceResult{}, err
	}
	result, err := replayresult.New(IAMCollectionAdvanceResultContentType, payload)
	if err != nil {
		return IAMCollectionAdvanceResult{}, ErrInvalidCompoundResult
	}
	wrapper := IAMCollectionAdvanceResult{result: result, value: value}
	if wrapper.Verify() != nil {
		return IAMCollectionAdvanceResult{}, ErrInvalidCompoundResult
	}
	return wrapper, nil
}

func encodeIAMCollectionAdvanceResult(value iamCollectionAdvanceResultProjection) ([]byte, error) {
	if value.pendingDigest == ([sha256.Size]byte{}) || value.envelopeDigest == ([sha256.Size]byte{}) ||
		value.capabilityDigest == ([sha256.Size]byte{}) || value.stateReadDigest == ([sha256.Size]byte{}) ||
		value.nextRevisionDigest == ([sha256.Size]byte{}) || value.sourceEnvelopeDigest == ([sha256.Size]byte{}) ||
		value.outerRecordDigest == ([sha256.Size]byte{}) || value.outerPayloadDigest == ([sha256.Size]byte{}) ||
		value.auditEventID == "" || value.sourceRevision == 0 || value.nextRevision != value.sourceRevision+1 ||
		value.previousCommitNotBeforeUnixNano <= 0 ||
		value.previousCommitNotAfterUnixNano < value.previousCommitNotBeforeUnixNano ||
		value.commitNotBeforeUnixNano <= 0 || value.commitNotAfterUnixNano <= value.commitNotBeforeUnixNano ||
		!validTransactionID(value.transactionID) ||
		value.transactionObservedAtUnixNano < value.commitNotBeforeUnixNano ||
		value.transactionObservedAtUnixNano >= value.commitNotAfterUnixNano {
		return nil, ErrInvalidCompoundResult
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.Uint32(iamCollectionAdvanceResultVersion)
		out.Uint32(uint32(iam.DurablePendingOwnershipTransferCollection))
		for _, digest := range [][sha256.Size]byte{value.pendingDigest, value.envelopeDigest,
			value.capabilityDigest, value.stateReadDigest, value.nextRevisionDigest,
			value.sourceEnvelopeDigest, value.outerRecordDigest, value.outerPayloadDigest} {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.String(value.auditEventID)
		out.Uint64(value.sourceRevision)
		out.Uint64(value.nextRevision)
		out.Int64(value.previousCommitNotBeforeUnixNano)
		out.Int64(value.previousCommitNotAfterUnixNano)
		out.Int64(value.commitNotBeforeUnixNano)
		out.Int64(value.commitNotAfterUnixNano)
		out.String(value.transactionID)
		out.Int64(value.transactionObservedAtUnixNano)
	})
}

func decodeIAMCollectionAdvanceResult(input []byte) (iamCollectionAdvanceResultProjection, error) {
	var value iamCollectionAdvanceResultProjection
	err := ccse.Unmarshal(input, 4096, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != iamCollectionAdvanceResultVersion {
			return ErrInvalidCompoundResult
		}
		kind, err := in.Uint32()
		if err != nil || iam.DurablePendingKind(kind) != iam.DurablePendingOwnershipTransferCollection {
			return ErrInvalidCompoundResult
		}
		for _, target := range []*[sha256.Size]byte{&value.pendingDigest, &value.envelopeDigest,
			&value.capabilityDigest, &value.stateReadDigest, &value.nextRevisionDigest,
			&value.sourceEnvelopeDigest, &value.outerRecordDigest, &value.outerPayloadDigest} {
			encoded, decodeErr := in.FixedBytes(sha256.Size)
			if decodeErr != nil {
				return ErrInvalidCompoundResult
			}
			copy(target[:], encoded)
		}
		if value.auditEventID, err = in.String(1024); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.sourceRevision, err = in.Uint64(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.nextRevision, err = in.Uint64(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.previousCommitNotBeforeUnixNano, err = in.Int64(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.previousCommitNotAfterUnixNano, err = in.Int64(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.commitNotBeforeUnixNano, err = in.Int64(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.commitNotAfterUnixNano, err = in.Int64(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.transactionID, err = in.String(20); err != nil {
			return ErrInvalidCompoundResult
		}
		value.transactionObservedAtUnixNano, err = in.Int64()
		return err
	})
	if err != nil {
		return iamCollectionAdvanceResultProjection{}, ErrInvalidCompoundResult
	}
	canonical, err := encodeIAMCollectionAdvanceResult(value)
	if err != nil || !bytes.Equal(canonical, input) {
		return iamCollectionAdvanceResultProjection{}, ErrInvalidCompoundResult
	}
	return value, nil
}
