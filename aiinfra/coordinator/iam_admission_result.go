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
	IAMAdmissionResultContentType = "application/vnd.cph.aiinfra.iam.pending-admission-result.v1+ccse"
	iamAdmissionResultVersion     = uint32(1)
)

type iamAdmissionResultProjection struct {
	kind                      iam.DurablePendingKind
	pendingDigest             [sha256.Size]byte
	envelopeDigest            [sha256.Size]byte
	capabilityDigest          [sha256.Size]byte
	stateReadDigest           [sha256.Size]byte
	revisionDigest            [sha256.Size]byte
	outerRecordDigest         [sha256.Size]byte
	outerPayloadDigest        [sha256.Size]byte
	auditEventID              string
	commitNotBeforeUnixNano   int64
	commitNotAfterUnixNano    int64
	transactionID             string
	transactionObservedAtNano int64
}

type IAMAdmissionResult struct {
	result replayresult.Result
	value  iamAdmissionResultProjection
}

func (value IAMAdmissionResult) Digest() [sha256.Size]byte { return value.result.Digest() }
func (value IAMAdmissionResult) ContentType() string       { return value.result.ContentType() }
func (value IAMAdmissionResult) Payload() []byte           { return value.result.Payload() }
func (value IAMAdmissionResult) Verify() error {
	if value.result.Verify() != nil || value.result.ContentType() != IAMAdmissionResultContentType {
		return ErrInvalidCompoundResult
	}
	encoded, err := encodeIAMAdmissionResult(value.value)
	if err != nil || !bytes.Equal(encoded, value.result.Payload()) {
		return ErrInvalidCompoundResult
	}
	return nil
}
func (value IAMAdmissionResult) Completion() (postgres.DurableCompletion, error) {
	if value.Verify() != nil {
		return postgres.DurableCompletion{}, ErrInvalidCompoundResult
	}
	return postgres.DurableCompletion{ContentType: value.ContentType(), Payload: value.Payload(),
		ExternalEffects: postgres.NoExternalEffects}, nil
}

type IAMAdmissionResultSnapshot struct {
	value        iamAdmissionResultProjection
	resultDigest [sha256.Size]byte
}

func (value IAMAdmissionResultSnapshot) Kind() iam.DurablePendingKind { return value.value.kind }
func (value IAMAdmissionResultSnapshot) PendingDigest() [sha256.Size]byte {
	return value.value.pendingDigest
}
func (value IAMAdmissionResultSnapshot) DurableEnvelopeDigest() [sha256.Size]byte {
	return value.value.envelopeDigest
}
func (value IAMAdmissionResultSnapshot) CapabilityDigest() [sha256.Size]byte {
	return value.value.capabilityDigest
}
func (value IAMAdmissionResultSnapshot) TransactionID() string { return value.value.transactionID }
func (value IAMAdmissionResultSnapshot) TransactionObservedAtUnixNano() int64 {
	return value.value.transactionObservedAtNano
}
func (value IAMAdmissionResultSnapshot) ResultDigest() [sha256.Size]byte { return value.resultDigest }

func DecodeIAMAdmissionResult(result replayresult.Result) (IAMAdmissionResultSnapshot, error) {
	if result.Verify() != nil || result.ContentType() != IAMAdmissionResultContentType {
		return IAMAdmissionResultSnapshot{}, ErrInvalidCompoundResult
	}
	value, err := decodeIAMAdmissionResult(result.Payload())
	if err != nil {
		return IAMAdmissionResultSnapshot{}, err
	}
	return IAMAdmissionResultSnapshot{value: value, resultDigest: result.Digest()}, nil
}

func newIAMAdmissionResult(value iamAdmissionResultProjection) (IAMAdmissionResult, error) {
	payload, err := encodeIAMAdmissionResult(value)
	if err != nil {
		return IAMAdmissionResult{}, err
	}
	result, err := replayresult.New(IAMAdmissionResultContentType, payload)
	if err != nil {
		return IAMAdmissionResult{}, ErrInvalidCompoundResult
	}
	wrapped := IAMAdmissionResult{result: result, value: value}
	if wrapped.Verify() != nil {
		return IAMAdmissionResult{}, ErrInvalidCompoundResult
	}
	return wrapped, nil
}

func encodeIAMAdmissionResult(value iamAdmissionResultProjection) ([]byte, error) {
	if value.kind < iam.DurablePendingMutation || value.kind > iam.DurablePendingOwnershipTransferCollection ||
		value.pendingDigest == ([sha256.Size]byte{}) || value.envelopeDigest == ([sha256.Size]byte{}) ||
		value.capabilityDigest == ([sha256.Size]byte{}) || value.stateReadDigest == ([sha256.Size]byte{}) ||
		value.revisionDigest == ([sha256.Size]byte{}) || value.outerRecordDigest == ([sha256.Size]byte{}) ||
		value.outerPayloadDigest == ([sha256.Size]byte{}) || value.auditEventID == "" ||
		value.commitNotBeforeUnixNano <= 0 || value.commitNotAfterUnixNano <= value.commitNotBeforeUnixNano ||
		!validTransactionID(value.transactionID) ||
		value.transactionObservedAtNano < value.commitNotBeforeUnixNano ||
		value.transactionObservedAtNano >= value.commitNotAfterUnixNano {
		return nil, ErrInvalidCompoundResult
	}
	return ccse.Marshal(4096, func(out *ccse.Encoder) {
		out.Uint32(iamAdmissionResultVersion)
		out.Uint32(uint32(value.kind))
		for _, digest := range [][sha256.Size]byte{value.pendingDigest, value.envelopeDigest,
			value.capabilityDigest, value.stateReadDigest, value.revisionDigest,
			value.outerRecordDigest, value.outerPayloadDigest} {
			out.FixedBytes(digest[:], sha256.Size)
		}
		out.String(value.auditEventID)
		out.Int64(value.commitNotBeforeUnixNano)
		out.Int64(value.commitNotAfterUnixNano)
		out.String(value.transactionID)
		out.Int64(value.transactionObservedAtNano)
	})
}

func decodeIAMAdmissionResult(input []byte) (iamAdmissionResultProjection, error) {
	var value iamAdmissionResultProjection
	err := ccse.Unmarshal(input, 4096, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != iamAdmissionResultVersion {
			return ErrInvalidCompoundResult
		}
		kind, err := in.Uint32()
		if err != nil {
			return ErrInvalidCompoundResult
		}
		value.kind = iam.DurablePendingKind(kind)
		for _, target := range []*[sha256.Size]byte{&value.pendingDigest, &value.envelopeDigest,
			&value.capabilityDigest, &value.stateReadDigest, &value.revisionDigest,
			&value.outerRecordDigest, &value.outerPayloadDigest} {
			encoded, decodeErr := in.FixedBytes(sha256.Size)
			if decodeErr != nil {
				return ErrInvalidCompoundResult
			}
			copy(target[:], encoded)
		}
		if value.auditEventID, err = in.String(1024); err != nil {
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
		value.transactionObservedAtNano, err = in.Int64()
		return err
	})
	if err != nil {
		return iamAdmissionResultProjection{}, ErrInvalidCompoundResult
	}
	canonical, err := encodeIAMAdmissionResult(value)
	if err != nil || !bytes.Equal(canonical, input) {
		return iamAdmissionResultProjection{}, ErrInvalidCompoundResult
	}
	return value, nil
}
