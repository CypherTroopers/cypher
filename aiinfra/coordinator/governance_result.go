// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"crypto/sha256"
	"reflect"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/replayresult"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

const (
	GovernanceApprovalAdmissionResultContentType = "application/vnd.cph.aiinfra.governance.approval-admission-result.v1+ccse"
	GovernancePolicyFinalResultContentType       = "application/vnd.cph.aiinfra.governance.policy-final-result.v1+ccse"
	GovernanceAuditAppendResultContentType       = "application/vnd.cph.aiinfra.governance.audit-append-result.v1+ccse"

	governanceResultVersion   = uint32(1)
	governanceResultAdmission = uint32(1)
	governanceResultFinal     = uint32(2)
	governanceResultAudit     = uint32(3)
)

type governanceResultProjection struct {
	phase                     uint32
	planDigest                [sha256.Size]byte
	pendingCapabilityDigest   [sha256.Size]byte
	auditAppendDigest         [sha256.Size]byte
	outerRecordDigest         [sha256.Size]byte
	outerPayloadDigest        [sha256.Size]byte
	eventID                   string
	operationKind             uint32
	evaluatedAtUnixNano       int64
	commitNotBeforeUnixNano   int64
	commitNotAfterUnixNano    int64
	transactionID             string
	transactionObservedAtNano int64
}

// GovernanceResult is an immutable result bound to one exact Governance plan,
// outer signed record and PostgreSQL transaction clock.
type GovernanceResult struct {
	result     replayresult.Result
	projection governanceResultProjection
}

func (value GovernanceResult) Digest() [sha256.Size]byte { return value.result.Digest() }
func (value GovernanceResult) ContentType() string       { return value.result.ContentType() }
func (value GovernanceResult) Payload() []byte           { return value.result.Payload() }
func (value GovernanceResult) Completion() (postgres.DurableCompletion, error) {
	if value.Verify() != nil {
		return postgres.DurableCompletion{}, ErrInvalidCompoundResult
	}
	return postgres.DurableCompletion{ContentType: value.result.ContentType(),
		Payload: value.result.Payload(), ExternalEffects: postgres.NoExternalEffects}, nil
}
func (value GovernanceResult) Verify() error {
	if value.result.Verify() != nil {
		return ErrInvalidCompoundResult
	}
	payload, err := encodeGovernanceResult(value.projection)
	if err != nil || value.result.ContentType() != governanceResultContentType(value.projection.phase) ||
		!bytes.Equal(payload, value.result.Payload()) {
		return ErrInvalidCompoundResult
	}
	rebuilt, err := replayresult.New(value.result.ContentType(), payload)
	if err != nil || rebuilt.Digest() != value.result.Digest() {
		return ErrInvalidCompoundResult
	}
	return nil
}

// GovernanceResultSnapshot is inert duplicate/restore state. It cannot
// recreate an admission or audited-final write capability.
type GovernanceResultSnapshot struct {
	projection   governanceResultProjection
	resultDigest [sha256.Size]byte
}

func (value GovernanceResultSnapshot) PlanDigest() [sha256.Size]byte {
	return value.projection.planDigest
}
func (value GovernanceResultSnapshot) PendingCapabilityDigest() [sha256.Size]byte {
	return value.projection.pendingCapabilityDigest
}
func (value GovernanceResultSnapshot) AuditAppendDigest() [sha256.Size]byte {
	return value.projection.auditAppendDigest
}
func (value GovernanceResultSnapshot) OuterRecordDigest() [sha256.Size]byte {
	return value.projection.outerRecordDigest
}
func (value GovernanceResultSnapshot) OuterPayloadDigest() [sha256.Size]byte {
	return value.projection.outerPayloadDigest
}
func (value GovernanceResultSnapshot) AuditEventID() (string, bool) {
	return value.projection.eventID, value.projection.phase != governanceResultAdmission
}
func (value GovernanceResultSnapshot) OperationKind() (governance.MutationKind, bool) {
	return governance.MutationKind(value.projection.operationKind), value.projection.phase != governanceResultAdmission
}
func (value GovernanceResultSnapshot) EvaluatedAtUnixNano() int64 {
	return value.projection.evaluatedAtUnixNano
}
func (value GovernanceResultSnapshot) CommitWindow() (int64, int64) {
	return value.projection.commitNotBeforeUnixNano, value.projection.commitNotAfterUnixNano
}
func (value GovernanceResultSnapshot) TransactionID() string {
	return value.projection.transactionID
}
func (value GovernanceResultSnapshot) TransactionObservedAtUnixNano() int64 {
	return value.projection.transactionObservedAtNano
}
func (value GovernanceResultSnapshot) ResultDigest() [sha256.Size]byte { return value.resultDigest }

func DecodeGovernanceResult(result replayresult.Result) (GovernanceResultSnapshot, error) {
	var zero GovernanceResultSnapshot
	if result.Verify() != nil ||
		(result.ContentType() != GovernanceApprovalAdmissionResultContentType &&
			result.ContentType() != GovernancePolicyFinalResultContentType &&
			result.ContentType() != GovernanceAuditAppendResultContentType) {
		return zero, ErrInvalidCompoundResult
	}
	payload := result.Payload()
	projection, err := decodeGovernanceResult(payload)
	if err != nil || governanceResultContentType(projection.phase) != result.ContentType() {
		return zero, ErrInvalidCompoundResult
	}
	rebuilt, err := encodeGovernanceResult(projection)
	if err != nil || !bytes.Equal(rebuilt, payload) {
		return zero, ErrInvalidCompoundResult
	}
	return GovernanceResultSnapshot{projection: projection, resultDigest: result.Digest()}, nil
}

func newGovernanceResult(contentType string, projection governanceResultProjection) (GovernanceResult, error) {
	payload, err := encodeGovernanceResult(projection)
	if err != nil || governanceResultContentType(projection.phase) != contentType {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	result, err := replayresult.New(contentType, payload)
	if err != nil {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	value := GovernanceResult{result: result, projection: projection}
	if value.Verify() != nil {
		return GovernanceResult{}, ErrInvalidCompoundResult
	}
	return value, nil
}

func governanceResultContentType(phase uint32) string {
	switch phase {
	case governanceResultAdmission:
		return GovernanceApprovalAdmissionResultContentType
	case governanceResultFinal:
		return GovernancePolicyFinalResultContentType
	case governanceResultAudit:
		return GovernanceAuditAppendResultContentType
	default:
		return ""
	}
}

func encodeGovernanceResult(value governanceResultProjection) ([]byte, error) {
	if governanceResultContentType(value.phase) == "" || value.planDigest == ([sha256.Size]byte{}) ||
		value.outerRecordDigest == ([sha256.Size]byte{}) || value.outerPayloadDigest == ([sha256.Size]byte{}) ||
		value.evaluatedAtUnixNano < 0 || value.commitNotBeforeUnixNano < 0 ||
		value.commitNotBeforeUnixNano > value.evaluatedAtUnixNano ||
		value.commitNotAfterUnixNano <= value.evaluatedAtUnixNano ||
		!validTransactionID(value.transactionID) ||
		value.transactionObservedAtNano < value.commitNotBeforeUnixNano ||
		value.transactionObservedAtNano >= value.commitNotAfterUnixNano ||
		!validGovernanceResultShape(value) {
		return nil, ErrInvalidCompoundResult
	}
	return ccse.Marshal(16<<10, func(out *ccse.Encoder) {
		out.Uint32(governanceResultVersion)
		out.Uint32(value.phase)
		out.FixedBytes(value.planDigest[:], sha256.Size)
		out.FixedBytes(value.pendingCapabilityDigest[:], sha256.Size)
		out.FixedBytes(value.auditAppendDigest[:], sha256.Size)
		out.FixedBytes(value.outerRecordDigest[:], sha256.Size)
		out.FixedBytes(value.outerPayloadDigest[:], sha256.Size)
		out.String(value.eventID)
		out.Uint32(value.operationKind)
		out.Int64(value.evaluatedAtUnixNano)
		out.Int64(value.commitNotBeforeUnixNano)
		out.Int64(value.commitNotAfterUnixNano)
		out.String(value.transactionID)
		out.Int64(value.transactionObservedAtNano)
	})
}

func validGovernanceResultShape(value governanceResultProjection) bool {
	switch value.phase {
	case governanceResultAdmission:
		return value.pendingCapabilityDigest != ([sha256.Size]byte{}) && value.eventID == "" &&
			value.auditAppendDigest == ([sha256.Size]byte{}) && value.operationKind == 0
	case governanceResultFinal:
		if value.eventID == "" || value.auditAppendDigest == ([sha256.Size]byte{}) ||
			value.operationKind < uint32(governance.MutationPolicyPublish) ||
			value.operationKind > uint32(governance.MutationPolicyAbort) {
			return false
		}
		return value.pendingCapabilityDigest != ([sha256.Size]byte{})
	case governanceResultAudit:
		return value.eventID != "" && value.auditAppendDigest != ([sha256.Size]byte{}) &&
			value.pendingCapabilityDigest == ([sha256.Size]byte{}) &&
			value.operationKind == uint32(governance.MutationAuditAppend)
	default:
		return false
	}
}

func decodeGovernanceResult(input []byte) (governanceResultProjection, error) {
	var value governanceResultProjection
	err := ccse.Unmarshal(input, 16<<10, func(in *ccse.Decoder) error {
		version, err := in.Uint32()
		if err != nil || version != governanceResultVersion {
			return ErrInvalidCompoundResult
		}
		if value.phase, err = in.Uint32(); err != nil {
			return ErrInvalidCompoundResult
		}
		for _, target := range []*[sha256.Size]byte{&value.planDigest, &value.pendingCapabilityDigest,
			&value.auditAppendDigest, &value.outerRecordDigest, &value.outerPayloadDigest} {
			encoded, decodeErr := in.FixedBytes(sha256.Size)
			if decodeErr != nil {
				return ErrInvalidCompoundResult
			}
			copy(target[:], encoded)
		}
		if value.eventID, err = in.String(1024); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.operationKind, err = in.Uint32(); err != nil {
			return ErrInvalidCompoundResult
		}
		if value.evaluatedAtUnixNano, err = in.Int64(); err != nil {
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
		return governanceResultProjection{}, ErrInvalidCompoundResult
	}
	if _, err := encodeGovernanceResult(value); err != nil {
		return governanceResultProjection{}, err
	}
	return value, nil
}

func exactGovernanceOuter(outer ccse.VerifiedRecord, expected governance.SignedEvidence) bool {
	raw := expected.Record()
	if raw == nil || expected.RecordDigest() == ([sha256.Size]byte{}) ||
		outer.Digest() != expected.RecordDigest() {
		return false
	}
	digest, err := raw.Digest(ccse.DefaultLimits())
	return err == nil && digest == expected.RecordDigest() && reflect.DeepEqual(*raw, outer.Record())
}
