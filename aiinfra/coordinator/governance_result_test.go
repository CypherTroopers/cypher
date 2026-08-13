// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func TestGovernanceResultRoundTripClosedShapes(t *testing.T) {
	base := governanceResultProjection{
		planDigest: fillDigest(0x11), outerRecordDigest: fillDigest(0x22),
		outerPayloadDigest: fillDigest(0x33), evaluatedAtUnixNano: 100,
		commitNotBeforeUnixNano: 90, commitNotAfterUnixNano: 200,
		transactionID: "42", transactionObservedAtNano: 101,
	}
	for _, test := range []struct {
		name        string
		contentType string
		projection  governanceResultProjection
		hasEvent    bool
	}{
		{name: "admission", contentType: GovernanceApprovalAdmissionResultContentType,
			projection: func() governanceResultProjection {
				value := base
				value.phase = governanceResultAdmission
				value.pendingCapabilityDigest = fillDigest(0x44)
				return value
			}()},
		{name: "policy", contentType: GovernancePolicyFinalResultContentType, hasEvent: true,
			projection: func() governanceResultProjection {
				value := base
				value.phase = governanceResultFinal
				value.pendingCapabilityDigest = fillDigest(0x44)
				value.auditAppendDigest = fillDigest(0x55)
				value.eventID = "event-1"
				value.operationKind = uint32(governance.MutationPolicyActivate)
				return value
			}()},
		{name: "audit", contentType: GovernanceAuditAppendResultContentType, hasEvent: true,
			projection: func() governanceResultProjection {
				value := base
				value.phase = governanceResultAudit
				value.auditAppendDigest = fillDigest(0x55)
				value.eventID = "event-2"
				value.operationKind = uint32(governance.MutationAuditAppend)
				return value
			}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := newGovernanceResult(test.contentType, test.projection)
			if err != nil || value.Verify() != nil {
				t.Fatalf("new result: %v", err)
			}
			snapshot, err := DecodeGovernanceResult(value.result)
			if err != nil || snapshot.PlanDigest() != test.projection.planDigest ||
				snapshot.ResultDigest() != value.Digest() ||
				snapshot.TransactionID() != test.projection.transactionID {
				t.Fatalf("snapshot=%+v err=%v", snapshot, err)
			}
			eventID, present := snapshot.AuditEventID()
			if present != test.hasEvent || eventID != test.projection.eventID {
				t.Fatalf("event=%q present=%t", eventID, present)
			}
		})
	}
}

func TestGovernanceResultRejectsForeignPhaseKindAndTamper(t *testing.T) {
	base := governanceResultProjection{
		phase: governanceResultFinal, planDigest: fillDigest(0x11),
		pendingCapabilityDigest: fillDigest(0x22), auditAppendDigest: fillDigest(0x33),
		outerRecordDigest: fillDigest(0x44), outerPayloadDigest: fillDigest(0x55),
		eventID: "event", operationKind: uint32(governance.MutationPolicyPublish),
		evaluatedAtUnixNano: 100, commitNotBeforeUnixNano: 90, commitNotAfterUnixNano: 200,
		transactionID: "42", transactionObservedAtNano: 101,
	}
	for _, mutate := range []func(*governanceResultProjection){
		func(value *governanceResultProjection) { value.operationKind = 999 },
		func(value *governanceResultProjection) { value.phase = governanceResultAudit },
		func(value *governanceResultProjection) { value.pendingCapabilityDigest = [32]byte{} },
		func(value *governanceResultProjection) { value.auditAppendDigest = [32]byte{} },
		func(value *governanceResultProjection) { value.transactionObservedAtNano = 200 },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := encodeGovernanceResult(candidate); err == nil {
			t.Fatal("invalid governance result shape was accepted")
		}
	}
	payload, err := encodeGovernanceResult(base)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(bytes.Clone(payload), 0)
	result, err := replayresult.New(GovernancePolicyFinalResultContentType, tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGovernanceResult(result); err == nil {
		t.Fatal("trailing governance result bytes accepted")
	}
}
