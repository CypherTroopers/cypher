// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func testIAMAdmissionProjection() iamAdmissionResultProjection {
	return iamAdmissionResultProjection{
		kind: iam.DurablePendingMutation, pendingDigest: fillDigest(0x11),
		envelopeDigest: fillDigest(0x22), capabilityDigest: fillDigest(0x33),
		stateReadDigest: fillDigest(0x44), revisionDigest: fillDigest(0x55),
		outerRecordDigest: fillDigest(0x66), outerPayloadDigest: fillDigest(0x77),
		auditEventID: "future-event", commitNotBeforeUnixNano: 90, commitNotAfterUnixNano: 200,
		transactionID: "42", transactionObservedAtNano: 100,
	}
}

func TestIAMAdmissionResultRoundTripAndOwnedPayload(t *testing.T) {
	projection := testIAMAdmissionProjection()
	result, err := newIAMAdmissionResult(projection)
	if err != nil || result.Verify() != nil {
		t.Fatalf("result: %v", err)
	}
	snapshot, err := DecodeIAMAdmissionResult(result.result)
	if err != nil || snapshot.Kind() != projection.kind ||
		snapshot.PendingDigest() != projection.pendingDigest ||
		snapshot.DurableEnvelopeDigest() != projection.envelopeDigest ||
		snapshot.CapabilityDigest() != projection.capabilityDigest ||
		snapshot.TransactionID() != projection.transactionID ||
		snapshot.ResultDigest() != result.Digest() {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	payload := result.Payload()
	payload[0] ^= 1
	if bytes.Equal(payload, result.Payload()) {
		t.Fatal("result payload aliases retained bytes")
	}
}

func TestIAMAdmissionResultRejectsForeignKindAndMalformedPayload(t *testing.T) {
	for _, mutate := range []func(*iamAdmissionResultProjection){
		func(value *iamAdmissionResultProjection) { value.kind = iam.DurablePendingReconciliation },
		func(value *iamAdmissionResultProjection) { value.capabilityDigest = [32]byte{} },
		func(value *iamAdmissionResultProjection) { value.auditEventID = "" },
		func(value *iamAdmissionResultProjection) { value.transactionID = "00" },
		func(value *iamAdmissionResultProjection) { value.transactionObservedAtNano = 200 },
	} {
		candidate := testIAMAdmissionProjection()
		mutate(&candidate)
		if _, err := encodeIAMAdmissionResult(candidate); err == nil {
			t.Fatal("invalid IAM admission projection accepted")
		}
	}
	payload, err := encodeIAMAdmissionResult(testIAMAdmissionProjection())
	if err != nil {
		t.Fatal(err)
	}
	result, err := replayresult.New(IAMAdmissionResultContentType, append(payload, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIAMAdmissionResult(result); err == nil {
		t.Fatal("trailing IAM admission bytes accepted")
	}
}
