// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"testing"

	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func testIAMCollectionAdvanceProjection() iamCollectionAdvanceResultProjection {
	return iamCollectionAdvanceResultProjection{
		pendingDigest: fillDigest(0x11), envelopeDigest: fillDigest(0x22),
		capabilityDigest: fillDigest(0x33), stateReadDigest: fillDigest(0x44),
		nextRevisionDigest: fillDigest(0x55), sourceEnvelopeDigest: fillDigest(0x66),
		outerRecordDigest: fillDigest(0x77), outerPayloadDigest: fillDigest(0x88),
		auditEventID: "future-event", sourceRevision: 1, nextRevision: 2,
		previousCommitNotBeforeUnixNano: 80, previousCommitNotAfterUnixNano: 210,
		commitNotBeforeUnixNano: 90, commitNotAfterUnixNano: 200,
		transactionID: "42", transactionObservedAtUnixNano: 100,
	}
}

func TestIAMCollectionAdvanceResultRoundTripAndOwnedPayload(t *testing.T) {
	projection := testIAMCollectionAdvanceProjection()
	result, err := newIAMCollectionAdvanceResult(projection)
	if err != nil || result.Verify() != nil {
		t.Fatalf("result: %v", err)
	}
	snapshot, err := DecodeIAMCollectionAdvanceResult(result.result)
	if err != nil || snapshot.PendingDigest() != projection.pendingDigest ||
		snapshot.DurableEnvelopeDigest() != projection.envelopeDigest ||
		snapshot.CapabilityDigest() != projection.capabilityDigest ||
		snapshot.SourceRevision() != projection.sourceRevision ||
		snapshot.NextRevision() != projection.nextRevision ||
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

func TestIAMCollectionAdvanceResultRejectsMalformedOrForeignShape(t *testing.T) {
	for _, mutate := range []func(*iamCollectionAdvanceResultProjection){
		func(value *iamCollectionAdvanceResultProjection) { value.nextRevision = value.sourceRevision + 2 },
		func(value *iamCollectionAdvanceResultProjection) { value.sourceEnvelopeDigest = [32]byte{} },
		func(value *iamCollectionAdvanceResultProjection) { value.previousCommitNotAfterUnixNano = 0 },
		func(value *iamCollectionAdvanceResultProjection) { value.auditEventID = "" },
		func(value *iamCollectionAdvanceResultProjection) { value.transactionID = "00" },
		func(value *iamCollectionAdvanceResultProjection) { value.transactionObservedAtUnixNano = 200 },
	} {
		candidate := testIAMCollectionAdvanceProjection()
		mutate(&candidate)
		if _, err := encodeIAMCollectionAdvanceResult(candidate); err == nil {
			t.Fatal("invalid collection advance projection accepted")
		}
	}
	payload, err := encodeIAMCollectionAdvanceResult(testIAMCollectionAdvanceProjection())
	if err != nil {
		t.Fatal(err)
	}
	result, err := replayresult.New(IAMCollectionAdvanceResultContentType, append(payload, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIAMCollectionAdvanceResult(result); err == nil {
		t.Fatal("trailing collection advance result bytes accepted")
	}
	wrongType, err := replayresult.New(IAMAdmissionResultContentType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIAMCollectionAdvanceResult(wrongType); err == nil {
		t.Fatal("first-admission content type accepted as collection advance")
	}
}
