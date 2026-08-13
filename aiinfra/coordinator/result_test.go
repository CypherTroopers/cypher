// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func TestAuditedSuccessProjectionGoldenAndResultDigest(t *testing.T) {
	projection := testAuditedSuccessProjection()
	encoded, err := encodeAuditedSuccessProjection(projection)
	if err != nil {
		t.Fatalf("encodeAuditedSuccessProjection: %v", err)
	}
	const wantPayloadSHA256 = "27aee2553e6286fd4e2fbce08ddc641091202536ec1177bc10762756e7210210"
	payloadDigest := sha256.Sum256(encoded)
	if actual := hex.EncodeToString(payloadDigest[:]); actual != wantPayloadSHA256 {
		t.Fatalf("payload SHA-256 = %s, want %s", actual, wantPayloadSHA256)
	}
	result, err := replayresult.New(AuditedSuccessResultContentType, encoded)
	if err != nil || result.Verify() != nil {
		t.Fatalf("replay result: %v", err)
	}
	const wantResultDigest = "111f88a18b24abfdf523089411bdf65c453f3181b0f948295b8c53db253f23f5"
	resultDigest := result.Digest()
	if actual := hex.EncodeToString(resultDigest[:]); actual != wantResultDigest {
		t.Fatalf("result digest = %s, want %s", actual, wantResultDigest)
	}
	snapshot, err := DecodeAuditedSuccessResult(result)
	if err != nil {
		t.Fatalf("DecodeAuditedSuccessResult: %v", err)
	}
	if snapshot.Kind() != projection.kind || snapshot.RequestDigest() != projection.requestDigest ||
		snapshot.PendingDigest() != projection.pendingDigest ||
		snapshot.DurableEnvelopeDigest() != projection.envelopeDigest ||
		snapshot.StateAndGlobalCASDigest() != projection.stateDigest ||
		snapshot.ExecutionFragmentDigest() != projection.executionDigest ||
		snapshot.GovernanceFragmentDigest() != projection.governanceDigest ||
		snapshot.AuditEventID() != projection.auditEventID ||
		snapshot.AuditRecordDigest() != projection.auditRecordDigest ||
		snapshot.AuditPayloadDigest() != projection.auditPayloadDigest ||
		snapshot.AuditSequence() != projection.auditSequence ||
		snapshot.EvaluatedAtUnixNano() != projection.evaluatedAtUnixNano ||
		snapshot.CommitNotBeforeUnixNano() != projection.commitNotBefore ||
		snapshot.CommitNotAfterUnixNano() != projection.commitNotAfter ||
		snapshot.EvidenceBundleDigest() != projection.evidenceBundleDigest ||
		snapshot.TransactionID() != projection.transactionID ||
		snapshot.TransactionObservedAtUnixNano() != projection.transactionObservedAt ||
		snapshot.ResultDigest() != resultDigest {
		t.Fatalf("decoded snapshot = %#v", snapshot)
	}
}

func TestDecodeAuditedSuccessResultRejectsMalformedOrWrongType(t *testing.T) {
	payload, err := encodeAuditedSuccessProjection(testAuditedSuccessProjection())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		contentType string
		mutate      func([]byte) []byte
	}{
		{name: "wrong content type", contentType: "application/cph.invalid", mutate: func(value []byte) []byte { return value }},
		{name: "unsupported version", contentType: AuditedSuccessResultContentType, mutate: func(value []byte) []byte { value[3] = 2; return value }},
		{name: "trailing bytes", contentType: AuditedSuccessResultContentType, mutate: func(value []byte) []byte { return append(value, 0) }},
		{name: "zero request digest", contentType: AuditedSuccessResultContentType, mutate: func(value []byte) []byte {
			for index := 12; index < 12+sha256.Size; index++ {
				value[index] = 0
			}
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(bytes.Clone(payload))
			result, newErr := replayresult.New(test.contentType, candidate)
			if newErr != nil {
				t.Fatal(newErr)
			}
			if _, decodeErr := DecodeAuditedSuccessResult(result); decodeErr == nil {
				t.Fatal("malformed durable success result was accepted")
			}
		})
	}
}

func TestAuditedSuccessProjectionBindsEveryField(t *testing.T) {
	base := testAuditedSuccessProjection()
	want, err := encodeAuditedSuccessProjection(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*auditedSuccessProjection){
		func(v *auditedSuccessProjection) { v.kind++ },
		func(v *auditedSuccessProjection) { v.requestDigest[0]++ },
		func(v *auditedSuccessProjection) { v.pendingDigest[0]++ },
		func(v *auditedSuccessProjection) { v.envelopeDigest[0]++ },
		func(v *auditedSuccessProjection) { v.stateDigest[0]++ },
		func(v *auditedSuccessProjection) { v.executionDigest[0]++ },
		func(v *auditedSuccessProjection) { v.governanceDigest[0]++ },
		func(v *auditedSuccessProjection) { v.auditEventID += "-other" },
		func(v *auditedSuccessProjection) { v.auditRecordDigest[0]++ },
		func(v *auditedSuccessProjection) { v.auditPayloadDigest[0]++ },
		func(v *auditedSuccessProjection) { v.auditSequence++ },
		func(v *auditedSuccessProjection) { v.evaluatedAtUnixNano++ },
		func(v *auditedSuccessProjection) { v.commitNotBefore++ },
		func(v *auditedSuccessProjection) { v.commitNotAfter++ },
		func(v *auditedSuccessProjection) { v.evidenceBundleDigest[0]++ },
		func(v *auditedSuccessProjection) { v.transactionID = "43" },
		func(v *auditedSuccessProjection) { v.transactionObservedAt++ },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		got, encodeErr := encodeAuditedSuccessProjection(candidate)
		if encodeErr != nil {
			continue
		}
		if bytes.Equal(got, want) {
			t.Fatalf("mutation %d was not committed", index)
		}
	}
}

func TestAuditedSuccessProjectionRejectsNoncanonicalTransactionIDs(t *testing.T) {
	for _, transactionID := range []string{"", "0", "00", "+1", " 1", "1 ", "18446744073709551616"} {
		candidate := testAuditedSuccessProjection()
		candidate.transactionID = transactionID
		if _, err := encodeAuditedSuccessProjection(candidate); err == nil {
			t.Fatalf("transaction ID %q was accepted", transactionID)
		}
	}
	maximum := testAuditedSuccessProjection()
	maximum.transactionID = "18446744073709551615"
	if _, err := encodeAuditedSuccessProjection(maximum); err != nil {
		t.Fatalf("maximum xid8 was rejected: %v", err)
	}
}

func TestAuditedResultRejectsCallerConstructedZeroCapabilities(t *testing.T) {
	if _, err := buildAuditedResult(context.Background(), nil, iam.JoinedAuditRequest{},
		governance.JoinedAuditFragment{}, ccse.VerifiedRecord{}); !errors.Is(err, ErrTransactionBoundaryRequired) {
		t.Fatalf("nil transaction boundary error = %v", err)
	}
	if (AuditedResult{}).VerifyFor(iam.JoinedAuditRequest{}, governance.JoinedAuditFragment{}, ccse.VerifiedRecord{}) == nil {
		t.Fatal("zero result verified")
	}
}

func testAuditedSuccessProjection() auditedSuccessProjection {
	return auditedSuccessProjection{
		kind:          iam.DurablePendingMutation,
		requestDigest: fillDigest(0x11), pendingDigest: fillDigest(0x22),
		envelopeDigest: fillDigest(0x33), stateDigest: fillDigest(0x44),
		executionDigest: fillDigest(0x55), governanceDigest: fillDigest(0x66),
		auditEventID:      "cph-audit-v1:00112233445566778899aabbccddeeff",
		auditRecordDigest: fillDigest(0x77), auditPayloadDigest: fillDigest(0x88),
		auditSequence: 7, auditOutcome: 1,
		evaluatedAtUnixNano:   1_800_000_000_000_000_000,
		commitNotBefore:       1_799_999_999_000_000_000,
		commitNotAfter:        1_800_000_600_000_000_000,
		evidenceBundleDigest:  fillDigest(0x99),
		transactionID:         "42",
		transactionObservedAt: 1_800_000_000_000_000_001,
	}
}

func fillDigest(value byte) (digest [sha256.Size]byte) {
	for index := range digest {
		digest[index] = value
	}
	return digest
}
