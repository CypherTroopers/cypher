// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"testing"

	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func TestAuditedFailureInnerBoundaryMatchesIAMCodec(t *testing.T) {
	if auditedFailureInnerMaxBytes != iam.MaxPendingReconciliationResultPayloadBytes {
		t.Fatalf("failure boundary drift: coordinator=%d IAM=%d",
			auditedFailureInnerMaxBytes, iam.MaxPendingReconciliationResultPayloadBytes)
	}
	if auditedFailureInnerMaxBytes != replayresult.MaxPayloadBytes {
		t.Fatalf("failure boundary drift: coordinator=%d replay=%d",
			auditedFailureInnerMaxBytes, replayresult.MaxPayloadBytes)
	}
}

func TestDecodeAuditedFailureResultRejectsWrongTypeAndMalformed(t *testing.T) {
	for _, result := range []replayresult.Result{
		{},
		mustReplayResult(t, AuditedSuccessResultContentType, []byte("not-a-failure")),
		mustReplayResult(t, AuditedFailureResultContentType, []byte("truncated")),
	} {
		if _, err := DecodeAuditedFailureResult(result); err == nil {
			t.Fatal("invalid audited failure result was decoded")
		}
	}
}

func mustReplayResult(t *testing.T, contentType string, payload []byte) replayresult.Result {
	t.Helper()
	result, err := replayresult.New(contentType, payload)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
