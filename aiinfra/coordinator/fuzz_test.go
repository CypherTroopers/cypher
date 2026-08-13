// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"testing"

	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func FuzzDecodeAuditedSuccessResultNeverPanics(f *testing.F) {
	seed, err := encodeAuditedSuccessProjection(testAuditedSuccessProjection())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > auditedSuccessResultMaxBytes+1 {
			return
		}
		result, newErr := replayresult.New(AuditedSuccessResultContentType, payload)
		if newErr != nil {
			return
		}
		_, _ = DecodeAuditedSuccessResult(result)
	})
}
