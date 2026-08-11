// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"crypto/sha256"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
)

func FuzzGovernanceRawRecordPreflight(f *testing.F) {
	f.Add([]byte("payload"), []byte("sender"), []byte("signature"), uint8(1), uint8(1))
	f.Add(make([]byte, maxPayloadBytesFor(0x0001000a)+1), []byte("sender"), []byte{1}, uint8(64), uint8(64))
	f.Fuzz(func(t *testing.T, payload, text, signature []byte, audienceCount, extensionCount uint8) {
		if len(payload) > maxPayloadBytesFor(0x0001000b)+1 || len(text) > 70<<10 || len(signature) > 70<<10 {
			t.Skip()
		}
		record := ccse.Record{
			Domain: ccse.Domain{
				Purpose: string(text), SenderIdentity: string(text), Environment: string(text), SignatureKeyID: string(text),
				ReplayDomainID: string(text), Audience: make([]string, int(audienceCount)),
			},
			Envelope: ccse.Envelope{SenderIdentity: string(text), Environment: string(text), SignatureKeyID: string(text),
				Extensions: make([]ccse.Extension, int(extensionCount))},
			Payload: append([]byte(nil), payload...), Signature: append([]byte(nil), signature...),
		}
		for index := range record.Domain.Audience {
			record.Domain.Audience[index] = string(text)
		}
		for index := range record.Envelope.Extensions {
			record.Envelope.Extensions[index].Value = append([]byte(nil), text...)
		}
		_ = preflightRawRecord(&record, maxPayloadBytesFor(0x0001000b))
	})
}

func FuzzBreakGlassCanonicalDocument(f *testing.F) {
	f.Add([]byte(`{"break_glass_scopes":["market.pause"],"policy_kind":"provider-eligibility"}`))
	f.Add([]byte(`{ "policy_kind": "provider-eligibility" }`))
	f.Add([]byte{0xff, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > maxPolicyDocumentBytes+1 {
			t.Skip()
		}
		digest := sha256.Sum256(document)
		_, _ = decodeBreakGlassDocument(PolicyDocumentSnapshot{
			DigestSHA256: digest, MediaType: breakGlassDocumentMediaType, CanonicalDocument: append([]byte(nil), document...),
		}, digest, breakGlassDocumentMediaType, "provider-eligibility")
	})
}
