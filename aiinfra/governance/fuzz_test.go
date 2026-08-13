// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
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

func FuzzDurablePolicyApprovalCollectionDecode(f *testing.F) {
	fixture := newGovernanceFixture(f)
	policy := fixture.normalPolicy()
	command := fixture.policyCommand(f, policy)
	payload, err := policy.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	binding := policyIdempotencyBinding(policy, sha256.Sum256(payload))
	stored := fixture.collections.collections[binding.Key]
	progress := fixture.idempotency.snapshots[binding.Key].ProgressDigest
	seed, err := EncodePolicyApprovalCollection(binding, uint64(len(stored)), progress, stored)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := fixture.planner.RehydratePolicyApprovalCollection(context.Background(), seed); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte{0, 0, 0, 1})
	f.Add(command.Approvals[0].Record.Payload)
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, decodeErr := DecodePolicyApprovalCollection(input)
		if decodeErr != nil {
			return
		}
		if decoded.Digest() != durablePolicyApprovalCollectionDigest(decoded.Bytes()) ||
			len(decoded.Bytes()) == 0 || len(decoded.EvidenceDigests()) == 0 {
			t.Fatal("successful decode did not retain an exact owned envelope")
		}
		roundTrip, err := DecodePolicyApprovalCollection(decoded.Bytes())
		if err != nil || roundTrip.Digest() != decoded.Digest() ||
			!bytes.Equal(roundTrip.Bytes(), decoded.Bytes()) {
			t.Fatalf("successful decode was not deterministic: %v", err)
		}
	})
}

func FuzzDurableEvidenceStorageCapability(f *testing.F) {
	fixture := newGovernanceFixture(f)
	approval := fixture.policyCommand(f, fixture.normalPolicy()).Approvals[0]
	signed, err := bindVerifiedSignedRecord(approval, maxPayloadBytesFor(approval.Record.MessageTypeID))
	if err != nil {
		f.Fatal(err)
	}
	receipt := []byte("canonical-iam-receipt")
	receiptDigest := domainSeparatedContentDigest(iamAuditEvidenceBundleDigestDomain, receipt)
	semantic, err := newIAMSemanticReceiptEvidence(iamAuditEvidenceReceiptDomain, receipt, receiptDigest)
	if err != nil {
		f.Fatal(err)
	}
	seeds := []DurableEvidence{
		newContentEvidence(sha256.Sum256([]byte("content-evidence")), []byte("content-evidence")),
		newSignedDurableEvidence(signed, fixture.authA),
		semantic,
	}
	for index, seed := range seeds {
		disposition := DurableEvidenceStorageReserveNew
		pendingKey, pendingRevision, hasPendingLink := [ccse.MessageIDSize]byte{}, uint64(0), false
		if index == 1 {
			disposition, pendingKey, pendingRevision, hasPendingLink =
				DurableEvidenceStorageAssertExisting, testID(0x81), 7, true
		}
		capability, capabilityErr := newDurableEvidenceStorageCapabilityWithPersistence(seed, "audit-fuzz-seed",
			disposition, pendingKey, pendingRevision, hasPendingLink)
		if capabilityErr != nil {
			f.Fatal(capabilityErr)
		}
		f.Add(uint8(capability.kind), capability.contentType, capability.canonicalContent,
			capability.expectedAuditEventID, capability.evidenceDigest[:], uint8(capability.disposition),
			capability.pendingKey[:], capability.pendingRevision, capability.hasPendingLink)
	}
	f.Add(uint8(0), "", []byte{0}, "", []byte{0}, uint8(0), []byte{0}, uint64(0), false)
	f.Fuzz(func(t *testing.T, kind uint8, contentType string, canonical []byte, eventID string,
		digestBytes []byte, disposition uint8, pendingKeyBytes []byte, pendingRevision uint64, hasPendingLink bool) {
		if len(contentType) > 512 || len(canonical) > (2<<20) || len(eventID) > 2048 ||
			len(digestBytes) > 64 || len(pendingKeyBytes) > 64 {
			t.Skip()
		}
		var digest [ccse.DigestSize]byte
		copy(digest[:], digestBytes)
		var pendingKey [ccse.MessageIDSize]byte
		copy(pendingKey[:], pendingKeyBytes)
		capability := DurableEvidenceStorageCapability{
			evidenceDigest: digest, kind: DurableEvidenceStorageKind(kind), contentType: contentType,
			canonicalContent: append([]byte(nil), canonical...), expectedAuditEventID: eventID,
			auditAssertionEventID: eventID,
			disposition:           DurableEvidenceStorageDisposition(disposition), pendingKey: pendingKey,
			pendingRevision: pendingRevision, hasPendingLink: hasPendingLink,
		}
		computed, computeErr := digestDurableEvidenceStorageCapability(capability)
		if computeErr != nil {
			return
		}
		capability.digest = computed
		if capability.VerifyDigest() != nil {
			t.Fatal("accepted storage capability did not verify deterministically")
		}
		cloned := cloneDurableEvidenceStorageCapabilities([]DurableEvidenceStorageCapability{capability})[0]
		if !equalDurableEvidenceStorageCapabilities(capability, cloned) {
			t.Fatal("accepted storage capability did not clone exactly")
		}
		if len(cloned.canonicalContent) > 0 {
			cloned.canonicalContent[0] ^= 1
			if bytes.Equal(cloned.canonicalContent, capability.canonicalContent) {
				t.Fatal("storage capability clone aliases canonical bytes")
			}
		}
	})
}
