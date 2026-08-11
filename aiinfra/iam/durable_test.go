// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

func assertDurableEnvelopeRoundTrip(t testing.TB, envelope DurablePendingEnvelope) {
	t.Helper()
	if envelope.CommitReady() || envelope.VerifyDigest() != nil || len(envelope.Bytes()) == 0 {
		t.Fatalf("invalid source durable envelope: kind=%v err=%v", envelope.Kind(), envelope.VerifyDigest())
	}
	original := envelope.Bytes()
	decoded, err := DecodeDurablePendingEnvelope(original)
	if err != nil || decoded.Kind() != envelope.Kind() || decoded.CodecVersion() != durablePendingCodecVersion ||
		decoded.Digest() != envelope.Digest() || !bytes.Equal(decoded.Bytes(), original) {
		t.Fatalf("durable round trip failed: kind=%v err=%v", envelope.Kind(), err)
	}

	// Both byte getters are detached. Mutating either result must not alter the
	// retained canonical bytes or their verified digest.
	for index, candidate := range [][]byte{envelope.Bytes(), decoded.Bytes()} {
		candidate[0] ^= 1
		if envelope.VerifyDigest() != nil ||
			!bytes.Equal(envelope.Bytes(), original) || !bytes.Equal(decoded.Bytes(), original) {
			t.Fatalf("durable byte getter %d aliases retained evidence", index)
		}
	}

	unknown := append(append([]byte(nil), original[:len(original)-1]...), []byte(`,"unknown":1}`)...)
	for name, malformed := range map[string][]byte{
		"trailing":     append(append([]byte(nil), original...), []byte(`{}`)...),
		"noncanonical": append([]byte{' '}, original...),
		"unknown":      unknown,
	} {
		if _, decodeErr := DecodeDurablePendingEnvelope(malformed); !errors.Is(decodeErr, ErrPendingPlanInvalid) {
			t.Fatalf("%s durable encoding accepted: %v", name, decodeErr)
		}
	}

	var wire durableEnvelopeWire
	if err := json.Unmarshal(original, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Version++
	wrongVersion, _ := json.Marshal(wire)
	if _, err := DecodeDurablePendingEnvelope(wrongVersion); !errors.Is(err, ErrPendingPlanInvalid) {
		t.Fatalf("unknown durable version accepted: %v", err)
	}

	if mutated := mutateDurableSignature(t, original); mutated != nil {
		if _, err := DecodeDurablePendingEnvelope(mutated); !errors.Is(err, ErrPendingPlanInvalid) {
			t.Fatalf("signature-tampered durable envelope accepted: %v", err)
		}
	}
	if mutated := mutateDurableField(t, original); mutated != nil {
		if _, err := DecodeDurablePendingEnvelope(mutated); !errors.Is(err, ErrPendingPlanInvalid) {
			t.Fatalf("field-tampered durable envelope accepted: %v", err)
		}
	}
}

func mutateDurableSignature(t testing.TB, encoded []byte) []byte {
	t.Helper()
	var wire durableEnvelopeWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	var signature *[]byte
	switch wire.Kind {
	case DurablePendingMutation:
		signature = &wire.Mutation.Audit.SourceRecord.Signature
	case DurablePendingKeyEnrollment:
		signature = &wire.Enrollment.Audit.SourceRecord.Signature
	case DurablePendingOwnershipTransferCollection:
		if len(wire.Transfer.Next.Approvals) > 0 {
			signature = &wire.Transfer.Next.Approvals[0].Signed.Record.Signature
		}
	case DurablePendingReconciliation:
		signature = &wire.Reconciliation.Audit.SourceRecord.Signature
	}
	if signature == nil || len(*signature) == 0 {
		return nil
	}
	(*signature)[0] ^= 1
	mutated, err := marshalDurableWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func mutateDurableField(t testing.TB, encoded []byte) []byte {
	t.Helper()
	var wire durableEnvelopeWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	switch wire.Kind {
	case DurablePendingMutation:
		wire.Mutation.Mutation.CommitNotAfter--
	case DurablePendingKeyEnrollment:
		wire.Enrollment.CommitNotAfter--
	case DurablePendingOwnershipTransferCollection:
		wire.Transfer.WriterEvidence[0] ^= 1
	case DurablePendingReconciliation:
		wire.Reconciliation.FailureEvidence[0] ^= 1
	default:
		return nil
	}
	mutated, err := marshalDurableWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func assertJoinedAuditRequestTamperResistance(t testing.TB, request JoinedAuditRequest) {
	t.Helper()
	if request.CommitReady() || request.VerifyDigest() != nil {
		t.Fatalf("invalid joined request: %v", request.VerifyDigest())
	}
	fragment, ok := request.ExecutionFragment()
	if !ok || fragment.CommitReady() || fragment.VerifyDigest() != nil {
		t.Fatalf("invalid IAM execution fragment: ok=%v err=%v", ok, fragment.VerifyDigest())
	}
	requestOutcome, requestOutcomeKnown := request.FailureOutcomeDigest()
	fragmentOutcome, fragmentOutcomeKnown := fragment.FailureOutcomeDigest()
	if requestOutcomeKnown != (request.Kind() == DurablePendingReconciliation) ||
		fragmentOutcomeKnown != requestOutcomeKnown || fragmentOutcome != requestOutcome ||
		(requestOutcomeKnown && requestOutcome == ([32]byte{})) ||
		(!requestOutcomeKnown && requestOutcome != ([32]byte{})) {
		t.Fatal("joined failure outcome availability mismatch")
	}
	outcomeTamperedRequest := request
	outcomeTamperedRequest.failureOutcomeDigest[0] ^= 1
	if digest, err := joinedAuditRequestDigest(outcomeTamperedRequest); err == nil && digest == request.Digest() {
		t.Fatal("failure outcome is not bound by joined request digest")
	}
	outcomeTamperedFragment := cloneIAMExecutionFragment(fragment)
	outcomeTamperedFragment.failureOutcomeDigest[0] ^= 1
	if digest, err := iamExecutionFragmentDigest(outcomeTamperedFragment); err == nil && digest == fragment.Digest() {
		t.Fatal("failure outcome is not bound by IAM execution digest")
	}

	// Every getter returning mutable data is detached.
	if values := request.IdempotencyCompletionClaims(); len(values) > 0 {
		values[0].NextVersion++
	}
	if values := request.IdentifierAssertions(); len(values) > 0 {
		values[0].Identifier += "-alias"
	}
	if values := request.CASIntents(); len(values) > 0 {
		values[0].WriterEvidenceDigest[0] ^= 1
	}
	if values := request.EvidenceReferences(); len(values) > 0 {
		values[0].Digest[0] ^= 1
	}
	if values := fragment.Mutations(); len(values) > 0 {
		if values[0].Identity != nil && len(values[0].Identity.CanonicalPayload) > 0 {
			values[0].Identity.CanonicalPayload[0] ^= 1
		}
		if values[0].Lifecycle != nil && len(values[0].Lifecycle.CanonicalPayload) > 0 {
			values[0].Lifecycle.CanonicalPayload[0] ^= 1
		}
	}
	if assertion, present := fragment.OwnershipTransferCollectionAssertion(); present &&
		len(assertion.Expected.CanonicalPayload) > 0 {
		assertion.Expected.CanonicalPayload[0] ^= 1
	}
	if write, present := fragment.AcceptedOwnershipTransferWrite(); present &&
		len(write.Next.CanonicalPayload) > 0 {
		write.Next.CanonicalPayload[0] ^= 1
	}
	if request.VerifyDigest() != nil {
		t.Fatal("joined request getter aliases retained state")
	}

	mutations := []func(*JoinedAuditRequest){
		func(value *JoinedAuditRequest) { value.parentExpected.Version++ },
		func(value *JoinedAuditRequest) { value.joinedExpected.Version++ },
		func(value *JoinedAuditRequest) { value.auditEventID += "-tampered" },
		func(value *JoinedAuditRequest) { value.commitNotBeforeUnixNano++ },
		func(value *JoinedAuditRequest) { value.commitNotAfterUnixNano-- },
		func(value *JoinedAuditRequest) { value.stateCommitment[0] ^= 1 },
		func(value *JoinedAuditRequest) { value.failureOutcomeDigest[0] ^= 1 },
		func(value *JoinedAuditRequest) {
			fragment := cloneIAMExecutionFragment(*value.execution)
			fragment.failureOutcomeDigest[0] ^= 1
			value.execution = &fragment
		},
		func(value *JoinedAuditRequest) {
			fragment := cloneIAMExecutionFragment(*value.execution)
			fragment.digest[0] ^= 1
			value.execution = &fragment
		},
		func(value *JoinedAuditRequest) { value.digest[0] ^= 1 },
	}
	if request.Kind() == DurablePendingOwnershipTransferCollection {
		mutations = append(mutations,
			func(value *JoinedAuditRequest) {
				fragment := cloneIAMExecutionFragment(*value.execution)
				fragment.transferCollection.Expected.ProgressDigest[0] ^= 1
				value.execution = &fragment
			},
			func(value *JoinedAuditRequest) {
				fragment := cloneIAMExecutionFragment(*value.execution)
				fragment.acceptedTransfer.ExpectedAbsent = false
				value.execution = &fragment
			},
			func(value *JoinedAuditRequest) {
				fragment := cloneIAMExecutionFragment(*value.execution)
				fragment.acceptedTransfer.Entity.ID += "-tampered"
				value.execution = &fragment
			},
		)
	}
	if len(request.completion) > 0 {
		mutations = append(mutations, func(value *JoinedAuditRequest) {
			value.completion = append([]idempotency.Claim(nil), value.completion...)
			value.completion[0].NextVersion++
		})
	}
	if len(request.identifierAssertions) > 0 {
		mutations = append(mutations, func(value *JoinedAuditRequest) {
			value.identifierAssertions = append([]globalid.Claim(nil), value.identifierAssertions...)
			value.identifierAssertions[0].Identifier += "-tampered"
		})
	}
	if len(request.casIntents) > 0 {
		mutations = append(mutations, func(value *JoinedAuditRequest) {
			value.casIntents = append([]CASIntent(nil), value.casIntents...)
			value.casIntents[0] = cloneCASIntent(value.casIntents[0])
			value.casIntents[0].WriterEvidenceDigest[0] ^= 1
		})
	}
	if len(request.evidenceReferences) > 0 {
		mutations = append(mutations, func(value *JoinedAuditRequest) {
			value.evidenceReferences = append([]ContentAddressedEvidenceReference(nil), value.evidenceReferences...)
			value.evidenceReferences[0].Embedded = !value.evidenceReferences[0].Embedded
		})
	}
	for index, mutate := range mutations {
		candidate := request
		mutate(&candidate)
		if candidate.VerifyDigest() == nil {
			t.Fatalf("joined request tamper %d accepted", index)
		}
	}

	// Embedded evidence is never just a caller-provided digest: it must be the
	// digest of the retained complete signed source record inside AuditIntent.
	if audit, ok := request.ExpectedAuditIntent(); ok {
		record, hasSource := audit.SourceAuthorizationRecord()
		if !hasSource {
			t.Fatal("joined audit source record missing")
		}
		digest, err := record.Digest(ccse.DefaultLimits())
		if err != nil || digest != audit.SourceAuthorizationDigest() {
			t.Fatalf("joined embedded source mismatch: %v", err)
		}
		found := false
		for _, reference := range request.EvidenceReferences() {
			if reference.Embedded && reference.Digest == digest {
				found = true
			}
		}
		if !found {
			t.Fatal("signed source is not exposed as embedded content-addressed evidence")
		}
	}
}

func TestDecodeDurablePendingEnvelopeRejectsOversize(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates the exact durable boundary")
	}
	oversize := make([]byte, durablePendingMaxBytes+1)
	if _, err := DecodeDurablePendingEnvelope(oversize); !errors.Is(err, ErrPendingPlanInvalid) {
		t.Fatalf("oversized durable envelope accepted: %v", err)
	}
}
