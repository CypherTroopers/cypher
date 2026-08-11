// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvidenceAuthenticationDoesNotConsumeReplay(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	authenticator := evidenceAuthenticatorFromVerifier(verifier)

	evidence, err := authenticator.Authenticate(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.MessageTypeID() != record.MessageTypeID || evidence.SchemaVersion() != record.SchemaVersion {
		t.Fatalf("evidence identity mismatch: type=%d schema=%+v", evidence.MessageTypeID(), evidence.SchemaVersion())
	}
	wantDigest, err := record.Digest(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Digest() != wantDigest {
		t.Fatal("evidence digest mismatch")
	}
	if _, err := evidence.PreflightSize(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, dispatchable := any(evidence).(interface {
		ReplayEntry() (ReplayEntry, error)
	}); dispatchable {
		t.Fatal("authenticated evidence unexpectedly exposes a replay identity")
	}

	// Evidence authentication must not reserve the signed replay identity. The
	// ordinary verifier still sees this record as first-seen and applies it.
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if result.Duplicate {
		t.Fatal("evidence authentication consumed replay state")
	}
}

func TestAuthenticatedEvidenceRecordIsDetached(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	authenticator := evidenceAuthenticatorFromVerifier(verifier)

	evidence, err := authenticator.Authenticate(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	want := evidence.Record()
	wantDigest := evidence.Digest()

	record.Domain.Audience[0] = "spiffe://attacker/audience"
	record.Payload[0] ^= 0xff
	record.Signature[0] ^= 0xff

	got := evidence.Record()
	if gotDigest, err := got.Digest(DefaultLimits()); err != nil || gotDigest != wantDigest {
		t.Fatalf("producer mutation changed evidence: digest=%x err=%v", gotDigest, err)
	}
	if !bytes.Equal(got.Payload, want.Payload) || !bytes.Equal(got.Signature, want.Signature) || got.Domain.Audience[0] != want.Domain.Audience[0] {
		t.Fatal("producer mutation aliased authenticated evidence")
	}

	got.Payload[0] ^= 0xff
	got.Signature[0] ^= 0xff
	got.Domain.Audience[0] = "spiffe://attacker/getter"
	again := evidence.Record()
	if !bytes.Equal(again.Payload, want.Payload) || !bytes.Equal(again.Signature, want.Signature) || again.Domain.Audience[0] != want.Domain.Audience[0] {
		t.Fatal("Record getter aliased authenticated evidence")
	}
}

func TestEvidenceAuthenticatorFailsClosed(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	authenticator := evidenceAuthenticatorFromVerifier(verifier)

	tests := []struct {
		name   string
		mutate func(*EvidenceAuthenticator, *Record)
		want   error
	}{
		{
			name: "wrong signed purpose",
			mutate: func(a *EvidenceAuthenticator, _ *Record) {
				a.Expectations.Purpose += ".other"
			},
			want: ErrWrongPurpose,
		},
		{
			name: "expired",
			mutate: func(a *EvidenceAuthenticator, _ *Record) {
				a.Clock = ClockFunc(func() time.Time { return testExpiresAt })
			},
			want: ErrExpired,
		},
		{
			name: "invalid signature",
			mutate: func(_ *EvidenceAuthenticator, r *Record) {
				r.Signature = append([]byte(nil), r.Signature...)
				r.Signature[0] ^= 0xff
			},
			want: ErrInvalidSignature,
		},
		{
			name: "missing key resolver",
			mutate: func(a *EvidenceAuthenticator, _ *Record) {
				a.Keys = nil
			},
			want: ErrKeyResolverRequired,
		},
		{
			name: "missing schema",
			mutate: func(a *EvidenceAuthenticator, _ *Record) {
				a.Schema = nil
			},
			want: ErrSchemaValidatorRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := *authenticator
			candidate := cloneRecord(record)
			test.mutate(&auth, candidate)
			if _, err := auth.Authenticate(context.Background(), candidate); !errors.Is(err, test.want) {
				t.Fatalf("Authenticate error=%v, want %v", err, test.want)
			}
		})
	}

	var zero AuthenticatedEvidenceRecord
	if err := zero.ValidateLimits(DefaultLimits()); err == nil {
		t.Fatal("zero evidence passed validation")
	}
}

func TestEvidenceSchemaCallbacksRunOnlyAfterSignatureAuthentication(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	authenticator := evidenceAuthenticatorFromVerifier(verifier)
	calls := 0
	authenticator.Schema = SchemaValidatorFuncs{
		Extensions: func(context.Context, uint32, Version, []Extension) error {
			calls++
			return nil
		},
		Payload: func(context.Context, uint32, Version, []byte) error {
			calls++
			return nil
		},
	}
	broken := cloneRecord(record)
	broken.Signature[0] ^= 0xff
	if _, err := authenticator.Authenticate(context.Background(), broken); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Authenticate error=%v, want %v", err, ErrInvalidSignature)
	}
	if calls != 0 {
		t.Fatalf("schema callbacks ran %d times before evidence signature authentication", calls)
	}
	if _, err := authenticator.Authenticate(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("schema callbacks ran %d times after valid evidence authentication, want 2", calls)
	}
}

func evidenceAuthenticatorFromVerifier(verifier *Verifier) *EvidenceAuthenticator {
	return &EvidenceAuthenticator{
		Expectations: verifier.Expectations,
		Limits:       verifier.Limits,
		Clock:        verifier.Clock,
		Keys:         verifier.Keys,
		Schema:       verifier.Schema,
	}
}

func FuzzAuthenticatedEvidenceRejectsSignedMutation(f *testing.F) {
	f.Add(uint8(0), uint16(0), uint8(1))
	f.Add(uint8(1), uint16(31), uint8(0xff))
	f.Add(uint8(2), uint16(7), uint8(9))
	f.Fuzz(func(t *testing.T, field uint8, offset uint16, delta uint8) {
		if delta == 0 {
			delta = 1
		}
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, record, publicKey)
		authenticator := evidenceAuthenticatorFromVerifier(verifier)
		switch field % 4 {
		case 0:
			record.Payload[int(offset)%len(record.Payload)] ^= delta
		case 1:
			record.Signature[int(offset)%len(record.Signature)] ^= delta
		case 2:
			record.Domain.ReplayDomainID += string([]byte{'-', 'a' + delta%26})
		case 3:
			record.Envelope.MessageID[int(offset)%len(record.Envelope.MessageID)] ^= delta
		}
		if _, err := authenticator.Authenticate(context.Background(), record); err == nil {
			t.Fatal("mutated signed evidence accepted")
		}
	})
}
