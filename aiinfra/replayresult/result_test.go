// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package replayresult

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestDigestIsFrozenAndInputSensitive(t *testing.T) {
	digest := Digest("application/cph.test+json", []byte(`{"ok":true}`))
	const expected = "c6f284d4953f954a4bed4cb15f8d618accad6bff4a0758dd37bd1f6c835d1071"
	if got := hex.EncodeToString(digest[:]); got != expected {
		t.Fatalf("digest changed: got %s want %s", got, expected)
	}
	if digest == Digest("application/cph.test+json", []byte(`{"ok":false}`)) {
		t.Fatal("payload mutation did not change digest")
	}
	if digest == Digest("application/octet-stream", []byte(`{"ok":true}`)) {
		t.Fatal("content-type mutation did not change digest")
	}
}

func TestResultOwnsInputAndReturnsDetachedPayload(t *testing.T) {
	payload := []byte("accepted")
	result, err := New("application/cph.test", payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 0xff
	first := result.Payload()
	if string(first) != "accepted" {
		t.Fatalf("owned payload = %q", first)
	}
	first[0] ^= 0xff
	if got := string(result.Payload()); got != "accepted" {
		t.Fatalf("detached payload = %q", got)
	}
	if err := result.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsInvalidAndOversizedInputs(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		payload     []byte
	}{
		{name: "empty type"},
		{name: "whitespace", contentType: " application/json"},
		{name: "control", contentType: "application/\njson"},
		{name: "non ascii", contentType: "application/\u2603"},
		{name: "long type", contentType: strings.Repeat("a", MaxContentTypeBytes+1)},
		{name: "long payload", contentType: "application/octet-stream", payload: make([]byte, MaxPayloadBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(test.contentType, test.payload); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
	if err := Validate(strings.Repeat("a", MaxContentTypeBytes), make([]byte, MaxPayloadBytes)); err != nil {
		t.Fatalf("maximum boundary rejected: %v", err)
	}
}

func TestZeroResultIsInvalid(t *testing.T) {
	if err := (Result{}).Verify(); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("Verify error = %v", err)
	}
}

func FuzzResultBoundary(f *testing.F) {
	f.Add("application/cph.test+json", []byte(`{"ok":true}`))
	f.Add("", []byte(nil))
	f.Add(" application/octet-stream", []byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, contentType string, payload []byte) {
		if len(contentType) > MaxContentTypeBytes+1 || len(payload) > MaxPayloadBytes+1 {
			t.Skip()
		}
		result, err := New(contentType, payload)
		if err != nil {
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if err := result.Verify(); err != nil {
			t.Fatal(err)
		}
		if result.Digest() != Digest(contentType, payload) || result.ContentType() != contentType {
			t.Fatal("result did not preserve the validated input")
		}
		got := result.Payload()
		if string(got) != string(payload) {
			t.Fatal("payload mismatch")
		}
		if len(got) != 0 {
			got[0] ^= 0xff
			if string(result.Payload()) != string(payload) {
				t.Fatal("payload getter leaked an alias")
			}
		}
	})
}
