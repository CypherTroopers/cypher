// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/replayresult"
)

func TestReplayMigrationDigestIsPinned(t *testing.T) {
	digest, err := ReplayMigrationDigest()
	if err != nil {
		t.Fatal(err)
	}
	const expected = "ce7e56583b042e2fd94f06a7378981b5afd231b3c2e9305f0b2b359ce2d38359"
	if got := hex.EncodeToString(digest[:]); got != expected {
		t.Fatalf("migration digest changed: got %s want %s; add a new numbered migration instead", got, expected)
	}
}

func TestReplayScopeDigestBindsEveryScopeField(t *testing.T) {
	base := testReplayEntry()
	want, err := replayScopeDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	const frozenScopeDigest = "f6b3539be3bd0cae4685b58d2acf30f7e776a3186745d3f125e6527acdefa543"
	if got := hex.EncodeToString(want[:]); got != frozenScopeDigest {
		t.Fatalf("replay scope v1 digest changed: got %s want %s; add a versioned migration and dual-read plan", got, frozenScopeDigest)
	}
	tests := []struct {
		name   string
		mutate func(*ccse.ReplayEntry)
	}{
		{"counter kind", func(v *ccse.ReplayEntry) { v.CounterKind = ccse.CounterExpectedGeneration }},
		{"replay domain", func(v *ccse.ReplayEntry) { v.ReplayDomainID += ".other" }},
		{"sender", func(v *ccse.ReplayEntry) { v.SenderIdentity += ".other" }},
		{"environment", func(v *ccse.ReplayEntry) { v.Environment += ".other" }},
		{"chain", func(v *ccse.ReplayEntry) { v.ChainID[0] ^= 1 }},
		{"genesis", func(v *ccse.ReplayEntry) { v.GenesisHash[0] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			got, err := replayScopeDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("scope mutation did not change digest")
			}
		})
	}
	changed := base
	changed.MessageID[0] ^= 1
	changed.Sequence++
	changed.Digest[0] ^= 1
	got, err := replayScopeDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("message-local fields changed the replay scope")
	}
}

func TestSequenceEncodingPreservesUnsignedOrder(t *testing.T) {
	values := []uint64{0, 1, 1<<63 - 1, 1 << 63, ^uint64(0)}
	for i := 1; i < len(values); i++ {
		previous := encodeSequence(values[i-1])
		current := encodeSequence(values[i])
		if string(previous[:]) >= string(current[:]) {
			t.Fatalf("encoded order does not preserve uint64 order: %d then %d", values[i-1], values[i])
		}
	}
}

func TestReplayStoreRejectsMissingDatabase(t *testing.T) {
	if _, err := NewReplayStore(context.Background(), nil); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("NewReplayStore error = %v, want %v", err, ErrDatabaseRequired)
	}
	var store *ReplayStore
	if _, err := store.Execute(context.Background(), testReplayEntry(), ccse.VerifiedRecord{}, func(context.Context, ccse.VerifiedRecord) ([32]byte, error) {
		return [32]byte{1}, nil
	}); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("Execute error = %v, want %v", err, ErrDatabaseRequired)
	}
}

func TestDurableResultDigestIsDomainSeparatedAndFrozen(t *testing.T) {
	digest := DurableResultDigest("application/cph.test+json", []byte(`{"ok":true}`))
	if digest != replayresult.Digest("application/cph.test+json", []byte(`{"ok":true}`)) {
		t.Fatal("PostgreSQL compatibility wrapper differs from the shared replay-result digest")
	}
	const expected = "c6f284d4953f954a4bed4cb15f8d618accad6bff4a0758dd37bd1f6c835d1071"
	if got := hex.EncodeToString(digest[:]); got != expected {
		t.Fatalf("durable-result digest changed: got %s want %s", got, expected)
	}
	if digest == DurableResultDigest("application/cph.test+json", []byte(`{"ok":false}`)) {
		t.Fatal("payload mutation did not change durable-result digest")
	}
	if digest == DurableResultDigest("application/octet-stream", []byte(`{"ok":true}`)) {
		t.Fatal("content-type mutation did not change durable-result digest")
	}
}

func TestDurableCompletionUsesSharedReplayResultBoundary(t *testing.T) {
	if maxContentTypeBytes != replayresult.MaxContentTypeBytes ||
		maxDurablePayloadBytes != replayresult.MaxPayloadBytes {
		t.Fatal("PostgreSQL durable-result bounds drifted from replayresult")
	}
	for _, completion := range []DurableCompletion{
		{ExternalEffects: NoExternalEffects},
		{ContentType: " application/cph.test", ExternalEffects: NoExternalEffects},
		{ContentType: "application/cph.\u2603", ExternalEffects: NoExternalEffects},
		{ContentType: strings.Repeat("a", replayresult.MaxContentTypeBytes+1), ExternalEffects: NoExternalEffects},
		{ContentType: "application/octet-stream", Payload: make([]byte, replayresult.MaxPayloadBytes+1), ExternalEffects: NoExternalEffects},
	} {
		if err := replayresult.Validate(completion.ContentType, completion.Payload); !errors.Is(err, replayresult.ErrInvalidResult) {
			t.Fatalf("shared boundary unexpectedly accepted %#v: %v", completion, err)
		}
		if err := validateCompletion(completion); !errors.Is(err, ErrInvalidCompletion) {
			t.Fatalf("PostgreSQL boundary error = %v, want %v", err, ErrInvalidCompletion)
		}
	}
}

func TestDurableCompletionRequiresExplicitEffectDisposition(t *testing.T) {
	valid := DurableCompletion{
		ContentType:     "application/cph.test+json",
		Payload:         []byte(`{"ok":true}`),
		ExternalEffects: NoExternalEffects,
	}
	if err := validateCompletion(valid); err != nil {
		t.Fatal(err)
	}
	valid.ExternalEffects = ExternalEffectsViaOutbox
	if err := validateCompletion(valid); !errors.Is(err, ErrInvalidCompletion) {
		t.Fatalf("missing outbox error = %v", err)
	}
	valid.Outbox = []OutboxIntent{{
		EventID:          [ccse.MessageIDSize]byte{1},
		Destination:      "cph.test.events.v1",
		DeduplicationKey: "test:1",
		ContentType:      "application/cph.test+json",
		Payload:          []byte(`{"event":1}`),
	}}
	if err := validateCompletion(valid); err != nil {
		t.Fatal(err)
	}
	valid.ExternalEffects = NoExternalEffects
	if err := validateCompletion(valid); !errors.Is(err, ErrInvalidCompletion) {
		t.Fatalf("unexpected outbox error = %v", err)
	}
	valid.ExternalEffects = ExternalEffectsViaOutbox
	valid.Outbox = append(valid.Outbox, OutboxIntent{
		EventID:          [ccse.MessageIDSize]byte{2},
		Destination:      "cph.test.events.v1",
		DeduplicationKey: "test:1",
		ContentType:      "application/cph.test+json",
	})
	if err := validateCompletion(valid); !errors.Is(err, ErrInvalidCompletion) {
		t.Fatalf("duplicate outbox identity error = %v", err)
	}
	valid.Outbox = valid.Outbox[:1]
	valid.Outbox[0].Destination = "cph.test.évents"
	if err := validateCompletion(valid); !errors.Is(err, ErrInvalidCompletion) {
		t.Fatalf("non-ASCII destination error = %v", err)
	}
}

func testReplayEntry() ccse.ReplayEntry {
	entry := ccse.ReplayEntry{
		MessageTypeID:  65537,
		SchemaVersion:  ccse.Version{Major: 1},
		CounterKind:    ccse.CounterSequence,
		ReplayDomainID: "cph.test.replay",
		SenderIdentity: "spiffe://test/provider/one",
		Environment:    "test",
		Sequence:       1,
		ExpiresAt:      2,
	}
	entry.ChainID[31] = 1
	entry.GenesisHash[0] = 2
	entry.MessageID[0] = 3
	entry.Digest[0] = 4
	return entry
}
