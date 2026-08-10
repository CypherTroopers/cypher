// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testMessageTypeID uint32 = 100

var (
	testProtocolVersion = Version{Major: 1, Minor: 0}
	testSchemaVersion   = Version{Major: 1, Minor: 0}
	testIssuedAt        = time.Unix(1_700_000_000, 123_456_789).UTC()
	testExpiresAt       = testIssuedAt.Add(5 * time.Minute)
)

type goldenOptionalString struct {
	Present bool   `json:"present"`
	Value   string `json:"value"`
}

type goldenOptionalHex struct {
	Present  bool   `json:"present"`
	ValueHex string `json:"value_hex"`
}

type goldenExtension struct {
	ID       uint32 `json:"id"`
	Critical bool   `json:"critical"`
	ValueHex string `json:"value_hex"`
}

type goldenVector struct {
	VectorID         string  `json:"vector_id"`
	Status           string  `json:"status"`
	Encoding         string  `json:"encoding"`
	MessageTypeScope string  `json:"message_type_scope"`
	MessageTypeID    uint32  `json:"message_type_id"`
	SchemaVersion    Version `json:"schema_version"`
	PrivateSeedHex   string  `json:"private_key_seed_hex"`
	Domain           struct {
		Purpose              string               `json:"purpose"`
		SenderIdentity       string               `json:"sender_identity"`
		Audience             []string             `json:"audience_set_unsorted"`
		TenantOrganization   goldenOptionalString `json:"tenant_organization"`
		ProviderOrganization goldenOptionalString `json:"provider_organization"`
		ChainIDHex           string               `json:"chain_id_uint256_hex"`
		GenesisHashHex       string               `json:"genesis_hash_hex"`
		Environment          string               `json:"environment"`
		ProtocolVersion      Version              `json:"protocol_version"`
		SignatureAlgorithm   uint32               `json:"signature_algorithm_id"`
		SignatureKeyID       string               `json:"signature_key_id"`
		IssuedAtUnixNano     int64                `json:"issued_at_unix_nano"`
		ExpiresAtUnixNano    int64                `json:"expires_at_unix_nano"`
		CounterKind          uint32               `json:"counter_kind"`
		Counter              uint64               `json:"counter"`
		ReplayDomainID       string               `json:"replay_domain_id"`
	} `json:"domain"`
	Envelope struct {
		MessageIDHex     string            `json:"message_id_hex"`
		CorrelationIDHex string            `json:"correlation_id_hex"`
		CausationID      goldenOptionalHex `json:"causation_id"`
		Extensions       []goldenExtension `json:"extensions"`
	} `json:"envelope"`
	Payload struct {
		SchemaNote   string               `json:"schema_note"`
		RecordKind   string               `json:"record_kind"`
		OptionalNote goldenOptionalString `json:"optional_note"`
		SampleCount  uint64               `json:"sample_count"`
		DisplayName  string               `json:"display_name"`
		Tags         []string             `json:"tags_set_unsorted"`
		CanonicalHex string               `json:"canonical_hex"`
	} `json:"payload_projection"`
	Expected struct {
		DomainHex    string `json:"canonical_domain_hex"`
		EnvelopeHex  string `json:"canonical_envelope_hex"`
		PreimageHex  string `json:"preimage_hex"`
		DigestHex    string `json:"sha256_digest_hex"`
		PublicKeyHex string `json:"ed25519_public_key_hex"`
		SignatureHex string `json:"ed25519_signature_hex"`
	} `json:"expected"`
}

type negativeVector struct {
	VectorSetID  string         `json:"vector_set_id"`
	BaseVectorID string         `json:"base_vector_id"`
	Status       string         `json:"status"`
	Cases        []negativeCase `json:"cases"`
}

type negativeCase struct {
	ID                string          `json:"id"`
	Operation         string          `json:"operation"`
	Path              string          `json:"path,omitempty"`
	Value             json.RawMessage `json:"value,omitempty"`
	ValueHex          string          `json:"value_hex,omitempty"`
	UnixNano          int64           `json:"unix_nano,omitempty"`
	RevokedAtUnixNano int64           `json:"revoked_at_unix_nano,omitempty"`
	ExtensionID       uint32          `json:"extension_id,omitempty"`
	Critical          bool            `json:"critical,omitempty"`
	NewKeyID          string          `json:"new_key_id,omitempty"`
	NewPrivateSeedHex string          `json:"new_private_key_seed_hex,omitempty"`
	ExpectedError     string          `json:"expected_error,omitempty"`
	ExpectedResult    string          `json:"expected_result,omitempty"`
}

func TestCCSEGoldenVector(t *testing.T) {
	vector := loadGoldenVector(t)
	record, publicKey, _ := signedTestRecord(t, nil)
	preimage, err := record.Preimage(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := record.Digest(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	domain, err := record.Domain.canonicalBytes(DefaultLimits().MaxDomainBytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := record.Envelope.canonicalBytes(DefaultLimits().MaxEnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if vector.MessageTypeID != record.MessageTypeID || vector.SchemaVersion != record.SchemaVersion {
		t.Fatalf("vector identity mismatch: type=%d schema=%+v", vector.MessageTypeID, vector.SchemaVersion)
	}
	assertHexEquals(t, "domain", domain, vector.Expected.DomainHex)
	assertHexEquals(t, "envelope", envelope, vector.Expected.EnvelopeHex)
	assertHexEquals(t, "payload", record.Payload, vector.Payload.CanonicalHex)
	assertHexEquals(t, "preimage", preimage, vector.Expected.PreimageHex)
	assertHexEquals(t, "digest", digest[:], vector.Expected.DigestHex)
	assertHexEquals(t, "public key", publicKey, vector.Expected.PublicKeyHex)
	assertHexEquals(t, "signature", record.Signature, vector.Expected.SignatureHex)
}

func TestCCSENegativeVectors(t *testing.T) {
	vector := loadNegativeVector(t)
	seen := make(map[string]struct{}, len(vector.Cases))
	for _, test := range vector.Cases {
		if _, duplicate := seen[test.ID]; duplicate {
			t.Fatalf("duplicate negative vector ID %q", test.ID)
		}
		seen[test.ID] = struct{}{}
		t.Run(test.ID, func(t *testing.T) {
			runNegativeVector(t, test)
		})
	}
}

func TestRecordFieldMutationsChangeDigest(t *testing.T) {
	base, _, _ := signedTestRecord(t, nil)
	baseDigest, err := base.Digest(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*Record)
	}{
		{name: "message type", mutate: func(r *Record) { r.MessageTypeID++ }},
		{name: "purpose", mutate: func(r *Record) { r.Domain.Purpose += ".other" }},
		{name: "audience", mutate: func(r *Record) { r.Domain.Audience = []string{"spiffe://cph/service/other"} }},
		{name: "tenant presence", mutate: func(r *Record) { r.Domain.TenantOrganization = OptionalString{Present: true} }},
		{name: "provider", mutate: func(r *Record) { r.Domain.ProviderOrganization.Value += ".other" }},
		{name: "genesis", mutate: func(r *Record) { r.Domain.GenesisHash[0] ^= 1 }},
		{name: "replay domain", mutate: func(r *Record) { r.Domain.ReplayDomainID += ".other" }},
		{name: "message ID", mutate: func(r *Record) { r.Envelope.MessageID[0] ^= 1 }},
		{name: "correlation ID", mutate: func(r *Record) { r.Envelope.CorrelationID[0] ^= 1 }},
		{name: "causation presence", mutate: func(r *Record) {
			r.Envelope.CausationID = OptionalMessageID{Present: true, Value: idFromHex(t, "303132333435363738393a3b3c3d3e3f")}
		}},
		{name: "extension", mutate: func(r *Record) { r.Envelope.Extensions = []Extension{{ID: 7, Value: []byte("v")}} }},
		{name: "payload", mutate: func(r *Record) {
			r.Payload = append([]byte(nil), r.Payload...)
			r.Payload[0] ^= 1
			r.Envelope.PayloadDigest = sha256.Sum256(r.Payload)
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			record := cloneRecord(base)
			mutation.mutate(record)
			digest, err := record.Digest(DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(digest[:], baseDigest[:]) {
				t.Fatal("mutation did not change digest")
			}
		})
	}
}

func TestVerifierAcceptsOnceAndClassifiesExactDuplicate(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if result.Duplicate {
		t.Fatal("first message classified as duplicate")
	}
	duplicate, err := verifier.Verify(context.Background(), record)
	if !errors.Is(err, ErrDuplicateMessage) || !duplicate.Duplicate || duplicate.Digest != result.Digest || duplicate.OutcomeDigest != result.OutcomeDigest {
		t.Fatalf("completed duplicate: result=%+v err=%v", duplicate, err)
	}
}

func TestVerifierAtomicHandlerFailureRollsBackReplayAdmission(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	wantErr := errors.New("business transaction aborted")
	calls := 0
	verifier.Handle = func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
		calls++
		if calls == 1 {
			return [DigestSize]byte{}, wantErr
		}
		return sha256.Sum256([]byte("durable retry outcome")), nil
	}
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, wantErr) {
		t.Fatalf("first handler error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatalf("safe retry failed: %v", err)
	}
	if calls != 2 || result.Duplicate || isZeroDigest(result.OutcomeDigest) {
		t.Fatalf("retry result=%+v calls=%d", result, calls)
	}
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("completed retry was not idempotent: %v", err)
	}
	if calls != 2 {
		t.Fatalf("duplicate invoked handler, calls=%d", calls)
	}
}

func TestVerifierAtomicReplayConcurrentAtMostOnce(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	var handlerCalls atomic.Int32
	verifier.Handle = func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
		handlerCalls.Add(1)
		return sha256.Sum256([]byte("concurrent durable outcome")), nil
	}
	const workers = 32
	var wg sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := verifier.Verify(context.Background(), record)
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(errorsSeen)
	applied, duplicates := 0, 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			applied++
		case errors.Is(err, ErrDuplicateMessage):
			duplicates++
		default:
			t.Fatalf("concurrent verification error: %v", err)
		}
	}
	if applied != 1 || duplicates != workers-1 || handlerCalls.Load() != 1 {
		t.Fatalf("applied=%d duplicates=%d handlerCalls=%d", applied, duplicates, handlerCalls.Load())
	}
}

func TestMemoryReplayStoreDoesNotBlockIndependentScopes(t *testing.T) {
	first, publicKey, privateKey := signedTestRecord(t, nil)
	second := cloneRecord(first)
	second.Domain.ReplayDomainID += ".independent"
	second.Envelope.MessageID[0] ^= 1
	if err := second.SignEd25519(privateKey, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	firstVerifier, _, shared := testVerifier(t, first, publicKey)
	secondVerifier, _, _ := testVerifier(t, second, publicKey)
	secondVerifier.Replay = shared
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
		started <- struct{}{}
		<-release
		return sha256.Sum256([]byte("independent outcome")), nil
	}
	firstVerifier.Handle = handler
	secondVerifier.Handle = handler
	errs := make(chan error, 2)
	go func() { _, err := firstVerifier.Verify(context.Background(), first); errs <- err }()
	go func() { _, err := secondVerifier.Verify(context.Background(), second); errs <- err }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("independent replay scope blocked behind another handler")
		}
	}
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestMemoryReplayStoreRejectsNestedScopeCycleAndCanceledWait(t *testing.T) {
	first, publicKey, privateKey := signedTestRecord(t, nil)
	second := cloneRecord(first)
	second.Domain.ReplayDomainID += ".nested"
	second.Envelope.MessageID[0] ^= 1
	if err := second.SignEd25519(privateKey, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	firstVerifier, _, shared := testVerifier(t, first, publicKey)
	secondVerifier, _, _ := testVerifier(t, second, publicKey)
	secondVerifier.Replay = shared
	firstVerifier.Handle = func(ctx context.Context, _ VerifiedRecord) ([DigestSize]byte, error) {
		secondVerifier.Handle = func(ctx context.Context, _ VerifiedRecord) ([DigestSize]byte, error) {
			_, err := firstVerifier.Verify(ctx, first)
			return [DigestSize]byte{}, err
		}
		_, err := secondVerifier.Verify(ctx, second)
		return [DigestSize]byte{}, err
	}
	if _, err := firstVerifier.Verify(context.Background(), first); !errors.Is(err, ErrReplayReentrant) {
		t.Fatalf("nested A-B-A replay cycle = %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	firstVerifier.Handle = func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
		close(entered)
		<-release
		return sha256.Sum256([]byte("lock holder outcome")), nil
	}
	done := make(chan error, 1)
	go func() { _, err := firstVerifier.Verify(context.Background(), first); done <- err }()
	<-entered
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := firstVerifier.Verify(canceled, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scope-lock wait = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVerifierRequiresAtomicHandlerAndNonzeroOutcome(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	verifier.Handle = nil
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrReplayHandlerRequired) {
		t.Fatalf("missing handler: %v", err)
	}
	verifier.Handle = func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
		return [DigestSize]byte{}, nil
	}
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrInvalidOutcomeDigest) {
		t.Fatalf("zero outcome: %v", err)
	}
	verifier.Handle = func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
		return sha256.Sum256([]byte("nonzero outcome")), nil
	}
	if _, err := verifier.Verify(context.Background(), record); err != nil {
		t.Fatalf("zero outcome left a replay reservation: %v", err)
	}
}

func TestVerifiedRecordIsDetachedFromInboundMutation(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := result.Verified.Payload()
	wantDomain := result.Verified.Domain()
	record.Payload[0] ^= 1
	record.Domain.Audience[0] = "spiffe://attacker.invalid"
	record.Envelope.Extensions = append(record.Envelope.Extensions, Extension{ID: 999, Value: []byte("mutated")})
	if !bytes.Equal(result.Verified.Payload(), wantPayload) {
		t.Fatal("verified payload changed after inbound mutation")
	}
	if got := result.Verified.Domain(); got.Audience[0] != wantDomain.Audience[0] {
		t.Fatal("verified domain changed after inbound mutation")
	}
}

func TestVerifierSnapshotsBeforeSchemaCallbacks(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	wantPayload := append([]byte(nil), record.Payload...)
	wantAudience := append([]string(nil), record.Domain.Audience...)
	verifier, _, _ := testVerifier(t, record, publicKey)
	verifier.Schema = testSchemaValidator(map[uint32]bool{}, func(context.Context, uint32, Version, []byte) error {
		// A callback can trigger unrelated caller activity, but it must not be
		// able to change the authorization snapshot under verification.
		record.Payload[0] ^= 1
		record.Domain.Audience[0] = "spiffe://attacker.invalid"
		return nil
	})
	result, err := verifier.Verify(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Verified.Payload(), wantPayload) {
		t.Fatal("schema callback changed verified payload")
	}
	if got := result.Verified.Domain().Audience; !slices.Equal(got, wantAudience) {
		t.Fatalf("schema callback changed audience: got %v want %v", got, wantAudience)
	}
}

func TestVerifierCanonicalizesObservableSignedSets(t *testing.T) {
	t.Run("audience", func(t *testing.T) {
		record, publicKey, _ := signedTestRecord(t, nil)
		want := append([]string(nil), record.Domain.Audience...)
		slices.Reverse(record.Domain.Audience)
		verifier, _, _ := testVerifier(t, record, publicKey)
		var observed []string
		verifier.Handle = func(_ context.Context, verified VerifiedRecord) ([DigestSize]byte, error) {
			observed = verified.Domain().Audience
			return sha256.Sum256([]byte("audience outcome")), nil
		}
		if _, err := verifier.Verify(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(observed, want) {
			t.Fatalf("handler audience order = %v, want canonical %v", observed, want)
		}
	})

	t.Run("extensions", func(t *testing.T) {
		record, publicKey, privateKey := signedTestRecord(t, func(record *Record) {
			record.Envelope.Extensions = []Extension{
				{ID: 20, Critical: false, Value: []byte("twenty")},
				{ID: 10, Critical: true, Value: []byte("ten")},
			}
		})
		if err := record.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		slices.Reverse(record.Envelope.Extensions)
		verifier, _, _ := testVerifier(t, record, publicKey)
		verifier.Schema = testSchemaValidator(map[uint32]bool{10: true, 20: false}, nil)
		var observed []Extension
		verifier.Handle = func(_ context.Context, verified VerifiedRecord) ([DigestSize]byte, error) {
			observed = verified.Envelope().Extensions
			return sha256.Sum256([]byte("extension outcome")), nil
		}
		if _, err := verifier.Verify(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		if len(observed) != 2 || observed[0].ID != 10 || observed[1].ID != 20 {
			t.Fatalf("handler extension order = %+v", observed)
		}
	})
}

func TestVerifierPreflightsVariableFieldsBeforeSnapshotOrCallbacks(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Record, Limits)
	}{
		{name: "domain string", mutate: func(record *Record, limits Limits) {
			record.Domain.Purpose = strings.Repeat("x", limits.MaxDomainBytes)
		}},
		{name: "extension value", mutate: func(record *Record, limits Limits) {
			record.Envelope.Extensions = []Extension{{ID: 1, Critical: true, Value: bytes.Repeat([]byte{1}, limits.MaxEnvelopeBytes)}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, publicKey, _ := signedTestRecord(t, nil)
			verifier, _, _ := testVerifier(t, record, publicKey)
			callbackCalls := 0
			verifier.Schema = SchemaValidatorFuncs{
				Extensions: func(context.Context, uint32, Version, []Extension) error { callbackCalls++; return nil },
				Payload:    func(context.Context, uint32, Version, []byte) error { callbackCalls++; return nil },
			}
			test.mutate(record, verifier.Limits)
			if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrProjectionTooLarge) {
				t.Fatalf("preflight error = %v", err)
			}
			if callbackCalls != 0 {
				t.Fatalf("schema callback ran %d times", callbackCalls)
			}
		})
	}
}

func TestVerifierRequiresCanonicalPayloadValidation(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	verifier.Schema = nil
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrSchemaValidatorRequired) {
		t.Fatalf("missing payload validator: got %v", err)
	}
	verifier.Schema = testSchemaValidator(map[uint32]bool{}, func(context.Context, uint32, Version, []byte) error { return errors.New("projection mismatch") })
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrNonCanonicalPayload) {
		t.Fatalf("noncanonical payload: got %v", err)
	}
}

func TestVerifierRejectsContextAndTimeMismatches(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	tests := []struct {
		name   string
		mutate func(*Verifier)
		want   error
	}{
		{name: "message type", mutate: func(v *Verifier) { v.Expectations.MessageTypeID++ }, want: ErrWrongMessageType},
		{name: "schema", mutate: func(v *Verifier) { v.Expectations.SchemaVersion.Minor++ }, want: ErrWrongSchemaVersion},
		{name: "protocol", mutate: func(v *Verifier) { v.Expectations.ProtocolVersion.Minor++ }, want: ErrWrongProtocolVersion},
		{name: "purpose", mutate: func(v *Verifier) { v.Expectations.Purpose += ".other" }, want: ErrWrongPurpose},
		{name: "audience", mutate: func(v *Verifier) { v.Expectations.Audience = []string{"spiffe://cph/service/other"} }, want: ErrWrongAudience},
		{name: "sender", mutate: func(v *Verifier) {
			v.Expectations.SenderIdentity = OptionalString{Present: true, Value: "spiffe://cph/agent/other"}
		}, want: ErrWrongSender},
		{name: "tenant", mutate: func(v *Verifier) { v.Expectations.TenantOrganization = OptionalString{Present: true, Value: "tenant"} }, want: ErrWrongTenant},
		{name: "provider", mutate: func(v *Verifier) { v.Expectations.ProviderOrganization.Value += ".other" }, want: ErrWrongProvider},
		{name: "environment", mutate: func(v *Verifier) { v.Expectations.Environment = "production" }, want: ErrWrongEnvironment},
		{name: "chain", mutate: func(v *Verifier) { v.Expectations.ChainID[31] ^= 1 }, want: ErrWrongChain},
		{name: "genesis", mutate: func(v *Verifier) { v.Expectations.GenesisHash[0] ^= 1 }, want: ErrWrongGenesis},
		{name: "replay domain", mutate: func(v *Verifier) { v.Expectations.ReplayDomainID += ".other" }, want: ErrWrongReplayDomain},
		{name: "counter kind", mutate: func(v *Verifier) { v.Expectations.CounterKind = CounterExpectedGeneration }, want: ErrWrongCounterKind},
		{name: "expired", mutate: func(v *Verifier) { v.Clock = ClockFunc(func() time.Time { return testExpiresAt.Add(time.Second) }) }, want: ErrExpired},
		{name: "future", mutate: func(v *Verifier) { v.Clock = ClockFunc(func() time.Time { return testIssuedAt.Add(-time.Minute) }) }, want: ErrNotYetValid},
		{name: "TTL", mutate: func(v *Verifier) { v.Expectations.MaxValidityWindow = time.Minute }, want: ErrValidityWindowTooLong},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, _, _ := testVerifier(t, record, publicKey)
			test.mutate(verifier)
			if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifierRejectsSignatureKeyExtensionAndReplayFailures(t *testing.T) {
	t.Run("bad signature", func(t *testing.T) {
		record, publicKey, _ := signedTestRecord(t, nil)
		record.Signature[0] ^= 1
		verifier, _, _ := testVerifier(t, record, publicKey)
		callbackCalls := 0
		verifier.Schema = SchemaValidatorFuncs{
			Extensions: func(context.Context, uint32, Version, []Extension) error {
				callbackCalls++
				return nil
			},
			Payload: func(context.Context, uint32, Version, []byte) error {
				callbackCalls++
				return nil
			},
		}
		if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("got %v", err)
		}
		if callbackCalls != 0 {
			t.Fatalf("schema callbacks ran %d times before signature authentication", callbackCalls)
		}
	})

	t.Run("unknown critical extension", func(t *testing.T) {
		record, publicKey, privateKey := signedTestRecord(t, func(r *Record) {
			r.Envelope.Extensions = []Extension{{ID: 77, Critical: true, Value: []byte("required")}}
		})
		if err := record.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		verifier, _, _ := testVerifier(t, record, publicKey)
		if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrUnknownCriticalExtension) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("known critical extension", func(t *testing.T) {
		record, publicKey, privateKey := signedTestRecord(t, func(r *Record) {
			r.Envelope.Extensions = []Extension{{ID: 77, Critical: true, Value: []byte("required")}}
		})
		if err := record.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		verifier, _, _ := testVerifier(t, record, publicKey)
		verifier.Schema = testSchemaValidator(map[uint32]bool{77: true}, nil)
		if _, err := verifier.Verify(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unknown noncritical extension", func(t *testing.T) {
		record, publicKey, privateKey := signedTestRecord(t, func(r *Record) {
			r.Envelope.Extensions = []Extension{{ID: 78, Critical: false, Value: []byte("optional")}}
		})
		if err := record.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		verifier, _, _ := testVerifier(t, record, publicKey)
		if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrUnknownExtension) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("criticality downgrade", func(t *testing.T) {
		record, publicKey, privateKey := signedTestRecord(t, func(r *Record) {
			r.Envelope.Extensions = []Extension{{ID: 77, Critical: false, Value: []byte("required")}}
		})
		if err := record.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		verifier, _, _ := testVerifier(t, record, publicKey)
		verifier.Schema = testSchemaValidator(map[uint32]bool{77: true}, nil)
		if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrExtensionCriticality) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("revoked key", func(t *testing.T) {
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, keys, _ := testVerifier(t, record, publicKey)
		if err := keys.Revoke(record.Domain.SignatureKeyID, testIssuedAt.Add(time.Minute).UnixNano()); err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrKeyRevoked) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("stale sequence", func(t *testing.T) {
		first, publicKey, privateKey := signedTestRecord(t, nil)
		verifier, _, replay := testVerifier(t, first, publicKey)
		if _, err := verifier.Verify(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		second := cloneRecord(first)
		second.Envelope.MessageID[0] ^= 1
		if err := second.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		verifier.Replay = replay
		if _, err := verifier.Verify(context.Background(), second); !errors.Is(err, ErrReplaySequence) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("message ID conflict", func(t *testing.T) {
		first, publicKey, privateKey := signedTestRecord(t, nil)
		verifier, _, replay := testVerifier(t, first, publicKey)
		if _, err := verifier.Verify(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		second := cloneRecord(first)
		second.Payload = append([]byte(nil), first.Payload...)
		second.Payload[len(second.Payload)-1] ^= 1
		second.Envelope.PayloadDigest = sha256.Sum256(second.Payload)
		if err := second.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		verifier.Replay = replay
		if _, err := verifier.Verify(context.Background(), second); !errors.Is(err, ErrMessageIDConflict) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestMemoryKeyRegistryRotation(t *testing.T) {
	first, firstPublic, _ := signedTestRecord(t, nil)
	verifier, keys, _ := testVerifier(t, first, firstPublic)
	if _, err := verifier.Verify(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	secondSeed := sha256.Sum256([]byte("CPH-AIIE test rotation key"))
	secondPrivate := ed25519.NewKeyFromSeed(secondSeed[:])
	secondPublic := secondPrivate.Public().(ed25519.PublicKey)
	second := cloneRecord(first)
	second.Domain.SignatureKeyID = "agent-key-0002"
	second.Envelope.SignatureKeyID = "agent-key-0002"
	second.Domain.Counter++
	second.Envelope.Counter++
	second.Envelope.MessageID[0] ^= 1
	if err := second.SignEd25519(secondPrivate, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := keys.Add(KeyRecord{
		KeyID:               second.Domain.SignatureKeyID,
		SubjectIdentity:     second.Domain.SenderIdentity,
		Algorithm:           SignatureAlgorithmEd25519,
		PublicKey:           secondPublic,
		NotBeforeUnixNano:   testIssuedAt.Add(-time.Minute).UnixNano(),
		NotAfterUnixNano:    testExpiresAt.Add(time.Hour).UnixNano(),
		AllowedMessageTypes: []uint32{testMessageTypeID},
	}); err != nil {
		t.Fatal(err)
	}
	if err := keys.Revoke(first.Domain.SignatureKeyID, testIssuedAt.Add(time.Minute).UnixNano()); err != nil {
		t.Fatal(err)
	}
	stale := cloneRecord(second)
	stale.Domain.Counter--
	stale.Envelope.Counter--
	stale.Envelope.MessageID[1] ^= 1
	if err := stale.SignEd25519(secondPrivate, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), stale); !errors.Is(err, ErrReplaySequence) {
		t.Fatalf("key rotation reset replay namespace: got %v", err)
	}
	if _, err := verifier.Verify(context.Background(), second); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
}

func TestVerifierRequiresOperationWindowInsideKeyValidity(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	keys := NewMemoryKeyRegistry()
	if err := keys.Add(KeyRecord{
		KeyID:               record.Domain.SignatureKeyID,
		SubjectIdentity:     record.Domain.SenderIdentity,
		Algorithm:           SignatureAlgorithmEd25519,
		PublicKey:           publicKey,
		NotBeforeUnixNano:   testIssuedAt.Add(-time.Hour).UnixNano(),
		NotAfterUnixNano:    testExpiresAt.Add(-time.Nanosecond).UnixNano(),
		AllowedMessageTypes: []uint32{testMessageTypeID},
	}); err != nil {
		t.Fatal(err)
	}
	verifier.Keys = keys
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("operation outlives key but got %v", err)
	}
}

func TestVerifierRejectsKeyBeforeActivationEvenWithinClockSkew(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	keys := NewMemoryKeyRegistry()
	if err := keys.Add(KeyRecord{
		KeyID:               record.Domain.SignatureKeyID,
		SubjectIdentity:     record.Domain.SenderIdentity,
		Algorithm:           SignatureAlgorithmEd25519,
		PublicKey:           publicKey,
		NotBeforeUnixNano:   testIssuedAt.UnixNano(),
		NotAfterUnixNano:    testExpiresAt.Add(time.Hour).UnixNano(),
		AllowedMessageTypes: []uint32{testMessageTypeID},
	}); err != nil {
		t.Fatal(err)
	}
	verifier.Keys = keys
	verifier.Clock = ClockFunc(func() time.Time { return testIssuedAt.Add(-time.Second) })
	verifier.Expectations.MaxClockSkew = 2 * time.Second
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("future key accepted within operation clock skew: %v", err)
	}
}

func TestRecordBoundsAndBinding(t *testing.T) {
	record, _, _ := signedTestRecord(t, nil)
	negative := DefaultLimits()
	negative.MaxEnvelopeBytes = -1
	if _, err := record.Preimage(negative); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative limit: got %v", err)
	}
	limits := DefaultLimits()
	limits.MaxPayloadBytes = len(record.Payload) - 1
	if _, err := record.Preimage(limits); !errors.Is(err, ErrProjectionTooLarge) {
		t.Fatalf("oversize payload: got %v", err)
	}
	broken := cloneRecord(record)
	broken.Envelope.Counter++
	if _, err := broken.Preimage(DefaultLimits()); !errors.Is(err, ErrDomainEnvelopeMismatch) {
		t.Fatalf("domain/envelope mismatch: got %v", err)
	}
	broken = cloneRecord(record)
	broken.Payload[0] ^= 1
	if _, err := broken.Preimage(DefaultLimits()); !errors.Is(err, ErrPayloadDigestMismatch) {
		t.Fatalf("payload digest mismatch: got %v", err)
	}
	broken = cloneRecord(record)
	broken.Envelope.CausationID.Value[0] = 1
	if _, err := broken.Preimage(DefaultLimits()); !errors.Is(err, ErrNonCanonicalAbsent) {
		t.Fatalf("hidden absent causation value: got %v", err)
	}
}

func TestVerifierRejectsNegativeLimits(t *testing.T) {
	record, publicKey, _ := signedTestRecord(t, nil)
	verifier, _, _ := testVerifier(t, record, publicKey)
	verifier.Limits.MaxPayloadBytes = -1
	if _, err := verifier.Verify(context.Background(), record); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative verifier limit: got %v", err)
	}
}

func FuzzSignedPayloadMutationRejected(f *testing.F) {
	f.Add([]byte{1})
	f.Add([]byte("mutation"))
	f.Fuzz(func(t *testing.T, mutation []byte) {
		if len(mutation) == 0 || len(mutation) > 1024 {
			t.Skip()
		}
		record, publicKey, _ := signedTestRecord(t, nil)
		index := int(mutation[0]) % len(record.Payload)
		delta := mutation[len(mutation)-1]
		if delta == 0 {
			delta = 1
		}
		record.Payload[index] ^= delta
		verifier, _, _ := testVerifier(t, record, publicKey)
		if _, err := verifier.Verify(context.Background(), record); err == nil {
			t.Fatal("mutated signed payload accepted")
		}
	})
}

func signedTestRecord(t testing.TB, mutate func(*Record)) (*Record, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	vector := loadGoldenVector(t)
	seed, err := hex.DecodeString(vector.PrivateSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("golden seed length %d", len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payload, err := Marshal(4096, func(e *Encoder) {
		e.String(vector.Payload.RecordKind)
		e.OptionalString(vector.Payload.OptionalNote.Present, vector.Payload.OptionalNote.Value)
		e.Uint64(vector.Payload.SampleCount)
		e.String(vector.Payload.DisplayName)
		e.StringSet(vector.Payload.Tags)
	})
	if err != nil {
		t.Fatal(err)
	}
	chainID := fixed32FromHex(t, vector.Domain.ChainIDHex)
	genesis := fixed32FromHex(t, vector.Domain.GenesisHashHex)
	domain := Domain{
		Purpose:              vector.Domain.Purpose,
		SenderIdentity:       vector.Domain.SenderIdentity,
		Audience:             append([]string(nil), vector.Domain.Audience...),
		TenantOrganization:   OptionalString{Present: vector.Domain.TenantOrganization.Present, Value: vector.Domain.TenantOrganization.Value},
		ProviderOrganization: OptionalString{Present: vector.Domain.ProviderOrganization.Present, Value: vector.Domain.ProviderOrganization.Value},
		ChainID:              chainID,
		GenesisHash:          genesis,
		Environment:          vector.Domain.Environment,
		ProtocolVersion:      vector.Domain.ProtocolVersion,
		SchemaVersion:        vector.SchemaVersion,
		SignatureAlgorithm:   SignatureAlgorithmID(vector.Domain.SignatureAlgorithm),
		SignatureKeyID:       vector.Domain.SignatureKeyID,
		IssuedAtUnixNano:     vector.Domain.IssuedAtUnixNano,
		ExpiresAtUnixNano:    vector.Domain.ExpiresAtUnixNano,
		CounterKind:          CounterKind(vector.Domain.CounterKind),
		Counter:              vector.Domain.Counter,
		ReplayDomainID:       vector.Domain.ReplayDomainID,
	}
	envelope := Envelope{
		ProtocolVersion:    domain.ProtocolVersion,
		SchemaVersion:      vector.SchemaVersion,
		MessageID:          idFromHex(t, vector.Envelope.MessageIDHex),
		CorrelationID:      idFromHex(t, vector.Envelope.CorrelationIDHex),
		SenderIdentity:     domain.SenderIdentity,
		ChainID:            chainID,
		Environment:        domain.Environment,
		IssuedAtUnixNano:   domain.IssuedAtUnixNano,
		ExpiresAtUnixNano:  domain.ExpiresAtUnixNano,
		CounterKind:        domain.CounterKind,
		Counter:            domain.Counter,
		SignatureAlgorithm: domain.SignatureAlgorithm,
		SignatureKeyID:     domain.SignatureKeyID,
	}
	if vector.Envelope.CausationID.Present {
		envelope.CausationID = OptionalMessageID{Present: true, Value: idFromHex(t, vector.Envelope.CausationID.ValueHex)}
	} else if vector.Envelope.CausationID.ValueHex != "" {
		t.Fatal("absent golden causation ID retains a value")
	}
	for _, extension := range vector.Envelope.Extensions {
		value, err := hex.DecodeString(extension.ValueHex)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Extensions = append(envelope.Extensions, Extension{ID: extension.ID, Critical: extension.Critical, Value: value})
	}
	record, err := NewRecord(vector.MessageTypeID, vector.SchemaVersion, domain, envelope, payload)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(record)
	}
	if err := record.SignEd25519(privateKey, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	return record, append(ed25519.PublicKey(nil), publicKey...), append(ed25519.PrivateKey(nil), privateKey...)
}

func testVerifier(t testing.TB, record *Record, publicKey ed25519.PublicKey) (*Verifier, *MemoryKeyRegistry, *MemoryReplayStore) {
	t.Helper()
	keys := NewMemoryKeyRegistry()
	if err := keys.Add(KeyRecord{
		KeyID:               record.Domain.SignatureKeyID,
		SubjectIdentity:     record.Domain.SenderIdentity,
		Algorithm:           SignatureAlgorithmEd25519,
		PublicKey:           publicKey,
		NotBeforeUnixNano:   testIssuedAt.Add(-time.Hour).UnixNano(),
		NotAfterUnixNano:    testExpiresAt.Add(time.Hour).UnixNano(),
		AllowedMessageTypes: []uint32{testMessageTypeID},
	}); err != nil {
		t.Fatal(err)
	}
	replay := NewMemoryReplayStore()
	return &Verifier{
		Expectations: Expectations{
			MessageTypeID:        testMessageTypeID,
			SchemaVersion:        testSchemaVersion,
			ProtocolVersion:      testProtocolVersion,
			Purpose:              record.Domain.Purpose,
			SenderIdentity:       OptionalString{Present: true, Value: record.Domain.SenderIdentity},
			Audience:             append([]string(nil), record.Domain.Audience...),
			TenantOrganization:   record.Domain.TenantOrganization,
			ProviderOrganization: record.Domain.ProviderOrganization,
			Environment:          record.Domain.Environment,
			ChainID:              record.Domain.ChainID,
			GenesisHash:          record.Domain.GenesisHash,
			ReplayDomainID:       record.Domain.ReplayDomainID,
			CounterKind:          record.Domain.CounterKind,
			MaxClockSkew:         0,
			MaxValidityWindow:    10 * time.Minute,
		},
		Limits: DefaultLimits(),
		Clock:  ClockFunc(func() time.Time { return testIssuedAt.Add(time.Minute) }),
		Keys:   keys,
		Replay: replay,
		Schema: testSchemaValidator(map[uint32]bool{}, func(_ context.Context, messageTypeID uint32, version Version, payload []byte) error {
			if messageTypeID != testMessageTypeID || version != testSchemaVersion || len(payload) == 0 {
				return ErrNonCanonicalPayload
			}
			return nil
		}),
		Handle: func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
			return sha256.Sum256([]byte("ccse test durable outcome")), nil
		},
	}, keys, replay
}

func idFromHex(t testing.TB, value string) [MessageIDSize]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != MessageIDSize {
		t.Fatalf("ID length %d", len(decoded))
	}
	var id [MessageIDSize]byte
	copy(id[:], decoded)
	return id
}

func fixed32FromHex(t testing.TB, value string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("fixed32 length %d", len(decoded))
	}
	var out [32]byte
	copy(out[:], decoded)
	return out
}

func loadGoldenVector(t testing.TB) goldenVector {
	t.Helper()
	file, err := os.Open("testdata/ccse_v1_ed25519_positive.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var vector goldenVector
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("golden vector has trailing JSON: %v", err)
	}
	if vector.VectorID != "ccse-v1-ed25519-conformance-0001" || vector.Status != "candidate" ||
		vector.Encoding != "CPH Canonical Signing Encoding v1" || vector.MessageTypeID != testMessageTypeID ||
		vector.SchemaVersion != testSchemaVersion || vector.Domain.ProtocolVersion != testProtocolVersion ||
		vector.Domain.IssuedAtUnixNano != testIssuedAt.UnixNano() || vector.Domain.ExpiresAtUnixNano != testExpiresAt.UnixNano() ||
		vector.PrivateSeedHex == "" || vector.Payload.SchemaNote == "" || vector.Payload.CanonicalHex == "" ||
		vector.Expected.DomainHex == "" || vector.Expected.EnvelopeHex == "" || vector.Expected.PreimageHex == "" ||
		vector.Expected.DigestHex == "" || vector.Expected.PublicKeyHex == "" || vector.Expected.SignatureHex == "" {
		t.Fatal("golden vector metadata or required value is invalid")
	}
	return vector
}

func loadNegativeVector(t testing.TB) negativeVector {
	t.Helper()
	file, err := os.Open("testdata/ccse_v1_negative.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var vector negativeVector
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("negative vector has trailing JSON: %v", err)
	}
	if vector.VectorSetID != "ccse-v1-negative-conformance-0001" || vector.BaseVectorID != "ccse-v1-ed25519-conformance-0001" || vector.Status != "candidate" || len(vector.Cases) == 0 {
		t.Fatal("negative vector metadata is invalid")
	}
	required := map[string]bool{
		"present-empty-is-not-absent": false, "non-nfc-string": false,
		"set-permutation": false, "set-duplicate": false,
		"wrong-audience": false, "wrong-environment": false,
		"wrong-chain": false, "wrong-genesis": false, "expired": false,
		"unknown-critical-extension": false, "unknown-noncritical-extension": false,
		"revoked-key": false, "exact-message-duplicate": false,
		"handler-rollback-safe-retry": false, "sequence-replay": false,
		"key-rotation-does-not-reset-replay": false,
		"message-id-conflict":                false, "algorithm-downgrade": false,
	}
	for _, test := range vector.Cases {
		if _, exists := required[test.ID]; !exists {
			t.Fatalf("unregistered negative vector case %q", test.ID)
		}
		if required[test.ID] {
			t.Fatalf("duplicate negative vector case %q", test.ID)
		}
		required[test.ID] = true
	}
	for id, present := range required {
		if !present {
			t.Fatalf("missing required negative vector case %q", id)
		}
	}
	return vector
}

func runNegativeVector(t *testing.T, test negativeCase) {
	t.Helper()
	var (
		gotError  error
		gotResult string
	)
	switch test.Operation {
	case "compare_digest":
		if test.Path != "domain.tenant_organization.present" {
			t.Fatalf("unsupported compare path %q", test.Path)
		}
		var present bool
		decodeNegativeValue(t, test.Value, &present)
		base, _, _ := signedTestRecord(t, nil)
		before, err := base.Digest(DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		changed := cloneRecord(base)
		changed.Domain.TenantOrganization = OptionalString{Present: present}
		after, err := changed.Digest(DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if before != after {
			gotResult = "DIFFERENT_DIGEST"
		} else {
			gotResult = "SAME_DIGEST"
		}

	case "encode":
		switch test.Path {
		case "payload_projection.display_name":
			var value string
			decodeNegativeValue(t, test.Value, &value)
			_, gotError = Marshal(4096, func(e *Encoder) { e.String(value) })
		case "payload_projection.tags_set_unsorted":
			var value []string
			decodeNegativeValue(t, test.Value, &value)
			_, gotError = Marshal(4096, func(e *Encoder) { e.StringSet(value) })
		default:
			t.Fatalf("unsupported encode path %q", test.Path)
		}

	case "encode_equivalent":
		if test.Path != "payload_projection.tags_set_unsorted" {
			t.Fatalf("unsupported equivalent path %q", test.Path)
		}
		var value []string
		decodeNegativeValue(t, test.Value, &value)
		baseVector := loadGoldenVector(t)
		first, err := Marshal(4096, func(e *Encoder) { e.StringSet(baseVector.Payload.Tags) })
		if err != nil {
			t.Fatal(err)
		}
		second, err := Marshal(4096, func(e *Encoder) { e.StringSet(value) })
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, second) {
			gotResult = "SAME_CANONICAL_BYTES"
		} else {
			gotResult = "DIFFERENT_CANONICAL_BYTES"
		}

	case "verify_with":
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, record, publicKey)
		switch test.Path {
		case "expectations.audience":
			decodeNegativeValue(t, test.Value, &verifier.Expectations.Audience)
		case "expectations.environment":
			decodeNegativeValue(t, test.Value, &verifier.Expectations.Environment)
		case "expectations.chain_id":
			verifier.Expectations.ChainID = fixed32FromHex(t, test.ValueHex)
		case "expectations.genesis_hash":
			verifier.Expectations.GenesisHash = fixed32FromHex(t, test.ValueHex)
		default:
			t.Fatalf("unsupported verify path %q", test.Path)
		}
		_, gotError = verifier.Verify(context.Background(), record)

	case "verify_at":
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, record, publicKey)
		verifier.Clock = ClockFunc(func() time.Time { return time.Unix(0, test.UnixNano).UTC() })
		_, gotError = verifier.Verify(context.Background(), record)

	case "resign_with_extension":
		record, publicKey, _ := signedTestRecord(t, func(record *Record) {
			record.Envelope.Extensions = []Extension{{ID: test.ExtensionID, Critical: test.Critical, Value: []byte("vector-extension")}}
		})
		verifier, _, _ := testVerifier(t, record, publicKey)
		_, gotError = verifier.Verify(context.Background(), record)

	case "revoke_then_verify":
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, keys, _ := testVerifier(t, record, publicKey)
		if err := keys.Revoke(record.Domain.SignatureKeyID, test.RevokedAtUnixNano); err != nil {
			t.Fatal(err)
		}
		_, gotError = verifier.Verify(context.Background(), record)

	case "verify_complete_then_verify_again":
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, record, publicKey)
		if _, err := verifier.Verify(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		_, gotError = verifier.Verify(context.Background(), record)

	case "handler_error_then_retry":
		record, publicKey, _ := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, record, publicKey)
		calls := 0
		verifier.Handle = func(context.Context, VerifiedRecord) ([DigestSize]byte, error) {
			calls++
			if calls == 1 {
				return [DigestSize]byte{}, errors.New("vector transaction rollback")
			}
			return sha256.Sum256([]byte("vector retry outcome")), nil
		}
		if _, err := verifier.Verify(context.Background(), record); err == nil {
			t.Fatal("first transactional handler did not fail")
		}
		if result, err := verifier.Verify(context.Background(), record); err == nil && !result.Duplicate && calls == 2 {
			gotResult = "RETRY_APPLIED_AFTER_ROLLBACK"
		} else {
			gotError = err
		}

	case "new_message_same_sequence":
		first, publicKey, privateKey := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, first, publicKey)
		if _, err := verifier.Verify(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		second := cloneRecord(first)
		second.Envelope.MessageID[0] ^= 1
		if err := second.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		_, gotError = verifier.Verify(context.Background(), second)

	case "rotate_key_new_message_same_sequence":
		first, publicKey, _ := signedTestRecord(t, nil)
		verifier, keys, _ := testVerifier(t, first, publicKey)
		if _, err := verifier.Verify(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		seed, err := hex.DecodeString(test.NewPrivateSeedHex)
		if err != nil || len(seed) != ed25519.SeedSize || test.NewKeyID == "" {
			t.Fatalf("invalid rotation vector key material: key_id=%q seed_err=%v seed_len=%d", test.NewKeyID, err, len(seed))
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		rotated := cloneRecord(first)
		rotated.Domain.SignatureKeyID = test.NewKeyID
		rotated.Envelope.SignatureKeyID = test.NewKeyID
		rotated.Envelope.MessageID[0] ^= 1
		if err := rotated.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		if err := keys.Add(KeyRecord{
			KeyID:               test.NewKeyID,
			SubjectIdentity:     rotated.Domain.SenderIdentity,
			Algorithm:           SignatureAlgorithmEd25519,
			PublicKey:           privateKey.Public().(ed25519.PublicKey),
			NotBeforeUnixNano:   testIssuedAt.Add(-time.Minute).UnixNano(),
			NotAfterUnixNano:    testExpiresAt.Add(time.Hour).UnixNano(),
			AllowedMessageTypes: []uint32{testMessageTypeID},
		}); err != nil {
			t.Fatal(err)
		}
		_, gotError = verifier.Verify(context.Background(), rotated)

	case "same_message_id_different_payload":
		first, publicKey, privateKey := signedTestRecord(t, nil)
		verifier, _, _ := testVerifier(t, first, publicKey)
		if _, err := verifier.Verify(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		second := cloneRecord(first)
		second.Payload[0] ^= 1
		second.Envelope.PayloadDigest = sha256.Sum256(second.Payload)
		if err := second.SignEd25519(privateKey, DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		_, gotError = verifier.Verify(context.Background(), second)

	case "mutate_domain_and_envelope":
		if test.Path != "signature_algorithm_id" {
			t.Fatalf("unsupported mutation path %q", test.Path)
		}
		var value uint32
		decodeNegativeValue(t, test.Value, &value)
		record, _, _ := signedTestRecord(t, nil)
		record.Domain.SignatureAlgorithm = SignatureAlgorithmID(value)
		record.Envelope.SignatureAlgorithm = SignatureAlgorithmID(value)
		_, gotError = record.Preimage(DefaultLimits())

	default:
		t.Fatalf("unsupported negative-vector operation %q", test.Operation)
	}

	if test.ExpectedError != "" {
		if code := ccseErrorCode(gotError); code != test.ExpectedError {
			t.Fatalf("error code %q (%v), want %q", code, gotError, test.ExpectedError)
		}
		return
	}
	if gotError != nil {
		t.Fatalf("unexpected error: %v", gotError)
	}
	if gotResult != test.ExpectedResult {
		t.Fatalf("result %q, want %q", gotResult, test.ExpectedResult)
	}
}

func decodeNegativeValue(t testing.TB, raw json.RawMessage, target any) {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("negative vector is missing value")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("negative value has trailing JSON: %v", err)
	}
}

func ccseErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNonNFCString):
		return "NON_NFC_STRING"
	case errors.Is(err, ErrDuplicateSetValue):
		return "DUPLICATE_SET_VALUE"
	case errors.Is(err, ErrWrongAudience):
		return "WRONG_AUDIENCE"
	case errors.Is(err, ErrWrongEnvironment):
		return "WRONG_ENVIRONMENT"
	case errors.Is(err, ErrWrongChain):
		return "WRONG_CHAIN"
	case errors.Is(err, ErrWrongGenesis):
		return "WRONG_GENESIS"
	case errors.Is(err, ErrExpired):
		return "EXPIRED"
	case errors.Is(err, ErrUnknownCriticalExtension):
		return "UNKNOWN_CRITICAL_EXTENSION"
	case errors.Is(err, ErrUnknownExtension):
		return "UNKNOWN_EXTENSION"
	case errors.Is(err, ErrKeyRevoked):
		return "KEY_REVOKED"
	case errors.Is(err, ErrDuplicateMessage):
		return "DUPLICATE_MESSAGE_USE_IDEMPOTENT_RESULT"
	case errors.Is(err, ErrReplaySequence):
		return "REPLAY_SEQUENCE"
	case errors.Is(err, ErrMessageIDConflict):
		return "MESSAGE_ID_CONFLICT"
	case errors.Is(err, ErrInvalidRecord):
		return "INVALID_RECORD_UNSPECIFIED_ALGORITHM"
	default:
		return "UNCLASSIFIED"
	}
}

func assertHexEquals(t testing.TB, name string, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("%s vector hex: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s vector mismatch\n got %x\nwant %x", name, got, want)
	}
}

func testSchemaValidator(knownExtensions map[uint32]bool, payload func(context.Context, uint32, Version, []byte) error) SchemaValidator {
	if payload == nil {
		payload = func(_ context.Context, messageTypeID uint32, version Version, value []byte) error {
			if messageTypeID != testMessageTypeID || version != testSchemaVersion || len(value) == 0 {
				return ErrNonCanonicalPayload
			}
			return nil
		}
	}
	return SchemaValidatorFuncs{
		Payload: payload,
		Extensions: func(_ context.Context, _ uint32, _ Version, extensions []Extension) error {
			for _, extension := range extensions {
				critical, known := knownExtensions[extension.ID]
				if !known {
					if extension.Critical {
						return ErrUnknownCriticalExtension
					}
					return ErrUnknownExtension
				}
				if extension.Critical != critical {
					return ErrExtensionCriticality
				}
				if len(extension.Value) == 0 || len(extension.Value) > 256 {
					return ErrInvalidExtension
				}
			}
			return nil
		},
	}
}
