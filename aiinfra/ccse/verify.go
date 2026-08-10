// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrWrongMessageType         = errors.New("ccse: unexpected message type")
	ErrWrongSchemaVersion       = errors.New("ccse: unexpected schema version")
	ErrWrongProtocolVersion     = errors.New("ccse: unexpected protocol version")
	ErrWrongPurpose             = errors.New("ccse: unexpected message purpose")
	ErrWrongAudience            = errors.New("ccse: unexpected audience")
	ErrWrongSender              = errors.New("ccse: unexpected sender")
	ErrWrongTenant              = errors.New("ccse: unexpected tenant organization")
	ErrWrongProvider            = errors.New("ccse: unexpected provider organization")
	ErrWrongEnvironment         = errors.New("ccse: unexpected deployment environment")
	ErrWrongChain               = errors.New("ccse: unexpected chain identifier")
	ErrWrongGenesis             = errors.New("ccse: unexpected genesis hash")
	ErrWrongReplayDomain        = errors.New("ccse: unexpected replay domain")
	ErrWrongCounterKind         = errors.New("ccse: unexpected counter kind")
	ErrNotYetValid              = errors.New("ccse: operation is not yet valid")
	ErrExpired                  = errors.New("ccse: operation has expired")
	ErrValidityWindowTooLong    = errors.New("ccse: validity window exceeds policy")
	ErrUnknownCriticalExtension = errors.New("ccse: unknown critical extension")
	ErrUnknownExtension         = errors.New("ccse: extension is not registered by the schema")
	ErrUnknownKey               = errors.New("ccse: unknown signature key")
	ErrKeySubjectMismatch       = errors.New("ccse: key subject does not match sender")
	ErrKeyNotActive             = errors.New("ccse: key was not active when issued")
	ErrKeyRevoked               = errors.New("ccse: signature key is revoked")
	ErrKeyNotAuthorized         = errors.New("ccse: key is not authorized for message type")
	ErrDuplicateMessage         = errors.New("ccse: duplicate message must use idempotent result")
	ErrMessageIDConflict        = errors.New("ccse: message identifier reused with different authorization")
	ErrReplaySequence           = errors.New("ccse: replayed or stale sequence")
	ErrReplayStoreRequired      = errors.New("ccse: replay store is required")
	ErrReplayHandlerRequired    = errors.New("ccse: atomic replay handler is required")
	ErrReplayReentrant          = errors.New("ccse: reentrant replay execution in the same scope")
	ErrInvalidOutcomeDigest     = errors.New("ccse: handler returned an empty outcome digest")
	ErrSchemaValidatorRequired  = errors.New("ccse: canonical schema validator is required")
	ErrNonCanonicalPayload      = errors.New("ccse: payload is not canonical for its schema")
	ErrExtensionCriticality     = errors.New("ccse: extension criticality conflicts with schema")
	ErrClockRequired            = errors.New("ccse: verification clock is required")
	ErrKeyResolverRequired      = errors.New("ccse: key resolver is required")
)

// Clock makes expiry behavior deterministic in tests and prevents schema code
// from consulting a host clock implicitly.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// SystemClock is the explicit production wall-clock implementation.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// KeyRecord is authorization metadata resolved from the identity/key registry.
// PublicKey is copied by MemoryKeyRegistry. Revocation is permanent and checked
// at verification time, not merely at issuance time.
type KeyRecord struct {
	KeyID               string
	SubjectIdentity     string
	Algorithm           SignatureAlgorithmID
	PublicKey           []byte
	NotBeforeUnixNano   int64
	NotAfterUnixNano    int64
	RevokedAtUnixNano   int64
	AllowedMessageTypes []uint32
}

// KeyResolver resolves an exact key ID. Implementations must not silently fall
// back to another key, algorithm, subject, or historical alias.
type KeyResolver interface {
	ResolveKey(context.Context, string) (KeyRecord, error)
}

// ReplayStatus distinguishes an operation applied in the authoritative
// transaction from an exact duplicate with an already durable outcome.
type ReplayStatus uint8

const (
	ReplayApplied ReplayStatus = iota + 1
	ReplayDuplicateCompleted
)

// ReplayDecision returns only a digest of the durable idempotent outcome. The
// service retrieves the actual response from its authoritative inbox/result
// store and verifies that digest before returning it.
type ReplayDecision struct {
	Status        ReplayStatus
	OutcomeDigest [DigestSize]byte
}

// ReplayEntry is the complete authorization identity needed for an atomic
// replay decision.
type ReplayEntry struct {
	MessageTypeID  uint32
	SchemaVersion  Version
	CounterKind    CounterKind
	ReplayDomainID string
	SenderIdentity string
	Environment    string
	ChainID        [32]byte
	GenesisHash    [DigestSize]byte
	MessageID      [MessageIDSize]byte
	Sequence       uint64
	Digest         [DigestSize]byte
	ExpiresAt      int64
}

// Validate rejects an incomplete replay identity before a store performs any
// database work. Durable ReplayStore implementations must call this method as
// callers may use a store independently of Verifier.
func (entry ReplayEntry) Validate() error {
	return validateReplayEntry(entry)
}

// ReplayHandler performs only the authoritative business transition and writes
// its durable result/outbox using the transaction carried by ctx. It must not
// perform a non-transactional external side effect.
type ReplayHandler func(context.Context, VerifiedRecord) ([DigestSize]byte, error)

// ReplayStore atomically checks replay state, invokes apply for a first-seen
// authorization, and commits the inbox row, business transition, outcome and
// outbox together. If apply fails or the process/transaction aborts, none of
// those effects may remain and a retry is safe. Exact completed duplicates do
// not invoke apply. A local cache does not satisfy the production contract.
type ReplayStore interface {
	Execute(context.Context, ReplayEntry, VerifiedRecord, ReplayHandler) (ReplayDecision, error)
}

// SchemaValidator is the sole authority for a message type's canonical payload
// and extension policy. It must reject every unregistered signed extension,
// including one marked noncritical by the sender. Transport-only unknown fields
// may be ignored only outside the signed projection under registry policy.
// Payload validation runs only after signature authentication. Decoding
// Protobuf wire bytes is not canonical validation.
type SchemaValidator interface {
	ValidateCanonicalPayload(context.Context, uint32, Version, []byte) error
	ValidateExtensions(context.Context, uint32, Version, []Extension) error
}

// SchemaValidatorFuncs adapts explicit payload and extension validators.
type SchemaValidatorFuncs struct {
	Payload    func(context.Context, uint32, Version, []byte) error
	Extensions func(context.Context, uint32, Version, []Extension) error
}

func (f SchemaValidatorFuncs) ValidateCanonicalPayload(ctx context.Context, messageTypeID uint32, version Version, payload []byte) error {
	if f.Payload == nil {
		return ErrSchemaValidatorRequired
	}
	return f.Payload(ctx, messageTypeID, version, payload)
}

func (f SchemaValidatorFuncs) ValidateExtensions(ctx context.Context, messageTypeID uint32, version Version, extensions []Extension) error {
	if f.Extensions == nil {
		return ErrSchemaValidatorRequired
	}
	return f.Extensions(ctx, messageTypeID, version, extensions)
}

// Expectations is a fail-closed receiving policy. All identity and deployment
// fields are exact matches; ExpectedAudience is an exact declared set.
type Expectations struct {
	MessageTypeID        uint32
	SchemaVersion        Version
	ProtocolVersion      Version
	Purpose              string
	SenderIdentity       OptionalString
	Audience             []string
	TenantOrganization   OptionalString
	ProviderOrganization OptionalString
	Environment          string
	ChainID              [32]byte
	GenesisHash          [DigestSize]byte
	ReplayDomainID       string
	CounterKind          CounterKind
	MaxClockSkew         time.Duration
	MaxValidityWindow    time.Duration
}

// Verifier enforces authorization policy and dispatches the state transition
// through Replay's authoritative atomic transaction.
type Verifier struct {
	Expectations Expectations
	Limits       Limits
	Clock        Clock
	Keys         KeyResolver
	Replay       ReplayStore
	Schema       SchemaValidator
	Handle       ReplayHandler
}

// VerificationResult identifies the exact signed authorization. Duplicate is
// true only when Verify also returns ErrDuplicateMessage.
type VerificationResult struct {
	Digest        [DigestSize]byte
	KeyID         string
	MessageID     [MessageIDSize]byte
	Sequence      uint64
	Duplicate     bool
	OutcomeDigest [DigestSize]byte
	Verified      VerifiedRecord
}

// VerifiedRecord is an immutable-by-API snapshot of the exact authorization
// which passed signature and schema validation. Getters return detached copies
// so mutation of the inbound Record cannot change handler inputs.
type VerifiedRecord struct {
	messageTypeID uint32
	schemaVersion Version
	domain        Domain
	envelope      Envelope
	payload       []byte
	digest        [DigestSize]byte
}

func (r VerifiedRecord) MessageTypeID() uint32    { return r.messageTypeID }
func (r VerifiedRecord) SchemaVersion() Version   { return r.schemaVersion }
func (r VerifiedRecord) Domain() Domain           { return cloneDomain(r.domain) }
func (r VerifiedRecord) Envelope() Envelope       { return cloneEnvelope(r.envelope) }
func (r VerifiedRecord) Payload() []byte          { return append([]byte(nil), r.payload...) }
func (r VerifiedRecord) Digest() [DigestSize]byte { return r.digest }

// Verify performs bounded canonical reconstruction, exact context checks, key
// authorization, signature verification, and atomic replay admission.
func (v *Verifier) Verify(ctx context.Context, record *Record) (VerificationResult, error) {
	var result VerificationResult
	if record == nil {
		return result, ErrInvalidRecord
	}
	if v == nil || v.Clock == nil {
		return result, ErrClockRequired
	}
	if v.Keys == nil {
		return result, ErrKeyResolverRequired
	}
	if v.Replay == nil {
		return result, ErrReplayStoreRequired
	}
	if v.Handle == nil {
		return result, ErrReplayHandlerRequired
	}
	if v.Schema == nil {
		return result, ErrSchemaValidatorRequired
	}
	limits, err := normalizeLimits(v.Limits)
	if err != nil {
		return result, err
	}
	if err := preflightUntrustedRecord(record, limits); err != nil {
		return result, err
	}
	// Take the detached authorization snapshot before canonical reconstruction.
	// Callers transfer read ownership for the duration of this call; subsequent
	// caller mutation cannot alter either validation or handler inputs.
	record = cloneRecord(record)
	canonicalizeRecordSets(record)
	digest, err := record.Digest(limits)
	if err != nil {
		return result, err
	}
	if err := v.validateExpectations(record); err != nil {
		return result, err
	}
	now := v.Clock.Now().UnixNano()
	if err := validateTimes(record.Domain, now, v.Expectations.MaxClockSkew, v.Expectations.MaxValidityWindow); err != nil {
		return result, err
	}
	key, err := v.Keys.ResolveKey(ctx, record.Envelope.SignatureKeyID)
	if err != nil {
		if errors.Is(err, ErrUnknownKey) {
			return result, err
		}
		return result, fmt.Errorf("ccse: resolve signature key: %w", err)
	}
	if err := validateKey(key, record, now); err != nil {
		return result, err
	}
	result = VerificationResult{
		Digest:    digest,
		KeyID:     key.KeyID,
		MessageID: record.Envelope.MessageID,
		Sequence:  record.Envelope.Counter,
	}
	switch key.Algorithm {
	case SignatureAlgorithmEd25519:
		if len(key.PublicKey) != ed25519.PublicKeySize || len(record.Signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key.PublicKey), digest[:], record.Signature) {
			return result, ErrInvalidSignature
		}
	default:
		return result, ErrUnsupportedAlgorithm
	}
	// Schema callbacks may parse extension values, so no callback runs until the
	// sender signature has authenticated the bounded canonical envelope.
	if err := v.Schema.ValidateExtensions(ctx, record.MessageTypeID, record.SchemaVersion, cloneExtensions(record.Envelope.Extensions)); err != nil {
		return result, err
	}
	if err := v.Schema.ValidateCanonicalPayload(ctx, record.MessageTypeID, record.SchemaVersion, append([]byte(nil), record.Payload...)); err != nil {
		if errors.Is(err, ErrNonCanonicalPayload) {
			return result, err
		}
		return result, fmt.Errorf("%w: %v", ErrNonCanonicalPayload, err)
	}
	result.Verified = newVerifiedRecord(record, digest)
	replayEntry := ReplayEntry{
		MessageTypeID:  record.MessageTypeID,
		SchemaVersion:  record.SchemaVersion,
		CounterKind:    record.Domain.CounterKind,
		ReplayDomainID: record.Domain.ReplayDomainID,
		SenderIdentity: record.Domain.SenderIdentity,
		Environment:    record.Domain.Environment,
		ChainID:        record.Domain.ChainID,
		GenesisHash:    record.Domain.GenesisHash,
		MessageID:      record.Envelope.MessageID,
		Sequence:       record.Envelope.Counter,
		Digest:         digest,
		ExpiresAt:      record.Envelope.ExpiresAtUnixNano,
	}
	decision, err := v.Replay.Execute(ctx, replayEntry, result.Verified, v.Handle)
	if err != nil {
		return result, err
	}
	result.OutcomeDigest = decision.OutcomeDigest
	switch decision.Status {
	case ReplayApplied:
		return result, nil
	case ReplayDuplicateCompleted:
		result.Duplicate = true
		return result, ErrDuplicateMessage
	default:
		return result, fmt.Errorf("%w: invalid replay-store status %d", ErrInvalidRecord, decision.Status)
	}
}
func (v *Verifier) validateExpectations(record *Record) error {
	e := v.Expectations
	if record == nil {
		return ErrInvalidRecord
	}
	if e.MessageTypeID == 0 || record.MessageTypeID != e.MessageTypeID {
		return ErrWrongMessageType
	}
	if e.SchemaVersion.Major == 0 || record.SchemaVersion != e.SchemaVersion {
		return ErrWrongSchemaVersion
	}
	if e.ProtocolVersion.Major == 0 || record.Domain.ProtocolVersion != e.ProtocolVersion || record.Envelope.ProtocolVersion != e.ProtocolVersion {
		return ErrWrongProtocolVersion
	}
	if e.Purpose == "" || record.Domain.Purpose != e.Purpose {
		return ErrWrongPurpose
	}
	if e.SenderIdentity.Present && record.Domain.SenderIdentity != e.SenderIdentity.Value {
		return ErrWrongSender
	}
	if !equalStringSet(record.Domain.Audience, e.Audience) {
		return ErrWrongAudience
	}
	if record.Domain.TenantOrganization != e.TenantOrganization {
		return ErrWrongTenant
	}
	if record.Domain.ProviderOrganization != e.ProviderOrganization {
		return ErrWrongProvider
	}
	if e.Environment == "" || record.Domain.Environment != e.Environment || record.Envelope.Environment != e.Environment {
		return ErrWrongEnvironment
	}
	if record.Domain.ChainID != e.ChainID || record.Envelope.ChainID != e.ChainID {
		return ErrWrongChain
	}
	if record.Domain.GenesisHash != e.GenesisHash {
		return ErrWrongGenesis
	}
	if e.ReplayDomainID == "" || record.Domain.ReplayDomainID != e.ReplayDomainID {
		return ErrWrongReplayDomain
	}
	if e.CounterKind == CounterUnspecified || record.Domain.CounterKind != e.CounterKind || record.Envelope.CounterKind != e.CounterKind {
		return ErrWrongCounterKind
	}
	return nil
}

func validateTimes(domain Domain, now int64, skew, maxWindow time.Duration) error {
	if now < 0 || skew < 0 || maxWindow <= 0 {
		return ErrInvalidValidityWindow
	}
	if domain.IssuedAtUnixNano > now && domain.IssuedAtUnixNano-now > int64(skew) {
		return ErrNotYetValid
	}
	if domain.ExpiresAtUnixNano <= now && now-domain.ExpiresAtUnixNano >= int64(skew) {
		return ErrExpired
	}
	if domain.ExpiresAtUnixNano-domain.IssuedAtUnixNano > int64(maxWindow) {
		return ErrValidityWindowTooLong
	}
	return nil
}

func validateKey(key KeyRecord, record *Record, now int64) error {
	if key.KeyID == "" || key.KeyID != record.Domain.SignatureKeyID || key.KeyID != record.Envelope.SignatureKeyID {
		return ErrUnknownKey
	}
	if key.SubjectIdentity == "" || key.SubjectIdentity != record.Domain.SenderIdentity {
		return ErrKeySubjectMismatch
	}
	if key.Algorithm != record.Domain.SignatureAlgorithm || key.Algorithm != record.Envelope.SignatureAlgorithm {
		return ErrUnsupportedAlgorithm
	}
	if key.NotBeforeUnixNano < 0 || key.NotAfterUnixNano <= key.NotBeforeUnixNano || now < key.NotBeforeUnixNano || record.Domain.IssuedAtUnixNano < key.NotBeforeUnixNano || record.Domain.IssuedAtUnixNano >= key.NotAfterUnixNano || record.Domain.ExpiresAtUnixNano > key.NotAfterUnixNano || now >= key.NotAfterUnixNano {
		return ErrKeyNotActive
	}
	if key.RevokedAtUnixNano > 0 && record.Domain.ExpiresAtUnixNano > key.RevokedAtUnixNano {
		return ErrKeyRevoked
	}
	if key.RevokedAtUnixNano > 0 && now >= key.RevokedAtUnixNano {
		return ErrKeyRevoked
	}
	if !containsMessageType(key.AllowedMessageTypes, record.MessageTypeID) {
		return ErrKeyNotAuthorized
	}
	return nil
}

func containsMessageType(values []uint32, target uint32) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	l := append([]string(nil), left...)
	r := append([]string(nil), right...)
	sort.Strings(l)
	sort.Strings(r)
	for i := range l {
		if l[i] != r[i] || (i > 0 && l[i] == l[i-1]) {
			return false
		}
	}
	return true
}

// MemoryKeyRegistry is a concurrency-safe test/development resolver. Production
// services replace it with the durable IAM projection but keep the same exact
// lookup and permanent-revocation semantics.
type MemoryKeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]KeyRecord
}

func NewMemoryKeyRegistry() *MemoryKeyRegistry {
	return &MemoryKeyRegistry{keys: make(map[string]KeyRecord)}
}

// Add inserts a globally unique key ID. Reusing an ID, even for the same bytes,
// is rejected so rotation and audit history are unambiguous.
func (r *MemoryKeyRegistry) Add(key KeyRecord) error {
	if r == nil {
		return ErrKeyResolverRequired
	}
	if err := validateKeyRecord(key); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil {
		r.keys = make(map[string]KeyRecord)
	}
	if _, exists := r.keys[key.KeyID]; exists {
		return fmt.Errorf("ccse: duplicate key ID %q", key.KeyID)
	}
	r.keys[key.KeyID] = cloneKeyRecord(key)
	return nil
}

// Revoke permanently marks a key revoked at the supplied UTC nanosecond.
func (r *MemoryKeyRegistry) Revoke(keyID string, revokedAt int64) error {
	if r == nil {
		return ErrKeyResolverRequired
	}
	if keyID == "" || revokedAt <= 0 {
		return fmt.Errorf("ccse: invalid revocation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key, exists := r.keys[keyID]
	if !exists {
		return ErrUnknownKey
	}
	if revokedAt < key.NotBeforeUnixNano {
		return fmt.Errorf("ccse: revocation predates key validity")
	}
	if key.RevokedAtUnixNano != 0 {
		return ErrKeyRevoked
	}
	key.RevokedAtUnixNano = revokedAt
	r.keys[keyID] = key
	return nil
}

func (r *MemoryKeyRegistry) ResolveKey(_ context.Context, keyID string) (KeyRecord, error) {
	if r == nil {
		return KeyRecord{}, ErrKeyResolverRequired
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	key, exists := r.keys[keyID]
	if !exists {
		return KeyRecord{}, ErrUnknownKey
	}
	return cloneKeyRecord(key), nil
}

func validateKeyRecord(key KeyRecord) error {
	if key.KeyID == "" || key.SubjectIdentity == "" || key.NotBeforeUnixNano < 0 || key.NotAfterUnixNano <= key.NotBeforeUnixNano || len(key.AllowedMessageTypes) == 0 {
		return fmt.Errorf("ccse: invalid key record")
	}
	if key.RevokedAtUnixNano < 0 || (key.RevokedAtUnixNano > 0 && key.RevokedAtUnixNano < key.NotBeforeUnixNano) {
		return fmt.Errorf("ccse: invalid key revocation time")
	}
	switch key.Algorithm {
	case SignatureAlgorithmEd25519:
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("ccse: invalid Ed25519 public key size")
		}
	case SignatureAlgorithmP256SHA256:
		// P-256 key parsing belongs to the policy-scoped TPM/HSM adapter. The
		// generic registry can retain the key but Verifier fails closed until
		// such an adapter is explicitly configured.
		if len(key.PublicKey) == 0 {
			return fmt.Errorf("ccse: empty P-256 public key")
		}
	default:
		return ErrUnsupportedAlgorithm
	}
	allowed := append([]uint32(nil), key.AllowedMessageTypes...)
	sort.Slice(allowed, func(i, j int) bool { return allowed[i] < allowed[j] })
	for i, value := range allowed {
		if value == 0 || (i > 0 && allowed[i-1] == value) {
			return fmt.Errorf("ccse: invalid allowed message types")
		}
	}
	return nil
}

func cloneKeyRecord(key KeyRecord) KeyRecord {
	key.PublicKey = append([]byte(nil), key.PublicKey...)
	key.AllowedMessageTypes = append([]uint32(nil), key.AllowedMessageTypes...)
	return key
}

func cloneDomain(domain Domain) Domain {
	domain.Audience = append([]string(nil), domain.Audience...)
	return domain
}

func cloneEnvelope(envelope Envelope) Envelope {
	envelope.Extensions = cloneExtensions(envelope.Extensions)
	return envelope
}

func cloneRecord(record *Record) *Record {
	cloned := *record
	cloned.Domain = cloneDomain(record.Domain)
	cloned.Envelope = cloneEnvelope(record.Envelope)
	cloned.Payload = append([]byte(nil), record.Payload...)
	cloned.Signature = append([]byte(nil), record.Signature...)
	return &cloned
}

// canonicalizeRecordSets makes every observable decoded representation agree
// with the set order used by the signing projection. A transport permutation
// therefore cannot preserve the signature while changing callback semantics.
func canonicalizeRecordSets(record *Record) {
	if record == nil {
		return
	}
	sort.Slice(record.Domain.Audience, func(i, j int) bool {
		left, right := record.Domain.Audience[i], record.Domain.Audience[j]
		if len(left) != len(right) {
			return len(left) < len(right)
		}
		return left < right
	})
	sort.Slice(record.Envelope.Extensions, func(i, j int) bool {
		return record.Envelope.Extensions[i].ID < record.Envelope.Extensions[j].ID
	})
}

func newVerifiedRecord(record *Record, digest [DigestSize]byte) VerifiedRecord {
	return VerifiedRecord{
		messageTypeID: record.MessageTypeID,
		schemaVersion: record.SchemaVersion,
		domain:        cloneDomain(record.Domain),
		envelope:      cloneEnvelope(record.Envelope),
		payload:       append([]byte(nil), record.Payload...),
		digest:        digest,
	}
}

func cloneExtensions(extensions []Extension) []Extension {
	cloned := make([]Extension, len(extensions))
	for i, extension := range extensions {
		cloned[i] = extension
		cloned[i].Value = append([]byte(nil), extension.Value...)
	}
	return cloned
}

type memoryReplayScope struct {
	CounterKind    CounterKind
	ReplayDomainID string
	SenderIdentity string
	Environment    string
	ChainID        [32]byte
	GenesisHash    [DigestSize]byte
}

type memoryReplayMessage struct {
	Scope     memoryReplayScope
	MessageID [MessageIDSize]byte
}

type memoryReplayValue struct {
	MessageTypeID uint32
	SchemaVersion Version
	Digest        [DigestSize]byte
	Sequence      uint64
	ExpiresAt     int64
	OutcomeDigest [DigestSize]byte
}

// MemoryReplayStore is a concurrency-safe conformance implementation. It keeps
// the highest sequence for each scope even after messages expire; production
// services need the same invariant in durable state.
type MemoryReplayStore struct {
	mu         sync.Mutex
	highest    map[memoryReplayScope]uint64
	seen       map[memoryReplayMessage]memoryReplayValue
	scopeLocks map[memoryReplayScope]chan struct{}
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{
		highest:    make(map[memoryReplayScope]uint64),
		seen:       make(map[memoryReplayMessage]memoryReplayValue),
		scopeLocks: make(map[memoryReplayScope]chan struct{}),
	}
}

type memoryReplayContextKey struct{}

type memoryReplayActivation struct {
	store *MemoryReplayStore
	scope memoryReplayScope
}

func (s *MemoryReplayStore) Execute(ctx context.Context, entry ReplayEntry, verified VerifiedRecord, apply ReplayHandler) (ReplayDecision, error) {
	if s == nil {
		return ReplayDecision{}, ErrReplayStoreRequired
	}
	if apply == nil {
		return ReplayDecision{}, ErrReplayHandlerRequired
	}
	if err := entry.Validate(); err != nil {
		return ReplayDecision{}, err
	}
	scope := memoryReplayScope{
		CounterKind:    entry.CounterKind,
		ReplayDomainID: entry.ReplayDomainID,
		SenderIdentity: entry.SenderIdentity,
		Environment:    entry.Environment,
		ChainID:        entry.ChainID,
		GenesisHash:    entry.GenesisHash,
	}
	activation := memoryReplayActivation{store: s, scope: scope}
	active, _ := ctx.Value(memoryReplayContextKey{}).(map[memoryReplayActivation]struct{})
	for ancestor := range active {
		if ancestor.store == s {
			// The memory adapter has no nested unit-of-work. Reject every
			// same-store nested execution so an inner scope cannot commit if
			// its outer handler later rolls back.
			return ReplayDecision{}, ErrReplayReentrant
		}
	}
	message := memoryReplayMessage{Scope: scope, MessageID: entry.MessageID}
	scopeLock := s.lockForScope(scope)
	select {
	case <-ctx.Done():
		return ReplayDecision{}, ctx.Err()
	case <-scopeLock:
	}
	defer func() { scopeLock <- struct{}{} }()

	s.mu.Lock()
	if s.highest == nil {
		s.highest = make(map[memoryReplayScope]uint64)
	}
	if s.seen == nil {
		s.seen = make(map[memoryReplayMessage]memoryReplayValue)
	}
	if prior, exists := s.seen[message]; exists {
		if prior.Sequence == entry.Sequence && bytes.Equal(prior.Digest[:], entry.Digest[:]) {
			s.mu.Unlock()
			return ReplayDecision{Status: ReplayDuplicateCompleted, OutcomeDigest: prior.OutcomeDigest}, nil
		}
		s.mu.Unlock()
		return ReplayDecision{}, ErrMessageIDConflict
	}
	if highest, exists := s.highest[scope]; exists && entry.Sequence <= highest {
		s.mu.Unlock()
		return ReplayDecision{}, ErrReplaySequence
	}
	s.mu.Unlock()

	nextActive := make(map[memoryReplayActivation]struct{}, len(active)+1)
	for item := range active {
		nextActive[item] = struct{}{}
	}
	nextActive[activation] = struct{}{}
	txCtx := context.WithValue(ctx, memoryReplayContextKey{}, nextActive)
	outcomeDigest, err := apply(txCtx, verified)
	if err != nil {
		return ReplayDecision{}, err
	}
	if isZeroDigest(outcomeDigest) {
		return ReplayDecision{}, ErrInvalidOutcomeDigest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.highest[scope] = entry.Sequence
	s.seen[message] = memoryReplayValue{
		MessageTypeID: entry.MessageTypeID,
		SchemaVersion: entry.SchemaVersion,
		Digest:        entry.Digest,
		Sequence:      entry.Sequence,
		ExpiresAt:     entry.ExpiresAt,
		OutcomeDigest: outcomeDigest,
	}
	return ReplayDecision{Status: ReplayApplied, OutcomeDigest: outcomeDigest}, nil
}

func (s *MemoryReplayStore) lockForScope(scope memoryReplayScope) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scopeLocks == nil {
		s.scopeLocks = make(map[memoryReplayScope]chan struct{})
	}
	lock := s.scopeLocks[scope]
	if lock == nil {
		lock = make(chan struct{}, 1)
		lock <- struct{}{}
		s.scopeLocks[scope] = lock
	}
	return lock
}

func validateReplayEntry(entry ReplayEntry) error {
	if entry.MessageTypeID == 0 || entry.SchemaVersion.Major == 0 ||
		(entry.CounterKind != CounterSequence && entry.CounterKind != CounterExpectedGeneration) ||
		entry.ReplayDomainID == "" || entry.SenderIdentity == "" || entry.Environment == "" ||
		isZeroDigest(entry.ChainID) || isZeroDigest(entry.GenesisHash) ||
		isZeroMessageID(entry.MessageID) || isZeroDigest(entry.Digest) || entry.ExpiresAt <= 0 {
		return ErrInvalidRecord
	}
	return nil
}
