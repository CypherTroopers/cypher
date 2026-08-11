// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package iam is the deterministic semantic kernel for Workstream 0 identity
// and key lifecycle changes. It validates detached state and returns mutation
// and audit intents; it never writes a database, consumes a replay counter, or
// performs an external side effect.
package iam

import (
	"context"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	KeyIDPrefix         = globalid.IAMKeyIDPrefix
	KeyIDDomain         = "CPH-AIIE-KEY-ID-V1\x00"
	ProofDomain         = "CPH-AIIE-KEY-POP-V1\x00"
	maxPredecessorDepth = 256
)

// EntityKind identifies a semantic mutation target without relying on a
// caller-constructed string namespace.
type EntityKind uint8

const (
	EntityIdentity EntityKind = iota + 1
	EntityKeyMaterial
	EntityKeyLifecycle
	EntityOwnershipTransfer
	EntityOwnershipTransferProfileActivation
)

// MutationKind identifies the sole authoritative write described by a plan.
type MutationKind uint8

const (
	MutationCreateKeyMaterial MutationKind = iota + 1
	MutationAppendIdentity
	MutationAppendKeyLifecycle
	MutationCollectOwnershipTransfer
)

// EntityRef is the stable writer-fence and CAS target.
type EntityRef struct {
	Kind          EntityKind
	PrincipalKind uint32
	ID            string
}

// WriterFence is supplied by the authenticated command. EvidenceDigest names
// the durable writer-lease/failover evidence returned by View.
type WriterFence struct {
	Entity               EntityRef
	WriterIdentity       string
	HomeRegion           string
	WriterEpoch          uint64
	ExpectedStateVersion uint64
	EvidenceDigest       [32]byte
}

// WriterLeaseSnapshot is read-only evidence for the single active writer.
// The half-open validity interval is evaluated only at the command's explicit
// EvaluatedAtUnixNano; the kernel never consults a host clock.
type WriterLeaseSnapshot struct {
	Entity             EntityRef
	WriterIdentity     string
	HomeRegion         string
	WriterEpoch        uint64
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
	EvidenceDigest     [32]byte
}

// EnrollmentDomain prevents a PoP challenge issued in one deployment from
// authorizing the same key/subject registration in another deployment.
type EnrollmentDomain struct {
	EnrollmentDomainID string
	Environment        string
	GenesisHash        [32]byte
}

// ProofChallengeSnapshot binds a one-use proof-of-possession challenge to its
// subject and exact expiry. Consumed is authoritative durable state.
type ProofChallengeSnapshot struct {
	Challenge              [32]byte
	SubjectIdentity        string
	SubjectKind            uint32
	TargetIdentity         EntityRef
	TransferEvidenceDigest [32]byte
	Domain                 EnrollmentDomain
	ExpiresAtUnixNano      int64
	Consumed               bool
	IssuerIdentity         string
	PolicyDigestsSHA256    [][32]byte
	EvidenceDigest         [32]byte
}

// OwnershipTransferSnapshot authoritatively links a terminal old identity to
// a different re-enrolled entity ID and the exact successor generation.
type OwnershipTransferSnapshot struct {
	PreviousEntity      EntityRef
	NextEntity          EntityRef
	PreviousPrincipal   string
	NextPrincipal       string
	PreviousGeneration  uint64
	NextGeneration      uint64
	CompletedAtUnixNano int64
	EvidenceDigest      [32]byte
}

// KeyMaterialSnapshot is an immutable public-key registration. Returned byte
// slices are detached by every kernel getter.
type KeyMaterialSnapshot struct {
	KeyID                         string
	Algorithm                     ccse.SignatureAlgorithmID
	CanonicalPublicKey            []byte
	SubjectIdentity               string
	SubjectKind                   uint32
	TargetIdentity                EntityRef
	TransferEvidenceDigest        [32]byte
	EnrollmentDomain              EnrollmentDomain
	ProofChallenge                [32]byte
	ProofExpiresAtUnixNano        int64
	ProofSignature                []byte
	ProofDigest                   [32]byte
	ChallengeEvidenceDigest       [32]byte
	EnrollmentAuthorityIdentity   string
	EnrollmentPolicyDigestsSHA256 [][32]byte
	EnrollmentBindingDigest       [32]byte
	WriterIdentity                string
	HomeRegion                    string
	WriterEpoch                   uint64
	StateVersion                  uint64
	IdempotencyKey                [16]byte
}

// IdentitySnapshot is the normalized, detached core shared by all eight v1
// identity projections. CanonicalPayload is the already validated CCSE payload.
type IdentitySnapshot struct {
	Ref                    EntityRef
	MessageTypeID          uint32
	RecordID               string
	CreatedAtUnixNano      int64
	PrincipalIdentity      string
	KeyID                  string
	State                  uint32
	Generation             uint64
	ValidFromUnixNano      int64
	ValidUntilUnixNano     int64
	HomeRegion             string
	WriterEpoch            uint64
	StateVersion           uint64
	IdempotencyKey         [16]byte
	PolicyDigestsSHA256    [][32]byte
	IntegrityDigestSHA256  [32]byte
	CanonicalPayload       []byte
	Bindings               IdentityBindings
	ImmutableBindingDigest [32]byte
}

// IdentityBindings retains the typed parent/ownership graph that cannot be
// recovered safely from an opaque payload by the semantic planner.
type IdentityBindings struct {
	ProviderID      string
	HostID          string
	ProviderSiteID  string
	AgentID         string
	DeviceIDs       []string
	LeaseID         string
	JobID           string
	AttemptID       string
	PayoutIdentity  string
	BillingIdentity string
	Environment     string
}

// KeyLifecycleSnapshot is a normalized, detached v1 KeyLifecycle projection.
type KeyLifecycleSnapshot struct {
	KeyID                           string
	RecordID                        string
	CreatedAtUnixNano               int64
	SubjectIdentity                 string
	SubjectKind                     uint32
	Algorithm                       ccse.SignatureAlgorithmID
	State                           uint32
	NotBeforeUnixNano               int64
	NotAfterUnixNano                int64
	RevokedAtUnixNano               int64
	HasRevokedAt                    bool
	RotationPredecessorKeyID        string
	HasRotationPredecessor          bool
	AllowedMessageTypeIDs           []uint32
	AuthorizationPolicyDigestSHA256 [32]byte
	TransitionReasonCode            string
	HasTransitionReason             bool
	HomeRegion                      string
	WriterEpoch                     uint64
	StateVersion                    uint64
	IdempotencyKey                  [16]byte
	PolicyDigestsSHA256             [][32]byte
	IntegrityDigestSHA256           [32]byte
	CanonicalPayload                []byte
	ImmutableBindingDigest          [32]byte
}

// ResolvedKeySnapshot composes immutable material and lifecycle state for
// authorization consumers such as Governance. Roles are deliberately absent:
// they are external policy, not a property of v1 KeyLifecycle.
type ResolvedKeySnapshot struct {
	KeyID                           string
	SubjectIdentity                 string
	SubjectKind                     uint32
	Algorithm                       ccse.SignatureAlgorithmID
	PublicKey                       []byte
	EnrollmentDomain                EnrollmentDomain
	TargetIdentity                  EntityRef
	State                           uint32
	StateVersion                    uint64
	WriterEpoch                     uint64
	NotBeforeUnixNano               int64
	NotAfterUnixNano                int64
	RevokedAtUnixNano               int64
	AllowedMessageTypeIDs           []uint32
	AuthorizationPolicyDigestSHA256 [32]byte
	// SnapshotDigest is a domain-separated digest of the normalized v1
	// KeyLifecycle canonical payload. Consumers bind it with StateVersion and
	// WriterEpoch in their commit-time snapshot precondition.
	SnapshotDigest             [32]byte
	IdentityStateVersion       uint64
	IdentityWriterEpoch        uint64
	IdentitySnapshotDigest     [32]byte
	IdentityValidFromUnixNano  int64
	IdentityValidUntilUnixNano int64
}

func cloneResolvedKey(source ResolvedKeySnapshot) ResolvedKeySnapshot {
	source.PublicKey = append([]byte(nil), source.PublicKey...)
	source.AllowedMessageTypeIDs = append([]uint32(nil), source.AllowedMessageTypeIDs...)
	return source
}

// View is an injected read-only authoritative snapshot boundary. Not-found is
// represented by found=false; implementations must not fall back to aliases.
// The planner treats all returned values as untrusted and immediately detaches
// their slices before validation.
type View interface {
	globalid.View
	idempotency.JoinedView
	LookupIdentity(context.Context, EntityRef) (snapshot IdentitySnapshot, found bool, err error)
	LookupIdentityByPrincipal(context.Context, uint32, string) (snapshot IdentitySnapshot, found bool, err error)
	LookupKeyMaterial(context.Context, string) (snapshot KeyMaterialSnapshot, found bool, err error)
	LookupKeyLifecycle(context.Context, string) (snapshot KeyLifecycleSnapshot, found bool, err error)
	LookupSubjectKeyLifecycles(context.Context, uint32, string) ([]KeyLifecycleSnapshot, error)
	LookupRotationSuccessor(context.Context, string) (snapshot KeyLifecycleSnapshot, found bool, err error)
	LookupOwnershipTransfer(context.Context, [32]byte) (snapshot OwnershipTransferSnapshot, found bool, err error)
	// LookupIdentityAt and LookupKeyLifecycleAt return the greatest immutable
	// history record effective at or before the supplied issuance time. They
	// must never reconstruct history from the current row.
	LookupIdentityAt(context.Context, EntityRef, int64) (snapshot IdentitySnapshot, found bool, err error)
	LookupKeyLifecycleAt(context.Context, string, int64) (snapshot KeyLifecycleSnapshot, found bool, err error)
	SnapshotOwnershipTransferApprovalCollection(context.Context, [16]byte) (snapshot OwnershipTransferApprovalCollectionSnapshot, found bool, err error)
	LookupAcceptedOwnershipTransfer(context.Context, [32]byte) (snapshot AcceptedOwnershipTransferSnapshot, found bool, err error)
	LookupProofChallenge(context.Context, [32]byte) (snapshot ProofChallengeSnapshot, found bool, err error)
	LookupWriterLease(context.Context, EntityRef) (snapshot WriterLeaseSnapshot, found bool, err error)
}

// AuthorityRequest is evaluated by the injected deployment policy. The
// kernel proves the writer fence independently; Profile decides whether that
// fenced identity is authorized for the requested semantic operation.
type AuthorityRequest struct {
	Mutation            MutationKind
	Entity              EntityRef
	ActorIdentity       string
	EvaluatedAtUnixNano int64
	PolicyDigestsSHA256 [][32]byte
}

// IdentityTransitionRequest carries detached old/new normalized snapshots.
// Profile supplies deployment-specific bootstrap and nonterminal transition
// policy that is deliberately absent from the immutable v1 schema.
type IdentityTransitionRequest struct {
	Previous *IdentitySnapshot
	Next     IdentitySnapshot
}

// AllowedMessageTypesRequest lets policy narrow the production schema
// registry. It may not add an unregistered message type.
type AllowedMessageTypesRequest struct {
	SubjectIdentity                 string
	SubjectKind                     uint32
	KeyID                           string
	MessageTypeIDs                  []uint32
	AuthorizationPolicyDigestSHA256 [32]byte
}

// EnrollmentAuthorityRequest gives policy the complete, authoritative
// subject/deployment/challenge binding. PoP proves control of the key; this
// request separately proves that the issuer permits the enrollment.
type EnrollmentAuthorityRequest struct {
	Entity                  EntityRef
	TargetIdentity          EntityRef
	TransferEvidenceDigest  [32]byte
	ActorIdentity           string
	SubjectIdentity         string
	SubjectKind             uint32
	Algorithm               ccse.SignatureAlgorithmID
	EnrollmentDomain        EnrollmentDomain
	Challenge               [32]byte
	ChallengeIssuerIdentity string
	ChallengeEvidenceDigest [32]byte
	PolicyDigestsSHA256     [][32]byte
	PrincipalClaimMode      globalid.ClaimMode
	EvaluatedAtUnixNano     int64
}

// Profile is a read-only deployment-policy boundary. Returning an error is a
// fail-closed rejection; the kernel never supplies permissive defaults.
type Profile interface {
	ValidateAuthority(context.Context, AuthorityRequest) error
	ValidateEnrollmentAuthority(context.Context, EnrollmentAuthorityRequest) error
	ValidateIdentityTransition(context.Context, IdentityTransitionRequest) error
	ValidateAllowedMessageTypes(context.Context, AllowedMessageTypesRequest) error
	OwnershipTransferProfile(context.Context, OwnershipTransferProfileRequest) (OwnershipTransferProfile, error)
	OwnershipTransferProfileAt(context.Context, OwnershipTransferProfileHistoryRequest) (OwnershipTransferProfile, error)
	ValidateOwnershipTransferEvidence(context.Context, OwnershipTransferEvidenceRequest) error
	ValidateOwnershipTransferEvidenceAt(context.Context, OwnershipTransferEvidenceHistoryRequest) error
	ReceiverProfile(context.Context, uint32) (ReceiverProfile, error)
}

// ReceiverProfile freezes all deployment context which a generic CCSE
// verifier alone cannot infer for this semantic consumer.
type ReceiverProfile struct {
	ProtocolVersion      ccse.Version
	SchemaVersion        ccse.Version
	Purpose              string
	Audience             []string
	TenantOrganization   ccse.OptionalString
	ProviderOrganization ccse.OptionalString
	Environment          string
	EnrollmentDomainID   string
	ChainID              [32]byte
	GenesisHash          [32]byte
	// ReplayDomainID is the frozen deployment/base namespace. State-changing
	// IAM records use DeriveEntityReplayDomainID to obtain the exact wire
	// replay domain for their semantic target. A type-wide replay namespace is
	// unsafe with CounterExpectedGeneration because unrelated entities commonly
	// have the same generation.
	ReplayDomainID            string
	CounterKind               ccse.CounterKind
	MaxClockSkewNanos         int64
	MaxValidityWindowNanos    int64
	MaxPlanCommitLatencyNanos int64
}

// KeyMaterialCommand requests first registration of content-addressed public
// material and atomic consumption of a one-use PoP challenge.
type KeyMaterialCommand struct {
	Algorithm                         ccse.SignatureAlgorithmID
	CanonicalPublicKey                []byte
	ClaimedKeyID                      string
	SubjectIdentity                   string
	SubjectKind                       uint32
	TargetIdentity                    EntityRef
	TransferEvidenceDigest            [32]byte
	EnrollmentDomain                  EnrollmentDomain
	Challenge                         [32]byte
	ChallengeExpiresAtUnixNano        int64
	ProofSignature                    []byte
	EnrollmentAuthorityIdentity       string
	EnrollmentAuthorityEvidenceDigest [32]byte
	EnrollmentPolicyDigestsSHA256     [][32]byte
	EvaluatedAtUnixNano               int64
	CorrelationID                     [16]byte
	IdempotencyKey                    [16]byte
	CauseCode                         string
	Fence                             WriterFence
}

// KeyEnrollmentCommand is the sole public bootstrap path for a new key. The
// lifecycle half must carry an exact CCSE-verified PREACTIVE v1 payload; the
// material half contributes content addressing and target-key PoP evidence.
type KeyEnrollmentCommand struct {
	Material  KeyMaterialCommand
	Lifecycle KeyLifecycleCommand
}

// IdentityCommand proposes one already canonical v1 identity record.
type IdentityCommand struct {
	Projection             any
	ActorIdentity          string
	EvaluatedAtUnixNano    int64
	CorrelationID          [16]byte
	CausationID            ccse.OptionalMessageID
	CauseCode              string
	Fence                  WriterFence
	Authorization          VerifiedAuthorization
	TransferEvidenceDigest [32]byte
}

// KeyLifecycleCommand proposes one already canonical v1 lifecycle record.
type KeyLifecycleCommand struct {
	Projection             any
	ActorIdentity          string
	EvaluatedAtUnixNano    int64
	CorrelationID          [16]byte
	CausationID            ccse.OptionalMessageID
	CauseCode              string
	Fence                  WriterFence
	Authorization          VerifiedAuthorization
	TransferEvidenceDigest [32]byte
}

// VerifiedAuthorization is immutable-by-API and can only be constructed from
// ccse.VerifiedRecord. It rebinds semantic planning to the exact authenticated
// sender, key, payload and record digest accepted by CCSE.
type VerifiedAuthorization struct {
	messageTypeID        uint32
	schemaVersion        ccse.Version
	senderIdentity       string
	signatureKeyID       string
	payload              []byte
	recordDigest         [32]byte
	messageID            [16]byte
	correlationID        [16]byte
	causationID          ccse.OptionalMessageID
	issuedAtUnixNano     int64
	expiresAtUnixNano    int64
	protocolVersion      ccse.Version
	purpose              string
	audience             []string
	tenantOrganization   ccse.OptionalString
	providerOrganization ccse.OptionalString
	environment          string
	chainID              [32]byte
	genesisHash          [32]byte
	replayDomainID       string
	counterKind          ccse.CounterKind
	counter              uint64
	sourceRecord         ccse.Record
	hasSourceRecord      bool
}

func AuthorizationFromVerifiedRecord(record ccse.VerifiedRecord) VerifiedAuthorization {
	domain := record.Domain()
	envelope := record.Envelope()
	source := record.Record()
	return VerifiedAuthorization{
		messageTypeID: record.MessageTypeID(), schemaVersion: record.SchemaVersion(),
		senderIdentity: domain.SenderIdentity, signatureKeyID: envelope.SignatureKeyID,
		payload: record.Payload(), recordDigest: record.Digest(), messageID: envelope.MessageID,
		correlationID: envelope.CorrelationID, causationID: envelope.CausationID,
		issuedAtUnixNano:  envelope.IssuedAtUnixNano,
		expiresAtUnixNano: envelope.ExpiresAtUnixNano, protocolVersion: domain.ProtocolVersion,
		purpose: domain.Purpose, audience: append([]string(nil), domain.Audience...),
		tenantOrganization: domain.TenantOrganization, providerOrganization: domain.ProviderOrganization,
		environment: domain.Environment, chainID: domain.ChainID, genesisHash: domain.GenesisHash,
		replayDomainID: domain.ReplayDomainID, counterKind: domain.CounterKind, counter: domain.Counter,
		sourceRecord: source, hasSourceRecord: true,
	}
}

func (authorization VerifiedAuthorization) MessageTypeID() uint32 { return authorization.messageTypeID }
func (authorization VerifiedAuthorization) SenderIdentity() string {
	return authorization.senderIdentity
}
func (authorization VerifiedAuthorization) SignatureKeyID() string {
	return authorization.signatureKeyID
}
func (authorization VerifiedAuthorization) Payload() []byte {
	return append([]byte(nil), authorization.payload...)
}
func (authorization VerifiedAuthorization) RecordDigest() [32]byte { return authorization.recordDigest }
func (authorization VerifiedAuthorization) MessageID() [16]byte    { return authorization.messageID }
func (authorization VerifiedAuthorization) CorrelationID() [16]byte {
	return authorization.correlationID
}
func (authorization VerifiedAuthorization) CausationID() ccse.OptionalMessageID {
	return authorization.causationID
}
func (authorization VerifiedAuthorization) IssuedAtUnixNano() int64 {
	return authorization.issuedAtUnixNano
}
func (authorization VerifiedAuthorization) SourceRecord() (ccse.Record, bool) {
	if !authorization.hasSourceRecord {
		return ccse.Record{}, false
	}
	return cloneCCSERecord(authorization.sourceRecord), true
}

// CASIntent contains exact authoritative preconditions. Persisting a plan is
// valid only when these comparisons and the mutation occur atomically with the
// replay result and audit append.
type CASIntent struct {
	Entity                    EntityRef
	ExpectedAbsent            bool
	ExpectedStateVersion      uint64
	ExpectedEntityWriterEpoch uint64
	AuthorizedWriterEpoch     uint64
	ConsumeChallenge          bool
	Challenge                 [32]byte
	ChallengeEvidenceDigest   [32]byte
	WriterEvidenceDigest      [32]byte
	Dependencies              []SnapshotPrecondition
	PredecessorIndexMode      PredecessorIndexMode
	RotationPredecessorKeyID  string
	TransferEvidenceDigest    [32]byte
	EnrollmentEvidenceDigest  [32]byte
	AuthorizationDigest       [32]byte
	PrincipalIndex            PrincipalIndexIntent
	IdentifierClaims          []globalid.Claim
	ExpectedSubjectAbsent     bool
	SubjectKind               uint32
	SubjectIdentity           string
	SubjectKeySetDigest       [32]byte
	IdempotencyClaims         []idempotency.Claim
}

type PredecessorIndexMode uint8

const (
	PredecessorReserveNew PredecessorIndexMode = iota + 1
	PredecessorAssertExisting
)

// PrincipalIndexIntent is the typed principal lookup CAS. It is separate from
// the global identifier claim because callers need an efficient
// (principal_kind, principal_identity) index as well as cross-kind uniqueness.
type PrincipalIndexIntent struct {
	Mode                      globalid.ClaimMode
	PrincipalKind             uint32
	PrincipalIdentity         string
	ExpectedOwner             EntityRef
	NextOwner                 EntityRef
	ExpectedStateVersion      uint64
	ExpectedEntityWriterEpoch uint64
	ExpectedState             uint32
	TransferEvidenceDigest    [32]byte
}

// SnapshotPrecondition must be rechecked by the authoritative transaction.
type SnapshotPrecondition struct {
	Entity                 EntityRef
	ExpectedStateVersion   uint64
	ExpectedWriterEpoch    uint64
	ExpectedState          uint32
	ExpectedSnapshotDigest [32]byte
}

// MutationPlan has no public constructor: WS0.2a does not expose a
// commit-ready IAM mutation before its exact AuditIntent is signed and joined
// to an audit-head CAS by the next durable workstream.
type MutationPlan struct {
	kind                    MutationKind
	cas                     CASIntent
	material                *KeyMaterialSnapshot
	identity                *IdentitySnapshot
	lifecycle               *KeyLifecycleSnapshot
	evaluatedAtUnixNano     int64
	commitNotBeforeUnixNano int64
	commitNotAfterUnixNano  int64
	digest                  [32]byte
}

func (p MutationPlan) Kind() MutationKind { return p.kind }
func (p MutationPlan) CAS() CASIntent {
	result := p.cas
	result.Dependencies = append([]SnapshotPrecondition(nil), p.cas.Dependencies...)
	result.IdentifierClaims = append([]globalid.Claim(nil), p.cas.IdentifierClaims...)
	result.IdempotencyClaims = append([]idempotency.Claim(nil), p.cas.IdempotencyClaims...)
	return result
}
func (p MutationPlan) Digest() [32]byte               { return p.digest }
func (p MutationPlan) EvaluatedAtUnixNano() int64     { return p.evaluatedAtUnixNano }
func (p MutationPlan) CommitNotBeforeUnixNano() int64 { return p.commitNotBeforeUnixNano }
func (p MutationPlan) CommitNotAfterUnixNano() int64  { return p.commitNotAfterUnixNano }

func (p MutationPlan) KeyMaterial() (KeyMaterialSnapshot, bool) {
	if p.material == nil {
		return KeyMaterialSnapshot{}, false
	}
	return cloneKeyMaterial(*p.material), true
}

func (p MutationPlan) Identity() (IdentitySnapshot, bool) {
	if p.identity == nil {
		return IdentitySnapshot{}, false
	}
	return cloneIdentity(*p.identity), true
}

func (p MutationPlan) KeyLifecycle() (KeyLifecycleSnapshot, bool) {
	if p.lifecycle == nil {
		return KeyLifecycleSnapshot{}, false
	}
	return cloneLifecycle(*p.lifecycle), true
}

// PendingMutationPlan is the only WS0.2a planner result. It commits the exact
// mutation and mandatory audit intent but is intentionally non-committable.
// WS0.2b must revalidate its time/CAS preconditions and bind AuditIntent to a
// signed AuditEvent plus audit-head CAS before introducing a commit-ready type.
type PendingMutationPlan struct {
	mutation              MutationPlan
	audit                 AuditIntent
	admission             PendingAdmissionIntent
	idempotencyCompletion []idempotency.Claim
	digest                [32]byte
}

func (p PendingMutationPlan) Kind() MutationKind         { return p.mutation.Kind() }
func (p PendingMutationPlan) CAS() CASIntent             { return p.mutation.CAS() }
func (p PendingMutationPlan) MutationDigest() [32]byte   { return p.mutation.Digest() }
func (p PendingMutationPlan) Digest() [32]byte           { return p.digest }
func (p PendingMutationPlan) EvaluatedAtUnixNano() int64 { return p.mutation.EvaluatedAtUnixNano() }
func (p PendingMutationPlan) CommitNotBeforeUnixNano() int64 {
	return p.mutation.CommitNotBeforeUnixNano()
}
func (p PendingMutationPlan) CommitNotAfterUnixNano() int64 {
	return p.mutation.CommitNotAfterUnixNano()
}
func (p PendingMutationPlan) KeyMaterial() (KeyMaterialSnapshot, bool) {
	return p.mutation.KeyMaterial()
}
func (p PendingMutationPlan) Identity() (IdentitySnapshot, bool) { return p.mutation.Identity() }
func (p PendingMutationPlan) KeyLifecycle() (KeyLifecycleSnapshot, bool) {
	return p.mutation.KeyLifecycle()
}
func (p PendingMutationPlan) AuditIntent() AuditIntent { return p.audit }
func (p PendingMutationPlan) AdmissionIntent() PendingAdmissionIntent {
	return p.admission.detached()
}
func (p PendingMutationPlan) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), p.idempotencyCompletion...)
}
func (PendingMutationPlan) CommitReady() bool     { return false }
func (p PendingMutationPlan) VerifyDigest() error { return verifyPendingMutationPlan(p) }

// RequiredTransferAuthorization returns an unresolved signed-transfer
// requirement. Frozen foundation-v1 payloads carry only its digest; until the
// dedicated versioned transfer schema/verifier is joined by WS0.2b, any plan
// returning required=true is intentionally impossible to finalize.
func (p PendingMutationPlan) RequiredTransferAuthorization() (digest [32]byte, required bool) {
	digest = p.mutation.CAS().TransferEvidenceDigest
	return digest, digest != ([32]byte{})
}

// PendingAdmissionIntent is the only state that may be persisted before audit
// finalization. In one transaction it reserves both X/Y COLLECTING rows,
// immutable final-owner global IDs, and the exact pending evidence digest.
// Aborted identifier reservations become permanent tombstones; they are never
// released for reuse.
type PendingAdmissionIntent struct {
	identifierReservations  []globalid.Claim
	idempotencyReservations []idempotency.Claim
	coreEvidenceDigest      [32]byte
	evaluatedAtUnixNano     int64
	commitNotBeforeUnixNano int64
	commitNotAfterUnixNano  int64
	digest                  [32]byte
}

func (intent PendingAdmissionIntent) IdentifierReservations() []globalid.Claim {
	return append([]globalid.Claim(nil), intent.identifierReservations...)
}
func (intent PendingAdmissionIntent) IdempotencyReservations() []idempotency.Claim {
	return append([]idempotency.Claim(nil), intent.idempotencyReservations...)
}
func (intent PendingAdmissionIntent) CoreEvidenceDigest() [32]byte { return intent.coreEvidenceDigest }
func (intent PendingAdmissionIntent) EvaluatedAtUnixNano() int64   { return intent.evaluatedAtUnixNano }
func (intent PendingAdmissionIntent) CommitNotBeforeUnixNano() int64 {
	return intent.commitNotBeforeUnixNano
}
func (intent PendingAdmissionIntent) CommitNotAfterUnixNano() int64 {
	return intent.commitNotAfterUnixNano
}
func (intent PendingAdmissionIntent) Digest() [32]byte { return intent.digest }
func (intent PendingAdmissionIntent) detached() PendingAdmissionIntent {
	intent.identifierReservations = append([]globalid.Claim(nil), intent.identifierReservations...)
	intent.idempotencyReservations = append([]idempotency.Claim(nil), intent.idempotencyReservations...)
	return intent
}

// AuditIntent describes a deterministic append request; the audit store still
// assigns and validates its sequence and previous-event digest atomically.
type AuditIntent struct {
	auditEventID                string
	eventType                   string
	actorIdentity               string
	actorKeyID                  string
	subjectIDs                  []string
	causeCode                   string
	correlationID               [16]byte
	causationID                 ccse.OptionalMessageID
	messageID                   [16]byte
	idempotencyKey              [16]byte
	expectedAuditIdempotencyKey [16]byte
	sourceAuthorizationRecord   ccse.Record
	hasSourceAuthorization      bool
	sourceAuthorizationDigest   [32]byte
	sourceCausationID           ccse.OptionalMessageID
	occurredAtUnixNano          int64
	policyDigestsSHA256         [][32]byte
	evidenceDigestsSHA256       [][32]byte
	digest                      [32]byte
}

func (a AuditIntent) AuditEventID() string                { return a.auditEventID }
func (a AuditIntent) EventType() string                   { return a.eventType }
func (a AuditIntent) ActorIdentity() string               { return a.actorIdentity }
func (a AuditIntent) ActorKeyID() string                  { return a.actorKeyID }
func (a AuditIntent) SubjectIDs() []string                { return append([]string(nil), a.subjectIDs...) }
func (a AuditIntent) CauseCode() string                   { return a.causeCode }
func (a AuditIntent) CorrelationID() [16]byte             { return a.correlationID }
func (a AuditIntent) CausationID() ccse.OptionalMessageID { return a.causationID }
func (a AuditIntent) MessageID() [16]byte                 { return a.messageID }
func (a AuditIntent) IdempotencyKey() [16]byte            { return a.idempotencyKey }
func (a AuditIntent) ExpectedAuditIdempotencyKey() [16]byte {
	return a.expectedAuditIdempotencyKey
}
func (a AuditIntent) SourceAuthorizationRecord() (ccse.Record, bool) {
	if !a.hasSourceAuthorization {
		return ccse.Record{}, false
	}
	return cloneCCSERecord(a.sourceAuthorizationRecord), true
}
func (a AuditIntent) SourceAuthorizationDigest() [32]byte { return a.sourceAuthorizationDigest }
func (a AuditIntent) SourceCausationID() ccse.OptionalMessageID {
	return a.sourceCausationID
}
func (a AuditIntent) OccurredAtUnixNano() int64       { return a.occurredAtUnixNano }
func (a AuditIntent) PolicyDigestsSHA256() [][32]byte { return cloneDigests(a.policyDigestsSHA256) }
func (a AuditIntent) EvidenceDigestsSHA256() [][32]byte {
	return cloneDigests(a.evidenceDigestsSHA256)
}
func (a AuditIntent) Digest() [32]byte { return a.digest }

// ReplayScope intentionally contains no signature key identifier. Rotation
// therefore cannot reset a sender's replay sequence namespace.
type ReplayScope struct {
	CounterKind    ccse.CounterKind
	ReplayDomainID string
	SenderIdentity string
	Environment    string
	ChainID        [32]byte
	GenesisHash    [32]byte
}

// ReplayScopeFromDomain copies only the CCSE replay namespace fields.
func ReplayScopeFromDomain(domain ccse.Domain) ReplayScope {
	return ReplayScope{
		CounterKind: domain.CounterKind, ReplayDomainID: domain.ReplayDomainID,
		SenderIdentity: domain.SenderIdentity, Environment: domain.Environment,
		ChainID: domain.ChainID, GenesisHash: domain.GenesisHash,
	}
}

func cloneDigests(source [][32]byte) [][32]byte {
	return append([][32]byte(nil), source...)
}

func cloneCCSERecord(source ccse.Record) ccse.Record {
	source.Domain.Audience = append([]string(nil), source.Domain.Audience...)
	source.Envelope.Extensions = append([]ccse.Extension(nil), source.Envelope.Extensions...)
	for index := range source.Envelope.Extensions {
		source.Envelope.Extensions[index].Value = append([]byte(nil), source.Envelope.Extensions[index].Value...)
	}
	source.Payload = append([]byte(nil), source.Payload...)
	source.Signature = append([]byte(nil), source.Signature...)
	return source
}

func cloneKeyMaterial(source KeyMaterialSnapshot) KeyMaterialSnapshot {
	source.CanonicalPublicKey = append([]byte(nil), source.CanonicalPublicKey...)
	source.ProofSignature = append([]byte(nil), source.ProofSignature...)
	source.EnrollmentPolicyDigestsSHA256 = cloneDigests(source.EnrollmentPolicyDigestsSHA256)
	return source
}

func cloneIdentity(source IdentitySnapshot) IdentitySnapshot {
	source.PolicyDigestsSHA256 = cloneDigests(source.PolicyDigestsSHA256)
	source.CanonicalPayload = append([]byte(nil), source.CanonicalPayload...)
	source.Bindings.DeviceIDs = append([]string(nil), source.Bindings.DeviceIDs...)
	return source
}

func cloneLifecycle(source KeyLifecycleSnapshot) KeyLifecycleSnapshot {
	source.AllowedMessageTypeIDs = append([]uint32(nil), source.AllowedMessageTypeIDs...)
	source.PolicyDigestsSHA256 = cloneDigests(source.PolicyDigestsSHA256)
	source.CanonicalPayload = append([]byte(nil), source.CanonicalPayload...)
	return source
}
