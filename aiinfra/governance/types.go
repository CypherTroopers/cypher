// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package governance validates signed policy approvals and immutable audit
// appends. It is deliberately a semantic planning kernel: it reads detached
// authoritative snapshots and returns deterministic compare-and-swap plans,
// but never mutates a registry, audit store, IAM state, or external service.
package governance

import (
	"context"
	"errors"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

var (
	ErrInvalidConfiguration    = errors.New("aiinfra governance: invalid configuration")
	ErrInvalidCommand          = errors.New("aiinfra governance: invalid command")
	ErrInvalidSignedRecord     = errors.New("aiinfra governance: invalid signed record binding")
	ErrWrongRecordContext      = errors.New("aiinfra governance: wrong CCSE record context")
	ErrApprovalPayloadMismatch = errors.New("aiinfra governance: approval payload mismatch")
	ErrApprovalSetMismatch     = errors.New("aiinfra governance: actual and declared approval sets differ")
	ErrDuplicateApprover       = errors.New("aiinfra governance: duplicate approver identity or key")
	ErrApprovalQuorum          = errors.New("aiinfra governance: approval quorum is not satisfied")
	ErrRoleSeparation          = errors.New("aiinfra governance: approval role separation is not satisfied")
	ErrUnknownGovernanceKey    = errors.New("aiinfra governance: unknown governance key")
	ErrKeyOwnership            = errors.New("aiinfra governance: key is not owned by the signed sender")
	ErrKeyNotActive            = errors.New("aiinfra governance: key is not active")
	ErrKeyRevoked              = errors.New("aiinfra governance: key is revoked")
	ErrKeyExpired              = errors.New("aiinfra governance: key is expired")
	ErrKeyNotAuthorized        = errors.New("aiinfra governance: key is not authorized")
	ErrInvalidSignature        = errors.New("aiinfra governance: invalid approval signature")
	ErrPolicySequence          = errors.New("aiinfra governance: invalid policy sequence")
	ErrPolicyPredecessor       = errors.New("aiinfra governance: invalid policy predecessor")
	ErrRollbackTarget          = errors.New("aiinfra governance: invalid rollback target")
	ErrActivationDelay         = errors.New("aiinfra governance: activation delay is not satisfied")
	ErrPolicyExpired           = errors.New("aiinfra governance: policy is expired")
	ErrPolicyConflict          = errors.New("aiinfra governance: conflicting policy exists")
	ErrBreakGlassScope         = errors.New("aiinfra governance: invalid break-glass scope")
	ErrBreakGlassExpiry        = errors.New("aiinfra governance: invalid break-glass expiry")
	ErrBreakGlassDualControl   = errors.New("aiinfra governance: break-glass dual control is not satisfied")
	ErrAuditRequired           = errors.New("aiinfra governance: immutable audit is required")
	ErrAuditAnchor             = errors.New("aiinfra governance: invalid deployment audit anchor")
	ErrAuditWriter             = errors.New("aiinfra governance: invalid audit writer")
	ErrAuditSequence           = errors.New("aiinfra governance: audit sequence gap or fork")
	ErrAuditLink               = errors.New("aiinfra governance: audit hash-chain link mismatch")
	ErrAuditEvidence           = errors.New("aiinfra governance: required source record digest is absent from audit evidence")
	ErrSnapshotInconsistent    = errors.New("aiinfra governance: authoritative snapshot is inconsistent")
	ErrApprovalCollection      = errors.New("aiinfra governance: approval collection is required or inconsistent")
)

// DuplicateCompletedError returns the durable outcome for an exact retry.
// Callers must not invoke semantic planning against advanced state.
type DuplicateCompletedError struct {
	OutcomeDigestSHA256 [ccse.DigestSize]byte
}

func (e DuplicateCompletedError) Error() string {
	return "aiinfra governance: business operation already completed"
}

// DuplicateApprovalError is the durable outcome of retrying the exact same
// signed approval while its policy operation is still COLLECTING. No write is
// required; callers should return this version/progress tuple to the submitter.
type DuplicateApprovalError struct {
	CollectionVersion    uint64
	ProgressDigestSHA256 [ccse.DigestSize]byte
	RecordDigestSHA256   [ccse.DigestSize]byte
}

func (e DuplicateApprovalError) Error() string {
	return "aiinfra governance: signed approval already collected"
}

const (
	// KeyLifecycleStateActive is the immutable v1 KeyLifecycle ACTIVE value.
	KeyLifecycleStateActive uint32 = 2

	PolicyStateApprovedDelayed uint32 = 2
	PolicyStateActive          uint32 = 3
	PolicyStateRolledBack      uint32 = 4
	PolicyStateRevoked         uint32 = 5
	PolicyStateExpired         uint32 = 6
)

// SignedRecord binds the retained signed CCSE record to the immutable snapshot
// returned by ccse.Verifier. The kernel rebinds every signed field and digest;
// callers cannot substitute a different raw record after verification.
type SignedRecord struct {
	Record   *ccse.Record
	Verified ccse.VerifiedRecord
}

// GovernanceKeySnapshot is the minimum IAM projection needed by this package.
// Implementations must return detached PublicKey, AllowedMessageTypeIDs, and
// Roles values. The kernel defensively copies them again before inspection.
type GovernanceKeySnapshot struct {
	KeyID                           string
	SubjectIdentity                 string
	TargetIdentityKind              uint32
	TargetPrincipalKind             uint32
	TargetIdentityID                string
	OrganizationIdentity            string
	Algorithm                       ccse.SignatureAlgorithmID
	PublicKey                       []byte
	LifecycleState                  uint32
	NotBeforeUnixNano               int64
	NotAfterUnixNano                int64
	RevokedAtUnixNano               int64
	AllowedMessageTypeIDs           []uint32
	Roles                           []string
	AuthorizationPolicyDigestSHA256 [ccse.DigestSize]byte
	StateVersion                    uint64
	WriterEpoch                     uint64
	SnapshotDigestSHA256            [ccse.DigestSize]byte
	IdentityStateVersion            uint64
	IdentityWriterEpoch             uint64
	IdentitySnapshotDigestSHA256    [ccse.DigestSize]byte
	EnrollmentDomainID              string
	EnrollmentEnvironment           string
	EnrollmentGenesisHash           [ccse.DigestSize]byte
}

// KeyStatePrecondition fences revocation/rotation between semantic planning
// and commit. The durable adapter must recheck every tuple in the same
// serializable transaction as policy and audit CAS operations.
type KeyStatePrecondition struct {
	KeyID                             string
	StateVersion                      uint64
	WriterEpoch                       uint64
	SnapshotDigestSHA256              [ccse.DigestSize]byte
	IdentityStateVersion              uint64
	IdentityWriterEpoch               uint64
	IdentitySnapshotDigestSHA256      [ccse.DigestSize]byte
	AuthorizationSnapshotDigestSHA256 [ccse.DigestSize]byte
}

// IAMView is intentionally local to avoid an iam <-> governance import cycle.
// A composition-root adapter can project the durable IAM read model into this
// exact, read-only contract.
type IAMView interface {
	ResolveGovernanceKey(context.Context, string) (GovernanceKeySnapshot, error)
	// ResolveGovernanceKeyAt returns the immutable authorization snapshot that
	// was authoritative at the supplied instant. Durable collection/history
	// recovery must not trust a key snapshot stored beside its own signed
	// record, and must not reinterpret an old approval through current IAM
	// state after rotation or revocation.
	ResolveGovernanceKeyAt(context.Context, string, int64) (GovernanceKeySnapshot, bool, error)
}

// PolicyRecordSnapshot describes one immutable policy-registry history item.
// BundleDigestSHA256 is SHA-256 of the canonical PolicyBundle payload, not a
// signer-specific CCSE record digest.
type PolicyRecordSnapshot struct {
	BundleDigestSHA256            [ccse.DigestSize]byte
	CanonicalPayload              []byte
	GovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	RecordID                      string
	HomeRegion                    string
	WriterEpoch                   uint64
	StateVersion                  uint64
	PolicyBundleID                string
	PolicyKind                    string
	PolicyVersion                 ccse.Version
	Sequence                      uint64
	PredecessorPresent            bool
	PredecessorDigestSHA256       [ccse.DigestSize]byte
	RollbackTargetPresent         bool
	RollbackTargetDigestSHA256    [ccse.DigestSize]byte
	State                         uint32
	ApprovedAtUnixNano            int64
	EffectiveAtUnixNano           int64
	ExpiresAtUnixNano             int64
	PolicyDocumentDigestSHA256    [ccse.DigestSize]byte
	PolicyDocumentMediaType       string
	ApproverIdentities            []string
	ApproverKeyIDs                []string
	MinimumApprovals              uint32
	Emergency                     bool
	BreakGlassExpiresAtUnixNano   int64
	BreakGlassScopes              []string
	ApprovalEvidence              []HistoricalPolicyApprovalEvidence
	AcceptanceEvidence            PolicyAcceptanceEvidenceSnapshot
}

// PolicyAcceptanceEvidenceSnapshot binds an immutable registry row to the
// writer lease/profile under which it committed and to retained compound
// plan/result objects addressed by their digests.
type PolicyAcceptanceEvidenceSnapshot struct {
	AcceptedAtUnixNano              int64
	HomeRegion                      string
	WriterEpoch                     uint64
	WriterLeaseEvidenceDigestSHA256 [ccse.DigestSize]byte
	WriterLeaseNotBeforeUnixNano    int64
	WriterLeaseNotAfterUnixNano     int64
	GovernanceProfileDigestSHA256   [ccse.DigestSize]byte
	GovernanceProfileActivation     GovernanceProfileActivationSnapshot
	MutationPlanDigestSHA256        [ccse.DigestSize]byte
	DurableResultDigestSHA256       [ccse.DigestSize]byte
}

// HistoricalPolicyApprovalEvidence is the complete signed authorization and
// the immutable IAM authorization snapshot accepted with one policy history
// record. A durable adapter must back the IAM lifecycle/identity digests with
// its historical registry, rather than reconstructing them from current IAM.
type HistoricalPolicyApprovalEvidence struct {
	Signed                      SignedRecord
	Key                         GovernanceKeySnapshot
	GovernanceProfileActivation GovernanceProfileActivationSnapshot
}

// PolicyRegistrySnapshot is one atomic, bounded view used to derive a CAS
// precondition. HeadPresent=false requires Head and all head fields to be zero.
type PolicyRegistrySnapshot struct {
	HeadPresent                     bool
	Head                            PolicyRecordSnapshot
	Records                         []PolicyRecordSnapshot
	AuthorizedHomeRegion            string
	AuthorizedWriterEpoch           uint64
	GovernanceProfileDigestSHA256   [ccse.DigestSize]byte
	WriterLeaseEvidenceDigestSHA256 [ccse.DigestSize]byte
	WriterLeaseNotBeforeUnixNano    int64
	WriterLeaseNotAfterUnixNano     int64
}

type PolicyView interface {
	SnapshotPolicy(context.Context, string) (PolicyRegistrySnapshot, error)
}

// GovernanceProfileCatalog resolves immutable, versioned acceptance profiles
// for historical records. Tightening the current profile must not reinterpret
// an already accepted record under different quorum or emergency rules.
type GovernanceProfileCatalog interface {
	ResolveGovernanceProfile(context.Context, [ccse.DigestSize]byte) (Profile, bool, error)
	ActiveGovernanceProfile(context.Context, int64) (GovernanceProfileActivationSnapshot, bool, error)
}

// GovernanceProfileActivationSnapshot is the authoritative timeline row used
// both for historical interpretation and as a commit-time CAS. Validity is a
// half-open interval and EvidenceDigest names its immutable activation record.
type GovernanceProfileActivationSnapshot struct {
	GovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	Version                       uint64
	ValidFromUnixNano             int64
	ValidUntilUnixNano            int64
	EvidenceDigestSHA256          [ccse.DigestSize]byte
}

// PolicyApprovalCollectionEntry is the immutable admission evidence for one
// collected vote. AdmissionKey is the complete IAM/profile projection that
// authorized Signed at ValidatedAt; AdmissionFingerprintSHA256 commits all of
// these fields. This lets timeout reconciliation authenticate an old vote
// after key/profile rotation without granting it current authority.
type PolicyApprovalCollectionEntry struct {
	Signed                        SignedRecord
	AdmissionKey                  GovernanceKeySnapshot
	GovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	GovernanceProfileActivation   GovernanceProfileActivationSnapshot
	ValidatedAtUnixNano           int64
	AdmissionFingerprintSHA256    [ccse.DigestSize]byte
}

// ApprovalAdmissionEvidence is the detached, digest-bound form retained by a
// pending/final mutation plan. RecordDigest joins it to ApprovalEvidence.
type ApprovalAdmissionEvidence struct {
	RecordDigestSHA256            [ccse.DigestSize]byte
	AdmissionKey                  GovernanceKeySnapshot
	GovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	GovernanceProfileActivation   GovernanceProfileActivationSnapshot
	ValidatedAtUnixNano           int64
	AdmissionFingerprintSHA256    [ccse.DigestSize]byte
}

// ApprovalCollectionView returns the complete detached admission-evidence
// set for one COLLECTING policy operation. The idempotency snapshot supplies
// its authoritative version and progress digest.
type ApprovalCollectionView interface {
	SnapshotPolicyApprovalCollection(context.Context, [ccse.MessageIDSize]byte) ([]PolicyApprovalCollectionEntry, error)
}

// PolicyDocumentSnapshot is metadata independently resolved by the content
// digest committed in PolicyBundle. v1 keeps the policy document opaque, so
// break-glass scope must be verified through this content-addressed view.
type PolicyDocumentSnapshot struct {
	DigestSHA256      [ccse.DigestSize]byte
	MediaType         string
	CanonicalDocument []byte
}

type PolicyDocumentView interface {
	ResolvePolicyDocument(context.Context, [ccse.DigestSize]byte) (PolicyDocumentSnapshot, error)
}

// EvidenceSnapshot is a content-addressed immutable source used by standalone
// audit appends. CanonicalPreimage is hashed by the kernel; DigestSHA256 is not
// trusted as an assertion by the view.
type EvidenceKind uint8

const (
	EvidenceContentSHA256 EvidenceKind = iota + 1
	EvidenceSignedCCSERecord
)

// EvidenceSnapshot is a closed union. Content is used only by
// EvidenceContentSHA256; Signed is used only by EvidenceSignedCCSERecord.
type EvidenceSnapshot struct {
	Kind         EvidenceKind
	DigestSHA256 [ccse.DigestSize]byte
	Content      []byte
	Signed       SignedRecord
}

type EvidenceView interface {
	ResolveEvidence(context.Context, [ccse.DigestSize]byte) (EvidenceSnapshot, bool, error)
}

// AuditHeadSnapshot is the single-writer append head. DeploymentAnchor is a
// nonzero, immutable deployment input. Sequence zero links the first event to
// that anchor; subsequent events link to LastRecordDigestSHA256.
type AuditHeadSnapshot struct {
	StreamID                                string
	DeploymentAnchorSHA256                  [ccse.DigestSize]byte
	Sequence                                uint64
	LastRecordDigestSHA256                  [ccse.DigestSize]byte
	HeadWriterIdentity                      string
	AuthorizedWriterIdentity                string
	HomeRegion                              string
	AuthorizedHomeRegion                    string
	WriterEpoch                             uint64
	AuthorizedWriterEpoch                   uint64
	HeadGovernanceProfileDigestSHA256       [ccse.DigestSize]byte
	AuthorizedGovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	WriterLeaseEvidenceDigestSHA256         [ccse.DigestSize]byte
	WriterLeaseNotBeforeUnixNano            int64
	WriterLeaseNotAfterUnixNano             int64
}

type AuditView interface {
	SnapshotAuditHead(context.Context, string) (AuditHeadSnapshot, error)
	LookupAuditEvent(context.Context, string) (AuditEventSnapshot, bool, error)
}

// AuditEventSnapshot is the immutable uniqueness index for AuditEventID.
type AuditEventSnapshot struct {
	Sequence           uint64
	RecordDigestSHA256 [ccse.DigestSize]byte
}

// Profile fixes deployment and receiver identity. Slice fields are copied by
// NewPlanner and are never retained by alias.
type Profile struct {
	ProtocolVersion                        ccse.Version
	SchemaVersion                          ccse.Version
	Audience                               []string
	TenantOrganization                     ccse.OptionalString
	ProviderOrganization                   ccse.OptionalString
	Environment                            string
	ChainID                                [ccse.DigestSize]byte
	GenesisHash                            [ccse.DigestSize]byte
	PolicyReplayDomainID                   string
	AuditReplayDomainID                    string
	AuditWriterIdentity                    string
	AuditWriterKeyID                       string
	AuditWriterRole                        string
	PolicyHomeRegion                       string
	AuditHomeRegion                        string
	AuditDeploymentAnchorSHA256            [ccse.DigestSize]byte
	EnrollmentDomainID                     string
	MinimumApprovals                       uint32
	MinimumDistinctApprovalOrganizations   uint32
	RequiredApprovalRoles                  []string
	BreakGlassMinimumApprovals             uint32
	BreakGlassMinimumDistinctOrganizations uint32
	BreakGlassRequiredRoles                []string
	AllowedBreakGlassScopes                []string
	MinActivationDelayNanos                int64
	MaxBreakGlassDurationNanos             int64
	MaxRecordValidityNanos                 int64
	MaxClockSkewNanos                      int64
	MaxPlanCommitLatencyNanos              int64
	MaxPolicyRecords                       int
}

// PolicyApprovalCommand contains all CCSE approvals over one canonical
// PolicyBundle payload. AtUnixNano is supplied by the caller so planning is
// deterministic and never consults a host clock.
type PolicyApprovalCommand struct {
	AtUnixNano int64
	Approvals  []SignedRecord
}

type PolicyApprovalIngestionCommand struct {
	AtUnixNano int64
	Approval   SignedRecord
}

// AuditAppendCommand plans one append. SourceRecordDigestsSHA256 names the
// authorizations/evidence that caused the event; every value must occur in the
// signed AuditEvent evidence set.
type AuditAppendCommand struct {
	AtUnixNano                int64
	Event                     SignedRecord
	SourceRecordDigestsSHA256 [][ccse.DigestSize]byte
}

type MutationKind uint8

const (
	MutationPolicyPublish MutationKind = iota + 1
	MutationPolicyActivate
	MutationPolicyRollback
	MutationPolicyRevoke
	MutationPolicyExpire
	MutationPolicyAbort
	MutationAuditAppend
)

// MutationPlan is a deterministic, detached compare-and-swap description. It
// deliberately carries no callback, transaction, handle, or mutable store.
type MutationPlanSnapshot struct {
	CommitReady                                    bool
	EvaluatedAtUnixNano                            int64
	CommitNotBeforeUnixNano                        int64
	CommitNotAfterUnixNano                         int64
	GovernanceProfileDigestSHA256                  [ccse.DigestSize]byte
	GovernanceProfileActivation                    GovernanceProfileActivationSnapshot
	Kind                                           MutationKind
	PolicyBundleID                                 string
	PolicyRecordID                                 string
	PolicyKind                                     string
	PolicySequence                                 uint64
	PolicyBundleDigestSHA256                       [ccse.DigestSize]byte
	PolicyDocumentDigestSHA256                     [ccse.DigestSize]byte
	PolicyDocumentEvidence                         []byte
	PolicyIdempotencySnapshot                      idempotency.Snapshot
	JoinedAuditIdempotencySnapshot                 idempotency.Snapshot
	ExpectedPolicyHeadPresent                      bool
	ExpectedPolicyHeadSequence                     uint64
	ExpectedPolicyHeadDigest                       [ccse.DigestSize]byte
	ExpectedPolicyHeadHomeRegion                   string
	AuthorizedPolicyHomeRegion                     string
	ExpectedPolicyHeadWriterEpoch                  uint64
	AuthorizedPolicyWriterEpoch                    uint64
	ExpectedPolicyWriterLeaseEvidenceDigestSHA256  [ccse.DigestSize]byte
	ExpectedPolicyWriterLeaseNotBeforeUnixNano     int64
	ExpectedPolicyWriterLeaseNotAfterUnixNano      int64
	RollbackTargetPresent                          bool
	RollbackTargetDigestSHA256                     [ccse.DigestSize]byte
	ApprovedAtUnixNano                             int64
	EffectiveAtUnixNano                            int64
	ExpiresAtUnixNano                              int64
	Emergency                                      bool
	BreakGlassExpiresAtUnixNano                    int64
	BreakGlassScopes                               []string
	ApprovalRecordDigestsSHA256                    [][ccse.DigestSize]byte
	AuditSourceDigestsSHA256                       [][ccse.DigestSize]byte
	AuditSourceEvidence                            []DurableEvidence
	AuditSourceKeyPreconditions                    []KeyStatePrecondition
	ApprovalEvidence                               []SignedEvidence
	ApprovalAdmissionEvidence                      []ApprovalAdmissionEvidence
	ApprovalKeyPreconditions                       []KeyStatePrecondition
	ExpectedPolicyBundleIDAbsent                   bool
	PolicyBundleOwnerDigestSHA256                  [ccse.DigestSize]byte
	ExpectedPolicyRecordIDAbsent                   bool
	AuditStreamID                                  string
	AuditEventID                                   string
	AuditRecordID                                  string
	ExpectedAuditEventAbsent                       bool
	DeploymentAnchorSHA256                         [ccse.DigestSize]byte
	ExpectedAuditSequence                          uint64
	ExpectedAuditHeadDigest                        [ccse.DigestSize]byte
	ExpectedAuditHeadHomeRegion                    string
	AuthorizedAuditHomeRegion                      string
	ExpectedAuditHeadWriterIdentity                string
	AuthorizedAuditWriterIdentity                  string
	ExpectedAuditHeadWriterEpoch                   uint64
	AuthorizedAuditWriterEpoch                     uint64
	ExpectedAuditHeadGovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	AuthorizedAuditGovernanceProfileDigestSHA256   [ccse.DigestSize]byte
	ExpectedAuditWriterLeaseEvidenceDigestSHA256   [ccse.DigestSize]byte
	ExpectedAuditWriterLeaseNotBeforeUnixNano      int64
	ExpectedAuditWriterLeaseNotAfterUnixNano       int64
	NextAuditSequence                              uint64
	NextAuditRecordDigestSHA256                    [ccse.DigestSize]byte
	AuditEventEvidence                             SignedEvidence
	AuditWriterKeyPrecondition                     KeyStatePrecondition
	IdentifierClaims                               []globalid.Claim
	IdempotencyClaims                              []idempotency.Claim
	IdempotencyOutcome                             uint32
}

// AuditIntent is mandatory output for every accepted governance mutation. A
// storage adapter must append the corresponding signed AuditEvent atomically
// with the plan or reject the mutation.
type AuditIntentSnapshot struct {
	Required                              bool
	StreamID                              string
	EventType                             string
	AuditEventID                          string
	ActorIdentity                         string
	ActorKeyID                            string
	SubjectIDs                            []string
	CauseCode                             string
	OccurredAtUnixNano                    int64
	Outcome                               uint32
	IdempotencyKey                        [ccse.MessageIDSize]byte
	CorrelationID                         [ccse.MessageIDSize]byte
	CausationID                           ccse.OptionalMessageID
	WriterAuthorizationPolicyDigestSHA256 [ccse.DigestSize]byte
	AppliedPolicyDigestsSHA256            [][ccse.DigestSize]byte
	EvidenceDigestsSHA256                 [][ccse.DigestSize]byte
	Emergency                             bool
	BreakGlassExpiresAtUnixNano           int64
	BreakGlassScopes                      []string
}

// SignedEvidence is an immutable retained authorization. Record returns a new
// deep copy on every call, including payload, signature and extension values.
type SignedEvidence struct {
	record       ccse.Record
	recordDigest [ccse.DigestSize]byte
}

// DurableEvidence is immutable content-addressed evidence retained by a plan.
// SignedEvidence returns a detached full CCSE record for signed sources.
type DurableEvidence struct {
	kind                       EvidenceKind
	digest                     [ccse.DigestSize]byte
	content                    []byte
	signed                     SignedEvidence
	authorizationPolicyDigests [][ccse.DigestSize]byte
	keyPreconditionPresent     bool
	keyPrecondition            KeyStatePrecondition
	authorizationNotAfter      int64
}

func (e DurableEvidence) Kind() EvidenceKind             { return e.kind }
func (e DurableEvidence) Digest() [ccse.DigestSize]byte  { return e.digest }
func (e DurableEvidence) Content() []byte                { return append([]byte(nil), e.content...) }
func (e DurableEvidence) SignedEvidence() SignedEvidence { return cloneSignedEvidence(e.signed) }
func (e DurableEvidence) AuthorizationPolicyDigests() [][ccse.DigestSize]byte {
	return append([][ccse.DigestSize]byte(nil), e.authorizationPolicyDigests...)
}
func (e DurableEvidence) KeyPrecondition() (KeyStatePrecondition, bool) {
	return e.keyPrecondition, e.keyPreconditionPresent
}
func (e DurableEvidence) AuthorizationNotAfterUnixNano() int64 { return e.authorizationNotAfter }

func (e SignedEvidence) Record() *ccse.Record {
	record := cloneCCSERecord(&e.record)
	return &record
}

func (e SignedEvidence) RecordDigest() [ccse.DigestSize]byte { return e.recordDigest }

// MutationPlan and AuditIntent keep mutable collections private. Snapshot
// returns detached values; Digest is a domain-separated commitment recomputed
// by VerifyDigest before a commit adapter uses the plan.
type MutationPlan struct {
	value  MutationPlanSnapshot
	digest [ccse.DigestSize]byte
}

func (p MutationPlan) Snapshot() MutationPlanSnapshot { return cloneMutationPlanSnapshot(p.value) }
func (p MutationPlan) Digest() [ccse.DigestSize]byte  { return p.digest }
func (p MutationPlan) CommitReady() bool              { return p.value.CommitReady && p.VerifyDigest() == nil }
func (p MutationPlan) VerifyDigest() error {
	digest, err := digestMutationPlan(p.value)
	if err != nil {
		return err
	}
	if digest != p.digest {
		return ErrInvalidCommand
	}
	return nil
}

type AuditIntent struct {
	value  AuditIntentSnapshot
	digest [ccse.DigestSize]byte
}

func (i AuditIntent) Snapshot() AuditIntentSnapshot { return cloneAuditIntentSnapshot(i.value) }
func (i AuditIntent) Digest() [ccse.DigestSize]byte { return i.digest }
func (i AuditIntent) VerifyDigest() error {
	digest, err := digestAuditIntent(i.value)
	if err != nil {
		return err
	}
	if digest != i.digest {
		return ErrInvalidCommand
	}
	return nil
}

// PendingPolicyPlan is the non-committable result of approval verification.
// FinalizePolicyMutation must bind its exact audit intent to a signed
// AuditEvent and one audit-head CAS before a commit-ready MutationPlan exists.
type PendingPolicyPlan struct {
	policy MutationPlan
	audit  AuditIntent
	digest [ccse.DigestSize]byte
}

type ApprovalCollectionDisposition uint8

const (
	ApprovalCollectionAppend ApprovalCollectionDisposition = iota + 1
	ApprovalCollectionReplace
)

type ApprovalCollectionPlanSnapshot struct {
	CommitReady                           bool
	EvaluatedAtUnixNano                   int64
	CommitNotBeforeUnixNano               int64
	CommitNotAfterUnixNano                int64
	GovernanceProfileDigestSHA256         [ccse.DigestSize]byte
	GovernanceProfileActivation           GovernanceProfileActivationSnapshot
	Disposition                           ApprovalCollectionDisposition
	Binding                               idempotency.Binding
	JoinedAuditIdempotencySnapshot        idempotency.Snapshot
	Claims                                []idempotency.Claim
	ExpectedCollectionRecordDigestsSHA256 [][ccse.DigestSize]byte
	ExpectedReplacedRecordDigestSHA256    [ccse.DigestSize]byte
	NextCollectionRecordDigestsSHA256     [][ccse.DigestSize]byte
	PreviousProgressDigestSHA256          [ccse.DigestSize]byte
	NextProgressDigestSHA256              [ccse.DigestSize]byte
	NextEvidence                          SignedEvidence
	NextKeyPrecondition                   KeyStatePrecondition
	NextAdmissionKey                      GovernanceKeySnapshot
	NextAdmissionProfileDigestSHA256      [ccse.DigestSize]byte
	NextAdmissionProfileActivation        GovernanceProfileActivationSnapshot
	NextAdmissionValidatedAtUnixNano      int64
	NextAdmissionFingerprintSHA256        [ccse.DigestSize]byte
	JoinedAuditEventID                    string
	IdentifierClaims                      []globalid.Claim
}

type ApprovalCollectionPlan struct {
	value  ApprovalCollectionPlanSnapshot
	digest [ccse.DigestSize]byte
}

func (p ApprovalCollectionPlan) Snapshot() ApprovalCollectionPlanSnapshot {
	value := p.value
	value.ExpectedCollectionRecordDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.ExpectedCollectionRecordDigestsSHA256...)
	value.NextCollectionRecordDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.NextCollectionRecordDigestsSHA256...)
	value.Claims = append([]idempotency.Claim(nil), value.Claims...)
	value.IdentifierClaims = append([]globalid.Claim(nil), value.IdentifierClaims...)
	value.NextEvidence = cloneSignedEvidence(value.NextEvidence)
	value.NextAdmissionKey = cloneKeySnapshot(value.NextAdmissionKey)
	return value
}
func (p ApprovalCollectionPlan) Digest() [ccse.DigestSize]byte { return p.digest }
func (p ApprovalCollectionPlan) CommitReady() bool {
	return p.value.CommitReady && p.VerifyDigest() == nil
}
func (p ApprovalCollectionPlan) VerifyDigest() error {
	digest, err := digestApprovalCollectionPlan(p.value)
	if err != nil || digest != p.digest {
		return ErrInvalidCommand
	}
	return nil
}

func (p PendingPolicyPlan) PolicySnapshot() MutationPlanSnapshot { return p.policy.Snapshot() }
func (p PendingPolicyPlan) AuditIntent() AuditIntent             { return p.audit }
func (p PendingPolicyPlan) Digest() [ccse.DigestSize]byte        { return p.digest }
func (p PendingPolicyPlan) VerifyDigest() error {
	if err := p.policy.VerifyDigest(); err != nil {
		return err
	}
	if err := p.audit.VerifyDigest(); err != nil {
		return err
	}
	expected := digestPendingPolicyPlan(p.policy.Digest(), p.audit.Digest())
	if expected != p.digest {
		return ErrInvalidCommand
	}
	return nil
}

// PolicyFinalizeCommand supplies the already signed audit event. Its source
// evidence is derived from PendingPolicyPlan and cannot be weakened by caller
// input.
type PolicyFinalizeCommand struct {
	AtUnixNano int64
	AuditEvent SignedRecord
}

// PolicyReconcileCommand terminally closes a stranded COLLECTING policy
// operation after its authorization/policy deadline. Outcome must be FAILED
// (3) or TIMED_OUT (4); no policy-registry state is mutated.
type PolicyReconcileCommand struct {
	AtUnixNano int64
	Binding    idempotency.Binding
	Outcome    uint32
	AuditEvent SignedRecord
}
