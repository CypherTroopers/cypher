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
	ErrSemanticUnrehydratable  = errors.New("aiinfra governance: canonical row has no lossless semantic companion")
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
	KeyMaterialStateVersion         uint64
	KeyMaterialStateDigestSHA256    [ccse.DigestSize]byte
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
	IdentityKind                      uint32
	IdentityPrincipalKind             uint32
	IdentityObjectID                  string
	IdentityStateVersion              uint64
	IdentityWriterEpoch               uint64
	IdentitySnapshotDigestSHA256      [ccse.DigestSize]byte
	AuthorizationSnapshotDigestSHA256 [ccse.DigestSize]byte
	KeyMaterialStateVersion           uint64
	KeyMaterialStateDigestSHA256      [ccse.DigestSize]byte
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

// CanonicalGovernanceKeyStateProjection is the exact storage-neutral IAM
// read-set behind one Governance key precondition. A composition-root adapter
// must obtain all three rows from the same optimistic pre-sign snapshot used
// to resolve the key. Governance retains the codec-owned bytes and the final
// serializable UoW must assert them byte-for-byte; it must not reconstruct IAM
// rows from the smaller KeyStatePrecondition tuple.
type CanonicalGovernanceKeyStateProjection struct {
	KeyMaterial CanonicalStateRecord
	Lifecycle   CanonicalStateRecord
	Identity    CanonicalStateRecord
}

// CanonicalGovernanceKeyStateView is an optional authoritative extension.
// Planning fails closed when it is absent because a digest-only key fence
// cannot be translated into an exact durable read assertion without guessing
// IAM's private canonical codecs.
type CanonicalGovernanceKeyStateView interface {
	CanonicalGovernanceKeyState(context.Context, KeyStatePrecondition) (
		CanonicalGovernanceKeyStateProjection, bool, error)
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

// CanonicalGovernanceProfileActivationView is an optional authoritative
// extension implemented by a composition-root adapter. Governance owns the
// closed activation codec and byte-compares the returned row to the exact
// semantic snapshot; the adapter supplies authoritative row presence only.
type CanonicalGovernanceProfileActivationView interface {
	CanonicalGovernanceProfileActivation(context.Context, GovernanceProfileActivationSnapshot) (CanonicalStateRecord, bool, error)
}

// CanonicalPolicyRegistryTransition is the detached semantic request supplied
// to the policy view's canonical codec. The view returns both the exact locked
// row and the exact proposed row in one snapshot operation.
type CanonicalPolicyRegistryTransition struct {
	Action                         MutationKind
	PolicyKind                     string
	PolicyBundleID                 string
	PolicyRecordID                 string
	PolicySequence                 uint64
	PolicyBundleDigestSHA256       [ccse.DigestSize]byte
	CanonicalPolicyBundle          []byte
	AuditEventID                   string
	ExpectedHeadPresent            bool
	ExpectedHeadSequence           uint64
	ExpectedHeadBundleDigestSHA256 [ccse.DigestSize]byte
	GovernanceProfileActivation    GovernanceProfileActivationSnapshot
}

// CanonicalGovernancePolicyRegistryView is an optional authoritative state
// extension. Implementations obtain Expected and project Next under the
// immutable canonical-state contract; Governance byte-compares both rows to
// the signed canonical policy payload and exact registry head.
type CanonicalGovernancePolicyRegistryView interface {
	CanonicalGovernancePolicyRegistryTransition(context.Context, CanonicalPolicyRegistryTransition) (
		expected CanonicalStateRecord, expectedPresent bool, next CanonicalStateRecord, err error)
}

const (
	CanonicalStateNamespaceIAM        uint8 = 1
	CanonicalStateNamespaceGovernance uint8 = 2

	CanonicalStateKindIAMKeyMaterial  = "cph.aiinfra.iam.key-material.v1"
	CanonicalStateKindIAMIdentity     = "cph.aiinfra.iam.identity.v1"
	CanonicalStateKindIAMKeyLifecycle = "cph.aiinfra.iam.key-lifecycle.v1"
	CanonicalStateKindIAMWriterLease  = "cph.aiinfra.iam.writer-lease.v1"

	CanonicalStateContentTypeIAMKeyMaterial  = "application/cph.aiinfra.iam.key-material-state.v1"
	CanonicalStateContentTypeIAMIdentity     = "application/cph.aiinfra.iam.identity-state.v1"
	CanonicalStateContentTypeIAMKeyLifecycle = "application/cph.aiinfra.iam.key-lifecycle-state.v1"
	CanonicalStateContentTypeIAMWriterLease  = "application/cph.aiinfra.iam.writer-lease-state.v1"

	CanonicalStateKindGovernancePolicyRegistry    = "cph.aiinfra.governance.policy-registry.v1"
	CanonicalStateKindGovernanceProfileActivation = "cph.aiinfra.governance.profile-activation.v1"

	CanonicalStateContentTypeGovernancePolicyRegistry    = "application/cph.aiinfra.governance.policy-registry-state.v1"
	CanonicalStateContentTypeGovernanceProfileActivation = "application/cph.aiinfra.governance.profile-activation-state.v1"
)

// CanonicalStateRecord is the storage-neutral exact row projection accepted
// from the authoritative view. StateDigest is semantic-codec-owned, so this
// package validates the complete row shape and immutable ownership but never
// substitutes plain SHA-256 for that digest.
type CanonicalStateRecord struct {
	Namespace          uint8
	Kind               string
	ObjectID           string
	Version            uint64
	StateDigestSHA256  [ccse.DigestSize]byte
	ContentType        string
	CanonicalState     []byte
	Terminal           bool
	AuditEventID       string
	HasValidityWindow  bool
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
}

// CanonicalStateAssertion is an opaque read assertion. Construction is
// restricted to exact rows returned by an authoritative canonical-state view,
// and its digest is re-derived from the complete retained row on every plan
// verification.
type CanonicalStateAssertion struct {
	record CanonicalStateRecord
	digest [ccse.DigestSize]byte
}

// CanonicalKeyStateAssertion is the opaque, storage-ready read capability for
// one key authorization snapshot. Records returns the exact IAM
// key-material/lifecycle/identity rows in deterministic order.
type CanonicalKeyStateAssertion struct {
	precondition KeyStatePrecondition
	records      []CanonicalStateAssertion
	digest       [ccse.DigestSize]byte
}

func (value CanonicalKeyStateAssertion) KeyPrecondition() KeyStatePrecondition {
	return value.precondition
}
func (value CanonicalKeyStateAssertion) Records() []CanonicalStateRecord {
	result := make([]CanonicalStateRecord, len(value.records))
	for index := range value.records {
		result[index] = value.records[index].Record()
	}
	return result
}
func (value CanonicalKeyStateAssertion) Digest() [ccse.DigestSize]byte { return value.digest }
func (value CanonicalKeyStateAssertion) VerifyDigest() error {
	digest, err := digestCanonicalKeyStateAssertion(value.precondition, value.records)
	if err != nil || digest != value.digest {
		return ErrSnapshotInconsistent
	}
	return nil
}

// CanonicalAuditWriterLeaseAssertion is the opaque current-authority read
// capability. Record is a complete IAM writer-lease row ready for a storage
// assertion; Requirement is the independently bound Governance tuple used to
// select it.
type CanonicalAuditWriterLeaseAssertion struct {
	requirement CanonicalAuditWriterLeaseRequirement
	record      CanonicalStateAssertion
	digest      [ccse.DigestSize]byte
}

func (value CanonicalAuditWriterLeaseAssertion) Requirement() CanonicalAuditWriterLeaseRequirement {
	return value.requirement
}
func (value CanonicalAuditWriterLeaseAssertion) Record() CanonicalStateRecord {
	return value.record.Record()
}
func (value CanonicalAuditWriterLeaseAssertion) Digest() [ccse.DigestSize]byte { return value.digest }
func (value CanonicalAuditWriterLeaseAssertion) VerifyDigest() error {
	digest, err := digestCanonicalAuditWriterLeaseAssertion(value.requirement, value.record)
	if err != nil || digest != value.digest {
		return ErrSnapshotInconsistent
	}
	return nil
}

func (value CanonicalStateAssertion) Record() CanonicalStateRecord {
	return cloneCanonicalStateRecord(value.record)
}
func (value CanonicalStateAssertion) Digest() [ccse.DigestSize]byte { return value.digest }
func (value CanonicalStateAssertion) VerifyDigest() error {
	digest, err := digestCanonicalStateAssertion(value.record)
	if err != nil || digest != value.digest {
		return ErrSnapshotInconsistent
	}
	return nil
}

// CanonicalStateMutation retains the complete expected->next CAS. A nil
// Expected row is valid only for an absent-to-version-one insert.
type CanonicalStateMutation struct {
	expected *CanonicalStateRecord
	next     CanonicalStateRecord
	digest   [ccse.DigestSize]byte
}

func (value CanonicalStateMutation) Expected() (CanonicalStateRecord, bool) {
	if value.expected == nil {
		return CanonicalStateRecord{}, false
	}
	return cloneCanonicalStateRecord(*value.expected), true
}
func (value CanonicalStateMutation) Next() CanonicalStateRecord {
	return cloneCanonicalStateRecord(value.next)
}
func (value CanonicalStateMutation) Digest() [ccse.DigestSize]byte { return value.digest }
func (value CanonicalStateMutation) VerifyDigest() error {
	digest, err := digestCanonicalStateMutation(value.expected, value.next)
	if err != nil || digest != value.digest {
		return ErrSnapshotInconsistent
	}
	return nil
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

// PolicyApprovalCollectionPersistenceSnapshot is an exact, storage-neutral
// read of the current open kind-7 head. It is accepted only through the
// optional authoritative extension below and is redecoded/rederived before a
// persistence capability is minted.
type PolicyApprovalCollectionPersistenceSnapshot struct {
	PendingKey                   [ccse.MessageIDSize]byte
	Kind                         DurablePendingKind
	Codec                        string
	CodecVersion                 uint32
	Revision                     uint64
	PreviousEnvelopeDigestSHA256 [ccse.DigestSize]byte
	EnvelopeDigestSHA256         [ccse.DigestSize]byte
	CanonicalEnvelope            []byte
	EvidenceDigestsSHA256        [][ccse.DigestSize]byte
	Status                       DurablePendingStatus
	CommitNotBeforeUnixNano      int64
	CommitNotAfterUnixNano       int64
	TerminalOutcomeDigestSHA256  [ccse.DigestSize]byte
	ExpectedAuditEventID         string
}

type PolicyApprovalCollectionPersistenceView interface {
	SnapshotPolicyApprovalCollectionPersistence(context.Context, [ccse.MessageIDSize]byte) (
		PolicyApprovalCollectionPersistenceSnapshot, bool, error)
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
	// EvidenceSemanticReceipt is a protocol-owned, domain-separated canonical
	// preimage. Unlike EvidenceContentSHA256, its address is not the plain
	// SHA-256 of Content. The closed domain is retained and rechecked by every
	// plan digest before a storage adapter may persist it.
	EvidenceSemanticReceipt
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

// CanonicalAuditWriterLeaseRequirement is the complete current-authority
// tuple selected before the outer AuditEvent is signed. It is deliberately
// separate from the immutable historical audit-head tuple so lease renewal
// and higher-epoch failover remain reachable.
type CanonicalAuditWriterLeaseRequirement struct {
	StreamID                                string
	WriterLeaseEntityKind                   uint32
	WriterLeaseEntityPrincipalKind          uint32
	WriterLeaseEntityID                     string
	AuthorizedWriterIdentity                string
	AuthorizedHomeRegion                    string
	AuthorizedWriterEpoch                   uint64
	AuthorizedGovernanceProfileDigestSHA256 [ccse.DigestSize]byte
	WriterLeaseEvidenceDigestSHA256         [ccse.DigestSize]byte
	WriterLeaseNotBeforeUnixNano            int64
	WriterLeaseNotAfterUnixNano             int64
}

// CanonicalAuditWriterLeaseView is a fail-closed optional extension. It must
// resolve the exact IAM writer-lease row semantically encoding requirement.
// The final UoW asserts that row byte-for-byte rather than treating the
// renewable tuple cached in audit_head as current authority.
type CanonicalAuditWriterLeaseView interface {
	CanonicalAuditWriterLease(context.Context, CanonicalAuditWriterLeaseRequirement) (
		CanonicalStateRecord, bool, error)
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
	CanonicalStateAssertions                       []CanonicalStateAssertion
	CanonicalKeyStateAssertions                    []CanonicalKeyStateAssertion
	CanonicalAuditWriterLeaseAssertion             CanonicalAuditWriterLeaseAssertion
	CanonicalStateMutations                        []CanonicalStateMutation
	DurablePolicyApprovalTerminalTemplate          DurablePendingTerminalTemplate
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
	AuditSourceStorageCapabilities                 []DurableEvidenceStorageCapability
	AuditSourceKeyPreconditions                    []KeyStatePrecondition
	CanonicalAuditAppend                           CanonicalAuditAppendCapability
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
	semanticDomain             string
	signed                     SignedEvidence
	authorizationPolicyDigests [][ccse.DigestSize]byte
	keyPreconditionPresent     bool
	keyPrecondition            KeyStatePrecondition
	authorizationNotAfter      int64
}

// CanonicalAuditAppendCapability is the storage-neutral, immutable projection
// of one exact AuditEvent append and its complete audit-head CAS. A storage
// mapper copies its getters; it never decodes the signed payload or derives a
// prior-head field itself.
type CanonicalAuditAppendCapability struct {
	eventID                             string
	streamID                            string
	sequence                            uint64
	previousEventDigest                 [ccse.DigestSize]byte
	hasPrevious                         bool
	eventDigest                         [ccse.DigestSize]byte
	recordDigest                        [ccse.DigestSize]byte
	canonicalEvent                      []byte
	occurredAtUnixNano                  int64
	deploymentAnchorDigest              [ccse.DigestSize]byte
	expectedHeadWriterIdentity          string
	authorizedWriterIdentity            string
	expectedHeadHomeRegion              string
	authorizedHomeRegion                string
	expectedHeadWriterEpoch             uint64
	authorizedWriterEpoch               uint64
	expectedHeadGovernanceProfileDigest [ccse.DigestSize]byte
	authorizedGovernanceProfileDigest   [ccse.DigestSize]byte
	writerLeaseEvidenceDigest           [ccse.DigestSize]byte
	writerLeaseNotBeforeUnixNano        int64
	writerLeaseNotAfterUnixNano         int64
	digest                              [ccse.DigestSize]byte
}

func (value CanonicalAuditAppendCapability) EventID() string  { return value.eventID }
func (value CanonicalAuditAppendCapability) StreamID() string { return value.streamID }
func (value CanonicalAuditAppendCapability) Sequence() uint64 { return value.sequence }
func (value CanonicalAuditAppendCapability) PreviousEventDigest() ([ccse.DigestSize]byte, bool) {
	return value.previousEventDigest, value.hasPrevious
}
func (value CanonicalAuditAppendCapability) EventDigest() [ccse.DigestSize]byte {
	return value.eventDigest
}
func (value CanonicalAuditAppendCapability) RecordDigest() [ccse.DigestSize]byte {
	return value.recordDigest
}
func (value CanonicalAuditAppendCapability) CanonicalEvent() []byte {
	return append([]byte(nil), value.canonicalEvent...)
}
func (value CanonicalAuditAppendCapability) OccurredAtUnixNano() int64 {
	return value.occurredAtUnixNano
}
func (value CanonicalAuditAppendCapability) DeploymentAnchorDigest() [ccse.DigestSize]byte {
	return value.deploymentAnchorDigest
}
func (value CanonicalAuditAppendCapability) ExpectedHeadWriterIdentity() string {
	return value.expectedHeadWriterIdentity
}
func (value CanonicalAuditAppendCapability) AuthorizedWriterIdentity() string {
	return value.authorizedWriterIdentity
}
func (value CanonicalAuditAppendCapability) ExpectedHeadHomeRegion() string {
	return value.expectedHeadHomeRegion
}
func (value CanonicalAuditAppendCapability) AuthorizedHomeRegion() string {
	return value.authorizedHomeRegion
}
func (value CanonicalAuditAppendCapability) ExpectedHeadWriterEpoch() uint64 {
	return value.expectedHeadWriterEpoch
}
func (value CanonicalAuditAppendCapability) AuthorizedWriterEpoch() uint64 {
	return value.authorizedWriterEpoch
}
func (value CanonicalAuditAppendCapability) ExpectedHeadGovernanceProfileDigest() [ccse.DigestSize]byte {
	return value.expectedHeadGovernanceProfileDigest
}
func (value CanonicalAuditAppendCapability) AuthorizedGovernanceProfileDigest() [ccse.DigestSize]byte {
	return value.authorizedGovernanceProfileDigest
}
func (value CanonicalAuditAppendCapability) WriterLeaseEvidenceDigest() [ccse.DigestSize]byte {
	return value.writerLeaseEvidenceDigest
}
func (value CanonicalAuditAppendCapability) WriterLeaseNotBeforeUnixNano() int64 {
	return value.writerLeaseNotBeforeUnixNano
}
func (value CanonicalAuditAppendCapability) WriterLeaseNotAfterUnixNano() int64 {
	return value.writerLeaseNotAfterUnixNano
}
func (value CanonicalAuditAppendCapability) Digest() [ccse.DigestSize]byte { return value.digest }
func (value CanonicalAuditAppendCapability) VerifyDigest() error {
	digest, err := digestCanonicalAuditAppendCapability(value)
	if err != nil || digest != value.digest {
		return ErrAuditAnchor
	}
	return nil
}

// DurableEvidenceStorageKind uses the exact closed numeric representation of
// the canonical storage contract. Value 3 is reserved for IAM authenticated
// evidence and cannot be minted by Governance.
type DurableEvidenceStorageKind uint8

const (
	DurableEvidenceStorageContentSHA256 DurableEvidenceStorageKind = 1
	DurableEvidenceStorageSignedCCSE    DurableEvidenceStorageKind = 2
	DurableEvidenceStorageSemantic      DurableEvidenceStorageKind = 4

	DurableEvidenceContentSHA256ContentType = "application/vnd.cph.aiinfra.governance.content-sha256.v1"
	DurableEvidenceSignedCCSEContentType    = "application/vnd.cph.aiinfra.governance.signed-ccse-record.v1+ccse"
	DurableEvidenceSemanticContentType      = "application/vnd.cph.aiinfra.governance.semantic-receipt.v1+ccse"
)

// DurablePendingKind and DurablePendingStatus use the exact closed numeric
// storage contract without importing a concrete database adapter. Governance
// can mint only kind 7.
type DurablePendingKind uint8
type DurablePendingStatus uint8

const (
	DurablePendingGovernancePolicyApprovalCollection DurablePendingKind   = 7
	DurablePendingOpen                               DurablePendingStatus = 1
	DurablePendingTerminal                           DurablePendingStatus = 2
)

// DurablePendingRevisionCapability is the exact storage-ready kind-7
// revision. All mutable bytes are private and every getter is detached.
type DurablePendingRevisionCapability struct {
	pendingKey                      [ccse.MessageIDSize]byte
	expectedKind                    DurablePendingKind
	kind                            DurablePendingKind
	codec                           string
	codecVersion                    uint32
	revision                        uint64
	previousEnvelopeDigest          [ccse.DigestSize]byte
	previousCanonicalEnvelope       []byte
	previousCommitNotBeforeUnixNano int64
	previousCommitNotAfterUnixNano  int64
	sourcePreviousEnvelopeDigest    [ccse.DigestSize]byte
	sourceEvidenceDigests           [][ccse.DigestSize]byte
	envelopeDigest                  [ccse.DigestSize]byte
	canonicalEnvelope               []byte
	evidenceDigests                 [][ccse.DigestSize]byte
	status                          DurablePendingStatus
	commitNotBeforeUnixNano         int64
	commitNotAfterUnixNano          int64
	terminalOutcomeDigest           [ccse.DigestSize]byte
	expectedAuditEventID            string
	terminalTemplateBaseDigest      [ccse.DigestSize]byte
	digest                          [ccse.DigestSize]byte
}

func (value DurablePendingRevisionCapability) PendingKey() [ccse.MessageIDSize]byte {
	return value.pendingKey
}
func (value DurablePendingRevisionCapability) ExpectedKind() DurablePendingKind {
	return value.expectedKind
}
func (value DurablePendingRevisionCapability) Kind() DurablePendingKind { return value.kind }
func (value DurablePendingRevisionCapability) Codec() string            { return value.codec }
func (value DurablePendingRevisionCapability) CodecVersion() uint32     { return value.codecVersion }
func (value DurablePendingRevisionCapability) Revision() uint64         { return value.revision }
func (value DurablePendingRevisionCapability) PreviousEnvelopeDigest() [ccse.DigestSize]byte {
	return value.previousEnvelopeDigest
}
func (value DurablePendingRevisionCapability) PreviousCanonicalEnvelope() []byte {
	return append([]byte(nil), value.previousCanonicalEnvelope...)
}
func (value DurablePendingRevisionCapability) PreviousCommitWindow() (int64, int64) {
	return value.previousCommitNotBeforeUnixNano, value.previousCommitNotAfterUnixNano
}
func (value DurablePendingRevisionCapability) SourcePreviousEnvelopeDigest() ([ccse.DigestSize]byte, bool) {
	return value.sourcePreviousEnvelopeDigest, value.revision > 1
}
func (value DurablePendingRevisionCapability) SourceEvidenceDigests() ([][ccse.DigestSize]byte, bool) {
	return append([][ccse.DigestSize]byte(nil), value.sourceEvidenceDigests...), value.revision > 1
}
func (value DurablePendingRevisionCapability) EnvelopeDigest() [ccse.DigestSize]byte {
	return value.envelopeDigest
}
func (value DurablePendingRevisionCapability) CanonicalEnvelope() []byte {
	return append([]byte(nil), value.canonicalEnvelope...)
}
func (value DurablePendingRevisionCapability) EvidenceDigests() [][ccse.DigestSize]byte {
	return append([][ccse.DigestSize]byte(nil), value.evidenceDigests...)
}
func (value DurablePendingRevisionCapability) Status() DurablePendingStatus { return value.status }
func (value DurablePendingRevisionCapability) CommitWindow() (int64, int64) {
	return value.commitNotBeforeUnixNano, value.commitNotAfterUnixNano
}
func (value DurablePendingRevisionCapability) TerminalOutcomeDigest() ([ccse.DigestSize]byte, bool) {
	return value.terminalOutcomeDigest, value.status == DurablePendingTerminal && !isZeroDigest(value.terminalOutcomeDigest)
}
func (value DurablePendingRevisionCapability) ExpectedAuditEventID() string {
	return value.expectedAuditEventID
}
func (value DurablePendingRevisionCapability) TerminalTemplateBaseDigest() ([ccse.DigestSize]byte, bool) {
	return value.terminalTemplateBaseDigest, value.status == DurablePendingTerminal && !isZeroDigest(value.terminalTemplateBaseDigest)
}
func (value DurablePendingRevisionCapability) Digest() [ccse.DigestSize]byte { return value.digest }
func (value DurablePendingRevisionCapability) VerifyDigest() error {
	digest, err := digestDurablePendingRevisionCapability(value)
	if err != nil || digest != value.digest {
		return ErrApprovalCollection
	}
	return nil
}

// DurablePendingTerminalTemplate binds every terminal field except the outer
// audited replay outcome. The explicit V1 unset sentinel is included in its
// BaseDigest. Finalize accepts only a nonzero result digest and cannot alter
// any base field.
type DurablePendingTerminalTemplate struct {
	base       DurablePendingRevisionCapability
	baseDigest [ccse.DigestSize]byte
}

func (value DurablePendingTerminalTemplate) BaseDigest() [ccse.DigestSize]byte {
	return value.baseDigest
}
func (value DurablePendingTerminalTemplate) VerifyDigest() error {
	digest, err := digestDurablePendingTerminalTemplate(value.base)
	if err != nil || digest != value.baseDigest || value.base.terminalTemplateBaseDigest != value.baseDigest {
		return ErrApprovalCollection
	}
	return nil
}
func (value DurablePendingTerminalTemplate) PendingKey() [ccse.MessageIDSize]byte {
	return value.base.pendingKey
}
func (value DurablePendingTerminalTemplate) Revision() uint64 { return value.base.revision }
func (value DurablePendingTerminalTemplate) ExpectedAuditEventID() string {
	return value.base.expectedAuditEventID
}
func (value DurablePendingTerminalTemplate) Finalize(resultDigest [ccse.DigestSize]byte) (DurablePendingRevisionCapability, error) {
	if value.VerifyDigest() != nil || isZeroDigest(resultDigest) {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	result := cloneDurablePendingRevisionCapability(value.base)
	result.terminalOutcomeDigest = resultDigest
	var err error
	result.digest, err = digestDurablePendingRevisionCapability(result)
	if err != nil {
		return DurablePendingRevisionCapability{}, ErrApprovalCollection
	}
	return result, nil
}

// DurableEvidenceStorageDisposition closes the coordinator action for one
// evidence row. ReserveNew maps only to immutable insertion; AssertExisting
// maps only to byte-exact assertion. It is not inferred from row presence.
type DurableEvidenceStorageDisposition uint8

const (
	DurableEvidenceStorageReserveNew DurableEvidenceStorageDisposition = iota + 1
	DurableEvidenceStorageAssertExisting
)

// DurableEvidenceStorageCapability is the sole storage-ready representation
// of Governance audit evidence. Its canonical bytes and attribution are
// private and digest-bound; a coordinator only copies the public getters into
// its durable evidence row and performs no codec inference.
type DurableEvidenceStorageCapability struct {
	evidenceDigest   [ccse.DigestSize]byte
	kind             DurableEvidenceStorageKind
	contentType      string
	canonicalContent []byte
	// expectedAuditEventID is immutable evidence-row origin attribution.
	// auditAssertionEventID is the current AuditEvent whose assertion consumes
	// the row; these differ when IAM reuses admission evidence for a child.
	expectedAuditEventID  string
	auditAssertionEventID string
	disposition           DurableEvidenceStorageDisposition
	hasPendingLink        bool
	pendingKey            [ccse.MessageIDSize]byte
	pendingRevision       uint64
	iamExistingProof      *durableEvidenceIAMExistingProof
	digest                [ccse.DigestSize]byte
}

func (value DurableEvidenceStorageCapability) EvidenceDigest() [ccse.DigestSize]byte {
	return value.evidenceDigest
}
func (value DurableEvidenceStorageCapability) Kind() DurableEvidenceStorageKind { return value.kind }
func (value DurableEvidenceStorageCapability) ContentType() string              { return value.contentType }
func (value DurableEvidenceStorageCapability) CanonicalContent() []byte {
	return append([]byte(nil), value.canonicalContent...)
}
func (value DurableEvidenceStorageCapability) ExpectedAuditEventID() string {
	return value.expectedAuditEventID
}
func (value DurableEvidenceStorageCapability) AuditAssertionEventID() string {
	return value.auditAssertionEventID
}
func (value DurableEvidenceStorageCapability) Disposition() DurableEvidenceStorageDisposition {
	return value.disposition
}
func (value DurableEvidenceStorageCapability) PendingLink() ([ccse.MessageIDSize]byte, uint64, bool) {
	return value.pendingKey, value.pendingRevision, value.hasPendingLink
}
func (value DurableEvidenceStorageCapability) Digest() [ccse.DigestSize]byte { return value.digest }
func (value DurableEvidenceStorageCapability) VerifyDigest() error {
	digest, err := digestDurableEvidenceStorageCapability(value)
	if err != nil || digest != value.digest {
		return ErrAuditEvidence
	}
	return nil
}

func (e DurableEvidence) Kind() EvidenceKind             { return e.kind }
func (e DurableEvidence) Digest() [ccse.DigestSize]byte  { return e.digest }
func (e DurableEvidence) Content() []byte                { return append([]byte(nil), e.content...) }
func (e DurableEvidence) SemanticDomain() string         { return e.semanticDomain }
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
	CanonicalStateAssertions              []CanonicalStateAssertion
	CanonicalKeyStateAssertions           []CanonicalKeyStateAssertion
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
	DurablePendingRevision                DurablePendingRevisionCapability
	NextEvidenceStorageCapability         DurableEvidenceStorageCapability
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
	value.CanonicalStateAssertions = cloneCanonicalStateAssertions(value.CanonicalStateAssertions)
	value.CanonicalKeyStateAssertions = cloneCanonicalKeyStateAssertions(value.CanonicalKeyStateAssertions)
	value.DurablePendingRevision = cloneDurablePendingRevisionCapability(value.DurablePendingRevision)
	value.NextEvidenceStorageCapability = cloneDurableEvidenceStorageCapabilities(
		[]DurableEvidenceStorageCapability{value.NextEvidenceStorageCapability})[0]
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
