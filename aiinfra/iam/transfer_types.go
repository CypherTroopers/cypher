// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package iam

import (
	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const maxTransferAuthorities = 64

// OwnershipTransferAuthorityRequirement is one frozen signer requirement.
// ProviderID, OrganizationID and Role are policy facts, not caller-provided
// payload fields. The kernel requires old/new organizations to be disjoint.
type OwnershipTransferAuthorityRequirement struct {
	Identity                        string
	KeyID                           string
	ProviderID                      string
	OrganizationID                  string
	Role                            string
	AuthorizationPolicyDigestSHA256 [32]byte
	Coordinator                     bool
}

// OwnershipTransferProfile is a versioned, frozen acceptance policy. Its
// canonical digest is computed by the kernel and committed to every plan.
type OwnershipTransferProfile struct {
	ProfileID                   string
	ProfileVersion              uint64
	PolicyDigest                [32]byte
	RecordIntegrityDigestSHA256 [32]byte
	OldAuthorities              []OwnershipTransferAuthorityRequirement
	NewAuthorities              []OwnershipTransferAuthorityRequirement
	Activation                  OwnershipTransferProfileActivation
}

// OwnershipTransferProfileActivation distinguishes two activations of the
// same immutable policy bytes. Collection may continue only under this exact
// row and its half-open validity interval. Once accepted, execution relies on
// the retained activation evidence rather than reinterpreting it through the
// mutable current-profile callback.
type OwnershipTransferProfileActivation struct {
	ProfileDigest      [32]byte
	ActivationVersion  uint64
	ValidFromUnixNano  int64
	ValidUntilUnixNano int64
	EvidenceDigest     [32]byte
	StateVersion       uint64
	WriterEpoch        uint64
	SnapshotDigest     [32]byte
}

func (activation OwnershipTransferProfileActivation) Precondition(profileID string,
	subjectKind uint32) SnapshotPrecondition {
	return SnapshotPrecondition{Entity: EntityRef{Kind: EntityOwnershipTransferProfileActivation,
		PrincipalKind: subjectKind, ID: profileID}, ExpectedStateVersion: activation.StateVersion,
		ExpectedWriterEpoch: activation.WriterEpoch, ExpectedState: 1,
		ExpectedSnapshotDigest: activation.SnapshotDigest}
}

type OwnershipTransferProfileRequest struct {
	TransferAuthorizationID string
	SubjectKind             uint32
	PreviousEntity          EntityRef
	NextEntity              EntityRef
	PreviousPrincipal       string
	NextPrincipal           string
	PreviousProviderID      string
	NextProviderID          string
	ExpectedGeneration      uint64
	NextGeneration          uint64
	EffectiveAtUnixNano     int64
	ExpiresAtUnixNano       int64
}

// OwnershipTransferProfileHistoryRequest resolves the exact immutable policy
// activation retained by an accepted transfer. It is distinct from the
// current-profile lookup: a later head activation must neither reinterpret nor
// strand an already accepted authorization, while a self-consistent forged
// Accepted row must not become authoritative merely by hashing itself.
type OwnershipTransferProfileHistoryRequest struct {
	ProfileID                string
	ProfileVersion           uint64
	SubjectKind              uint32
	ProfileDigest            [32]byte
	ActivationVersion        uint64
	ActivationSnapshotDigest [32]byte
}

// OwnershipTransferEvidenceRequest lets the same frozen profile validate the
// semantic issuer/type for every digest-committed auxiliary record. The
// kernel has already verified the exact CCSE record digest and signature
// boundary before invoking it.
type OwnershipTransferEvidenceRequest struct {
	TransferAuthorizationID string
	TransferEvidenceDigest  [32]byte
	Profile                 OwnershipTransferProfile
	ProfileDigest           [32]byte
	Activation              OwnershipTransferProfileActivation
	EvidenceKind            uint32
	Record                  ccse.Record
	RecordDigest            [32]byte
	EvaluatedAtUnixNano     int64
}

// OwnershipTransferEvidenceHistoryRequest resolves one immutable policy
// decision made under an exact retained profile activation. Unlike the live
// validation callback, this lookup must remain stable after policy cutover and
// is therefore suitable for terminal recovery of an already-admitted
// collection. PolicyDecisionDigest is the kernel-derived decision tuple that
// the authoritative history store must attest.
type OwnershipTransferEvidenceHistoryRequest struct {
	EvidenceRequest      OwnershipTransferEvidenceRequest
	PolicyDecisionDigest [32]byte
}

// OwnershipTransferApprovalIngestionCommand ingests exactly one declared
// authority signature. Fixed closure/evidence records are supplied in full on
// every ingestion and must match the collection byte-for-byte.
type OwnershipTransferApprovalIngestionCommand struct {
	Approval                        ccse.VerifiedRecord
	PreviousTerminalIdentityPayload []byte
	NextPendingIdentityPayload      []byte
	KeyClosureRecords               []ccse.VerifiedRecord
	EvidenceRecords                 []ccse.VerifiedRecord
	EvaluatedAtUnixNano             int64
	Fence                           WriterFence
}

type HistoricalKeyAuthorizationSnapshot struct {
	Material  KeyMaterialSnapshot
	Lifecycle KeyLifecycleSnapshot
	Identity  IdentitySnapshot
}

type RetainedVerifiedRecord struct {
	record ccse.Record
	digest [32]byte
}

func (record RetainedVerifiedRecord) Record() ccse.Record { return cloneCCSERecord(record.record) }
func (record RetainedVerifiedRecord) Digest() [32]byte    { return record.digest }

type OwnershipTransferAuthorityAdmission struct {
	Authority                 OwnershipTransferAuthorityRequirement
	OldSide                   bool
	Signed                    RetainedVerifiedRecord
	Historical                HistoricalKeyAuthorizationSnapshot
	Receiver                  ReceiverProfile
	CurrentPreconditions      []SnapshotPrecondition
	AdmissionProfileDigest    [32]byte
	AdmissionActivationDigest [32]byte
	ValidatedAtUnixNano       int64
	Fingerprint               [32]byte
}

// OwnershipTransferEvidenceAdmission is the immutable policy/authorization
// decision retained at collection time. Cutover revalidates the signature and
// historical rows against these exact bytes; it never reinterprets accepted
// evidence through a mutable current Profile callback.
type OwnershipTransferEvidenceAdmission struct {
	RecordDigest         [32]byte
	EvidenceKind         uint32
	Historical           HistoricalKeyAuthorizationSnapshot
	Receiver             ReceiverProfile
	ProfileDigest        [32]byte
	ActivationDigest     [32]byte
	PolicyDecisionDigest [32]byte
	ValidatedAtUnixNano  int64
	Fingerprint          [32]byte
}

type OwnershipTransferFixedEvidence struct {
	PreviousTerminalIdentity IdentitySnapshot
	NextPendingIdentity      IdentitySnapshot
	PreviousIdentityCAS      SnapshotPrecondition
	KeyClosureRecords        []RetainedVerifiedRecord
	KeyClosureSnapshots      []KeyLifecycleSnapshot
	EvidenceRecords          []RetainedVerifiedRecord
	EvidenceAdmissions       []OwnershipTransferEvidenceAdmission
	ClosurePreconditions     []SnapshotPrecondition
	EvidencePreconditions    []SnapshotPrecondition
}

// OwnershipTransferApprovalCollectionSnapshot is the complete durable
// COLLECTING state. ProgressDigest commits this snapshot; adapters return it
// detached and never synthesize missing signed evidence.
type OwnershipTransferApprovalCollectionSnapshot struct {
	Binding                idempotency.Binding
	Version                uint64
	ProgressDigest         [32]byte
	CanonicalPayload       []byte
	TransferEvidenceDigest [32]byte
	Profile                OwnershipTransferProfile
	ProfileDigest          [32]byte
	Approvals              []OwnershipTransferAuthorityAdmission
	FixedEvidence          OwnershipTransferFixedEvidence
	HomeRegion             string
	WriterEpoch            uint64
}

// AcceptedOwnershipTransferSnapshot is immutable authority evidence consumed
// by key enrollment and the successor PENDING identity. SnapshotDigest binds
// all full signed records (including signatures), historical authorization
// snapshots, the canonical transfer payload and frozen profile.
type AcceptedOwnershipTransferSnapshot struct {
	Projection             foundationv1.OwnershipTransferAuthorizationSigningProjection
	CanonicalPayload       []byte
	TransferEvidenceDigest [32]byte
	Profile                OwnershipTransferProfile
	ProfileDigest          [32]byte
	Approvals              []OwnershipTransferAuthorityAdmission
	FixedEvidence          OwnershipTransferFixedEvidence
	AcceptedAtUnixNano     int64
	StateVersion           uint64
	WriterEpoch            uint64
	SnapshotDigest         [32]byte
}

func (snapshot AcceptedOwnershipTransferSnapshot) Precondition() SnapshotPrecondition {
	return SnapshotPrecondition{Entity: EntityRef{Kind: EntityOwnershipTransfer,
		PrincipalKind: snapshot.Projection.SubjectKind, ID: snapshot.Projection.TransferAuthorizationID},
		ExpectedStateVersion: snapshot.StateVersion, ExpectedWriterEpoch: snapshot.WriterEpoch,
		ExpectedState: 1, ExpectedSnapshotDigest: snapshot.SnapshotDigest}
}

type OwnershipTransferCollectionDisposition uint8

const (
	OwnershipTransferCollectionAppend OwnershipTransferCollectionDisposition = iota + 1
	OwnershipTransferCollectionReplace
)

// OwnershipTransferApprovalCollectionPlan mutates only the durable approval
// collection. It is never an IAM identity/key commit-ready plan. When
// QuorumSatisfied is true, Accepted and Audit describe the immutable result
// that WS0.2b must join with canonical AuditEvent/head and X/Y completion.
type OwnershipTransferApprovalCollectionPlan struct {
	disposition                OwnershipTransferCollectionDisposition
	evaluatedAtUnixNano        int64
	commitNotBeforeUnixNano    int64
	commitNotAfterUnixNano     int64
	expectedVersion            uint64
	expectedProgressDigest     [32]byte
	expectedHomeRegion         string
	expectedWriterEpoch        uint64
	authorizedWriterEpoch      uint64
	authorizedWriterIdentity   string
	authorizedWriterHomeRegion string
	writerEvidenceDigest       [32]byte
	dependencies               []SnapshotPrecondition
	next                       OwnershipTransferApprovalCollectionSnapshot
	idempotencyClaims          []idempotency.Claim
	joinedAuditSnapshot        idempotency.Snapshot
	identifierClaims           []globalid.Claim
	quorumSatisfied            bool
	accepted                   *AcceptedOwnershipTransferSnapshot
	audit                      *AuditIntent
	idempotencyCompletion      []idempotency.Claim
	digest                     [32]byte
}

func (plan OwnershipTransferApprovalCollectionPlan) CommitReady() bool { return false }
func (plan OwnershipTransferApprovalCollectionPlan) CollectionAdmissionReady() bool {
	return plan.digest != ([32]byte{})
}
func (plan OwnershipTransferApprovalCollectionPlan) Digest() [32]byte { return plan.digest }
func (plan OwnershipTransferApprovalCollectionPlan) Disposition() OwnershipTransferCollectionDisposition {
	return plan.disposition
}
func (plan OwnershipTransferApprovalCollectionPlan) EvaluatedAtUnixNano() int64 {
	return plan.evaluatedAtUnixNano
}
func (plan OwnershipTransferApprovalCollectionPlan) CommitNotBeforeUnixNano() int64 {
	return plan.commitNotBeforeUnixNano
}
func (plan OwnershipTransferApprovalCollectionPlan) CommitNotAfterUnixNano() int64 {
	return plan.commitNotAfterUnixNano
}
func (plan OwnershipTransferApprovalCollectionPlan) ExpectedCollectionVersion() uint64 {
	return plan.expectedVersion
}
func (plan OwnershipTransferApprovalCollectionPlan) ExpectedProgressDigest() [32]byte {
	return plan.expectedProgressDigest
}
func (plan OwnershipTransferApprovalCollectionPlan) ExpectedHomeRegion() string {
	return plan.expectedHomeRegion
}
func (plan OwnershipTransferApprovalCollectionPlan) ExpectedWriterEpoch() uint64 {
	return plan.expectedWriterEpoch
}
func (plan OwnershipTransferApprovalCollectionPlan) AuthorizedWriterEpoch() uint64 {
	return plan.authorizedWriterEpoch
}
func (plan OwnershipTransferApprovalCollectionPlan) AuthorizedWriterIdentity() string {
	return plan.authorizedWriterIdentity
}
func (plan OwnershipTransferApprovalCollectionPlan) AuthorizedWriterHomeRegion() string {
	return plan.authorizedWriterHomeRegion
}
func (plan OwnershipTransferApprovalCollectionPlan) WriterEvidenceDigest() [32]byte {
	return plan.writerEvidenceDigest
}
func (plan OwnershipTransferApprovalCollectionPlan) Dependencies() []SnapshotPrecondition {
	return append([]SnapshotPrecondition(nil), plan.dependencies...)
}
func (plan OwnershipTransferApprovalCollectionPlan) NextCollection() OwnershipTransferApprovalCollectionSnapshot {
	return cloneTransferCollection(plan.next)
}
func (plan OwnershipTransferApprovalCollectionPlan) IdempotencyClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), plan.idempotencyClaims...)
}

// JoinedAuditSnapshot is nonzero for a continuation and must be rechecked in
// the same transaction as the parent collection CAS. Shared idempotency has no
// no-op assertion claim, so the exact joined row is carried separately.
func (plan OwnershipTransferApprovalCollectionPlan) JoinedAuditSnapshot() (idempotency.Snapshot, bool) {
	return plan.joinedAuditSnapshot, plan.joinedAuditSnapshot != (idempotency.Snapshot{})
}
func (plan OwnershipTransferApprovalCollectionPlan) IdentifierClaims() []globalid.Claim {
	return append([]globalid.Claim(nil), plan.identifierClaims...)
}
func (plan OwnershipTransferApprovalCollectionPlan) QuorumSatisfied() bool {
	return plan.quorumSatisfied
}
func (plan OwnershipTransferApprovalCollectionPlan) ReadyForAcceptance() bool {
	return plan.quorumSatisfied && plan.accepted == nil
}
func (plan OwnershipTransferApprovalCollectionPlan) AcceptedSnapshot() (AcceptedOwnershipTransferSnapshot, bool) {
	if plan.accepted == nil {
		return AcceptedOwnershipTransferSnapshot{}, false
	}
	return cloneAcceptedTransfer(*plan.accepted), true
}
func (plan OwnershipTransferApprovalCollectionPlan) AuditIntent() (AuditIntent, bool) {
	if plan.audit == nil {
		return AuditIntent{}, false
	}
	return *plan.audit, true
}
func (plan OwnershipTransferApprovalCollectionPlan) IdempotencyCompletionClaims() []idempotency.Claim {
	return append([]idempotency.Claim(nil), plan.idempotencyCompletion...)
}
func (plan OwnershipTransferApprovalCollectionPlan) VerifyDigest() error {
	return verifyOwnershipTransferApprovalCollectionPlan(plan)
}

func cloneTransferProfile(source OwnershipTransferProfile) OwnershipTransferProfile {
	source.OldAuthorities = append([]OwnershipTransferAuthorityRequirement(nil), source.OldAuthorities...)
	source.NewAuthorities = append([]OwnershipTransferAuthorityRequirement(nil), source.NewAuthorities...)
	return source
}

func cloneRetainedRecords(source []RetainedVerifiedRecord) []RetainedVerifiedRecord {
	result := make([]RetainedVerifiedRecord, len(source))
	for index := range source {
		result[index] = RetainedVerifiedRecord{record: cloneCCSERecord(source[index].record), digest: source[index].digest}
	}
	return result
}

func cloneTransferAdmission(source OwnershipTransferAuthorityAdmission) OwnershipTransferAuthorityAdmission {
	source.Signed = RetainedVerifiedRecord{record: cloneCCSERecord(source.Signed.record), digest: source.Signed.digest}
	source.Historical.Material = cloneKeyMaterial(source.Historical.Material)
	source.Historical.Lifecycle = cloneLifecycle(source.Historical.Lifecycle)
	source.Historical.Identity = cloneIdentity(source.Historical.Identity)
	source.Receiver = cloneReceiverProfile(source.Receiver)
	source.CurrentPreconditions = append([]SnapshotPrecondition(nil), source.CurrentPreconditions...)
	return source
}

func cloneReceiverProfile(source ReceiverProfile) ReceiverProfile {
	source.Audience = append([]string(nil), source.Audience...)
	return source
}

func cloneTransferEvidenceAdmission(source OwnershipTransferEvidenceAdmission) OwnershipTransferEvidenceAdmission {
	source.Historical.Material = cloneKeyMaterial(source.Historical.Material)
	source.Historical.Lifecycle = cloneLifecycle(source.Historical.Lifecycle)
	source.Historical.Identity = cloneIdentity(source.Historical.Identity)
	source.Receiver = cloneReceiverProfile(source.Receiver)
	return source
}

func cloneTransferFixedEvidence(source OwnershipTransferFixedEvidence) OwnershipTransferFixedEvidence {
	result := OwnershipTransferFixedEvidence{
		PreviousTerminalIdentity: cloneIdentity(source.PreviousTerminalIdentity),
		NextPendingIdentity:      cloneIdentity(source.NextPendingIdentity),
		PreviousIdentityCAS:      source.PreviousIdentityCAS,
		KeyClosureRecords:        cloneRetainedRecords(source.KeyClosureRecords),
		KeyClosureSnapshots:      append([]KeyLifecycleSnapshot(nil), source.KeyClosureSnapshots...),
		EvidenceRecords:          cloneRetainedRecords(source.EvidenceRecords),
		EvidenceAdmissions:       make([]OwnershipTransferEvidenceAdmission, len(source.EvidenceAdmissions)),
		ClosurePreconditions:     append([]SnapshotPrecondition(nil), source.ClosurePreconditions...),
		EvidencePreconditions:    append([]SnapshotPrecondition(nil), source.EvidencePreconditions...)}
	for index := range source.KeyClosureSnapshots {
		result.KeyClosureSnapshots[index] = cloneLifecycle(source.KeyClosureSnapshots[index])
	}
	for index := range source.EvidenceAdmissions {
		result.EvidenceAdmissions[index] = cloneTransferEvidenceAdmission(source.EvidenceAdmissions[index])
	}
	return result
}

func cloneTransferCollection(source OwnershipTransferApprovalCollectionSnapshot) OwnershipTransferApprovalCollectionSnapshot {
	source.CanonicalPayload = append([]byte(nil), source.CanonicalPayload...)
	source.Profile = cloneTransferProfile(source.Profile)
	source.Approvals = append([]OwnershipTransferAuthorityAdmission(nil), source.Approvals...)
	for index := range source.Approvals {
		source.Approvals[index] = cloneTransferAdmission(source.Approvals[index])
	}
	source.FixedEvidence = cloneTransferFixedEvidence(source.FixedEvidence)
	return source
}

func cloneAcceptedTransfer(source AcceptedOwnershipTransferSnapshot) AcceptedOwnershipTransferSnapshot {
	source.Projection = cloneTransferProjection(source.Projection)
	source.CanonicalPayload = append([]byte(nil), source.CanonicalPayload...)
	source.Profile = cloneTransferProfile(source.Profile)
	source.Approvals = append([]OwnershipTransferAuthorityAdmission(nil), source.Approvals...)
	for index := range source.Approvals {
		source.Approvals[index] = cloneTransferAdmission(source.Approvals[index])
	}
	source.FixedEvidence = cloneTransferFixedEvidence(source.FixedEvidence)
	return source
}

func cloneTransferProjection(source foundationv1.OwnershipTransferAuthorizationSigningProjection) foundationv1.OwnershipTransferAuthorizationSigningProjection {
	source.Metadata.PolicyDigestsSHA256 = cloneDigests(source.Metadata.PolicyDigestsSHA256)
	source.OldKeyClosures = append([]foundationv1.KeyClosureSigningProjection(nil), source.OldKeyClosures...)
	source.EvidenceCommitments = append([]foundationv1.TransferEvidenceCommitmentSigningProjection(nil), source.EvidenceCommitments...)
	source.OldAuthorities = append([]foundationv1.TransferAuthoritySigningProjection(nil), source.OldAuthorities...)
	source.NewAuthorities = append([]foundationv1.TransferAuthoritySigningProjection(nil), source.NewAuthorities...)
	return source
}
