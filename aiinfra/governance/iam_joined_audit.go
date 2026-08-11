// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const iamJoinedAuditFragmentDigestDomain = "CPH-AIIE-GOVERNANCE-IAM-JOINED-AUDIT-FRAGMENT-V1\x00"

// The bridge remains fail-closed until IAM's revalidated request carries the
// closed typed evidence fragments needed to verify every domain-separated
// evidence digest. Bare digest/domain references are not sufficient proof.
const iamJoinedTypedEvidenceBridgeEnabled = false

// IAMJoinedAuditCommand supplies only the canonical Audit Writer's signed
// event. All expected IAM intent, X/Y state, global-ID fences, evidence and
// commit-window values come from the opaque, digest-verified IAM request.
type IAMJoinedAuditCommand struct {
	AtUnixNano int64
	Request    iam.JoinedAuditRequest
	AuditEvent SignedRecord
}

// JoinedAuditFragmentSnapshot is a detached, non-committable half of the
// WS0.2b compound transaction. It contains the complete canonical audit/head
// CAS but deliberately cannot be converted into a standalone MutationPlan.
// The coordinator must join it with the exact IAM request digest and state
// commitment in one serializable transaction.
type JoinedAuditFragmentSnapshot struct {
	CommitReady                        bool
	EvaluatedAtUnixNano                int64
	CommitNotBeforeUnixNano            int64
	CommitNotAfterUnixNano             int64
	IAMRequestDigestSHA256             [ccse.DigestSize]byte
	IAMPendingDigestSHA256             [ccse.DigestSize]byte
	IAMDurableEnvelopeDigestSHA256     [ccse.DigestSize]byte
	IAMStateAndGlobalCASDigestSHA256   [ccse.DigestSize]byte
	IAMExecutionFragmentDigestSHA256   [ccse.DigestSize]byte
	ParentBinding                      idempotency.Binding
	ExpectedParentSnapshot             idempotency.Snapshot
	JoinedBinding                      idempotency.Binding
	ExpectedJoinedSnapshot             idempotency.Snapshot
	ParentCompletionClaim              idempotency.Claim
	JoinedCompletionClaim              idempotency.Claim
	JoinedAuditEventID                 string
	ExpectedOutcome                    uint32
	IAMExpectedAuditIntentDigestSHA256 [ccse.DigestSize]byte
	GovernanceProfileActivation        GovernanceProfileActivationSnapshot
	CanonicalAuditIntent               AuditIntentSnapshot
	AuditSourceDigestsSHA256           [][ccse.DigestSize]byte
	AuditSourceEvidence                []DurableEvidence
	AuditSourceKeyPreconditions        []KeyStatePrecondition
	AuditStreamID                      string
	AuditRecordID                      string
	ExpectedAuditEventAbsent           bool
	DeploymentAnchorSHA256             [ccse.DigestSize]byte
	ExpectedAuditSequence              uint64
	ExpectedAuditHeadDigestSHA256      [ccse.DigestSize]byte
	ExpectedAuditHeadHomeRegion        string
	AuthorizedAuditHomeRegion          string
	ExpectedAuditHeadWriterIdentity    string
	AuthorizedAuditWriterIdentity      string
	ExpectedAuditHeadWriterEpoch       uint64
	AuthorizedAuditWriterEpoch         uint64
	ExpectedAuditHeadProfileSHA256     [ccse.DigestSize]byte
	AuthorizedAuditProfileSHA256       [ccse.DigestSize]byte
	WriterLeaseEvidenceDigestSHA256    [ccse.DigestSize]byte
	WriterLeaseNotBeforeUnixNano       int64
	WriterLeaseNotAfterUnixNano        int64
	NextAuditSequence                  uint64
	NextAuditRecordDigestSHA256        [ccse.DigestSize]byte
	AuditEventEvidence                 SignedEvidence
	AuditWriterKeyPrecondition         KeyStatePrecondition
	AuditEventIdentifierClaim          globalid.Claim
	ExpectedIAMEvidenceReferences      []iam.ContentAddressedEvidenceReference
}

// JoinedAuditFragment is opaque and always non-committable on its own.
type JoinedAuditFragment struct {
	request          iam.JoinedAuditRequest
	audit            MutationPlan
	intent           AuditIntent
	parentExpected   idempotency.Snapshot
	joinedExpected   idempotency.Snapshot
	parentCompletion idempotency.Claim
	joinedCompletion idempotency.Claim
	expectedOutcome  uint32
	iamIntentDigest  [ccse.DigestSize]byte
	evaluatedAt      int64
	commitNotBefore  int64
	commitNotAfter   int64
	digest           [ccse.DigestSize]byte
}

func (JoinedAuditFragment) CommitReady() bool                      { return false }
func (fragment JoinedAuditFragment) Digest() [ccse.DigestSize]byte { return fragment.digest }

func (fragment JoinedAuditFragment) VerifyDigest() error {
	if fragment.request.CommitReady() || fragment.request.VerifyDigest() != nil ||
		fragment.audit.VerifyDigest() != nil || fragment.intent.VerifyDigest() != nil {
		return ErrInvalidCommand
	}
	digest, err := digestIAMJoinedAuditFragment(fragment)
	if err != nil || digest != fragment.digest {
		return ErrInvalidCommand
	}
	return nil
}

func (fragment JoinedAuditFragment) Snapshot() JoinedAuditFragmentSnapshot {
	audit := fragment.audit.Snapshot()
	execution, _ := fragment.request.ExecutionFragment()
	identifier := globalid.Claim{}
	if len(audit.IdentifierClaims) == 1 {
		identifier = audit.IdentifierClaims[0]
	}
	value := JoinedAuditFragmentSnapshot{
		CommitReady: false, EvaluatedAtUnixNano: fragment.evaluatedAt,
		CommitNotBeforeUnixNano: fragment.commitNotBefore, CommitNotAfterUnixNano: fragment.commitNotAfter,
		IAMRequestDigestSHA256: fragment.request.Digest(), IAMPendingDigestSHA256: fragment.request.PendingDigest(),
		IAMDurableEnvelopeDigestSHA256:   fragment.request.DurableEnvelopeDigest(),
		IAMStateAndGlobalCASDigestSHA256: fragment.request.StateAndGlobalCASCommitment(),
		IAMExecutionFragmentDigestSHA256: execution.Digest(),
		ParentBinding:                    fragment.request.ParentBinding(), ExpectedParentSnapshot: fragment.parentExpected,
		JoinedBinding: fragment.request.JoinedBinding(), ExpectedJoinedSnapshot: fragment.joinedExpected,
		ParentCompletionClaim: fragment.parentCompletion, JoinedCompletionClaim: fragment.joinedCompletion,
		JoinedAuditEventID: fragment.request.JoinedAuditEventID(), ExpectedOutcome: fragment.expectedOutcome,
		IAMExpectedAuditIntentDigestSHA256: fragment.iamIntentDigest,
		GovernanceProfileActivation:        audit.GovernanceProfileActivation,
		CanonicalAuditIntent:               fragment.intent.Snapshot(), AuditSourceDigestsSHA256: audit.AuditSourceDigestsSHA256,
		AuditSourceEvidence: audit.AuditSourceEvidence, AuditSourceKeyPreconditions: audit.AuditSourceKeyPreconditions,
		AuditStreamID: audit.AuditStreamID, AuditRecordID: audit.AuditRecordID,
		ExpectedAuditEventAbsent: audit.ExpectedAuditEventAbsent, DeploymentAnchorSHA256: audit.DeploymentAnchorSHA256,
		ExpectedAuditSequence: audit.ExpectedAuditSequence, ExpectedAuditHeadDigestSHA256: audit.ExpectedAuditHeadDigest,
		ExpectedAuditHeadHomeRegion: audit.ExpectedAuditHeadHomeRegion, AuthorizedAuditHomeRegion: audit.AuthorizedAuditHomeRegion,
		ExpectedAuditHeadWriterIdentity: audit.ExpectedAuditHeadWriterIdentity,
		AuthorizedAuditWriterIdentity:   audit.AuthorizedAuditWriterIdentity,
		ExpectedAuditHeadWriterEpoch:    audit.ExpectedAuditHeadWriterEpoch, AuthorizedAuditWriterEpoch: audit.AuthorizedAuditWriterEpoch,
		ExpectedAuditHeadProfileSHA256:  audit.ExpectedAuditHeadGovernanceProfileDigestSHA256,
		AuthorizedAuditProfileSHA256:    audit.AuthorizedAuditGovernanceProfileDigestSHA256,
		WriterLeaseEvidenceDigestSHA256: audit.ExpectedAuditWriterLeaseEvidenceDigestSHA256,
		WriterLeaseNotBeforeUnixNano:    audit.ExpectedAuditWriterLeaseNotBeforeUnixNano,
		WriterLeaseNotAfterUnixNano:     audit.ExpectedAuditWriterLeaseNotAfterUnixNano,
		NextAuditSequence:               audit.NextAuditSequence, NextAuditRecordDigestSHA256: audit.NextAuditRecordDigestSHA256,
		AuditEventEvidence: audit.AuditEventEvidence, AuditWriterKeyPrecondition: audit.AuditWriterKeyPrecondition,
		AuditEventIdentifierClaim:     identifier,
		ExpectedIAMEvidenceReferences: fragment.request.EvidenceReferences(),
	}
	return cloneJoinedAuditFragmentSnapshot(value)
}

// PlanIAMJoinedAudit validates the opaque IAM half and the canonical signed
// AuditEvent, but returns only a non-committable fragment. This method never
// exposes the internal standalone audit MutationPlan.
func (p *Planner) PlanIAMJoinedAudit(ctx context.Context, command IAMJoinedAuditCommand) (JoinedAuditFragment, error) {
	if p == nil || p.canonical == nil || command.AtUnixNano < 0 || command.Request.CommitReady() {
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	if err := contextErr(ctx); err != nil {
		return JoinedAuditFragment{}, err
	}
	request := command.Request
	if err := request.VerifyDigest(); err != nil {
		return JoinedAuditFragment{}, fmt.Errorf("%w: IAM joined request", ErrInvalidCommand)
	}
	if !iamJoinedTypedEvidenceBridgeEnabled {
		return JoinedAuditFragment{}, fmt.Errorf("%w: IAM typed evidence bridge unavailable", ErrInvalidCommand)
	}
	execution, hasExecution := request.ExecutionFragment()
	if !hasExecution || execution.CommitReady() || execution.VerifyDigest() != nil ||
		execution.PendingDigest() != request.PendingDigest() ||
		execution.DurableEnvelopeDigest() != request.DurableEnvelopeDigest() ||
		execution.StateAndGlobalCASCommitment() != request.StateAndGlobalCASCommitment() ||
		execution.JoinedAuditEventIdentifierAssertion() != request.JoinedAuditEventIdentifierAssertion() ||
		execution.EvaluatedAtUnixNano() != request.EvaluatedAtUnixNano() ||
		execution.CommitNotBeforeUnixNano() != request.CommitNotBeforeUnixNano() ||
		execution.CommitNotAfterUnixNano() != request.CommitNotAfterUnixNano() {
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	parentBinding := request.ParentBinding()
	joinedBinding, err := idempotency.JoinedAuditBinding(parentBinding)
	if err != nil || joinedBinding != request.JoinedBinding() || parentBinding.Domain == idempotency.OperationGovernancePolicy ||
		parentBinding.Domain == idempotency.OperationGovernanceAudit || parentBinding.Domain == idempotency.OperationJoinedAudit {
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	eventID, err := idempotency.JoinedAuditEventID(parentBinding)
	if err != nil || eventID != request.JoinedAuditEventID() {
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	decision, err := idempotency.PrecheckJoined(ctx, p.idempotency, parentBinding)
	if err != nil {
		return JoinedAuditFragment{}, err
	}
	if decision.Kind() == idempotency.DuplicateCompleted {
		return JoinedAuditFragment{}, DuplicateCompletedError{OutcomeDigestSHA256: decision.OutcomeDigest()}
	}
	if decision.Kind() != idempotency.ContinueCollection || decision.ParentSnapshot() != request.ParentExpectedSnapshot() ||
		decision.AuditSnapshot() != request.JoinedExpectedSnapshot() {
		return JoinedAuditFragment{}, ErrApprovalCollection
	}
	if command.AtUnixNano < request.EvaluatedAtUnixNano() || command.AtUnixNano < request.CommitNotBeforeUnixNano() ||
		request.CommitNotAfterUnixNano() <= command.AtUnixNano {
		return JoinedAuditFragment{}, ErrPolicyExpired
	}
	parentCompletion, err := idempotency.NewCompleteCollection(decision.ParentSnapshot())
	if err != nil {
		return JoinedAuditFragment{}, ErrApprovalCollection
	}
	joinedCompletion, err := idempotency.NewCompleteCollection(decision.AuditSnapshot())
	if err != nil || !exactCompletionClaims(request.IdempotencyCompletionClaims(), parentCompletion, joinedCompletion) {
		return JoinedAuditFragment{}, ErrApprovalCollection
	}

	iamIntent, ok := request.ExpectedAuditIntent()
	if !ok {
		// Reconciliation requires an independently verified FAILED/TIMED_OUT
		// evidence contract. Until IAM exposes its exact outcome/policy/window
		// tuple, it remains fail-closed rather than becoming a caller assertion.
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	if request.ExpectedOutcome() != 1 {
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	sourceRecord, hasSource := iamIntent.SourceAuthorizationRecord()
	if !hasSource || iamIntent.ActorKeyID() == "" {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	source, sourceKey, err := p.validateOpaqueIAMSource(ctx, sourceRecord, iamIntent.SourceAuthorizationDigest(), command.AtUnixNano)
	if err != nil || source.record.Domain.SenderIdentity != iamIntent.ActorIdentity() ||
		source.record.Domain.SignatureKeyID != iamIntent.ActorKeyID() {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	sourcePolicies := append(iamIntent.PolicyDigestsSHA256(), sourceKey.AuthorizationPolicyDigestSHA256, p.profileDigest)
	sourcePolicies = uniqueSortedDigests(sourcePolicies)
	sources := append(iamIntent.EvidenceDigestsSHA256(), source.digest)
	sources = uniqueSortedDigests(sources)
	if !validIAMEvidenceReferences(request.EvidenceReferences(), sources, source.digest) {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	transactionEvidence := map[[ccse.DigestSize]byte]DurableEvidence{
		source.digest: newSignedDurableEvidenceWithKey(source, sourceKey, sourcePolicies...),
	}
	// Resolve and validate the complete IAM evidence set before touching the
	// caller-supplied AuditEvent. planAuditAppend receives only this closed map,
	// so it cannot interleave an event signature check with late evidence I/O.
	retainedEvidence, _, resolvedPolicies, evidenceDeadline, err := p.validateAuditSources(
		ctx, sources, transactionEvidence, command.AtUnixNano,
	)
	if err != nil || len(retainedEvidence) != len(sources) || evidenceDeadline <= command.AtUnixNano {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	transactionEvidence = make(map[[ccse.DigestSize]byte]DurableEvidence, len(retainedEvidence))
	for _, evidence := range retainedEvidence {
		if _, duplicate := transactionEvidence[evidence.digest]; duplicate {
			return JoinedAuditFragment{}, ErrAuditEvidence
		}
		transactionEvidence[evidence.digest] = cloneDurableEvidence(evidence)
	}
	policies := uniqueSortedDigests(resolvedPolicies)
	expected, err := newAuditIntent(AuditIntentSnapshot{
		Required: true, StreamID: p.profile.AuditReplayDomainID, EventType: iamIntent.EventType(), AuditEventID: eventID,
		ActorIdentity: iamIntent.ActorIdentity(), ActorKeyID: iamIntent.ActorKeyID(),
		SubjectIDs: uniqueSortedStrings(iamIntent.SubjectIDs()), CauseCode: iamIntent.CauseCode(),
		OccurredAtUnixNano: iamIntent.OccurredAtUnixNano(), Outcome: request.ExpectedOutcome(), IdempotencyKey: joinedBinding.Key,
		CorrelationID: iamIntent.CorrelationID(), CausationID: iamIntent.CausationID(),
		AppliedPolicyDigestsSHA256: policies, EvidenceDigestsSHA256: sources,
	})
	if err != nil {
		return JoinedAuditFragment{}, err
	}
	auditPlan, actualIntent, err := p.planAuditAppend(ctx, AuditAppendCommand{
		AtUnixNano: command.AtUnixNano, Event: command.AuditEvent, SourceRecordDigestsSHA256: sources,
	}, transactionEvidence, ptrIdempotencySnapshot(decision.AuditSnapshot()), &parentBinding)
	if err != nil {
		return JoinedAuditFragment{}, err
	}
	if !auditIntentSatisfiesPending(actualIntent.Snapshot(), expected.Snapshot()) {
		return JoinedAuditFragment{}, ErrAuditRequired
	}
	audit := auditPlan.Snapshot()
	if !audit.CommitReady || audit.Kind != MutationAuditAppend || audit.AuditEventID != eventID ||
		len(audit.IdempotencyClaims) != 1 || audit.IdempotencyClaims[0] != joinedCompletion ||
		len(audit.IdentifierClaims) != 1 || audit.IdentifierClaims[0] != request.JoinedAuditEventIdentifierAssertion() {
		return JoinedAuditFragment{}, ErrAuditRequired
	}
	commitNotBefore := maximumInt64(request.CommitNotBeforeUnixNano(), audit.CommitNotBeforeUnixNano)
	commitNotAfter := minimumInt64(request.CommitNotAfterUnixNano(), audit.CommitNotAfterUnixNano)
	commitNotAfter = minimumInt64(commitNotAfter, evidenceDeadline)
	if commitNotAfter <= command.AtUnixNano || commitNotAfter <= commitNotBefore {
		return JoinedAuditFragment{}, ErrPolicyExpired
	}
	fragment := JoinedAuditFragment{
		request: request, audit: auditPlan, intent: actualIntent,
		parentExpected: decision.ParentSnapshot(), joinedExpected: decision.AuditSnapshot(),
		parentCompletion: parentCompletion, joinedCompletion: joinedCompletion,
		expectedOutcome: request.ExpectedOutcome(), iamIntentDigest: iamIntent.Digest(),
		evaluatedAt: command.AtUnixNano, commitNotBefore: commitNotBefore, commitNotAfter: commitNotAfter,
	}
	fragment.digest, err = digestIAMJoinedAuditFragment(fragment)
	if err != nil {
		return JoinedAuditFragment{}, err
	}
	return fragment, nil
}

func (p *Planner) validateOpaqueIAMSource(ctx context.Context, raw ccse.Record, expected [ccse.DigestSize]byte,
	at int64) (signedRecordSnapshot, GovernanceKeySnapshot, error) {
	const maxIAMSourcePayloadBytes = 1 << 20
	if isZeroDigest(expected) || !preflightRawRecord(&raw, maxIAMSourcePayloadBytes) {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	record := cloneCCSERecord(&raw)
	digest, err := record.Digest(ccse.DefaultLimits())
	if err != nil || digest != expected || record.MessageTypeID == 0 || record.SchemaVersion != p.profile.SchemaVersion ||
		record.Domain.ProtocolVersion != p.profile.ProtocolVersion || record.Envelope.ProtocolVersion != p.profile.ProtocolVersion ||
		record.Domain.TenantOrganization != p.profile.TenantOrganization || record.Domain.ProviderOrganization != p.profile.ProviderOrganization ||
		record.Domain.Environment != p.profile.Environment || record.Envelope.Environment != p.profile.Environment ||
		record.Domain.ChainID != p.profile.ChainID || record.Envelope.ChainID != p.profile.ChainID ||
		record.Domain.GenesisHash != p.profile.GenesisHash || record.Domain.Purpose == "" || record.Domain.ReplayDomainID == "" ||
		record.Domain.CounterKind == 0 || record.Domain.CounterKind != record.Envelope.CounterKind ||
		record.Domain.IssuedAtUnixNano > at || record.Domain.ExpiresAtUnixNano <= at ||
		record.Domain.ExpiresAtUnixNano-record.Domain.IssuedAtUnixNano > p.profile.MaxRecordValidityNanos ||
		sha256.Sum256(record.Payload) != record.Envelope.PayloadDigest {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	if err := p.canonical.ValidateExtensions(ctx, record.MessageTypeID, record.SchemaVersion, record.Envelope.Extensions); err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	if _, err := p.canonical.Decode(record.MessageTypeID, record.SchemaVersion, record.Payload); err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	snapshot := signedRecordSnapshot{record: record, digest: digest}
	key, err := p.authorizeKey(ctx, snapshot, record.MessageTypeID, at)
	if err != nil {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	return snapshot, key, nil
}

func exactCompletionClaims(actual []idempotency.Claim, parent, joined idempotency.Claim) bool {
	want, err := idempotency.NormalizeClaims([]idempotency.Claim{parent, joined})
	if err != nil {
		return false
	}
	got, err := idempotency.NormalizeClaims(actual)
	if err != nil || len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func validIAMEvidenceReferences(references []iam.ContentAddressedEvidenceReference,
	sources [][ccse.DigestSize]byte, signedSource [ccse.DigestSize]byte) bool {
	if len(references) != len(sources) || len(references) == 0 || len(references) > 128 {
		return false
	}
	seen := make(map[[ccse.DigestSize]byte]struct{}, len(references))
	for _, reference := range references {
		if isZeroDigest(reference.Digest) || reference.Domain == "" {
			return false
		}
		if _, duplicate := seen[reference.Digest]; duplicate {
			return false
		}
		seen[reference.Digest] = struct{}{}
		if reference.Digest == signedSource {
			if !reference.Embedded || reference.Domain != "iam.source-authorization.v1" {
				return false
			}
		} else if reference.Embedded || reference.Domain != "iam.audit-evidence.v1" {
			return false
		}
	}
	for _, source := range sources {
		if _, ok := seen[source]; !ok {
			return false
		}
	}
	return true
}

func digestIAMJoinedAuditFragment(fragment JoinedAuditFragment) ([ccse.DigestSize]byte, error) {
	if fragment.request.VerifyDigest() != nil || fragment.audit.VerifyDigest() != nil || fragment.intent.VerifyDigest() != nil ||
		fragment.evaluatedAt < 0 || fragment.commitNotBefore > fragment.evaluatedAt ||
		fragment.commitNotAfter <= fragment.evaluatedAt || fragment.commitNotAfter <= fragment.commitNotBefore ||
		fragment.parentExpected != fragment.request.ParentExpectedSnapshot() ||
		fragment.joinedExpected != fragment.request.JoinedExpectedSnapshot() || fragment.expectedOutcome != fragment.request.ExpectedOutcome() ||
		fragment.expectedOutcome == 0 || isZeroDigest(fragment.iamIntentDigest) {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	execution, ok := fragment.request.ExecutionFragment()
	if !ok || execution.CommitReady() || execution.VerifyDigest() != nil {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	parentCompletion, err := idempotency.NewCompleteCollection(fragment.parentExpected)
	if err != nil || parentCompletion != fragment.parentCompletion {
		return [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	joinedCompletion, err := idempotency.NewCompleteCollection(fragment.joinedExpected)
	if err != nil || joinedCompletion != fragment.joinedCompletion ||
		!exactCompletionClaims(fragment.request.IdempotencyCompletionClaims(), parentCompletion, joinedCompletion) {
		return [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	iamIntent, ok := fragment.request.ExpectedAuditIntent()
	if !ok || iamIntent.Digest() != fragment.iamIntentDigest {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	audit := fragment.audit.Snapshot()
	if audit.Kind != MutationAuditAppend || !audit.CommitReady || len(audit.IdempotencyClaims) != 1 ||
		audit.IdempotencyClaims[0] != fragment.joinedCompletion || len(audit.IdentifierClaims) != 1 {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	refs := fragment.request.EvidenceReferences()
	if len(refs) == 0 || len(refs) > 128 {
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	// Sort a detached copy so connector iteration cannot perturb the fragment.
	refs = append([]iam.ContentAddressedEvidenceReference(nil), refs...)
	sort.Slice(refs, func(i, j int) bool {
		if comparison := bytes.Compare(refs[i].Digest[:], refs[j].Digest[:]); comparison != 0 {
			return comparison < 0
		}
		if refs[i].Domain != refs[j].Domain {
			return refs[i].Domain < refs[j].Domain
		}
		return !refs[i].Embedded && refs[j].Embedded
	})
	w := newDigestWriter(iamJoinedAuditFragmentDigestDomain)
	w.digest(fragment.request.Digest())
	w.digest(fragment.request.PendingDigest())
	w.digest(fragment.request.DurableEnvelopeDigest())
	w.digest(fragment.request.StateAndGlobalCASCommitment())
	w.digest(execution.Digest())
	w.idempotencyBinding(fragment.request.ParentBinding())
	w.idempotencySnapshot(fragment.parentExpected)
	w.idempotencyBinding(fragment.request.JoinedBinding())
	w.idempotencySnapshot(fragment.joinedExpected)
	w.idempotencyClaims([]idempotency.Claim{fragment.parentCompletion, fragment.joinedCompletion})
	w.string(fragment.request.JoinedAuditEventID())
	w.uint64(uint64(fragment.expectedOutcome))
	w.digest(fragment.iamIntentDigest)
	w.int64(fragment.evaluatedAt)
	w.int64(fragment.commitNotBefore)
	w.int64(fragment.commitNotAfter)
	w.digest(fragment.audit.Digest())
	w.digest(fragment.intent.Digest())
	w.uint64(uint64(len(refs)))
	for _, reference := range refs {
		w.digest(reference.Digest)
		w.string(reference.Domain)
		w.bool(reference.Embedded)
	}
	return w.sum()
}

func cloneJoinedAuditFragmentSnapshot(value JoinedAuditFragmentSnapshot) JoinedAuditFragmentSnapshot {
	value.CanonicalAuditIntent = cloneAuditIntentSnapshot(value.CanonicalAuditIntent)
	value.AuditSourceDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.AuditSourceDigestsSHA256...)
	value.AuditSourceEvidence = append([]DurableEvidence(nil), value.AuditSourceEvidence...)
	for index := range value.AuditSourceEvidence {
		value.AuditSourceEvidence[index] = cloneDurableEvidence(value.AuditSourceEvidence[index])
	}
	value.AuditSourceKeyPreconditions = append([]KeyStatePrecondition(nil), value.AuditSourceKeyPreconditions...)
	value.AuditEventEvidence = cloneSignedEvidence(value.AuditEventEvidence)
	value.ExpectedIAMEvidenceReferences = append([]iam.ContentAddressedEvidenceReference(nil), value.ExpectedIAMEvidenceReferences...)
	return value
}
