// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const iamJoinedAuditFragmentDigestDomain = "CPH-AIIE-GOVERNANCE-IAM-JOINED-AUDIT-FRAGMENT-V6\x00"

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
// IAM state/persistence and Governance audit/profile/head values are
// optimistic pre-sign snapshots: the coordinator must join and byte-exactly
// assert/CAS them in one serializable final transaction. Replanning after the
// AuditEvent is signed would create a signature/result cycle and is forbidden.
// A reconciliation database clock observation is therefore a final-result
// concern, not a field inferred or required by this pre-sign fragment.
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
	CanonicalStateAssertions           []CanonicalStateAssertion
	CanonicalKeyStateAssertions        []CanonicalKeyStateAssertion
	CanonicalAuditWriterLeaseAssertion CanonicalAuditWriterLeaseAssertion
	CanonicalAuditIntent               AuditIntentSnapshot
	AuditSourceDigestsSHA256           [][ccse.DigestSize]byte
	AuditSourceEvidence                []DurableEvidence
	AuditSourceStorageCapabilities     []DurableEvidenceStorageCapability
	AuditSourceKeyPreconditions        []KeyStatePrecondition
	CanonicalAuditAppend               CanonicalAuditAppendCapability
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
	IAMAuditEvidenceBundleDigestSHA256 [ccse.DigestSize]byte
	IAMAuditEvidenceBundleDomain       string
	IAMAuditEvidenceCount              int
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
		CanonicalStateAssertions:           cloneCanonicalStateAssertions(audit.CanonicalStateAssertions),
		CanonicalKeyStateAssertions:        cloneCanonicalKeyStateAssertions(audit.CanonicalKeyStateAssertions),
		CanonicalAuditWriterLeaseAssertion: cloneCanonicalAuditWriterLeaseAssertion(audit.CanonicalAuditWriterLeaseAssertion),
		CanonicalAuditIntent:               fragment.intent.Snapshot(), AuditSourceDigestsSHA256: audit.AuditSourceDigestsSHA256,
		AuditSourceEvidence:            audit.AuditSourceEvidence,
		AuditSourceStorageCapabilities: cloneDurableEvidenceStorageCapabilities(audit.AuditSourceStorageCapabilities),
		AuditSourceKeyPreconditions:    audit.AuditSourceKeyPreconditions,
		CanonicalAuditAppend:           cloneCanonicalAuditAppendCapability(audit.CanonicalAuditAppend),
		AuditStreamID:                  audit.AuditStreamID, AuditRecordID: audit.AuditRecordID,
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
		AuditEventEvidence:                 audit.AuditEventEvidence,
		AuditWriterKeyPrecondition:         audit.AuditWriterKeyPrecondition,
		AuditEventIdentifierClaim:          identifier,
		IAMAuditEvidenceBundleDigestSHA256: auditEvidenceBundleDigest(fragment.request),
	}
	if bundle, ok := fragment.request.AuditEvidenceBundle(); ok {
		value.IAMAuditEvidenceCount = bundle.EvidenceCount()
		value.IAMAuditEvidenceBundleDomain, _, _ = bundle.SemanticReceipt()
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

	bundle, ok := request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(request) != nil || bundle.EvidenceCount() <= 0 || bundle.EvidenceCount() > 384 {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	domain, canonicalReceipt, bundleDigest := bundle.SemanticReceipt()
	if domain != iamAuditEvidenceReceiptDomain || len(canonicalReceipt) == 0 || len(canonicalReceipt) > 64<<20 ||
		bundleDigest != bundle.Digest() {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	receiptEvidence, err := newIAMSemanticReceiptEvidence(domain, canonicalReceipt, bundleDigest)
	if err != nil {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	sourceRecord, hasSource := bundle.SourceAuthorizationRecord()
	sourceDigest := bundle.SourceAuthorizationDigest()
	if !hasSource || isZeroDigest(sourceDigest) {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	sources := bundle.AuditSourceDigestsSHA256()
	if sourceDigest == bundleDigest || len(sources) != 2 || hasDuplicateDigests(sources) ||
		!containsDigest(sources, sourceDigest) || !containsDigest(sources, bundleDigest) {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	sources = uniqueSortedDigests(sources)

	expectedOutcome := request.ExpectedOutcome()
	if expectedOutcome != 1 && expectedOutcome != 3 && expectedOutcome != 4 {
		return JoinedAuditFragment{}, ErrInvalidCommand
	}
	transactionEvidence := map[[ccse.DigestSize]byte]DurableEvidence{bundleDigest: receiptEvidence}
	var (
		eventType        string
		actorIdentity    string
		actorKeyID       string
		subjectIDs       []string
		causeCode        string
		occurredAt       int64
		correlationID    [ccse.MessageIDSize]byte
		causationID      ccse.OptionalMessageID
		semanticPolicies [][ccse.DigestSize]byte
		sourceDeadline   = int64(^uint64(0) >> 1)
	)
	if expectedOutcome == 1 {
		iamIntent, present := request.ExpectedAuditIntent()
		if !present || iamIntent.ActorKeyID() == "" || iamIntent.SourceAuthorizationDigest() != sourceDigest {
			return JoinedAuditFragment{}, ErrAuditEvidence
		}
		source, sourceKey, validateErr := p.validateOpaqueIAMSource(ctx, sourceRecord, sourceDigest, command.AtUnixNano)
		if validateErr != nil || source.record.Domain.SenderIdentity != iamIntent.ActorIdentity() ||
			source.record.Domain.SignatureKeyID != iamIntent.ActorKeyID() {
			return JoinedAuditFragment{}, ErrAuditEvidence
		}
		sourcePolicies := uniqueSortedDigests(append(iamIntent.PolicyDigestsSHA256(), sourceKey.AuthorizationPolicyDigestSHA256, p.profileDigest))
		transactionEvidence[sourceDigest] = newSignedDurableEvidenceWithKey(source, sourceKey, sourcePolicies...)
		sourceDeadline = minimumInt64(source.record.Domain.ExpiresAtUnixNano, sourceKey.NotAfterUnixNano)
		eventType, actorIdentity, actorKeyID = iamIntent.EventType(), iamIntent.ActorIdentity(), iamIntent.ActorKeyID()
		subjectIDs, causeCode, occurredAt = iamIntent.SubjectIDs(), iamIntent.CauseCode(), iamIntent.OccurredAtUnixNano()
		correlationID, causationID = iamIntent.CorrelationID(), iamIntent.CausationID()
		semanticPolicies = sourcePolicies
	} else {
		requirement, present := request.ReconciliationAuditRequirement()
		if !present || !requirement.FreshReconcilerAuthorityRequired() ||
			requirement.HistoricalCausationDigest() != sourceDigest ||
			requirement.AuditEventID() != eventID || requirement.AuditIdempotencyKey() != joinedBinding.Key ||
			isZeroDigest(requirement.FreshRequirementDigest()) || requirement.EventType() == "" ||
			requirement.CauseCode() == "" || len(requirement.SubjectIDs()) == 0 ||
			requirement.OccurredAtUnixNano() != command.AtUnixNano {
			return JoinedAuditFragment{}, ErrAuditEvidence
		}
		historical, sourceKey, validateErr := p.validateHistoricalOpaqueIAMSource(ctx, sourceRecord, sourceDigest)
		if validateErr != nil || historical.record.Domain.SenderIdentity != requirement.LogicalActorIdentity() ||
			historical.record.Domain.SignatureKeyID != requirement.LogicalActorKeyID() {
			return JoinedAuditFragment{}, ErrAuditEvidence
		}
		// The expired/revoked original signer is causation only. It deliberately
		// contributes no current key precondition and cannot constrain the new
		// audit commit window. Fresh current authority is the AuditEvent writer
		// validated by planAuditAppend against the active key/profile/lease.
		historicalPolicies := uniqueSortedDigests(append(requirement.PolicyDigestsSHA256(), sourceKey.AuthorizationPolicyDigestSHA256))
		transactionEvidence[sourceDigest] = newSignedDurableEvidence(historical, historicalPolicies...)
		eventType, actorIdentity, actorKeyID = requirement.EventType(), p.profile.AuditWriterIdentity, p.profile.AuditWriterKeyID
		subjectIDs, causeCode, occurredAt = requirement.SubjectIDs(), requirement.CauseCode(), requirement.OccurredAtUnixNano()
		correlationID, causationID = requirement.CorrelationID(), requirement.CausationID()
		semanticPolicies = historicalPolicies
	}
	policies := uniqueSortedDigests(append(semanticPolicies, p.profileDigest))
	if len(policies) == 0 || len(policies) > maxAuditPolicyDigests {
		return JoinedAuditFragment{}, ErrKeyNotAuthorized
	}
	existingEvidence, err := iamPendingEvidenceLinks(request, sourceDigest, eventID)
	if err != nil {
		return JoinedAuditFragment{}, ErrAuditEvidence
	}
	expected, err := newAuditIntent(AuditIntentSnapshot{
		Required: true, StreamID: p.profile.AuditReplayDomainID, EventType: eventType, AuditEventID: eventID,
		ActorIdentity: actorIdentity, ActorKeyID: actorKeyID,
		SubjectIDs: uniqueSortedStrings(subjectIDs), CauseCode: causeCode,
		OccurredAtUnixNano: occurredAt, Outcome: expectedOutcome, IdempotencyKey: joinedBinding.Key,
		CorrelationID: correlationID, CausationID: causationID,
		AppliedPolicyDigestsSHA256: policies, EvidenceDigestsSHA256: sources,
	})
	if err != nil {
		return JoinedAuditFragment{}, err
	}
	auditPlan, actualIntent, err := p.planAuditAppend(ctx, AuditAppendCommand{
		AtUnixNano: command.AtUnixNano, Event: command.AuditEvent, SourceRecordDigestsSHA256: sources,
	}, transactionEvidence, ptrIdempotencySnapshot(decision.AuditSnapshot()), &parentBinding, existingEvidence)
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
	commitNotAfter = minimumInt64(commitNotAfter, sourceDeadline)
	if commitNotAfter <= command.AtUnixNano || commitNotAfter <= commitNotBefore {
		return JoinedAuditFragment{}, ErrPolicyExpired
	}
	fragment := JoinedAuditFragment{
		request: request, audit: auditPlan, intent: actualIntent,
		parentExpected: decision.ParentSnapshot(), joinedExpected: decision.AuditSnapshot(),
		parentCompletion: parentCompletion, joinedCompletion: joinedCompletion,
		expectedOutcome: expectedOutcome, iamIntentDigest: expectedIAMSemanticIntentDigest(request),
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

// validateHistoricalOpaqueIAMSource authenticates an expired/revoked original
// IAM authorization as causation only. It deliberately performs no current
// key lookup and produces no commit-time key precondition. The exact IAM
// lifecycle/identity snapshot at issuance must still exist in the authoritative
// historical registry and the original Ed25519 signature is verified again.
func (p *Planner) validateHistoricalOpaqueIAMSource(ctx context.Context, raw ccse.Record,
	expected [ccse.DigestSize]byte) (signedRecordSnapshot, GovernanceKeySnapshot, error) {
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
		record.Domain.IssuedAtUnixNano < 0 || record.Domain.ExpiresAtUnixNano <= record.Domain.IssuedAtUnixNano ||
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
	key, found, err := p.iam.ResolveGovernanceKeyAt(ctx, record.Domain.SignatureKeyID, record.Domain.IssuedAtUnixNano)
	if err != nil || !found || !preflightKeySnapshot(key) {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	key = cloneKeySnapshot(key)
	if key.KeyID != record.Domain.SignatureKeyID || key.KeyID != record.Envelope.SignatureKeyID ||
		key.SubjectIdentity != record.Domain.SenderIdentity || key.SubjectIdentity != record.Envelope.SenderIdentity ||
		key.TargetIdentityKind != 1 || key.TargetPrincipalKind < 1 || key.TargetPrincipalKind > 8 ||
		key.TargetIdentityID == "" || key.OrganizationIdentity == "" || key.LifecycleState != KeyLifecycleStateActive ||
		key.RevokedAtUnixNano != 0 || key.NotBeforeUnixNano < 0 || key.NotAfterUnixNano <= key.NotBeforeUnixNano ||
		record.Domain.IssuedAtUnixNano < key.NotBeforeUnixNano || record.Domain.ExpiresAtUnixNano > key.NotAfterUnixNano ||
		!containsMessageType(key.AllowedMessageTypeIDs, record.MessageTypeID) || isZeroDigest(key.AuthorizationPolicyDigestSHA256) ||
		key.StateVersion == 0 || key.WriterEpoch == 0 || isZeroDigest(key.SnapshotDigestSHA256) ||
		key.IdentityStateVersion == 0 || key.IdentityWriterEpoch == 0 || isZeroDigest(key.IdentitySnapshotDigestSHA256) ||
		key.KeyMaterialStateVersion != 1 || isZeroDigest(key.KeyMaterialStateDigestSHA256) ||
		key.EnrollmentDomainID != p.profile.EnrollmentDomainID || key.EnrollmentEnvironment != p.profile.Environment ||
		key.EnrollmentGenesisHash != p.profile.GenesisHash || hasDuplicateUint32(key.AllowedMessageTypeIDs) ||
		hasDuplicateStrings(key.Roles) || containsEmpty(key.Roles) || key.Algorithm != ccse.SignatureAlgorithmEd25519 ||
		key.Algorithm != record.Domain.SignatureAlgorithm || key.Algorithm != record.Envelope.SignatureAlgorithm ||
		len(key.PublicKey) != ed25519.PublicKeySize || len(record.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(key.PublicKey), digest[:], record.Signature) {
		return signedRecordSnapshot{}, GovernanceKeySnapshot{}, ErrAuditEvidence
	}
	return signedRecordSnapshot{record: record, digest: digest}, key, nil
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
	if expectedIAMSemanticIntentDigest(fragment.request) != fragment.iamIntentDigest {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	audit := fragment.audit.Snapshot()
	if audit.Kind != MutationAuditAppend || !audit.CommitReady || len(audit.IdempotencyClaims) != 1 ||
		audit.IdempotencyClaims[0] != fragment.joinedCompletion || len(audit.IdentifierClaims) != 1 ||
		validateCanonicalKeyStateAssertions(audit) != nil ||
		validateCanonicalAuditWriterLeaseAssertion(audit) != nil ||
		len(audit.CanonicalStateAssertions)+3*len(audit.CanonicalKeyStateAssertions)+1 > 384 {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	bundle, ok := fragment.request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(fragment.request) != nil || bundle.EvidenceCount() <= 0 || bundle.EvidenceCount() > 384 {
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	domain, receipt, receiptDigest := bundle.SemanticReceipt()
	if domain != iamAuditEvidenceReceiptDomain || receiptDigest != bundle.Digest() ||
		domainSeparatedContentDigest(iamAuditEvidenceBundleDigestDomain, receipt) != receiptDigest {
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	links, err := iamPendingEvidenceLinks(fragment.request, bundle.SourceAuthorizationDigest(), audit.AuditEventID)
	if err != nil {
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	expectedStorage, err := newDurableEvidenceStorageCapabilitiesForAudit(audit.AuditSourceEvidence,
		audit.AuditEventID, links)
	if err != nil || len(expectedStorage) != len(audit.AuditSourceStorageCapabilities) {
		return [ccse.DigestSize]byte{}, ErrAuditEvidence
	}
	for index := range expectedStorage {
		if !equalDurableEvidenceStorageCapabilities(expectedStorage[index],
			audit.AuditSourceStorageCapabilities[index]) {
			return [ccse.DigestSize]byte{}, ErrAuditEvidence
		}
	}
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
	w.uint64(uint64(len(audit.CanonicalKeyStateAssertions)))
	for _, assertion := range audit.CanonicalKeyStateAssertions {
		if assertion.VerifyDigest() != nil {
			return [ccse.DigestSize]byte{}, ErrSnapshotInconsistent
		}
		w.digest(assertion.digest)
	}
	if audit.CanonicalAuditWriterLeaseAssertion.VerifyDigest() != nil {
		return [ccse.DigestSize]byte{}, ErrAuditAnchor
	}
	w.digest(audit.CanonicalAuditWriterLeaseAssertion.digest)
	if audit.CanonicalAuditAppend.VerifyDigest() != nil {
		return [ccse.DigestSize]byte{}, ErrAuditAnchor
	}
	w.digest(audit.CanonicalAuditAppend.digest)
	w.uint64(uint64(len(audit.AuditSourceStorageCapabilities)))
	for _, capability := range audit.AuditSourceStorageCapabilities {
		if capability.VerifyDigest() != nil || capability.auditAssertionEventID != audit.AuditEventID {
			return [ccse.DigestSize]byte{}, ErrAuditEvidence
		}
		w.digest(capability.digest)
	}
	w.string(domain)
	w.digest(receiptDigest)
	w.bytes(receipt)
	w.uint64(uint64(bundle.EvidenceCount()))
	return w.sum()
}

func auditEvidenceBundleDigest(request iam.JoinedAuditRequest) [ccse.DigestSize]byte {
	bundle, ok := request.AuditEvidenceBundle()
	if !ok || bundle.VerifyFor(request) != nil {
		return [ccse.DigestSize]byte{}
	}
	return bundle.Digest()
}

func expectedIAMSemanticIntentDigest(request iam.JoinedAuditRequest) [ccse.DigestSize]byte {
	if intent, ok := request.ExpectedAuditIntent(); ok && request.ExpectedOutcome() == 1 {
		return intent.Digest()
	}
	if requirement, ok := request.ReconciliationAuditRequirement(); ok &&
		(request.ExpectedOutcome() == 3 || request.ExpectedOutcome() == 4) {
		return requirement.OriginalAuditIntentDigest()
	}
	return [ccse.DigestSize]byte{}
}

func cloneJoinedAuditFragmentSnapshot(value JoinedAuditFragmentSnapshot) JoinedAuditFragmentSnapshot {
	value.CanonicalAuditIntent = cloneAuditIntentSnapshot(value.CanonicalAuditIntent)
	value.CanonicalStateAssertions = cloneCanonicalStateAssertions(value.CanonicalStateAssertions)
	value.CanonicalKeyStateAssertions = cloneCanonicalKeyStateAssertions(value.CanonicalKeyStateAssertions)
	value.CanonicalAuditWriterLeaseAssertion = cloneCanonicalAuditWriterLeaseAssertion(value.CanonicalAuditWriterLeaseAssertion)
	value.AuditSourceDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.AuditSourceDigestsSHA256...)
	value.AuditSourceEvidence = append([]DurableEvidence(nil), value.AuditSourceEvidence...)
	for index := range value.AuditSourceEvidence {
		value.AuditSourceEvidence[index] = cloneDurableEvidence(value.AuditSourceEvidence[index])
	}
	value.AuditSourceStorageCapabilities = cloneDurableEvidenceStorageCapabilities(value.AuditSourceStorageCapabilities)
	value.CanonicalAuditAppend = cloneCanonicalAuditAppendCapability(value.CanonicalAuditAppend)
	value.AuditSourceKeyPreconditions = append([]KeyStatePrecondition(nil), value.AuditSourceKeyPreconditions...)
	value.AuditEventEvidence = cloneSignedEvidence(value.AuditEventEvidence)
	return value
}
