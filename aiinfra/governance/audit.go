// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

// PlanAuditAppend validates one signed AuditEvent against the single-writer
// stream head. PreviousEventDigestSHA256 uses ccse.Record.Digest exactly: the
// SHA-256 digest of the canonical CCSE preimage defined by the existing API.
func (p *Planner) PlanAuditAppend(ctx context.Context, command AuditAppendCommand) (MutationPlan, AuditIntent, error) {
	return p.planAuditAppend(ctx, command, nil, nil, nil)
}

func (p *Planner) planAuditAppend(ctx context.Context, command AuditAppendCommand, transactionEvidence map[[ccse.DigestSize]byte]DurableEvidence,
	joinedReservation *idempotency.Snapshot, joinedParent *idempotency.Binding) (MutationPlan, AuditIntent, error) {
	if p == nil || p.canonical == nil {
		return MutationPlan{}, AuditIntent{}, ErrInvalidConfiguration
	}
	if err := contextErr(ctx); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if command.AtUnixNano < 0 || len(command.SourceRecordDigestsSHA256) == 0 || len(command.SourceRecordDigestsSHA256) > 128 ||
		hasDuplicateDigests(command.SourceRecordDigestsSHA256) {
		return MutationPlan{}, AuditIntent{}, ErrAuditEvidence
	}
	sources := append([][ccse.DigestSize]byte(nil), command.SourceRecordDigestsSHA256...)
	for _, source := range sources {
		if isZeroDigest(source) {
			return MutationPlan{}, AuditIntent{}, ErrAuditEvidence
		}
	}
	sortDigests(sources)
	signed, err := p.validateSignedRecord(ctx, command.Event, schema.MessageTypeAuditEvent, auditPurpose, p.profile.AuditReplayDomainID, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	decoded, err := p.canonical.Decode(schema.MessageTypeAuditEvent, p.profile.SchemaVersion, signed.record.Payload)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	event, ok := decoded.(foundationv1.AuditEventSigningProjection)
	if !ok {
		return MutationPlan{}, AuditIntent{}, ErrInvalidSignedRecord
	}
	binding := idempotency.Binding{}
	if joinedReservation == nil {
		if joinedParent != nil || strings.HasPrefix(event.AuditEventID, globalid.JoinedAuditEventIDPrefix) {
			return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
		}
		binding = idempotency.Binding{
			Key: event.Metadata.IdempotencyKey, Domain: idempotency.OperationGovernanceAudit,
			OwnerID: event.AuditEventID, RequestDigest: signed.record.Envelope.PayloadDigest,
		}
	} else {
		if joinedParent == nil {
			return MutationPlan{}, AuditIntent{}, ErrAuditRequired
		}
		expectedJoinedBinding, joinErr := idempotency.JoinedAuditBinding(*joinedParent)
		expectedEventID, eventIDErr := idempotency.JoinedAuditEventID(*joinedParent)
		binding = joinedReservation.Binding
		if joinErr != nil || eventIDErr != nil || binding != expectedJoinedBinding ||
			!validJoinedAuditReservation(*joinedReservation, expectedJoinedBinding) ||
			event.Metadata.IdempotencyKey != expectedJoinedBinding.Key || event.AuditEventID != expectedEventID {
			return MutationPlan{}, AuditIntent{}, ErrAuditRequired
		}
	}
	var idempotencyClaim idempotency.Claim
	if joinedReservation == nil {
		decision, precheckErr := idempotency.Precheck(ctx, p.idempotency, binding)
		if precheckErr != nil {
			return MutationPlan{}, AuditIntent{}, precheckErr
		}
		if decision.Kind() == idempotency.DuplicateCompleted {
			return MutationPlan{}, AuditIntent{}, DuplicateCompletedError{OutcomeDigestSHA256: decision.OutcomeDigest()}
		}
		if decision.Kind() != idempotency.Proceed {
			return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
		}
		idempotencyClaim, err = idempotency.NewReserveCompletion(binding)
	} else {
		idempotencyClaim, err = idempotency.NewCompleteCollection(*joinedReservation)
	}
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	sourceEvidence, sourceKeyPreconditions, sourceAuthorizationPolicies, sourceDeadline, err := p.validateAuditSources(ctx, sources, transactionEvidence, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	key, err := p.authorizeKey(ctx, signed, schema.MessageTypeAuditEvent, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if signed.record.Domain.SenderIdentity != p.profile.AuditWriterIdentity ||
		signed.record.Domain.SignatureKeyID != p.profile.AuditWriterKeyID ||
		key.SubjectIdentity != p.profile.AuditWriterIdentity || key.KeyID != p.profile.AuditWriterKeyID ||
		!containsString(key.Roles, p.profile.AuditWriterRole) {
		return MutationPlan{}, AuditIntent{}, ErrAuditWriter
	}
	if event.ActorIdentity == "" || event.ActorKeyID == "" {
		return MutationPlan{}, AuditIntent{}, ErrAuditWriter
	}
	if event.ActorIdentity == p.profile.AuditWriterIdentity {
		if event.ActorKeyID != p.profile.AuditWriterKeyID {
			return MutationPlan{}, AuditIntent{}, ErrAuditWriter
		}
	} else if !logicalAuditActorHasUniqueSignedSource(event.ActorIdentity, event.ActorKeyID, sourceEvidence) {
		return MutationPlan{}, AuditIntent{}, ErrAuditEvidence
	}
	if event.OccurredAtUnixNano > event.Metadata.CreatedAtUnixNano ||
		event.Metadata.CreatedAtUnixNano > signed.record.Domain.IssuedAtUnixNano ||
		signed.record.Domain.IssuedAtUnixNano > command.AtUnixNano {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: event occurred in the future", ErrInvalidCommand)
	}
	if event.AuditSequence != signed.record.Domain.Counter || event.AuditSequence != signed.record.Envelope.Counter ||
		event.Metadata.StateVersion != event.AuditSequence {
		return MutationPlan{}, AuditIntent{}, ErrAuditSequence
	}
	if event.Metadata.RecordID != event.AuditEventID || event.CorrelationID != signed.record.Envelope.CorrelationID ||
		event.CausationID.Present != signed.record.Envelope.CausationID.Present ||
		(event.CausationID.Present && event.CausationID.Value != signed.record.Envelope.CausationID.Value) {
		return MutationPlan{}, AuditIntent{}, ErrInvalidSignedRecord
	}
	requiredPolicies := append([][ccse.DigestSize]byte(nil), sourceAuthorizationPolicies...)
	requiredPolicies = uniqueSortedDigests(append(requiredPolicies, key.AuthorizationPolicyDigestSHA256, p.profileDigest))
	if !equalDigestSets(event.Metadata.PolicyDigestsSHA256, event.AppliedPolicyDigestsSHA256) ||
		!equalDigestSets(event.AppliedPolicyDigestsSHA256, requiredPolicies) {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("%w: exact audit authorization policy set differs", ErrKeyNotAuthorized)
	}
	for _, source := range sources {
		if source == signed.digest || !containsDigest(event.EvidenceDigestsSHA256, source) {
			return MutationPlan{}, AuditIntent{}, ErrAuditEvidence
		}
	}
	if !equalDigestSets(event.EvidenceDigestsSHA256, sources) {
		return MutationPlan{}, AuditIntent{}, ErrAuditEvidence
	}
	profileActivation, activeProfile, err := p.profiles.ActiveGovernanceProfile(ctx, command.AtUnixNano)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: resolve active profile: %w", err)
	}
	if !activeProfile || !validGovernanceProfileActivation(profileActivation, command.AtUnixNano) ||
		profileActivation.GovernanceProfileDigestSHA256 != p.profileDigest {
		return MutationPlan{}, AuditIntent{}, ErrAuditAnchor
	}

	head, err := p.audit.SnapshotAuditHead(ctx, p.profile.AuditReplayDomainID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: snapshot audit head: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if err := p.validateAuditHead(ctx, head, command.AtUnixNano); err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	if head.Sequence == math.MaxUint64 || event.AuditSequence != head.Sequence+1 {
		return MutationPlan{}, AuditIntent{}, ErrAuditSequence
	}
	expectedPrevious := head.LastRecordDigestSHA256
	if head.Sequence == 0 {
		expectedPrevious = head.DeploymentAnchorSHA256
	}
	if event.PreviousEventDigestSHA256 != expectedPrevious {
		return MutationPlan{}, AuditIntent{}, ErrAuditLink
	}
	if event.Metadata.WriterEpoch != head.AuthorizedWriterEpoch || event.Metadata.HomeRegion != head.AuthorizedHomeRegion ||
		event.Metadata.HomeRegion != p.profile.AuditHomeRegion || event.Metadata.CreatedAtUnixNano > command.AtUnixNano {
		return MutationPlan{}, AuditIntent{}, ErrAuditWriter
	}
	priorEvent, exists, err := p.audit.LookupAuditEvent(ctx, event.AuditEventID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: lookup audit event: %w", err)
	}
	if exists || priorEvent != (AuditEventSnapshot{}) {
		return MutationPlan{}, AuditIntent{}, ErrAuditSequence
	}
	globalID, globalExists, err := p.ids.LookupGlobalID(ctx, event.AuditEventID)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, fmt.Errorf("aiinfra governance: lookup global audit ID: %w", err)
	}
	eventOwner := globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: event.AuditEventID}
	latencyDeadline, ok := addPositiveNanos(command.AtUnixNano, p.profile.MaxPlanCommitLatencyNanos)
	if !ok {
		return MutationPlan{}, AuditIntent{}, ErrInvalidCommand
	}
	commitDeadline := minimumInt64(minimumInt64(signed.record.Domain.ExpiresAtUnixNano, key.NotAfterUnixNano), latencyDeadline)
	commitDeadline = minimumInt64(commitDeadline, head.WriterLeaseNotAfterUnixNano)
	commitDeadline = minimumInt64(commitDeadline, sourceDeadline)
	commitDeadline = minimumInt64(commitDeadline, profileActivation.ValidUntilUnixNano)
	commitNotBefore := maximumInt64(subtractFloorZero(command.AtUnixNano, p.profile.MaxClockSkewNanos), event.OccurredAtUnixNano)
	commitNotBefore = maximumInt64(commitNotBefore, profileActivation.ValidFromUnixNano)
	if commitDeadline <= commitNotBefore {
		return MutationPlan{}, AuditIntent{}, ErrPolicyExpired
	}

	var auditIDClaim globalid.Claim
	if joinedReservation == nil {
		if globalExists || globalID != (globalid.Snapshot{}) {
			return MutationPlan{}, AuditIntent{}, ErrAuditSequence
		}
		auditIDClaim, err = globalid.Reserve(event.AuditEventID, eventOwner)
	} else {
		if !globalExists {
			return MutationPlan{}, AuditIntent{}, ErrAuditSequence
		}
		auditIDClaim, err = globalid.Assert(event.AuditEventID, globalID, eventOwner)
	}
	if err != nil {
		return MutationPlan{}, AuditIntent{}, ErrAuditSequence
	}
	planValue := MutationPlanSnapshot{
		CommitReady:                                    true,
		EvaluatedAtUnixNano:                            command.AtUnixNano,
		CommitNotBeforeUnixNano:                        commitNotBefore,
		CommitNotAfterUnixNano:                         commitDeadline,
		GovernanceProfileDigestSHA256:                  p.profileDigest,
		GovernanceProfileActivation:                    profileActivation,
		Kind:                                           MutationAuditAppend,
		AuditSourceDigestsSHA256:                       append([][ccse.DigestSize]byte(nil), sources...),
		AuditSourceEvidence:                            sourceEvidence,
		AuditSourceKeyPreconditions:                    sourceKeyPreconditions,
		AuditStreamID:                                  p.profile.AuditReplayDomainID,
		AuditEventID:                                   event.AuditEventID,
		AuditRecordID:                                  event.Metadata.RecordID,
		ExpectedAuditEventAbsent:                       true,
		DeploymentAnchorSHA256:                         head.DeploymentAnchorSHA256,
		ExpectedAuditSequence:                          head.Sequence,
		ExpectedAuditHeadDigest:                        head.LastRecordDigestSHA256,
		ExpectedAuditHeadHomeRegion:                    head.HomeRegion,
		AuthorizedAuditHomeRegion:                      head.AuthorizedHomeRegion,
		ExpectedAuditHeadWriterIdentity:                head.HeadWriterIdentity,
		AuthorizedAuditWriterIdentity:                  head.AuthorizedWriterIdentity,
		ExpectedAuditHeadWriterEpoch:                   head.WriterEpoch,
		AuthorizedAuditWriterEpoch:                     head.AuthorizedWriterEpoch,
		ExpectedAuditHeadGovernanceProfileDigestSHA256: head.HeadGovernanceProfileDigestSHA256,
		AuthorizedAuditGovernanceProfileDigestSHA256:   head.AuthorizedGovernanceProfileDigestSHA256,
		ExpectedAuditWriterLeaseEvidenceDigestSHA256:   head.WriterLeaseEvidenceDigestSHA256,
		ExpectedAuditWriterLeaseNotBeforeUnixNano:      head.WriterLeaseNotBeforeUnixNano,
		ExpectedAuditWriterLeaseNotAfterUnixNano:       head.WriterLeaseNotAfterUnixNano,
		NextAuditSequence:                              event.AuditSequence,
		NextAuditRecordDigestSHA256:                    signed.digest,
		AuditEventEvidence:                             newSignedEvidence(signed),
		AuditWriterKeyPrecondition:                     keyPrecondition(key),
		IdentifierClaims:                               []globalid.Claim{auditIDClaim},
		IdempotencyClaims:                              []idempotency.Claim{idempotencyClaim},
		IdempotencyOutcome:                             event.Outcome,
	}
	intentValue := AuditIntentSnapshot{
		Required:           true,
		StreamID:           p.profile.AuditReplayDomainID,
		EventType:          event.EventType,
		AuditEventID:       event.AuditEventID,
		ActorIdentity:      event.ActorIdentity,
		ActorKeyID:         event.ActorKeyID,
		SubjectIDs:         uniqueSortedStrings(event.SubjectIDs),
		CauseCode:          event.CauseCode,
		OccurredAtUnixNano: event.OccurredAtUnixNano,
		Outcome:            event.Outcome,
		IdempotencyKey:     event.Metadata.IdempotencyKey,
		CorrelationID:      event.CorrelationID,
		CausationID: ccse.OptionalMessageID{
			Present: event.CausationID.Present, Value: event.CausationID.Value,
		},
		WriterAuthorizationPolicyDigestSHA256: key.AuthorizationPolicyDigestSHA256,
		AppliedPolicyDigestsSHA256:            uniqueSortedDigests(event.AppliedPolicyDigestsSHA256),
		EvidenceDigestsSHA256:                 uniqueSortedDigests(event.EvidenceDigestsSHA256),
	}
	if transactionEvidence != nil {
		emergency, breakGlassExpiry, scopes, found, deriveErr := p.derivePolicyAuditContext(transactionEvidence)
		if deriveErr != nil {
			return MutationPlan{}, AuditIntent{}, deriveErr
		}
		if found {
			intentValue.Emergency = emergency
			intentValue.BreakGlassExpiresAtUnixNano = breakGlassExpiry
			intentValue.BreakGlassScopes = scopes
		}
	}
	plan, err := newMutationPlan(planValue)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	intent, err := newAuditIntent(intentValue)
	if err != nil {
		return MutationPlan{}, AuditIntent{}, err
	}
	return plan, intent, nil
}

func (p *Planner) derivePolicyAuditContext(evidence map[[ccse.DigestSize]byte]DurableEvidence) (bool, int64, []string, bool, error) {
	var bundle *foundationv1.PolicyBundleSigningProjection
	for _, item := range evidence {
		if item.kind != EvidenceContentSHA256 || len(item.content) == 0 {
			continue
		}
		decoded, err := p.canonical.Decode(schema.MessageTypePolicyBundle, p.profile.SchemaVersion, item.content)
		if err != nil {
			continue
		}
		projection, ok := decoded.(foundationv1.PolicyBundleSigningProjection)
		if !ok {
			continue
		}
		if bundle != nil {
			return false, 0, nil, false, ErrAuditEvidence
		}
		copyProjection := projection
		bundle = &copyProjection
	}
	if bundle == nil {
		return false, 0, nil, false, nil
	}
	if !bundle.Emergency {
		return false, 0, nil, true, nil
	}
	if !bundle.BreakGlassExpiresAtUnixNano.Present {
		return false, 0, nil, false, ErrAuditEvidence
	}
	document, exists := evidence[bundle.PolicyDocumentDigestSHA256]
	if !exists || document.kind != EvidenceContentSHA256 {
		return false, 0, nil, false, ErrAuditEvidence
	}
	scopes, err := decodeBreakGlassDocument(PolicyDocumentSnapshot{
		DigestSHA256: bundle.PolicyDocumentDigestSHA256, MediaType: bundle.PolicyDocumentMediaType,
		CanonicalDocument: document.content,
	}, bundle.PolicyDocumentDigestSHA256, bundle.PolicyDocumentMediaType, bundle.PolicyKind)
	if err != nil {
		return false, 0, nil, false, ErrAuditEvidence
	}
	return true, bundle.BreakGlassExpiresAtUnixNano.Value, uniqueSortedStrings(scopes), true, nil
}

func logicalAuditActorHasUniqueSignedSource(identity, keyID string, evidence []DurableEvidence) bool {
	matches := 0
	for _, item := range evidence {
		if item.kind != EvidenceSignedCCSERecord || item.signed.record.MessageTypeID == 0 {
			continue
		}
		if item.signed.record.Domain.SenderIdentity == identity && item.signed.record.Domain.SignatureKeyID == keyID {
			matches++
		}
	}
	return matches == 1
}

func (p *Planner) validateAuditSources(ctx context.Context, sources [][ccse.DigestSize]byte,
	transactionEvidence map[[ccse.DigestSize]byte]DurableEvidence, at int64) ([]DurableEvidence, []KeyStatePrecondition, [][ccse.DigestSize]byte, int64, error) {
	const maxEvidencePreimageBytes = 128 << 10
	retained := make([]DurableEvidence, 0, len(sources))
	keyStates := make(map[string]KeyStatePrecondition)
	authorizationPolicies := make([][ccse.DigestSize]byte, 0, len(sources))
	deadline := int64(math.MaxInt64)
	for _, source := range sources {
		if evidence, present := transactionEvidence[source]; present {
			if evidence.digest != source {
				return nil, nil, nil, 0, ErrAuditEvidence
			}
			if evidence.kind == EvidenceSignedCCSERecord {
				if len(evidence.authorizationPolicyDigests) == 0 || hasDuplicateDigests(evidence.authorizationPolicyDigests) {
					return nil, nil, nil, 0, ErrAuditEvidence
				}
				for _, digest := range evidence.authorizationPolicyDigests {
					if isZeroDigest(digest) {
						return nil, nil, nil, 0, ErrAuditEvidence
					}
				}
				authorizationPolicies = append(authorizationPolicies, evidence.authorizationPolicyDigests...)
				if evidence.keyPreconditionPresent {
					if !validKeyStatePrecondition(evidence.keyPrecondition) ||
						evidence.keyPrecondition.KeyID != evidence.signed.record.Domain.SignatureKeyID ||
						evidence.keyPrecondition.KeyID != evidence.signed.record.Envelope.SignatureKeyID ||
						evidence.authorizationNotAfter < evidence.signed.record.Domain.ExpiresAtUnixNano ||
						evidence.authorizationNotAfter <= at || evidence.signed.record.Domain.ExpiresAtUnixNano <= at {
						return nil, nil, nil, 0, ErrAuditEvidence
					}
					if existing, duplicate := keyStates[evidence.keyPrecondition.KeyID]; duplicate && existing != evidence.keyPrecondition {
						return nil, nil, nil, 0, ErrAuditEvidence
					}
					keyStates[evidence.keyPrecondition.KeyID] = evidence.keyPrecondition
					deadline = minimumInt64(deadline, evidence.signed.record.Domain.ExpiresAtUnixNano)
					deadline = minimumInt64(deadline, evidence.authorizationNotAfter)
				} else if evidence.keyPrecondition != (KeyStatePrecondition{}) || evidence.authorizationNotAfter != 0 {
					return nil, nil, nil, 0, ErrAuditEvidence
				}
			} else if evidence.kind != EvidenceContentSHA256 || len(evidence.authorizationPolicyDigests) != 0 ||
				evidence.keyPreconditionPresent || evidence.keyPrecondition != (KeyStatePrecondition{}) || evidence.authorizationNotAfter != 0 {
				return nil, nil, nil, 0, ErrAuditEvidence
			}
			retained = append(retained, cloneDurableEvidence(evidence))
			continue
		}
		evidence, exists, err := p.evidence.ResolveEvidence(ctx, source)
		if err != nil {
			return nil, nil, nil, 0, fmt.Errorf("%w: resolve source evidence: %v", ErrAuditEvidence, err)
		}
		if !exists || evidence.DigestSHA256 != source {
			return nil, nil, nil, 0, ErrAuditEvidence
		}
		switch evidence.Kind {
		case EvidenceContentSHA256:
			if evidence.Signed.Record != nil || len(evidence.Content) == 0 || len(evidence.Content) > maxEvidencePreimageBytes ||
				sha256.Sum256(evidence.Content) != source {
				return nil, nil, nil, 0, ErrAuditEvidence
			}
			retained = append(retained, newContentEvidence(source, evidence.Content))
		case EvidenceSignedCCSERecord:
			if len(evidence.Content) != 0 {
				return nil, nil, nil, 0, ErrAuditEvidence
			}
			signed, sourceKey, validateErr := p.validateEvidenceSignedRecord(ctx, evidence.Signed, at)
			if validateErr != nil || signed.digest != source {
				return nil, nil, nil, 0, ErrAuditEvidence
			}
			retained = append(retained, newSignedDurableEvidence(signed, sourceKey.AuthorizationPolicyDigestSHA256, p.profileDigest))
			authorizationPolicies = append(authorizationPolicies, sourceKey.AuthorizationPolicyDigestSHA256, p.profileDigest)
			precondition := keyPrecondition(sourceKey)
			if existing, duplicate := keyStates[precondition.KeyID]; duplicate && existing != precondition {
				return nil, nil, nil, 0, ErrAuditEvidence
			}
			keyStates[precondition.KeyID] = precondition
			deadline = minimumInt64(deadline, signed.record.Domain.ExpiresAtUnixNano)
			deadline = minimumInt64(deadline, sourceKey.NotAfterUnixNano)
		default:
			return nil, nil, nil, 0, ErrAuditEvidence
		}
	}
	if err := contextErr(ctx); err != nil {
		return nil, nil, nil, 0, err
	}
	preconditions := make([]KeyStatePrecondition, 0, len(keyStates))
	for _, precondition := range keyStates {
		preconditions = append(preconditions, precondition)
	}
	sort.Slice(preconditions, func(i, j int) bool { return preconditions[i].KeyID < preconditions[j].KeyID })
	return retained, preconditions, uniqueSortedDigests(authorizationPolicies), deadline, nil
}

func (p *Planner) validateAuditHead(ctx context.Context, head AuditHeadSnapshot, at int64) error {
	if head.StreamID != p.profile.AuditReplayDomainID || head.DeploymentAnchorSHA256 != p.profile.AuditDeploymentAnchorSHA256 ||
		isZeroDigest(head.DeploymentAnchorSHA256) || head.AuthorizedWriterIdentity != p.profile.AuditWriterIdentity ||
		head.AuthorizedGovernanceProfileDigestSHA256 != p.profileDigest ||
		head.AuthorizedHomeRegion != p.profile.AuditHomeRegion || head.AuthorizedWriterEpoch == 0 || head.WriterEpoch > head.AuthorizedWriterEpoch ||
		isZeroDigest(head.WriterLeaseEvidenceDigestSHA256) ||
		head.WriterLeaseNotBeforeUnixNano < 0 || head.WriterLeaseNotAfterUnixNano <= head.WriterLeaseNotBeforeUnixNano ||
		at < head.WriterLeaseNotBeforeUnixNano || at >= head.WriterLeaseNotAfterUnixNano {
		return ErrAuditAnchor
	}
	if (head.Sequence == 0) != isZeroDigest(head.LastRecordDigestSHA256) {
		return ErrSnapshotInconsistent
	}
	if (head.Sequence == 0) != isZeroDigest(head.HeadGovernanceProfileDigestSHA256) {
		return ErrSnapshotInconsistent
	}
	if (head.Sequence == 0) != (head.HeadWriterIdentity == "") {
		return ErrSnapshotInconsistent
	}
	if head.Sequence != 0 {
		historical, found, err := p.profiles.ResolveGovernanceProfile(ctx, head.HeadGovernanceProfileDigestSHA256)
		if err != nil || !found || !preflightProfile(historical) {
			return ErrSnapshotInconsistent
		}
		historical = cloneProfile(historical)
		computed, digestErr := digestGovernanceProfile(historical)
		if validateProfile(historical) != nil || digestErr != nil || computed != head.HeadGovernanceProfileDigestSHA256 ||
			head.HeadWriterIdentity != historical.AuditWriterIdentity {
			return ErrSnapshotInconsistent
		}
	}
	if (head.Sequence == 0) != (head.WriterEpoch == 0) {
		return ErrSnapshotInconsistent
	}
	if (head.Sequence == 0) != (head.HomeRegion == "") ||
		(head.WriterEpoch == head.AuthorizedWriterEpoch && head.HomeRegion != head.AuthorizedHomeRegion) {
		return ErrSnapshotInconsistent
	}
	return nil
}
