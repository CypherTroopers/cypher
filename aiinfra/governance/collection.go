// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	legacyApprovalCollectionDigestDomain = "CPH-AIIE-GOVERNANCE-APPROVAL-COLLECTION-V1\x00"
	approvalCollectionDigestDomain       = "CPH-AIIE-GOVERNANCE-APPROVAL-COLLECTION-V2\x00"
	approvalEvidenceDigestDomain         = "CPH-AIIE-GOVERNANCE-APPROVAL-EVIDENCE-V1\x00"
	legacyApprovalAdmissionDigestDomain  = "CPH-AIIE-GOVERNANCE-APPROVAL-ADMISSION-EVIDENCE-V1\x00"
	approvalAdmissionDigestDomain        = "CPH-AIIE-GOVERNANCE-APPROVAL-ADMISSION-EVIDENCE-V2\x00"
)

type policyApproval struct {
	record                 signedRecordSnapshot
	key                    GovernanceKeySnapshot
	bundle                 foundationv1.PolicyBundleSigningProjection
	admissionKey           GovernanceKeySnapshot
	admissionProfileDigest [ccse.DigestSize]byte
	admissionActivation    GovernanceProfileActivationSnapshot
	admissionValidatedAt   int64
	admissionFingerprint   [ccse.DigestSize]byte
	legacyAdmission        bool
}

func policyIdempotencyBinding(bundle foundationv1.PolicyBundleSigningProjection, payloadDigest [ccse.DigestSize]byte) idempotency.Binding {
	owner := policyBundleOwnerDigest(bundle.PolicyKind, bundle.PolicyBundleID)
	return idempotency.Binding{
		Key:           bundle.Metadata.IdempotencyKey,
		Domain:        idempotency.OperationGovernancePolicy,
		OwnerID:       hex.EncodeToString(owner[:]),
		RequestDigest: payloadDigest,
	}
}

// PlanPolicyApprovalIngestion validates one approval and returns the exact
// collection/idempotency CAS needed to append it, or to replace a prior
// signature by the same declared sender and key. It never counts a replacement
// as another vote. Replay admission remains part of the signed CCSE boundary;
// a replacement is possible only when that boundary accepted its fresh record.
func (p *Planner) PlanPolicyApprovalIngestion(ctx context.Context, command PolicyApprovalIngestionCommand) (ApprovalCollectionPlan, error) {
	if p == nil || p.canonical == nil || command.AtUnixNano < 0 {
		return ApprovalCollectionPlan{}, ErrInvalidCommand
	}
	if err := contextErr(ctx); err != nil {
		return ApprovalCollectionPlan{}, err
	}
	approval, err := p.decodePolicyApproval(ctx, command.Approval, command.AtUnixNano, false)
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	binding := policyIdempotencyBinding(approval.bundle, approval.record.record.Envelope.PayloadDigest)
	decision, err := idempotency.PrecheckJoined(ctx, p.idempotency, binding)
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	if decision.Kind() == idempotency.DuplicateCompleted {
		return ApprovalCollectionPlan{}, DuplicateCompletedError{OutcomeDigestSHA256: decision.OutcomeDigest()}
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(binding)
	if err != nil {
		return ApprovalCollectionPlan{}, ErrInvalidCommand
	}
	if decision.Kind() == idempotency.ContinueCollection && !validJoinedAuditReservation(decision.AuditSnapshot(), joinedBinding) {
		return ApprovalCollectionPlan{}, ErrApprovalCollection
	}
	eventID, err := idempotency.JoinedAuditEventID(binding)
	if err != nil {
		return ApprovalCollectionPlan{}, ErrInvalidCommand
	}
	identifierClaims, err := p.policyAdmissionIdentifierClaims(ctx, approval.bundle, approval.record.record.Envelope.PayloadDigest, eventID, decision.Kind())
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	key, err := p.authorizeKey(ctx, approval.record, schema.MessageTypePolicyBundle, command.AtUnixNano)
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	issuedActivation, activeAtIssue, err := p.profiles.ActiveGovernanceProfile(ctx, approval.record.record.Domain.IssuedAtUnixNano)
	if err != nil {
		return ApprovalCollectionPlan{}, fmt.Errorf("aiinfra governance: resolve profile at approval issuance: %w", err)
	}
	currentActivation, activeNow, err := p.profiles.ActiveGovernanceProfile(ctx, command.AtUnixNano)
	if err != nil {
		return ApprovalCollectionPlan{}, fmt.Errorf("aiinfra governance: resolve profile at approval admission: %w", err)
	}
	if !activeAtIssue || !activeNow || !validGovernanceProfileActivation(issuedActivation, approval.record.record.Domain.IssuedAtUnixNano) ||
		!validGovernanceProfileActivation(currentActivation, command.AtUnixNano) ||
		issuedActivation.GovernanceProfileDigestSHA256 != p.profileDigest || currentActivation.GovernanceProfileDigestSHA256 != p.profileDigest ||
		issuedActivation != currentActivation {
		return ApprovalCollectionPlan{}, ErrKeyNotAuthorized
	}
	if !containsDigest(approval.bundle.Metadata.PolicyDigestsSHA256, key.AuthorizationPolicyDigestSHA256) ||
		!containsDigest(approval.bundle.Metadata.PolicyDigestsSHA256, p.profileDigest) {
		return ApprovalCollectionPlan{}, ErrKeyNotAuthorized
	}
	approval.key = key
	approval.admissionKey = cloneKeySnapshot(key)
	approval.admissionProfileDigest = p.profileDigest
	approval.admissionActivation = currentActivation
	approval.admissionValidatedAt = command.AtUnixNano
	approval.admissionFingerprint, err = policyApprovalAdmissionFingerprint(approval)
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}

	var (
		existing       []policyApproval
		claims         []idempotency.Claim
		disposition    = ApprovalCollectionAppend
		replacedDigest [ccse.DigestSize]byte
	)
	switch decision.Kind() {
	case idempotency.Proceed:
		raw, loadErr := p.collections.SnapshotPolicyApprovalCollection(ctx, binding.Key)
		if loadErr != nil {
			return ApprovalCollectionPlan{}, fmt.Errorf("%w: load empty collection: %v", ErrApprovalCollection, loadErr)
		}
		if len(raw) != 0 {
			return ApprovalCollectionPlan{}, ErrApprovalCollection
		}
	case idempotency.ContinueCollection:
		existing, err = p.loadPolicyApprovalCollection(ctx, binding, decision.ParentSnapshot(), command.AtUnixNano)
		if err != nil {
			return ApprovalCollectionPlan{}, err
		}
	default:
		return ApprovalCollectionPlan{}, ErrApprovalCollection
	}

	newFingerprint, err := approvalEvidenceDigest(newSignedEvidence(approval.record))
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	replaceAt := -1
	for index := range existing {
		fingerprint, fingerprintErr := approvalEvidenceDigest(newSignedEvidence(existing[index].record))
		if fingerprintErr != nil {
			return ApprovalCollectionPlan{}, fingerprintErr
		}
		if fingerprint == newFingerprint {
			return ApprovalCollectionPlan{}, DuplicateApprovalError{
				CollectionVersion: decision.ParentSnapshot().Version, ProgressDigestSHA256: decision.ParentSnapshot().ProgressDigest,
				RecordDigestSHA256: approval.record.digest,
			}
		}
		if existing[index].record.record.Domain.SenderIdentity == approval.record.record.Domain.SenderIdentity {
			if existing[index].record.record.Domain.SignatureKeyID != approval.record.record.Domain.SignatureKeyID {
				// A key rotation changes the canonical PolicyBundle approver key
				// set and therefore requires a new business operation.
				return ApprovalCollectionPlan{}, ErrApprovalSetMismatch
			}
			replaceAt = index
		}
		if existing[index].record.record.Domain.SignatureKeyID == approval.record.record.Domain.SignatureKeyID &&
			existing[index].record.record.Domain.SenderIdentity != approval.record.record.Domain.SenderIdentity {
			return ApprovalCollectionPlan{}, ErrDuplicateApprover
		}
	}

	next := append([]policyApproval(nil), existing...)
	if replaceAt >= 0 {
		prior := existing[replaceAt]
		if prior.record.record.Envelope.MessageID == approval.record.record.Envelope.MessageID ||
			approval.record.record.Domain.Counter <= prior.record.record.Domain.Counter ||
			approval.record.record.Domain.IssuedAtUnixNano <= prior.record.record.Domain.IssuedAtUnixNano ||
			approval.record.record.Domain.ExpiresAtUnixNano <= prior.record.record.Domain.ExpiresAtUnixNano ||
			approval.record.record.Envelope.CorrelationID != prior.record.record.Envelope.CorrelationID ||
			approval.record.record.Envelope.CausationID != prior.record.record.Envelope.CausationID {
			return ApprovalCollectionPlan{}, ErrApprovalCollection
		}
		disposition = ApprovalCollectionReplace
		replacedDigest = prior.record.digest
		next[replaceAt] = approval
	} else {
		if len(existing) >= maxApprovals {
			return ApprovalCollectionPlan{}, ErrApprovalCollection
		}
		next = append(next, approval)
	}
	if err := validatePolicyApprovalCollectionShape(binding, next); err != nil {
		return ApprovalCollectionPlan{}, err
	}
	nextProgress, err := approvalCollectionDigest(binding, next)
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	if decision.Kind() == idempotency.Proceed {
		collectionClaim, claimErr := idempotency.NewReserveCollection(binding, nextProgress)
		if claimErr != nil {
			return ApprovalCollectionPlan{}, fmt.Errorf("%w: collection claim: %v", ErrApprovalCollection, claimErr)
		}
		joinedClaim, claimErr := idempotency.NewReserveCollection(joinedBinding, joinedBinding.RequestDigest)
		if claimErr != nil {
			return ApprovalCollectionPlan{}, fmt.Errorf("%w: joined audit claim: %v", ErrApprovalCollection, claimErr)
		}
		claims = []idempotency.Claim{collectionClaim, joinedClaim}
	} else {
		collectionClaim, claimErr := idempotency.NewAdvanceCollection(decision.ParentSnapshot(), nextProgress)
		if claimErr != nil {
			return ApprovalCollectionPlan{}, fmt.Errorf("%w: collection claim: %v", ErrApprovalCollection, claimErr)
		}
		claims = []idempotency.Claim{collectionClaim}
	}
	claims, err = idempotency.NormalizeClaims(claims)
	if err != nil {
		return ApprovalCollectionPlan{}, fmt.Errorf("%w: normalize collection claims: %v", ErrApprovalCollection, err)
	}

	latencyDeadline, ok := addPositiveNanos(command.AtUnixNano, p.profile.MaxPlanCommitLatencyNanos)
	if !ok {
		return ApprovalCollectionPlan{}, ErrInvalidCommand
	}
	commitDeadline := minimumInt64(latencyDeadline, approval.record.record.Domain.ExpiresAtUnixNano)
	commitDeadline = minimumInt64(commitDeadline, approval.key.NotAfterUnixNano)
	commitDeadline = minimumInt64(commitDeadline, currentActivation.ValidUntilUnixNano)
	commitNotBefore := maximumInt64(subtractFloorZero(command.AtUnixNano, p.profile.MaxClockSkewNanos), approval.record.record.Domain.IssuedAtUnixNano)
	commitNotBefore = maximumInt64(commitNotBefore, currentActivation.ValidFromUnixNano)
	if commitDeadline <= commitNotBefore {
		return ApprovalCollectionPlan{}, ErrPolicyExpired
	}
	value := ApprovalCollectionPlanSnapshot{
		CommitReady:                           true,
		EvaluatedAtUnixNano:                   command.AtUnixNano,
		CommitNotBeforeUnixNano:               commitNotBefore,
		CommitNotAfterUnixNano:                commitDeadline,
		GovernanceProfileDigestSHA256:         p.profileDigest,
		GovernanceProfileActivation:           currentActivation,
		Disposition:                           disposition,
		Binding:                               binding,
		JoinedAuditIdempotencySnapshot:        decision.AuditSnapshot(),
		Claims:                                claims,
		ExpectedCollectionRecordDigestsSHA256: approvalRecordDigests(existing),
		ExpectedReplacedRecordDigestSHA256:    replacedDigest,
		NextCollectionRecordDigestsSHA256:     approvalRecordDigests(next),
		NextProgressDigestSHA256:              nextProgress,
		NextEvidence:                          newSignedEvidence(approval.record),
		NextKeyPrecondition:                   keyPrecondition(approval.key),
		NextAdmissionKey:                      cloneKeySnapshot(approval.admissionKey),
		NextAdmissionProfileDigestSHA256:      approval.admissionProfileDigest,
		NextAdmissionProfileActivation:        approval.admissionActivation,
		NextAdmissionValidatedAtUnixNano:      approval.admissionValidatedAt,
		NextAdmissionFingerprintSHA256:        approval.admissionFingerprint,
		JoinedAuditEventID:                    eventID,
		IdentifierClaims:                      identifierClaims,
	}
	if decision.Kind() == idempotency.ContinueCollection {
		value.PreviousProgressDigestSHA256 = decision.ParentSnapshot().ProgressDigest
	}
	return newApprovalCollectionPlan(value)
}

func (p *Planner) policyAdmissionIdentifierClaims(ctx context.Context, bundle foundationv1.PolicyBundleSigningProjection,
	payloadDigest [ccse.DigestSize]byte, eventID string, decision idempotency.DecisionKind) ([]globalid.Claim, error) {
	if bundle.PolicyBundleID == bundle.Metadata.RecordID || bundle.PolicyBundleID == eventID || bundle.Metadata.RecordID == eventID {
		return nil, ErrInvalidCommand
	}
	bundleOwnerDigest := policyBundleOwnerDigest(bundle.PolicyKind, bundle.PolicyBundleID)
	bundleOwner := globalid.Owner{Domain: globalid.OwnerGovernancePolicyBundle, ID: hex.EncodeToString(bundleOwnerDigest[:])}
	recordOwner := globalid.Owner{Domain: globalid.OwnerCanonicalRecord, ID: hex.EncodeToString(payloadDigest[:])}
	eventOwner := globalid.Owner{Domain: globalid.OwnerGovernanceAuditEvent, ID: eventID}
	type candidate struct {
		id    string
		owner globalid.Owner
		fresh bool
	}
	newLifecycle := bundle.State == PolicyStateApprovedDelayed || (bundle.State == PolicyStateActive && bundle.Emergency)
	candidates := []candidate{
		{id: bundle.PolicyBundleID, owner: bundleOwner, fresh: newLifecycle},
		{id: bundle.Metadata.RecordID, owner: recordOwner, fresh: true},
		{id: eventID, owner: eventOwner, fresh: true},
	}
	claims := make([]globalid.Claim, 0, len(candidates))
	for _, item := range candidates {
		snapshot, exists, err := p.ids.LookupGlobalID(ctx, item.id)
		if err != nil {
			return nil, fmt.Errorf("aiinfra governance: lookup admission identifier: %w", err)
		}
		if decision == idempotency.Proceed && item.fresh {
			if exists || snapshot != (globalid.Snapshot{}) {
				return nil, ErrPolicyConflict
			}
			claim, reserveErr := globalid.Reserve(item.id, item.owner)
			if reserveErr != nil {
				return nil, ErrInvalidCommand
			}
			claims = append(claims, claim)
			continue
		}
		if !exists {
			return nil, ErrPolicyConflict
		}
		claim, assertErr := globalid.Assert(item.id, snapshot, item.owner)
		if assertErr != nil {
			return nil, ErrPolicyConflict
		}
		claims = append(claims, claim)
	}
	claims, err := globalid.NormalizeClaims(claims)
	if err != nil {
		return nil, ErrPolicyConflict
	}
	return claims, nil
}

func validJoinedAuditReservation(snapshot idempotency.Snapshot, binding idempotency.Binding) bool {
	return snapshot.Validate() == nil && snapshot.Binding == binding && snapshot.State == idempotency.StateCollecting &&
		snapshot.Version == 1 && snapshot.ProgressDigest == binding.RequestDigest && snapshot.OutcomeDigest == ([ccse.DigestSize]byte{})
}

func (p *Planner) decodePolicyApproval(ctx context.Context, input SignedRecord, at int64, authorize bool) (policyApproval, error) {
	record, err := p.validateSignedRecord(ctx, input, schema.MessageTypePolicyBundle, policyPurpose, p.profile.PolicyReplayDomainID, at)
	if err != nil {
		return policyApproval{}, err
	}
	decoded, err := p.canonical.Decode(schema.MessageTypePolicyBundle, p.profile.SchemaVersion, record.record.Payload)
	if err != nil {
		return policyApproval{}, ErrInvalidSignedRecord
	}
	bundle, ok := decoded.(foundationv1.PolicyBundleSigningProjection)
	if !ok {
		return policyApproval{}, ErrInvalidSignedRecord
	}
	identity := record.record.Domain.SenderIdentity
	keyID := record.record.Domain.SignatureKeyID
	if bundle.Metadata.CreatedAtUnixNano > record.record.Domain.IssuedAtUnixNano ||
		len(bundle.ApproverIdentities) == 0 || len(bundle.ApproverIdentities) != len(bundle.ApproverKeyIDs) ||
		len(bundle.ApproverIdentities) > maxApprovals || hasDuplicateStrings(bundle.ApproverIdentities) ||
		hasDuplicateStrings(bundle.ApproverKeyIDs) || !containsString(bundle.ApproverIdentities, identity) ||
		!containsString(bundle.ApproverKeyIDs, keyID) || bundle.MinimumApprovals == 0 ||
		bundle.MinimumApprovals > uint32(len(bundle.ApproverIdentities)) {
		return policyApproval{}, ErrApprovalSetMismatch
	}
	result := policyApproval{record: record, bundle: bundle}
	if authorize {
		key, authorizeErr := p.authorizeKey(ctx, record, schema.MessageTypePolicyBundle, at)
		if authorizeErr != nil {
			return policyApproval{}, authorizeErr
		}
		if !containsDigest(bundle.Metadata.PolicyDigestsSHA256, key.AuthorizationPolicyDigestSHA256) ||
			!containsDigest(bundle.Metadata.PolicyDigestsSHA256, p.profileDigest) {
			return policyApproval{}, ErrKeyNotAuthorized
		}
		result.key = key
	}
	return result, nil
}

func (p *Planner) loadPolicyApprovalCollection(ctx context.Context, binding idempotency.Binding, snapshot idempotency.Snapshot, at int64) ([]policyApproval, error) {
	if snapshot.Validate() != nil || snapshot.State != idempotency.StateCollecting || snapshot.Binding != binding ||
		snapshot.Version == 0 || isZeroDigest(snapshot.ProgressDigest) {
		return nil, ErrApprovalCollection
	}
	raw, err := p.collections.SnapshotPolicyApprovalCollection(ctx, binding.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: load: %v", ErrApprovalCollection, err)
	}
	if len(raw) == 0 || len(raw) > maxApprovals || snapshot.Version < uint64(len(raw)) {
		return nil, ErrApprovalCollection
	}
	approvals := make([]policyApproval, 0, len(raw))
	for index := range raw {
		admitted, _, decodeErr := p.validatePolicyApprovalAdmission(ctx, raw[index])
		if decodeErr != nil {
			return nil, fmt.Errorf("retained admission %d: %w", index, decodeErr)
		}
		if admitted.legacyAdmission {
			return nil, fmt.Errorf("retained admission %d: %w", index, ErrApprovalCollection)
		}
		approval, decodeErr := p.decodePolicyApproval(ctx, raw[index].Signed, at, true)
		if decodeErr != nil {
			return nil, fmt.Errorf("retained approval %d: %w", index, decodeErr)
		}
		approval.admissionKey = cloneKeySnapshot(admitted.admissionKey)
		approval.admissionProfileDigest = admitted.admissionProfileDigest
		approval.admissionActivation = admitted.admissionActivation
		approval.admissionValidatedAt = admitted.admissionValidatedAt
		approval.admissionFingerprint = admitted.admissionFingerprint
		approvals = append(approvals, approval)
	}
	if err := validatePolicyApprovalCollectionShape(binding, approvals); err != nil {
		return nil, err
	}
	activeActivation, active, err := p.profiles.ActiveGovernanceProfile(ctx, at)
	if err != nil || !active || !validGovernanceProfileActivation(activeActivation, at) ||
		activeActivation != approvals[0].admissionActivation {
		return nil, ErrApprovalCollection
	}
	progress, err := approvalCollectionDigest(binding, approvals)
	if err != nil || progress != snapshot.ProgressDigest {
		return nil, ErrApprovalCollection
	}
	return approvals, contextErr(ctx)
}

func (p *Planner) validatePolicyApprovalAdmission(ctx context.Context, entry PolicyApprovalCollectionEntry) (policyApproval, Profile, error) {
	if entry.Signed.Record == nil || !preflightRawRecord(entry.Signed.Record, maxPayloadBytesFor(schema.MessageTypePolicyBundle)) ||
		!preflightKeySnapshot(entry.AdmissionKey) || isZeroDigest(entry.GovernanceProfileDigestSHA256) ||
		isZeroDigest(entry.AdmissionFingerprintSHA256) || entry.ValidatedAtUnixNano < 0 {
		return policyApproval{}, Profile{}, ErrApprovalCollection
	}
	approval, profile, profileDigest, err := p.decodePolicyApprovalForReconcile(ctx, entry.Signed)
	if err != nil || profileDigest != entry.GovernanceProfileDigestSHA256 {
		return policyApproval{}, Profile{}, ErrApprovalCollection
	}
	issuedActivation, activeAtIssue, err := p.profiles.ActiveGovernanceProfile(ctx, approval.record.record.Domain.IssuedAtUnixNano)
	if err != nil || !activeAtIssue || !validGovernanceProfileActivation(issuedActivation, approval.record.record.Domain.IssuedAtUnixNano) ||
		issuedActivation.GovernanceProfileDigestSHA256 != profileDigest {
		return policyApproval{}, Profile{}, ErrApprovalCollection
	}
	key, err := authorizeHistoricalPolicyKey(approval.record, entry.AdmissionKey, profile)
	if err != nil || entry.ValidatedAtUnixNano < approval.record.record.Domain.IssuedAtUnixNano ||
		entry.ValidatedAtUnixNano >= approval.record.record.Domain.ExpiresAtUnixNano ||
		entry.ValidatedAtUnixNano < key.NotBeforeUnixNano || entry.ValidatedAtUnixNano >= key.NotAfterUnixNano ||
		!containsDigest(approval.bundle.Metadata.PolicyDigestsSHA256, profileDigest) ||
		!containsDigest(approval.bundle.Metadata.PolicyDigestsSHA256, key.AuthorizationPolicyDigestSHA256) {
		return policyApproval{}, Profile{}, ErrApprovalCollection
	}
	authoritative, found, historyErr := p.iam.ResolveGovernanceKeyAt(ctx, key.KeyID, entry.ValidatedAtUnixNano)
	if historyErr != nil || !found || !preflightKeySnapshot(authoritative) ||
		!exactGovernanceKeySnapshot(key, authoritative) {
		return policyApproval{}, Profile{}, ErrApprovalCollection
	}
	approval.admissionKey = cloneKeySnapshot(key)
	approval.admissionProfileDigest = profileDigest
	approval.admissionValidatedAt = entry.ValidatedAtUnixNano
	if entry.GovernanceProfileActivation == (GovernanceProfileActivationSnapshot{}) {
		// Legacy V1 admission evidence did not retain the activation row. It is
		// sufficient only to terminally reconcile a stranded collection; it can
		// never contribute to a successful policy mutation or a new ingestion.
		approval.legacyAdmission = true
		approval.admissionFingerprint, err = legacyPolicyApprovalAdmissionFingerprint(approval)
	} else {
		admissionActivation, activeAtAdmission, activationErr := p.profiles.ActiveGovernanceProfile(ctx, entry.ValidatedAtUnixNano)
		if activationErr != nil || !activeAtAdmission ||
			!validGovernanceProfileActivation(entry.GovernanceProfileActivation, approval.record.record.Domain.IssuedAtUnixNano) ||
			!validGovernanceProfileActivation(entry.GovernanceProfileActivation, entry.ValidatedAtUnixNano) ||
			entry.GovernanceProfileActivation.GovernanceProfileDigestSHA256 != profileDigest ||
			issuedActivation != entry.GovernanceProfileActivation || admissionActivation != entry.GovernanceProfileActivation {
			return policyApproval{}, Profile{}, ErrApprovalCollection
		}
		approval.admissionActivation = entry.GovernanceProfileActivation
		approval.admissionFingerprint, err = policyApprovalAdmissionFingerprint(approval)
	}
	if err != nil || approval.admissionFingerprint != entry.AdmissionFingerprintSHA256 {
		return policyApproval{}, Profile{}, ErrApprovalCollection
	}
	return approval, profile, nil
}

func (p *Planner) validatePolicyApprovalCollection(ctx context.Context, binding idempotency.Binding, snapshot idempotency.Snapshot,
	incoming []policyApproval, at int64) ([]policyApproval, error) {
	collected, err := p.loadPolicyApprovalCollection(ctx, binding, snapshot, at)
	if err != nil {
		return nil, err
	}
	if !approvalEvidenceSetsEqual(collected, incoming) {
		return nil, ErrApprovalCollection
	}
	return collected, nil
}

func validatePolicyApprovalCollectionShape(binding idempotency.Binding, approvals []policyApproval) error {
	if binding.Validate() != nil || len(approvals) == 0 || len(approvals) > maxApprovals {
		return ErrApprovalCollection
	}
	firstPayload := approvals[0].record.record.Payload
	firstCorrelation := approvals[0].record.record.Envelope.CorrelationID
	firstCausation := approvals[0].record.record.Envelope.CausationID
	identities := make(map[string]struct{}, len(approvals))
	keys := make(map[string]string, len(approvals))
	digests := make(map[[ccse.DigestSize]byte]struct{}, len(approvals))
	var exactActivation GovernanceProfileActivationSnapshot
	for _, approval := range approvals {
		actualBinding := policyIdempotencyBinding(approval.bundle, approval.record.record.Envelope.PayloadDigest)
		identity := approval.record.record.Domain.SenderIdentity
		keyID := approval.record.record.Domain.SignatureKeyID
		if actualBinding != binding || !bytes.Equal(firstPayload, approval.record.record.Payload) ||
			approval.record.record.Envelope.CorrelationID != firstCorrelation || approval.record.record.Envelope.CausationID != firstCausation ||
			isZeroDigest(approval.admissionProfileDigest) || approval.admissionValidatedAt < 0 ||
			isZeroDigest(approval.admissionFingerprint) || !preflightKeySnapshot(approval.admissionKey) {
			return ErrApprovalPayloadMismatch
		}
		var fingerprint [ccse.DigestSize]byte
		var err error
		if approval.legacyAdmission {
			fingerprint, err = legacyPolicyApprovalAdmissionFingerprint(approval)
		} else {
			if exactActivation == (GovernanceProfileActivationSnapshot{}) {
				exactActivation = approval.admissionActivation
			} else if approval.admissionActivation != exactActivation {
				return ErrApprovalCollection
			}
			fingerprint, err = policyApprovalAdmissionFingerprint(approval)
		}
		if err != nil || fingerprint != approval.admissionFingerprint {
			return ErrApprovalCollection
		}
		if _, duplicate := identities[identity]; duplicate {
			return ErrDuplicateApprover
		}
		if owner, duplicate := keys[keyID]; duplicate && owner != identity {
			return ErrDuplicateApprover
		}
		if _, duplicate := digests[approval.record.digest]; duplicate {
			return ErrDuplicateApprover
		}
		identities[identity] = struct{}{}
		keys[keyID] = identity
		digests[approval.record.digest] = struct{}{}
	}
	return nil
}

func approvalCollectionDigest(binding idempotency.Binding, approvals []policyApproval) ([ccse.DigestSize]byte, error) {
	var zero [ccse.DigestSize]byte
	if err := validatePolicyApprovalCollectionShape(binding, approvals); err != nil {
		return zero, err
	}
	ordered := orderedPolicyApprovals(approvals)
	w := newDigestWriter(approvalCollectionDigestDomain)
	w.bytes(binding.Key[:])
	w.string(string(binding.Domain))
	w.string(binding.OwnerID)
	w.digest(binding.RequestDigest)
	w.uint64(uint64(len(ordered)))
	for _, approval := range ordered {
		w.string(approval.record.record.Domain.SenderIdentity)
		w.string(approval.record.record.Domain.SignatureKeyID)
		w.evidence(newSignedEvidence(approval.record))
		w.digest(digestGovernanceAuthorizationSnapshot(approval.admissionKey))
		w.digest(approval.admissionProfileDigest)
		w.profileActivation(approval.admissionActivation)
		w.int64(approval.admissionValidatedAt)
		w.digest(approval.admissionFingerprint)
	}
	return w.sum()
}

// legacyApprovalCollectionDigest reproduces the original V1 progress tuple.
// It is accepted only by terminal reconciliation when at least one retained
// admission predates exact activation-row retention.
func legacyApprovalCollectionDigest(binding idempotency.Binding, approvals []policyApproval) ([ccse.DigestSize]byte, error) {
	var zero [ccse.DigestSize]byte
	if err := validatePolicyApprovalCollectionShape(binding, approvals); err != nil {
		return zero, err
	}
	ordered := orderedPolicyApprovals(approvals)
	w := newDigestWriter(legacyApprovalCollectionDigestDomain)
	w.bytes(binding.Key[:])
	w.string(string(binding.Domain))
	w.string(binding.OwnerID)
	w.digest(binding.RequestDigest)
	w.uint64(uint64(len(ordered)))
	for _, approval := range ordered {
		w.string(approval.record.record.Domain.SenderIdentity)
		w.string(approval.record.record.Domain.SignatureKeyID)
		w.evidence(newSignedEvidence(approval.record))
		w.digest(approval.admissionFingerprint)
	}
	return w.sum()
}

func orderedPolicyApprovals(approvals []policyApproval) []policyApproval {
	ordered := append([]policyApproval(nil), approvals...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i].record.record.Domain, ordered[j].record.record.Domain
		if left.SenderIdentity != right.SenderIdentity {
			return left.SenderIdentity < right.SenderIdentity
		}
		if left.SignatureKeyID != right.SignatureKeyID {
			return left.SignatureKeyID < right.SignatureKeyID
		}
		return bytes.Compare(ordered[i].record.digest[:], ordered[j].record.digest[:]) < 0
	})
	return ordered
}

func policyApprovalAdmissionFingerprint(approval policyApproval) ([ccse.DigestSize]byte, error) {
	if approval.record.record.MessageTypeID == 0 || !preflightKeySnapshot(approval.admissionKey) ||
		isZeroDigest(approval.admissionProfileDigest) || approval.admissionValidatedAt < approval.record.record.Domain.IssuedAtUnixNano ||
		approval.admissionValidatedAt >= approval.record.record.Domain.ExpiresAtUnixNano ||
		approval.admissionKey.KeyID != approval.record.record.Domain.SignatureKeyID ||
		approval.admissionKey.KeyID != approval.record.record.Envelope.SignatureKeyID ||
		approval.admissionKey.SubjectIdentity != approval.record.record.Domain.SenderIdentity ||
		approval.admissionKey.SubjectIdentity != approval.record.record.Envelope.SenderIdentity ||
		approval.admissionKey.TargetIdentityKind != 1 || approval.admissionKey.TargetPrincipalKind < 1 ||
		approval.admissionKey.TargetPrincipalKind > 8 || approval.admissionKey.TargetIdentityID == "" ||
		approval.admissionKey.OrganizationIdentity == "" || approval.admissionKey.LifecycleState != KeyLifecycleStateActive ||
		approval.admissionKey.RevokedAtUnixNano != 0 || approval.admissionKey.NotBeforeUnixNano > approval.record.record.Domain.IssuedAtUnixNano ||
		approval.admissionKey.NotAfterUnixNano < approval.record.record.Domain.ExpiresAtUnixNano ||
		approval.admissionKey.Algorithm != ccse.SignatureAlgorithmEd25519 ||
		approval.admissionKey.Algorithm != approval.record.record.Domain.SignatureAlgorithm ||
		approval.admissionKey.Algorithm != approval.record.record.Envelope.SignatureAlgorithm ||
		!containsMessageType(approval.admissionKey.AllowedMessageTypeIDs, schema.MessageTypePolicyBundle) ||
		approval.admissionKey.EnrollmentDomainID == "" || approval.admissionKey.EnrollmentEnvironment == "" ||
		isZeroDigest(approval.admissionKey.EnrollmentGenesisHash) || isZeroDigest(approval.admissionKey.AuthorizationPolicyDigestSHA256) ||
		approval.admissionKey.StateVersion == 0 || approval.admissionKey.WriterEpoch == 0 ||
		isZeroDigest(approval.admissionKey.SnapshotDigestSHA256) || approval.admissionKey.IdentityStateVersion == 0 ||
		approval.admissionKey.IdentityWriterEpoch == 0 || isZeroDigest(approval.admissionKey.IdentitySnapshotDigestSHA256) ||
		len(approval.admissionKey.PublicKey) != ed25519.PublicKeySize || len(approval.record.record.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(approval.admissionKey.PublicKey), approval.record.digest[:], approval.record.record.Signature) ||
		!validGovernanceProfileActivation(approval.admissionActivation, approval.record.record.Domain.IssuedAtUnixNano) ||
		!validGovernanceProfileActivation(approval.admissionActivation, approval.admissionValidatedAt) ||
		approval.admissionActivation.GovernanceProfileDigestSHA256 != approval.admissionProfileDigest || approval.legacyAdmission {
		return [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	w := newDigestWriter(approvalAdmissionDigestDomain)
	w.evidence(newSignedEvidence(approval.record))
	w.digest(digestGovernanceAuthorizationSnapshot(approval.admissionKey))
	w.digest(approval.admissionProfileDigest)
	w.profileActivation(approval.admissionActivation)
	w.int64(approval.admissionValidatedAt)
	return w.sum()
}

func legacyPolicyApprovalAdmissionFingerprint(approval policyApproval) ([ccse.DigestSize]byte, error) {
	approval.admissionActivation = GovernanceProfileActivationSnapshot{
		GovernanceProfileDigestSHA256: approval.admissionProfileDigest,
		Version:                       1, ValidFromUnixNano: 0, ValidUntilUnixNano: approval.admissionKey.NotAfterUnixNano,
		EvidenceDigestSHA256: approval.record.digest,
	}
	approval.legacyAdmission = false
	// Reuse all V2 structural/signature checks, then encode the exact legacy V1
	// preimage. The synthetic activation is never retained or trusted.
	if _, err := policyApprovalAdmissionFingerprint(approval); err != nil {
		return [ccse.DigestSize]byte{}, err
	}
	w := newDigestWriter(legacyApprovalAdmissionDigestDomain)
	w.evidence(newSignedEvidence(approval.record))
	w.digest(digestGovernanceAuthorizationSnapshot(approval.admissionKey))
	w.digest(approval.admissionProfileDigest)
	w.int64(approval.admissionValidatedAt)
	return w.sum()
}

func approvalEvidenceDigest(evidence SignedEvidence) ([ccse.DigestSize]byte, error) {
	w := newDigestWriter(approvalEvidenceDigestDomain)
	w.evidence(evidence)
	return w.sum()
}

func approvalEvidenceSetsEqual(left, right []policyApproval) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[[ccse.DigestSize]byte]struct{}, len(left))
	for _, approval := range left {
		digest, err := approvalEvidenceDigest(newSignedEvidence(approval.record))
		if err != nil {
			return false
		}
		seen[digest] = struct{}{}
	}
	if len(seen) != len(left) {
		return false
	}
	for _, approval := range right {
		digest, err := approvalEvidenceDigest(newSignedEvidence(approval.record))
		if err != nil {
			return false
		}
		if _, ok := seen[digest]; !ok {
			return false
		}
		delete(seen, digest)
	}
	return len(seen) == 0
}

func approvalEvidenceSetMatchesRetained(left []policyApproval, right []SignedEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[[ccse.DigestSize]byte]struct{}, len(left))
	for _, approval := range left {
		digest, err := approvalEvidenceDigest(newSignedEvidence(approval.record))
		if err != nil {
			return false
		}
		seen[digest] = struct{}{}
	}
	if len(seen) != len(left) {
		return false
	}
	for _, evidence := range right {
		digest, err := approvalEvidenceDigest(evidence)
		if err != nil {
			return false
		}
		if _, ok := seen[digest]; !ok {
			return false
		}
		delete(seen, digest)
	}
	return len(seen) == 0
}

func approvalRecordDigests(approvals []policyApproval) [][ccse.DigestSize]byte {
	result := make([][ccse.DigestSize]byte, 0, len(approvals))
	for _, approval := range approvals {
		result = append(result, approval.record.digest)
	}
	sortDigests(result)
	return result
}

func approvalAdmissionEvidence(approvals []policyApproval) []ApprovalAdmissionEvidence {
	result := make([]ApprovalAdmissionEvidence, 0, len(approvals))
	for _, approval := range approvals {
		result = append(result, ApprovalAdmissionEvidence{
			RecordDigestSHA256: approval.record.digest, AdmissionKey: cloneKeySnapshot(approval.admissionKey),
			GovernanceProfileDigestSHA256: approval.admissionProfileDigest, ValidatedAtUnixNano: approval.admissionValidatedAt,
			GovernanceProfileActivation: approval.admissionActivation,
			AdmissionFingerprintSHA256:  approval.admissionFingerprint,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].RecordDigestSHA256[:], result[j].RecordDigestSHA256[:]) < 0
	})
	return result
}

func newApprovalCollectionPlan(value ApprovalCollectionPlanSnapshot) (ApprovalCollectionPlan, error) {
	value.ExpectedCollectionRecordDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.ExpectedCollectionRecordDigestsSHA256...)
	value.NextCollectionRecordDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.NextCollectionRecordDigestsSHA256...)
	value.Claims = append([]idempotency.Claim(nil), value.Claims...)
	value.IdentifierClaims = append([]globalid.Claim(nil), value.IdentifierClaims...)
	value.NextEvidence = cloneSignedEvidence(value.NextEvidence)
	value.NextAdmissionKey = cloneKeySnapshot(value.NextAdmissionKey)
	digest, err := digestApprovalCollectionPlan(value)
	if err != nil {
		return ApprovalCollectionPlan{}, err
	}
	return ApprovalCollectionPlan{value: value, digest: digest}, nil
}
