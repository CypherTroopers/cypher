// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package coordinator

import (
	"bytes"
	"context"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/governance"
	"github.com/cypherium/cypher/aiinfra/iam"
	"github.com/cypherium/cypher/aiinfra/idempotency"
	"github.com/cypherium/cypher/aiinfra/storage/postgres"
)

func addCanonicalWriteBytes(total *uint64, size int) error {
	if total == nil || size < 0 || *total > postgres.MaxCanonicalUOWBytes ||
		uint64(size) > postgres.MaxCanonicalUOWBytes-*total {
		return ErrInvalidCompoundResult
	}
	*total += uint64(size)
	return nil
}

// preflightAuditedFinalWriteBudget mirrors PostgreSQL's shared 64 MiB write
// budget before the executor issues its first semantic write. Existing
// evidence assertions are reads and do not consume it; newly reserved IAM and
// Governance evidence, pending revision envelopes and canonical-state Next
// rows do. This prevents a valid pre-sign plan from being stranded only after
// its result receipt has enabled writes.
func preflightAuditedFinalWriteBudget(request iam.JoinedAuditRequest,
	execution iam.IAMExecutionFragment, view governance.JoinedAuditFragmentSnapshot,
	persistence iam.IAMPendingPersistenceCapability,
	revisions []iam.IAMPendingRevision) error {
	var total uint64
	if state, present := request.CanonicalStateBundle(); present {
		for _, mutation := range state.Mutations() {
			if mutation.VerifyDigest() != nil ||
				addCanonicalWriteBytes(&total, len(mutation.Next().CanonicalState)) != nil {
				return ErrInvalidCompoundResult
			}
		}
		projections, err := iam.BuildSemanticProjectionsV2(execution)
		if err != nil {
			return ErrInvalidCompoundResult
		}
		for _, projection := range projections {
			if addCanonicalWriteBytes(&total, len(projection.Bytes())) != nil {
				return ErrInvalidCompoundResult
			}
		}
	}
	for _, capability := range persistence.EvidenceStorageCapabilities() {
		if capability.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		if capability.Disposition() == iam.IAMEvidenceStorageReserveNew {
			evidence := capability.Evidence()
			if evidence.VerifyDigest() != nil ||
				addCanonicalWriteBytes(&total, len(evidence.Record().CanonicalContent)) != nil {
				return ErrInvalidCompoundResult
			}
		}
	}
	for _, capability := range view.AuditSourceStorageCapabilities {
		if capability.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		if capability.Disposition() == governance.DurableEvidenceStorageReserveNew &&
			addCanonicalWriteBytes(&total, len(capability.CanonicalContent())) != nil {
			return ErrInvalidCompoundResult
		}
	}
	for _, revision := range revisions {
		if revision.VerifyDigest() != nil ||
			addCanonicalWriteBytes(&total, len(revision.Record().CanonicalEnvelope)) != nil {
			return ErrInvalidCompoundResult
		}
	}
	return nil
}

func applyGovernanceStateAssertions(ctx context.Context, uow *postgres.CanonicalUOW,
	values []governance.CanonicalStateAssertion) error {
	if uow == nil || len(values) == 0 {
		return ErrInvalidCompoundResult
	}
	for _, value := range values {
		record, err := mapGovernanceStateAssertion(value)
		if err != nil {
			return err
		}
		if err := uow.AssertCanonicalState(ctx, record); err != nil {
			return err
		}
	}
	return nil
}

func applyGovernanceKeyStateAssertions(ctx context.Context, uow *postgres.CanonicalUOW,
	values []governance.CanonicalKeyStateAssertion) error {
	if uow == nil || len(values) == 0 {
		return ErrInvalidCompoundResult
	}
	for _, value := range values {
		if value.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		records := value.Records()
		if len(records) != 3 {
			return ErrInvalidCompoundResult
		}
		for _, record := range records {
			mapped, err := mapGovernanceIAMStateRecord(record)
			if err != nil {
				return err
			}
			if err := uow.AssertCanonicalState(ctx, mapped); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyGovernanceAuditWriterLeaseAssertion(ctx context.Context, uow *postgres.CanonicalUOW,
	value governance.CanonicalAuditWriterLeaseAssertion) error {
	if uow == nil || value.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	record, err := mapGovernanceIAMStateRecord(value.Record())
	if err != nil || record.Kind != postgres.CanonicalStateIAMWriterLease {
		return ErrInvalidCompoundResult
	}
	return uow.AssertCanonicalState(ctx, record)
}

func assertIAMStateBundle(ctx context.Context, uow *postgres.CanonicalUOW,
	bundle iam.IAMCanonicalStateBundle) error {
	if uow == nil || bundle.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	for _, value := range bundle.Assertions() {
		record, err := mapIAMStateAssertion(value)
		if err != nil {
			return err
		}
		if err := uow.AssertCanonicalState(ctx, record); err != nil {
			return err
		}
		if projection, present := value.SemanticProjectionV2(); present {
			if projection.Codec() != postgres.SemanticProjectionCodecIAMV2 ||
				projection.Kind != string(record.Kind) || projection.ObjectID != record.ObjectID ||
				projection.Version != record.Version || projection.StateDigestSHA256 != record.StateDigest {
				return ErrInvalidCompoundResult
			}
			if err := uow.AssertSemanticProjection(ctx, postgres.SemanticProjectionRecord{
				State: record, Codec: projection.Codec(), ProjectionDigest: projection.Digest(),
				CanonicalProjection: projection.Bytes(),
			}); err != nil {
				return err
			}
		}
	}
	for _, value := range bundle.Absences() {
		namespace, kind, objectID, err := mapIAMStateAbsence(value)
		if err != nil {
			return err
		}
		if err := uow.AssertCanonicalStateAbsent(ctx, namespace, kind, objectID); err != nil {
			return err
		}
	}
	return nil
}

func mapIAMStateAbsence(value iam.CanonicalStateAbsence) (postgres.CanonicalStateNamespace,
	postgres.CanonicalStateKind, string, error) {
	if value.VerifyDigest() != nil || value.Namespace() != iam.CanonicalStateNamespaceIAM ||
		value.ObjectID() == "" {
		return 0, "", "", ErrInvalidCompoundResult
	}
	var kind postgres.CanonicalStateKind
	switch value.Kind() {
	case iam.CanonicalStateKindIAMKeyMaterial:
		kind = postgres.CanonicalStateIAMKeyMaterial
	case iam.CanonicalStateKindIAMIdentity:
		kind = postgres.CanonicalStateIAMIdentity
	case iam.CanonicalStateKindIAMKeyLifecycle:
		kind = postgres.CanonicalStateIAMKeyLifecycle
	case iam.CanonicalStateKindIAMAcceptedOwnershipTransfer:
		kind = postgres.CanonicalStateIAMAcceptedOwnershipTransfer
	case iam.CanonicalStateKindIAMProofChallenge:
		kind = postgres.CanonicalStateIAMProofChallenge
	case iam.CanonicalStateKindIAMPrincipalIdentityIndex:
		kind = postgres.CanonicalStateIAMPrincipalIdentityIndex
	case iam.CanonicalStateKindIAMRotationPredecessorIndex:
		kind = postgres.CanonicalStateIAMRotationPredecessorIndex
	case iam.CanonicalStateKindIAMSubjectKeySet:
		kind = postgres.CanonicalStateIAMSubjectKeySet
	case iam.CanonicalStateKindIAMWriterLease:
		kind = postgres.CanonicalStateIAMWriterLease
	case iam.CanonicalStateKindIAMTransferProfileActivation:
		kind = postgres.CanonicalStateIAMTransferProfileActivation
	default:
		return 0, "", "", ErrInvalidCompoundResult
	}
	if value.Kind() != string(kind) {
		return 0, "", "", ErrInvalidCompoundResult
	}
	return postgres.CanonicalStateIAM, kind, value.ObjectID(), nil
}

func applyIAMStateMutations(ctx context.Context, uow *postgres.CanonicalUOW,
	bundle iam.IAMCanonicalStateBundle, execution iam.IAMExecutionFragment) error {
	if uow == nil || bundle.VerifyDigest() != nil || execution.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	values := bundle.Mutations()
	mutations := make([]postgres.CanonicalStateMutation, len(values))
	for index, value := range values {
		mapped, err := mapIAMStateMutation(value)
		if err != nil {
			return err
		}
		mutations[index] = mapped
	}
	if len(mutations) == 0 {
		return nil
	}
	projections, err := iam.BuildSemanticProjectionsV2(execution)
	if err != nil {
		return ErrInvalidCompoundResult
	}
	if err := uow.ApplyCanonicalStates(ctx, mutations); err != nil {
		return err
	}
	for _, projection := range projections {
		var state *postgres.CanonicalStateRecord
		for index := range mutations {
			next := mutations[index].Next
			if string(next.Kind) == projection.Kind && next.ObjectID == projection.ObjectID &&
				next.Version == projection.Version && next.StateDigest == projection.StateDigestSHA256 {
				if state != nil {
					return ErrInvalidCompoundResult
				}
				copy := next
				state = &copy
			}
		}
		if state == nil || projection.Codec() != postgres.SemanticProjectionCodecIAMV2 {
			return ErrInvalidCompoundResult
		}
		if err := uow.AttachSemanticProjection(ctx, postgres.SemanticProjectionRecord{
			State: *state, Codec: projection.Codec(), ProjectionDigest: projection.Digest(),
			CanonicalProjection: projection.Bytes(), LookupDigest: projection.LookupDigestSHA256,
			HasLookupDigest: projection.HasLookupDigest,
		}); err != nil {
			return err
		}
	}
	return nil
}

func applyBusinessClaims(ctx context.Context, uow *postgres.CanonicalUOW,
	request iam.JoinedAuditRequest, execution iam.IAMExecutionFragment, outcome [32]byte) error {
	if uow == nil || request.VerifyDigest() != nil || execution.VerifyDigest() != nil || outcome == ([32]byte{}) {
		return ErrInvalidCompoundResult
	}
	completion := execution.IdempotencyCompletionClaims()
	members := execution.CompoundMemberCompletionClaims()
	if len(completion) == 0 {
		return ErrInvalidCompoundResult
	}
	if err := uow.ApplyBusinessIdempotency(ctx, postgres.BusinessIdempotencyMutation{
		ExpectedAuditEventID: request.JoinedAuditEventID(), OutcomeDigest: outcome,
		Claims: completion, CompoundMembers: members,
	}); err != nil {
		return err
	}
	admission := execution.IdempotencyAdmissionClaims()
	memberAdmission := execution.CompoundMemberAdmissionClaims()
	if len(admission) == 0 && len(memberAdmission) == 0 {
		return nil
	}
	futureEventID, err := joinedEventIDForClaims(admission)
	if err != nil {
		return err
	}
	return uow.ApplyBusinessIdempotency(ctx, postgres.BusinessIdempotencyMutation{
		ExpectedAuditEventID: futureEventID, Claims: admission, CompoundMembers: memberAdmission,
	})
}

func joinedEventIDForClaims(input []idempotency.Claim) (string, error) {
	claims, err := idempotency.NormalizeClaims(input)
	if err != nil {
		return "", ErrInvalidCompoundResult
	}
	var parent *idempotency.Binding
	for _, claim := range claims {
		if claim.Binding.Domain == idempotency.OperationJoinedAudit {
			continue
		}
		if parent != nil {
			return "", ErrInvalidCompoundResult
		}
		value := claim.Binding
		parent = &value
	}
	if parent == nil {
		return "", ErrInvalidCompoundResult
	}
	joined, err := idempotency.JoinedAuditBinding(*parent)
	if err != nil {
		return "", ErrInvalidCompoundResult
	}
	found := false
	for _, claim := range claims {
		if claim.Binding == joined {
			found = true
		}
	}
	if !found {
		return "", ErrInvalidCompoundResult
	}
	eventID, err := idempotency.JoinedAuditEventID(*parent)
	if err != nil {
		return "", ErrInvalidCompoundResult
	}
	return eventID, nil
}

func applyGlobalClaims(ctx context.Context, uow *postgres.CanonicalUOW,
	request iam.JoinedAuditRequest, execution iam.IAMExecutionFragment) error {
	if uow == nil || request.VerifyDigest() != nil || execution.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	assertions, err := normalizeFinalIdentifierAssertions(execution.IdentifierAssertions(),
		execution.JoinedAuditEventIdentifierAssertion())
	if err != nil {
		return ErrInvalidCompoundResult
	}
	if err := uow.ApplyGlobalClaims(ctx, postgres.GlobalClaimMutation{
		AuditEventID: request.JoinedAuditEventID(), Claims: assertions,
	}); err != nil {
		return err
	}
	reservations := execution.IdentifierReservations()
	if len(reservations) == 0 {
		return nil
	}
	futureEventID, err := joinedEventIDForClaims(execution.IdempotencyAdmissionClaims())
	if err != nil {
		return err
	}
	return uow.ApplyGlobalClaims(ctx, postgres.GlobalClaimMutation{
		AuditEventID: futureEventID, Claims: reservations,
	})
}

func normalizeFinalIdentifierAssertions(values []globalid.Claim,
	joinedEvent globalid.Claim) ([]globalid.Claim, error) {
	assertions, err := globalid.NormalizeClaims(values)
	if err != nil || len(assertions) == 0 || joinedEvent.Validate() != nil {
		return nil, ErrInvalidCompoundResult
	}
	// The joined AuditEvent assertion is part of the semantic set already.
	// Appending it before normalization turns a valid maximal claim set into a
	// max+1 raw input, which the shared boundary correctly rejects
	// before deduplication. Require exact membership instead.
	for _, assertion := range assertions {
		if assertion == joinedEvent {
			return assertions, nil
		}
	}
	return nil, ErrInvalidCompoundResult
}

func mapGovernanceEvidence(value governance.DurableEvidenceStorageCapability) (
	postgres.DurableEvidenceRecord, postgres.EvidenceAssertion, governance.DurableEvidenceStorageDisposition, error) {
	if value.VerifyDigest() != nil {
		return postgres.DurableEvidenceRecord{}, postgres.EvidenceAssertion{}, 0, ErrInvalidCompoundResult
	}
	kind := postgres.DurableEvidenceKind(value.Kind())
	if kind != postgres.DurableEvidenceContentSHA256 && kind != postgres.DurableEvidenceSignedCCSERecord &&
		kind != postgres.DurableEvidenceSemanticReceipt {
		return postgres.DurableEvidenceRecord{}, postgres.EvidenceAssertion{}, 0, ErrInvalidCompoundResult
	}
	pendingKey, pendingRevision, hasPending := value.PendingLink()
	return postgres.DurableEvidenceRecord{Digest: value.EvidenceDigest(), Kind: kind,
			ContentType: value.ContentType(), CanonicalContent: value.CanonicalContent(),
			ExpectedAuditEventID: value.ExpectedAuditEventID()}, postgres.EvidenceAssertion{
			EvidenceDigest: value.EvidenceDigest(), HasPending: hasPending,
			PendingKey: pendingKey, PendingRevision: pendingRevision,
		}, value.Disposition(), nil
}

// applyGovernanceEvidence executes only the disposition embedded in each
// semantic capability, then records the exact audited-final assertion set.
// No row-presence probe is used to choose reserve versus assert.
func applyGovernanceEvidence(ctx context.Context, uow *postgres.CanonicalUOW,
	eventID string, values []governance.DurableEvidenceStorageCapability) error {
	if uow == nil || eventID == "" || len(values) == 0 {
		return ErrInvalidCompoundResult
	}
	type mapped struct {
		record      postgres.DurableEvidenceRecord
		assertion   postgres.EvidenceAssertion
		disposition governance.DurableEvidenceStorageDisposition
	}
	prepared := make([]mapped, len(values))
	for index, value := range values {
		if value.AuditAssertionEventID() != eventID {
			return ErrInvalidCompoundResult
		}
		record, assertion, disposition, err := mapGovernanceEvidence(value)
		if err != nil {
			return err
		}
		prepared[index] = mapped{record: record, assertion: assertion, disposition: disposition}
	}
	sort.Slice(prepared, func(i, j int) bool {
		return bytes.Compare(prepared[i].record.Digest[:], prepared[j].record.Digest[:]) < 0
	})
	for index, value := range prepared {
		if index > 0 && value.record.Digest == prepared[index-1].record.Digest {
			return ErrInvalidCompoundResult
		}
		switch value.disposition {
		case governance.DurableEvidenceStorageReserveNew:
			if value.assertion.HasPending {
				return ErrInvalidCompoundResult
			}
			if err := uow.ReserveDurableEvidence(ctx, value.record); err != nil {
				return err
			}
		case governance.DurableEvidenceStorageAssertExisting:
			if err := uow.AssertDurableEvidenceContent(ctx, value.record); err != nil {
				return err
			}
		default:
			return ErrInvalidCompoundResult
		}
	}
	assertions := make([]postgres.EvidenceAssertion, len(prepared))
	for index := range prepared {
		assertions[index] = prepared[index].assertion
	}
	return uow.AssertDurableEvidence(ctx, assertions)
}

// applyIAMEvidenceStorage materializes IAM-internal persistence evidence that
// is not part of the AuditEvent's public evidence set. In particular, a
// reconciliation's freshly authenticated failure record must exist before the
// terminal pending revision links it. Existing source rows are byte-asserted;
// callers never select insert-versus-assert from database presence.
func applyIAMEvidenceStorage(ctx context.Context, uow *postgres.CanonicalUOW,
	eventID string, persistence iam.IAMPendingPersistenceCapability) error {
	if uow == nil || eventID == "" || persistence.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	values := persistence.EvidenceStorageCapabilities()
	if len(values) == 0 {
		return ErrInvalidCompoundResult
	}
	type mapped struct {
		digest      [32]byte
		record      postgres.DurableEvidenceRecord
		disposition uint8
		hasLink     bool
	}
	prepared := make([]mapped, len(values))
	for index, value := range values {
		if value.VerifyDigest() != nil || value.AuditAssertionEventID() != eventID {
			return ErrInvalidCompoundResult
		}
		evidence := value.Evidence()
		if evidence.VerifyDigest() != nil {
			return ErrInvalidCompoundResult
		}
		record := evidence.Record()
		kind := postgres.DurableEvidenceKind(record.Kind)
		if kind < postgres.DurableEvidenceContentSHA256 || kind > postgres.DurableEvidenceSemanticReceipt {
			return ErrInvalidCompoundResult
		}
		pendingKey, revision, hasLink := value.PendingLink()
		if hasLink != (revision != 0) ||
			hasLink != (pendingKey != ([ccse.MessageIDSize]byte{})) {
			return ErrInvalidCompoundResult
		}
		prepared[index] = mapped{digest: record.DigestSHA256,
			record: postgres.DurableEvidenceRecord{Digest: record.DigestSHA256, Kind: kind,
				ContentType: record.ContentType, CanonicalContent: append([]byte(nil), record.CanonicalContent...),
				ExpectedAuditEventID: record.ExpectedAuditEventID},
			disposition: value.Disposition(), hasLink: hasLink}
	}
	sort.Slice(prepared, func(i, j int) bool {
		return bytes.Compare(prepared[i].digest[:], prepared[j].digest[:]) < 0
	})
	for index, value := range prepared {
		if index > 0 && value.digest == prepared[index-1].digest {
			return ErrInvalidCompoundResult
		}
		switch value.disposition {
		case iam.IAMEvidenceStorageReserveNew:
			if value.hasLink || value.record.ExpectedAuditEventID != eventID {
				return ErrInvalidCompoundResult
			}
			if err := uow.ReserveDurableEvidence(ctx, value.record); err != nil {
				return err
			}
		case iam.IAMEvidenceStorageAssertExisting:
			if !value.hasLink {
				return ErrInvalidCompoundResult
			}
			if err := uow.AssertDurableEvidenceContent(ctx, value.record); err != nil {
				return err
			}
		default:
			return ErrInvalidCompoundResult
		}
	}
	return nil
}

// assertIAMPendingSource converts the complete optimistic IAM predecessor
// into a storage-owned locked assertion. Reconciliation changes the pending
// kind and envelope, so the later UPDATE cannot by itself prove the original
// evidence set and commit window observed before the AuditEvent was signed.
func assertIAMPendingSource(ctx context.Context, uow *postgres.CanonicalUOW,
	persistence iam.IAMPendingPersistenceCapability) error {
	if uow == nil || persistence.VerifyDigest() != nil {
		return ErrInvalidCompoundResult
	}
	source := persistence.Source()
	if source.Kind == iam.DurablePendingOwnershipTransferAcceptance ||
		source.Codec != postgres.DurablePendingIAMCodec || source.CodecVersion != 1 ||
		source.Status != iam.IAMPendingStatusOpen || source.Revision == 0 ||
		source.TerminalOutcomeDigestSHA256 != ([32]byte{}) {
		return ErrInvalidCompoundResult
	}
	return assertIAMPendingStoredSource(ctx, uow, source)
}

func assertIAMPendingStoredSource(ctx context.Context, uow *postgres.CanonicalUOW,
	source iam.IAMPendingStoredRevision) error {
	if uow == nil || source.Kind == iam.DurablePendingOwnershipTransferAcceptance ||
		source.Codec != postgres.DurablePendingIAMCodec || source.CodecVersion != 1 ||
		source.Status != iam.IAMPendingStatusOpen || source.Revision == 0 ||
		source.TerminalOutcomeDigestSHA256 != ([32]byte{}) {
		return ErrInvalidCompoundResult
	}
	expected := postgres.DurablePendingRevision{
		PendingKey: source.PendingKey, Kind: postgres.DurablePendingKind(source.Kind),
		Codec: source.Codec, CodecVersion: source.CodecVersion, Revision: source.Revision,
		PreviousEnvelopeDigest:  source.PreviousEnvelopeDigestSHA256,
		EnvelopeDigest:          source.EnvelopeDigestSHA256,
		CanonicalEnvelope:       append([]byte(nil), source.CanonicalEnvelope...),
		EvidenceDigests:         append([][32]byte(nil), source.EvidenceDigestsSHA256...),
		Status:                  postgres.DurablePendingOpen,
		CommitNotBeforeUnixNano: source.CommitNotBeforeUnixNano,
		CommitNotAfterUnixNano:  source.CommitNotAfterUnixNano,
		ExpectedAuditEventID:    source.ExpectedAuditEventID,
	}
	return uow.AssertDurablePendingOpen(ctx, expected)
}

func mapIAMPendingRevision(value iam.IAMPendingRevision) (postgres.DurablePendingRevision, error) {
	if value.VerifyDigest() != nil {
		return postgres.DurablePendingRevision{}, ErrInvalidCompoundResult
	}
	record := value.Record()
	if record.Kind == iam.DurablePendingOwnershipTransferAcceptance ||
		record.Codec != postgres.DurablePendingIAMCodec || record.CodecVersion != 1 ||
		record.Status < iam.IAMPendingStatusOpen || record.Status > iam.IAMPendingStatusTerminal {
		return postgres.DurablePendingRevision{}, ErrInvalidCompoundResult
	}
	return postgres.DurablePendingRevision{
		PendingKey: record.PendingKey, ExpectedKind: postgres.DurablePendingKind(record.ExpectedKind),
		Kind: postgres.DurablePendingKind(record.Kind), Codec: record.Codec,
		CodecVersion: record.CodecVersion, Revision: record.Revision,
		PreviousEnvelopeDigest:          record.PreviousEnvelopeDigestSHA256,
		PreviousCanonicalEnvelope:       append([]byte(nil), record.PreviousCanonicalEnvelope...),
		PreviousCommitNotBeforeUnixNano: record.PreviousCommitNotBeforeUnixNano,
		PreviousCommitNotAfterUnixNano:  record.PreviousCommitNotAfterUnixNano,
		EnvelopeDigest:                  record.EnvelopeDigestSHA256,
		CanonicalEnvelope:               append([]byte(nil), record.CanonicalEnvelope...),
		EvidenceDigests:                 append([][32]byte(nil), record.EvidenceDigestsSHA256...),
		Status:                          postgres.DurablePendingStatus(record.Status),
		CommitNotBeforeUnixNano:         record.CommitNotBeforeUnixNano,
		CommitNotAfterUnixNano:          record.CommitNotAfterUnixNano,
		TerminalOutcomeDigest:           record.TerminalOutcomeDigestSHA256,
		ExpectedAuditEventID:            record.ExpectedAuditEventID,
	}, nil
}

func applyIAMPendingRevisions(ctx context.Context, uow *postgres.CanonicalUOW,
	values []iam.IAMPendingRevision) error {
	if uow == nil || len(values) == 0 || len(values) > 2 {
		return ErrInvalidCompoundResult
	}
	for _, value := range values {
		revision, err := mapIAMPendingRevision(value)
		if err != nil {
			return err
		}
		if err := uow.ApplyDurablePendingRevision(ctx, revision); err != nil {
			return err
		}
	}
	return nil
}

func mapGovernancePendingRevision(value governance.DurablePendingRevisionCapability) (
	postgres.DurablePendingRevision, error) {
	if value.VerifyDigest() != nil || value.Kind() != governance.DurablePendingGovernancePolicyApprovalCollection ||
		value.Codec() != postgres.DurablePendingGovernanceCodec ||
		value.CodecVersion() != governance.DurablePolicyApprovalCollectionCodecVersion {
		return postgres.DurablePendingRevision{}, ErrInvalidCompoundResult
	}
	previousNotBefore, previousNotAfter := value.PreviousCommitWindow()
	notBefore, notAfter := value.CommitWindow()
	outcome, terminal := value.TerminalOutcomeDigest()
	if terminal != (value.Status() == governance.DurablePendingTerminal) {
		return postgres.DurablePendingRevision{}, ErrInvalidCompoundResult
	}
	return postgres.DurablePendingRevision{
		PendingKey: value.PendingKey(), ExpectedKind: postgres.DurablePendingKind(value.ExpectedKind()),
		Kind: postgres.DurablePendingKind(value.Kind()), Codec: value.Codec(), CodecVersion: value.CodecVersion(),
		Revision: value.Revision(), PreviousEnvelopeDigest: value.PreviousEnvelopeDigest(),
		PreviousCanonicalEnvelope:       value.PreviousCanonicalEnvelope(),
		PreviousCommitNotBeforeUnixNano: previousNotBefore,
		PreviousCommitNotAfterUnixNano:  previousNotAfter,
		EnvelopeDigest:                  value.EnvelopeDigest(), CanonicalEnvelope: value.CanonicalEnvelope(),
		EvidenceDigests: value.EvidenceDigests(), Status: postgres.DurablePendingStatus(value.Status()),
		CommitNotBeforeUnixNano: notBefore, CommitNotAfterUnixNano: notAfter,
		TerminalOutcomeDigest: outcome, ExpectedAuditEventID: value.ExpectedAuditEventID(),
	}, nil
}

func applyGovernancePendingRevision(ctx context.Context, uow *postgres.CanonicalUOW,
	value governance.DurablePendingRevisionCapability) error {
	if uow == nil {
		return ErrInvalidCompoundResult
	}
	revision, err := mapGovernancePendingRevision(value)
	if err != nil {
		return err
	}
	return uow.ApplyDurablePendingRevision(ctx, revision)
}

// mapGovernanceCanonicalState copies a digest-verified semantic row into the
// closed PostgreSQL catalog. Every kind and content type is compared against
// both packages' literals; adding a semantic kind cannot silently widen the
// storage contract.
func mapGovernanceCanonicalState(value governance.CanonicalStateRecord) (postgres.CanonicalStateRecord, error) {
	var kind postgres.CanonicalStateKind
	switch value.Kind {
	case governance.CanonicalStateKindGovernancePolicyRegistry:
		if governance.CanonicalStateKindGovernancePolicyRegistry != string(postgres.CanonicalStateGovernancePolicyRegistry) ||
			governance.CanonicalStateContentTypeGovernancePolicyRegistry != postgres.CanonicalStateGovernancePolicyRegistryContentType ||
			value.ContentType != governance.CanonicalStateContentTypeGovernancePolicyRegistry {
			return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
		}
		kind = postgres.CanonicalStateGovernancePolicyRegistry
	case governance.CanonicalStateKindGovernanceProfileActivation:
		if governance.CanonicalStateKindGovernanceProfileActivation != string(postgres.CanonicalStateGovernanceProfileActivation) ||
			governance.CanonicalStateContentTypeGovernanceProfileActivation != postgres.CanonicalStateGovernanceProfileActivationContentType ||
			value.ContentType != governance.CanonicalStateContentTypeGovernanceProfileActivation {
			return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
		}
		kind = postgres.CanonicalStateGovernanceProfileActivation
	default:
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	if governance.CanonicalStateNamespaceGovernance != uint8(postgres.CanonicalStateGovernance) ||
		value.Namespace != governance.CanonicalStateNamespaceGovernance {
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	return postgres.CanonicalStateRecord{
		Namespace: postgres.CanonicalStateGovernance, Kind: kind, ObjectID: value.ObjectID,
		Version: value.Version, StateDigest: value.StateDigestSHA256, ContentType: value.ContentType,
		CanonicalState: append([]byte(nil), value.CanonicalState...), Terminal: value.Terminal,
		AuditEventID: value.AuditEventID, HasValidityWindow: value.HasValidityWindow,
		ValidFromUnixNano: value.ValidFromUnixNano, ValidUntilUnixNano: value.ValidUntilUnixNano,
	}, nil
}

func mapGovernanceIAMStateRecord(value governance.CanonicalStateRecord) (
	postgres.CanonicalStateRecord, error) {
	var kind postgres.CanonicalStateKind
	wantType := ""
	switch value.Kind {
	case governance.CanonicalStateKindIAMKeyMaterial:
		kind, wantType = postgres.CanonicalStateIAMKeyMaterial,
			governance.CanonicalStateContentTypeIAMKeyMaterial
	case governance.CanonicalStateKindIAMKeyLifecycle:
		kind, wantType = postgres.CanonicalStateIAMKeyLifecycle,
			governance.CanonicalStateContentTypeIAMKeyLifecycle
	case governance.CanonicalStateKindIAMIdentity:
		kind, wantType = postgres.CanonicalStateIAMIdentity,
			governance.CanonicalStateContentTypeIAMIdentity
	case governance.CanonicalStateKindIAMWriterLease:
		kind, wantType = postgres.CanonicalStateIAMWriterLease,
			governance.CanonicalStateContentTypeIAMWriterLease
	default:
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	if governance.CanonicalStateNamespaceIAM != uint8(postgres.CanonicalStateIAM) ||
		value.Namespace != governance.CanonicalStateNamespaceIAM || value.Kind != string(kind) ||
		wantType != canonicalStorageContentType(kind) || value.ContentType != wantType ||
		value.HasValidityWindow || value.ValidFromUnixNano != 0 || value.ValidUntilUnixNano != 0 {
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	return postgres.CanonicalStateRecord{
		Namespace: postgres.CanonicalStateIAM, Kind: kind, ObjectID: value.ObjectID,
		Version: value.Version, StateDigest: value.StateDigestSHA256, ContentType: value.ContentType,
		CanonicalState: append([]byte(nil), value.CanonicalState...), Terminal: value.Terminal,
		AuditEventID: value.AuditEventID,
	}, nil
}

func mapIAMCanonicalState(value iam.CanonicalStateRecord) (postgres.CanonicalStateRecord, error) {
	var kind postgres.CanonicalStateKind
	wantType := ""
	switch value.Kind {
	case iam.CanonicalStateKindIAMKeyMaterial:
		kind, wantType = postgres.CanonicalStateIAMKeyMaterial, iam.CanonicalStateContentTypeIAMKeyMaterial
	case iam.CanonicalStateKindIAMIdentity:
		kind, wantType = postgres.CanonicalStateIAMIdentity, iam.CanonicalStateContentTypeIAMIdentity
	case iam.CanonicalStateKindIAMKeyLifecycle:
		kind, wantType = postgres.CanonicalStateIAMKeyLifecycle, iam.CanonicalStateContentTypeIAMKeyLifecycle
	case iam.CanonicalStateKindIAMAcceptedOwnershipTransfer:
		kind, wantType = postgres.CanonicalStateIAMAcceptedOwnershipTransfer, iam.CanonicalStateContentTypeIAMAcceptedOwnershipTransfer
	case iam.CanonicalStateKindIAMProofChallenge:
		kind, wantType = postgres.CanonicalStateIAMProofChallenge, iam.CanonicalStateContentTypeIAMProofChallenge
	case iam.CanonicalStateKindIAMPrincipalIdentityIndex:
		kind, wantType = postgres.CanonicalStateIAMPrincipalIdentityIndex, iam.CanonicalStateContentTypeIAMPrincipalIdentityIndex
	case iam.CanonicalStateKindIAMRotationPredecessorIndex:
		kind, wantType = postgres.CanonicalStateIAMRotationPredecessorIndex, iam.CanonicalStateContentTypeIAMRotationPredecessorIndex
	case iam.CanonicalStateKindIAMSubjectKeySet:
		kind, wantType = postgres.CanonicalStateIAMSubjectKeySet, iam.CanonicalStateContentTypeIAMSubjectKeySet
	case iam.CanonicalStateKindIAMWriterLease:
		kind, wantType = postgres.CanonicalStateIAMWriterLease, iam.CanonicalStateContentTypeIAMWriterLease
	case iam.CanonicalStateKindIAMTransferProfileActivation:
		kind, wantType = postgres.CanonicalStateIAMTransferProfileActivation, iam.CanonicalStateContentTypeIAMTransferProfileActivation
	default:
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	storageType := canonicalStorageContentType(kind)
	if iam.CanonicalStateNamespaceIAM != uint8(postgres.CanonicalStateIAM) ||
		value.Namespace != iam.CanonicalStateNamespaceIAM || value.Kind != string(kind) ||
		wantType != storageType || value.ContentType != wantType {
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	return postgres.CanonicalStateRecord{
		Namespace: postgres.CanonicalStateIAM, Kind: kind, ObjectID: value.ObjectID,
		Version: value.Version, StateDigest: value.StateDigestSHA256, ContentType: value.ContentType,
		CanonicalState: append([]byte(nil), value.CanonicalState...), Terminal: value.Terminal,
		AuditEventID: value.AuditEventID, HasValidityWindow: value.HasValidityWindow,
		ValidFromUnixNano: value.ValidFromUnixNano, ValidUntilUnixNano: value.ValidUntilUnixNano,
	}, nil
}

func canonicalStorageContentType(kind postgres.CanonicalStateKind) string {
	switch kind {
	case postgres.CanonicalStateIAMKeyMaterial:
		return postgres.CanonicalStateIAMKeyMaterialContentType
	case postgres.CanonicalStateIAMIdentity:
		return postgres.CanonicalStateIAMIdentityContentType
	case postgres.CanonicalStateIAMKeyLifecycle:
		return postgres.CanonicalStateIAMKeyLifecycleContentType
	case postgres.CanonicalStateIAMAcceptedOwnershipTransfer:
		return postgres.CanonicalStateIAMAcceptedOwnershipTransferContentType
	case postgres.CanonicalStateIAMProofChallenge:
		return postgres.CanonicalStateIAMProofChallengeContentType
	case postgres.CanonicalStateIAMPrincipalIdentityIndex:
		return postgres.CanonicalStateIAMPrincipalIdentityIndexContentType
	case postgres.CanonicalStateIAMRotationPredecessorIndex:
		return postgres.CanonicalStateIAMRotationPredecessorIndexContentType
	case postgres.CanonicalStateIAMSubjectKeySet:
		return postgres.CanonicalStateIAMSubjectKeySetContentType
	case postgres.CanonicalStateIAMWriterLease:
		return postgres.CanonicalStateIAMWriterLeaseContentType
	case postgres.CanonicalStateIAMTransferProfileActivation:
		return postgres.CanonicalStateIAMTransferProfileActivationContentType
	case postgres.CanonicalStateGovernancePolicyRegistry:
		return postgres.CanonicalStateGovernancePolicyRegistryContentType
	case postgres.CanonicalStateGovernanceProfileActivation:
		return postgres.CanonicalStateGovernanceProfileActivationContentType
	default:
		return ""
	}
}

func mapGovernanceStateAssertion(value governance.CanonicalStateAssertion) (postgres.CanonicalStateRecord, error) {
	if value.VerifyDigest() != nil {
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	return mapGovernanceCanonicalState(value.Record())
}

func mapIAMStateAssertion(value iam.CanonicalStateAssertion) (postgres.CanonicalStateRecord, error) {
	if value.VerifyDigest() != nil {
		return postgres.CanonicalStateRecord{}, ErrInvalidCompoundResult
	}
	return mapIAMCanonicalState(value.Record())
}

func mapGovernanceStateMutation(value governance.CanonicalStateMutation) (postgres.CanonicalStateMutation, error) {
	if value.VerifyDigest() != nil {
		return postgres.CanonicalStateMutation{}, ErrInvalidCompoundResult
	}
	next, err := mapGovernanceCanonicalState(value.Next())
	if err != nil {
		return postgres.CanonicalStateMutation{}, err
	}
	result := postgres.CanonicalStateMutation{Next: next}
	if expected, present := value.Expected(); present {
		mapped, mapErr := mapGovernanceCanonicalState(expected)
		if mapErr != nil {
			return postgres.CanonicalStateMutation{}, mapErr
		}
		result.Expected = &mapped
	}
	return result, nil
}

func mapIAMStateMutation(value iam.CanonicalStateMutation) (postgres.CanonicalStateMutation, error) {
	if value.VerifyDigest() != nil {
		return postgres.CanonicalStateMutation{}, ErrInvalidCompoundResult
	}
	next, err := mapIAMCanonicalState(value.Next())
	if err != nil {
		return postgres.CanonicalStateMutation{}, err
	}
	result := postgres.CanonicalStateMutation{Next: next}
	if expected, present := value.Expected(); present {
		mapped, mapErr := mapIAMCanonicalState(expected)
		if mapErr != nil {
			return postgres.CanonicalStateMutation{}, mapErr
		}
		result.Expected = &mapped
	}
	return result, nil
}

func mapCanonicalAuditAppend(value governance.CanonicalAuditAppendCapability) (postgres.AuditEventRecord, error) {
	if value.VerifyDigest() != nil {
		return postgres.AuditEventRecord{}, ErrInvalidCompoundResult
	}
	previous, hasPrevious := value.PreviousEventDigest()
	return postgres.AuditEventRecord{
		EventID: value.EventID(), StreamID: value.StreamID(), Sequence: value.Sequence(),
		PreviousEventDigest: previous, HasPrevious: hasPrevious, EventDigest: value.EventDigest(),
		RecordDigest: value.RecordDigest(), CanonicalEvent: value.CanonicalEvent(),
		OccurredAtUnixNano: value.OccurredAtUnixNano(),
		Head: postgres.AuditHeadCAS{
			DeploymentAnchorDigest:              value.DeploymentAnchorDigest(),
			ExpectedHeadWriterIdentity:          value.ExpectedHeadWriterIdentity(),
			AuthorizedWriterIdentity:            value.AuthorizedWriterIdentity(),
			ExpectedHeadHomeRegion:              value.ExpectedHeadHomeRegion(),
			AuthorizedHomeRegion:                value.AuthorizedHomeRegion(),
			ExpectedHeadWriterEpoch:             value.ExpectedHeadWriterEpoch(),
			AuthorizedWriterEpoch:               value.AuthorizedWriterEpoch(),
			ExpectedHeadGovernanceProfileDigest: value.ExpectedHeadGovernanceProfileDigest(),
			AuthorizedGovernanceProfileDigest:   value.AuthorizedGovernanceProfileDigest(),
			WriterLeaseEvidenceDigest:           value.WriterLeaseEvidenceDigest(),
			WriterLeaseNotBeforeUnixNano:        value.WriterLeaseNotBeforeUnixNano(),
			WriterLeaseNotAfterUnixNano:         value.WriterLeaseNotAfterUnixNano(),
		},
	}, nil
}
