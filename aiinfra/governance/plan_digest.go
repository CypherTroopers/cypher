// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sort"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/globalid"
	"github.com/cypherium/cypher/aiinfra/idempotency"
)

const (
	mutationPlanDigestDomain           = "CPH-AIIE-GOVERNANCE-MUTATION-PLAN-V1\x00"
	auditIntentDigestDomain            = "CPH-AIIE-GOVERNANCE-AUDIT-INTENT-V1\x00"
	pendingPlanDigestDomain            = "CPH-AIIE-GOVERNANCE-PENDING-POLICY-PLAN-V1\x00"
	approvalCollectionPlanDigestDomain = "CPH-AIIE-GOVERNANCE-APPROVAL-COLLECTION-PLAN-V1\x00"
	authorizationSnapshotDigestDomain  = "CPH-AIIE-GOVERNANCE-AUTHORIZATION-SNAPSHOT-V1\x00"
)

func digestGovernanceAuthorizationSnapshot(snapshot GovernanceKeySnapshot) [ccse.DigestSize]byte {
	allowed := append([]uint32(nil), snapshot.AllowedMessageTypeIDs...)
	roles := append([]string(nil), snapshot.Roles...)
	sort.Slice(allowed, func(i, j int) bool { return allowed[i] < allowed[j] })
	sort.Strings(roles)
	w := newDigestWriter(authorizationSnapshotDigestDomain)
	w.string(snapshot.KeyID)
	w.string(snapshot.SubjectIdentity)
	w.uint64(uint64(snapshot.TargetIdentityKind))
	w.uint64(uint64(snapshot.TargetPrincipalKind))
	w.string(snapshot.TargetIdentityID)
	w.string(snapshot.OrganizationIdentity)
	w.uint64(uint64(snapshot.Algorithm))
	w.bytes(snapshot.PublicKey)
	w.uint64(uint64(snapshot.LifecycleState))
	w.int64(snapshot.NotBeforeUnixNano)
	w.int64(snapshot.NotAfterUnixNano)
	w.int64(snapshot.RevokedAtUnixNano)
	w.uint64(uint64(len(allowed)))
	for _, messageTypeID := range allowed {
		w.uint64(uint64(messageTypeID))
	}
	w.strings(roles)
	w.digest(snapshot.AuthorizationPolicyDigestSHA256)
	w.uint64(snapshot.StateVersion)
	w.uint64(snapshot.WriterEpoch)
	w.digest(snapshot.SnapshotDigestSHA256)
	w.uint64(snapshot.IdentityStateVersion)
	w.uint64(snapshot.IdentityWriterEpoch)
	w.digest(snapshot.IdentitySnapshotDigestSHA256)
	w.string(snapshot.EnrollmentDomainID)
	w.string(snapshot.EnrollmentEnvironment)
	w.digest(snapshot.EnrollmentGenesisHash)
	result, _ := w.sum()
	return result
}

type digestWriter struct {
	h   hash.Hash
	err error
}

func newDigestWriter(domain string) *digestWriter {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	return &digestWriter{h: h}
}

func (w *digestWriter) uint8(value uint8) {
	if w.err == nil {
		_, w.err = w.h.Write([]byte{value})
	}
}

func (w *digestWriter) bool(value bool) {
	if value {
		w.uint8(1)
		return
	}
	w.uint8(0)
}

func (w *digestWriter) uint64(value uint64) {
	if w.err != nil {
		return
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, w.err = w.h.Write(encoded[:])
}

func (w *digestWriter) int64(value int64) { w.uint64(uint64(value)) }

func (w *digestWriter) bytes(value []byte) {
	w.uint64(uint64(len(value)))
	if w.err == nil {
		_, w.err = w.h.Write(value)
	}
}

func (w *digestWriter) string(value string) { w.bytes([]byte(value)) }

func (w *digestWriter) digest(value [ccse.DigestSize]byte) { w.bytes(value[:]) }

func (w *digestWriter) strings(values []string) {
	w.uint64(uint64(len(values)))
	for _, value := range values {
		w.string(value)
	}
}

func (w *digestWriter) digests(values [][ccse.DigestSize]byte) {
	w.uint64(uint64(len(values)))
	for _, value := range values {
		w.digest(value)
	}
}

func (w *digestWriter) evidence(evidence SignedEvidence) {
	present := evidence.record.MessageTypeID != 0
	w.bool(present)
	if !present || w.err != nil {
		return
	}
	digest, err := evidence.record.Digest(ccse.DefaultLimits())
	if err != nil || digest != evidence.recordDigest {
		w.err = fmt.Errorf("%w: retained evidence digest", ErrInvalidSignedRecord)
		return
	}
	preimage, err := evidence.record.Preimage(ccse.DefaultLimits())
	if err != nil {
		w.err = err
		return
	}
	w.digest(evidence.recordDigest)
	w.bytes(preimage)
	w.bytes(evidence.record.Signature)
}

func (w *digestWriter) durableEvidence(evidence DurableEvidence) {
	w.uint8(uint8(evidence.kind))
	w.digest(evidence.digest)
	switch evidence.kind {
	case EvidenceContentSHA256:
		if len(evidence.content) == 0 || sha256.Sum256(evidence.content) != evidence.digest || evidence.signed.record.MessageTypeID != 0 ||
			len(evidence.authorizationPolicyDigests) != 0 || evidence.keyPreconditionPresent ||
			evidence.keyPrecondition != (KeyStatePrecondition{}) || evidence.authorizationNotAfter != 0 {
			w.err = ErrAuditEvidence
			return
		}
		w.bytes(evidence.content)
	case EvidenceSignedCCSERecord:
		if len(evidence.content) != 0 || evidence.signed.recordDigest != evidence.digest ||
			len(evidence.authorizationPolicyDigests) == 0 || hasDuplicateDigests(evidence.authorizationPolicyDigests) {
			w.err = ErrAuditEvidence
			return
		}
		for index, digest := range evidence.authorizationPolicyDigests {
			if isZeroDigest(digest) || (index > 0 && bytes.Compare(evidence.authorizationPolicyDigests[index-1][:], digest[:]) >= 0) {
				w.err = ErrAuditEvidence
				return
			}
		}
		w.evidence(evidence.signed)
		w.digests(evidence.authorizationPolicyDigests)
		w.bool(evidence.keyPreconditionPresent)
		if evidence.keyPreconditionPresent {
			if !validKeyStatePrecondition(evidence.keyPrecondition) ||
				evidence.keyPrecondition.KeyID != evidence.signed.record.Domain.SignatureKeyID ||
				evidence.keyPrecondition.KeyID != evidence.signed.record.Envelope.SignatureKeyID ||
				evidence.authorizationNotAfter < evidence.signed.record.Domain.ExpiresAtUnixNano {
				w.err = ErrAuditEvidence
				return
			}
			w.keyPrecondition(evidence.keyPrecondition)
			w.int64(evidence.authorizationNotAfter)
		} else if evidence.keyPrecondition != (KeyStatePrecondition{}) || evidence.authorizationNotAfter != 0 {
			w.err = ErrAuditEvidence
			return
		}
	default:
		w.err = ErrAuditEvidence
	}
}

func (w *digestWriter) keyPrecondition(value KeyStatePrecondition) {
	w.string(value.KeyID)
	w.uint64(value.StateVersion)
	w.uint64(value.WriterEpoch)
	w.digest(value.SnapshotDigestSHA256)
	w.uint64(value.IdentityStateVersion)
	w.uint64(value.IdentityWriterEpoch)
	w.digest(value.IdentitySnapshotDigestSHA256)
	w.digest(value.AuthorizationSnapshotDigestSHA256)
}

func (w *digestWriter) idempotencyBinding(value idempotency.Binding) {
	w.bytes(value.Key[:])
	w.string(string(value.Domain))
	w.string(value.OwnerID)
	w.digest(value.RequestDigest)
}

func (w *digestWriter) idempotencySnapshot(value idempotency.Snapshot) {
	w.idempotencyBinding(value.Binding)
	w.uint8(uint8(value.State))
	w.uint64(value.Version)
	w.digest(value.ProgressDigest)
	w.digest(value.OutcomeDigest)
}

func (w *digestWriter) profileActivation(value GovernanceProfileActivationSnapshot) {
	w.digest(value.GovernanceProfileDigestSHA256)
	w.uint64(value.Version)
	w.int64(value.ValidFromUnixNano)
	w.int64(value.ValidUntilUnixNano)
	w.digest(value.EvidenceDigestSHA256)
}

func (w *digestWriter) idempotencyClaims(values []idempotency.Claim) {
	w.bool(len(values) != 0)
	if len(values) == 0 || w.err != nil {
		return
	}
	encoded, err := idempotency.CanonicalBytes(values)
	if err != nil {
		w.err = fmt.Errorf("%w: idempotency claims: %v", ErrInvalidCommand, err)
		return
	}
	w.bytes(encoded)
}

func (w *digestWriter) sum() ([ccse.DigestSize]byte, error) {
	if w.err != nil {
		return [ccse.DigestSize]byte{}, w.err
	}
	var result [ccse.DigestSize]byte
	copy(result[:], w.h.Sum(nil))
	return result, nil
}

func digestMutationPlan(value MutationPlanSnapshot) ([ccse.DigestSize]byte, error) {
	if !validGovernanceProfileActivation(value.GovernanceProfileActivation, value.EvaluatedAtUnixNano) ||
		value.GovernanceProfileActivation.GovernanceProfileDigestSHA256 != value.GovernanceProfileDigestSHA256 ||
		value.CommitNotBeforeUnixNano < value.GovernanceProfileActivation.ValidFromUnixNano ||
		value.CommitNotAfterUnixNano > value.GovernanceProfileActivation.ValidUntilUnixNano ||
		value.CommitNotBeforeUnixNano > value.EvaluatedAtUnixNano ||
		value.CommitNotAfterUnixNano <= value.EvaluatedAtUnixNano {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	w := newDigestWriter(mutationPlanDigestDomain)
	w.bool(value.CommitReady)
	w.int64(value.EvaluatedAtUnixNano)
	w.int64(value.CommitNotBeforeUnixNano)
	w.int64(value.CommitNotAfterUnixNano)
	w.digest(value.GovernanceProfileDigestSHA256)
	w.profileActivation(value.GovernanceProfileActivation)
	w.uint8(uint8(value.Kind))
	w.string(value.PolicyBundleID)
	w.string(value.PolicyRecordID)
	w.string(value.PolicyKind)
	w.uint64(value.PolicySequence)
	w.digest(value.PolicyBundleDigestSHA256)
	w.digest(value.PolicyDocumentDigestSHA256)
	w.bytes(value.PolicyDocumentEvidence)
	w.idempotencySnapshot(value.PolicyIdempotencySnapshot)
	w.idempotencySnapshot(value.JoinedAuditIdempotencySnapshot)
	w.bool(value.ExpectedPolicyHeadPresent)
	w.uint64(value.ExpectedPolicyHeadSequence)
	w.digest(value.ExpectedPolicyHeadDigest)
	w.string(value.ExpectedPolicyHeadHomeRegion)
	w.string(value.AuthorizedPolicyHomeRegion)
	w.uint64(value.ExpectedPolicyHeadWriterEpoch)
	w.uint64(value.AuthorizedPolicyWriterEpoch)
	w.digest(value.ExpectedPolicyWriterLeaseEvidenceDigestSHA256)
	w.int64(value.ExpectedPolicyWriterLeaseNotBeforeUnixNano)
	w.int64(value.ExpectedPolicyWriterLeaseNotAfterUnixNano)
	w.bool(value.RollbackTargetPresent)
	w.digest(value.RollbackTargetDigestSHA256)
	w.int64(value.ApprovedAtUnixNano)
	w.int64(value.EffectiveAtUnixNano)
	w.int64(value.ExpiresAtUnixNano)
	w.bool(value.Emergency)
	w.int64(value.BreakGlassExpiresAtUnixNano)
	w.strings(value.BreakGlassScopes)
	w.digests(value.ApprovalRecordDigestsSHA256)
	w.digests(value.AuditSourceDigestsSHA256)
	w.uint64(uint64(len(value.AuditSourceEvidence)))
	for _, evidence := range value.AuditSourceEvidence {
		w.durableEvidence(evidence)
	}
	w.uint64(uint64(len(value.AuditSourceKeyPreconditions)))
	for _, key := range value.AuditSourceKeyPreconditions {
		w.keyPrecondition(key)
	}
	w.uint64(uint64(len(value.ApprovalEvidence)))
	for _, evidence := range value.ApprovalEvidence {
		w.evidence(evidence)
	}
	if value.Kind >= MutationPolicyPublish && value.Kind <= MutationPolicyAbort &&
		(len(value.ApprovalAdmissionEvidence) == 0 || len(value.ApprovalAdmissionEvidence) != len(value.ApprovalEvidence)) {
		return [ccse.DigestSize]byte{}, ErrApprovalCollection
	}
	w.uint64(uint64(len(value.ApprovalAdmissionEvidence)))
	var priorAdmissionDigest [ccse.DigestSize]byte
	var admissionActivation GovernanceProfileActivationSnapshot
	for admissionIndex, admission := range value.ApprovalAdmissionEvidence {
		if admissionIndex > 0 && bytes.Compare(priorAdmissionDigest[:], admission.RecordDigestSHA256[:]) >= 0 {
			return [ccse.DigestSize]byte{}, ErrApprovalCollection
		}
		priorAdmissionDigest = admission.RecordDigestSHA256
		var retained *SignedEvidence
		for index := range value.ApprovalEvidence {
			if value.ApprovalEvidence[index].recordDigest == admission.RecordDigestSHA256 {
				copyEvidence := value.ApprovalEvidence[index]
				retained = &copyEvidence
				break
			}
		}
		if retained == nil {
			return [ccse.DigestSize]byte{}, ErrApprovalCollection
		}
		approval := policyApproval{
			record:       signedRecordSnapshot{record: cloneCCSERecord(&retained.record), digest: retained.recordDigest},
			admissionKey: cloneKeySnapshot(admission.AdmissionKey), admissionProfileDigest: admission.GovernanceProfileDigestSHA256,
			admissionActivation: admission.GovernanceProfileActivation, admissionValidatedAt: admission.ValidatedAtUnixNano,
			admissionFingerprint: admission.AdmissionFingerprintSHA256,
		}
		var fingerprint [ccse.DigestSize]byte
		var err error
		if admission.GovernanceProfileActivation == (GovernanceProfileActivationSnapshot{}) {
			if value.Kind != MutationPolicyAbort {
				return [ccse.DigestSize]byte{}, ErrApprovalCollection
			}
			approval.legacyAdmission = true
			fingerprint, err = legacyPolicyApprovalAdmissionFingerprint(approval)
		} else {
			if admissionActivation == (GovernanceProfileActivationSnapshot{}) {
				admissionActivation = admission.GovernanceProfileActivation
			} else if admission.GovernanceProfileActivation != admissionActivation {
				return [ccse.DigestSize]byte{}, ErrApprovalCollection
			}
			if value.Kind != MutationPolicyAbort && admission.GovernanceProfileActivation != value.GovernanceProfileActivation {
				return [ccse.DigestSize]byte{}, ErrApprovalCollection
			}
			fingerprint, err = policyApprovalAdmissionFingerprint(approval)
		}
		if err != nil || fingerprint != admission.AdmissionFingerprintSHA256 {
			return [ccse.DigestSize]byte{}, ErrApprovalCollection
		}
		w.digest(admission.RecordDigestSHA256)
		w.digest(digestGovernanceAuthorizationSnapshot(admission.AdmissionKey))
		w.digest(admission.GovernanceProfileDigestSHA256)
		w.profileActivation(admission.GovernanceProfileActivation)
		w.int64(admission.ValidatedAtUnixNano)
		w.digest(admission.AdmissionFingerprintSHA256)
	}
	w.uint64(uint64(len(value.ApprovalKeyPreconditions)))
	for _, key := range value.ApprovalKeyPreconditions {
		w.keyPrecondition(key)
	}
	w.bool(value.ExpectedPolicyBundleIDAbsent)
	w.digest(value.PolicyBundleOwnerDigestSHA256)
	w.bool(value.ExpectedPolicyRecordIDAbsent)
	w.string(value.AuditStreamID)
	w.string(value.AuditEventID)
	w.string(value.AuditRecordID)
	w.bool(value.ExpectedAuditEventAbsent)
	w.digest(value.DeploymentAnchorSHA256)
	w.uint64(value.ExpectedAuditSequence)
	w.digest(value.ExpectedAuditHeadDigest)
	w.string(value.ExpectedAuditHeadHomeRegion)
	w.string(value.AuthorizedAuditHomeRegion)
	w.string(value.ExpectedAuditHeadWriterIdentity)
	w.string(value.AuthorizedAuditWriterIdentity)
	w.uint64(value.ExpectedAuditHeadWriterEpoch)
	w.uint64(value.AuthorizedAuditWriterEpoch)
	w.digest(value.ExpectedAuditHeadGovernanceProfileDigestSHA256)
	w.digest(value.AuthorizedAuditGovernanceProfileDigestSHA256)
	w.digest(value.ExpectedAuditWriterLeaseEvidenceDigestSHA256)
	w.int64(value.ExpectedAuditWriterLeaseNotBeforeUnixNano)
	w.int64(value.ExpectedAuditWriterLeaseNotAfterUnixNano)
	w.uint64(value.NextAuditSequence)
	w.digest(value.NextAuditRecordDigestSHA256)
	w.evidence(value.AuditEventEvidence)
	w.keyPrecondition(value.AuditWriterKeyPrecondition)
	claimBytes, err := globalid.CanonicalBytes(value.IdentifierClaims)
	if err != nil {
		return [ccse.DigestSize]byte{}, fmt.Errorf("%w: global identifier claims: %v", ErrInvalidCommand, err)
	}
	w.bytes(claimBytes)
	w.idempotencyClaims(value.IdempotencyClaims)
	w.uint64(uint64(value.IdempotencyOutcome))
	return w.sum()
}

func digestApprovalCollectionPlan(value ApprovalCollectionPlanSnapshot) ([ccse.DigestSize]byte, error) {
	if !value.CommitReady || value.Binding.Validate() != nil ||
		value.GovernanceProfileDigestSHA256 == ([ccse.DigestSize]byte{}) ||
		!validGovernanceProfileActivation(value.GovernanceProfileActivation, value.EvaluatedAtUnixNano) ||
		value.GovernanceProfileActivation.GovernanceProfileDigestSHA256 != value.GovernanceProfileDigestSHA256 ||
		value.CommitNotBeforeUnixNano < value.GovernanceProfileActivation.ValidFromUnixNano ||
		value.CommitNotAfterUnixNano > value.GovernanceProfileActivation.ValidUntilUnixNano ||
		value.CommitNotBeforeUnixNano > value.EvaluatedAtUnixNano ||
		value.CommitNotAfterUnixNano <= value.EvaluatedAtUnixNano ||
		value.CommitNotAfterUnixNano <= value.CommitNotBeforeUnixNano ||
		value.NextProgressDigestSHA256 == ([ccse.DigestSize]byte{}) ||
		len(value.NextCollectionRecordDigestsSHA256) == 0 ||
		hasDuplicateDigests(value.ExpectedCollectionRecordDigestsSHA256) || hasDuplicateDigests(value.NextCollectionRecordDigestsSHA256) {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	claims, err := idempotency.NormalizeClaims(value.Claims)
	if err != nil || len(claims) != len(value.Claims) {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	var collectionClaim *idempotency.Claim
	for index := range claims {
		if claims[index].Binding == value.Binding {
			copyClaim := claims[index]
			collectionClaim = &copyClaim
		}
	}
	if collectionClaim == nil || collectionClaim.NextProgressDigest != value.NextProgressDigestSHA256 {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	joinedBinding, err := idempotency.JoinedAuditBinding(value.Binding)
	if err != nil {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	if value.JoinedAuditIdempotencySnapshot == (idempotency.Snapshot{}) {
		if len(claims) != 2 || collectionClaim.Mode != idempotency.ReserveCollection {
			return [ccse.DigestSize]byte{}, ErrInvalidCommand
		}
		foundJoined := false
		for _, claim := range claims {
			if claim.Binding == joinedBinding && claim.Mode == idempotency.ReserveCollection && claim.NextProgressDigest == joinedBinding.RequestDigest {
				foundJoined = true
			}
		}
		if !foundJoined {
			return [ccse.DigestSize]byte{}, ErrInvalidCommand
		}
	} else if len(claims) != 1 || collectionClaim.Mode != idempotency.AdvanceCollection ||
		!validJoinedAuditReservation(value.JoinedAuditIdempotencySnapshot, joinedBinding) {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	if value.NextEvidence.record.MessageTypeID == 0 || !containsDigest(value.NextCollectionRecordDigestsSHA256, value.NextEvidence.recordDigest) {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	admission := policyApproval{
		record:                 signedRecordSnapshot{record: cloneCCSERecord(&value.NextEvidence.record), digest: value.NextEvidence.recordDigest},
		admissionKey:           cloneKeySnapshot(value.NextAdmissionKey),
		admissionProfileDigest: value.NextAdmissionProfileDigestSHA256,
		admissionActivation:    value.NextAdmissionProfileActivation,
		admissionValidatedAt:   value.NextAdmissionValidatedAtUnixNano,
		admissionFingerprint:   value.NextAdmissionFingerprintSHA256,
	}
	fingerprint, err := policyApprovalAdmissionFingerprint(admission)
	if err != nil || fingerprint != value.NextAdmissionFingerprintSHA256 ||
		value.NextAdmissionProfileDigestSHA256 != value.GovernanceProfileDigestSHA256 ||
		value.NextAdmissionProfileActivation != value.GovernanceProfileActivation ||
		value.NextKeyPrecondition != keyPrecondition(value.NextAdmissionKey) {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	switch value.Disposition {
	case ApprovalCollectionAppend:
		if value.ExpectedReplacedRecordDigestSHA256 != ([ccse.DigestSize]byte{}) ||
			len(value.NextCollectionRecordDigestsSHA256) != len(value.ExpectedCollectionRecordDigestsSHA256)+1 {
			return [ccse.DigestSize]byte{}, ErrInvalidCommand
		}
	case ApprovalCollectionReplace:
		if value.ExpectedReplacedRecordDigestSHA256 == ([ccse.DigestSize]byte{}) ||
			!containsDigest(value.ExpectedCollectionRecordDigestsSHA256, value.ExpectedReplacedRecordDigestSHA256) ||
			len(value.NextCollectionRecordDigestsSHA256) != len(value.ExpectedCollectionRecordDigestsSHA256) {
			return [ccse.DigestSize]byte{}, ErrInvalidCommand
		}
	default:
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	claimBytes, err := idempotency.CanonicalBytes(claims)
	if err != nil {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	identifierBytes, err := globalid.CanonicalBytes(value.IdentifierClaims)
	if err != nil || value.JoinedAuditEventID == "" {
		return [ccse.DigestSize]byte{}, ErrInvalidCommand
	}
	w := newDigestWriter(approvalCollectionPlanDigestDomain)
	w.bool(value.CommitReady)
	w.int64(value.EvaluatedAtUnixNano)
	w.int64(value.CommitNotBeforeUnixNano)
	w.int64(value.CommitNotAfterUnixNano)
	w.digest(value.GovernanceProfileDigestSHA256)
	w.profileActivation(value.GovernanceProfileActivation)
	w.uint8(uint8(value.Disposition))
	w.idempotencyBinding(value.Binding)
	w.idempotencySnapshot(value.JoinedAuditIdempotencySnapshot)
	w.bytes(claimBytes)
	w.digests(value.ExpectedCollectionRecordDigestsSHA256)
	w.digest(value.ExpectedReplacedRecordDigestSHA256)
	w.digests(value.NextCollectionRecordDigestsSHA256)
	w.digest(value.PreviousProgressDigestSHA256)
	w.digest(value.NextProgressDigestSHA256)
	w.evidence(value.NextEvidence)
	w.keyPrecondition(value.NextKeyPrecondition)
	w.digest(digestGovernanceAuthorizationSnapshot(value.NextAdmissionKey))
	w.digest(value.NextAdmissionProfileDigestSHA256)
	w.profileActivation(value.NextAdmissionProfileActivation)
	w.int64(value.NextAdmissionValidatedAtUnixNano)
	w.digest(value.NextAdmissionFingerprintSHA256)
	w.string(value.JoinedAuditEventID)
	w.bytes(identifierBytes)
	return w.sum()
}

func digestPendingPolicyPlan(policy, audit [ccse.DigestSize]byte) [ccse.DigestSize]byte {
	preimage := make([]byte, 0, len(pendingPlanDigestDomain)+2*ccse.DigestSize)
	preimage = append(preimage, pendingPlanDigestDomain...)
	preimage = append(preimage, policy[:]...)
	preimage = append(preimage, audit[:]...)
	return sha256.Sum256(preimage)
}

func digestAuditIntent(value AuditIntentSnapshot) ([ccse.DigestSize]byte, error) {
	w := newDigestWriter(auditIntentDigestDomain)
	w.bool(value.Required)
	w.string(value.StreamID)
	w.string(value.EventType)
	w.string(value.AuditEventID)
	w.string(value.ActorIdentity)
	w.string(value.ActorKeyID)
	w.strings(value.SubjectIDs)
	w.string(value.CauseCode)
	w.int64(value.OccurredAtUnixNano)
	w.uint64(uint64(value.Outcome))
	w.bytes(value.IdempotencyKey[:])
	w.bytes(value.CorrelationID[:])
	w.bool(value.CausationID.Present)
	w.bytes(value.CausationID.Value[:])
	w.digest(value.WriterAuthorizationPolicyDigestSHA256)
	w.digests(value.AppliedPolicyDigestsSHA256)
	w.digests(value.EvidenceDigestsSHA256)
	w.bool(value.Emergency)
	w.int64(value.BreakGlassExpiresAtUnixNano)
	w.strings(value.BreakGlassScopes)
	return w.sum()
}

func newMutationPlan(value MutationPlanSnapshot) (MutationPlan, error) {
	value = cloneMutationPlanSnapshot(value)
	digest, err := digestMutationPlan(value)
	if err != nil {
		return MutationPlan{}, err
	}
	return MutationPlan{value: value, digest: digest}, nil
}

func newAuditIntent(value AuditIntentSnapshot) (AuditIntent, error) {
	value = cloneAuditIntentSnapshot(value)
	digest, err := digestAuditIntent(value)
	if err != nil {
		return AuditIntent{}, err
	}
	return AuditIntent{value: value, digest: digest}, nil
}

func newSignedEvidence(snapshot signedRecordSnapshot) SignedEvidence {
	return SignedEvidence{record: cloneCCSERecord(&snapshot.record), recordDigest: snapshot.digest}
}

func newContentEvidence(digest [ccse.DigestSize]byte, content []byte) DurableEvidence {
	return DurableEvidence{kind: EvidenceContentSHA256, digest: digest, content: append([]byte(nil), content...)}
}

func newSignedDurableEvidence(snapshot signedRecordSnapshot, authorizationPolicyDigests ...[ccse.DigestSize]byte) DurableEvidence {
	return DurableEvidence{
		kind: EvidenceSignedCCSERecord, digest: snapshot.digest, signed: newSignedEvidence(snapshot),
		authorizationPolicyDigests: uniqueSortedDigests(authorizationPolicyDigests),
	}
}

func newSignedDurableEvidenceWithKey(snapshot signedRecordSnapshot, key GovernanceKeySnapshot,
	authorizationPolicyDigests ...[ccse.DigestSize]byte) DurableEvidence {
	evidence := newSignedDurableEvidence(snapshot, authorizationPolicyDigests...)
	evidence.keyPreconditionPresent = true
	evidence.keyPrecondition = keyPrecondition(key)
	evidence.authorizationNotAfter = key.NotAfterUnixNano
	return evidence
}

func cloneSignedEvidence(evidence SignedEvidence) SignedEvidence {
	if evidence.record.MessageTypeID == 0 {
		return SignedEvidence{}
	}
	return SignedEvidence{record: cloneCCSERecord(&evidence.record), recordDigest: evidence.recordDigest}
}

func cloneDurableEvidence(evidence DurableEvidence) DurableEvidence {
	return DurableEvidence{
		kind: evidence.kind, digest: evidence.digest, content: append([]byte(nil), evidence.content...),
		signed:                     cloneSignedEvidence(evidence.signed),
		authorizationPolicyDigests: append([][ccse.DigestSize]byte(nil), evidence.authorizationPolicyDigests...),
		keyPreconditionPresent:     evidence.keyPreconditionPresent, keyPrecondition: evidence.keyPrecondition,
		authorizationNotAfter: evidence.authorizationNotAfter,
	}
}

func cloneMutationPlanSnapshot(value MutationPlanSnapshot) MutationPlanSnapshot {
	value.PolicyDocumentEvidence = append([]byte(nil), value.PolicyDocumentEvidence...)
	value.BreakGlassScopes = append([]string(nil), value.BreakGlassScopes...)
	value.ApprovalRecordDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.ApprovalRecordDigestsSHA256...)
	value.AuditSourceDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.AuditSourceDigestsSHA256...)
	value.AuditSourceEvidence = append([]DurableEvidence(nil), value.AuditSourceEvidence...)
	for index := range value.AuditSourceEvidence {
		value.AuditSourceEvidence[index] = cloneDurableEvidence(value.AuditSourceEvidence[index])
	}
	value.AuditSourceKeyPreconditions = append([]KeyStatePrecondition(nil), value.AuditSourceKeyPreconditions...)
	value.ApprovalEvidence = append([]SignedEvidence(nil), value.ApprovalEvidence...)
	for index := range value.ApprovalEvidence {
		value.ApprovalEvidence[index] = cloneSignedEvidence(value.ApprovalEvidence[index])
	}
	value.ApprovalAdmissionEvidence = append([]ApprovalAdmissionEvidence(nil), value.ApprovalAdmissionEvidence...)
	for index := range value.ApprovalAdmissionEvidence {
		value.ApprovalAdmissionEvidence[index].AdmissionKey = cloneKeySnapshot(value.ApprovalAdmissionEvidence[index].AdmissionKey)
	}
	value.ApprovalKeyPreconditions = append([]KeyStatePrecondition(nil), value.ApprovalKeyPreconditions...)
	value.IdentifierClaims = append([]globalid.Claim(nil), value.IdentifierClaims...)
	value.IdempotencyClaims = append([]idempotency.Claim(nil), value.IdempotencyClaims...)
	value.AuditEventEvidence = cloneSignedEvidence(value.AuditEventEvidence)
	return value
}

func cloneAuditIntentSnapshot(value AuditIntentSnapshot) AuditIntentSnapshot {
	value.SubjectIDs = append([]string(nil), value.SubjectIDs...)
	value.AppliedPolicyDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.AppliedPolicyDigestsSHA256...)
	value.EvidenceDigestsSHA256 = append([][ccse.DigestSize]byte(nil), value.EvidenceDigestsSHA256...)
	value.BreakGlassScopes = append([]string(nil), value.BreakGlassScopes...)
	return value
}
