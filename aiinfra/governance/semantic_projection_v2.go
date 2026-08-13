// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package governance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	foundationcanonical "github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const (
	PolicyRegistrySemanticProjectionCodecV2 = "cph.aiinfra.governance.policy-registry-projection.v2"
	ProfileSemanticProjectionCodecV2        = "cph.aiinfra.governance.profile-activation-projection.v2"
	governanceSemanticProjectionMax         = 64 << 20
)

// SemanticProjectionV2 is one immutable, storage-neutral companion bound to
// an exact Governance canonical-state history row.
type SemanticProjectionV2 struct {
	Kind              string
	ObjectID          string
	Version           uint64
	StateDigestSHA256 [sha256.Size]byte
	Codec             string
	Canonical         []byte
	DigestSHA256      [sha256.Size]byte
}

func (value SemanticProjectionV2) Bytes() []byte             { return bytes.Clone(value.Canonical) }
func (value SemanticProjectionV2) Digest() [sha256.Size]byte { return value.DigestSHA256 }

type policyApprovalProjectionV2Wire struct {
	Record               ccse.Record                         `json:"record"`
	Key                  GovernanceKeySnapshot               `json:"key"`
	Activation           GovernanceProfileActivationSnapshot `json:"activation"`
	ValidatedAtUnixNano  int64                               `json:"validated_at_unix_nano"`
	AdmissionFingerprint [sha256.Size]byte                   `json:"admission_fingerprint"`
}

type policyRegistryProjectionV2Wire struct {
	Version                      uint32                           `json:"version"`
	Record                       PolicyRecordSnapshot             `json:"record"`
	Approvals                    []policyApprovalProjectionV2Wire `json:"approvals"`
	AuthorizedHomeRegion         string                           `json:"authorized_home_region"`
	AuthorizedWriterEpoch        uint64                           `json:"authorized_writer_epoch"`
	GovernanceProfileDigest      [sha256.Size]byte                `json:"governance_profile_digest"`
	WriterLeaseEvidenceDigest    [sha256.Size]byte                `json:"writer_lease_evidence_digest"`
	WriterLeaseNotBeforeUnixNano int64                            `json:"writer_lease_not_before_unix_nano"`
	WriterLeaseNotAfterUnixNano  int64                            `json:"writer_lease_not_after_unix_nano"`
}

type profileProjectionV2Wire struct {
	Version    uint32                              `json:"version"`
	Profile    Profile                             `json:"profile"`
	Activation GovernanceProfileActivationSnapshot `json:"activation"`
}

type DecodedSemanticProjectionV2 struct {
	projection SemanticProjectionV2
	policy     *policyRegistryProjectionV2Wire
	profile    *Profile
	activation *GovernanceProfileActivationSnapshot
}

func (value DecodedSemanticProjectionV2) Projection() SemanticProjectionV2 {
	result := value.projection
	result.Canonical = bytes.Clone(result.Canonical)
	return result
}
func (value DecodedSemanticProjectionV2) PolicyRegistryRecord() (PolicyRecordSnapshot,
	PolicyRegistrySnapshot, bool) {
	if value.policy == nil {
		return PolicyRecordSnapshot{}, PolicyRegistrySnapshot{}, false
	}
	record := clonePolicyRegistrySnapshot(PolicyRegistrySnapshot{HeadPresent: true,
		Head: value.policy.Record, Records: []PolicyRecordSnapshot{value.policy.Record}}).Head
	metadata := PolicyRegistrySnapshot{AuthorizedHomeRegion: value.policy.AuthorizedHomeRegion,
		AuthorizedWriterEpoch:           value.policy.AuthorizedWriterEpoch,
		GovernanceProfileDigestSHA256:   value.policy.GovernanceProfileDigest,
		WriterLeaseEvidenceDigestSHA256: value.policy.WriterLeaseEvidenceDigest,
		WriterLeaseNotBeforeUnixNano:    value.policy.WriterLeaseNotBeforeUnixNano,
		WriterLeaseNotAfterUnixNano:     value.policy.WriterLeaseNotAfterUnixNano}
	return record, metadata, true
}
func (value DecodedSemanticProjectionV2) GovernanceProfile() (Profile,
	GovernanceProfileActivationSnapshot, bool) {
	if value.profile == nil || value.activation == nil {
		return Profile{}, GovernanceProfileActivationSnapshot{}, false
	}
	return cloneProfile(*value.profile), *value.activation, true
}

// BuildPolicyRegistrySemanticProjectionV2 retains every historical approval
// and IAM authorization preimage omitted by policy-registry.v1.
func BuildPolicyRegistrySemanticProjectionV2(plan MutationPlan,
	durableResultDigest [sha256.Size]byte) (SemanticProjectionV2, error) {
	if plan.VerifyDigest() != nil || durableResultDigest == ([sha256.Size]byte{}) {
		return SemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	view := plan.Snapshot()
	if view.Kind < MutationPolicyPublish || view.Kind > MutationPolicyExpire ||
		len(view.CanonicalStateMutations) != 1 || len(view.ApprovalEvidence) == 0 ||
		len(view.ApprovalEvidence) != len(view.ApprovalAdmissionEvidence) {
		return SemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	next := view.CanonicalStateMutations[0].Next()
	if next.Kind != CanonicalStateKindGovernancePolicyRegistry ||
		next.ObjectID != view.PolicyKind || next.Version != view.PolicySequence ||
		next.StateDigestSHA256 != view.PolicyBundleDigestSHA256 {
		return SemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return SemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	decoded, err := validator.Decode(schema.MessageTypePolicyBundle,
		ccse.Version{Major: 1}, next.CanonicalState)
	bundle, ok := decoded.(foundationv1.PolicyBundleSigningProjection)
	if err != nil || !ok || !bytes.Equal(next.CanonicalState, view.ApprovalEvidence[0].Record().Payload) {
		return SemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	record := PolicyRecordSnapshot{BundleDigestSHA256: view.PolicyBundleDigestSHA256,
		CanonicalPayload:              bytes.Clone(next.CanonicalState),
		GovernanceProfileDigestSHA256: view.GovernanceProfileDigestSHA256,
		RecordID:                      view.PolicyRecordID, HomeRegion: bundle.Metadata.HomeRegion,
		WriterEpoch: bundle.Metadata.WriterEpoch, StateVersion: bundle.Metadata.StateVersion,
		PolicyBundleID: view.PolicyBundleID, PolicyKind: view.PolicyKind,
		PolicyVersion: ccse.Version{Major: bundle.PolicyVersion.Major, Minor: bundle.PolicyVersion.Minor},
		Sequence:      view.PolicySequence, PredecessorPresent: bundle.PredecessorDigestSHA256.Present,
		PredecessorDigestSHA256:    bundle.PredecessorDigestSHA256.Value,
		RollbackTargetPresent:      view.RollbackTargetPresent,
		RollbackTargetDigestSHA256: view.RollbackTargetDigestSHA256,
		State:                      bundle.State, ApprovedAtUnixNano: view.ApprovedAtUnixNano,
		EffectiveAtUnixNano: view.EffectiveAtUnixNano, ExpiresAtUnixNano: view.ExpiresAtUnixNano,
		PolicyDocumentDigestSHA256: view.PolicyDocumentDigestSHA256,
		PolicyDocumentMediaType:    bundle.PolicyDocumentMediaType,
		ApproverIdentities:         append([]string(nil), bundle.ApproverIdentities...),
		ApproverKeyIDs:             append([]string(nil), bundle.ApproverKeyIDs...),
		MinimumApprovals:           bundle.MinimumApprovals, Emergency: view.Emergency,
		BreakGlassExpiresAtUnixNano: view.BreakGlassExpiresAtUnixNano,
		BreakGlassScopes:            append([]string(nil), view.BreakGlassScopes...),
		AcceptanceEvidence: PolicyAcceptanceEvidenceSnapshot{
			AcceptedAtUnixNano:              view.EvaluatedAtUnixNano,
			HomeRegion:                      view.AuthorizedPolicyHomeRegion,
			WriterEpoch:                     view.AuthorizedPolicyWriterEpoch,
			WriterLeaseEvidenceDigestSHA256: view.ExpectedPolicyWriterLeaseEvidenceDigestSHA256,
			WriterLeaseNotBeforeUnixNano:    view.ExpectedPolicyWriterLeaseNotBeforeUnixNano,
			WriterLeaseNotAfterUnixNano:     view.ExpectedPolicyWriterLeaseNotAfterUnixNano,
			GovernanceProfileDigestSHA256:   view.GovernanceProfileDigestSHA256,
			GovernanceProfileActivation:     view.GovernanceProfileActivation,
			MutationPlanDigestSHA256:        plan.Digest(), DurableResultDigestSHA256: durableResultDigest}}
	admissions := make(map[[sha256.Size]byte]ApprovalAdmissionEvidence,
		len(view.ApprovalAdmissionEvidence))
	for _, admission := range view.ApprovalAdmissionEvidence {
		if _, duplicate := admissions[admission.RecordDigestSHA256]; duplicate {
			return SemanticProjectionV2{}, ErrSnapshotInconsistent
		}
		admissions[admission.RecordDigestSHA256] = admission
	}
	approvals := make([]policyApprovalProjectionV2Wire, 0, len(view.ApprovalEvidence))
	for _, signed := range view.ApprovalEvidence {
		admission, found := admissions[signed.RecordDigest()]
		if !found {
			return SemanticProjectionV2{}, ErrSnapshotInconsistent
		}
		raw := signed.Record()
		approvals = append(approvals, policyApprovalProjectionV2Wire{Record: cloneCCSERecord(raw),
			Key: cloneKeySnapshot(admission.AdmissionKey), Activation: admission.GovernanceProfileActivation,
			ValidatedAtUnixNano:  admission.ValidatedAtUnixNano,
			AdmissionFingerprint: admission.AdmissionFingerprintSHA256})
	}
	wire := policyRegistryProjectionV2Wire{Version: 2, Record: record, Approvals: approvals,
		AuthorizedHomeRegion:         view.AuthorizedPolicyHomeRegion,
		AuthorizedWriterEpoch:        view.AuthorizedPolicyWriterEpoch,
		GovernanceProfileDigest:      view.GovernanceProfileDigestSHA256,
		WriterLeaseEvidenceDigest:    view.ExpectedPolicyWriterLeaseEvidenceDigestSHA256,
		WriterLeaseNotBeforeUnixNano: view.ExpectedPolicyWriterLeaseNotBeforeUnixNano,
		WriterLeaseNotAfterUnixNano:  view.ExpectedPolicyWriterLeaseNotAfterUnixNano}
	encoded, err := marshalGovernanceSemantic(wire)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	decodedProjection, err := DecodePolicyRegistrySemanticProjectionV2(next, encoded)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	return decodedProjection.projection, nil
}

func NewGovernanceProfileSemanticProjectionV2(record CanonicalStateRecord, profile Profile,
	activation GovernanceProfileActivationSnapshot) (SemanticProjectionV2, error) {
	profile = cloneProfile(profile)
	digest, err := ProfileDigest(profile)
	canonical, stateDigest, objectID, stateErr := canonicalProfileActivationState(activation)
	if err != nil || stateErr != nil || digest != activation.GovernanceProfileDigestSHA256 ||
		record.Kind != CanonicalStateKindGovernanceProfileActivation || record.ObjectID != objectID ||
		record.Version != activation.Version || record.StateDigestSHA256 != stateDigest ||
		!bytes.Equal(record.CanonicalState, canonical) || !record.HasValidityWindow ||
		record.ValidFromUnixNano != activation.ValidFromUnixNano ||
		record.ValidUntilUnixNano != activation.ValidUntilUnixNano {
		return SemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	encoded, err := marshalGovernanceSemantic(profileProjectionV2Wire{Version: 2,
		Profile: profile, Activation: activation})
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	decoded, err := DecodeGovernanceProfileSemanticProjectionV2(record, encoded)
	if err != nil {
		return SemanticProjectionV2{}, err
	}
	return decoded.projection, nil
}

// CanonicalGovernanceProfileActivationStateV1 exposes the frozen v1 row for
// the explicit audited bootstrap path. It reuses the same closed validator as
// planning and v2 decode; callers cannot supply an arbitrary object ID/digest.
func CanonicalGovernanceProfileActivationStateV1(activation GovernanceProfileActivationSnapshot) (
	[]byte, [sha256.Size]byte, string, error) {
	return canonicalProfileActivationState(activation)
}

func marshalGovernanceSemantic(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > governanceSemanticProjectionMax {
		return nil, ErrSnapshotInconsistent
	}
	return encoded, nil
}

func strictGovernanceSemanticDecode(input []byte, output any) error {
	if len(input) == 0 || len(input) > governanceSemanticProjectionMax {
		return ErrSnapshotInconsistent
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrSnapshotInconsistent
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrSnapshotInconsistent
	}
	encoded, err := marshalGovernanceSemantic(output)
	if err != nil || !bytes.Equal(encoded, input) {
		return ErrSnapshotInconsistent
	}
	return nil
}

func DecodePolicyRegistrySemanticProjectionV2(record CanonicalStateRecord,
	input []byte) (DecodedSemanticProjectionV2, error) {
	var wire policyRegistryProjectionV2Wire
	if strictGovernanceSemanticDecode(input, &wire) != nil || wire.Version != 2 ||
		record.Kind != CanonicalStateKindGovernancePolicyRegistry || wire.Record.PolicyKind != record.ObjectID ||
		wire.Record.Sequence != record.Version || wire.Record.StateVersion != record.Version ||
		wire.Record.BundleDigestSHA256 != record.StateDigestSHA256 ||
		sha256.Sum256(wire.Record.CanonicalPayload) != record.StateDigestSHA256 ||
		!bytes.Equal(wire.Record.CanonicalPayload, record.CanonicalState) ||
		len(wire.Approvals) == 0 || len(wire.Approvals) > maxApprovals {
		return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	wire.Record.ApprovalEvidence = make([]HistoricalPolicyApprovalEvidence, 0, len(wire.Approvals))
	identities := make([]string, 0, len(wire.Approvals))
	keyIDs := make([]string, 0, len(wire.Approvals))
	recordDigests := make([][ccse.DigestSize]byte, 0, len(wire.Approvals))
	authorizationDigests := make([][ccse.DigestSize]byte, 0, len(wire.Approvals)+1)
	var correlation [ccse.MessageIDSize]byte
	var causation ccse.OptionalMessageID
	for _, approval := range wire.Approvals {
		signed, err := bindHistoricalSignedRecord(SignedRecord{Record: &approval.Record},
			maxPayloadBytesFor(schema.MessageTypePolicyBundle))
		candidate := policyApproval{record: signed, admissionKey: cloneKeySnapshot(approval.Key),
			admissionProfileDigest: approval.Activation.GovernanceProfileDigestSHA256,
			admissionActivation:    approval.Activation,
			admissionValidatedAt:   approval.ValidatedAtUnixNano,
			admissionFingerprint:   approval.AdmissionFingerprint}
		fingerprint, fingerprintErr := policyApprovalAdmissionFingerprint(candidate)
		if err != nil || approval.Record.MessageTypeID != schema.MessageTypePolicyBundle ||
			approval.Record.SchemaVersion != (ccse.Version{Major: 1, Minor: 0}) ||
			!bytes.Equal(approval.Record.Payload, wire.Record.CanonicalPayload) ||
			approval.Record.Envelope.PayloadDigest != wire.Record.BundleDigestSHA256 ||
			!preflightKeySnapshot(approval.Key) || fingerprintErr != nil ||
			fingerprint != approval.AdmissionFingerprint ||
			approval.Activation != wire.Record.AcceptanceEvidence.GovernanceProfileActivation ||
			approval.ValidatedAtUnixNano > wire.Record.AcceptanceEvidence.AcceptedAtUnixNano ||
			wire.Record.AcceptanceEvidence.AcceptedAtUnixNano < approval.Record.Domain.IssuedAtUnixNano ||
			wire.Record.AcceptanceEvidence.AcceptedAtUnixNano >= approval.Record.Domain.ExpiresAtUnixNano ||
			wire.Record.AcceptanceEvidence.AcceptedAtUnixNano < approval.Key.NotBeforeUnixNano ||
			wire.Record.AcceptanceEvidence.AcceptedAtUnixNano >= approval.Key.NotAfterUnixNano ||
			approval.Key.Algorithm != ccse.SignatureAlgorithmEd25519 ||
			len(approval.Key.PublicKey) != ed25519.PublicKeySize ||
			len(approval.Record.Signature) != ed25519.SignatureSize ||
			approval.Record.Domain.SignatureKeyID != approval.Key.KeyID ||
			!ed25519.Verify(ed25519.PublicKey(approval.Key.PublicKey), signed.digest[:],
				approval.Record.Signature) {
			return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
		}
		if len(recordDigests) == 0 {
			correlation, causation = approval.Record.Envelope.CorrelationID, approval.Record.Envelope.CausationID
		} else if correlation != approval.Record.Envelope.CorrelationID || causation != approval.Record.Envelope.CausationID {
			return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
		}
		identities = append(identities, approval.Record.Domain.SenderIdentity)
		keyIDs = append(keyIDs, approval.Record.Domain.SignatureKeyID)
		recordDigests = append(recordDigests, signed.digest)
		authorizationDigests = append(authorizationDigests, approval.Key.AuthorizationPolicyDigestSHA256)
		raw := cloneCCSERecord(&approval.Record)
		wire.Record.ApprovalEvidence = append(wire.Record.ApprovalEvidence,
			HistoricalPolicyApprovalEvidence{Signed: SignedRecord{Record: &raw},
				Key: cloneKeySnapshot(approval.Key), GovernanceProfileActivation: approval.Activation})
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	decoded, decodeErr := validator.Decode(schema.MessageTypePolicyBundle,
		ccse.Version{Major: 1}, wire.Record.CanonicalPayload)
	bundle, ok := decoded.(foundationv1.PolicyBundleSigningProjection)
	acceptance := wire.Record.AcceptanceEvidence
	authorizationDigests = uniqueSortedDigests(append(authorizationDigests,
		wire.Record.GovernanceProfileDigestSHA256))
	if decodeErr != nil || !ok || !policyRecordMatchesProjection(wire.Record, bundle) ||
		wire.AuthorizedHomeRegion == "" || wire.AuthorizedWriterEpoch == 0 ||
		wire.GovernanceProfileDigest == ([sha256.Size]byte{}) ||
		wire.WriterLeaseEvidenceDigest == ([sha256.Size]byte{}) ||
		wire.WriterLeaseNotBeforeUnixNano < 0 ||
		wire.WriterLeaseNotAfterUnixNano <= wire.WriterLeaseNotBeforeUnixNano ||
		wire.Record.GovernanceProfileDigestSHA256 != wire.GovernanceProfileDigest ||
		acceptance.GovernanceProfileDigestSHA256 != wire.GovernanceProfileDigest ||
		acceptance.HomeRegion != wire.AuthorizedHomeRegion ||
		acceptance.WriterEpoch != wire.AuthorizedWriterEpoch ||
		acceptance.WriterLeaseEvidenceDigestSHA256 != wire.WriterLeaseEvidenceDigest ||
		acceptance.WriterLeaseNotBeforeUnixNano != wire.WriterLeaseNotBeforeUnixNano ||
		acceptance.WriterLeaseNotAfterUnixNano != wire.WriterLeaseNotAfterUnixNano ||
		wire.Record.HomeRegion != acceptance.HomeRegion || wire.Record.WriterEpoch != acceptance.WriterEpoch ||
		!validGovernanceProfileActivation(acceptance.GovernanceProfileActivation,
			acceptance.AcceptedAtUnixNano) ||
		acceptance.GovernanceProfileActivation.GovernanceProfileDigestSHA256 != wire.GovernanceProfileDigest ||
		acceptance.AcceptedAtUnixNano < acceptance.WriterLeaseNotBeforeUnixNano ||
		acceptance.AcceptedAtUnixNano >= acceptance.WriterLeaseNotAfterUnixNano ||
		acceptance.AcceptedAtUnixNano < wire.Record.ApprovedAtUnixNano ||
		!validHistoricalAcceptanceTime(wire.Record, acceptance.AcceptedAtUnixNano) ||
		isZeroDigest(acceptance.MutationPlanDigestSHA256) ||
		isZeroDigest(acceptance.DurableResultDigestSHA256) ||
		wire.Record.RecordID == "" || wire.Record.RecordID == wire.Record.PolicyBundleID ||
		wire.Record.PolicyBundleID == "" || wire.Record.PolicyVersion.Major == 0 ||
		wire.Record.PolicyDocumentDigestSHA256 == ([sha256.Size]byte{}) ||
		wire.Record.PolicyDocumentMediaType == "" || wire.Record.ApprovedAtUnixNano < 0 ||
		wire.Record.EffectiveAtUnixNano < wire.Record.ApprovedAtUnixNano ||
		wire.Record.ExpiresAtUnixNano <= wire.Record.EffectiveAtUnixNano ||
		!validPolicyCreatedAtForState(wire.Record.State, bundle.Metadata.CreatedAtUnixNano,
			wire.Record.ApprovedAtUnixNano, wire.Record.EffectiveAtUnixNano,
			wire.Record.ExpiresAtUnixNano) ||
		len(wire.Record.ApproverIdentities) != len(wire.Approvals) ||
		len(wire.Record.ApproverKeyIDs) != len(wire.Approvals) ||
		wire.Record.MinimumApprovals == 0 || int(wire.Record.MinimumApprovals) > len(wire.Approvals) ||
		hasDuplicateStrings(identities) || hasDuplicateStrings(keyIDs) ||
		hasDuplicateDigests(recordDigests) ||
		!equalStringSets(identities, wire.Record.ApproverIdentities) ||
		!equalStringSets(keyIDs, wire.Record.ApproverKeyIDs) ||
		!equalDigestSets(bundle.Metadata.PolicyDigestsSHA256, authorizationDigests) ||
		wire.Record.State < PolicyStateApprovedDelayed || wire.Record.State > PolicyStateExpired ||
		wire.Record.Emergency != (len(wire.Record.BreakGlassScopes) != 0) ||
		hasDuplicateStrings(wire.Record.BreakGlassScopes) || containsEmpty(wire.Record.BreakGlassScopes) ||
		wire.Record.RollbackTargetPresent != (wire.Record.State == PolicyStateRolledBack) ||
		(!wire.Record.PredecessorPresent && !isZeroDigest(wire.Record.PredecessorDigestSHA256)) ||
		(!wire.Record.RollbackTargetPresent && !isZeroDigest(wire.Record.RollbackTargetDigestSHA256)) {
		return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	result := DecodedSemanticProjectionV2{policy: &wire}
	result.projection = SemanticProjectionV2{Kind: record.Kind, ObjectID: record.ObjectID,
		Version: record.Version, StateDigestSHA256: record.StateDigestSHA256,
		Codec: PolicyRegistrySemanticProjectionCodecV2, Canonical: bytes.Clone(input),
		DigestSHA256: sha256.Sum256(input)}
	return result, nil
}

func DecodeGovernanceProfileSemanticProjectionV2(record CanonicalStateRecord,
	input []byte) (DecodedSemanticProjectionV2, error) {
	var wire profileProjectionV2Wire
	if strictGovernanceSemanticDecode(input, &wire) != nil || wire.Version != 2 {
		return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	digest, err := ProfileDigest(wire.Profile)
	canonical, stateDigest, objectID, stateErr := canonicalProfileActivationState(wire.Activation)
	if err != nil || stateErr != nil || digest != wire.Activation.GovernanceProfileDigestSHA256 ||
		record.Kind != CanonicalStateKindGovernanceProfileActivation || record.ObjectID != objectID ||
		record.Version != wire.Activation.Version || record.StateDigestSHA256 != stateDigest ||
		!bytes.Equal(record.CanonicalState, canonical) || !record.HasValidityWindow ||
		record.ValidFromUnixNano != wire.Activation.ValidFromUnixNano ||
		record.ValidUntilUnixNano != wire.Activation.ValidUntilUnixNano {
		return DecodedSemanticProjectionV2{}, ErrSnapshotInconsistent
	}
	profile, activation := cloneProfile(wire.Profile), wire.Activation
	result := DecodedSemanticProjectionV2{profile: &profile, activation: &activation}
	result.projection = SemanticProjectionV2{Kind: record.Kind, ObjectID: record.ObjectID,
		Version: record.Version, StateDigestSHA256: record.StateDigestSHA256,
		Codec: ProfileSemanticProjectionCodecV2, Canonical: bytes.Clone(input),
		DigestSHA256: sha256.Sum256(input)}
	return result, nil
}

// ValidatePolicyRegistrySemanticProjectionV2ForProfile closes the contextual
// half of policy restoration. The structural decoder deliberately cannot
// infer a Governance profile from a digest; storage and read adapters must
// load the exact row-backed activation and call this verifier before treating
// a decoded policy projection as authoritative.
func ValidatePolicyRegistrySemanticProjectionV2ForProfile(value DecodedSemanticProjectionV2,
	profile Profile, activation GovernanceProfileActivationSnapshot) error {
	if value.policy == nil || value.profile != nil || value.activation != nil ||
		validateProfile(profile) != nil {
		return ErrSnapshotInconsistent
	}
	digest, err := digestGovernanceProfile(profile)
	record := value.policy.Record
	accepted := record.AcceptanceEvidence
	if err != nil || digest != record.GovernanceProfileDigestSHA256 ||
		activation != accepted.GovernanceProfileActivation ||
		activation.GovernanceProfileDigestSHA256 != digest ||
		!validGovernanceProfileActivation(activation, accepted.AcceptedAtUnixNano) ||
		len(record.ApprovalEvidence) == 0 || len(record.ApprovalEvidence) > maxApprovals ||
		len(record.ApprovalEvidence) != len(record.ApproverIdentities) ||
		uint32(len(record.ApprovalEvidence)) < record.MinimumApprovals ||
		record.MinimumApprovals < profile.MinimumApprovals ||
		(!record.Emergency && record.EffectiveAtUnixNano-record.ApprovedAtUnixNano <
			profile.MinActivationDelayNanos) ||
		(record.Emergency && (record.MinimumApprovals < profile.BreakGlassMinimumApprovals ||
			record.BreakGlassExpiresAtUnixNano-record.EffectiveAtUnixNano >
				profile.MaxBreakGlassDurationNanos)) ||
		record.Sequence > uint64(profile.MaxPolicyRecords) {
		return ErrSnapshotInconsistent
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return ErrSnapshotInconsistent
	}
	organizations := make([]string, 0, len(record.ApprovalEvidence))
	keys := make([]GovernanceKeySnapshot, 0, len(record.ApprovalEvidence))
	for _, retained := range record.ApprovalEvidence {
		if retained.Signed.Record == nil || retained.GovernanceProfileActivation != activation {
			return ErrSnapshotInconsistent
		}
		signed, bindErr := bindHistoricalSignedRecord(retained.Signed,
			maxPayloadBytesFor(schema.MessageTypePolicyBundle))
		if bindErr != nil {
			return ErrSnapshotInconsistent
		}
		raw := signed.record
		if raw.MessageTypeID != schema.MessageTypePolicyBundle || raw.SchemaVersion != profile.SchemaVersion ||
			raw.Domain.Purpose != policyPurpose || raw.Domain.ProtocolVersion != profile.ProtocolVersion ||
			raw.Envelope.ProtocolVersion != profile.ProtocolVersion ||
			!equalStringSets(raw.Domain.Audience, profile.Audience) ||
			raw.Domain.TenantOrganization != profile.TenantOrganization ||
			raw.Domain.ProviderOrganization != profile.ProviderOrganization ||
			raw.Domain.Environment != profile.Environment || raw.Envelope.Environment != profile.Environment ||
			raw.Domain.ChainID != profile.ChainID || raw.Envelope.ChainID != profile.ChainID ||
			raw.Domain.GenesisHash != profile.GenesisHash ||
			raw.Domain.ReplayDomainID != profile.PolicyReplayDomainID ||
			raw.Domain.CounterKind != ccse.CounterSequence || raw.Envelope.CounterKind != ccse.CounterSequence ||
			raw.Domain.IssuedAtUnixNano < 0 || raw.Domain.ExpiresAtUnixNano <= raw.Domain.IssuedAtUnixNano ||
			raw.Domain.ExpiresAtUnixNano-raw.Domain.IssuedAtUnixNano > profile.MaxRecordValidityNanos ||
			validator.ValidateExtensions(context.Background(), schema.MessageTypePolicyBundle,
				profile.SchemaVersion, raw.Envelope.Extensions) != nil ||
			sha256.Sum256(raw.Payload) != raw.Envelope.PayloadDigest {
			return ErrSnapshotInconsistent
		}
		key, keyErr := authorizeHistoricalPolicyKey(signed, retained.Key, profile)
		if keyErr != nil {
			return ErrSnapshotInconsistent
		}
		organizations = append(organizations, key.OrganizationIdentity)
		keys = append(keys, key)
	}
	if uint32(distinctStringCount(organizations)) < profile.MinimumDistinctApprovalOrganizations ||
		!rolesHaveDistinctAssignment(keys, profile.RequiredApprovalRoles) ||
		(record.Emergency && (uint32(distinctStringCount(organizations)) <
			profile.BreakGlassMinimumDistinctOrganizations ||
			!rolesHaveDistinctAssignment(keys, profile.BreakGlassRequiredRoles))) {
		return ErrSnapshotInconsistent
	}
	return nil
}
