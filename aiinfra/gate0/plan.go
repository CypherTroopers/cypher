// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package gate0

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	foundationcanonical "github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

// SignedFoundationPlan is the predeclared foundation ExperimentPlan that must
// be frozen before Gate 0 evidence collection starts.
type SignedFoundationPlan struct {
	Projection foundationv1.ExperimentPlanSigningProjection
	Record     *ccse.Record
}

type FoundationPlanPolicy struct {
	ExperimentPlanID string
	CapabilityID     string
	Component        string
	SoftwareVersion  string
	Purpose          string
	Audience         string
	Environment      string
	SignatureKeyID   string
	ApproverIdentity string
	SenderIdentity   string
	ChainID          [32]byte
	GenesisHash      [32]byte
	ReplayDomainID   string
}

// BuildSignedFoundationPlan signs the existing ExperimentPlan schema. Callers
// supply the full numeric plan; this helper adds no post-hoc thresholds.
func BuildSignedFoundationPlan(plan foundationv1.ExperimentPlanSigningProjection,
	domain ccse.Domain, envelope ccse.Envelope, privateKey ed25519.PrivateKey) (SignedFoundationPlan, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedFoundationPlan{}, fmt.Errorf("%w: ExperimentPlan signing key is required", ErrUntrustedEvidence)
	}
	if domain.Purpose != "evidence.experiment.plan.freeze" || domain.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 ||
		envelope.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 || domain.SignatureKeyID == "" ||
		domain.SignatureKeyID != envelope.SignatureKeyID || len(domain.Audience) == 0 {
		return SignedFoundationPlan{}, fmt.Errorf("%w: invalid ExperimentPlan CCSE boundary", ErrUntrustedEvidence)
	}
	if err := ValidateGate0ExperimentPlan(plan); err != nil {
		return SignedFoundationPlan{}, err
	}
	payload, err := plan.CanonicalBytes()
	if err != nil {
		return SignedFoundationPlan{}, fmt.Errorf("%w: foundation ExperimentPlan: %v", ErrInvalidEvidence, err)
	}
	record, err := ccse.NewRecord(schema.MessageTypeExperimentPlan, ccse.Version{Major: 1}, domain, envelope, payload)
	if err != nil {
		return SignedFoundationPlan{}, err
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = 262144
	if err := record.SignEd25519(privateKey, limits); err != nil {
		return SignedFoundationPlan{}, err
	}
	return SignedFoundationPlan{Projection: plan, Record: record}, nil
}

// ValidateGate0ExperimentPlan requires a predeclared exact boolean criterion
// for every closed Gate 0 check. Missing and post-hoc extra criteria fail.
func ValidateGate0ExperimentPlan(plan foundationv1.ExperimentPlanSigningProjection) error {
	if plan.TargetLevel != 3 || len(plan.Criteria) != len(requiredGate0Checks) || len(plan.ApprovingIdentities) == 0 {
		return fmt.Errorf("%w: incomplete Gate 0 ExperimentPlan", ErrInvalidEvidence)
	}
	want := make(map[string]struct{}, len(requiredGate0Checks))
	for _, check := range requiredGate0Checks {
		want["gate0."+check+".passed"] = struct{}{}
	}
	for _, criterion := range plan.Criteria {
		if _, ok := want[criterion.MetricID]; !ok || criterion.Comparison != 3 || criterion.ThresholdNumerator != 1 ||
			criterion.ThresholdDenominator != 1 || criterion.Unit != "boolean" || criterion.MinimumMetricSampleSize == 0 ||
			criterion.UpperThresholdNumerator.Present || criterion.UpperThresholdDenominator.Present || criterion.PercentileBasisPoints.Present {
			return fmt.Errorf("%w: invalid Gate 0 criterion %q", ErrInvalidEvidence, criterion.MetricID)
		}
		delete(want, criterion.MetricID)
	}
	if len(want) != 0 {
		return fmt.Errorf("%w: missing Gate 0 criterion", ErrInvalidEvidence)
	}
	for _, approver := range plan.ApprovingIdentities {
		if approver == "placeholder" {
			return fmt.Errorf("%w: placeholder plan approver", ErrInvalidEvidence)
		}
	}
	return nil
}

func VerifySignedFoundationPlan(plan SignedFoundationPlan, publicKey ed25519.PublicKey) error {
	if plan.Record == nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: foundation plan key or record absent", ErrUntrustedEvidence)
	}
	if plan.Record.MessageTypeID != schema.MessageTypeExperimentPlan || plan.Record.SchemaVersion != (ccse.Version{Major: 1}) {
		return fmt.Errorf("%w: foundation ExperimentPlan type or schema mismatch", ErrUntrustedEvidence)
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = 262144
	digest, err := plan.Record.Digest(limits)
	if err != nil || !ed25519.Verify(publicKey, digest[:], plan.Record.Signature) {
		return fmt.Errorf("%w: foundation plan signature invalid", ErrUntrustedEvidence)
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return err
	}
	decoded, err := validator.Decode(schema.MessageTypeExperimentPlan, ccse.Version{Major: 1}, plan.Record.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedEvidence, err)
	}
	want, err := plan.Projection.CanonicalBytes()
	if err != nil || !bytes.Equal(want, plan.Record.Payload) || decoded.MessageTypeID() != schema.MessageTypeExperimentPlan {
		return fmt.Errorf("%w: foundation plan projection mismatch", ErrUntrustedEvidence)
	}
	return nil
}

func VerifySignedFoundationPlanForPolicy(plan SignedFoundationPlan, publicKey ed25519.PublicKey, policy FoundationPlanPolicy) error {
	if err := VerifySignedFoundationPlan(plan, publicKey); err != nil {
		return err
	}
	if err := ValidateGate0ExperimentPlan(plan.Projection); err != nil {
		return err
	}
	projection := plan.Projection
	if projection.ExperimentPlanID != policy.ExperimentPlanID || projection.CapabilityID != policy.CapabilityID ||
		projection.Component != policy.Component || projection.SoftwareVersion != policy.SoftwareVersion ||
		len(projection.ApprovingIdentities) != 1 || projection.ApprovingIdentities[0] != policy.ApproverIdentity {
		return fmt.Errorf("%w: foundation ExperimentPlan policy mismatch", ErrUntrustedEvidence)
	}
	domain, envelope := plan.Record.Domain, plan.Record.Envelope
	if domain.Purpose != policy.Purpose || domain.Environment != policy.Environment || envelope.Environment != policy.Environment ||
		domain.SenderIdentity != policy.SenderIdentity || envelope.SenderIdentity != policy.SenderIdentity ||
		domain.ChainID != policy.ChainID || envelope.ChainID != policy.ChainID || domain.GenesisHash != policy.GenesisHash ||
		domain.ReplayDomainID != policy.ReplayDomainID ||
		domain.ProtocolVersion != (ccse.Version{Major: 1}) || domain.SchemaVersion != (ccse.Version{Major: 1}) ||
		envelope.ProtocolVersion != (ccse.Version{Major: 1}) || envelope.SchemaVersion != (ccse.Version{Major: 1}) ||
		domain.IssuedAtUnixNano != envelope.IssuedAtUnixNano || domain.ExpiresAtUnixNano != envelope.ExpiresAtUnixNano ||
		domain.CounterKind != ccse.CounterSequence || envelope.CounterKind != ccse.CounterSequence ||
		domain.Counter != envelope.Counter || domain.Counter == 0 ||
		domain.SignatureKeyID != policy.SignatureKeyID || envelope.SignatureKeyID != policy.SignatureKeyID ||
		domain.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 || envelope.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 ||
		len(domain.Audience) != 1 || domain.Audience[0] != policy.Audience {
		return fmt.Errorf("%w: foundation ExperimentPlan CCSE policy mismatch", ErrUntrustedEvidence)
	}
	return nil
}

// VerifySignedFoundationPlanForManifest proves that numerical criteria were
// frozen before collection and that the complete manifest observation window
// is inside the predeclared plan. It also binds the plan and manifest owner,
// scope, software, approver, and exact closed check set.
func VerifySignedFoundationPlanForManifest(plan SignedFoundationPlan, manifest ArtifactManifest,
	publicKey ed25519.PublicKey, policy FoundationPlanPolicy) error {
	if err := VerifySignedFoundationPlanForPolicy(plan, publicKey, policy); err != nil {
		return err
	}
	if err := validateRecord(manifest, true); err != nil {
		return err
	}
	projection := plan.Projection
	if projection.ExperimentPlanID != "gate0-release-plan-v1" || projection.CapabilityID != manifest.CapabilityID ||
		projection.Component != manifest.Component || projection.OwnerIdentity != manifest.CI.Repository ||
		projection.SoftwareVersion != manifest.SoftwareVersion || len(projection.HardwareScope) != 1 ||
		projection.HardwareScope[0] != manifest.Images[0].Platform || len(projection.WorkloadScope) != 1 ||
		projection.WorkloadScope[0] != "gate0-release" || len(projection.RegionScope) != 1 ||
		projection.RegionScope[0] != manifest.CI.RunnerEnvironment || len(projection.ApprovingIdentities) != 1 ||
		projection.ApprovingIdentities[0] != manifest.ApproverIdentity {
		return fmt.Errorf("%w: ExperimentPlan does not bind manifest", ErrUntrustedEvidence)
	}
	started, ended, err := evidenceCheckWindow(manifest.Checks)
	if err != nil {
		return err
	}
	manifestExpires, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: manifest expiry", ErrInvalidEvidence)
	}
	if projection.CollectionNotBeforeUnixNano > started.UnixNano() || projection.FrozenAtUnixNano > started.UnixNano() ||
		projection.ObservationWindowNanos > math.MaxInt64 ||
		projection.CollectionNotBeforeUnixNano > math.MaxInt64-int64(projection.ObservationWindowNanos) ||
		ended.UnixNano() > projection.CollectionNotBeforeUnixNano+int64(projection.ObservationWindowNanos) ||
		projection.ExpiresAtUnixNano < ended.UnixNano() || projection.ExpiresAtUnixNano < manifestExpires.UnixNano() ||
		projection.MinimumSampleSize > uint64(len(manifest.Checks)) {
		return fmt.Errorf("%w: manifest observation is outside frozen ExperimentPlan", ErrUntrustedEvidence)
	}
	return nil
}

func DecodeRetainedFoundationPlan(data []byte) (SignedFoundationPlan, error) {
	record, err := UnmarshalRetainedRecord(data)
	if err != nil {
		return SignedFoundationPlan{}, err
	}
	if record.MessageTypeID != schema.MessageTypeExperimentPlan || record.SchemaVersion != (ccse.Version{Major: 1}) {
		return SignedFoundationPlan{}, fmt.Errorf("%w: retained record is not foundation ExperimentPlan v1", ErrInvalidEvidence)
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return SignedFoundationPlan{}, err
	}
	decoded, err := validator.Decode(record.MessageTypeID, record.SchemaVersion, record.Payload)
	if err != nil {
		return SignedFoundationPlan{}, fmt.Errorf("%w: retained ExperimentPlan: %v", ErrInvalidEvidence, err)
	}
	projection, ok := decoded.(foundationv1.ExperimentPlanSigningProjection)
	if !ok {
		return SignedFoundationPlan{}, fmt.Errorf("%w: retained ExperimentPlan projection", ErrInvalidEvidence)
	}
	return SignedFoundationPlan{Projection: projection, Record: record}, nil
}
