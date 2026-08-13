// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// Package gate0 defines the offline-verifiable artifact manifest referenced by
// the canonical foundation.v1 EvidenceRecord used for the Workstream 0 supply-
// chain gate. This manifest is not a competing EvidenceRecord schema: its
// digest is one of EvidenceRecord.evidence_artifact_digests_sha256. The JSON
// representation is deliberately closed: unknown fields, duplicate fields,
// non-canonical ordering and unreferenced files are rejected.
package gate0

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/schema"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
	foundationcanonical "github.com/cypherium/cypher/aiinfra/schema/foundation/v1/canonical"
)

const (
	SchemaVersion        = "cph.aiinfra.gate0.artifact-manifest.v1"
	RetainedRecordSchema = "cph.aiinfra.gate0.retained-ccse-record.v1"
	DigestPrefix         = "sha256:"
	maxJSONBytes         = 4 << 20
)

var (
	ErrInvalidEvidence   = errors.New("aiinfra gate0: invalid release evidence")
	ErrUntrustedEvidence = errors.New("aiinfra gate0: untrusted release evidence")
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identityPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/@._+=,-]{0,511}$`)
)

var requiredGate0Checks = [...]string{
	"artifact-provenance",
	"artifact-signature",
	"backup-restore",
	"ccse-fail-closed",
	"cross-language-signatures",
	"pilot-plan-owner-coverage",
	"rollback-drill",
	"sbom-policy",
	"secret-scan",
	"telemetry-cardinality-redaction",
}

type Digest struct {
	SHA256 string `json:"sha256"`
}

type Artifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

type OCIImage struct {
	Reference              string `json:"reference"`
	IndexDigest            string `json:"index_digest"`
	Platform               string `json:"platform"`
	PlatformManifestDigest string `json:"platform_manifest_digest"`
}

type CIIdentity struct {
	Provider           string `json:"provider"`
	Repository         string `json:"repository"`
	WorkflowRef        string `json:"workflow_ref"`
	WorkflowSHA256     string `json:"workflow_sha256"`
	RunID              string `json:"run_id"`
	RunAttempt         string `json:"run_attempt"`
	SourceCommit       string `json:"source_commit"`
	SourceTreeSHA256   string `json:"source_tree_sha256"`
	RunnerEnvironment  string `json:"runner_environment"`
	ProvenanceBundle   string `json:"provenance_bundle"`
	ProvenanceSHA256   string `json:"provenance_sha256"`
	VerificationLog    string `json:"provenance_verification_log"`
	VerificationSHA256 string `json:"provenance_verification_sha256"`
}

type Check struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
	Log       string `json:"log"`
	LogSHA256 string `json:"log_sha256"`
}

type RollbackDrill struct {
	Status               string `json:"status"`
	PlanID               string `json:"plan_id"`
	StartedAt            string `json:"started_at"`
	EndedAt              string `json:"ended_at"`
	FromArtifactSHA256   string `json:"from_artifact_sha256,omitempty"`
	TargetArtifactSHA256 string `json:"target_artifact_sha256,omitempty"`
	Log                  string `json:"log"`
	LogSHA256            string `json:"log_sha256"`
}

type Signature struct {
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	Payload         string `json:"payload"`
	Detached        string `json:"detached"`
}

// ArtifactManifest is the closed, offline-verifiable artifact index that a
// CCSE-signed foundation EvidenceRecord commits to by SHA-256.
type ArtifactManifest struct {
	Schema           string        `json:"schema"`
	EvidenceID       string        `json:"evidence_id"`
	CapabilityID     string        `json:"capability_id"`
	Component        string        `json:"component"`
	SoftwareVersion  string        `json:"software_version"`
	CreatedAt        string        `json:"created_at"`
	ExpiresAt        string        `json:"expires_at"`
	ApprovingRole    string        `json:"approving_role"`
	ApproverIdentity string        `json:"approver_identity"`
	Status           string        `json:"status"`
	CI               CIIdentity    `json:"ci_identity"`
	Images           []OCIImage    `json:"images"`
	Artifacts        []Artifact    `json:"artifacts"`
	Checks           []Check       `json:"checks"`
	Rollback         RollbackDrill `json:"rollback_drill"`
	Signature        Signature     `json:"signature"`
}

type VerifyOptions struct {
	Now                        time.Time
	ExpectedSourceCommit       string
	ExpectedRepository         string
	ExpectedWorkflowRef        string
	ExpectedOCIIndexDigest     string
	ExpectedPlatformManifest   string
	ExpectedImages             []OCIImage
	ExpectedSBOMNamespace      string
	PublicKeyPath              string
	RequirePassed              bool
	RequireRollback            bool
	RejectUnreferencedRegulars bool
}

type FoundationEvidencePolicy struct {
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

// SignedFoundationEvidence contains the canonical EvidenceRecord payload and
// its complete CCSE record. Raw artifact-manifest signatures authenticate the
// bundle for offline release tooling; this independent foundation record is
// the normative evidence claim consumed by CPH IAM/Governance.
type SignedFoundationEvidence struct {
	Projection foundationv1.EvidenceRecordSigningProjection
	Record     *ccse.Record
}

// RetainedRecord is the closed canonical JSON representation stored in an
// evidence bundle. It preserves every signed CCSE field without depending on
// Protobuf transport bytes.
type RetainedRecord struct {
	Schema string      `json:"schema"`
	Record ccse.Record `json:"record"`
}

func MarshalRetainedRecord(record *ccse.Record) ([]byte, error) {
	if record == nil || len(record.Signature) == 0 {
		return nil, fmt.Errorf("%w: signed record absent", ErrInvalidEvidence)
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = 262144
	if _, err := record.Preimage(limits); err != nil {
		return nil, err
	}
	return json.Marshal(RetainedRecord{Schema: RetainedRecordSchema, Record: *record})
}

func UnmarshalRetainedRecord(data []byte) (*ccse.Record, error) {
	if len(data) == 0 || len(data) > maxJSONBytes {
		return nil, fmt.Errorf("%w: retained record size", ErrInvalidEvidence)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var retained RetainedRecord
	if err := decoder.Decode(&retained); err != nil {
		return nil, fmt.Errorf("%w: retained record decode: %v", ErrInvalidEvidence, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(retained)
	if err != nil || !bytes.Equal(canonical, data) || retained.Schema != RetainedRecordSchema {
		return nil, fmt.Errorf("%w: non-canonical retained record", ErrInvalidEvidence)
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = 262144
	if _, err := retained.Record.Preimage(limits); err != nil {
		return nil, fmt.Errorf("%w: retained CCSE preimage: %v", ErrInvalidEvidence, err)
	}
	return &retained.Record, nil
}

func DecodeRetainedFoundationEvidence(data []byte) (SignedFoundationEvidence, error) {
	record, err := UnmarshalRetainedRecord(data)
	if err != nil {
		return SignedFoundationEvidence{}, err
	}
	if record.MessageTypeID != schema.MessageTypeEvidenceRecord || record.SchemaVersion != (ccse.Version{Major: 1}) {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: retained record is not foundation EvidenceRecord v1", ErrInvalidEvidence)
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return SignedFoundationEvidence{}, err
	}
	decoded, err := validator.Decode(record.MessageTypeID, record.SchemaVersion, record.Payload)
	if err != nil {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: retained EvidenceRecord: %v", ErrInvalidEvidence, err)
	}
	projection, ok := decoded.(foundationv1.EvidenceRecordSigningProjection)
	if !ok {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: retained EvidenceRecord projection", ErrInvalidEvidence)
	}
	return SignedFoundationEvidence{Projection: projection, Record: record}, nil
}

// RequiredCheckIDs returns a copy of the closed Gate 0 check set.
func RequiredCheckIDs() []string {
	return append([]string(nil), requiredGate0Checks[:]...)
}

// SignArtifactManifest adds the detached-signature metadata and returns the
// canonical manifest plus its raw Ed25519 detached signature. The public key
// must be the key derived from privateKey; a caller cannot label one key while
// signing with another.
func SignArtifactManifest(manifest ArtifactManifest, keyID, detachedPath string,
	publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (ArtifactManifest, []byte, []byte, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		return ArtifactManifest{}, nil, nil, fmt.Errorf("%w: manifest Ed25519 key mismatch", ErrUntrustedEvidence)
	}
	if manifest.Signature != (Signature{}) {
		return ArtifactManifest{}, nil, nil, fmt.Errorf("%w: manifest already has signature metadata", ErrInvalidEvidence)
	}
	publicDigest := sha256.Sum256(publicKey)
	manifest.Signature = Signature{Algorithm: "Ed25519", KeyID: keyID,
		PublicKeySHA256: DigestPrefix + hex.EncodeToString(publicDigest[:]),
		Payload:         "artifact-manifest.json#without-signature", Detached: detachedPath}
	payload, err := CanonicalPayload(manifest)
	if err != nil {
		return ArtifactManifest{}, nil, nil, err
	}
	signature := ed25519.Sign(privateKey, payload)
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return ArtifactManifest{}, nil, nil, err
	}
	if _, err := Decode(canonical); err != nil {
		return ArtifactManifest{}, nil, nil, err
	}
	return manifest, canonical, signature, nil
}

// BuildSignedFoundationEvidence constructs and signs the existing canonical
// foundation EvidenceRecord. Both PASSED and FAILED observations are retained;
// a PASSED record is impossible unless the entire closed check set passed.
// The function fails closed when the key is absent or the exact artifact-
// manifest digest cannot be committed.
func BuildSignedFoundationEvidence(manifest ArtifactManifest, metadata foundationv1.RecordMetadataSigningProjection,
	domain ccse.Domain, envelope ccse.Envelope, privateKey ed25519.PrivateKey) (SignedFoundationEvidence, error) {
	return BuildSignedFoundationEvidenceForPlan(manifest, "gate0-release-plan-v1", metadata, domain, envelope, privateKey)
}

// BuildSignedFoundationEvidenceForPlan binds the evidence to an explicit
// frozen ExperimentPlan identifier.
func BuildSignedFoundationEvidenceForPlan(manifest ArtifactManifest, experimentPlanID string,
	metadata foundationv1.RecordMetadataSigningProjection, domain ccse.Domain, envelope ccse.Envelope,
	privateKey ed25519.PrivateKey) (SignedFoundationEvidence, error) {
	if err := validateRecord(manifest, true); err != nil {
		return SignedFoundationEvidence{}, err
	}
	if !validIdentifier(experimentPlanID) {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: ExperimentPlan ID", ErrInvalidEvidence)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: Ed25519 signing key is required", ErrUntrustedEvidence)
	}
	if domain.Purpose != "evidence.record.release" || domain.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 ||
		envelope.SignatureAlgorithm != ccse.SignatureAlgorithmEd25519 || domain.SignatureKeyID == "" ||
		domain.SignatureKeyID != envelope.SignatureKeyID || len(domain.Audience) == 0 {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: invalid EvidenceRecord CCSE boundary", ErrUntrustedEvidence)
	}
	payload, err := CanonicalPayload(manifest)
	if err != nil {
		return SignedFoundationEvidence{}, err
	}
	artifactDigest := sha256.Sum256(payload)
	expires, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	testStarted, testEnded, err := evidenceCheckWindow(manifest.Checks)
	if err != nil {
		return SignedFoundationEvidence{}, err
	}
	status, achievedLevel := uint32(3), uint32(1)
	if manifest.Status == "PASSED" {
		status, achievedLevel = 2, 3
	}
	projection := foundationv1.EvidenceRecordSigningProjection{
		Metadata: metadata, EvidenceID: manifest.EvidenceID, ExperimentPlanID: experimentPlanID,
		CapabilityID: manifest.CapabilityID, Component: manifest.Component, OwnerIdentity: manifest.CI.Repository,
		SoftwareVersion: manifest.SoftwareVersion, HardwareScope: []string{manifest.Images[0].Platform},
		WorkloadScope: []string{"gate0-release"}, RegionScope: []string{manifest.CI.RunnerEnvironment},
		TestStartedAtUnixNano: testStarted.UnixNano(), TestEndedAtUnixNano: testEnded.UnixNano(), SampleSize: uint64(len(manifest.Checks)),
		EvidenceArtifactDigestsSHA256: [][sha256.Size]byte{artifactDigest},
		Observations:                  gate0Observations(manifest.Checks),
		ApprovingRole:                 manifest.ApprovingRole, ApprovingIdentities: []string{manifest.ApproverIdentity},
		ApprovedAtUnixNano: testEnded.UnixNano(), ExpiresAtUnixNano: expires.UnixNano(),
		RevalidationTriggers: []string{"artifact-change", "dependency-change", "signing-key-rotation", "workflow-change"},
		AchievedLevel:        achievedLevel, Status: status,
	}
	canonicalPayload, err := projection.CanonicalBytes()
	if err != nil {
		return SignedFoundationEvidence{}, fmt.Errorf("%w: foundation EvidenceRecord: %v", ErrInvalidEvidence, err)
	}
	record, err := ccse.NewRecord(schema.MessageTypeEvidenceRecord, ccse.Version{Major: 1}, domain, envelope, canonicalPayload)
	if err != nil {
		return SignedFoundationEvidence{}, err
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = 262144
	if err := record.SignEd25519(privateKey, limits); err != nil {
		return SignedFoundationEvidence{}, err
	}
	return SignedFoundationEvidence{Projection: projection, Record: record}, nil
}

func gate0PassingObservations() []foundationv1.MetricObservationSigningProjection {
	checks := make([]Check, 0, len(requiredGate0Checks))
	for _, check := range requiredGate0Checks {
		checks = append(checks, Check{ID: check, Status: "PASSED"})
	}
	return gate0Observations(checks)
}

func gate0Observations(checks []Check) []foundationv1.MetricObservationSigningProjection {
	results := make(map[string]bool, len(checks))
	for _, check := range checks {
		results[check.ID] = check.Status == "PASSED"
	}
	observations := make([]foundationv1.MetricObservationSigningProjection, 0, len(requiredGate0Checks))
	for _, check := range requiredGate0Checks {
		value := int64(0)
		if results[check] {
			value = 1
		}
		observations = append(observations, foundationv1.MetricObservationSigningProjection{
			MetricID: "gate0." + check + ".passed", ObservedNumerator: value, ObservedDenominator: 1, SampleSize: 1,
			ConfidenceLowerNumerator: value, ConfidenceLowerDenominator: 1,
			ConfidenceUpperNumerator: value, ConfidenceUpperDenominator: 1, CriterionPassed: results[check],
		})
	}
	return observations
}

func evidenceCheckWindow(checks []Check) (time.Time, time.Time, error) {
	var start, end time.Time
	for _, check := range checks {
		checkStart, startErr := time.Parse(time.RFC3339Nano, check.StartedAt)
		checkEnd, endErr := time.Parse(time.RFC3339Nano, check.EndedAt)
		if startErr != nil || endErr != nil || !checkEnd.After(checkStart) {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: check window", ErrInvalidEvidence)
		}
		if start.IsZero() || checkStart.Before(start) {
			start = checkStart
		}
		if end.IsZero() || checkEnd.After(end) {
			end = checkEnd
		}
	}
	if start.IsZero() || !end.After(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: empty check window", ErrInvalidEvidence)
	}
	return start, end, nil
}

// VerifySignedFoundationEvidence checks both the Ed25519 signature and the
// independent canonical decoder before accepting a release claim.
func VerifySignedFoundationEvidence(evidence SignedFoundationEvidence, publicKey ed25519.PublicKey) error {
	if evidence.Record == nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: foundation evidence key or record absent", ErrUntrustedEvidence)
	}
	if evidence.Record.MessageTypeID != schema.MessageTypeEvidenceRecord || evidence.Record.SchemaVersion != (ccse.Version{Major: 1}) {
		return fmt.Errorf("%w: foundation EvidenceRecord type or schema mismatch", ErrUntrustedEvidence)
	}
	limits := ccse.DefaultLimits()
	limits.MaxPayloadBytes = 262144
	digest, err := evidence.Record.Digest(limits)
	if err != nil || !ed25519.Verify(publicKey, digest[:], evidence.Record.Signature) {
		return fmt.Errorf("%w: foundation signature invalid", ErrUntrustedEvidence)
	}
	validator, err := foundationcanonical.NewValidator()
	if err != nil {
		return err
	}
	decoded, err := validator.Decode(schema.MessageTypeEvidenceRecord, ccse.Version{Major: 1}, evidence.Record.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedEvidence, err)
	}
	want, err := evidence.Projection.CanonicalBytes()
	if err != nil || !bytes.Equal(want, evidence.Record.Payload) || decoded.MessageTypeID() != schema.MessageTypeEvidenceRecord {
		return fmt.Errorf("%w: foundation projection mismatch", ErrUntrustedEvidence)
	}
	return nil
}

// VerifySignedFoundationEvidenceForManifest binds cryptographic validity to
// the exact artifact manifest and the deployment's expected trust policy.
func VerifySignedFoundationEvidenceForManifest(manifest ArtifactManifest, evidence SignedFoundationEvidence,
	publicKey ed25519.PublicKey, policy FoundationEvidencePolicy) error {
	return verifySignedFoundationEvidenceForManifest(manifest, evidence, publicKey, policy, true)
}

// VerifySignedFoundationEvidenceCandidateForManifest verifies an explicitly
// FAILED candidate. It can be used to audit a signed incomplete run, but must
// never be used as Gate 0 acceptance.
func VerifySignedFoundationEvidenceCandidateForManifest(manifest ArtifactManifest, evidence SignedFoundationEvidence,
	publicKey ed25519.PublicKey, policy FoundationEvidencePolicy) error {
	return verifySignedFoundationEvidenceForManifest(manifest, evidence, publicKey, policy, false)
}

func verifySignedFoundationEvidenceForManifest(manifest ArtifactManifest, evidence SignedFoundationEvidence,
	publicKey ed25519.PublicKey, policy FoundationEvidencePolicy, requirePassed bool) error {
	if err := VerifySignedFoundationEvidence(evidence, publicKey); err != nil {
		return err
	}
	if err := validateRecord(manifest, true); err != nil {
		return err
	}
	if requirePassed && manifest.Status != "PASSED" {
		return fmt.Errorf("%w: a failed manifest cannot support a normative foundation EvidenceRecord", ErrUntrustedEvidence)
	}
	projection := evidence.Projection
	if projection.ExperimentPlanID != policy.ExperimentPlanID || projection.CapabilityID != policy.CapabilityID ||
		projection.Component != policy.Component || projection.SoftwareVersion != policy.SoftwareVersion ||
		projection.EvidenceID != manifest.EvidenceID || projection.CapabilityID != manifest.CapabilityID ||
		projection.Component != manifest.Component || projection.SoftwareVersion != manifest.SoftwareVersion ||
		projection.OwnerIdentity != manifest.CI.Repository || len(projection.HardwareScope) != 1 || projection.HardwareScope[0] != manifest.Images[0].Platform ||
		len(projection.WorkloadScope) != 1 || projection.WorkloadScope[0] != "gate0-release" ||
		len(projection.RegionScope) != 1 || projection.RegionScope[0] != manifest.CI.RunnerEnvironment ||
		projection.Status != evidenceStatus(manifest.Status) || projection.AchievedLevel != evidenceLevel(manifest.Status) || projection.ApprovingRole != manifest.ApprovingRole ||
		len(projection.ApprovingIdentities) != 1 || projection.ApprovingIdentities[0] != policy.ApproverIdentity ||
		projection.ApprovingIdentities[0] != manifest.ApproverIdentity {
		return fmt.Errorf("%w: foundation EvidenceRecord policy mismatch", ErrUntrustedEvidence)
	}
	payload, err := CanonicalPayload(manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if len(projection.EvidenceArtifactDigestsSHA256) != 1 || projection.EvidenceArtifactDigestsSHA256[0] != digest {
		return fmt.Errorf("%w: foundation EvidenceRecord does not commit exact manifest", ErrUntrustedEvidence)
	}
	start, end, err := evidenceCheckWindow(manifest.Checks)
	if err != nil || projection.TestStartedAtUnixNano != start.UnixNano() || projection.TestEndedAtUnixNano != end.UnixNano() ||
		projection.ApprovedAtUnixNano != end.UnixNano() || projection.SampleSize != uint64(len(manifest.Checks)) {
		return fmt.Errorf("%w: foundation EvidenceRecord observation window mismatch", ErrUntrustedEvidence)
	}
	expires, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if projection.ExpiresAtUnixNano != expires.UnixNano() || !validGate0Observations(projection.Observations, manifest.Checks) {
		return fmt.Errorf("%w: foundation EvidenceRecord result mismatch", ErrUntrustedEvidence)
	}
	domain, envelope := evidence.Record.Domain, evidence.Record.Envelope
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
		return fmt.Errorf("%w: foundation EvidenceRecord CCSE policy mismatch", ErrUntrustedEvidence)
	}
	return nil
}

func evidenceStatus(status string) uint32 {
	if status == "PASSED" {
		return 2
	}
	return 3
}

func evidenceLevel(status string) uint32 {
	if status == "PASSED" {
		return 3
	}
	return 1
}

func validGate0Observations(observations []foundationv1.MetricObservationSigningProjection, checks []Check) bool {
	if len(observations) != len(requiredGate0Checks) {
		return false
	}
	want := make(map[string]bool, len(requiredGate0Checks))
	for _, check := range checks {
		want["gate0."+check.ID+".passed"] = check.Status == "PASSED"
	}
	for _, observation := range observations {
		passed, ok := want[observation.MetricID]
		value := int64(0)
		if passed {
			value = 1
		}
		if !ok || observation.ObservedNumerator != value || observation.ObservedDenominator != 1 ||
			observation.SampleSize != 1 || observation.ConfidenceLowerNumerator != value || observation.ConfidenceLowerDenominator != 1 ||
			observation.ConfidenceUpperNumerator != value || observation.ConfidenceUpperDenominator != 1 || observation.CriterionPassed != passed {
			return false
		}
		delete(want, observation.MetricID)
	}
	return len(want) == 0
}

func Decode(data []byte) (ArtifactManifest, error) {
	if len(data) == 0 || len(data) > maxJSONBytes {
		return ArtifactManifest{}, fmt.Errorf("%w: evidence JSON size", ErrInvalidEvidence)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record ArtifactManifest
	if err := decoder.Decode(&record); err != nil {
		return ArtifactManifest{}, fmt.Errorf("%w: decode: %v", ErrInvalidEvidence, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ArtifactManifest{}, err
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(data, canonical) {
		return ArtifactManifest{}, fmt.Errorf("%w: artifact manifest is not canonical JSON", ErrInvalidEvidence)
	}
	return record, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidEvidence)
		}
		return fmt.Errorf("%w: trailing JSON: %v", ErrInvalidEvidence, err)
	}
	return nil
}

func CanonicalPayload(record ArtifactManifest) ([]byte, error) {
	copyRecord := record
	copyRecord.Signature = Signature{}
	if err := validateRecord(copyRecord, false); err != nil {
		return nil, err
	}
	return json.Marshal(copyRecord)
}

func VerifyDirectory(directory string, options VerifyOptions) (ArtifactManifest, error) {
	recordPath := filepath.Join(directory, "artifact-manifest.json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return ArtifactManifest{}, fmt.Errorf("%w: read artifact manifest: %v", ErrInvalidEvidence, err)
	}
	record, err := Decode(data)
	if err != nil {
		return ArtifactManifest{}, err
	}
	if err := validateRecord(record, true); err != nil {
		return ArtifactManifest{}, err
	}
	if options.RequirePassed && record.Status != "PASSED" {
		return ArtifactManifest{}, fmt.Errorf("%w: evidence status %q", ErrUntrustedEvidence, record.Status)
	}
	if options.RequireRollback && record.Rollback.Status != "PASSED" {
		return ArtifactManifest{}, fmt.Errorf("%w: rollback status %q", ErrUntrustedEvidence, record.Rollback.Status)
	}
	if options.ExpectedSourceCommit != "" && record.CI.SourceCommit != options.ExpectedSourceCommit {
		return ArtifactManifest{}, fmt.Errorf("%w: source commit mismatch", ErrUntrustedEvidence)
	}
	if options.ExpectedRepository != "" && record.CI.Repository != options.ExpectedRepository {
		return ArtifactManifest{}, fmt.Errorf("%w: repository mismatch", ErrUntrustedEvidence)
	}
	if options.ExpectedWorkflowRef != "" && record.CI.WorkflowRef != options.ExpectedWorkflowRef {
		return ArtifactManifest{}, fmt.Errorf("%w: workflow ref mismatch", ErrUntrustedEvidence)
	}
	if options.ExpectedOCIIndexDigest != "" || options.ExpectedPlatformManifest != "" {
		if !hasExpectedImage(record.Images, options.ExpectedOCIIndexDigest, options.ExpectedPlatformManifest) {
			return ArtifactManifest{}, fmt.Errorf("%w: expected OCI image identity absent", ErrUntrustedEvidence)
		}
	}
	if len(options.ExpectedImages) == 0 {
		return ArtifactManifest{}, fmt.Errorf("%w: exact OCI image policy is required", ErrUntrustedEvidence)
	}
	if !equalOCIImages(record.Images, options.ExpectedImages) {
		return ArtifactManifest{}, fmt.Errorf("%w: exact OCI image set mismatch", ErrUntrustedEvidence)
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expires, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return ArtifactManifest{}, fmt.Errorf("%w: evidence expired", ErrUntrustedEvidence)
	}
	if err := verifyReferencedFiles(directory, record, options.RejectUnreferencedRegulars); err != nil {
		return ArtifactManifest{}, err
	}
	if err := verifyManifestSBOMs(directory, record, options.ExpectedSBOMNamespace,
		options.RequirePassed || gate0CheckPassed(record.Checks, "sbom-policy")); err != nil {
		return ArtifactManifest{}, err
	}
	if options.PublicKeyPath == "" {
		return ArtifactManifest{}, fmt.Errorf("%w: public key path is required", ErrUntrustedEvidence)
	}
	if gate0CheckPassed(record.Checks, "artifact-signature") {
		if err := verifyReleaseArtifactSignature(directory, record, options.PublicKeyPath); err != nil {
			return ArtifactManifest{}, err
		}
	}
	if err := verifySignature(directory, record, options.PublicKeyPath); err != nil {
		return ArtifactManifest{}, err
	}
	return record, nil
}

func gate0CheckPassed(checks []Check, id string) bool {
	for _, check := range checks {
		if check.ID == id {
			return check.Status == "PASSED"
		}
	}
	return false
}

func validateRecord(record ArtifactManifest, requireSignature bool) error {
	if record.Schema != SchemaVersion || !validIdentifier(record.EvidenceID) ||
		!validIdentifier(record.CapabilityID) || !validIdentifier(record.Component) ||
		!validIdentifier(record.SoftwareVersion) || !validIdentifier(record.ApprovingRole) ||
		!validIdentifier(record.ApproverIdentity) {
		return fmt.Errorf("%w: required identity", ErrInvalidEvidence)
	}
	created, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil {
		return fmt.Errorf("%w: created_at", ErrInvalidEvidence)
	}
	expires, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	if err != nil || !expires.After(created) {
		return fmt.Errorf("%w: expires_at", ErrInvalidEvidence)
	}
	if record.Status != "PASSED" && record.Status != "FAILED" {
		return fmt.Errorf("%w: status", ErrInvalidEvidence)
	}
	if err := validateCI(record.CI); err != nil {
		return err
	}
	if len(record.Images) == 0 || len(record.Artifacts) == 0 || len(record.Checks) == 0 {
		return fmt.Errorf("%w: empty evidence collection", ErrInvalidEvidence)
	}
	if !sort.SliceIsSorted(record.Images, func(i, j int) bool { return record.Images[i].Reference < record.Images[j].Reference }) ||
		!sort.SliceIsSorted(record.Artifacts, func(i, j int) bool { return record.Artifacts[i].Name < record.Artifacts[j].Name }) ||
		!sort.SliceIsSorted(record.Checks, func(i, j int) bool { return record.Checks[i].ID < record.Checks[j].ID }) {
		return fmt.Errorf("%w: collections are not canonical sorted sets", ErrInvalidEvidence)
	}
	seen := make(map[string]struct{})
	for _, image := range record.Images {
		if !validIdentifier(image.Reference) || !validDigest(image.IndexDigest) ||
			!validIdentifier(image.Platform) || !validDigest(image.PlatformManifestDigest) {
			return fmt.Errorf("%w: OCI image identity", ErrInvalidEvidence)
		}
		if _, duplicate := seen[image.Reference]; duplicate {
			return fmt.Errorf("%w: duplicate OCI image", ErrInvalidEvidence)
		}
		seen[image.Reference] = struct{}{}
	}
	seen = make(map[string]struct{})
	artifactNames := make(map[string]struct{})
	paths := map[string]string{
		"artifact-manifest.json":   "manifest",
		record.Signature.Detached:  "signature",
		record.CI.ProvenanceBundle: "provenance",
		record.CI.VerificationLog:  "provenance verification",
	}
	if len(paths) != 4 {
		return fmt.Errorf("%w: reserved evidence paths collide", ErrInvalidEvidence)
	}
	hasSBOM, hasReleaseArtifact := false, false
	for _, artifact := range record.Artifacts {
		if !validIdentifier(artifact.Name) || !validPath(artifact.Path) ||
			!validIdentifier(artifact.MediaType) || !validDigest(artifact.SHA256) || artifact.Size < 0 {
			return fmt.Errorf("%w: artifact", ErrInvalidEvidence)
		}
		if _, duplicate := seen[artifact.Path]; duplicate {
			return fmt.Errorf("%w: duplicate artifact path", ErrInvalidEvidence)
		}
		seen[artifact.Path] = struct{}{}
		if _, duplicate := artifactNames[artifact.Name]; duplicate {
			return fmt.Errorf("%w: duplicate artifact name", ErrInvalidEvidence)
		}
		artifactNames[artifact.Name] = struct{}{}
		if prior, exists := paths[artifact.Path]; exists {
			return fmt.Errorf("%w: path %q reused by %s and artifact", ErrInvalidEvidence, artifact.Path, prior)
		}
		paths[artifact.Path] = "artifact"
		hasSBOM = hasSBOM || artifact.MediaType == "application/spdx+json"
		hasReleaseArtifact = hasReleaseArtifact || artifact.Name == "release-artifact"
	}
	if record.Status == "PASSED" && (!hasSBOM || !hasReleaseArtifact) {
		return fmt.Errorf("%w: passed evidence lacks SBOM or release artifact", ErrInvalidEvidence)
	}
	seen = make(map[string]struct{})
	if len(record.Checks) != len(requiredGate0Checks) {
		return fmt.Errorf("%w: Gate 0 check set is not closed", ErrInvalidEvidence)
	}
	allowedChecks := make(map[string]struct{}, len(requiredGate0Checks))
	for _, required := range requiredGate0Checks {
		allowedChecks[required] = struct{}{}
	}
	allChecksPassed := true
	for _, check := range record.Checks {
		if !validIdentifier(check.ID) || !validPath(check.Log) || !validDigest(check.LogSHA256) ||
			!validWindow(check.StartedAt, check.EndedAt) || (check.Status != "PASSED" && check.Status != "FAILED") {
			return fmt.Errorf("%w: check", ErrInvalidEvidence)
		}
		if _, duplicate := seen[check.ID]; duplicate {
			return fmt.Errorf("%w: duplicate check", ErrInvalidEvidence)
		}
		if _, allowed := allowedChecks[check.ID]; !allowed {
			return fmt.Errorf("%w: unknown Gate 0 check %q", ErrInvalidEvidence, check.ID)
		}
		seen[check.ID] = struct{}{}
		if prior, exists := paths[check.Log]; exists {
			return fmt.Errorf("%w: path %q reused by %s and check", ErrInvalidEvidence, check.Log, prior)
		}
		paths[check.Log] = "check"
		allChecksPassed = allChecksPassed && check.Status == "PASSED"
	}
	for _, required := range requiredGate0Checks {
		if _, ok := seen[required]; !ok {
			return fmt.Errorf("%w: missing required Gate 0 check %q", ErrInvalidEvidence, required)
		}
	}
	if record.Status == "PASSED" && !allChecksPassed {
		return fmt.Errorf("%w: passed record contains failed check", ErrInvalidEvidence)
	}
	if record.Status == "FAILED" && allChecksPassed {
		return fmt.Errorf("%w: failed record contains no failed check", ErrInvalidEvidence)
	}
	if record.Status == "PASSED" && record.ApproverIdentity == "placeholder" {
		return fmt.Errorf("%w: placeholder approver", ErrInvalidEvidence)
	}
	if !validIdentifier(record.Rollback.PlanID) || !validPath(record.Rollback.Log) ||
		!validDigest(record.Rollback.LogSHA256) || !validWindow(record.Rollback.StartedAt, record.Rollback.EndedAt) ||
		(record.Rollback.Status != "PASSED" && record.Rollback.Status != "FAILED") {
		return fmt.Errorf("%w: rollback drill", ErrInvalidEvidence)
	}
	if record.Rollback.Status == "PASSED" && (!validDigest(record.Rollback.FromArtifactSHA256) ||
		!validDigest(record.Rollback.TargetArtifactSHA256)) {
		return fmt.Errorf("%w: passed rollback lacks actual artifact digests", ErrInvalidEvidence)
	}
	if record.Rollback.Status == "FAILED" && (record.Rollback.FromArtifactSHA256 != "" || record.Rollback.TargetArtifactSHA256 != "") &&
		(!validDigest(record.Rollback.FromArtifactSHA256) || !validDigest(record.Rollback.TargetArtifactSHA256)) {
		return fmt.Errorf("%w: partial rollback artifact identity", ErrInvalidEvidence)
	}
	if record.Rollback.FromArtifactSHA256 != "" && record.Rollback.FromArtifactSHA256 == record.Rollback.TargetArtifactSHA256 {
		return fmt.Errorf("%w: rollback source and target are identical", ErrInvalidEvidence)
	}
	if prior, exists := paths[record.Rollback.Log]; exists {
		return fmt.Errorf("%w: path %q reused by %s and rollback", ErrInvalidEvidence, record.Rollback.Log, prior)
	}
	if record.Status == "PASSED" && record.Rollback.Status != "PASSED" {
		return fmt.Errorf("%w: passed record lacks passed rollback", ErrInvalidEvidence)
	}
	if requireSignature {
		if record.Signature.Algorithm != "Ed25519" || !validIdentifier(record.Signature.KeyID) ||
			!validDigest(record.Signature.PublicKeySHA256) || record.Signature.Payload != "artifact-manifest.json#without-signature" ||
			!validPath(record.Signature.Detached) {
			return fmt.Errorf("%w: signature metadata", ErrInvalidEvidence)
		}
	} else if record.Signature != (Signature{}) {
		return fmt.Errorf("%w: payload signature fields not empty", ErrInvalidEvidence)
	}
	return nil
}

func validateCI(ci CIIdentity) error {
	if ci.Provider != "github-actions" || !validIdentifier(ci.Repository) || !validIdentifier(ci.WorkflowRef) ||
		!validDigest(ci.WorkflowSHA256) || !validIdentifier(ci.RunID) || !validIdentifier(ci.RunAttempt) ||
		len(ci.SourceCommit) != 40 || !isLowerHex(ci.SourceCommit) || !validDigest(ci.SourceTreeSHA256) ||
		!validIdentifier(ci.RunnerEnvironment) || !validPath(ci.ProvenanceBundle) || !validDigest(ci.ProvenanceSHA256) ||
		!validPath(ci.VerificationLog) || !validDigest(ci.VerificationSHA256) || ci.ProvenanceBundle == ci.VerificationLog {
		return fmt.Errorf("%w: CI identity", ErrInvalidEvidence)
	}
	return nil
}

func verifyReferencedFiles(directory string, record ArtifactManifest, rejectUnreferenced bool) error {
	referenced := map[string]struct{}{"artifact-manifest.json": {}, record.Signature.Detached: {}}
	verify := func(path, expected string, expectedSize *int64) error {
		if !validPath(path) {
			return fmt.Errorf("%w: unsafe evidence path", ErrInvalidEvidence)
		}
		full := filepath.Join(directory, filepath.FromSlash(path))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: missing regular file %q", ErrUntrustedEvidence, path)
		}
		if expectedSize != nil && info.Size() != *expectedSize {
			return fmt.Errorf("%w: size mismatch for %q", ErrUntrustedEvidence, path)
		}
		actual, err := sha256File(full)
		if err != nil || DigestPrefix+actual != expected {
			return fmt.Errorf("%w: digest mismatch for %q", ErrUntrustedEvidence, path)
		}
		referenced[path] = struct{}{}
		return nil
	}
	for _, artifact := range record.Artifacts {
		if err := verify(artifact.Path, artifact.SHA256, &artifact.Size); err != nil {
			return err
		}
	}
	for _, check := range record.Checks {
		if err := verify(check.Log, check.LogSHA256, nil); err != nil {
			return err
		}
	}
	if err := verify(record.CI.ProvenanceBundle, record.CI.ProvenanceSHA256, nil); err != nil {
		return err
	}
	if err := verify(record.CI.VerificationLog, record.CI.VerificationSHA256, nil); err != nil {
		return err
	}
	if err := verify(record.Rollback.Log, record.Rollback.LogSHA256, nil); err != nil {
		return err
	}
	if !rejectUnreferenced {
		return nil
	}
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, ok := referenced[relative]; !ok {
			return fmt.Errorf("%w: unreferenced evidence file %q", ErrUntrustedEvidence, relative)
		}
		return nil
	})
}

func verifyManifestSBOMs(directory string, record ArtifactManifest, expectedNamespace string, required bool) error {
	seen := false
	covered := make(map[string]struct{})
	for _, artifact := range record.Artifacts {
		if artifact.MediaType != "application/spdx+json" {
			continue
		}
		seen = true
		if expectedNamespace == "" {
			if required {
				return fmt.Errorf("%w: expected SBOM namespace is required", ErrUntrustedEvidence)
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(artifact.Path)))
		if err != nil {
			return fmt.Errorf("%w: read SPDX: %v", ErrUntrustedEvidence, err)
		}
		document, err := VerifySPDX(data, expectedNamespace)
		if err != nil {
			return err
		}
		for _, item := range document.Packages {
			covered[DigestPrefix+item.Checksums[0].ChecksumValue] = struct{}{}
		}
	}
	if required && !seen {
		return fmt.Errorf("%w: SPDX SBOM absent", ErrUntrustedEvidence)
	}
	if required {
		for _, artifact := range record.Artifacts {
			if artifact.MediaType == "application/spdx+json" {
				continue
			}
			if _, ok := covered[artifact.SHA256]; !ok {
				return fmt.Errorf("%w: SPDX does not cover artifact %q", ErrUntrustedEvidence, artifact.Name)
			}
		}
	}
	return nil
}

func verifySignature(directory string, record ArtifactManifest, publicKeyPath string) error {
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid raw Ed25519 public key", ErrUntrustedEvidence)
	}
	digest := sha256.Sum256(publicKey)
	if DigestPrefix+hex.EncodeToString(digest[:]) != record.Signature.PublicKeySHA256 {
		return fmt.Errorf("%w: public key digest mismatch", ErrUntrustedEvidence)
	}
	signature, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(record.Signature.Detached)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid detached signature", ErrUntrustedEvidence)
	}
	payload, err := CanonicalPayload(record)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return fmt.Errorf("%w: detached signature verification failed", ErrUntrustedEvidence)
	}
	return nil
}

func verifyReleaseArtifactSignature(directory string, record ArtifactManifest, publicKeyPath string) error {
	var releaseArtifact, releaseSignature *Artifact
	for index := range record.Artifacts {
		artifact := &record.Artifacts[index]
		switch artifact.Name {
		case "release-artifact":
			releaseArtifact = artifact
		case "release-artifact-signature":
			releaseSignature = artifact
		}
	}
	if releaseArtifact == nil || releaseSignature == nil ||
		releaseSignature.MediaType != "application/vnd.cph.ed25519-signature" ||
		releaseSignature.Size != ed25519.SignatureSize {
		return fmt.Errorf("%w: release artifact detached signature metadata", ErrUntrustedEvidence)
	}
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid raw Ed25519 public key", ErrUntrustedEvidence)
	}
	artifact, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(releaseArtifact.Path)))
	if err != nil {
		return fmt.Errorf("%w: read release artifact: %v", ErrUntrustedEvidence, err)
	}
	signature, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(releaseSignature.Path)))
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), artifact, signature) {
		return fmt.Errorf("%w: release artifact detached signature verification failed", ErrUntrustedEvidence)
	}
	return nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func hasExpectedImage(images []OCIImage, index, platform string) bool {
	for _, image := range images {
		if (index == "" || image.IndexDigest == index) &&
			(platform == "" || image.PlatformManifestDigest == platform) {
			return true
		}
	}
	return false
}

func equalOCIImages(actual, expected []OCIImage) bool {
	if len(actual) != len(expected) {
		return false
	}
	want := append([]OCIImage(nil), expected...)
	sort.Slice(want, func(i, j int) bool { return want[i].Reference < want[j].Reference })
	for index := range actual {
		if actual[index] != want[index] {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool { return identityPattern.MatchString(value) }
func validDigest(value string) bool     { return digestPattern.MatchString(value) }
func isLowerHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
func validWindow(start, end string) bool {
	first, err := time.Parse(time.RFC3339Nano, start)
	if err != nil {
		return false
	}
	last, err := time.Parse(time.RFC3339Nano, end)
	return err == nil && !last.Before(first)
}
func validPath(path string) bool {
	return path != "" && len(path) <= 1024 && path == filepath.ToSlash(path) &&
		path == filepath.Clean(path) && !filepath.IsAbs(path) && path != "." &&
		path != ".." && !strings.HasPrefix(path, "../") && !strings.Contains(path, "\\")
}
