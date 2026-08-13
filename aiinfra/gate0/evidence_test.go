// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package gate0

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const testSBOMNamespace = "https://cypherium.io/spdx/gate0/0123456789abcdef"

func TestArtifactManifestVerifyDirectory(t *testing.T) {
	directory := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeGate0FixtureFiles(t, directory, private)
	publicDigest := sha256.Sum256(public)
	record := validArtifactManifest(t, directory)
	record.Signature = Signature{Algorithm: "Ed25519", KeyID: "release-key-2026-01",
		PublicKeySHA256: DigestPrefix + hex.EncodeToString(publicDigest[:]),
		Payload:         "artifact-manifest.json#without-signature", Detached: "artifact-manifest.sig"}
	payload, err := CanonicalPayload(record)
	if err != nil {
		t.Fatal(err)
	}
	writeEvidenceFile(t, directory, record.Signature.Detached, ed25519.Sign(private, payload))
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeEvidenceFile(t, directory, "artifact-manifest.json", data)
	publicPath := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(publicPath, public, 0o600); err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{Now: time.Date(2026, 8, 13, 13, 0, 0, 0, time.UTC),
		ExpectedSourceCommit: "0123456789abcdef0123456789abcdef01234567",
		ExpectedRepository:   "CypherTroopers/cypher", ExpectedWorkflowRef: "CypherTroopers/cypher/.github/workflows/gate0-release-evidence.yml@refs/heads/GPU",
		ExpectedOCIIndexDigest:   "sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382",
		ExpectedPlatformManifest: "sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568",
		ExpectedSBOMNamespace:    testSBOMNamespace,
		ExpectedImages:           append([]OCIImage(nil), record.Images...),
		PublicKeyPath:            publicPath, RequirePassed: true, RequireRollback: true, RejectUnreferencedRegulars: true}
	if _, err := VerifyDirectory(directory, options); err != nil {
		t.Fatalf("verify exact artifact manifest: %v", err)
	}
	missingImagePolicy := options
	missingImagePolicy.ExpectedImages = nil
	if _, err := VerifyDirectory(directory, missingImagePolicy); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("missing exact OCI policy accepted: %v", err)
	}
	wrongGo := options
	wrongGo.ExpectedImages = append([]OCIImage(nil), record.Images...)
	wrongGo.ExpectedImages[0].PlatformManifestDigest = "sha256:" + strings.Repeat("99", 32)
	if _, err := VerifyDirectory(directory, wrongGo); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("changed OCI image accepted: %v", err)
	}
	extraImage := options
	extraImage.ExpectedImages = append(append([]OCIImage(nil), record.Images...), record.Images[0])
	if _, err := VerifyDirectory(directory, extraImage); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("extra expected OCI image accepted: %v", err)
	}

	t.Run("tampered artifact", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(directory, "logs/check-00.log"), []byte("tampered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyDirectory(directory, options); !errors.Is(err, ErrUntrustedEvidence) {
			t.Fatalf("tamper error=%v", err)
		}
	})
}

func TestReleaseArtifactSignatureVerification(t *testing.T) {
	directory := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("signed release artifact\n")
	signature := ed25519.Sign(private, artifact)
	writeEvidenceFile(t, directory, "artifacts/release.bin", artifact)
	writeEvidenceFile(t, directory, "artifacts/release.bin.sig", signature)
	publicPath := filepath.Join(directory, "release.pub")
	writeEvidenceFile(t, directory, "release.pub", public)
	record := ArtifactManifest{Artifacts: []Artifact{
		{Name: "release-artifact", Path: "artifacts/release.bin", Size: int64(len(artifact))},
		{Name: "release-artifact-signature", Path: "artifacts/release.bin.sig",
			MediaType: "application/vnd.cph.ed25519-signature", Size: int64(len(signature))},
	}}
	if err := verifyReleaseArtifactSignature(directory, record, publicPath); err != nil {
		t.Fatalf("valid release signature: %v", err)
	}
	signature[0] ^= 0x80
	writeEvidenceFile(t, directory, "artifacts/release.bin.sig", signature)
	if err := verifyReleaseArtifactSignature(directory, record, publicPath); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("invalid release signature error=%v", err)
	}
}

func TestArtifactManifestFailsClosed(t *testing.T) {
	record := ArtifactManifest{Schema: SchemaVersion}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"extension":true}`)...)
	if _, err := Decode(data); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("unknown field error=%v", err)
	}

	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "artifact-manifest.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(directory, VerifyOptions{}); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("empty record error=%v", err)
	}

	t.Run("missing required Gate 0 check", func(t *testing.T) {
		fixture := t.TempDir()
		writeGate0FixtureFiles(t, fixture)
		manifest := validArtifactManifest(t, fixture)
		manifest.Checks = manifest.Checks[:len(manifest.Checks)-1]
		manifest.Signature = Signature{Algorithm: "Ed25519", KeyID: "release-key-2026-01", PublicKeySHA256: "sha256:" + strings.Repeat("55", 32), Payload: "artifact-manifest.json#without-signature", Detached: "artifact-manifest.sig"}
		if err := validateRecord(manifest, true); !errors.Is(err, ErrInvalidEvidence) {
			t.Fatalf("missing required check error=%v", err)
		}
	})
}

func TestExactOCIImageSetRejectsChangedAndExtraImage(t *testing.T) {
	actual := []OCIImage{
		{Reference: "docker.io/library/golang:1.26.2-bookworm", IndexDigest: "sha256:" + strings.Repeat("11", 32), Platform: "linux/amd64", PlatformManifestDigest: "sha256:" + strings.Repeat("22", 32)},
		{Reference: "docker.io/library/postgres:18.4-bookworm", IndexDigest: "sha256:" + strings.Repeat("33", 32), Platform: "linux/amd64", PlatformManifestDigest: "sha256:" + strings.Repeat("44", 32)},
	}
	expected := append([]OCIImage(nil), actual...)
	if !equalOCIImages(actual, expected) {
		t.Fatal("exact OCI set rejected")
	}
	expected[0].PlatformManifestDigest = "sha256:" + strings.Repeat("55", 32)
	if equalOCIImages(actual, expected) {
		t.Fatal("changed Go platform image accepted")
	}
	expected = append(append([]OCIImage(nil), actual...), OCIImage{Reference: "extra", IndexDigest: "sha256:" + strings.Repeat("66", 32), Platform: "linux/amd64", PlatformManifestDigest: "sha256:" + strings.Repeat("77", 32)})
	if equalOCIImages(actual, expected) {
		t.Fatal("extra OCI image accepted")
	}
}

func TestBuildSignedFoundationEvidenceUsesCanonicalSchema(t *testing.T) {
	directory := t.TempDir()
	writeGate0FixtureFiles(t, directory)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validArtifactManifest(t, directory)
	manifest.Signature = Signature{Algorithm: "Ed25519", KeyID: "release-key-2026-01",
		PublicKeySHA256: "sha256:" + strings.Repeat("55", 32), Payload: "artifact-manifest.json#without-signature", Detached: "artifact-manifest.sig"}
	var integrity [32]byte
	copy(integrity[:], bytesRepeat(0x71, 32))
	var idempotency [16]byte
	copy(idempotency[:], bytesRepeat(0x81, 16))
	metadata := foundationMetadata(integrity, idempotency)
	domain, envelope := evidenceCCSEBoundary()
	evidence, err := BuildSignedFoundationEvidence(manifest, metadata, domain, envelope, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationEvidence(evidence, public); err != nil {
		t.Fatalf("verify canonical foundation evidence: %v", err)
	}
	policy := FoundationEvidencePolicy{ExperimentPlanID: "gate0-release-plan-v1", CapabilityID: manifest.CapabilityID,
		Component: manifest.Component, SoftwareVersion: manifest.SoftwareVersion, Purpose: "evidence.record.release",
		Audience: "spiffe://cph.example/release/verifier", Environment: "gate0-ci",
		SignatureKeyID: "release-key-2026-01", ApproverIdentity: manifest.ApproverIdentity,
		SenderIdentity: domain.SenderIdentity, ChainID: domain.ChainID, GenesisHash: domain.GenesisHash, ReplayDomainID: domain.ReplayDomainID}
	if err := VerifySignedFoundationEvidenceForManifest(manifest, evidence, public, policy); err != nil {
		t.Fatalf("verify foundation evidence for exact manifest: %v", err)
	}
	retained, err := MarshalRetainedRecord(evidence.Record)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeRetainedFoundationEvidence(retained)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationEvidenceForManifest(manifest, restored, public, policy); err != nil {
		t.Fatalf("verify retained foundation evidence: %v", err)
	}
	nonCanonical := append([]byte(" "), retained...)
	if _, err := UnmarshalRetainedRecord(nonCanonical); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("non-canonical retained record error=%v", err)
	}
	wrong := policy
	wrong.SoftwareVersion = "ffffffffffffffffffffffffffffffffffffffff"
	if err := VerifySignedFoundationEvidenceForManifest(manifest, evidence, public, wrong); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("wrong source policy error=%v", err)
	}
	wrongBoundary := policy
	wrongBoundary.SenderIdentity = "spiffe://attacker.example/release/ci"
	if err := VerifySignedFoundationEvidenceForManifest(manifest, evidence, public, wrongBoundary); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("foreign EvidenceRecord boundary accepted: %v", err)
	}
	foreignBoundary := evidence
	foreignBoundary.Record = cloneCCSERecord(evidence.Record)
	foreignBoundary.Record.Domain.SenderIdentity = "spiffe://attacker.example/release/ci"
	foreignBoundary.Record.Envelope.SenderIdentity = foreignBoundary.Record.Domain.SenderIdentity
	if err := foreignBoundary.Record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationEvidenceForManifest(manifest, foreignBoundary, public, policy); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("self-consistent foreign EvidenceRecord accepted: %v", err)
	}
	foreignCounter := evidence
	foreignCounter.Record = cloneCCSERecord(evidence.Record)
	foreignCounter.Record.Domain.CounterKind = ccse.CounterExpectedGeneration
	foreignCounter.Record.Envelope.CounterKind = ccse.CounterExpectedGeneration
	if err := foreignCounter.Record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationEvidenceForManifest(manifest, foreignCounter, public, policy); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("foreign EvidenceRecord counter kind accepted: %v", err)
	}
	foreignType := evidence
	foreignType.Record = cloneCCSERecord(evidence.Record)
	foreignType.Record.MessageTypeID++
	if err := VerifySignedFoundationEvidence(foreignType, public); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("foreign EvidenceRecord type accepted: %v", err)
	}
	evidence.Record.Payload[0] ^= 1
	if err := VerifySignedFoundationEvidence(evidence, public); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("tampered foundation evidence error=%v", err)
	}
}

func TestFailedEvidenceIsAuditableButCannotPassAcceptance(t *testing.T) {
	directory := t.TempDir()
	writeGate0FixtureFiles(t, directory)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validArtifactManifest(t, directory)
	manifest.Status = "FAILED"
	manifest.Checks[0].Status = "FAILED"
	manifest.Signature = Signature{Algorithm: "Ed25519", KeyID: "release-key-2026-01",
		PublicKeySHA256: "sha256:" + strings.Repeat("55", 32), Payload: "artifact-manifest.json#without-signature", Detached: "artifact-manifest.sig"}
	var integrity [32]byte
	copy(integrity[:], bytesRepeat(0x73, 32))
	var idempotency [16]byte
	copy(idempotency[:], bytesRepeat(0x83, 16))
	domain, envelope := evidenceCCSEBoundary()
	evidence, err := BuildSignedFoundationEvidence(manifest, foundationMetadata(integrity, idempotency), domain, envelope, private)
	if err != nil {
		t.Fatal(err)
	}
	policy := FoundationEvidencePolicy{ExperimentPlanID: "gate0-release-plan-v1", CapabilityID: manifest.CapabilityID,
		Component: manifest.Component, SoftwareVersion: manifest.SoftwareVersion, Purpose: "evidence.record.release",
		Audience: "spiffe://cph.example/release/verifier", Environment: "gate0-ci",
		SignatureKeyID: "release-key-2026-01", ApproverIdentity: manifest.ApproverIdentity,
		SenderIdentity: domain.SenderIdentity, ChainID: domain.ChainID, GenesisHash: domain.GenesisHash, ReplayDomainID: domain.ReplayDomainID}
	if err := VerifySignedFoundationEvidenceCandidateForManifest(manifest, evidence, public, policy); err != nil {
		t.Fatalf("failed candidate should be auditable: %v", err)
	}
	if err := VerifySignedFoundationEvidenceForManifest(manifest, evidence, public, policy); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("failed candidate accepted as normative evidence: %v", err)
	}
}

func TestBuildSignedFoundationPlanUsesCanonicalSchema(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var integrity [32]byte
	copy(integrity[:], bytesRepeat(0x72, 32))
	var idempotency [16]byte
	copy(idempotency[:], bytesRepeat(0x82, 16))
	plan := foundationv1.ExperimentPlanSigningProjection{
		Metadata: foundationMetadata(integrity, idempotency), ExperimentPlanID: "gate0-release-plan-v1",
		CapabilityID: "GATE-0-SUPPLY-CHAIN", Component: "cph-aiinfra-postgres",
		OwnerIdentity: "github:CypherTroopers/release-environment", SoftwareVersion: "0123456789abcdef0123456789abcdef01234567",
		HardwareScope: []string{"linux/amd64"}, WorkloadScope: []string{"gate0-release"}, RegionScope: []string{"github-hosted:ubuntu-24.04"},
		CollectionNotBeforeUnixNano: 1_818_158_400_000_000_000, ObservationWindowNanos: uint64(time.Hour), MinimumSampleSize: 1,
		ConfidenceLevelBasisPoints: 10_000, ConfidenceMethod: 1,
		Criteria:             gate0TestCriteria(),
		RevalidationTriggers: []string{"artifact-change", "dependency-change", "signing-key-rotation", "workflow-change"},
		ExpiresAtUnixNano:    1_820_750_400_000_000_000, ExperimentPolicyDigestSHA256: sha256.Sum256([]byte("gate0-release-policy-v1")),
		TargetLevel: 3, FrozenAtUnixNano: 1_818_158_399_000_000_000,
		ApprovingIdentities: []string{"github:CypherTroopers/release-environment"},
	}
	domain, envelope := evidenceCCSEBoundary()
	domain.Purpose = "evidence.experiment.plan.freeze"
	signed, err := BuildSignedFoundationPlan(plan, domain, envelope, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationPlan(signed, public); err != nil {
		t.Fatalf("verify canonical foundation plan: %v", err)
	}
	planPolicy := FoundationPlanPolicy{ExperimentPlanID: plan.ExperimentPlanID, CapabilityID: plan.CapabilityID,
		Component: plan.Component, SoftwareVersion: plan.SoftwareVersion, Purpose: "evidence.experiment.plan.freeze",
		Audience: "spiffe://cph.example/release/verifier", Environment: "gate0-ci",
		SignatureKeyID: "release-key-2026-01", ApproverIdentity: plan.ApprovingIdentities[0],
		SenderIdentity: domain.SenderIdentity, ChainID: domain.ChainID, GenesisHash: domain.GenesisHash, ReplayDomainID: domain.ReplayDomainID}
	if err := VerifySignedFoundationPlanForPolicy(signed, public, planPolicy); err != nil {
		t.Fatalf("verify canonical foundation plan policy: %v", err)
	}
	retained, err := MarshalRetainedRecord(signed.Record)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeRetainedFoundationPlan(retained)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationPlanForPolicy(restored, public, planPolicy); err != nil {
		t.Fatalf("verify retained foundation plan policy: %v", err)
	}
	wrongBoundary := planPolicy
	wrongBoundary.ReplayDomainID = "foreign-replay-domain"
	if err := VerifySignedFoundationPlanForPolicy(signed, public, wrongBoundary); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("foreign ExperimentPlan boundary accepted: %v", err)
	}
	foreignBoundary := signed
	foreignBoundary.Record = cloneCCSERecord(signed.Record)
	foreignBoundary.Record.Domain.ReplayDomainID = "foreign-replay-domain"
	if err := foreignBoundary.Record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationPlanForPolicy(foreignBoundary, public, planPolicy); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("self-consistent foreign ExperimentPlan accepted: %v", err)
	}
	foreignCounter := signed
	foreignCounter.Record = cloneCCSERecord(signed.Record)
	foreignCounter.Record.Domain.CounterKind = ccse.CounterExpectedGeneration
	foreignCounter.Record.Envelope.CounterKind = ccse.CounterExpectedGeneration
	if err := foreignCounter.Record.SignEd25519(private, ccse.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedFoundationPlanForPolicy(foreignCounter, public, planPolicy); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("foreign ExperimentPlan counter kind accepted: %v", err)
	}
	foreignType := signed
	foreignType.Record = cloneCCSERecord(signed.Record)
	foreignType.Record.MessageTypeID++
	if err := VerifySignedFoundationPlan(foreignType, public); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("foreign ExperimentPlan type accepted: %v", err)
	}
	if _, err := BuildSignedFoundationPlan(plan, domain, envelope, nil); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatalf("missing plan key error=%v", err)
	}
}

func cloneCCSERecord(record *ccse.Record) *ccse.Record {
	copyRecord := *record
	copyRecord.Payload = append([]byte(nil), record.Payload...)
	copyRecord.Signature = append([]byte(nil), record.Signature...)
	return &copyRecord
}

func gate0TestCriteria() []foundationv1.MetricCriterionSigningProjection {
	criteria := make([]foundationv1.MetricCriterionSigningProjection, 0, len(requiredGate0Checks))
	for _, check := range requiredGate0Checks {
		criteria = append(criteria, foundationv1.MetricCriterionSigningProjection{MetricID: "gate0." + check + ".passed", Comparison: 3,
			ThresholdNumerator: 1, ThresholdDenominator: 1, Unit: "boolean", MinimumMetricSampleSize: 1})
	}
	return criteria
}

func validArtifactManifest(t *testing.T, directory string) ArtifactManifest {
	t.Helper()
	artifactInfo, artifactDigest := evidenceFileIdentity(t, directory, "artifacts/release.spdx.json")
	releaseInfo, releaseDigest := evidenceFileIdentity(t, directory, "artifacts/release.bin")
	artifacts := []Artifact{{Name: "release-artifact", Path: "artifacts/release.bin",
		MediaType: "application/octet-stream", SHA256: releaseDigest, Size: releaseInfo.Size()}}
	if _, err := os.Stat(filepath.Join(directory, "artifacts/release.bin.sig")); err == nil {
		signatureInfo, signatureDigest := evidenceFileIdentity(t, directory, "artifacts/release.bin.sig")
		artifacts = append(artifacts, Artifact{Name: "release-artifact-signature", Path: "artifacts/release.bin.sig",
			MediaType: "application/vnd.cph.ed25519-signature", SHA256: signatureDigest, Size: signatureInfo.Size()})
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	artifacts = append(artifacts, Artifact{Name: "release-sbom", Path: "artifacts/release.spdx.json",
		MediaType: "application/spdx+json", SHA256: artifactDigest, Size: artifactInfo.Size()})
	_, checkDigest := evidenceFileIdentity(t, directory, "logs/check-00.log")
	_, rollbackDigest := evidenceFileIdentity(t, directory, "logs/rollback.log")
	_, provenanceDigest := evidenceFileIdentity(t, directory, "provenance/attestation.json")
	_, provenanceVerificationDigest := evidenceFileIdentity(t, directory, "logs/provenance-verification.log")
	return ArtifactManifest{
		Schema: SchemaVersion, EvidenceID: "gate0-release-0123456789ab", CapabilityID: "GATE-0-SUPPLY-CHAIN",
		Component: "cph-aiinfra-postgres", SoftwareVersion: "0123456789abcdef0123456789abcdef01234567",
		CreatedAt: "2026-08-13T12:00:00Z", ExpiresAt: "2026-09-12T12:00:00Z",
		ApprovingRole: "release-approver", ApproverIdentity: "github:CypherTroopers/release-environment",
		Status: "PASSED",
		CI: CIIdentity{Provider: "github-actions", Repository: "CypherTroopers/cypher",
			WorkflowRef:    "CypherTroopers/cypher/.github/workflows/gate0-release-evidence.yml@refs/heads/GPU",
			WorkflowSHA256: "sha256:" + strings.Repeat("11", 32), RunID: "1234", RunAttempt: "1",
			SourceCommit: "0123456789abcdef0123456789abcdef01234567", SourceTreeSHA256: "sha256:" + strings.Repeat("22", 32), RunnerEnvironment: "github-hosted:ubuntu-24.04",
			ProvenanceBundle: "provenance/attestation.json", ProvenanceSHA256: provenanceDigest,
			VerificationLog: "logs/provenance-verification.log", VerificationSHA256: provenanceVerificationDigest},
		Images: []OCIImage{{Reference: "docker.io/library/golang:1.26.2-bookworm", Platform: "linux/amd64",
			IndexDigest:            "sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19",
			PlatformManifestDigest: "sha256:6b9b1ff26b22fde9b31abc5c6994586f588107ee3aa54dba50626aaac5884995"},
			{Reference: "docker.io/library/postgres:18.4-bookworm", Platform: "linux/amd64",
				IndexDigest:            "sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382",
				PlatformManifestDigest: "sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568"}},
		Artifacts: artifacts,
		Checks:    requiredPassingChecks(checkDigest),
		Rollback: RollbackDrill{Status: "PASSED", PlanID: "ROLLBACK-GATE0-01", StartedAt: "2026-08-13T12:01:00Z", EndedAt: "2026-08-13T12:02:00Z",
			FromArtifactSHA256: "sha256:" + strings.Repeat("33", 32), TargetArtifactSHA256: "sha256:" + strings.Repeat("44", 32), Log: "logs/rollback.log", LogSHA256: rollbackDigest},
	}
}

func requiredPassingChecks(logDigest string) []Check {
	checks := make([]Check, 0, len(requiredGate0Checks))
	for index, id := range requiredGate0Checks {
		checks = append(checks, Check{ID: id, Status: "PASSED", StartedAt: "2026-08-13T12:00:00Z", EndedAt: "2026-08-13T12:01:00Z", Log: fmt.Sprintf("logs/check-%02d.log", index), LogSHA256: logDigest})
	}
	return checks
}

func writeRequiredCheckLogs(t *testing.T, directory string) {
	for index := range requiredGate0Checks {
		writeEvidenceFile(t, directory, fmt.Sprintf("logs/check-%02d.log", index), []byte("ci passed\n"))
	}
}

func writeGate0FixtureFiles(t *testing.T, directory string, signingKey ...ed25519.PrivateKey) {
	t.Helper()
	writeEvidenceFile(t, directory, "logs/rollback.log", []byte("rollback passed\n"))
	release := []byte("release fixture\n")
	writeEvidenceFile(t, directory, "artifacts/release.bin", release)
	_, releaseDigest := evidenceFileIdentity(t, directory, "artifacts/release.bin")
	components := []SBOMComponent{{SPDXID: "SPDXRef-Package-release", Name: "cypher-release", Version: "0123456789abcdef",
		DownloadLocation: "NOASSERTION", SHA256: strings.TrimPrefix(releaseDigest, DigestPrefix)}}
	if len(signingKey) > 1 {
		t.Fatal("at most one fixture signing key is allowed")
	}
	if len(signingKey) == 1 {
		signature := ed25519.Sign(signingKey[0], release)
		writeEvidenceFile(t, directory, "artifacts/release.bin.sig", signature)
		_, signatureDigest := evidenceFileIdentity(t, directory, "artifacts/release.bin.sig")
		components = append(components, SBOMComponent{SPDXID: "SPDXRef-Package-release-signature",
			Name: "cypher-release-signature", Version: "0123456789abcdef", DownloadLocation: "NOASSERTION",
			SHA256: strings.TrimPrefix(signatureDigest, DigestPrefix)})
	}
	sbom, err := GenerateSPDX(SBOMInput{Name: "cypher-gate0", DocumentNamespace: testSBOMNamespace,
		CreatedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), Creator: "Tool:cph-gate0-sbom-v1",
		Components: components})
	if err != nil {
		t.Fatal(err)
	}
	writeEvidenceFile(t, directory, "artifacts/release.spdx.json", sbom)
	writeEvidenceFile(t, directory, "provenance/attestation.json", []byte("{\"bundle\":\"verified fixture\"}\n"))
	writeEvidenceFile(t, directory, "logs/provenance-verification.log", []byte("attestation verified\n"))
	writeRequiredCheckLogs(t, directory)
}

func evidenceFileIdentity(t *testing.T, directory, relative string) (os.FileInfo, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, relative))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, relative))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return info, DigestPrefix + hex.EncodeToString(digest[:])
}

func writeEvidenceFile(t *testing.T, directory, relative string, data []byte) {
	t.Helper()
	path := filepath.Join(directory, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func bytesRepeat(value byte, count int) []byte {
	return bytes.Repeat([]byte{value}, count)
}

func foundationMetadata(integrity [32]byte, idempotency [16]byte) foundationv1.RecordMetadataSigningProjection {
	return foundationv1.RecordMetadataSigningProjection{
		SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1}, RecordID: "gate0-release-record-01",
		CreatedAtUnixNano: 1_818_158_400_000_000_000, IntegrityDigest: integrity, HomeRegion: "global",
		WriterEpoch: 1, StateVersion: 1, IdempotencyKey: idempotency,
		PolicyDigestsSHA256: [][32]byte{sha256.Sum256([]byte("gate0-release-policy-v1"))},
	}
}

func evidenceCCSEBoundary() (ccse.Domain, ccse.Envelope) {
	version := ccse.Version{Major: 1}
	issued := int64(1_818_158_400_000_000_000)
	expires := int64(1_820_750_400_000_000_000)
	chain := sha256.Sum256([]byte("gate0-test-chain"))
	genesis := sha256.Sum256([]byte("gate0-test-genesis"))
	message := sha256.Sum256([]byte("gate0-test-message"))
	correlation := sha256.Sum256([]byte("gate0-test-correlation"))
	domain := ccse.Domain{Purpose: "evidence.record.release", SenderIdentity: "spiffe://cph.example/release/ci",
		Audience: []string{"spiffe://cph.example/release/verifier"}, ChainID: chain, GenesisHash: genesis,
		Environment: "gate0-ci", ProtocolVersion: version, SchemaVersion: version,
		SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: "release-key-2026-01",
		IssuedAtUnixNano: issued, ExpiresAtUnixNano: expires, CounterKind: ccse.CounterSequence, Counter: 1,
		ReplayDomainID: "gate0-release-evidence"}
	envelope := ccse.Envelope{ProtocolVersion: version, SchemaVersion: version,
		SenderIdentity: domain.SenderIdentity, ChainID: chain, Environment: domain.Environment,
		IssuedAtUnixNano: issued, ExpiresAtUnixNano: expires, CounterKind: domain.CounterKind, Counter: domain.Counter,
		SignatureAlgorithm: domain.SignatureAlgorithm, SignatureKeyID: domain.SignatureKeyID}
	copy(envelope.MessageID[:], message[:16])
	copy(envelope.CorrelationID[:], correlation[:16])
	return domain, envelope
}
