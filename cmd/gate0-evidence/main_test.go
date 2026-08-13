// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cypherium/cypher/aiinfra/gate0"
)

func TestBuildAndVerifyPassedAndFailedBundles(t *testing.T) {
	for _, test := range []struct {
		name   string
		failed bool
	}{
		{name: "passed"},
		{name: "failed", failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			bundleRoot := filepath.Join(directory, "bundle")
			payloadRoot := filepath.Join(bundleRoot, payloadDirectoryName)
			mustMkdir(t, filepath.Join(payloadRoot, "artifacts"))
			mustMkdir(t, filepath.Join(payloadRoot, "logs"))
			mustMkdir(t, filepath.Join(payloadRoot, "provenance"))
			mustWrite(t, filepath.Join(payloadRoot, "artifacts/release.bin"), []byte("deterministic release\n"))
			mustWrite(t, filepath.Join(payloadRoot, "provenance/attestation.jsonl"), []byte("{\"bundle\":\"verified\"}\n"))
			mustWrite(t, filepath.Join(payloadRoot, "logs/provenance-verification.json"), []byte("[{\"verified\":true}]\n"))
			mustWrite(t, filepath.Join(payloadRoot, "logs/rollback.log"), []byte("rollback exercised\n"))

			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publicPath := filepath.Join(directory, "release.pub")
			privatePath := filepath.Join(directory, "release.key")
			mustWrite(t, publicPath, public)
			mustWrite(t, privatePath, private)
			releaseSignature := ed25519.Sign(private, []byte("deterministic release\n"))
			mustWrite(t, filepath.Join(payloadRoot, "artifacts/release.bin.sig"), releaseSignature)

			boundary := boundarySpec{SenderIdentity: "spiffe://example.test/release/ci",
				Audience: "spiffe://example.test/release/verifier", Environment: "gate0-ci",
				SignatureKeyID: "release-key-2026-01", ChainIDSHA256: "sha256:" + strings.Repeat("11", 32),
				GenesisSHA256: "sha256:" + strings.Repeat("22", 32), ReplayDomainID: "gate0-release-evidence"}
			software := strings.Repeat("ab", 20)
			plan := planSpec{Schema: planInputSchema, ExperimentPlanID: "gate0-release-plan-v1",
				CapabilityID: "GATE-0-SUPPLY-CHAIN", Component: "cph-aiinfra-postgres", OwnerIdentity: "example/cypher",
				SoftwareVersion: software, HardwareScope: []string{"linux/amd64"}, WorkloadScope: []string{"gate0-release"},
				RegionScope: []string{"github-hosted:ubuntu-24.04"}, CollectionNotBefore: "2026-08-13T12:00:00Z",
				ObservationWindowNanos: 3_600_000_000_000, MinimumSampleSize: 10, ConfidenceLevelBasisPoint: 10_000,
				ConfidenceMethod: 1, ExpiresAt: "2026-08-14T12:00:00Z", FrozenAt: "2026-08-13T11:59:00Z",
				ApproverIdentity: "github:example/release-environment", PolicySHA256: "sha256:" + strings.Repeat("33", 32),
				Boundary: boundary}
			planSpecPath := filepath.Join(directory, "plan-spec.json")
			mustWriteJSON(t, planSpecPath, plan)
			if err := run([]string{"plan", "-spec", planSpecPath, "-private-key", privatePath,
				"-public-key", publicPath, "-out", filepath.Join(bundleRoot, planFileName)}); err != nil {
				t.Fatalf("plan: %v", err)
			}

			sbom := sbomSpec{Schema: sbomInputSchema, Name: "cypher-gate0", DocumentNamespace: "https://example.test/spdx/gate0/fixture",
				CreatedAt: "2026-08-13T12:00:00Z", Creator: "Tool:cph-gate0-evidence-v1", OutputPath: "artifacts/release.spdx.json",
				Components: []sbomComponentSpec{{SPDXID: "SPDXRef-Package-release", Name: "cypher-release",
					Version: software, DownloadLocation: "NOASSERTION", Path: "artifacts/release.bin"},
					{SPDXID: "SPDXRef-Package-release-signature", Name: "cypher-release-signature",
						Version: software, DownloadLocation: "NOASSERTION", Path: "artifacts/release.bin.sig"}}}
			sbomSpecPath := filepath.Join(directory, "sbom-spec.json")
			mustWriteJSON(t, sbomSpecPath, sbom)
			if err := run([]string{"sbom", "-spec", sbomSpecPath, "-root", payloadRoot}); err != nil {
				t.Fatalf("sbom: %v", err)
			}

			checks := make([]checkInput, 0, 10)
			for _, id := range []string{"artifact-provenance", "artifact-signature", "backup-restore", "ccse-fail-closed",
				"cross-language-signatures", "pilot-plan-owner-coverage", "rollback-drill", "sbom-policy", "secret-scan",
				"telemetry-cardinality-redaction"} {
				status := "PASSED"
				if test.failed && id == "pilot-plan-owner-coverage" {
					status = "FAILED"
				}
				logPath := "logs/check-" + id + ".log"
				mustWrite(t, filepath.Join(payloadRoot, filepath.FromSlash(logPath)), []byte(status+"\n"))
				checks = append(checks, checkInput{ID: id, Status: status, StartedAt: "2026-08-13T12:01:00Z",
					EndedAt: "2026-08-13T12:02:00Z", Log: logPath})
			}
			bundle := bundleSpec{Schema: bundleInputSchema, EvidenceID: "gate0-release-" + software[:12],
				CapabilityID: plan.CapabilityID, Component: plan.Component, SoftwareVersion: software,
				CreatedAt: "2026-08-13T12:03:00Z", ExpiresAt: "2026-08-14T12:00:00Z", ApprovingRole: "release-approver",
				ApproverIdentity: plan.ApproverIdentity, PolicySHA256: plan.PolicySHA256, SBOMNamespace: sbom.DocumentNamespace,
				CI: ciInput{Repository: "example/cypher",
					WorkflowRef:    "example/cypher/.github/workflows/gate0-release-evidence.yml@refs/tags/v1.2.3",
					WorkflowSHA256: "sha256:" + strings.Repeat("44", 32), RunID: "1234", RunAttempt: "1",
					SourceCommit: software, SourceTreeSHA256: "sha256:" + strings.Repeat("55", 32),
					RunnerEnvironment: "github-hosted:ubuntu-24.04", ProvenanceBundle: "provenance/attestation.jsonl",
					VerificationLog: "logs/provenance-verification.json"},
				Images: []gate0.OCIImage{(gate0ImageFixture{}).image()},
				Artifacts: []artifactInput{{Name: "release-artifact", Path: "artifacts/release.bin", MediaType: "application/octet-stream"},
					{Name: "release-artifact-signature", Path: "artifacts/release.bin.sig", MediaType: "application/vnd.cph.ed25519-signature"},
					{Name: "release-sbom", Path: "artifacts/release.spdx.json", MediaType: "application/spdx+json"}},
				Checks: checks, Rollback: rollbackInput{Status: "PASSED", PlanID: "ROLLBACK-GATE0-01",
					StartedAt: "2026-08-13T12:01:00Z", EndedAt: "2026-08-13T12:02:00Z",
					FromArtifactSHA256: "sha256:" + strings.Repeat("66", 32), TargetArtifactSHA256: "sha256:" + strings.Repeat("77", 32),
					Log: "logs/rollback.log"}, Boundary: boundary}
			bundleSpecPath := filepath.Join(directory, "bundle-spec.json")
			mustWriteJSON(t, bundleSpecPath, bundle)
			if err := run([]string{"bundle", "-spec", bundleSpecPath, "-root", bundleRoot,
				"-private-key", privatePath, "-public-key", publicPath}); err != nil {
				t.Fatalf("bundle: %v", err)
			}

			verify := verifySpec{Schema: verifyInputSchema, Now: "2026-08-13T12:04:00Z", RequirePassed: !test.failed,
				ExpectedSourceCommit: software, ExpectedRepository: bundle.CI.Repository, ExpectedWorkflowRef: bundle.CI.WorkflowRef,
				ExpectedOCIIndexDigest:   bundle.Images[0].IndexDigest,
				ExpectedPlatformManifest: bundle.Images[0].PlatformManifestDigest, ExpectedSBOMNamespace: sbom.DocumentNamespace,
				ExpectedImages:   bundle.Images,
				ExperimentPlanID: plan.ExperimentPlanID, CapabilityID: plan.CapabilityID, Component: plan.Component,
				SoftwareVersion: software, ApproverIdentity: plan.ApproverIdentity, Boundary: boundary}
			verifySpecPath := filepath.Join(directory, "verify-spec.json")
			mustWriteJSON(t, verifySpecPath, verify)
			if err := run([]string{"verify", "-spec", verifySpecPath, "-root", bundleRoot, "-public-key", publicPath}); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if test.failed {
				verify.RequirePassed = true
				mustWriteJSON(t, filepath.Join(directory, "must-pass.json"), verify)
				if err := run([]string{"verify", "-spec", filepath.Join(directory, "must-pass.json"), "-root", bundleRoot,
					"-public-key", publicPath}); err == nil {
					t.Fatal("failed bundle accepted by require_passed policy")
				}
			}
		})
	}
}

func TestSourceArchiveIsDeterministicAndClosed(t *testing.T) {
	directory := t.TempDir()
	mustWrite(t, filepath.Join(directory, "a.txt"), []byte("a\n"))
	mustWrite(t, filepath.Join(directory, "nested/b.txt"), []byte("b\n"))
	mustWrite(t, filepath.Join(directory, "files.txt"), []byte("a.txt\nnested/b.txt\n"))
	first := filepath.Join(directory, "first.tar")
	second := filepath.Join(directory, "second.tar")
	for _, output := range []string{first, second} {
		if err := run([]string{"source-archive", "-root", directory, "-list", filepath.Join(directory, "files.txt"),
			"-out", output, "-epoch", "1818158400"}); err != nil {
			t.Fatal(err)
		}
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstData) != string(secondData) {
		t.Fatal("source archive is not deterministic")
	}
	mustWrite(t, filepath.Join(directory, "bad-list.txt"), []byte("nested/b.txt\na.txt\n"))
	if err := run([]string{"source-archive", "-root", directory, "-list", filepath.Join(directory, "bad-list.txt"),
		"-out", filepath.Join(directory, "bad.tar"), "-epoch", "1818158400"}); err == nil {
		t.Fatal("unsorted source list accepted")
	}
}

func TestDetachedFileSignatureRoundTripAndTamper(t *testing.T) {
	directory := t.TempDir()
	artifact := filepath.Join(directory, "artifact.tar")
	signature := filepath.Join(directory, "artifact.sig")
	mustWrite(t, artifact, []byte("artifact\n"))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(directory, "release.pub")
	privatePath := filepath.Join(directory, "release.key")
	mustWrite(t, publicPath, public)
	mustWrite(t, privatePath, private)
	if err := run([]string{"sign-file", "-in", artifact, "-private-key", privatePath, "-public-key", publicPath,
		"-out", signature}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify-file", "-in", artifact, "-signature", signature, "-public-key", publicPath}); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, artifact, []byte("tampered\n"))
	if err := run([]string{"verify-file", "-in", artifact, "-signature", signature, "-public-key", publicPath}); err == nil {
		t.Fatal("tampered artifact signature accepted")
	}
}

// A named wrapper keeps the fixture readable without hiding the production
// gate0.OCIImage type behind untyped JSON.
type gate0ImageFixture struct{}

func (gate0ImageFixture) image() gate0.OCIImage {
	return gate0.OCIImage{Reference: "docker.io/library/postgres:18.4-bookworm", Platform: "linux/amd64",
		IndexDigest:            "sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382",
		PlatformManifestDigest: "sha256:7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568"}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, data)
}
