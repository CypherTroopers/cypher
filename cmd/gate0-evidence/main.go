// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

// gate0-evidence builds and verifies the offline Gate 0 release-evidence
// bundle. It never obtains signing material itself and never converts missing
// checks into success.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cypherium/cypher/aiinfra/ccse"
	"github.com/cypherium/cypher/aiinfra/gate0"
	foundationv1 "github.com/cypherium/cypher/aiinfra/schema/foundation/v1"
)

const (
	planInputSchema   = "cph.aiinfra.gate0.plan-input.v1"
	sbomInputSchema   = "cph.aiinfra.gate0.sbom-input.v1"
	bundleInputSchema = "cph.aiinfra.gate0.bundle-input.v1"
	verifyInputSchema = "cph.aiinfra.gate0.verify-policy.v1"

	payloadDirectoryName  = "payload"
	manifestFileName      = "artifact-manifest.json"
	manifestSignatureName = "artifact-manifest.sig"
	planFileName          = "foundation-experiment-plan.ccse.json"
	evidenceFileName      = "foundation-evidence-record.ccse.json"
	maxInputBytes         = 4 << 20
	maxArtifactBytes      = 1 << 30
)

type boundarySpec struct {
	SenderIdentity string `json:"sender_identity"`
	Audience       string `json:"audience"`
	Environment    string `json:"environment"`
	SignatureKeyID string `json:"signature_key_id"`
	ChainIDSHA256  string `json:"chain_id_sha256"`
	GenesisSHA256  string `json:"genesis_hash_sha256"`
	ReplayDomainID string `json:"replay_domain_id"`
}

type planSpec struct {
	Schema                    string       `json:"schema"`
	ExperimentPlanID          string       `json:"experiment_plan_id"`
	CapabilityID              string       `json:"capability_id"`
	Component                 string       `json:"component"`
	OwnerIdentity             string       `json:"owner_identity"`
	SoftwareVersion           string       `json:"software_version"`
	HardwareScope             []string     `json:"hardware_scope"`
	WorkloadScope             []string     `json:"workload_scope"`
	RegionScope               []string     `json:"region_scope"`
	CollectionNotBefore       string       `json:"collection_not_before"`
	ObservationWindowNanos    uint64       `json:"observation_window_nanos"`
	MinimumSampleSize         uint64       `json:"minimum_sample_size"`
	ConfidenceLevelBasisPoint uint32       `json:"confidence_level_basis_points"`
	ConfidenceMethod          uint32       `json:"confidence_method"`
	ExpiresAt                 string       `json:"expires_at"`
	FrozenAt                  string       `json:"frozen_at"`
	ApproverIdentity          string       `json:"approver_identity"`
	PolicySHA256              string       `json:"policy_sha256"`
	Boundary                  boundarySpec `json:"ccse_boundary"`
}

type sbomComponentSpec struct {
	SPDXID           string `json:"spdx_id"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	DownloadLocation string `json:"download_location"`
	Path             string `json:"path"`
}

type sbomSpec struct {
	Schema            string              `json:"schema"`
	Name              string              `json:"name"`
	DocumentNamespace string              `json:"document_namespace"`
	CreatedAt         string              `json:"created_at"`
	Creator           string              `json:"creator"`
	OutputPath        string              `json:"output_path"`
	Components        []sbomComponentSpec `json:"components"`
}

type artifactInput struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
}

type checkInput struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
	Log       string `json:"log"`
}

type ciInput struct {
	Repository        string `json:"repository"`
	WorkflowRef       string `json:"workflow_ref"`
	WorkflowSHA256    string `json:"workflow_sha256"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
	SourceCommit      string `json:"source_commit"`
	SourceTreeSHA256  string `json:"source_tree_sha256"`
	RunnerEnvironment string `json:"runner_environment"`
	ProvenanceBundle  string `json:"provenance_bundle"`
	VerificationLog   string `json:"provenance_verification_log"`
}

type rollbackInput struct {
	Status               string `json:"status"`
	PlanID               string `json:"plan_id"`
	StartedAt            string `json:"started_at"`
	EndedAt              string `json:"ended_at"`
	FromArtifactSHA256   string `json:"from_artifact_sha256"`
	TargetArtifactSHA256 string `json:"target_artifact_sha256"`
	Log                  string `json:"log"`
}

type bundleSpec struct {
	Schema           string           `json:"schema"`
	EvidenceID       string           `json:"evidence_id"`
	CapabilityID     string           `json:"capability_id"`
	Component        string           `json:"component"`
	SoftwareVersion  string           `json:"software_version"`
	CreatedAt        string           `json:"created_at"`
	ExpiresAt        string           `json:"expires_at"`
	ApprovingRole    string           `json:"approving_role"`
	ApproverIdentity string           `json:"approver_identity"`
	PolicySHA256     string           `json:"policy_sha256"`
	SBOMNamespace    string           `json:"sbom_namespace"`
	CI               ciInput          `json:"ci_identity"`
	Images           []gate0.OCIImage `json:"images"`
	Artifacts        []artifactInput  `json:"artifacts"`
	Checks           []checkInput     `json:"checks"`
	Rollback         rollbackInput    `json:"rollback_drill"`
	Boundary         boundarySpec     `json:"ccse_boundary"`
}

type verifySpec struct {
	Schema                   string           `json:"schema"`
	Now                      string           `json:"now"`
	RequirePassed            bool             `json:"require_passed"`
	ExpectedSourceCommit     string           `json:"expected_source_commit"`
	ExpectedRepository       string           `json:"expected_repository"`
	ExpectedWorkflowRef      string           `json:"expected_workflow_ref"`
	ExpectedOCIIndexDigest   string           `json:"expected_oci_index_digest"`
	ExpectedPlatformManifest string           `json:"expected_platform_manifest_digest"`
	ExpectedImages           []gate0.OCIImage `json:"expected_images"`
	ExpectedSBOMNamespace    string           `json:"expected_sbom_namespace"`
	ExperimentPlanID         string           `json:"experiment_plan_id"`
	CapabilityID             string           `json:"capability_id"`
	Component                string           `json:"component"`
	SoftwareVersion          string           `json:"software_version"`
	ApproverIdentity         string           `json:"approver_identity"`
	Boundary                 boundarySpec     `json:"ccse_boundary"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gate0-evidence: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("command is required: plan, sbom, source-archive, sign-file, verify-file, bundle, or verify")
	}
	switch args[0] {
	case "plan":
		return runPlan(args[1:])
	case "sbom":
		return runSBOM(args[1:])
	case "bundle":
		return runBundle(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "source-archive":
		return runSourceArchive(args[1:])
	case "sign-file":
		return runSignFile(args[1:])
	case "verify-file":
		return runVerifyFile(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runSignFile(args []string) error {
	flags := flag.NewFlagSet("sign-file", flag.ContinueOnError)
	inputPath := flags.String("in", "", "regular artifact path")
	privatePath := flags.String("private-key", "", "raw 64-byte Ed25519 private key")
	publicPath := flags.String("public-key", "", "raw 32-byte Ed25519 public key")
	outputPath := flags.String("out", "", "new raw detached signature path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *inputPath == "" || *privatePath == "" || *publicPath == "" || *outputPath == "" {
		return errors.New("sign-file requires -in, -private-key, -public-key, and -out")
	}
	input, err := readRegular(*inputPath, maxArtifactBytes)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := readKeyPair(*privatePath, *publicPath)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(privateKey, input)
	if !ed25519.Verify(publicKey, input, signature) {
		return errors.New("internal detached signature verification failed")
	}
	return writeNew(*outputPath, signature, 0o600)
}

func runVerifyFile(args []string) error {
	flags := flag.NewFlagSet("verify-file", flag.ContinueOnError)
	inputPath := flags.String("in", "", "regular artifact path")
	signaturePath := flags.String("signature", "", "raw 64-byte Ed25519 signature")
	publicPath := flags.String("public-key", "", "trusted raw 32-byte Ed25519 public key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *inputPath == "" || *signaturePath == "" || *publicPath == "" {
		return errors.New("verify-file requires -in, -signature, and -public-key")
	}
	input, err := readRegular(*inputPath, maxArtifactBytes)
	if err != nil {
		return err
	}
	signature, err := readRegular(*signaturePath, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid raw Ed25519 signature")
	}
	publicKey, err := readRegular(*publicPath, ed25519.PublicKeySize)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid raw Ed25519 public key")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), input, signature) {
		return errors.New("detached file signature verification failed")
	}
	fmt.Printf("verified_file_sha256=sha256:%x\n", sha256.Sum256(input))
	return nil
}

func runSourceArchive(args []string) error {
	flags := flag.NewFlagSet("source-archive", flag.ContinueOnError)
	root := flags.String("root", "", "source tree root")
	listPath := flags.String("list", "", "sorted newline-delimited source paths")
	outputPath := flags.String("out", "", "new deterministic tar path")
	epoch := flags.Int64("epoch", -1, "source commit Unix epoch")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *root == "" || *listPath == "" || *outputPath == "" || *epoch < 0 {
		return errors.New("source-archive requires -root, -list, -out, and nonnegative -epoch")
	}
	list, err := readRegular(*listPath, maxInputBytes)
	if err != nil {
		return err
	}
	if len(list) == 0 || list[len(list)-1] != '\n' {
		return errors.New("source list must be nonempty and newline terminated")
	}
	paths := strings.Split(string(list[:len(list)-1]), "\n")
	if !sort.StringsAreSorted(paths) {
		return errors.New("source list is not sorted")
	}
	for index, path := range paths {
		if !safeRelative(path) || (index > 0 && path == paths[index-1]) {
			return fmt.Errorf("invalid source list path %q", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(*outputPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create source archive: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(*outputPath)
		}
	}()
	writer := tar.NewWriter(file)
	stamp := time.Unix(*epoch, 0).UTC()
	for _, relative := range paths {
		data, err := readRegular(filepath.Join(*root, filepath.FromSlash(relative)), maxArtifactBytes)
		if err != nil {
			_ = writer.Close()
			return err
		}
		header := &tar.Header{Name: relative, Mode: 0o644, Size: int64(len(data)), ModTime: stamp,
			AccessTime: time.Unix(0, 0).UTC(), ChangeTime: time.Unix(0, 0).UTC(), Uid: 0, Gid: 0,
			Uname: "", Gname: "", Format: tar.FormatPAX}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func runPlan(args []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	specPath := flags.String("spec", "", "strict JSON plan specification")
	privatePath := flags.String("private-key", "", "raw 64-byte Ed25519 private key")
	publicPath := flags.String("public-key", "", "raw 32-byte Ed25519 public key")
	outputPath := flags.String("out", "", "new retained CCSE plan path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *specPath == "" || *privatePath == "" || *publicPath == "" || *outputPath == "" {
		return errors.New("plan requires -spec, -private-key, -public-key, and -out")
	}
	var spec planSpec
	if err := readStrictJSON(*specPath, &spec); err != nil {
		return err
	}
	if spec.Schema != planInputSchema || spec.ExperimentPlanID != "gate0-release-plan-v1" {
		return errors.New("invalid Gate 0 plan schema or plan ID")
	}
	privateKey, publicKey, err := readKeyPair(*privatePath, *publicPath)
	if err != nil {
		return err
	}
	frozen, err := parseTime("frozen_at", spec.FrozenAt)
	if err != nil {
		return err
	}
	notBefore, err := parseTime("collection_not_before", spec.CollectionNotBefore)
	if err != nil {
		return err
	}
	expires, err := parseTime("expires_at", spec.ExpiresAt)
	if err != nil {
		return err
	}
	policyDigest, err := parseDigest(spec.PolicySHA256)
	if err != nil {
		return fmt.Errorf("policy digest: %w", err)
	}
	metadata := metadataProjection(spec.ExperimentPlanID+"-record", frozen, policyDigest,
		"plan:"+spec.ExperimentPlanID+":"+spec.SoftwareVersion)
	criteria := make([]foundationv1.MetricCriterionSigningProjection, 0, len(gate0.RequiredCheckIDs()))
	for _, check := range gate0.RequiredCheckIDs() {
		criteria = append(criteria, foundationv1.MetricCriterionSigningProjection{MetricID: "gate0." + check + ".passed",
			Comparison: 3, ThresholdNumerator: 1, ThresholdDenominator: 1, Unit: "boolean", MinimumMetricSampleSize: 1})
	}
	plan := foundationv1.ExperimentPlanSigningProjection{Metadata: metadata, ExperimentPlanID: spec.ExperimentPlanID,
		CapabilityID: spec.CapabilityID, Component: spec.Component, OwnerIdentity: spec.OwnerIdentity,
		SoftwareVersion: spec.SoftwareVersion, HardwareScope: spec.HardwareScope, WorkloadScope: spec.WorkloadScope,
		RegionScope: spec.RegionScope, CollectionNotBeforeUnixNano: notBefore.UnixNano(),
		ObservationWindowNanos: spec.ObservationWindowNanos, MinimumSampleSize: spec.MinimumSampleSize,
		ConfidenceLevelBasisPoints: spec.ConfidenceLevelBasisPoint, ConfidenceMethod: spec.ConfidenceMethod,
		Criteria: criteria, RevalidationTriggers: revalidationTriggers(), ExpiresAtUnixNano: expires.UnixNano(),
		ExperimentPolicyDigestSHA256: policyDigest, TargetLevel: 3, FrozenAtUnixNano: frozen.UnixNano(),
		ApprovingIdentities: []string{spec.ApproverIdentity}}
	domain, envelope, err := ccseBoundary(spec.Boundary, "evidence.experiment.plan.freeze", frozen, expires, 1,
		"plan:"+spec.ExperimentPlanID+":"+spec.SoftwareVersion)
	if err != nil {
		return err
	}
	signed, err := gate0.BuildSignedFoundationPlan(plan, domain, envelope, privateKey)
	if err != nil {
		return err
	}
	policy := planPolicy(spec.ExperimentPlanID, spec.CapabilityID, spec.Component, spec.SoftwareVersion,
		spec.ApproverIdentity, spec.Boundary)
	if err := gate0.VerifySignedFoundationPlanForPolicy(signed, publicKey, policy); err != nil {
		return err
	}
	retained, err := gate0.MarshalRetainedRecord(signed.Record)
	if err != nil {
		return err
	}
	return writeNew(*outputPath, retained, 0o600)
}

func runSBOM(args []string) error {
	flags := flag.NewFlagSet("sbom", flag.ContinueOnError)
	specPath := flags.String("spec", "", "strict JSON SBOM specification")
	root := flags.String("root", "", "payload directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *specPath == "" || *root == "" {
		return errors.New("sbom requires -spec and -root")
	}
	var spec sbomSpec
	if err := readStrictJSON(*specPath, &spec); err != nil {
		return err
	}
	if spec.Schema != sbomInputSchema || !safeRelative(spec.OutputPath) {
		return errors.New("invalid SBOM schema or output path")
	}
	created, err := parseTime("created_at", spec.CreatedAt)
	if err != nil {
		return err
	}
	components := make([]gate0.SBOMComponent, 0, len(spec.Components))
	for _, component := range spec.Components {
		if !safeRelative(component.Path) {
			return fmt.Errorf("unsafe SBOM component path %q", component.Path)
		}
		_, digest, err := fileIdentity(filepath.Join(*root, filepath.FromSlash(component.Path)))
		if err != nil {
			return err
		}
		components = append(components, gate0.SBOMComponent{SPDXID: component.SPDXID, Name: component.Name,
			Version: component.Version, DownloadLocation: component.DownloadLocation, SHA256: strings.TrimPrefix(digest, gate0.DigestPrefix)})
	}
	data, err := gate0.GenerateSPDX(gate0.SBOMInput{Name: spec.Name, DocumentNamespace: spec.DocumentNamespace,
		CreatedAt: created, Creator: spec.Creator, Components: components})
	if err != nil {
		return err
	}
	if _, err := gate0.VerifySPDX(data, spec.DocumentNamespace); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(*root, filepath.FromSlash(spec.OutputPath)), data, 0o600); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	fmt.Printf("verified_spdx_namespace=%s sha256=sha256:%x components=%d\n",
		spec.DocumentNamespace, digest, len(components))
	return nil
}

func runBundle(args []string) error {
	flags := flag.NewFlagSet("bundle", flag.ContinueOnError)
	specPath := flags.String("spec", "", "strict JSON bundle specification")
	root := flags.String("root", "", "bundle root")
	privatePath := flags.String("private-key", "", "raw 64-byte Ed25519 private key")
	publicPath := flags.String("public-key", "", "raw 32-byte Ed25519 public key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *specPath == "" || *root == "" || *privatePath == "" || *publicPath == "" {
		return errors.New("bundle requires -spec, -root, -private-key, and -public-key")
	}
	var spec bundleSpec
	if err := readStrictJSON(*specPath, &spec); err != nil {
		return err
	}
	if spec.Schema != bundleInputSchema {
		return errors.New("invalid bundle input schema")
	}
	privateKey, publicKey, err := readKeyPair(*privatePath, *publicPath)
	if err != nil {
		return err
	}
	payloadRoot := filepath.Join(*root, payloadDirectoryName)
	manifest, err := materializeManifest(payloadRoot, spec)
	if err != nil {
		return err
	}
	manifest, canonical, signature, err := gate0.SignArtifactManifest(manifest, spec.Boundary.SignatureKeyID,
		manifestSignatureName, publicKey, privateKey)
	if err != nil {
		return err
	}
	planData, err := readRegular(filepath.Join(*root, planFileName), maxInputBytes)
	if err != nil {
		return err
	}
	signedPlan, err := gate0.DecodeRetainedFoundationPlan(planData)
	if err != nil {
		return err
	}
	planPolicyValue := planPolicy("gate0-release-plan-v1", manifest.CapabilityID, manifest.Component,
		manifest.SoftwareVersion, manifest.ApproverIdentity, spec.Boundary)
	if err := gate0.VerifySignedFoundationPlanForManifest(signedPlan, manifest, publicKey, planPolicyValue); err != nil {
		return err
	}
	created, err := parseTime("created_at", spec.CreatedAt)
	if err != nil {
		return err
	}
	expires, err := parseTime("expires_at", spec.ExpiresAt)
	if err != nil {
		return err
	}
	policyDigest, err := parseDigest(spec.PolicySHA256)
	if err != nil {
		return fmt.Errorf("policy digest: %w", err)
	}
	payload, err := gate0.CanonicalPayload(manifest)
	if err != nil {
		return err
	}
	manifestDigest := sha256.Sum256(payload)
	metadata := metadataProjection(manifest.EvidenceID+"-record", created, manifestDigest,
		"evidence:"+manifest.EvidenceID+":"+hex.EncodeToString(policyDigest[:]))
	metadata.PolicyDigestsSHA256 = [][32]byte{policyDigest}
	counter, err := strconv.ParseUint(manifest.CI.RunAttempt, 10, 64)
	if err != nil || counter == 0 {
		return errors.New("run_attempt must be a positive decimal counter")
	}
	domain, envelope, err := ccseBoundary(spec.Boundary, "evidence.record.release", created, expires, counter,
		"evidence:"+manifest.EvidenceID)
	if err != nil {
		return err
	}
	signedEvidence, err := gate0.BuildSignedFoundationEvidenceForPlan(manifest, signedPlan.Projection.ExperimentPlanID,
		metadata, domain, envelope, privateKey)
	if err != nil {
		return err
	}
	evidencePolicyValue := evidencePolicy("gate0-release-plan-v1", manifest.CapabilityID, manifest.Component,
		manifest.SoftwareVersion, manifest.ApproverIdentity, spec.Boundary)
	if err := verifyFoundationCandidate(manifest, signedEvidence, publicKey, evidencePolicyValue); err != nil {
		return err
	}
	retainedEvidence, err := gate0.MarshalRetainedRecord(signedEvidence.Record)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(payloadRoot, manifestSignatureName), signature, 0o600); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(payloadRoot, manifestFileName), canonical, 0o600); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(*root, evidenceFileName), retainedEvidence, 0o600); err != nil {
		return err
	}
	options := gate0.VerifyOptions{Now: created, ExpectedSourceCommit: manifest.CI.SourceCommit,
		ExpectedRepository: manifest.CI.Repository, ExpectedWorkflowRef: manifest.CI.WorkflowRef,
		ExpectedOCIIndexDigest: manifest.Images[0].IndexDigest, ExpectedPlatformManifest: manifest.Images[0].PlatformManifestDigest,
		ExpectedSBOMNamespace: spec.SBOMNamespace, PublicKeyPath: *publicPath, RequirePassed: manifest.Status == "PASSED",
		RequireRollback: manifest.Status == "PASSED", RejectUnreferencedRegulars: true}
	options.ExpectedImages = append([]gate0.OCIImage(nil), manifest.Images...)
	if _, err := gate0.VerifyDirectory(payloadRoot, options); err != nil {
		return err
	}
	fmt.Printf("bundle_status=%s\n", manifest.Status)
	return nil
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	specPath := flags.String("spec", "", "strict external verification policy")
	root := flags.String("root", "", "bundle root")
	publicPath := flags.String("public-key", "", "trusted raw 32-byte Ed25519 public key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *specPath == "" || *root == "" || *publicPath == "" {
		return errors.New("verify requires -spec, -root, and -public-key")
	}
	var spec verifySpec
	if err := readStrictJSON(*specPath, &spec); err != nil {
		return err
	}
	if spec.Schema != verifyInputSchema || spec.ExperimentPlanID != "gate0-release-plan-v1" {
		return errors.New("invalid verification policy schema or plan ID")
	}
	publicData, err := readRegular(*publicPath, ed25519.PublicKeySize)
	if err != nil || len(publicData) != ed25519.PublicKeySize {
		return errors.New("invalid trusted raw Ed25519 public key")
	}
	publicKey := ed25519.PublicKey(publicData)
	now, err := parseTime("now", spec.Now)
	if err != nil {
		return err
	}
	payloadRoot := filepath.Join(*root, payloadDirectoryName)
	manifest, err := gate0.VerifyDirectory(payloadRoot, gate0.VerifyOptions{Now: now,
		ExpectedSourceCommit: spec.ExpectedSourceCommit, ExpectedRepository: spec.ExpectedRepository,
		ExpectedWorkflowRef: spec.ExpectedWorkflowRef, ExpectedOCIIndexDigest: spec.ExpectedOCIIndexDigest,
		ExpectedPlatformManifest: spec.ExpectedPlatformManifest, ExpectedSBOMNamespace: spec.ExpectedSBOMNamespace,
		ExpectedImages: spec.ExpectedImages,
		PublicKeyPath:  *publicPath, RequirePassed: spec.RequirePassed, RequireRollback: spec.RequirePassed,
		RejectUnreferencedRegulars: true})
	if err != nil {
		return err
	}
	if manifest.CapabilityID != spec.CapabilityID || manifest.Component != spec.Component ||
		manifest.SoftwareVersion != spec.SoftwareVersion || manifest.ApproverIdentity != spec.ApproverIdentity {
		return errors.New("manifest does not match external verification policy")
	}
	planData, err := readRegular(filepath.Join(*root, planFileName), maxInputBytes)
	if err != nil {
		return err
	}
	evidenceData, err := readRegular(filepath.Join(*root, evidenceFileName), maxInputBytes)
	if err != nil {
		return err
	}
	signedPlan, err := gate0.DecodeRetainedFoundationPlan(planData)
	if err != nil {
		return err
	}
	signedEvidence, err := gate0.DecodeRetainedFoundationEvidence(evidenceData)
	if err != nil {
		return err
	}
	if err := gate0.VerifySignedFoundationPlanForManifest(signedPlan, manifest, publicKey,
		planPolicy(spec.ExperimentPlanID, spec.CapabilityID, spec.Component, spec.SoftwareVersion,
			spec.ApproverIdentity, spec.Boundary)); err != nil {
		return err
	}
	evidencePolicyValue := evidencePolicy(spec.ExperimentPlanID, spec.CapabilityID, spec.Component, spec.SoftwareVersion,
		spec.ApproverIdentity, spec.Boundary)
	if err := verifyFoundationCandidate(manifest, signedEvidence, publicKey, evidencePolicyValue); err != nil {
		return err
	}
	if spec.RequirePassed {
		if err := gate0.VerifySignedFoundationEvidenceForManifest(manifest, signedEvidence, publicKey, evidencePolicyValue); err != nil {
			return err
		}
	}
	if err := verifyBundleRoot(*root); err != nil {
		return err
	}
	fmt.Printf("verified_bundle_status=%s\n", manifest.Status)
	return nil
}

func materializeManifest(payloadRoot string, spec bundleSpec) (gate0.ArtifactManifest, error) {
	artifacts := make([]gate0.Artifact, 0, len(spec.Artifacts))
	for _, input := range spec.Artifacts {
		if !safeRelative(input.Path) {
			return gate0.ArtifactManifest{}, fmt.Errorf("unsafe artifact path %q", input.Path)
		}
		size, digest, err := fileIdentity(filepath.Join(payloadRoot, filepath.FromSlash(input.Path)))
		if err != nil {
			return gate0.ArtifactManifest{}, err
		}
		artifacts = append(artifacts, gate0.Artifact{Name: input.Name, Path: input.Path, MediaType: input.MediaType,
			SHA256: digest, Size: size})
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	checks := make([]gate0.Check, 0, len(spec.Checks))
	allPassed := true
	for _, input := range spec.Checks {
		if !safeRelative(input.Log) {
			return gate0.ArtifactManifest{}, fmt.Errorf("unsafe check log path %q", input.Log)
		}
		_, digest, err := fileIdentity(filepath.Join(payloadRoot, filepath.FromSlash(input.Log)))
		if err != nil {
			return gate0.ArtifactManifest{}, err
		}
		checks = append(checks, gate0.Check{ID: input.ID, Status: input.Status, StartedAt: input.StartedAt,
			EndedAt: input.EndedAt, Log: input.Log, LogSHA256: digest})
		allPassed = allPassed && input.Status == "PASSED"
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	_, provenanceDigest, err := fileIdentity(filepath.Join(payloadRoot, filepath.FromSlash(spec.CI.ProvenanceBundle)))
	if err != nil {
		return gate0.ArtifactManifest{}, err
	}
	_, verificationDigest, err := fileIdentity(filepath.Join(payloadRoot, filepath.FromSlash(spec.CI.VerificationLog)))
	if err != nil {
		return gate0.ArtifactManifest{}, err
	}
	_, rollbackDigest, err := fileIdentity(filepath.Join(payloadRoot, filepath.FromSlash(spec.Rollback.Log)))
	if err != nil {
		return gate0.ArtifactManifest{}, err
	}
	status := "FAILED"
	if allPassed && spec.Rollback.Status == "PASSED" {
		status = "PASSED"
	}
	return gate0.ArtifactManifest{Schema: gate0.SchemaVersion, EvidenceID: spec.EvidenceID,
		CapabilityID: spec.CapabilityID, Component: spec.Component, SoftwareVersion: spec.SoftwareVersion,
		CreatedAt: spec.CreatedAt, ExpiresAt: spec.ExpiresAt, ApprovingRole: spec.ApprovingRole,
		ApproverIdentity: spec.ApproverIdentity, Status: status,
		CI: gate0.CIIdentity{Provider: "github-actions", Repository: spec.CI.Repository,
			WorkflowRef: spec.CI.WorkflowRef, WorkflowSHA256: spec.CI.WorkflowSHA256, RunID: spec.CI.RunID,
			RunAttempt: spec.CI.RunAttempt, SourceCommit: spec.CI.SourceCommit, SourceTreeSHA256: spec.CI.SourceTreeSHA256,
			RunnerEnvironment: spec.CI.RunnerEnvironment, ProvenanceBundle: spec.CI.ProvenanceBundle,
			ProvenanceSHA256: provenanceDigest, VerificationLog: spec.CI.VerificationLog,
			VerificationSHA256: verificationDigest},
		Images: spec.Images, Artifacts: artifacts, Checks: checks,
		Rollback: gate0.RollbackDrill{Status: spec.Rollback.Status, PlanID: spec.Rollback.PlanID,
			StartedAt: spec.Rollback.StartedAt, EndedAt: spec.Rollback.EndedAt,
			FromArtifactSHA256:   spec.Rollback.FromArtifactSHA256,
			TargetArtifactSHA256: spec.Rollback.TargetArtifactSHA256,
			Log:                  spec.Rollback.Log, LogSHA256: rollbackDigest}}, nil
}

func ccseBoundary(spec boundarySpec, purpose string, issued, expires time.Time, counter uint64, seed string) (ccse.Domain, ccse.Envelope, error) {
	chain, err := parseDigest(spec.ChainIDSHA256)
	if err != nil {
		return ccse.Domain{}, ccse.Envelope{}, fmt.Errorf("chain ID: %w", err)
	}
	genesis, err := parseDigest(spec.GenesisSHA256)
	if err != nil {
		return ccse.Domain{}, ccse.Envelope{}, fmt.Errorf("genesis hash: %w", err)
	}
	if strings.TrimSpace(spec.SenderIdentity) == "" || strings.TrimSpace(spec.Audience) == "" ||
		strings.TrimSpace(spec.Environment) == "" || strings.TrimSpace(spec.SignatureKeyID) == "" ||
		strings.TrimSpace(spec.ReplayDomainID) == "" || counter == 0 {
		return ccse.Domain{}, ccse.Envelope{}, errors.New("incomplete CCSE boundary")
	}
	version := ccse.Version{Major: 1}
	replayDomain := derivedReplayDomain(spec.ReplayDomainID, purpose)
	domain := ccse.Domain{Purpose: purpose, SenderIdentity: spec.SenderIdentity, Audience: []string{spec.Audience},
		ChainID: chain, GenesisHash: genesis, Environment: spec.Environment, ProtocolVersion: version,
		SchemaVersion: version, SignatureAlgorithm: ccse.SignatureAlgorithmEd25519, SignatureKeyID: spec.SignatureKeyID,
		IssuedAtUnixNano: issued.UnixNano(), ExpiresAtUnixNano: expires.UnixNano(), CounterKind: ccse.CounterSequence,
		Counter: counter, ReplayDomainID: replayDomain}
	message := sha256.Sum256([]byte("gate0:message:" + purpose + ":" + seed))
	correlation := sha256.Sum256([]byte("gate0:correlation:" + seed))
	envelope := ccse.Envelope{ProtocolVersion: version, SchemaVersion: version, SenderIdentity: spec.SenderIdentity,
		ChainID: chain, Environment: spec.Environment, IssuedAtUnixNano: issued.UnixNano(), ExpiresAtUnixNano: expires.UnixNano(),
		CounterKind: ccse.CounterSequence, Counter: counter, SignatureAlgorithm: ccse.SignatureAlgorithmEd25519,
		SignatureKeyID: spec.SignatureKeyID}
	copy(envelope.MessageID[:], message[:len(envelope.MessageID)])
	copy(envelope.CorrelationID[:], correlation[:len(envelope.CorrelationID)])
	return domain, envelope, nil
}

func metadataProjection(recordID string, created time.Time, integrity [32]byte, seed string) foundationv1.RecordMetadataSigningProjection {
	idempotencyDigest := sha256.Sum256([]byte("gate0:idempotency:" + seed))
	var idempotency [16]byte
	copy(idempotency[:], idempotencyDigest[:len(idempotency)])
	return foundationv1.RecordMetadataSigningProjection{SchemaVersion: foundationv1.SchemaVersionSigningProjection{Major: 1},
		RecordID: recordID, CreatedAtUnixNano: created.UnixNano(), IntegrityDigest: integrity, HomeRegion: "global",
		WriterEpoch: 1, StateVersion: 1, IdempotencyKey: idempotency, PolicyDigestsSHA256: [][32]byte{integrity}}
}

func planPolicy(planID, capability, component, software, approver string, boundary boundarySpec) gate0.FoundationPlanPolicy {
	chain, chainErr := parseDigest(boundary.ChainIDSHA256)
	genesis, genesisErr := parseDigest(boundary.GenesisSHA256)
	if chainErr != nil || genesisErr != nil {
		return gate0.FoundationPlanPolicy{}
	}
	return gate0.FoundationPlanPolicy{ExperimentPlanID: planID, CapabilityID: capability, Component: component,
		SoftwareVersion: software, Purpose: "evidence.experiment.plan.freeze", Audience: boundary.Audience,
		Environment: boundary.Environment, SignatureKeyID: boundary.SignatureKeyID, ApproverIdentity: approver,
		SenderIdentity: boundary.SenderIdentity, ChainID: chain, GenesisHash: genesis,
		ReplayDomainID: derivedReplayDomain(boundary.ReplayDomainID, "evidence.experiment.plan.freeze")}
}

func evidencePolicy(planID, capability, component, software, approver string, boundary boundarySpec) gate0.FoundationEvidencePolicy {
	chain, chainErr := parseDigest(boundary.ChainIDSHA256)
	genesis, genesisErr := parseDigest(boundary.GenesisSHA256)
	if chainErr != nil || genesisErr != nil {
		return gate0.FoundationEvidencePolicy{}
	}
	return gate0.FoundationEvidencePolicy{ExperimentPlanID: planID, CapabilityID: capability, Component: component,
		SoftwareVersion: software, Purpose: "evidence.record.release", Audience: boundary.Audience,
		Environment: boundary.Environment, SignatureKeyID: boundary.SignatureKeyID, ApproverIdentity: approver,
		SenderIdentity: boundary.SenderIdentity, ChainID: chain, GenesisHash: genesis,
		ReplayDomainID: derivedReplayDomain(boundary.ReplayDomainID, "evidence.record.release")}
}

func derivedReplayDomain(base, purpose string) string {
	if purpose == "evidence.experiment.plan.freeze" {
		return base + ":plan"
	}
	return base + ":evidence"
}

func verifyFoundationCandidate(manifest gate0.ArtifactManifest, evidence gate0.SignedFoundationEvidence,
	publicKey ed25519.PublicKey, policy gate0.FoundationEvidencePolicy) error {
	if manifest.Status == "PASSED" {
		return gate0.VerifySignedFoundationEvidenceForManifest(manifest, evidence, publicKey, policy)
	}
	return gate0.VerifySignedFoundationEvidenceCandidateForManifest(manifest, evidence, publicKey, policy)
}

func revalidationTriggers() []string {
	return []string{"artifact-change", "dependency-change", "signing-key-rotation", "workflow-change"}
}

func parseDigest(value string) ([32]byte, error) {
	var out [32]byte
	if !strings.HasPrefix(value, gate0.DigestPrefix) || len(value) != len(gate0.DigestPrefix)+64 {
		return out, errors.New("expected sha256:<64 lowercase hex>")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, gate0.DigestPrefix))
	if err != nil || hex.EncodeToString(decoded) != strings.TrimPrefix(value, gate0.DigestPrefix) {
		return out, errors.New("expected sha256:<64 lowercase hex>")
	}
	copy(out[:], decoded)
	if out == ([32]byte{}) {
		return out, errors.New("zero digest is forbidden")
	}
	return out, nil
}

func parseTime(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 UTC: %q", name, value)
	}
	return parsed, nil
}

func readStrictJSON(path string, target any) error {
	data, err := readRegular(path, maxInputBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: trailing JSON", path)
	}
	return nil
}

func readKeyPair(privatePath, publicPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateData, err := readRegular(privatePath, ed25519.PrivateKeySize)
	if err != nil || len(privateData) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid raw Ed25519 private key")
	}
	publicData, err := readRegular(publicPath, ed25519.PublicKeySize)
	if err != nil || len(publicData) != ed25519.PublicKeySize {
		return nil, nil, errors.New("invalid raw Ed25519 public key")
	}
	privateKey, publicKey := ed25519.PrivateKey(privateData), ed25519.PublicKey(publicData)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return nil, nil, errors.New("Ed25519 public/private key mismatch")
	}
	return privateKey, publicKey, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, fmt.Errorf("missing, non-regular, or oversized file %q", path)
	}
	return os.ReadFile(path)
}

func fileIdentity(path string) (int64, string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxArtifactBytes {
		return 0, "", fmt.Errorf("missing, non-regular, or oversized artifact %q", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return 0, "", err
	}
	return info.Size(), gate0.DigestPrefix + hex.EncodeToString(digest.Sum(nil)), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create new %s: %w", path, err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func safeRelative(path string) bool {
	return path != "" && len(path) <= 1024 && path == filepath.ToSlash(path) && path == filepath.Clean(path) &&
		!filepath.IsAbs(path) && path != "." && path != ".." && !strings.HasPrefix(path, "../") && !strings.Contains(path, "\\")
}

func verifyBundleRoot(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	want := map[string]bool{payloadDirectoryName: false, planFileName: false, evidenceFileName: false}
	for _, entry := range entries {
		if _, ok := want[entry.Name()]; !ok {
			return fmt.Errorf("unreferenced bundle-root entry %q", entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink bundle-root entry %q", entry.Name())
		}
		if entry.Name() == payloadDirectoryName && !entry.IsDir() {
			return errors.New("payload is not a directory")
		}
		if entry.Name() != payloadDirectoryName && entry.Type().IsRegular() == false {
			return fmt.Errorf("non-regular bundle-root entry %q", entry.Name())
		}
		want[entry.Name()] = true
	}
	for name, seen := range want {
		if !seen {
			return fmt.Errorf("missing bundle-root entry %q", name)
		}
	}
	return nil
}
