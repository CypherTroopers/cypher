// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

//go:build solidity_conformance

package solidity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts/abi"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/vm"
	evmruntime "github.com/cypherium/cypher/core/vm/runtime"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
)

const (
	pinnedSolcArtifact = "solc-linux-amd64-v0.8.30+commit.73712a01"
	pinnedSolcVersion  = "0.8.30+commit.73712a01"
	pinnedSolcSHA256   = "f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7"
	pinnedSolcURL      = "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.30+commit.73712a01"

	harnessSource   = "CCSEEIP712BridgeHarness.sol"
	harnessContract = "CCSEEIP712BridgeHarnessV1"
)

type solcLock struct {
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}

type standardJSONProfile struct {
	Language string `json:"language"`
	Sources  map[string]struct {
		URLs []string `json:"urls"`
	} `json:"sources"`
	Settings struct {
		Optimizer struct {
			Enabled bool   `json:"enabled"`
			Runs    uint64 `json:"runs"`
		} `json:"optimizer"`
		EVMVersion string `json:"evmVersion"`
		ViaIR      bool   `json:"viaIR"`
		Metadata   struct {
			AppendCBOR        bool   `json:"appendCBOR"`
			BytecodeHash      string `json:"bytecodeHash"`
			UseLiteralContent bool   `json:"useLiteralContent"`
		} `json:"metadata"`
		OutputSelection map[string]map[string][]string `json:"outputSelection"`
	} `json:"settings"`
}

type standardJSONOutput struct {
	Contracts map[string]map[string]struct {
		ABI json.RawMessage `json:"abi"`
		EVM struct {
			Bytecode struct {
				Object string `json:"object"`
			} `json:"bytecode"`
			DeployedBytecode struct {
				Object string `json:"object"`
			} `json:"deployedBytecode"`
		} `json:"evm"`
	} `json:"contracts"`
	Errors []struct {
		Severity         string `json:"severity"`
		FormattedMessage string `json:"formattedMessage"`
	} `json:"errors"`
}

type compiledHarness struct {
	abi         abi.ABI
	runtimeCode []byte
}

type evmFinancialAuthorization struct {
	CcseRecordDigest     [32]byte
	FinancialOperationId [32]byte
	LeaseId              [32]byte
	ReceiptId            [32]byte
	SettlementId         [32]byte
	AssetId              [32]byte
	Payer                common.Address
	Payee                common.Address
	AmountSmallestUnit   *big.Int
	ExpectedGeneration   uint64
	ValidAfterUnix       uint64
	ValidBeforeUnix      uint64
}

func TestPinnedSolcCypherEVMConformance(t *testing.T) {
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get package directory: %v", err)
	}
	profileBytes, profile := loadAndVerifySolcProfile(t)
	solcPath := verifyPinnedSolc(t, packageDir)

	firstOutput := runSolc(t, solcPath, packageDir, profileBytes)
	secondOutput := runSolc(t, solcPath, packageDir, profileBytes)
	if !bytes.Equal(firstOutput, secondOutput) {
		t.Fatal("pinned solc standard-json output is not deterministic")
	}
	harness := parseCompiledHarness(t, firstOutput)
	if profile.Settings.EVMVersion != "paris" {
		t.Fatalf("unexpected EVM profile %q", profile.Settings.EVMVersion)
	}

	base := loadStrictJSON[bridgeVector](t, "eip712_bridge_vectors.json")
	executePositiveVectorInCypherEVM(t, harness, base)
	executeNegativeVectorsInCypherEVM(t, harness, base)
}

func loadAndVerifySolcProfile(t *testing.T) ([]byte, standardJSONProfile) {
	t.Helper()
	lock := loadStrictJSON[solcLock](t, "solc.lock.json")
	if lock.Artifact != pinnedSolcArtifact || lock.Version != pinnedSolcVersion ||
		lock.SHA256 != pinnedSolcSHA256 || lock.URL != pinnedSolcURL {
		t.Fatalf("solc lock does not match the reviewed compiler pin: %+v", lock)
	}

	profileBytes, err := os.ReadFile("solc_standard_json_profile.json")
	if err != nil {
		t.Fatalf("read solc standard-json profile: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(profileBytes))
	decoder.DisallowUnknownFields()
	var profile standardJSONProfile
	if err := decoder.Decode(&profile); err != nil {
		t.Fatalf("decode solc standard-json profile: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("solc standard-json profile has trailing data: %v", err)
	}
	if profile.Language != "Solidity" || len(profile.Sources) != 2 {
		t.Fatalf("unexpected solc language/source set: %q %+v", profile.Language, profile.Sources)
	}
	wantSources := map[string][]string{
		"CCSEEIP712Bridge.sol":        {"CCSEEIP712Bridge.sol"},
		"CCSEEIP712BridgeHarness.sol": {"CCSEEIP712BridgeHarness.sol"},
	}
	for name, urls := range wantSources {
		source, ok := profile.Sources[name]
		if !ok || !reflect.DeepEqual(source.URLs, urls) {
			t.Fatalf("unexpected solc source %q: %+v", name, source.URLs)
		}
	}
	wantOutput := map[string]map[string][]string{
		"*": {"*": {"abi", "evm.bytecode.object", "evm.deployedBytecode.object"}},
	}
	if !profile.Settings.Optimizer.Enabled || profile.Settings.Optimizer.Runs != 200 ||
		profile.Settings.EVMVersion != "paris" || profile.Settings.ViaIR ||
		profile.Settings.Metadata.AppendCBOR || profile.Settings.Metadata.BytecodeHash != "none" ||
		!profile.Settings.Metadata.UseLiteralContent ||
		!reflect.DeepEqual(profile.Settings.OutputSelection, wantOutput) {
		t.Fatalf("solc standard-json settings differ from the reviewed deterministic profile: %+v", profile.Settings)
	}
	return profileBytes, profile
}

func verifyPinnedSolc(t *testing.T, packageDir string) string {
	t.Helper()
	repoRoot := filepath.Clean(filepath.Join(packageDir, "../../.."))
	solcPath := filepath.Join(repoRoot, ".codex-tmp", "toolchains", pinnedSolcArtifact)
	linkInfo, err := os.Lstat(solcPath)
	if err != nil {
		t.Fatalf("locate pinned solc at %s (run ./fetch-solc.sh first): %v", solcPath, err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("pinned solc path must not be a symlink: %s", solcPath)
	}
	binary, err := os.ReadFile(solcPath)
	if err != nil {
		t.Fatalf("read pinned solc at %s (run ./fetch-solc.sh first): %v", solcPath, err)
	}
	digest := sha256.Sum256(binary)
	if got := hex.EncodeToString(digest[:]); got != pinnedSolcSHA256 {
		t.Fatalf("solc SHA-256 %s, want %s", got, pinnedSolcSHA256)
	}
	info, err := os.Stat(solcPath)
	if err != nil {
		t.Fatalf("stat pinned solc: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("pinned solc is not an executable regular file: %s", solcPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versionOutput, err := exec.CommandContext(ctx, solcPath, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("execute pinned solc --version: %v: %s", err, versionOutput)
	}
	wantVersionLine := "Version: " + pinnedSolcVersion + ".Linux.g++"
	if !strings.Contains(string(versionOutput), wantVersionLine) {
		t.Fatalf("unexpected solc version output %q, want line %q", versionOutput, wantVersionLine)
	}
	return solcPath
}

func runSolc(t *testing.T, solcPath, packageDir string, profile []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, solcPath, "--base-path", packageDir, "--standard-json")
	cmd.Stdin = bytes.NewReader(profile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("compile Solidity standard-json profile: %v: %s", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("pinned solc wrote unexpected stderr: %s", stderr.String())
	}
	return output
}

func parseCompiledHarness(t *testing.T, output []byte) compiledHarness {
	t.Helper()
	var compiled standardJSONOutput
	if err := json.Unmarshal(output, &compiled); err != nil {
		t.Fatalf("decode solc standard-json output: %v", err)
	}
	if len(compiled.Errors) != 0 {
		var diagnostics []string
		for _, diagnostic := range compiled.Errors {
			diagnostics = append(diagnostics, diagnostic.Severity+": "+diagnostic.FormattedMessage)
		}
		t.Fatalf("solc emitted diagnostics (fail closed): %s", strings.Join(diagnostics, "\n"))
	}
	bySource, ok := compiled.Contracts[harnessSource]
	if !ok {
		t.Fatalf("solc output lacks source %q", harnessSource)
	}
	contract, ok := bySource[harnessContract]
	if !ok {
		t.Fatalf("solc output lacks contract %q", harnessContract)
	}
	parsedABI, err := parseCypherCompatibleABI(contract.ABI)
	if err != nil {
		t.Fatalf("parse compiled harness ABI: %v", err)
	}
	for _, method := range []string{
		"domainSeparatorPure", "authorizationStructHashPure", "typedDataDigestPure", "verifyPure",
	} {
		if _, ok := parsedABI.Methods[method]; !ok {
			t.Fatalf("compiled harness ABI lacks %s", method)
		}
	}
	runtimeCode, err := hex.DecodeString(contract.EVM.DeployedBytecode.Object)
	if err != nil || len(runtimeCode) == 0 {
		t.Fatalf("decode compiled harness runtime bytecode: length=%d err=%v", len(runtimeCode), err)
	}
	creationCode, err := hex.DecodeString(contract.EVM.Bytecode.Object)
	if err != nil || len(creationCode) <= len(runtimeCode) {
		t.Fatalf("decode compiled harness creation bytecode: length=%d runtime=%d err=%v", len(creationCode), len(runtimeCode), err)
	}
	return compiledHarness{abi: parsedABI, runtimeCode: runtimeCode}
}

// Cypher's legacy ABI decoder predates Solidity custom-error ABI entries. The
// compiler output is still authoritative: validate the exact error set first,
// then remove only type=error entries before handing function entries to it.
func parseCypherCompatibleABI(raw json.RawMessage) (abi.ABI, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return abi.ABI{}, fmt.Errorf("decode ABI entries: %w", err)
	}
	wantErrors := map[string]bool{
		"InvalidAuthorization()":            false,
		"InvalidDomain()":                   false,
		"InvalidSignature()":                false,
		"UnexpectedSigner(address,address)": false,
	}
	functions := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		var header struct {
			Type   string `json:"type"`
			Name   string `json:"name"`
			Inputs []struct {
				Type string `json:"type"`
			} `json:"inputs"`
		}
		if err := json.Unmarshal(entry, &header); err != nil {
			return abi.ABI{}, fmt.Errorf("decode ABI entry: %w", err)
		}
		if header.Type != "error" {
			functions = append(functions, entry)
			continue
		}
		inputTypes := make([]string, len(header.Inputs))
		for i := range header.Inputs {
			inputTypes[i] = header.Inputs[i].Type
		}
		signature := header.Name + "(" + strings.Join(inputTypes, ",") + ")"
		seen, ok := wantErrors[signature]
		if !ok {
			return abi.ABI{}, fmt.Errorf("unexpected Solidity custom error %s", signature)
		}
		if seen {
			return abi.ABI{}, fmt.Errorf("duplicate Solidity custom error %s", signature)
		}
		wantErrors[signature] = true
	}
	for signature, seen := range wantErrors {
		if !seen {
			return abi.ABI{}, fmt.Errorf("compiled ABI lacks Solidity custom error %s", signature)
		}
	}
	functionJSON, err := json.Marshal(functions)
	if err != nil {
		return abi.ABI{}, fmt.Errorf("encode function-only ABI: %w", err)
	}
	return abi.JSON(bytes.NewReader(functionJSON))
}

func executePositiveVectorInCypherEVM(t *testing.T, harness compiledHarness, vector bridgeVector) {
	t.Helper()
	chainID := mustCanonicalUint(t, vector.Domain.ChainIDDecimal, 256)
	genesisHash := mustBytes32(t, vector.Domain.GenesisHashHex)
	authorization := mustEVMAuthorization(t, vector)

	assertEVMBytes32Result(t, harness, "domainSeparatorPure", vector.Expected.DomainSeparatorHex,
		vector.Domain.Name, vector.Domain.Version, chainID,
		common.HexToAddress(vector.Domain.VerifyingContract), genesisHash)
	assertEVMBytes32Result(t, harness, "authorizationStructHashPure", vector.Expected.AuthorizationStructHashHex,
		authorization)
	assertEVMBytes32Result(t, harness, "typedDataDigestPure", vector.Expected.EIP712SigningDigestHex,
		vector.Domain.Name, vector.Domain.Version, chainID,
		common.HexToAddress(vector.Domain.VerifyingContract), genesisHash, authorization)

	signature := mustVariableHex(t, vector.Expected.SignatureRSV27Hex)
	output, err := executeHarnessMethod(t, harness, "verifyPure",
		vector.Domain.Name, vector.Domain.Version, chainID,
		common.HexToAddress(vector.Domain.VerifyingContract), genesisHash, authorization,
		signature, common.HexToAddress(vector.ConformanceKey.ExpectedSigner), authorization.ValidAfterUnix)
	if err != nil {
		t.Fatalf("Cypher EVM rejected positive bridge vector: %v (return %x)", err, output)
	}
	if len(output) != 64 {
		t.Fatalf("verifyPure returned %d bytes, want 64", len(output))
	}
	assertHex(t, "Cypher EVM verified digest", output[:32], vector.Expected.EIP712SigningDigestHex, 32)
	wantSigner := common.HexToAddress(vector.ConformanceKey.ExpectedSigner)
	if gotSigner := common.BytesToAddress(output[32:64]); gotSigner != wantSigner {
		t.Fatalf("Cypher EVM recovered signer %s, want %s", gotSigner.Hex(), wantSigner.Hex())
	}
}

func executeNegativeVectorsInCypherEVM(t *testing.T, harness compiledHarness, base bridgeVector) {
	t.Helper()
	set := loadStrictJSON[negativeVectorSet](t, "eip712_bridge_negative.json")
	assertRequiredNegativeCaseSet(t, set.Cases)
	for _, tc := range set.Cases {
		t.Run("cypher-evm/"+tc.ID, func(t *testing.T) {
			vector := base
			signatureHex := base.Expected.SignatureRSV27Hex
			now := uint64(1_700_000_000)
			applyNegativeMutation(t, &vector, &signatureHex, &now, tc)

			chainID := mustCanonicalUint(t, vector.Domain.ChainIDDecimal, 256)
			genesisHash := mustBytes32(t, vector.Domain.GenesisHashHex)
			authorization := mustEVMAuthorization(t, vector)
			output, err := executeHarnessMethod(t, harness, "verifyPure",
				vector.Domain.Name, vector.Domain.Version, chainID,
				common.HexToAddress(vector.Domain.VerifyingContract), genesisHash, authorization,
				mustVariableHex(t, signatureHex), common.HexToAddress(vector.ConformanceKey.ExpectedSigner), now)
			if !errors.Is(err, vm.ErrExecutionReverted) {
				t.Fatalf("negative vector did not revert: err=%v return=%x", err, output)
			}
			wantSelector := expectedSolidityErrorSelector(t, tc.ExpectedError)
			if len(output) < 4 || !bytes.Equal(output[:4], wantSelector) {
				t.Fatalf("revert selector %x, want %x for %s", output, wantSelector, tc.ExpectedError)
			}
		})
	}
}

func applyNegativeMutation(t *testing.T, vector *bridgeVector, signatureHex *string, now *uint64, tc negativeCase) {
	t.Helper()
	switch tc.Operation {
	case "replace":
		if err := replaceVectorField(vector, tc.Path, tc.Value); err != nil {
			t.Fatal(err)
		}
	case "verify_at":
		if tc.Path != "verification.current_unix" {
			t.Fatalf("unexpected verify_at path %q", tc.Path)
		}
		*now = mustCanonicalUint(t, tc.Value, 64).Uint64()
	case "flip_signature_byte":
		assertSignaturePath(t, tc.Path)
		index, err := strconv.Atoi(tc.Value)
		if err != nil || index < 0 || index >= 65 {
			t.Fatalf("invalid signature byte index %q", tc.Value)
		}
		signature := mustVariableHex(t, *signatureHex)
		signature[index] ^= 1
		*signatureHex = hex.EncodeToString(signature)
	case "replace_signature_v":
		assertSignaturePath(t, tc.Path)
		value, err := strconv.ParseUint(tc.Value, 10, 8)
		if err != nil {
			t.Fatalf("parse signature v: %v", err)
		}
		signature := mustVariableHex(t, *signatureHex)
		signature[64] = byte(value)
		*signatureHex = hex.EncodeToString(signature)
	case "replace_signature_r":
		assertSignaturePath(t, tc.Path)
		*signatureHex = replaceSignatureComponent(t, *signatureHex, 0, tc.Value)
	case "replace_signature_s":
		assertSignaturePath(t, tc.Path)
		*signatureHex = replaceSignatureComponent(t, *signatureHex, 32, tc.Value)
	case "malleate_signature_high_s":
		assertSignaturePath(t, tc.Path)
		*signatureHex = malleateHighS(t, *signatureHex)
	case "truncate_signature":
		assertSignaturePath(t, tc.Path)
		length, err := strconv.Atoi(tc.Value)
		if err != nil || length < 0 || length >= 65 {
			t.Fatalf("invalid truncated signature length %q", tc.Value)
		}
		signature := mustVariableHex(t, *signatureHex)
		*signatureHex = hex.EncodeToString(signature[:length])
	default:
		t.Fatalf("unknown negative operation %q", tc.Operation)
	}
}

func mustEVMAuthorization(t *testing.T, vector bridgeVector) evmFinancialAuthorization {
	t.Helper()
	return evmFinancialAuthorization{
		CcseRecordDigest:     mustBytes32(t, vector.Authorization.CCSERecordDigestHex),
		FinancialOperationId: mustBytes32(t, vector.Authorization.FinancialOperationIDHex),
		LeaseId:              mustBytes32(t, vector.Authorization.LeaseIDHex),
		ReceiptId:            mustBytes32(t, vector.Authorization.ReceiptIDHex),
		SettlementId:         mustBytes32(t, vector.Authorization.SettlementIDHex),
		AssetId:              mustBytes32(t, vector.Authorization.AssetIDHex),
		Payer:                common.HexToAddress(vector.Authorization.Payer),
		Payee:                common.HexToAddress(vector.Authorization.Payee),
		AmountSmallestUnit:   mustCanonicalUint(t, vector.Authorization.AmountSmallestUnitDecimal, 256),
		ExpectedGeneration:   mustCanonicalUint(t, vector.Authorization.ExpectedGenerationDecimal, 64).Uint64(),
		ValidAfterUnix:       mustCanonicalUint(t, vector.Authorization.ValidAfterUnixDecimal, 64).Uint64(),
		ValidBeforeUnix:      mustCanonicalUint(t, vector.Authorization.ValidBeforeUnixDecimal, 64).Uint64(),
	}
}

func executeHarnessMethod(t *testing.T, harness compiledHarness, method string, args ...interface{}) ([]byte, error) {
	t.Helper()
	calldata, err := harness.abi.Pack(method, args...)
	if err != nil {
		t.Fatalf("ABI-pack %s: %v", method, err)
	}
	returnValue, _, err := evmruntime.Execute(harness.runtimeCode, calldata, &evmruntime.Config{
		ChainConfig: params.AllcolossusXProtocolChanges,
		Origin:      common.HexToAddress("0x000000000000000000000000000000000000c0de"),
		BlockNumber: big.NewInt(1),
		Time:        big.NewInt(1_700_000_000),
		GasLimit:    30_000_000,
	})
	return returnValue, err
}

func assertEVMBytes32Result(t *testing.T, harness compiledHarness, method, expected string, args ...interface{}) {
	t.Helper()
	output, err := executeHarnessMethod(t, harness, method, args...)
	if err != nil {
		t.Fatalf("Cypher EVM %s failed: %v (return %x)", method, err, output)
	}
	assertHex(t, "Cypher EVM "+method, output, expected, 32)
}

func expectedSolidityErrorSelector(t *testing.T, expected string) []byte {
	t.Helper()
	signature := ""
	switch expected {
	case "INVALID_AUTHORIZATION", "NOT_YET_VALID", "EXPIRED":
		signature = "InvalidAuthorization()"
	case "INVALID_SIGNATURE":
		signature = "InvalidSignature()"
	case "UNEXPECTED_SIGNER":
		signature = "UnexpectedSigner(address,address)"
	default:
		t.Fatalf("no Solidity custom-error mapping for %q", expected)
	}
	return crypto.Keccak256([]byte(signature))[:4]
}

func mustCanonicalUint(t *testing.T, value string, bits int) *big.Int {
	t.Helper()
	parsed, err := parseCanonicalUint(value, bits)
	if err != nil {
		t.Fatalf("parse canonical uint%d %q: %v", bits, value, err)
	}
	return parsed
}

func mustBytes32(t *testing.T, value string) [32]byte {
	t.Helper()
	decoded := mustDecodeHex(t, value, 32)
	var fixed [32]byte
	copy(fixed[:], decoded)
	return fixed
}

func mustVariableHex(t *testing.T, value string) []byte {
	t.Helper()
	if value != strings.ToLower(value) || len(value)%2 != 0 {
		t.Fatalf("want lowercase even-length unprefixed hex, got %q", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}
