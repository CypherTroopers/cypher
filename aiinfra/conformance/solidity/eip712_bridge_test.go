// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package solidity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
)

var (
	errInvalidAuthorization = errors.New("INVALID_AUTHORIZATION")
	errInvalidSignature     = errors.New("INVALID_SIGNATURE")
	errUnexpectedSigner     = errors.New("UNEXPECTED_SIGNER")
	errNotYetValid          = errors.New("NOT_YET_VALID")
	errExpired              = errors.New("EXPIRED")
)

const (
	frozenDomainType        = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
	frozenAuthorizationType = "CPHFinancialAuthorizationV1(bytes32 ccseRecordDigest,bytes32 financialOperationId,bytes32 leaseId,bytes32 receiptId,bytes32 settlementId,bytes32 assetId,address payer,address payee,uint256 amountSmallestUnit,uint64 expectedGeneration,uint64 validAfterUnix,uint64 validBeforeUnix)"
)

type bridgeVector struct {
	VectorID string `json:"vector_id"`
	Status   string `json:"status"`
	Profile  string `json:"profile"`
	CCSE     struct {
		VectorID              string `json:"vector_id"`
		SHA256RecordDigestHex string `json:"sha256_record_digest_hex"`
	} `json:"ccse_source"`
	Domain struct {
		TypeString        string `json:"type_string"`
		Name              string `json:"name"`
		Version           string `json:"version"`
		ChainIDDecimal    string `json:"chain_id_decimal"`
		VerifyingContract string `json:"verifying_contract"`
		GenesisHashHex    string `json:"genesis_hash_hex"`
	} `json:"domain"`
	Authorization struct {
		TypeString                string `json:"type_string"`
		CCSERecordDigestHex       string `json:"ccse_record_digest_hex"`
		FinancialOperationIDHex   string `json:"financial_operation_id_hex"`
		LeaseIDHex                string `json:"lease_id_hex"`
		ReceiptIDHex              string `json:"receipt_id_hex"`
		SettlementIDHex           string `json:"settlement_id_hex"`
		AssetIDHex                string `json:"asset_id_hex"`
		Payer                     string `json:"payer"`
		Payee                     string `json:"payee"`
		AmountSmallestUnitDecimal string `json:"amount_smallest_unit_decimal"`
		ExpectedGenerationDecimal string `json:"expected_generation_decimal"`
		ValidAfterUnixDecimal     string `json:"valid_after_unix_decimal"`
		ValidBeforeUnixDecimal    string `json:"valid_before_unix_decimal"`
	} `json:"authorization"`
	ConformanceKey struct {
		PrivateKeyHex  string `json:"private_key_hex"`
		ExpectedSigner string `json:"expected_signer"`
	} `json:"conformance_key"`
	Expected struct {
		DomainTypeHashHex          string `json:"domain_type_hash_hex"`
		AuthorizationTypeHashHex   string `json:"authorization_type_hash_hex"`
		DomainSeparatorHex         string `json:"domain_separator_hex"`
		AuthorizationStructHashHex string `json:"authorization_struct_hash_hex"`
		EIP712SigningDigestHex     string `json:"eip712_signing_digest_hex"`
		SignatureRSV27Hex          string `json:"signature_rsv_27_hex"`
	} `json:"expected"`
}

type negativeVectorSet struct {
	VectorSetID  string         `json:"vector_set_id"`
	BaseVectorID string         `json:"base_vector_id"`
	Status       string         `json:"status"`
	Cases        []negativeCase `json:"cases"`
}

type negativeCase struct {
	ID            string `json:"id"`
	Operation     string `json:"operation"`
	Path          string `json:"path"`
	Value         string `json:"value"`
	ExpectedError string `json:"expected_error"`
}

var requiredNegativeCaseIDs = [...]string{
	"wrong-chain", "wrong-contract", "wrong-name", "wrong-version", "wrong-genesis",
	"wrong-ccse-digest", "wrong-financial-operation-id", "wrong-lease-id", "wrong-receipt-id",
	"wrong-settlement-id", "wrong-asset-id", "wrong-payer", "wrong-payee", "wrong-amount",
	"wrong-generation", "zero-financial-operation-id", "not-yet-valid", "expired", "invalid-window",
	"signature-bitflip", "signature-invalid-v", "signature-high-s", "signature-short",
	"signature-zero-r", "signature-zero-s", "signature-invalid-r", "zero-expected-signer",
}

type computedHashes struct {
	domainTypeHash        []byte
	authorizationTypeHash []byte
	domainSeparator       []byte
	authorizationHash     []byte
	signingDigest         []byte
}

func TestEIP712BridgePositiveVector(t *testing.T) {
	v := loadStrictJSON[bridgeVector](t, "eip712_bridge_vectors.json")
	if v.VectorID != "ccse-v1-eip712-bridge-conformance-0001" || v.Status != "candidate" {
		t.Fatalf("unexpected vector identity/status: %q %q", v.VectorID, v.Status)
	}
	if v.CCSE.VectorID != "ccse-v1-ed25519-conformance-0001" {
		t.Fatalf("unexpected source CCSE vector: %q", v.CCSE.VectorID)
	}

	assertCCSESourceDigest(t, v)
	assertSoliditySourceProfile(t, v)

	hashes, err := computeHashes(v)
	if err != nil {
		t.Fatalf("compute EIP-712 hashes: %v", err)
	}
	assertHex(t, "domain type hash", hashes.domainTypeHash, v.Expected.DomainTypeHashHex, 32)
	assertHex(t, "authorization type hash", hashes.authorizationTypeHash, v.Expected.AuthorizationTypeHashHex, 32)
	assertHex(t, "domain separator", hashes.domainSeparator, v.Expected.DomainSeparatorHex, 32)
	assertHex(t, "authorization struct hash", hashes.authorizationHash, v.Expected.AuthorizationStructHashHex, 32)
	assertHex(t, "EIP-712 signing digest", hashes.signingDigest, v.Expected.EIP712SigningDigestHex, 32)

	privateKey, err := crypto.HexToECDSA(v.ConformanceKey.PrivateKeyHex)
	if err != nil {
		t.Fatalf("parse conformance private key: %v", err)
	}
	if signer := crypto.PubkeyToAddress(privateKey.PublicKey); signer != common.HexToAddress(v.ConformanceKey.ExpectedSigner) {
		t.Fatalf("private key signer %s, want %s", signer.Hex(), v.ConformanceKey.ExpectedSigner)
	}
	signature, err := crypto.Sign(hashes.signingDigest, privateKey)
	if err != nil {
		t.Fatalf("sign EIP-712 digest: %v", err)
	}
	signature[64] += 27 // Solidity ecrecover convention used by the fixture.
	assertHex(t, "signature", signature, v.Expected.SignatureRSV27Hex, 65)

	if err := verifyAt(v, v.Expected.SignatureRSV27Hex, 1_700_000_000); err != nil {
		t.Fatalf("verify at inclusive start: %v", err)
	}
	if err := verifyAt(v, v.Expected.SignatureRSV27Hex, 1_700_000_299); err != nil {
		t.Fatalf("verify before exclusive expiry: %v", err)
	}
}

func TestEIP712BridgeNegativeVectors(t *testing.T) {
	base := loadStrictJSON[bridgeVector](t, "eip712_bridge_vectors.json")
	set := loadStrictJSON[negativeVectorSet](t, "eip712_bridge_negative.json")
	if set.VectorSetID != "ccse-v1-eip712-bridge-negative-0001" || set.BaseVectorID != base.VectorID || set.Status != "candidate" {
		t.Fatalf("unexpected negative vector identity/status: %+v", set)
	}

	assertRequiredNegativeCaseSet(t, set.Cases)

	for _, tc := range set.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			v := base
			signatureHex := base.Expected.SignatureRSV27Hex
			now := uint64(1_700_000_000)

			switch tc.Operation {
			case "replace":
				if err := replaceVectorField(&v, tc.Path, tc.Value); err != nil {
					t.Fatal(err)
				}
			case "verify_at":
				if tc.Path != "verification.current_unix" {
					t.Fatalf("unexpected verify_at path %q", tc.Path)
				}
				parsed, err := parseCanonicalUint(tc.Value, 64)
				if err != nil {
					t.Fatalf("parse verify time: %v", err)
				}
				now = parsed.Uint64()
			case "flip_signature_byte":
				assertSignaturePath(t, tc.Path)
				index, err := strconv.Atoi(tc.Value)
				if err != nil || index < 0 || index >= 65 {
					t.Fatalf("invalid signature byte index %q", tc.Value)
				}
				signature := mustDecodeHex(t, signatureHex, 65)
				signature[index] ^= 1
				signatureHex = hex.EncodeToString(signature)
			case "replace_signature_v":
				assertSignaturePath(t, tc.Path)
				value, err := strconv.ParseUint(tc.Value, 10, 8)
				if err != nil {
					t.Fatalf("parse signature v: %v", err)
				}
				signature := mustDecodeHex(t, signatureHex, 65)
				signature[64] = byte(value)
				signatureHex = hex.EncodeToString(signature)
			case "replace_signature_r":
				assertSignaturePath(t, tc.Path)
				signatureHex = replaceSignatureComponent(t, signatureHex, 0, tc.Value)
			case "replace_signature_s":
				assertSignaturePath(t, tc.Path)
				signatureHex = replaceSignatureComponent(t, signatureHex, 32, tc.Value)
			case "malleate_signature_high_s":
				assertSignaturePath(t, tc.Path)
				signatureHex = malleateHighS(t, signatureHex)
			case "truncate_signature":
				assertSignaturePath(t, tc.Path)
				length, err := strconv.Atoi(tc.Value)
				if err != nil || length < 0 || length >= 65 {
					t.Fatalf("invalid truncated signature length %q", tc.Value)
				}
				signature := mustDecodeHex(t, signatureHex, 65)
				signatureHex = hex.EncodeToString(signature[:length])
			default:
				t.Fatalf("unknown negative operation %q", tc.Operation)
			}

			got := verifyAt(v, signatureHex, now)
			want := expectedError(tc.ExpectedError)
			if !errors.Is(got, want) {
				t.Fatalf("verify error %v, want %v", got, want)
			}
		})
	}
}

func assertRequiredNegativeCaseSet(t *testing.T, cases []negativeCase) {
	t.Helper()
	required := make(map[string]bool, len(requiredNegativeCaseIDs))
	for _, id := range requiredNegativeCaseIDs {
		if _, duplicate := required[id]; duplicate {
			t.Fatalf("test declares duplicate required negative case %q", id)
		}
		required[id] = false
	}
	if len(cases) != len(required) {
		t.Fatalf("negative vector count %d, want exactly %d", len(cases), len(required))
	}
	for _, tc := range cases {
		seen, known := required[tc.ID]
		if !known {
			t.Fatalf("unknown negative vector case %q", tc.ID)
		}
		if seen {
			t.Fatalf("duplicate negative vector case %q", tc.ID)
		}
		required[tc.ID] = true
	}
	for id, seen := range required {
		if !seen {
			t.Fatalf("missing required negative vector case %q", id)
		}
	}
}

func loadStrictJSON[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("%s has trailing JSON value or bytes", name)
	}
	return value
}

func computeHashes(v bridgeVector) (computedHashes, error) {
	if v.Domain.TypeString != frozenDomainType || v.Authorization.TypeString != frozenAuthorizationType {
		return computedHashes{}, fmt.Errorf("fixture changes the frozen EIP-712 type")
	}
	if !common.IsHexAddress(v.Domain.VerifyingContract) || !common.IsHexAddress(v.Authorization.Payer) || !common.IsHexAddress(v.Authorization.Payee) {
		return computedHashes{}, fmt.Errorf("invalid EIP-712 address")
	}
	chainID, err := parseCanonicalUint(v.Domain.ChainIDDecimal, 256)
	if err != nil {
		return computedHashes{}, fmt.Errorf("chain ID: %w", err)
	}
	genesisHash, err := decodeFixedHex(v.Domain.GenesisHashHex, 32)
	if err != nil {
		return computedHashes{}, fmt.Errorf("genesis hash: %w", err)
	}
	domainTypeHash := crypto.Keccak256([]byte(frozenDomainType))
	domainSeparator, err := hashABIWords(
		domainTypeHash,
		crypto.Keccak256([]byte(v.Domain.Name)),
		crypto.Keccak256([]byte(v.Domain.Version)),
		uintWord(chainID),
		addressWord(v.Domain.VerifyingContract),
		genesisHash,
	)
	if err != nil {
		return computedHashes{}, fmt.Errorf("domain: %w", err)
	}

	authorizationTypeHash := crypto.Keccak256([]byte(frozenAuthorizationType))
	ccseDigest, err := decodeFixedHex(v.Authorization.CCSERecordDigestHex, 32)
	if err != nil {
		return computedHashes{}, err
	}
	operationID, err := decodeFixedHex(v.Authorization.FinancialOperationIDHex, 32)
	if err != nil {
		return computedHashes{}, err
	}
	leaseID, err := decodeFixedHex(v.Authorization.LeaseIDHex, 32)
	if err != nil {
		return computedHashes{}, err
	}
	receiptID, err := decodeFixedHex(v.Authorization.ReceiptIDHex, 32)
	if err != nil {
		return computedHashes{}, err
	}
	settlementID, err := decodeFixedHex(v.Authorization.SettlementIDHex, 32)
	if err != nil {
		return computedHashes{}, err
	}
	assetID, err := decodeFixedHex(v.Authorization.AssetIDHex, 32)
	if err != nil {
		return computedHashes{}, err
	}
	amount, err := parseCanonicalUint(v.Authorization.AmountSmallestUnitDecimal, 256)
	if err != nil {
		return computedHashes{}, err
	}
	generation, err := parseCanonicalUint(v.Authorization.ExpectedGenerationDecimal, 64)
	if err != nil {
		return computedHashes{}, err
	}
	validAfter, err := parseCanonicalUint(v.Authorization.ValidAfterUnixDecimal, 64)
	if err != nil {
		return computedHashes{}, err
	}
	validBefore, err := parseCanonicalUint(v.Authorization.ValidBeforeUnixDecimal, 64)
	if err != nil {
		return computedHashes{}, err
	}
	authorizationHash, err := hashABIWords(
		authorizationTypeHash,
		ccseDigest,
		operationID,
		leaseID,
		receiptID,
		settlementID,
		assetID,
		addressWord(v.Authorization.Payer),
		addressWord(v.Authorization.Payee),
		uintWord(amount),
		uintWord(generation),
		uintWord(validAfter),
		uintWord(validBefore),
	)
	if err != nil {
		return computedHashes{}, fmt.Errorf("authorization: %w", err)
	}
	return computedHashes{
		domainTypeHash:        domainTypeHash,
		authorizationTypeHash: authorizationTypeHash,
		domainSeparator:       domainSeparator,
		authorizationHash:     authorizationHash,
		signingDigest:         crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator, authorizationHash),
	}, nil
}

func hashABIWords(words ...[]byte) ([]byte, error) {
	encoded := make([]byte, 0, 32*len(words))
	for i, word := range words {
		if len(word) != 32 {
			return nil, fmt.Errorf("ABI word %d has %d bytes", i, len(word))
		}
		encoded = append(encoded, word...)
	}
	return crypto.Keccak256(encoded), nil
}

func uintWord(value *big.Int) []byte {
	word := make([]byte, 32)
	encoded := value.Bytes()
	copy(word[len(word)-len(encoded):], encoded)
	return word
}

func addressWord(value string) []byte {
	word := make([]byte, 32)
	copy(word[12:], common.HexToAddress(value).Bytes())
	return word
}

func verifyAt(v bridgeVector, signatureHex string, now uint64) error {
	if err := validateAuthorization(v, now); err != nil {
		return err
	}
	if !common.IsHexAddress(v.ConformanceKey.ExpectedSigner) || common.HexToAddress(v.ConformanceKey.ExpectedSigner) == (common.Address{}) {
		return errInvalidSignature
	}
	hashes, err := computeHashes(v)
	if err != nil {
		return errors.Join(errInvalidAuthorization, err)
	}
	signature, err := decodeFixedHex(signatureHex, 65)
	if err != nil {
		return errors.Join(errInvalidSignature, err)
	}
	if signature[64] != 27 && signature[64] != 28 {
		return errInvalidSignature
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	if !crypto.ValidateSignatureValues(signature[64]-27, r, s, true) {
		return errInvalidSignature
	}
	recoverySignature := append([]byte(nil), signature...)
	recoverySignature[64] -= 27
	publicKey, err := crypto.SigToPub(hashes.signingDigest, recoverySignature)
	if err != nil {
		return errors.Join(errInvalidSignature, err)
	}
	recovered := crypto.PubkeyToAddress(*publicKey)
	if recovered != common.HexToAddress(v.ConformanceKey.ExpectedSigner) {
		return fmt.Errorf("%w: recovered %s", errUnexpectedSigner, recovered.Hex())
	}
	return nil
}

func validateAuthorization(v bridgeVector, now uint64) error {
	if v.Domain.Name == "" || v.Domain.Version == "" {
		return errInvalidAuthorization
	}
	chainID, err := parseCanonicalUint(v.Domain.ChainIDDecimal, 256)
	if err != nil || chainID.Sign() == 0 {
		return errInvalidAuthorization
	}
	genesis, err := decodeFixedHex(v.Domain.GenesisHashHex, 32)
	if err != nil || allZero(genesis) || !common.IsHexAddress(v.Domain.VerifyingContract) || common.HexToAddress(v.Domain.VerifyingContract) == (common.Address{}) {
		return errInvalidAuthorization
	}
	for _, value := range financialByteFields(v) {
		decoded, err := decodeFixedHex(value, 32)
		if err != nil || allZero(decoded) {
			return errInvalidAuthorization
		}
	}
	if !common.IsHexAddress(v.Authorization.Payer) || !common.IsHexAddress(v.Authorization.Payee) || common.HexToAddress(v.Authorization.Payer) == (common.Address{}) || common.HexToAddress(v.Authorization.Payee) == (common.Address{}) {
		return errInvalidAuthorization
	}
	amount, err := parseCanonicalUint(v.Authorization.AmountSmallestUnitDecimal, 256)
	if err != nil || amount.Sign() == 0 {
		return errInvalidAuthorization
	}
	if _, err := parseCanonicalUint(v.Authorization.ExpectedGenerationDecimal, 64); err != nil {
		return errInvalidAuthorization
	}
	after, err := parseCanonicalUint(v.Authorization.ValidAfterUnixDecimal, 64)
	if err != nil {
		return errInvalidAuthorization
	}
	before, err := parseCanonicalUint(v.Authorization.ValidBeforeUnixDecimal, 64)
	if err != nil || before.Cmp(after) <= 0 {
		return errInvalidAuthorization
	}
	if now < after.Uint64() {
		return errNotYetValid
	}
	if now >= before.Uint64() {
		return errExpired
	}
	return nil
}

func financialByteFields(v bridgeVector) map[string]string {
	return map[string]string{
		"ccse_record_digest":     v.Authorization.CCSERecordDigestHex,
		"financial_operation_id": v.Authorization.FinancialOperationIDHex,
		"lease_id":               v.Authorization.LeaseIDHex,
		"receipt_id":             v.Authorization.ReceiptIDHex,
		"settlement_id":          v.Authorization.SettlementIDHex,
		"asset_id":               v.Authorization.AssetIDHex,
	}
}

func replaceVectorField(v *bridgeVector, path, value string) error {
	switch path {
	case "domain.chain_id_decimal":
		v.Domain.ChainIDDecimal = value
	case "domain.verifying_contract":
		v.Domain.VerifyingContract = value
	case "domain.name":
		v.Domain.Name = value
	case "domain.version":
		v.Domain.Version = value
	case "domain.genesis_hash_hex":
		v.Domain.GenesisHashHex = value
	case "authorization.ccse_record_digest_hex":
		v.Authorization.CCSERecordDigestHex = value
	case "authorization.financial_operation_id_hex":
		v.Authorization.FinancialOperationIDHex = value
	case "authorization.lease_id_hex":
		v.Authorization.LeaseIDHex = value
	case "authorization.receipt_id_hex":
		v.Authorization.ReceiptIDHex = value
	case "authorization.settlement_id_hex":
		v.Authorization.SettlementIDHex = value
	case "authorization.asset_id_hex":
		v.Authorization.AssetIDHex = value
	case "authorization.payer":
		v.Authorization.Payer = value
	case "authorization.payee":
		v.Authorization.Payee = value
	case "authorization.amount_smallest_unit_decimal":
		v.Authorization.AmountSmallestUnitDecimal = value
	case "authorization.expected_generation_decimal":
		v.Authorization.ExpectedGenerationDecimal = value
	case "authorization.valid_before_unix_decimal":
		v.Authorization.ValidBeforeUnixDecimal = value
	case "conformance_key.expected_signer":
		v.ConformanceKey.ExpectedSigner = value
	default:
		return fmt.Errorf("unknown replacement path %q", path)
	}
	return nil
}

func expectedError(name string) error {
	switch name {
	case errInvalidAuthorization.Error():
		return errInvalidAuthorization
	case errInvalidSignature.Error():
		return errInvalidSignature
	case errUnexpectedSigner.Error():
		return errUnexpectedSigner
	case errNotYetValid.Error():
		return errNotYetValid
	case errExpired.Error():
		return errExpired
	default:
		return fmt.Errorf("unknown expected error %q", name)
	}
}

func parseCanonicalUint(value string, bits int) (*big.Int, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return nil, fmt.Errorf("non-canonical unsigned decimal %q", value)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("non-decimal unsigned integer %q", value)
		}
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Sign() < 0 || parsed.BitLen() > bits {
		return nil, fmt.Errorf("value %q does not fit uint%d", value, bits)
	}
	return parsed, nil
}

func decodeFixedHex(value string, size int) ([]byte, error) {
	if value != strings.ToLower(value) || len(value) != size*2 {
		return nil, fmt.Errorf("want %d-byte lowercase unprefixed hex", size)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func mustDecodeHex(t *testing.T, value string, size int) []byte {
	t.Helper()
	decoded, err := decodeFixedHex(value, size)
	if err != nil {
		t.Fatalf("decode %d-byte hex: %v", size, err)
	}
	return decoded
}

func assertHex(t *testing.T, name string, got []byte, expected string, size int) {
	t.Helper()
	want := mustDecodeHex(t, expected, size)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s %x, want %x", name, got, want)
	}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func malleateHighS(t *testing.T, signatureHex string) string {
	t.Helper()
	signature := mustDecodeHex(t, signatureHex, 65)
	curveN, ok := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	if !ok {
		t.Fatal("parse secp256k1 order")
	}
	s := new(big.Int).SetBytes(signature[32:64])
	highS := new(big.Int).Sub(curveN, s)
	encoded := highS.Bytes()
	for i := 32; i < 64; i++ {
		signature[i] = 0
	}
	copy(signature[64-len(encoded):64], encoded)
	if signature[64] == 27 {
		signature[64] = 28
	} else {
		signature[64] = 27
	}
	return hex.EncodeToString(signature)
}

func replaceSignatureComponent(t *testing.T, signatureHex string, offset int, componentHex string) string {
	t.Helper()
	if offset != 0 && offset != 32 {
		t.Fatalf("invalid signature component offset %d", offset)
	}
	signature := mustDecodeHex(t, signatureHex, 65)
	component := mustDecodeHex(t, componentHex, 32)
	copy(signature[offset:offset+32], component)
	return hex.EncodeToString(signature)
}

func assertSignaturePath(t *testing.T, path string) {
	t.Helper()
	if path != "expected.signature_rsv_27_hex" {
		t.Fatalf("unexpected signature path %q", path)
	}
}

func assertCCSESourceDigest(t *testing.T, v bridgeVector) {
	t.Helper()
	data, err := os.ReadFile("../../ccse/testdata/ccse_v1_ed25519_positive.json")
	if err != nil {
		t.Fatalf("read source CCSE vector: %v", err)
	}
	var source struct {
		VectorID string `json:"vector_id"`
		Expected struct {
			SHA256DigestHex string `json:"sha256_digest_hex"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatalf("decode source CCSE vector: %v", err)
	}
	if source.VectorID != v.CCSE.VectorID || source.Expected.SHA256DigestHex != v.CCSE.SHA256RecordDigestHex || v.CCSE.SHA256RecordDigestHex != v.Authorization.CCSERecordDigestHex {
		t.Fatalf("EIP-712 vector is not bound to the source CCSE digest")
	}
}

func assertSoliditySourceProfile(t *testing.T, v bridgeVector) {
	t.Helper()
	source, err := os.ReadFile("CCSEEIP712Bridge.sol")
	if err != nil {
		t.Fatalf("read Solidity source: %v", err)
	}
	for _, exact := range []string{
		`"` + v.Domain.TypeString + `"`,
		`"` + v.Authorization.TypeString + `"`,
		"0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
		"block.timestamp > type(uint64).max",
	} {
		if !bytes.Contains(source, []byte(exact)) {
			t.Fatalf("Solidity source lacks frozen profile value %q", exact)
		}
	}
}
