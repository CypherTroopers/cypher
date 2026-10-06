// SPDX-License-Identifier: LGPL-3.0-or-later

// Package browserrelay implements the public, browser-facing header boundary.
// A gateway signature authenticates its observation, not consensus finality.
package browserrelay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cypherium/cypher/node/lightnode"
)

const (
	MaxHeaderBytes   = 8192
	MaxHeaders       = 32
	MaxManifestBytes = 16384
	MaxEnvelopeBytes = 24576
	MaxSafeInteger   = uint64(9007199254740991)
	ManifestDomain   = "cypher-browser-header-manifest-v1\x00"
)

type Network = lightnode.Network

type Entry struct {
	Height     uint64 `json:"height"`
	BlockHash  string `json:"blockHash"`
	ParentHash string `json:"parentHash"`
	Digest     string `json:"digest"`
	RawBytes   int    `json:"rawBytes"`
}

type Manifest struct {
	Version      int     `json:"version"`
	Network      Network `json:"network"`
	SourceID     string  `json:"sourceId"`
	SourceBootID string  `json:"sourceBootId"`
	Sequence     string  `json:"sequence"`
	ObservedAt   int64   `json:"observedAt"`
	ExpiresAt    int64   `json:"expiresAt"`
	HeadHeight   uint64  `json:"headHeight"`
	HeadHash     string  `json:"headHash"`
	Entries      []Entry `json:"entries"`
}

type Envelope struct {
	KeyID           string `json:"keyId"`
	ManifestBase64  string `json:"manifestBase64"`
	SignatureBase64 string `json:"signatureBase64"`
}

// JWK is a verification-only public WebCrypto key. Coordinates are exactly
// 32 bytes encoded using unpadded base64url; no private key material is exposed.
type JWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Ext    bool     `json:"ext"`
	KeyOps []string `json:"key_ops"`
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func lowerHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validHash(s string) bool {
	return strings.HasPrefix(s, "0x") && lowerHex(s[2:], 64) && s != "0x"+strings.Repeat("0", 64)
}

func ValidateNetwork(n Network) error {
	if n.ChainID == 0 || n.ChainID > MaxSafeInteger || !validHash(n.GenesisHash) {
		return errors.New("invalid browser relay network")
	}
	return nil
}

// ValidateManifest checks the complete observation's structure. It does not
// consult a clock, choose a trusted network/key, or independently verify RLP/QCs.
func ValidateManifest(m Manifest) error {
	if err := ValidateNetwork(m.Network); err != nil {
		return err
	}
	if m.Version != 1 || !validID(m.SourceID) || !lowerHex(m.SourceBootID, 32) {
		return errors.New("invalid manifest version or source identity")
	}
	seq, err := strconv.ParseUint(m.Sequence, 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != m.Sequence {
		return errors.New("invalid manifest sequence")
	}
	if m.ObservedAt < 0 || uint64(m.ObservedAt) > MaxSafeInteger || m.ExpiresAt <= m.ObservedAt || uint64(m.ExpiresAt) > MaxSafeInteger || m.ExpiresAt-m.ObservedAt > 30000 {
		return errors.New("invalid manifest observation lifetime")
	}
	if m.HeadHeight > MaxSafeInteger || !validHash(m.HeadHash) || m.Entries == nil {
		return errors.New("invalid manifest head or entries")
	}
	count := m.HeadHeight
	if count > MaxHeaders {
		count = MaxHeaders
	}
	if uint64(len(m.Entries)) != count {
		return errors.New("manifest must contain the complete recent window")
	}
	if m.HeadHeight == 0 {
		if m.HeadHash != m.Network.GenesisHash {
			return errors.New("empty manifest head must be genesis")
		}
		return nil
	}
	first := m.HeadHeight - count + 1
	seen := make(map[string]bool, len(m.Entries))
	for i, e := range m.Entries {
		if e.Height != first+uint64(i) || !validHash(e.BlockHash) || !validHash(e.ParentHash) || !lowerHex(e.Digest, 64) || e.RawBytes < 1 || e.RawBytes > MaxHeaderBytes || seen[e.Digest] {
			return fmt.Errorf("invalid manifest entry %d", i)
		}
		seen[e.Digest] = true
		if e.Height == 1 && e.ParentHash != m.Network.GenesisHash || i > 0 && e.ParentHash != m.Entries[i-1].BlockHash {
			return fmt.Errorf("manifest parent discontinuity at entry %d", i)
		}
	}
	if m.Entries[len(m.Entries)-1].BlockHash != m.HeadHash {
		return errors.New("manifest head does not match the last entry")
	}
	return nil
}

func validPublicKey(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

func PublicJWK(key *ecdsa.PublicKey) (JWK, error) {
	if !validPublicKey(key) {
		return JWK{}, errors.New("browser relay requires a P-256 public key")
	}
	return JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))), Ext: true, KeyOps: []string{"verify"}}, nil
}

func manifestHash(raw []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(ManifestDomain))
	_, _ = h.Write(raw)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func SignManifest(m Manifest, keyID string, key *ecdsa.PrivateKey) (Envelope, error) {
	if !validID(keyID) || key == nil || !validPublicKey(&key.PublicKey) || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return Envelope{}, errors.New("invalid manifest signing key or key ID")
	}
	x, y := elliptic.P256().ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return Envelope{}, errors.New("manifest private and public keys disagree")
	}
	if err := ValidateManifest(m); err != nil {
		return Envelope{}, err
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxManifestBytes {
		return Envelope{}, errors.New("manifest encoding exceeds byte limit")
	}
	digest := manifestHash(raw)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return Envelope{}, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Envelope{keyID, base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyManifest authenticates the exact manifest bytes, without reserializing
// them. The caller must separately enforce its pinned network, source identity,
// wall-clock freshness, boot changes, and monotonic sequence/equivocation rules.
func VerifyManifest(e Envelope, keyID string, key *ecdsa.PublicKey) (Manifest, error) {
	if !validID(keyID) || e.KeyID != keyID || !validPublicKey(key) {
		return Manifest{}, errors.New("untrusted manifest key")
	}
	raw, sig, m, err := decodeEnvelopeFields(e)
	if err != nil {
		return Manifest{}, err
	}
	digest := manifestHash(raw)
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return Manifest{}, errors.New("invalid manifest signature")
	}
	return m, nil
}

// ManifestID is the SHA-256 of the domain and exact manifest bytes. An ID is
// not evidence of signature validity; callers authenticate with VerifyManifest.
func ManifestID(e Envelope) (string, error) {
	raw, _, _, err := decodeEnvelopeFields(e)
	if err != nil {
		return "", err
	}
	id := manifestHash(raw)
	return hex.EncodeToString(id[:]), nil
}

// DecodeEnvelope is the strict, bounded entrypoint for untrusted envelope JSON.
// Decoding directly into Envelope with json.Unmarshal cannot reject unknown or
// case-insensitive field aliases and should not be used at a network boundary.
func DecodeEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return Envelope{}, errors.New("envelope byte limit")
	}
	if err := strictJSON(raw); err != nil {
		return Envelope{}, err
	}
	if _, err := exactObject(raw, "keyId", "manifestBase64", "signatureBase64"); err != nil {
		return Envelope{}, err
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return Envelope{}, err
	}
	if _, _, _, err := decodeEnvelopeFields(e); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

func decodeEnvelopeFields(e Envelope) ([]byte, []byte, Manifest, error) {
	if !validID(e.KeyID) {
		return nil, nil, Manifest{}, errors.New("invalid envelope key ID")
	}
	raw, err := canonicalBase64(e.ManifestBase64, MaxManifestBytes)
	if err != nil {
		return nil, nil, Manifest{}, err
	}
	sig, err := canonicalBase64(e.SignatureBase64, 64)
	if err != nil || len(sig) != 64 {
		return nil, nil, Manifest{}, errors.New("invalid raw P-256 signature encoding")
	}
	m, err := decodeManifest(raw)
	return raw, sig, m, err
}

func canonicalBase64(s string, max int) ([]byte, error) {
	if len(s) == 0 || len(s) > base64.StdEncoding.EncodedLen(max) {
		return nil, errors.New("base64 byte limit")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) > max || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, errors.New("noncanonical base64")
	}
	return raw, nil
}

func decodeManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return Manifest{}, errors.New("manifest byte limit")
	}
	if err := strictJSON(raw); err != nil {
		return Manifest{}, err
	}
	fields, err := exactObject(raw, "version", "network", "sourceId", "sourceBootId", "sequence", "observedAt", "expiresAt", "headHeight", "headHash", "entries")
	if err != nil {
		return Manifest{}, err
	}
	if _, err := exactObject(fields["network"], "chainId", "genesisHash"); err != nil {
		return Manifest{}, err
	}
	var entries []json.RawMessage
	if bytes.Equal(bytes.TrimSpace(fields["entries"]), []byte("null")) {
		return Manifest{}, errors.New("entries must be an array")
	}
	if err := json.Unmarshal(fields["entries"], &entries); err != nil || len(entries) > MaxHeaders {
		return Manifest{}, errors.New("invalid manifest entries")
	}
	for _, entry := range entries {
		if _, err := exactObject(entry, "height", "blockHash", "parentHash", "digest", "rawBytes"); err != nil {
			return Manifest{}, err
		}
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, err
	}
	return m, ValidateManifest(m)
}

func exactObject(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != len(names) {
		return nil, errors.New("invalid JSON object fields")
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("missing, null or noncanonical JSON field %q", name)
		}
	}
	return fields, nil
}

// Walk tokens before struct decoding so duplicate keys (including escaped
// aliases), invalid UTF-8, excessive nesting and trailing values fail closed.
func strictJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("JSON nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
