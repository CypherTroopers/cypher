// SPDX-License-Identifier: LGPL-3.0-or-later

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
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func protocolFixture() Manifest {
	genesis := "0x" + strings.Repeat("11", 32)
	head := "0x" + strings.Repeat("22", 32)
	return Manifest{
		Version: 1, Network: Network{ChainID: 7, GenesisHash: genesis},
		SourceID: "test-source_1", SourceBootID: strings.Repeat("ab", 16), Sequence: "1",
		ObservedAt: 1700000000000, ExpiresAt: 1700000030000, HeadHeight: 1, HeadHash: head,
		Entries: []Entry{{Height: 1, BlockHash: head, ParentHash: genesis, Digest: strings.Repeat("33", 32), RawBytes: 8192}},
	}
}

func protocolKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedProtocolBytes(t *testing.T, key *ecdsa.PrivateKey, raw []byte, domain string) Envelope {
	t.Helper()
	input := append([]byte(domain), raw...)
	hash := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Envelope{KeyID: "test-key", ManifestBase64: base64.StdEncoding.EncodeToString(raw), SignatureBase64: base64.StdEncoding.EncodeToString(sig)}
}

func TestProtocolSignatureBindsExactBytesAndDomain(t *testing.T) {
	key := protocolKey(t)
	m := protocolFixture()
	e, err := SignManifest(m, "test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyManifest(e, "test-key", &key.PublicKey)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	wire, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelope(wire)
	if err != nil || decoded != e {
		t.Fatalf("envelope round trip: %+v, %v", decoded, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(e.ManifestBase64)
	wantHash := sha256.Sum256(append([]byte("cypher-browser-header-manifest-v1\x00"), raw...))
	id, err := ManifestID(e)
	if err != nil || id != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("manifest ID mismatch: %q, %v", id, err)
	}
	// Equivalent JSON is valid only when the exact alternate bytes were signed.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", " "); err != nil {
		t.Fatal(err)
	}
	tampered := e
	tampered.ManifestBase64 = base64.StdEncoding.EncodeToString(pretty.Bytes())
	if _, err := VerifyManifest(tampered, "test-key", &key.PublicKey); err == nil {
		t.Fatal("accepted JSON reserialization with the old signature")
	}
	resigned := signedProtocolBytes(t, key, pretty.Bytes(), ManifestDomain)
	if _, err := VerifyManifest(resigned, "test-key", &key.PublicKey); err != nil {
		t.Fatalf("rejected signed exact whitespace: %v", err)
	}
	for _, domain := range []string{"", "cypher-browser-header-manifest-v1", "cypher-browser-header-manifest-v1\\0", "cypher-common-lightnode-header-overlay-v1\x00"} {
		if _, err := VerifyManifest(signedProtocolBytes(t, key, raw, domain), "test-key", &key.PublicKey); err == nil {
			t.Fatalf("accepted wrong signature domain %q", domain)
		}
	}
	if _, err := VerifyManifest(e, "other-key", &key.PublicKey); err == nil {
		t.Fatal("accepted the wrong pinned key ID")
	}
	other := protocolKey(t)
	if _, err := VerifyManifest(e, "test-key", &other.PublicKey); err == nil {
		t.Fatal("accepted the wrong pinned public key")
	}
}

func TestProtocolManifestStructure(t *testing.T) {
	tests := map[string]func(*Manifest){
		"version":            func(m *Manifest) { m.Version = 2 },
		"zero network":       func(m *Manifest) { m.Network.ChainID = 0 },
		"unsafe network":     func(m *Manifest) { m.Network.ChainID = MaxSafeInteger + 1 },
		"genesis case":       func(m *Manifest) { m.Network.GenesisHash = "0x" + strings.Repeat("AB", 32) },
		"zero genesis":       func(m *Manifest) { m.Network.GenesisHash = "0x" + strings.Repeat("0", 64) },
		"bad source":         func(m *Manifest) { m.SourceID = "https://operator.invalid" },
		"long source":        func(m *Manifest) { m.SourceID = strings.Repeat("a", 65) },
		"boot length":        func(m *Manifest) { m.SourceBootID = strings.Repeat("a", 31) },
		"boot case":          func(m *Manifest) { m.SourceBootID = strings.Repeat("AB", 16) },
		"sequence zero pad":  func(m *Manifest) { m.Sequence = "01" },
		"sequence sign":      func(m *Manifest) { m.Sequence = "+1" },
		"sequence overflow":  func(m *Manifest) { m.Sequence = "18446744073709551616" },
		"negative time":      func(m *Manifest) { m.ObservedAt = -1 },
		"unsafe time":        func(m *Manifest) { m.ObservedAt = int64(MaxSafeInteger) + 1; m.ExpiresAt = m.ObservedAt + 1 },
		"unsafe expiry":      func(m *Manifest) { m.ExpiresAt = int64(MaxSafeInteger) + 1 },
		"zero lifetime":      func(m *Manifest) { m.ExpiresAt = m.ObservedAt },
		"long lifetime":      func(m *Manifest) { m.ExpiresAt = m.ObservedAt + 30001 },
		"unsafe head":        func(m *Manifest) { m.HeadHeight = MaxSafeInteger + 1 },
		"nil entries":        func(m *Manifest) { m.Entries = nil },
		"incomplete window":  func(m *Manifest) { m.HeadHeight = 2 },
		"wrong entry height": func(m *Manifest) { m.Entries[0].Height = 2 },
		"wrong head hash":    func(m *Manifest) { m.HeadHash = m.Network.GenesisHash },
		"wrong parent":       func(m *Manifest) { m.Entries[0].ParentHash = m.HeadHash },
		"short digest":       func(m *Manifest) { m.Entries[0].Digest = "01" },
		"digest case":        func(m *Manifest) { m.Entries[0].Digest = strings.Repeat("AB", 32) },
		"empty header":       func(m *Manifest) { m.Entries[0].RawBytes = 0 },
		"large header":       func(m *Manifest) { m.Entries[0].RawBytes = MaxHeaderBytes + 1 },
	}
	key := protocolKey(t)
	for name, alter := range tests {
		t.Run(name, func(t *testing.T) {
			m := protocolFixture()
			alter(&m)
			if err := ValidateManifest(m); err == nil {
				t.Fatal("accepted invalid structure")
			}
			if _, err := SignManifest(m, "test-key", key); err == nil {
				t.Fatal("signed invalid structure")
			}
			raw, _ := json.Marshal(m)
			if _, err := VerifyManifest(signedProtocolBytes(t, key, raw, ManifestDomain), "test-key", &key.PublicKey); err == nil {
				t.Fatal("accepted invalid structure with a real signature")
			}
		})
	}
	// Structural verification intentionally does not consult the current clock.
	m := protocolFixture()
	m.ObservedAt, m.ExpiresAt, m.Sequence = 0, 1, "18446744073709551615"
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("valid timestamp/uint64 boundary: %v", err)
	}
	m.HeadHeight, m.HeadHash, m.Entries = 0, m.Network.GenesisHash, []Entry{}
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("genesis window: %v", err)
	}
	if _, err := SignManifest(m, "test-key", key); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolCompleteWindowAndParentLinks(t *testing.T) {
	m := protocolFixture()
	m.HeadHeight, m.Entries = 33, make([]Entry, MaxHeaders)
	previous := m.Network.GenesisHash
	for i := range m.Entries {
		h := sha256.Sum256([]byte{byte(i)})
		hash := "0x" + hex.EncodeToString(h[:])
		m.Entries[i] = Entry{Height: uint64(i + 2), BlockHash: hash, ParentHash: previous, Digest: hex.EncodeToString(h[:]), RawBytes: 1}
		previous = hash
	}
	m.HeadHash = previous
	if err := ValidateManifest(m); err != nil {
		t.Fatal(err)
	}
	m.Entries[1].ParentHash = m.Network.GenesisHash
	if err := ValidateManifest(m); err == nil {
		t.Fatal("accepted disconnected recent window")
	}
}

func TestProtocolRejectsAmbiguousJSONEvenWithValidSignature(t *testing.T) {
	key := protocolKey(t)
	raw, _ := json.Marshal(protocolFixture())
	original := string(raw)
	tests := map[string]string{
		"duplicate root":    strings.Replace(original, `"version":1`, `"version":1,"version":1`, 1),
		"escaped duplicate": strings.Replace(original, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		"duplicate network": strings.Replace(original, `"chainId":7`, `"chainId":7,"chainId":7`, 1),
		"duplicate entry":   strings.Replace(original, `"rawBytes":8192`, `"rawBytes":8192,"rawBytes":8192`, 1),
		"unknown root":      strings.Replace(original, `"version":1`, `"version":1,"extra":false`, 1),
		"unknown network":   strings.Replace(original, `"chainId":7`, `"chainId":7,"extra":false`, 1),
		"unknown entry":     strings.Replace(original, `"rawBytes":8192`, `"rawBytes":8192,"extra":false`, 1),
		"case alias":        strings.Replace(original, `"headHeight":1`, `"HeadHeight":1`, 1),
		"missing field":     strings.Replace(original, `"sequence":"1",`, ``, 1),
		"null field":        strings.Replace(original, `"observedAt":1700000000000`, `"observedAt":null`, 1),
		"exponent":          strings.Replace(original, `"headHeight":1`, `"headHeight":1e0`, 1),
		"fraction":          strings.Replace(original, `"headHeight":1`, `"headHeight":1.0`, 1),
		"numeric string":    strings.Replace(original, `"headHeight":1`, `"headHeight":"1"`, 1),
		"trailing object":   original + `{}`,
		"deep nesting":      strings.Replace(original, `"version":1`, `"version":[[[[[[[[[1]]]]]]]]]`, 1),
		"invalid UTF8":      strings.Replace(original, "test-source_1", "test-\xff-source", 1),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if encoded == original {
				t.Fatal("test mutation had no effect")
			}
			if _, err := VerifyManifest(signedProtocolBytes(t, key, []byte(encoded), ManifestDomain), "test-key", &key.PublicKey); err == nil {
				t.Fatal("accepted ambiguous manifest JSON")
			}
		})
	}
}

func TestProtocolEnvelopeAndEncodingBounds(t *testing.T) {
	key := protocolKey(t)
	e, err := SignManifest(protocolFixture(), "test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Envelope){
		"manifest newline":  func(e *Envelope) { e.ManifestBase64 = "\n" + e.ManifestBase64 },
		"signature newline": func(e *Envelope) { e.SignatureBase64 = e.SignatureBase64[:10] + "\n" + e.SignatureBase64[10:] },
		"short signature":   func(e *Envelope) { e.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, 63)) },
		"zero signature":    func(e *Envelope) { e.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		"large manifest": func(e *Envelope) {
			e.ManifestBase64 = base64.StdEncoding.EncodeToString(make([]byte, MaxManifestBytes+1))
		},
		"unknown key": func(e *Envelope) { e.KeyID = "unknown-key" },
	}
	for name, alter := range tests {
		t.Run(name, func(t *testing.T) {
			modified := e
			alter(&modified)
			if _, err := VerifyManifest(modified, "test-key", &key.PublicKey); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		})
	}
	wire, _ := json.Marshal(e)
	for _, raw := range [][]byte{
		bytes.Replace(wire, []byte(`"keyId":"test-key"`), []byte(`"keyId":"test-key","keyId":"test-key"`), 1),
		bytes.Replace(wire, []byte(`"keyId"`), []byte(`"KeyID"`), 1),
		append(wire[:len(wire)-1:len(wire)-1], []byte(`,"unknown":true}`)...),
		append(append([]byte(nil), wire...), []byte(`{}`)...),
		bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1),
		[]byte(`null`),
	} {
		if _, err := DecodeEnvelope(raw); err == nil {
			t.Fatal("accepted malformed envelope JSON")
		}
	}
}

func TestProtocolPublicJWKAndInvalidKeys(t *testing.T) {
	key := protocolKey(t)
	jwk, err := PublicJWK(&key.PublicKey)
	if err != nil || jwk.Kty != "EC" || jwk.Crv != "P-256" || !jwk.Ext || !reflect.DeepEqual(jwk.KeyOps, []string{"verify"}) {
		t.Fatalf("invalid JWK: %+v, %v", jwk, err)
	}
	for i, coordinate := range []string{jwk.X, jwk.Y} {
		raw, err := base64.RawURLEncoding.DecodeString(coordinate)
		if err != nil || len(raw) != 32 {
			t.Fatalf("coordinate %d is not 32 bytes", i)
		}
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []*ecdsa.PublicKey{nil, {}, &p384.PublicKey, {Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}} {
		if _, err := PublicJWK(invalid); err == nil {
			t.Fatal("accepted invalid public key")
		}
	}
	broken := *key
	broken.D = big.NewInt(0)
	if _, err := SignManifest(protocolFixture(), "test-key", &broken); err == nil {
		t.Fatal("accepted zero private scalar")
	}
	broken.D = new(big.Int).Sub(elliptic.P256().Params().N, key.D)
	if _, err := SignManifest(protocolFixture(), "test-key", &broken); err == nil {
		t.Fatal("accepted inconsistent public/private key")
	}
}
