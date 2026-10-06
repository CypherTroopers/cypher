// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/node/lightnode"
)

// The checked-in vector was produced independently by Node WebCrypto, using
// the public test scalar 1. No operational signing key is stored in the tree.
func TestIndependentWebCryptoVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/protocol-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicJWK JWK `json:"publicJwk"`
		Header    struct {
			Network Network `json:"network"`
			Height  uint64  `json:"height"`
			RawHex  string  `json:"rawHex"`
			Digest  string  `json:"digest"`
		} `json:"header"`
		Envelope   Envelope `json:"envelope"`
		ManifestID string   `json:"manifestId"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: big.NewInt(1)}
	jwk, err := PublicJWK(&key.PublicKey)
	if err != nil || jwk.X != vector.PublicJWK.X || jwk.Y != vector.PublicJWK.Y {
		t.Fatalf("independent public key mismatch: %v", err)
	}
	manifest, err := VerifyManifest(vector.Envelope, "test_key", &key.PublicKey)
	if err != nil {
		t.Fatalf("Node signature rejected by Go: %v", err)
	}
	id, err := ManifestID(vector.Envelope)
	if err != nil || id != vector.ManifestID {
		t.Fatalf("manifest ID mismatch: %s %v", id, err)
	}
	header, err := hex.DecodeString(vector.Header.RawHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := lightnode.HeaderDigest(vector.Header.Network, vector.Header.Height, header); got != vector.Header.Digest {
		t.Fatalf("independent header digest mismatch: %s", got)
	}

	t.Run("GoSignatureVerifiedByWebCrypto", func(t *testing.T) {
		node, err := exec.LookPath("node")
		if err != nil {
			t.Skip("Node not installed; independent static vector above still checked")
		}
		envelope, err := SignManifest(manifest, "test_key", key)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "go-envelope.json")
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, "testdata/webcrypto.mjs", path).CombinedOutput()
		if err != nil {
			t.Fatalf("Go signature rejected by WebCrypto: %v\n%s", err, out)
		}
	})
}
