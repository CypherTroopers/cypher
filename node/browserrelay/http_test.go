// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cypherium/cypher/node/lightnode"
)

func TestHTTPServesSignedSnapshotWithoutSourceReads(t *testing.T) {
	e, f := newExporterFixture(t, 40)
	handler := NewHandler(e)
	request := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	opens := f.opens.Load()
	w := request("GET", "/relay/v1/head")
	if w.Code != http.StatusOK {
		t.Fatalf("head: %d %s", w.Code, w.Body.String())
	}
	envelope, err := DecodeEnvelope(bytes.TrimSpace(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifyManifest(envelope, envelope.KeyID, &f.key.PublicKey)
	if err != nil || len(manifest.Entries) != 32 {
		t.Fatalf("manifest: %v", err)
	}
	for _, entry := range manifest.Entries {
		w = request("GET", "/relay/v1/headers/"+entry.Digest)
		if w.Code != http.StatusOK {
			t.Fatalf("header: %d", w.Code)
		}
		var packet lightnode.Packet
		if err := json.Unmarshal(w.Body.Bytes(), &packet); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(packet.HeaderRLP)
		if err != nil || len(raw) != entry.RawBytes || lightnode.HeaderDigest(packet.Network, packet.Height, raw) != entry.Digest {
			t.Fatalf("header byte binding failed: %v", err)
		}
		f.mu.Lock()
		same := bytes.Equal(raw, f.headers[entry.Height])
		f.mu.Unlock()
		if !same {
			t.Fatal("source bytes changed")
		}
	}
	if f.opens.Load() != opens {
		t.Fatal("HTTP request opened a fresh database snapshot")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("private handler cache/CORS boundary changed")
	}
	if head := request("HEAD", "/relay/v1/head"); head.Code != 200 || head.Body.Len() != 0 {
		t.Fatal("HEAD emitted a body")
	}
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"POST", "/relay/v1/head", 405},
		{"GET", "/relay/v1/head?refresh=1", 400},
		{"GET", "/relay/v1/headers/" + strings.Repeat("a", 64), 404},
		{"GET", "/relay/v1/headers/" + strings.Repeat("A", 64), 400},
		{"GET", "/relay/v1/headers/../head", 400},
		{"GET", "/relay/v1/sessions", 404},
		{"GET", "/relay/v1/head/", 404},
	} {
		if got := request(tc.method, tc.path); got.Code != tc.code {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, got.Code, tc.code)
		}
	}
	f.clock.Store(manifest.ExpiresAt)
	if got := request("GET", "/relay/v1/head"); got.Code != 503 {
		t.Fatal("expired head was served")
	}
	if got := request("GET", "/relay/v1/headers/"+manifest.Entries[0].Digest); got.Code != 503 {
		t.Fatal("expired header was served")
	}
	if got := request("GET", "/relay/v1/source-status"); got.Code != 200 || !strings.Contains(got.Body.String(), `"healthy":false`) {
		t.Fatal("missing expired source status")
	}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := request("GET", "/relay/v1/head"); got.Code != 503 {
		t.Fatal("stopped head was served")
	}
}
