package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/node/browserrelay"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

func TestBrowserMeshHTTPSessionCapacity(t *testing.T) {
	h := newBrowserMeshHTTP(context.Background(), nil, []string{"https://fixture.invalid"})
	// Exercise concurrent lease capacity independently of admission pacing.
	h.admissions = rate.NewLimiter(rate.Inf, 1)
	h.requests = rate.NewLimiter(rate.Inf, 1)
	h.start()
	defer h.stop()
	request := func(method, path, token string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, "/relay/v1/mesh/"+path, nil)
		req.Header.Set("Origin", "https://fixture.invalid")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		var body map[string]any
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		return response.Code, body
	}
	if status, config := request("GET", "config", ""); status != 200 || config["maxSessions"] != float64(80) || config["nativePeers"] != float64(40) {
		t.Fatalf("advertised mesh capacity: %d %+v", status, config)
	}
	var first string
	for i := 0; i < 80; i++ {
		status, session := request("POST", "sessions", "")
		if status != 201 {
			t.Fatalf("session %d rejected: %d", i+1, status)
		}
		if i == 0 {
			first, _ = session["token"].(string)
		}
	}
	if status, _ := request("POST", "sessions", ""); status != 429 {
		t.Fatalf("81st session accepted: %d", status)
	}
	if status, _ := request("DELETE", "sessions", first); status != 204 {
		t.Fatalf("session release: %d", status)
	}
	if status, _ := request("POST", "sessions", ""); status != 201 {
		t.Fatalf("released capacity was not reusable: %d", status)
	}
}

func TestBrowserMeshHTTPLeaseDisconnectAndStop(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	n := enode.NewV4(&key.PublicKey, net.ParseIP("127.0.0.1"), 12345, 0)
	mesh, err := browserrelay.NewMesh(browserrelay.MeshConfig{
		Network:   browserrelay.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)},
		LocalNode: func() *enode.Node { return n }, SignDigest: func(b []byte) ([]byte, error) { return crypto.Sign(b, key) },
		OnInbound: func(c net.Conn, n *enode.Node) error { return c.Close() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = mesh.Start(); err != nil {
		t.Fatal(err)
	}
	defer mesh.Stop()
	h := newBrowserMeshHTTP(context.Background(), mesh, []string{"https://fixture.invalid"})
	h.start()
	defer h.stop()
	server := httptest.NewServer(h)
	defer server.Close()
	request := func(method, path, token, origin string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+"/relay/v1/mesh/"+path, nil)
		req.Header.Set("Origin", origin)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var data map[string]any
		_ = json.Unmarshal(raw, &data)
		return resp.StatusCode, data
	}
	if status, _ := request("POST", "sessions", "", "https://wrong.invalid"); status != 403 {
		t.Fatal(status)
	}
	if status, _ := request("POST", "sessions?token=secret", "", "https://fixture.invalid"); status != 403 {
		t.Fatal(status)
	}
	status, session := request("POST", "sessions", "", "https://fixture.invalid")
	if status != 201 {
		t.Fatal(status)
	}
	token := session["token"].(string)
	if status, _ := request("POST", "renew", token, "https://fixture.invalid"); status != 200 {
		t.Fatal(status)
	}
	connect := func(token string) *websocket.Conn {
		t.Helper()
		ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/relay/v1/mesh/connect", http.Header{"Origin": []string{"https://fixture.invalid"}})
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			if err := ws.WriteJSON(map[string]string{"token": token}); err != nil {
				t.Fatal(err)
			}
		}
		return ws
	}
	ws := connect(token)
	_ = ws.SetReadDeadline(time.Now().Add(time.Second))
	var hello browserrelay.MeshFrame
	if err := ws.ReadJSON(&hello); err != nil || hello.Type != "hello" || hello.Protocol != browserrelay.MeshProtocol {
		t.Fatalf("authenticated hello: %+v %v", hello, err)
	}
	duplicate := connect(token)
	_ = duplicate.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := duplicate.ReadMessage(); err == nil {
		t.Fatal("token attached twice")
	}
	duplicate.Close()
	if status, _ := request("DELETE", "sessions", token, "https://fixture.invalid"); status != 204 {
		t.Fatal(status)
	}
	_ = ws.SetReadDeadline(time.Now().Add(time.Second))
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			break
		}
	}
	ws.Close()
	if status, _ := request("POST", "renew", token, "https://fixture.invalid"); status != 401 {
		t.Fatal("revoked session renewed", status)
	}
	status, session = request("POST", "sessions", "", "https://fixture.invalid")
	if status != 201 {
		t.Fatal(status)
	}
	token = session["token"].(string)
	hash, _ := browserMeshToken(token)
	h.mu.Lock()
	h.sessions[hash].expires = time.Now().Add(-time.Second)
	h.mu.Unlock()
	if status, _ := request("POST", "renew", token, "https://fixture.invalid"); status != 401 {
		t.Fatal("expired lease resurrected", status)
	}
	unauthenticated := connect("")
	defer unauthenticated.Close()
	start := time.Now()
	h.stop()
	if time.Since(start) > time.Second {
		t.Fatal("stop did not cancel unauthenticated socket")
	}
	if mesh.Status().Sessions != 0 {
		t.Fatal("stopped endpoint retained sessions")
	}
	if status, _ := request("GET", "config", "", "https://fixture.invalid"); status != 503 {
		t.Fatal(status)
	}
}

func TestBrowserMeshHTTPEndpoint(t *testing.T) {
	key, _ := crypto.GenerateKey()
	n := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30445, 0)
	for _, enabled := range []bool{false, true} {
		origin := ""
		if enabled {
			origin = "https://gateway.example.org"
		}
		mesh, err := browserrelay.NewMesh(browserrelay.MeshConfig{Network: browserrelay.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("2", 64)}, LocalNode: func() *enode.Node { return n }, SignDigest: func(d []byte) ([]byte, error) { return crypto.Sign(d, key) }, OnInbound: func(c net.Conn, _ *enode.Node) error { return c.Close() }, SourceID: "common-a", PublicGatewayOrigin: origin})
		if err != nil {
			t.Fatal(err)
		}
		defer mesh.Stop()
		if err = mesh.Start(); err != nil {
			t.Fatal(err)
		}
		h := newBrowserMeshHTTP(context.Background(), mesh, []string{"https://gateway.example.org"})
		h.requests = rate.NewLimiter(rate.Inf, 1)
		h.start()
		defer h.stop()
		request := func(method, origin, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, "/relay/v1/mesh/endpoint", strings.NewReader(body))
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w
		}
		w := request("GET", "https://gateway.example.org", "")
		want := 404
		if enabled {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("enabled=%v status=%d", enabled, w.Code)
		}
		if enabled {
			var envelope browserrelay.MeshAdvertisement
			if json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
				t.Fatal("endpoint JSON")
			}
			expected, _ := mesh.Endpoint()
			if expected != envelope || w.Body.Len() > 8192 {
				t.Fatal("endpoint envelope changed")
			}
		}
		if request("GET", "https://evil.example.org", "").Code != 403 {
			t.Fatal("Origin bypass")
		}
		if request("GET", "https://gateway.example.org", "{}").Code != 400 {
			t.Fatal("endpoint body accepted")
		}
		if request("POST", "https://gateway.example.org", "").Code != 404 {
			t.Fatal("endpoint write accepted")
		}
		if mesh.Status().Sessions != 0 || mesh.Status().Circuits != 0 {
			t.Fatal("descriptor GET created session/circuit")
		}
		h.stop()
		if request("GET", "https://gateway.example.org", "").Code != 503 {
			t.Fatal("endpoint after stop")
		}
	}
}
