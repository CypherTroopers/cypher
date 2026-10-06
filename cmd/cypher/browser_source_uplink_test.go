package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/node/browserrelay"
	"github.com/cypherium/cypher/p2p/enode"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestBrowserSourcePipeOwnsHijackedConnections(t *testing.T) {
	ended := make(chan struct{})
	s := newSourceLocalHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(ended)
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_ = ws.WriteMessage(websocket.TextMessage, []byte("hello"))
		_, _, _ = ws.ReadMessage()
	}))
	d := websocket.Dialer{NetDialContext: s.listener.DialContext, HandshakeTimeout: time.Second}
	ws, _, err := d.Dial("ws://mesh-in-process/relay/v1/mesh/connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_, raw, err := ws.ReadMessage()
	if err != nil || string(raw) != "hello" {
		t.Fatal("in-process WS handshake", err)
	}
	s.Close()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("hijacked handler outlived source shutdown")
	}
	s.listener.mu.Lock()
	count := len(s.listener.connections)
	s.listener.mu.Unlock()
	if count != 0 {
		t.Fatal("closed connection ownership leaked")
	}
	if _, err = s.listener.DialContext(context.Background(), "ignored", "ignored"); err == nil {
		t.Fatal("closed pipe listener resurrected")
	}
}

func TestBrowserSourceLocalHTTPReusesNativeOriginAndBodyGuards(t *testing.T) {
	h := newBrowserMeshHTTP(context.Background(), nil, []string{"https://gateway.example.org"})
	h.start()
	defer h.stop()
	s := newSourceLocalHTTP(h)
	defer s.Close()
	client := &http.Client{Transport: s.transport, Timeout: time.Second}
	for _, tc := range []struct {
		path, origin, body string
		status             int
	}{
		{"config", "https://gateway.example.org", "", 200},
		{"config", "https://attacker.example.org", "", 403},
		{"../source-config", "https://gateway.example.org", "", 404},
		{"sessions", "https://gateway.example.org", strings.Repeat("x", 1025), 400},
	} {
		method := "GET"
		if tc.body != "" {
			method = "POST"
		}
		req, _ := http.NewRequest(method, "http://mesh-in-process/relay/v1/mesh/"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Origin", tc.origin)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: %d", tc.path, resp.StatusCode)
		}
	}
}

func TestBrowserSourcePipeCancelledDialReleasesSlot(t *testing.T) {
	l := newSourcePipeListener()
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.DialContext(ctx, "ignored", "ignored"); err == nil {
		t.Fatal("cancelled dial accepted")
	}
	l.mu.Lock()
	count := len(l.connections)
	l.mu.Unlock()
	if count != 0 {
		t.Fatal("cancelled dial leaked capacity")
	}
}

// The TLS server uses the standard test certificate for example.com. Only this
// fixture remaps its socket; production uses verified TLS and ordinary DNS.
func sourceTLSFixture(t *testing.T) (*browserSourceUplink, *websocket.Conn, *browserMeshHTTP) {
	t.Helper()
	const origin = "https://example.com"
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	node := enode.NewV4(&key.PublicKey, net.ParseIP("127.0.0.1"), 30445, 0)
	mesh, err := browserrelay.NewMesh(browserrelay.MeshConfig{Network: browserrelay.Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("2", 64)}, LocalNode: func() *enode.Node { return node }, SourceID: "common-mine", PublicGatewayOrigin: origin, SignDigest: func(raw []byte) ([]byte, error) { return crypto.Sign(raw, key) }, OnInbound: func(c net.Conn, _ *enode.Node) error { return c.Close() }})
	if err != nil {
		t.Fatal(err)
	}
	if err = mesh.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mesh.Stop() })
	h := newBrowserMeshHTTP(context.Background(), mesh, []string{origin})
	h.start()
	t.Cleanup(h.stop)
	accepted := make(chan *websocket.Conn, 1)
	faults := make(chan error, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != sourceBase+"source" || r.Header.Get("Origin") != origin || r.TLS == nil {
			faults <- fmt.Errorf("incorrect source TLS/route/origin")
			http.Error(w, "bad", 400)
			return
		}
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		ws, e := up.Upgrade(w, r, nil)
		if e != nil {
			faults <- e
			return
		}
		challenge := []byte(fmt.Sprintf(`{"version":1,"origin":%q,"nonce":"00112233445566778899aabbccddeeff","expiresAt":%d}`, origin, time.Now().Add(5*time.Second).UnixMilli()))
		if e = ws.WriteJSON(map[string]any{"kind": "challenge", "challenge": base64.StdEncoding.EncodeToString(challenge)}); e != nil {
			faults <- e
			ws.Close()
			return
		}
		ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		var auth struct {
			Kind         string
			Endpoint     browserrelay.MeshAdvertisement
			SignatureHex string
		}
		if e = ws.ReadJSON(&auth); e != nil {
			faults <- e
			ws.Close()
			return
		}
		signature, e := hex.DecodeString(auth.SignatureHex)
		if e != nil {
			faults <- e
			ws.Close()
			return
		}
		pub, e := crypto.Ecrecover(crypto.Keccak256([]byte(sourceAuthDomain), challenge), signature)
		raw, _ := base64.StdEncoding.DecodeString(auth.Endpoint.PayloadBase64)
		var endpoint struct {
			SourceID      string
			GatewayOrigin string
		}
		_ = json.Unmarshal(raw, &endpoint)
		if e != nil || auth.Kind != "auth" || !bytes.Equal(pub, crypto.FromECDSAPub(&key.PublicKey)) || endpoint.SourceID != node.ID().String() || endpoint.GatewayOrigin != origin {
			faults <- fmt.Errorf("source proof/unique identity invalid: %v", e)
			ws.Close()
			return
		}
		if e = ws.WriteJSON(map[string]any{"kind": "ready", "sourceId": node.ID().String(), "nodeId": node.ID().String()}); e != nil {
			faults <- e
			ws.Close()
			return
		}
		accepted <- ws
	}))
	t.Cleanup(server.Close)
	u := newBrowserSourceUplink(mesh, h, origin, func(raw []byte) ([]byte, error) { return crypto.Sign(raw, key) })
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.dialer.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	u.dialer.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "example.com:443" {
			return nil, fmt.Errorf("wrong dial target")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	u.retryDelay = func(int) time.Duration { return time.Hour }
	if err = u.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Stop)
	select {
	case ws := <-accepted:
		t.Cleanup(func() { ws.Close() })
		return u, ws, h
	case err := <-faults:
		t.Fatal(err)
	case <-time.After(8 * time.Second):
		t.Fatal("source TLS handshake timed out")
	}
	return nil, nil, nil
}
func sourceReadPacket(t *testing.T, ws *websocket.Conn) map[string]json.RawMessage {
	t.Helper()
	ws.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, raw, err := ws.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]json.RawMessage
	if json.Unmarshal(raw, &p) != nil {
		t.Fatal("invalid source JSON")
	}
	return p
}
func sourceTestRequest(t *testing.T, ws *websocket.Conn, n int, method, path, token string) (int, []byte) {
	t.Helper()
	id := fmt.Sprintf("%032x", n)
	if err := ws.WriteJSON(sourcePacket{Kind: "request", ID: id, Method: method, Path: sourceBase + path, Token: token}); err != nil {
		t.Fatal(err)
	}
	p := sourceReadPacket(t, ws)
	var kind, gotID, body string
	var status int
	_ = json.Unmarshal(p["kind"], &kind)
	_ = json.Unmarshal(p["id"], &gotID)
	_ = json.Unmarshal(p["status"], &status)
	_ = json.Unmarshal(p["body"], &body)
	if kind != "reply" || gotID != id {
		t.Fatalf("unexpected source reply kind=%s id=%s", kind, gotID)
	}
	raw, err := sourceBase64(body, 65536)
	if err != nil {
		t.Fatal(err)
	}
	return status, raw
}
func sourceLocalToken(t *testing.T, h *browserMeshHTTP, origin string) string {
	t.Helper()
	req := httptest.NewRequest("POST", sourceBase+"sessions", nil)
	req.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var result struct{ Token string }
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatalf("local lease: %d", w.Code)
	}
	return result.Token
}
func sourceTokenPresent(h *browserMeshHTTP, token string) bool {
	key, _ := browserMeshToken(token)
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[key] != nil
}
func sourceWait(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("source cleanup condition timed out")
}

func TestBrowserSourceTLSHTTPWebSocketOwnershipAndCleanup(t *testing.T) {
	u, ws, h := sourceTLSFixture(t)
	localToken := sourceLocalToken(t, h, u.origin)
	if status, raw := sourceTestRequest(t, ws, 1, "GET", "config", ""); status != 200 || !bytes.Contains(raw, []byte(`"maxSessions":80`)) {
		t.Fatalf("native config %d %s", status, raw)
	}
	status, raw := sourceTestRequest(t, ws, 2, "POST", "sessions", "")
	var owned struct{ Token string }
	_ = json.Unmarshal(raw, &owned)
	if status != 201 || !sourceHex(owned.Token, 64) {
		t.Fatal("source lease failed")
	}
	if status, _ = sourceTestRequest(t, ws, 3, "POST", "renew", localToken); status != 401 {
		t.Fatal("source renewed an owner token")
	}
	if status, _ = sourceTestRequest(t, ws, 4, "POST", "renew", owned.Token); status != 200 {
		t.Fatal("source failed owned renewal")
	}
	id := strings.Repeat("a", 32)
	if err := ws.WriteJSON(sourcePacket{Kind: "open", ID: id, Token: owned.Token}); err != nil {
		t.Fatal(err)
	}
	p := sourceReadPacket(t, ws)
	if string(p["kind"]) != `"opened"` {
		t.Fatal("missing opened")
	}
	auth, _ := json.Marshal(map[string]string{"token": owned.Token})
	if err := ws.WriteJSON(sourcePacket{Kind: "message", ID: id, Data: base64.StdEncoding.EncodeToString(auth)}); err != nil {
		t.Fatal(err)
	}
	p = sourceReadPacket(t, ws)
	var data string
	_ = json.Unmarshal(p["data"], &data)
	hello, _ := sourceBase64(data, 16384)
	if string(p["kind"]) != `"message"` || !bytes.Contains(hello, []byte(`"protocol":"cypher-browser-mesh/1"`)) {
		t.Fatalf("native hello missing %s", hello)
	}
	sourceWait(t, func() bool { return h.mesh.Status().Sessions == 1 })
	// A second lease has no WS: shutdown must revoke both and retain owner lease.
	status, raw = sourceTestRequest(t, ws, 5, "POST", "sessions", "")
	var httpOnly struct{ Token string }
	_ = json.Unmarshal(raw, &httpOnly)
	if status != 201 {
		t.Fatal("HTTP-only lease")
	}
	ws.Close()
	sourceWait(t, func() bool {
		return !sourceTokenPresent(h, owned.Token) && !sourceTokenPresent(h, httpOnly.Token) && h.mesh.Status().Sessions == 0
	})
	if !sourceTokenPresent(h, localToken) {
		t.Fatal("source shutdown revoked owner lease")
	}
	u.Stop()
	if err := u.Start(); err == nil {
		t.Fatal("stopped uplink revived")
	}
}

func TestBrowserSourceChallengeAndPacketStrictness(t *testing.T) {
	raw := []byte(`{"version":1,"origin":"https://gateway.example.org","nonce":"00112233445566778899aabbccddeeff","expiresAt":1700000005000}`)
	now := time.UnixMilli(1700000000000)
	if err := validateSourceChallenge(raw, "https://gateway.example.org", now); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(crypto.Keccak256([]byte(sourceAuthDomain), raw)); got != "876d3a9c9a0c849736f842c6d077bbc1fb658002b4675df851d5906531cb8362" {
		t.Fatal("Go/Noble source digest mismatch")
	}
	for _, bad := range []string{strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(raw), `1700000005000`, `1700000000000`, 1), strings.Replace(string(raw), `1700000005000`, `1700000010000`, 1), strings.Replace(string(raw), `"origin":`, `"extra":0,"origin":`, 1), strings.Replace(string(raw), `gateway.example.org`, `attacker.example.org`, 1)} {
		if validateSourceChallenge([]byte(bad), "https://gateway.example.org", now) == nil {
			t.Fatal("invalid source challenge accepted")
		}
	}
	for _, bad := range []string{`{"kind":"close","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, `{"kind":"close","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","token":null}`, `{"kind":"binary","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, `{"kind":"message","id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","data":""}`} {
		if _, err := decodeSourcePacket([]byte(bad)); err == nil {
			t.Fatal("invalid source packet accepted")
		}
	}
	for _, bad := range []string{"YQ", "YR==", "YQ==\n"} {
		if _, err := sourceBase64(bad, 16); err == nil {
			t.Fatal("noncanonical base64 accepted")
		}
	}
}

type sourceDelayedBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *sourceDelayedBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *sourceDelayedBody) Close() error { return nil }
func TestBrowserSourceLateIssuanceRevokedAfterDisconnect(t *testing.T) {
	h := newBrowserMeshHTTP(context.Background(), nil, []string{"https://gateway.example.org"})
	h.start()
	defer h.stop()
	u := newBrowserSourceUplink(nil, h, "https://gateway.example.org", nil)
	s := newSourceSession(u, nil)
	owner := sourceLocalToken(t, h, u.origin)
	body := &sourceDelayedBody{entered: make(chan struct{}), release: make(chan struct{})}
	req := httptest.NewRequest("POST", sourceBase+"sessions", nil)
	req.Body = body
	req.Header.Set("Origin", u.origin)
	w := httptest.NewRecorder()
	handled := make(chan struct{})
	go func() { s.serveHTTP(w, req); close(handled) }()
	<-body.entered
	stopped := make(chan struct{})
	go func() { s.close(); close(stopped) }()
	sourceWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closed })
	close(body.release)
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("source shutdown blocked")
	}
	<-handled
	h.mu.Lock()
	count := len(h.sessions)
	h.mu.Unlock()
	if count != 1 || !sourceTokenPresent(h, owner) {
		t.Fatalf("late issuance leaked or owner removed: %d", count)
	}
	if w.Code != 503 {
		t.Fatalf("late response succeeded: %d", w.Code)
	}
}

func TestBrowserSourceRequestPathsHistoryAndQueueBounds(t *testing.T) {
	h := newBrowserMeshHTTP(context.Background(), nil, []string{"https://gateway.example.org"})
	h.start()
	defer h.stop()
	u := newBrowserSourceUplink(nil, h, "https://gateway.example.org", nil)
	s := newSourceSession(u, nil)
	defer s.close()
	for _, p := range []sourcePacket{{Kind: "request", ID: strings.Repeat("1", 32), Method: "GET", Path: "/"}, {Kind: "request", ID: strings.Repeat("1", 32), Method: "GET", Path: sourceBase + "endpoint"}, {Kind: "request", ID: strings.Repeat("1", 32), Method: "POST", Path: sourceBase + "sessions", Body: base64.StdEncoding.EncodeToString([]byte(" {}"))}} {
		if s.request(p) == nil {
			t.Fatal("arbitrary source path/body accepted")
		}
	}
	for i := 0; i < sourceStreamHistory; i++ {
		s.history[fmt.Sprintf("%032x", i)] = true
	}
	if s.open(sourcePacket{ID: strings.Repeat("f", 32), Token: strings.Repeat("a", 64)}) == nil {
		t.Fatal("stream history unbounded")
	}
	// Include a packet already reserved by a writer, not only queued packets.
	s.queuedFrames = 1
	s.queuedBytes = 10
	for i := 0; i < sourceQueueFrames-1; i++ {
		if err := s.send(map[string]string{"kind": "close", "id": fmt.Sprintf("%032x", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if s.send(map[string]string{"kind": "close", "id": strings.Repeat("b", 32)}) == nil {
		t.Fatal("in-flight packet excluded from queue limit")
	}
}

func TestBrowserSourceInnerSlowWriterKeepsReservations(t *testing.T) {
	accepted := make(chan struct{})
	release := make(chan struct{})
	local := newSourceLocalHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		close(accepted)
		<-release
	}))
	defer local.Close()
	defer close(release)
	dial := websocket.Dialer{NetDialContext: local.listener.DialContext}
	ws, _, err := dial.Dial("ws://mesh-in-process/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	<-accepted
	h := newBrowserMeshHTTP(context.Background(), nil, []string{"https://gateway.example.org"})
	h.start()
	defer h.stop()
	u := newBrowserSourceUplink(nil, h, "https://gateway.example.org", nil)
	s := newSourceSession(u, nil)
	defer s.close()
	token := strings.Repeat("a", 64)
	id := strings.Repeat("b", 32)
	st := &sourceStream{session: s, id: id, token: token, ws: ws, input: make(chan sourceInput, sourceQueueFrames), done: make(chan struct{})}
	s.streams[id] = st
	s.history[id] = true
	s.wg.Add(1)
	go st.write()
	auth, _ := json.Marshal(map[string]string{"token": token})
	p := sourcePacket{Kind: "message", ID: id, Data: base64.StdEncoding.EncodeToString(auth)}
	if err = s.input(p); err != nil {
		t.Fatal(err)
	}
	sourceWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(st.input) == 0 })
	s.mu.Lock()
	count := s.incomingFrames
	s.mu.Unlock()
	if count != 1 {
		t.Fatal("blocked write lost reservation")
	}
	for i := 0; i < 63; i++ {
		if err = s.input(p); err != nil {
			t.Fatal(err)
		}
	}
	if s.input(p) == nil {
		t.Fatal("65th reserved frame accepted")
	}
	st.stop()
	sourceWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.incomingFrames == 0 && s.incomingBytes == 0 })
}

func TestBrowserSourceCancelledRequestCannotLeaveHTTPOnlyLease(t *testing.T) {
	h := newBrowserMeshHTTP(context.Background(), nil, []string{"https://gateway.example.org"})
	h.start()
	defer h.stop()
	u := newBrowserSourceUplink(nil, h, "https://gateway.example.org", nil)
	s := newSourceSession(u, nil)
	defer s.close()
	owner := sourceLocalToken(t, h, u.origin)
	body := &sourceDelayedBody{entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", sourceBase+"sessions", nil).WithContext(ctx)
	req.Body = body
	req.Header.Set("Origin", u.origin)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.serveHTTP(w, req); close(done) }()
	<-body.entered
	cancel()
	close(body.release)
	<-done
	h.mu.Lock()
	count := len(h.sessions)
	h.mu.Unlock()
	if count != 1 || !sourceTokenPresent(h, owner) || s.ctx.Err() != nil {
		t.Fatalf("cancelled request leaked lease or killed generation: %d", count)
	}
}
func TestBrowserSourceTLSRejectsUntrustedCertificate(t *testing.T) {
	u, ws, _ := sourceTLSFixture(t)
	u.Stop()
	ws.Close()
	v := newBrowserSourceUplink(u.mesh, u.handler, u.origin, u.sign)
	v.dialer.NetDialContext = u.dialer.NetDialContext
	if err := v.connect(); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	v.Stop()
}
