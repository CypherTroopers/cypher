package lightnode

// These tests exercise the real HTTP handler with explicitly synthetic owned
// views. Their opaque bytes are not real chain RLP or a finality verification.
import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var syntheticNetwork = Network{10101919, "0x" + strings.Repeat("1", 64)}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type syntheticStore struct {
	mu            sync.Mutex
	head          uint64
	network       Network
	headers       map[uint64][]byte
	calls, closes int32
	entered       chan struct{}
	release       chan struct{}
	honorCancel   bool
	factoryError  bool
	onHeader      func()
}
type syntheticView struct {
	store *syntheticStore
	once  sync.Once
}

func (s *syntheticStore) Factory(context.Context) (View, error) {
	atomic.AddInt32(&s.calls, 1)
	v := &syntheticView{store: s}
	if s.factoryError {
		return v, errors.New("synthetic failed factory")
	}
	return v, nil
}
func (v *syntheticView) Network() Network { return v.store.network }
func (v *syntheticView) LatestHeight(ctx context.Context) (uint64, error) {
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	return v.store.head, ctx.Err()
}
func syntheticBytes(h uint64) []byte {
	return []byte(fmt.Sprintf("SYNTHETIC-not-chain-header:%d:full-SignInfo", h))
}
func (v *syntheticView) HeaderRLP(ctx context.Context, h uint64, limit int) ([]byte, error) {
	s := v.store
	if s.onHeader != nil {
		s.onHeader()
	}
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.release != nil {
		if s.honorCancel {
			select {
			case <-s.release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			<-s.release
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.headers[h]
	if b == nil {
		b = syntheticBytes(h)
	}
	return b, nil // The handler independently enforces the cap and copies ownership.
}
func (v *syntheticView) Close() error {
	v.once.Do(func() { atomic.AddInt32(&v.store.closes, 1) })
	return nil
}
func setup(t *testing.T) (*Server, *syntheticStore, *testClock) {
	t.Helper()
	c := &testClock{now: time.Unix(1700000000, 0)}
	store := &syntheticStore{head: 100, network: syntheticNetwork, headers: make(map[uint64][]byte)}
	s, err := New(Config{Enabled: true, ListenAddr: "127.0.0.1:18083", AllowedPageOrigin: "http://127.0.0.1:18081", ExpectedNetwork: syntheticNetwork, Factory: store.Factory, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, store, c
}
func rawRequest(s *Server, method, path, token string, b []byte, edit func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:18083"+path, bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:12000"
	r.Header.Set("Origin", "http://127.0.0.1:18081")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if len(b) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	if edit != nil {
		edit(r)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func request(s *Server, method, path, token string, p interface{}) *httptest.ResponseRecorder {
	var b []byte
	if p != nil {
		b, _ = json.Marshal(p)
	}
	return rawRequest(s, method, path, token, b, nil)
}
func connect(t *testing.T, s *Server) string {
	t.Helper()
	w := request(s, "POST", "/v1/on", "", map[string]interface{}{"userApproved": true})
	if w.Code != 201 {
		t.Fatalf("on=%d %s", w.Code, w.Body.String())
	}
	var response struct {
		SessionToken string  `json:"sessionToken"`
		Network      Network `json:"network"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !lowerHex(response.SessionToken, 64) || response.Network != syntheticNetwork {
		t.Fatal("invalid on contract")
	}
	return response.SessionToken
}

type pullResponse struct {
	Packet       *Packet `json:"packet"`
	Source       string  `json:"source"`
	Window       Window  `json:"window"`
	ReceiptToken *string `json:"receiptToken"`
}

func pull(t *testing.T, s *Server, token string) pullResponse {
	t.Helper()
	w := request(s, "POST", "/v1/pull", token, map[string]interface{}{"userApproved": true})
	if w.Code != 200 {
		t.Fatalf("pull=%d %s", w.Code, w.Body.String())
	}
	var p pullResponse
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func forward(t *testing.T, s *Server, token string, p Packet) *httptest.ResponseRecorder {
	t.Helper()
	return request(s, "POST", "/v1/forward", token, map[string]interface{}{"userApproved": true, "packet": p})
}
func ackRequest(s *Server, token, nonce string, p Packet) *httptest.ResponseRecorder {
	return request(s, "POST", "/v1/ack", token, map[string]interface{}{"userApproved": true, "receiptToken": nonce, "digest": p.Digest, "headerRLP": p.HeaderRLP})
}
func leaseFor(s *Server, token string) *lease {
	r := httptest.NewRequest("GET", "http://localhost", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return s.authenticate(r)
}

func TestDisabledAndConfigurationFailClosed(t *testing.T) {
	calls := 0
	s, err := New(Config{Factory: func(context.Context) (View, error) { calls++; return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	w := request(s, "POST", "/v1/on", "", map[string]interface{}{"userApproved": true})
	if w.Code != 503 || calls != 0 {
		t.Fatal("disabled source activity")
	}
	s.Close()
	base := Config{Enabled: true, ListenAddr: "127.0.0.1:18083", AllowedPageOrigin: "http://127.0.0.1:18081", ExpectedNetwork: syntheticNetwork, Factory: func(context.Context) (View, error) { return nil, nil }}
	for _, addr := range []string{"localhost:18083", "0.0.0.0:18083", "127.0.0.1:018083", "127.0.0.1:0", "2130706433:18083", "[::1%lo]:18083"} {
		c := base
		c.ListenAddr = addr
		if _, err := New(c); err == nil {
			t.Errorf("accepted addr %s", addr)
		}
	}
	for _, origin := range []string{"http://localhost:18081", "https://127.0.0.1:18081", "http://127.0.0.1:18081/", "http://user@127.0.0.1:18081", "http://127.0.0.1:018081", "null"} {
		c := base
		c.AllowedPageOrigin = origin
		if _, err := New(c); err == nil {
			t.Errorf("accepted origin %s", origin)
		}
	}
	c := base
	c.ExpectedNetwork.GenesisHash = "0x" + strings.Repeat("0", 64)
	if _, err := New(c); err == nil {
		t.Fatal("zero genesis")
	}
	c = base
	c.Factory = nil
	if _, err := New(c); err == nil {
		t.Fatal("missing factory")
	}
	c = base
	c.ListenAddr = "[::1]:18083"
	c.AllowedPageOrigin = "http://[::1]:18081"
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedHTTPSOriginConfigurationIsExactAndDisabledByDefault(t *testing.T) {
	const origin = "https://ai-test.make-cph-great-again.community"
	store := &syntheticStore{head: 100, network: syntheticNetwork, headers: make(map[uint64][]byte)}
	base := Config{Enabled: true, ListenAddr: "127.0.0.1:18083", AllowedPageOrigin: origin, ExpectedNetwork: syntheticNetwork, Factory: store.Factory}
	s, err := New(base)
	if err != nil || s == nil {
		t.Fatalf("exact selected HTTPS origin rejected: %v", err)
	}
	s.Close()
	for _, value := range []string{
		"https://other.make-cph-great-again.community",
		"https://ai-test.make-cph-great-again.community:443",
		"https://ai-test.make-cph-great-again.community/",
		"https://AI-TEST.make-cph-great-again.community",
		"HTTPS://ai-test.make-cph-great-again.community",
		"https://user@ai-test.make-cph-great-again.community",
		"https://*.make-cph-great-again.community",
		"https://ai-test.make-cph-great-again.community.",
		"http://ai-test.make-cph-great-again.community",
		"https://ai-test.make-cph-great-again.community?target=x",
		"https://ai-test.make-cph-great-again.community#x",
		"https://%61i-test.make-cph-great-again.community",
	} {
		c := base
		c.AllowedPageOrigin = value
		if candidate, err := New(c); err == nil {
			candidate.Close()
			t.Errorf("nonexact selected origin accepted: %q", value)
		}
	}
	for _, address := range []string{"0.0.0.0:18083", "ai-test.make-cph-great-again.community:18083"} {
		c := base
		c.ListenAddr = address
		if candidate, err := New(c); err == nil {
			candidate.Close()
			t.Errorf("public page origin widened listener: %q", address)
		}
	}
	c := base
	c.ExpectedNetwork.GenesisHash = "0x" + strings.Repeat("0", 64)
	if candidate, err := New(c); err == nil {
		candidate.Close()
		t.Fatal("selected origin bypassed required network pins")
	}
	// A recognized public origin supplies no enablement, source acquisition or
	// session permission. This remains a synthetic-source constructor check.
	disabled, err := New(Config{AllowedPageOrigin: origin, Factory: store.Factory})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disabled.Close() })
	w := rawRequest(disabled, "POST", "/v1/on", "", []byte(`{"userApproved":true}`), func(r *http.Request) { r.Header.Set("Origin", origin) })
	if w.Code != 503 || atomic.LoadInt32(&store.calls) != 0 || disabled.admissions != 0 {
		t.Fatal("recognized origin activated the disabled service")
	}
}

func TestSelectedHTTPSOriginRequestsKeepLoopbackAndNetworkGates(t *testing.T) {
	const origin = "https://ai-test.make-cph-great-again.community"
	private, store, _ := setup(t)
	c := private.config
	private.Close()
	c.AllowedPageOrigin = origin
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	send := func(method, path, token string, edit func(*http.Request)) *httptest.ResponseRecorder {
		var body []byte
		if method == "POST" {
			body = []byte(`{"userApproved":true}`)
		}
		return rawRequest(s, method, path, token, body, func(r *http.Request) {
			r.Header.Set("Origin", origin)
			if edit != nil {
				edit(r)
			}
		})
	}
	for name, edit := range map[string]func(*http.Request){
		"other HTTPS": func(r *http.Request) { r.Header.Set("Origin", "https://other.make-cph-great-again.community") },
		"private origin is not an automatic second origin": func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:18081") },
		"explicit443":      func(r *http.Request) { r.Header.Set("Origin", origin+":443") },
		"slash":            func(r *http.Request) { r.Header.Set("Origin", origin+"/") },
		"missing origin":   func(r *http.Request) { r.Header.Del("Origin") },
		"duplicate origin": func(r *http.Request) { r.Header.Add("Origin", origin) },
		"public Host":      func(r *http.Request) { r.Host = "ai-test.make-cph-great-again.community" },
		"remote client":    func(r *http.Request) { r.RemoteAddr = "192.0.2.1:123" },
		"TLS backend":      func(r *http.Request) { r.TLS = &tls.ConnectionState{} },
	} {
		t.Run(name, func(t *testing.T) {
			if w := send("POST", "/v1/on", "", edit); w.Code != 403 {
				t.Fatalf("request gate accepted %q: %d", name, w.Code)
			}
		})
	}
	if atomic.LoadInt32(&store.calls) != 0 || s.admissions != 0 {
		t.Fatal("rejected public requests acquired source or session")
	}
	w := send("OPTIONS", "/v1/pull", "", func(r *http.Request) { r.Header.Set("Access-Control-Request-Method", "POST") })
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != origin || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("selected-origin CORS contract")
	}
	w = send("POST", "/v1/on", "", nil)
	var session struct {
		SessionToken string  `json:"sessionToken"`
		Network      Network `json:"network"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &session) != nil || session.Network != syntheticNetwork || !lowerHex(session.SessionToken, 64) || atomic.LoadInt32(&store.calls) != 0 {
		t.Fatal("selected-origin passive ON contract")
	}
	w = send("POST", "/v1/pull", session.SessionToken, nil)
	var p pullResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Packet == nil || p.Source != "common" || p.Packet.Network != syntheticNetwork {
		t.Fatalf("approved selected-origin synthetic pull: %d %s", w.Code, w.Body.String())
	}
	if _, err := validPacket(*p.Packet, syntheticNetwork); err != nil {
		t.Fatal("selected origin bypassed packet byte binding")
	}
	store.network.ChainID++
	w = send("POST", "/v1/pull", session.SessionToken, nil)
	if w.Code != 502 || strings.Contains(w.Body.String(), `"packet"`) || atomic.LoadInt32(&store.calls) != 2 || atomic.LoadInt32(&store.closes) != 2 {
		t.Fatal("selected public origin bypassed owned-source network pins or cleanup")
	}
}

func TestOriginHostRouteAndCORSBoundaries(t *testing.T) {
	s, store, _ := setup(t)
	for name, edit := range map[string]func(*http.Request){
		"host": func(r *http.Request) { r.Host = "evil.example:18083" }, "remote": func(r *http.Request) { r.RemoteAddr = "192.0.2.1:123" },
		"missing origin": func(r *http.Request) { r.Header.Del("Origin") }, "duplicate origin": func(r *http.Request) { r.Header.Add("Origin", "http://127.0.0.1:18081") },
		"null origin": func(r *http.Request) { r.Header.Set("Origin", "null") }, "other port": func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:18082") },
	} {
		t.Run(name, func(t *testing.T) {
			w := rawRequest(s, "POST", "/v1/on", "", []byte(`{"userApproved":true}`), edit)
			if w.Code != 403 {
				t.Fatalf("%d", w.Code)
			}
		})
	}
	for _, path := range []string{"/v1/on?target=http://example.com", "/v1/unknown", "/v1/%6fn", "/v1/on?"} {
		w := rawRequest(s, "POST", path, "", []byte(`{"userApproved":true}`), nil)
		if w.Code != 404 {
			t.Errorf("path %s got %d", path, w.Code)
		}
	}
	w := rawRequest(s, "OPTIONS", "/v1/pull", "", nil, func(r *http.Request) {
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	})
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:18081" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("CORS contract")
	}
	w = rawRequest(s, "OPTIONS", "/v1/pull", "", nil, func(r *http.Request) {
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "X-Target")
	})
	if w.Code != 403 {
		t.Fatal("unsafe preflight")
	}
	if atomic.LoadInt32(&store.calls) != 0 {
		t.Fatal("gate opened source")
	}
}

func TestStrictJSONAndExplicitApproval(t *testing.T) {
	s, store, _ := setup(t)
	for _, body := range []string{`{"userApproved":false}`, `{"userApproved":true,"userApproved":true}`, `{"userApproved":false,"UserApproved":true}`, `{"USERAPPROVED":true}`, `{"userApproved":true,"target":"http://example.com"}`, `null`, `{"userApproved":true} {}`, `{"userApproved":1}`, `{"userApproved":true,"nested":{"x":1,"x":2}}`} {
		w := rawRequest(s, "POST", "/v1/on", "", []byte(body), nil)
		if w.Code != 400 {
			t.Errorf("accepted %s: %d", body, w.Code)
		}
	}
	body := append([]byte(`{"userApproved":true}`), bytes.Repeat([]byte(" "), maxJSON)...)
	if w := rawRequest(s, "POST", "/v1/on", "", body, nil); w.Code != 400 {
		t.Fatal("unbounded body")
	}
	if atomic.LoadInt32(&store.calls) != 0 {
		t.Fatal("invalid approval source I/O")
	}
	var p struct {
		X interface{} `json:"x"`
	}
	if strictJSON([]byte(`{"x":{"n":1,"n":2}}`), &p) == nil {
		t.Fatal("nested duplicate")
	}
}

func TestLatestWindowNoHistoricalAcquisitionAndExactDigest(t *testing.T) {
	s, store, _ := setup(t)
	token := connect(t, s)
	p := pull(t, s, token)
	if p.Source != "common" || p.Packet == nil || p.Packet.Height != 100 || p.Window != (Window{69, 100}) || p.ReceiptToken != nil {
		t.Fatalf("initial %+v", p)
	}
	raw, err := validPacket(*p.Packet, syntheticNetwork)
	if err != nil || !bytes.Equal(raw, syntheticBytes(100)) {
		t.Fatal("exact packet bytes")
	}
	if p.Packet.Digest != HeaderDigest(syntheticNetwork, 100, raw) {
		t.Fatal("digest")
	}
	if pull(t, s, token).Packet != nil {
		t.Fatal("unchanged latest repeated")
	}
	store.mu.Lock()
	store.head = 101
	store.mu.Unlock()
	if p = pull(t, s, token); p.Packet == nil || p.Packet.Height != 101 || p.Window.First != 70 {
		t.Fatal("latest did not advance")
	}
	if atomic.LoadInt32(&store.calls) != 3 || atomic.LoadInt32(&store.closes) != 3 {
		t.Fatal("fresh view ownership")
	}
	store.mu.Lock()
	store.head = 0
	store.mu.Unlock()
	if p = pull(t, s, token); p.Packet != nil || p.Window != (Window{}) {
		t.Fatal("genesis is not a packet")
	}
}

func TestFullByteCanonicalForwardAndRecentWindow(t *testing.T) {
	s, store, _ := setup(t)
	token := connect(t, s)
	p := pull(t, s, token)
	p.Packet.HeaderRLP = base64.StdEncoding.EncodeToString([]byte("modified full SignInfo"))
	p.Packet.Digest = HeaderDigest(syntheticNetwork, 100, []byte("modified full SignInfo"))
	if w := forward(t, s, token, *p.Packet); w.Code != 409 {
		t.Fatalf("full byte mismatch=%d", w.Code)
	}
	for _, h := range []uint64{69, 68} {
		packet := s.packet(h, syntheticBytes(h))
		w := forward(t, s, token, packet)
		if h == 69 && w.Code != 200 || h == 68 && w.Code != 409 {
			t.Errorf("height %d code %d", h, w.Code)
		}
	}
	packet := s.packet(100, syntheticBytes(100))
	packet.Digest = strings.Repeat("a", 64)
	if w := forward(t, s, token, packet); w.Code != 400 {
		t.Fatal("digest mismatch accepted")
	}
	if atomic.LoadInt32(&store.closes) != atomic.LoadInt32(&store.calls) {
		t.Fatal("source leaked")
	}
}

func TestIndependentConsumerExactBytesAckAndNoPeerClaim(t *testing.T) {
	s, _, _ := setup(t)
	a := connect(t, s)
	ap := pull(t, s, a)
	if w := forward(t, s, a, *ap.Packet); w.Code != 200 || !strings.Contains(w.Body.String(), `"consumed":false`) {
		t.Fatal("premature consumption")
	}
	b := connect(t, s)
	bp := pull(t, s, b)
	if bp.Source != "common" || bp.ReceiptToken != nil {
		t.Fatal("first pull not Common")
	}
	bp = pull(t, s, b)
	if bp.Source != "forwarded" || bp.Packet == nil || bp.ReceiptToken == nil {
		t.Fatal("no forwarded receive")
	}
	// Independently recompute the domain digest from the actual received bytes.
	raw, err := base64.StdEncoding.Strict().DecodeString(bp.Packet.HeaderRLP)
	if err != nil || !bytes.Equal(raw, syntheticBytes(100)) || HeaderDigest(bp.Packet.Network, bp.Packet.Height, raw) != bp.Packet.Digest {
		t.Fatal("consumer bytes verification")
	}
	w := request(s, "GET", "/v1/status", a, nil)
	if !strings.Contains(w.Body.String(), `"consumed":false`) {
		t.Fatal("delivery alone counted as ack")
	}
	if w = ackRequest(s, b, *bp.ReceiptToken, *bp.Packet); w.Code != 200 {
		t.Fatalf("ack %d %s", w.Code, w.Body.String())
	}
	if w = ackRequest(s, b, *bp.ReceiptToken, *bp.Packet); w.Code != 409 {
		t.Fatal("receipt replay")
	}
	w = request(s, "GET", "/v1/status", a, nil)
	if !strings.Contains(w.Body.String(), `"consumed":true`) || !strings.Contains(w.Body.String(), `"consumerAcknowledgements":1`) || strings.Contains(w.Body.String(), "authenticatedPeer") || strings.Contains(w.Body.String(), "sessionToken") {
		t.Fatalf("status %s", w.Body.String())
	}
	if pull(t, s, b).Packet != nil {
		t.Fatal("same consumer packet reissued after ack")
	}
}

func TestReceiptBoundToLeaseAndExactBytesSingleUse(t *testing.T) {
	s, _, _ := setup(t)
	a := connect(t, s)
	ap := pull(t, s, a)
	if forward(t, s, a, *ap.Packet).Code != 200 {
		t.Fatal("forward")
	}
	b := connect(t, s)
	pull(t, s, b)
	bp := pull(t, s, b)
	c := connect(t, s)
	pull(t, s, c)
	if ackRequest(s, c, *bp.ReceiptToken, *bp.Packet).Code != 409 {
		t.Fatal("cross lease receipt")
	}
	bad := *bp.Packet
	bad.HeaderRLP = base64.StdEncoding.EncodeToString([]byte("different exact bytes"))
	if ackRequest(s, b, *bp.ReceiptToken, bad).Code != 409 {
		t.Fatal("mutated ack")
	}
	if ackRequest(s, b, *bp.ReceiptToken, *bp.Packet).Code != 409 {
		t.Fatal("mutated attempt did not consume nonce")
	}
	bp = pull(t, s, b)
	if bp.ReceiptToken == nil || ackRequest(s, b, *bp.ReceiptToken, *bp.Packet).Code != 200 {
		t.Fatal("fresh receipt after failed attempt")
	}
}

func TestRetainedPacketReorgAndOwnerOffInvalidateReceipts(t *testing.T) {
	s, store, _ := setup(t)
	a := connect(t, s)
	ap := pull(t, s, a)
	forward(t, s, a, *ap.Packet)
	b := connect(t, s)
	pull(t, s, b)
	store.mu.Lock()
	store.headers[100] = []byte("SYNTHETIC-reorg-with-different-SignInfo")
	store.mu.Unlock()
	p := pull(t, s, b)
	if p.Source != "common" || p.ReceiptToken != nil {
		t.Fatal("reorged retained bytes delivered")
	}
	w := request(s, "GET", "/v1/status", a, nil)
	if !strings.Contains(w.Body.String(), `"retained":false`) {
		t.Fatal("stale cache not removed")
	}
	if p.Packet == nil || forward(t, s, b, *p.Packet).Code != 200 {
		t.Fatal("fresh reorg packet")
	}
	c := connect(t, s)
	pull(t, s, c)
	cp := pull(t, s, c)
	if cp.ReceiptToken == nil {
		t.Fatal("new cache")
	}
	if request(s, "DELETE", "/v1/off", b, nil).Code != 204 || ackRequest(s, c, *cp.ReceiptToken, *cp.Packet).Code != 409 {
		t.Fatal("owner off did not revoke cache receipt")
	}
}

func TestStatusNoSourceOrIdleRefreshAndAbsoluteLifetime(t *testing.T) {
	s, store, clock := setup(t)
	token := connect(t, s)
	clock.Add(29 * time.Second)
	w := request(s, "GET", "/v1/status", token, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"latestHeight":null`) || !strings.Contains(w.Body.String(), `"idleExpiresInMs":1000`) {
		t.Fatal(w.Body.String())
	}
	clock.Add(time.Second)
	if request(s, "GET", "/v1/status", token, nil).Code != 401 {
		t.Fatal("status kept idle alive")
	}
	if atomic.LoadInt32(&store.calls) != 0 {
		t.Fatal("status source I/O")
	}
	token = connect(t, s)
	for i := 0; i < 29; i++ {
		clock.Add(20 * time.Second)
		pull(t, s, token)
	}
	clock.Add(20 * time.Second)
	if request(s, "POST", "/v1/pull", token, map[string]bool{"userApproved": true}).Code != 401 {
		t.Fatal("absolute lease lifetime")
	}
}

func TestRateLimitOffAndLifetimeAdmissionCaps(t *testing.T) {
	s, _, _ := setup(t)
	token := connect(t, s)
	for i := 0; i < maxRequests; i++ {
		if w := request(s, "GET", "/v1/status", token, nil); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if request(s, "GET", "/v1/status", token, nil).Code != 429 {
		t.Fatal("rate cap")
	}
	if request(s, "DELETE", "/v1/off", token, nil).Code != 204 {
		t.Fatal("OFF rate limited")
	}
	for i := 1; i < maxAdmissions; i++ {
		token = connect(t, s)
		if request(s, "DELETE", "/v1/off", token, nil).Code != 204 {
			t.Fatal("off")
		}
	}
	if request(s, "POST", "/v1/on", "", map[string]bool{"userApproved": true}).Code != 503 {
		t.Fatal("lifetime admission count refunded")
	}
}

func TestActiveSessionCapAndBodyAndByteBudgets(t *testing.T) {
	s, _, _ := setup(t)
	tokens := make([]string, maxSessions)
	for i := range tokens {
		tokens[i] = connect(t, s)
	}
	if request(s, "POST", "/v1/on", "", map[string]bool{"userApproved": true}).Code != 503 {
		t.Fatal("active session cap")
	}
	l := leaseFor(s, tokens[0])
	s.mu.Lock()
	l.bytes = maxSessionBytes - 1
	s.mu.Unlock()
	if request(s, "POST", "/v1/pull", tokens[0], map[string]bool{"userApproved": true}).Code != 413 || leaseFor(s, tokens[0]) != nil {
		t.Fatal("session byte cap not revoked")
	}
	token := connect(t, s)
	body := []byte(`{"userApproved":true}`)
	body = append(body, bytes.Repeat([]byte(" "), maxJSON-len(body))...)
	if rawRequest(s, "POST", "/v1/pull", token, body, nil).Code != 200 {
		t.Fatal("exact JSON bound")
	}
	body = append(body, ' ')
	if rawRequest(s, "POST", "/v1/pull", token, body, nil).Code != 400 {
		t.Fatal("JSON over bound")
	}
}

func TestHeaderRawCapAndSourceFailureClosesExactlyOnce(t *testing.T) {
	for _, size := range []int{maxHeader, maxHeader + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, store, _ := setup(t)
			store.headers[100] = bytes.Repeat([]byte{0xaa}, size)
			token := connect(t, s)
			w := request(s, "POST", "/v1/pull", token, map[string]bool{"userApproved": true})
			if size == maxHeader && w.Code != 200 || size > maxHeader && w.Code != 502 {
				t.Fatal(w.Code)
			}
			if atomic.LoadInt32(&store.closes) != 1 {
				t.Fatal("view close")
			}
		})
	}
	s, store, _ := setup(t)
	store.factoryError = true
	token := connect(t, s)
	if request(s, "POST", "/v1/pull", token, map[string]bool{"userApproved": true}).Code != 502 || atomic.LoadInt32(&store.closes) != 1 {
		t.Fatal("factory error view leak")
	}
}

func TestCacheCountBytesTTLAndForwardAttemptBudget(t *testing.T) {
	s, store, clock := setup(t)
	token := connect(t, s)
	pull(t, s, token)
	for h := uint64(92); h <= 100; h++ {
		if forward(t, s, token, s.packet(h, syntheticBytes(h))).Code != 200 {
			t.Fatal("cache fill")
		}
	}
	s.mu.Lock()
	count, cacheBytes := len(s.cache), s.cacheBytes
	s.mu.Unlock()
	if count != maxCacheEntries || cacheBytes > maxCacheBytes {
		t.Fatal("entry capacity")
	}
	// Keep the lease alive while the earliest cache retention expires.
	clock.Add(20 * time.Second)
	pull(t, s, token)
	clock.Add(20 * time.Second)
	pull(t, s, token)
	clock.Add(20 * time.Second)
	pull(t, s, token)
	s.mu.Lock()
	count = len(s.cache)
	s.mu.Unlock()
	if count != 0 {
		t.Fatal("cache TTL not finite")
	}
	// Attempt quota is cumulative, including malformed packets, and rate windows
	// are not bypassed. Small synthetic packets keep the independent byte cap low.
	s2, _, c2 := setup(t)
	tok := connect(t, s2)
	pull(t, s2, tok)
	for i := 0; i < maxForwards; i++ {
		c2.Add(10 * time.Second)
		w := forward(t, s2, tok, Packet{})
		if w.Code != 400 {
			t.Fatalf("attempt %d=%d", i, w.Code)
		}
		pull(t, s2, tok)
	}
	if forward(t, s2, tok, Packet{}).Code != 429 {
		t.Fatal("forward lifetime cap")
	}
	// Actual retained representations account for raw bytes plus JSON/base64.
	s3, store3, _ := setup(t)
	tok = connect(t, s3)
	pull(t, s3, tok)
	for h := uint64(93); h <= 100; h++ {
		store3.headers[h] = bytes.Repeat([]byte{byte(h)}, maxHeader)
		if forward(t, s3, tok, s3.packet(h, store3.headers[h])).Code != 200 {
			t.Fatal("large cache")
		}
	}
	s3.mu.Lock()
	count, cacheBytes = len(s3.cache), s3.cacheBytes
	s3.mu.Unlock()
	if cacheBytes > maxCacheBytes || count >= maxCacheEntries {
		t.Fatal("raw+wire cache byte cap")
	}
	_ = store
}

func TestOffCancelsActiveSourceNoLatePublication(t *testing.T) {
	s, store, _ := setup(t)
	store.entered = make(chan struct{}, 1)
	store.release = make(chan struct{})
	store.honorCancel = true
	token := connect(t, s)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(s, "POST", "/v1/pull", token, map[string]bool{"userApproved": true}) }()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("source not entered")
	}
	if request(s, "GET", "/v1/status", token, nil).Code != 409 {
		t.Fatal("overlapping request admitted")
	}
	if request(s, "DELETE", "/v1/off", token, nil).Code != 204 {
		t.Fatal("OFF blocked behind source")
	}
	select {
	case w := <-done:
		if w.Code < 400 || strings.Contains(w.Body.String(), `"packet"`) {
			t.Fatal("late publication")
		}
	case <-time.After(time.Second):
		t.Fatal("source not canceled")
	}
	if atomic.LoadInt32(&store.closes) != 1 {
		t.Fatal("view must close exactly once")
	}
	s.mu.Lock()
	n, active := len(s.cache), s.inFlight
	s.mu.Unlock()
	if n != 0 || active != 0 {
		t.Fatal("OFF retained resources")
	}
}

func TestCanceledUncooperativeSourceRetainsGlobalWorkSlots(t *testing.T) {
	s, store, _ := setup(t)
	store.entered = make(chan struct{}, maxSessions)
	store.release = make(chan struct{})
	done := make(chan struct{}, maxSessions)
	for i := 0; i < maxSessions; i++ {
		token := connect(t, s)
		go func(tok string) {
			request(s, "POST", "/v1/pull", tok, map[string]bool{"userApproved": true})
			done <- struct{}{}
		}(token)
		select {
		case <-store.entered:
		case <-time.After(time.Second):
			t.Fatal("entry")
		}
		if request(s, "DELETE", "/v1/off", token, nil).Code != 204 {
			t.Fatal("off")
		}
	}
	token := connect(t, s)
	if w := request(s, "POST", "/v1/pull", token, map[string]bool{"userApproved": true}); w.Code != 409 {
		t.Fatal("canceled source work slot prematurely released")
	}
	if atomic.LoadInt32(&store.calls) != maxSessions {
		t.Fatal("unbounded source calls")
	}
	close(store.release)
	for i := 0; i < maxSessions; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("source return")
		}
	}
	if atomic.LoadInt32(&store.closes) != maxSessions {
		t.Fatal("source close accounting")
	}
}

type failedWriter struct{ header http.Header }

func (w *failedWriter) Header() http.Header       { return w.header }
func (w *failedWriter) WriteHeader(int)           {}
func (w *failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestFailedResponseRevokesLeaseAndRetainedCache(t *testing.T) {
	s, _, _ := setup(t)
	token := connect(t, s)
	p := pull(t, s, token)
	b, _ := json.Marshal(map[string]interface{}{"userApproved": true, "packet": p.Packet})
	r := httptest.NewRequest("POST", "http://127.0.0.1:18083/v1/forward", bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("Origin", "http://127.0.0.1:18081")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(&failedWriter{make(http.Header)}, r)
	if leaseFor(s, token) != nil {
		t.Fatal("write failure active lease")
	}
	s.mu.Lock()
	n := len(s.cache)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("write failure retained cache")
	}
}

func TestCanceledOrLostOnResponseDoesNotLeakAnUnboundedCapability(t *testing.T) {
	s, store, clock := setup(t)
	b := []byte(`{"userApproved":true}`)
	r := httptest.NewRequest("POST", "http://127.0.0.1:18083/v1/on", bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("Origin", "http://127.0.0.1:18081")
	r.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 410 || s.admissions != 0 || len(s.leases) != 0 {
		t.Fatal("canceled on allocated a capability")
	}
	r = httptest.NewRequest("POST", "http://127.0.0.1:18083/v1/on", bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("Origin", "http://127.0.0.1:18081")
	r.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(&failedWriter{make(http.Header)}, r)
	if s.admissions != 1 || len(s.leases) != 0 {
		t.Fatal("failed on write retained capability or refunded admission")
	}
	// A successful response whose token is lost by the caller is indistinguishable
	// from a delivered one. Its passive lease expires after30s; no source opens.
	request(s, "POST", "/v1/on", "", map[string]bool{"userApproved": true})
	if len(s.leases) != 1 {
		t.Fatal("lost token fixture")
	}
	clock.Add(idleLifetime)
	connect(t, s)
	if len(s.leases) != 1 || s.admissions != 3 || atomic.LoadInt32(&store.calls) != 0 {
		t.Fatal("lost response lease failed finite cleanup")
	}
}

func TestAuthenticatedDeniedResponsesConsumeRemainingBytes(t *testing.T) {
	s, _, _ := setup(t)
	token := connect(t, s)
	for i := 0; i < maxRequests; i++ {
		if request(s, "GET", "/v1/status", token, nil).Code != 200 {
			t.Fatal("rate fixture")
		}
	}
	l := leaseFor(s, token)
	s.mu.Lock()
	l.bytes = maxSessionBytes - 1
	s.mu.Unlock()
	if request(s, "GET", "/v1/status", token, nil).Code != 413 || leaseFor(s, token) != nil {
		t.Fatal("denied response escaped session byte cap")
	}
}

func TestCacheExpiryDuringFreshCanonicalCheckNeverIssuesExpiredReceipt(t *testing.T) {
	s, store, clock := setup(t)
	a := connect(t, s)
	ap := pull(t, s, a)
	forward(t, s, a, *ap.Packet)
	clock.Add(20 * time.Second)
	pull(t, s, a)
	clock.Add(20 * time.Second)
	pull(t, s, a)
	b := connect(t, s)
	pull(t, s, b)
	var once sync.Once
	store.onHeader = func() { once.Do(func() { clock.Add(21 * time.Second) }) }
	// Canonical checking is successful, but it crossed cacheTTL60s while both
	// leases are still alive. An already-expired receipt must not be emitted.
	p := pull(t, s, b)
	if p.Source != "common" || p.Packet != nil || p.ReceiptToken != nil {
		t.Fatal("expired cache pointer escaped pruning")
	}
	if w := request(s, "GET", "/v1/status", a, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"retained":false`) {
		t.Fatal("producer expiry status")
	}
}

func TestSourcePinsAndUnsafeHeadFailClosedBeforePacketPublication(t *testing.T) {
	for _, which := range []string{"chainId", "genesis", "unsafeHead"} {
		t.Run(which, func(t *testing.T) {
			s, store, _ := setup(t)
			switch which {
			case "chainId":
				store.network.ChainID++
			case "genesis":
				store.network.GenesisHash = "0x" + strings.Repeat("2", 64)
			case "unsafeHead":
				store.head = maxSafeInteger + 1
			}
			token := connect(t, s)
			w := request(s, "POST", "/v1/pull", token, map[string]bool{"userApproved": true})
			if w.Code != 502 || strings.Contains(w.Body.String(), `"packet"`) || atomic.LoadInt32(&store.closes) != 1 {
				t.Fatal("untrusted source publication or owned view leak")
			}
			w = request(s, "GET", "/v1/status", token, nil)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"sourceObserved":false`) {
				t.Fatal("failed source reported observed")
			}
		})
	}
}
