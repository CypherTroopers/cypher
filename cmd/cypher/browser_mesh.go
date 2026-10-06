package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/node/browserrelay"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

// The private socket is the only listener. An operator-owned HTTPS proxy may
// expose /relay/v1/mesh/*, never the node's RPC/IPC or unrestricted TCP dialing.
type browserMeshConfiguration struct {
	AllowedOrigins      []string `json:"allowedOrigins"`
	PublicGatewayOrigin string   `json:"publicGatewayOrigin,omitempty"`
	GatewayUplink       bool     `json:"gatewayUplink,omitempty"`
}

func validateBrowserMeshConfiguration(c *browserMeshConfiguration) error {
	if c == nil || len(c.AllowedOrigins) == 0 || len(c.AllowedOrigins) > 8 {
		return errors.New("mesh requires one to eight exact HTTPS origins")
	}
	if c.PublicGatewayOrigin != "" {
		if err := browserrelay.ValidateMeshGatewayOrigin(c.PublicGatewayOrigin); err != nil {
			return err
		}
	}
	if c.GatewayUplink && c.PublicGatewayOrigin == "" {
		return errors.New("mesh gateway uplink requires a configured HTTPS gateway origin")
	}
	seen := make(map[string]bool)
	for _, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || seen[origin] || len(origin) > 256 {
			return errors.New("mesh origin must be a unique exact HTTPS origin without path or credentials")
		}
		seen[origin] = true
	}
	if c.GatewayUplink && !seen[c.PublicGatewayOrigin] {
		return errors.New("mesh gateway uplink origin must be allowed by the native handler")
	}
	return nil
}

type browserRelayRuntime struct {
	exporter *browserrelay.Exporter
	mesh     *browserrelay.Mesh
	http     *browserMeshHTTP
	uplink   *browserSourceUplink
}

func (r *browserRelayRuntime) Start() error {
	if r.exporter != nil {
		if err := r.exporter.Start(); err != nil {
			return err
		}
	}
	if r.mesh != nil {
		if err := r.mesh.Start(); err != nil {
			_ = r.Stop()
			return err
		}
		r.http.start()
		if r.uplink != nil {
			if err := r.uplink.Start(); err != nil {
				_ = r.Stop()
				return err
			}
		}
	}
	return nil
}

func (r *browserRelayRuntime) Stop() error {
	var err error
	if r.uplink != nil {
		r.uplink.Stop()
	}
	if r.http != nil {
		r.http.stop()
	}
	if r.mesh != nil {
		err = r.mesh.Stop()
	}
	if r.exporter != nil {
		err = errors.Join(err, r.exporter.Stop())
	}
	return err
}

func initializeBrowserMesh(g *browserPublicRelayStartup, stack *node.Node, backend *eth.EthAPIBackend, exporter *browserrelay.Exporter) error {
	runtime := &browserRelayRuntime{exporter: exporter}
	mux := http.NewServeMux()
	mux.Handle("/", browserrelay.NewHandler(exporter))
	if g.public.Mesh != nil {
		chain := backend.ChainConfig()
		if chain == nil || !chain.FairHotstuff || !(chain.FixedCommittee || chain.FixedLeader) || chain.ChainID == nil || !chain.ChainID.IsUint64() || chain.ChainID.Uint64() != g.public.Network.ChainID {
			return errors.New("browser mesh requires the configured fixed-committee Common network")
		}
		genesis, err := backend.HeaderByNumber(g.ctx, 0)
		if err != nil || genesis == nil || genesis.Hash().Hex() != g.public.Network.GenesisHash {
			return errors.New("browser mesh genesis differs from its fixed network")
		}
		srv := stack.Server()
		mesh, err := browserrelay.NewMesh(browserrelay.MeshConfig{
			Network: g.public.Network, LocalNode: srv.Self,
			SourceID: g.public.SourceID, PublicGatewayOrigin: g.public.Mesh.PublicGatewayOrigin,
			SignDigest: func(digest []byte) ([]byte, error) { return crypto.Sign(digest, srv.PrivateKey) },
			OnInbound: func(conn net.Conn, remote *enode.Node) error {
				wrapped, err := wrapBrowserMeshConnection(conn)
				if err != nil {
					conn.Close()
					return err
				}
				return srv.SetupBrowserMesh(wrapped)
			},
		})
		if err != nil {
			return err
		}
		runtime.mesh = mesh
		it := &browserMeshCandidates{mesh: mesh, done: make(chan struct{})}
		srv.BrowserMesh = &p2p.BrowserMeshConfig{Dialer: browserMeshDialer{mesh}, Candidates: it,
			HasRoute: func(id enode.ID) bool {
				for _, n := range mesh.Candidates() {
					if n.ID() == id {
						return true
					}
				}
				return false
			},
			MaxPeers: min(p2p.BrowserMeshMaxPeers, srv.MaxPeers), MaxPending: 4, MaxFrameBytes: 4 << 20, BytesPerSecond: 16 << 10}
		runtime.http = newBrowserMeshHTTP(g.ctx, mesh, g.public.Mesh.AllowedOrigins)
		if g.public.Mesh.GatewayUplink {
			runtime.uplink = newBrowserSourceUplink(mesh, runtime.http, g.public.Mesh.PublicGatewayOrigin, func(digest []byte) ([]byte, error) { return crypto.Sign(digest, srv.PrivateKey) })
		}
		mux.Handle("/relay/v1/mesh/", runtime.http)
	}
	g.source, g.handler = runtime, mux
	return nil
}

func wrapBrowserMeshConnection(conn net.Conn) (net.Conn, error) {
	info, ok := browserrelay.MeshConnectionInfo(conn)
	if !ok || info.RemoteID == (enode.ID{}) {
		return nil, errors.New("unidentified browser mesh circuit")
	}
	return p2p.NewBrowserMeshConn(conn, p2p.BrowserMeshInfo{CircuitID: info.CircuitID, RemoteID: info.RemoteID, RelayIDs: info.RelayIDs})
}

type browserMeshDialer struct{ mesh *browserrelay.Mesh }

func (d browserMeshDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	conn, err := d.mesh.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapBrowserMeshConnection(conn)
	if err != nil {
		conn.Close()
	}
	return wrapped, err
}

// Refresh the bounded, expiring route table instead of permanently adding
// browser-advertised nodes to the server's static/trusted peer lists.
type browserMeshCandidates struct {
	mesh    *browserrelay.Mesh
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	current *enode.Node
	next    int
}

func (it *browserMeshCandidates) Next() bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-it.done:
			return false
		case <-timer.C:
			nodes := it.mesh.Candidates()
			if len(nodes) != 0 {
				it.mu.Lock()
				it.current = nodes[it.next%len(nodes)]
				it.next = (it.next + 1) % len(nodes)
				it.mu.Unlock()
				return true
			}
			timer.Reset(time.Second)
		}
	}
}
func (it *browserMeshCandidates) Node() *enode.Node {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.current
}
func (it *browserMeshCandidates) Close() { it.once.Do(func() { close(it.done) }) }

const browserMeshLease = 5 * time.Minute

type browserMeshSession struct {
	id       string
	origin   string
	expires  time.Time
	attached bool
	ctx      context.Context
	cancel   context.CancelFunc
	budget   *rate.Limiter
}

type browserMeshHTTP struct {
	mesh             *browserrelay.Mesh
	origins          map[string]bool
	mu               sync.Mutex
	sessions         map[[32]byte]*browserMeshSession
	admissions       *rate.Limiter
	requests         *rate.Limiter
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	started, stopped bool
}

func newBrowserMeshHTTP(parent context.Context, mesh *browserrelay.Mesh, origins []string) *browserMeshHTTP {
	ctx, cancel := context.WithCancel(parent)
	h := &browserMeshHTTP{mesh: mesh, origins: make(map[string]bool), sessions: make(map[[32]byte]*browserMeshSession),
		admissions: rate.NewLimiter(1, 8), requests: rate.NewLimiter(16, 32), ctx: ctx, cancel: cancel}
	for _, origin := range origins {
		h.origins[origin] = true
	}
	return h
}

func (h *browserMeshHTTP) start() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started || h.stopped {
		return
	}
	h.started = true
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case now := <-t.C:
				h.mu.Lock()
				for key, session := range h.sessions {
					if !now.Before(session.expires) {
						session.cancel()
						delete(h.sessions, key)
					}
				}
				h.mu.Unlock()
			}
		}
	}()
}
func (h *browserMeshHTTP) stop() {
	h.mu.Lock()
	h.stopped = true
	h.cancel()
	for key, session := range h.sessions {
		session.cancel()
		delete(h.sessions, key)
	}
	h.mu.Unlock()
	h.wg.Wait()
}

func meshJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *browserMeshHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	origin := r.Header.Get("Origin")
	if !h.origins[origin] || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.Error(w, "invalid origin or request", http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	if !h.requests.Allow() {
		http.Error(w, "request limit", http.StatusTooManyRequests)
		return
	}
	h.mu.Lock()
	active := h.started && !h.stopped && h.ctx.Err() == nil
	h.mu.Unlock()
	if !active {
		http.Error(w, "mesh stopped", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/relay/v1/mesh/")
	switch {
	case path == "config" && r.Method == http.MethodGet:
		meshJSON(w, 200, map[string]any{"version": 1, "sessionSeconds": 300, "renewAfterSeconds": 120, "maxSessions": browserrelay.MeshMaxSessions, "maxFrameBytes": browserrelay.MeshMaxFrameBytes, "nativeMaxFrameBytes": 4 << 20, "nativePeers": p2p.BrowserMeshMaxPeers, "initialState": "OFF"})
	case path == "endpoint" && r.Method == http.MethodGet:
		if r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "unexpected body", 400)
			return
		}
		if h.mesh == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		endpoint, err := h.mesh.Endpoint()
		if errors.Is(err, browserrelay.ErrMeshEndpointDisabled) {
			http.Error(w, "endpoint publication disabled", 404)
			return
		}
		if err != nil {
			http.Error(w, "endpoint unavailable", 503)
			return
		}
		meshJSON(w, 200, endpoint)
	case path == "status" && r.Method == http.MethodGet:
		if h.mesh == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		meshJSON(w, 200, h.mesh.Status())
	case path == "sessions" && r.Method == http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil || len(body) > 1024 || (len(body) != 0 && string(body) != "{}") {
			http.Error(w, "expected empty object", 400)
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.stopped || len(h.sessions) >= browserrelay.MeshMaxSessions || !h.admissions.Allow() {
			http.Error(w, "session capacity", 429)
			return
		}
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			http.Error(w, "entropy unavailable", 503)
			return
		}
		token := hex.EncodeToString(secret[:])
		clear(secret[:])
		key := sha256.Sum256([]byte(token))
		ctx, cancel := context.WithCancel(h.ctx)
		session := &browserMeshSession{id: hex.EncodeToString(key[:16]), origin: origin, expires: time.Now().Add(browserMeshLease), ctx: ctx, cancel: cancel, budget: rate.NewLimiter(1, 4)}
		h.sessions[key] = session
		meshJSON(w, 201, map[string]any{"token": token, "browserId": session.id, "expiresAt": session.expires.UnixMilli()})
	case path == "renew" && r.Method == http.MethodPost, path == "sessions" && r.Method == http.MethodDelete:
		if r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "unexpected body", 400)
			return
		}
		key, ok := browserMeshToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !ok {
			http.Error(w, "invalid session", 401)
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		s := h.sessions[key]
		if s == nil || s.origin != origin || !time.Now().Before(s.expires) || s.ctx.Err() != nil {
			http.Error(w, "expired session", 401)
			return
		}
		if !s.budget.Allow() {
			http.Error(w, "session request limit", 429)
			return
		}
		if r.Method == http.MethodDelete {
			s.cancel()
			delete(h.sessions, key)
			w.WriteHeader(204)
			return
		}
		s.expires = time.Now().Add(browserMeshLease)
		meshJSON(w, 200, map[string]any{"expiresAt": s.expires.UnixMilli()})
	case path == "connect" && r.Method == http.MethodGet:
		h.connect(w, r, origin)
	default:
		http.Error(w, "unknown mesh route or method", 404)
	}
}

func browserMeshToken(token string) ([32]byte, bool) {
	var zero [32]byte
	if len(token) != 64 || token != strings.ToLower(token) {
		return zero, false
	}
	if _, err := hex.DecodeString(token); err != nil {
		return zero, false
	}
	return sha256.Sum256([]byte(token)), true
}

func (h *browserMeshHTTP) connect(w http.ResponseWriter, r *http.Request, origin string) {
	if h.mesh == nil {
		http.Error(w, "unavailable", 503)
		return
	}
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		http.Error(w, "stopped", 503)
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()
	upgrader := websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 16384, CheckOrigin: func(*http.Request) bool { return true }}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	stopClose := context.AfterFunc(h.ctx, func() { _ = ws.Close() })
	defer stopClose()
	ws.SetReadLimit(1024)
	ws.SetPingHandler(func(string) error { return errors.New("authenticate before control frames") })
	ws.SetPongHandler(func(string) error { return errors.New("authenticate before control frames") })
	_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := ws.ReadMessage()
	if err != nil {
		return
	}
	fields, err := publicRelayObject(raw, "token")
	if err != nil {
		return
	}
	var token string
	if json.Unmarshal(fields["token"], &token) != nil {
		return
	}
	key, ok := browserMeshToken(token)
	if !ok {
		return
	}
	h.mu.Lock()
	s := h.sessions[key]
	if h.stopped || s == nil || s.attached || s.origin != origin || !time.Now().Before(s.expires) || s.ctx.Err() != nil {
		h.mu.Unlock()
		return
	}
	s.attached = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if h.sessions[key] == s {
			delete(h.sessions, key)
		}
		s.cancel()
		h.mu.Unlock()
	}()
	_ = ws.SetReadDeadline(time.Time{})
	_ = ws.SetWriteDeadline(time.Time{})
	_ = h.mesh.Attach(s.ctx, s.id, ws)
}
