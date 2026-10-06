// Package lightnode provides a private, bounded public-header relay overlay.
// It never writes the chain database, signs, submits transactions, or asserts finality.
package lightnode

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Kind            = "common-lightnode-header-overlay-v1"
	maxSessions     = 8
	maxAdmissions   = 32
	maxJSON         = 16 << 10
	maxHeader       = 8 << 10
	maxSessionBytes = 256 << 10
	maxCacheEntries = 8
	maxCacheBytes   = 128 << 10
	maxRequests     = 16
	maxForwards     = 24
	maxSafeInteger  = uint64(9007199254740991)
	leaseLifetime   = 10 * time.Minute
	idleLifetime    = 30 * time.Second
	cacheLifetime   = 60 * time.Second
	sourceDeadline  = 2 * time.Second
)

const selectedHTTPSPageOrigin = "https://ai-test.make-cph-great-again.community"

// Network is the owner's independently selected public chain identity.
type Network struct {
	ChainID     uint64 `json:"chainId"`
	GenesisHash string `json:"genesisHash"`
}

// View must be a fresh, bounded, immutable, read-only view owned by this request.
// Every potentially blocking method, including Factory, must honor its context.
// Close revokes the view, never the enclosing Common database or node.
type View interface {
	Network() Network
	LatestHeight(context.Context) (uint64, error)
	HeaderRLP(context.Context, uint64, int) ([]byte, error)
	Close() error
}

type Factory func(context.Context) (View, error)

// Config's public fields form the owner-only JSON configuration. Hard resource
// limits cannot be raised by configuration. New does no source I/O or listening.
type Config struct {
	Enabled           bool             `json:"enabled"`
	ListenAddr        string           `json:"listenAddr"`
	AllowedPageOrigin string           `json:"allowedPageOrigin"`
	ExpectedNetwork   Network          `json:"expectedNetwork"`
	Factory           Factory          `json:"-"`
	Now               func() time.Time `json:"-"`
}

type Packet struct {
	Version   int     `json:"version"`
	Network   Network `json:"network"`
	Height    uint64  `json:"height"`
	HeaderRLP string  `json:"headerRLP"`
	Digest    string  `json:"digest"`
}

type Window struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}
type forwardState struct {
	Digest                   string `json:"digest"`
	Retained                 bool   `json:"retained"`
	Consumed                 bool   `json:"consumed"`
	ConsumerAcknowledgements int    `json:"consumerAcknowledgements"`
	entry                    uint64
}
type receipt struct {
	entry   uint64
	digest  string
	raw     []byte
	expires time.Time
}
type lease struct {
	key                    [32]byte
	ctx                    context.Context
	cancel                 context.CancelFunc
	created, idle          time.Time
	requests               []time.Time
	bytes, forwardAttempts int
	busy, sourceObserved   bool
	latest                 uint64
	lastCommonDigest       string
	forwards               map[string]*forwardState
	receipts               map[string]receipt
	consumed               map[uint64]bool
}
type cacheEntry struct {
	id      uint64
	owner   [32]byte
	packet  Packet
	raw     []byte
	created time.Time
	size    int
}

type Server struct {
	config               Config
	mu                   sync.Mutex
	closed               bool
	admissions, inFlight int
	nextEntry            uint64
	leases               map[[32]byte]*lease
	cache                map[uint64]*cacheEntry
	cacheBytes           int
}

// New validates enabled configuration without opening the database or creating
// goroutines. A disabled configuration needs no factory or public chain pins.
func New(c Config) (*Server, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if !c.Enabled && c.AllowedPageOrigin == "" {
		c.AllowedPageOrigin = "http://127.0.0.1:18081"
	}
	if c.Enabled {
		if !literalAddress(c.ListenAddr) {
			return nil, errors.New("listenAddr must be a canonical literal loopback address with explicit port")
		}
		if !literalOrigin(c.AllowedPageOrigin) {
			return nil, errors.New("allowedPageOrigin must be a canonical HTTP loopback origin or the exact selected ai-test HTTPS origin")
		}
		if !validNetwork(c.ExpectedNetwork) {
			return nil, errors.New("expectedNetwork requires a safe positive chainId and nonzero canonical genesis hash")
		}
		if c.Factory == nil {
			return nil, errors.New("enabled lightnode requires an owned source factory")
		}
	}
	return &Server{config: c, leases: make(map[[32]byte]*lease), cache: make(map[uint64]*cacheEntry)}, nil
}

func literalAddress(s string) bool {
	h, p, err := net.SplitHostPort(s)
	if err != nil || (h != "127.0.0.1" && h != "::1") {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == p && net.JoinHostPort(h, p) == s
}
func literalOrigin(s string) bool {
	// This one owner-selected public page is an exact additional origin, not a
	// general HTTPS/domain allowlist. The listener and request Host stay loopback.
	if s == selectedHTTPSPageOrigin {
		return true
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "http" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && literalAddress(u.Host) && "http://"+u.Host == s
}
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validNetwork(n Network) bool {
	return n.ChainID > 0 && n.ChainID <= maxSafeInteger && strings.HasPrefix(n.GenesisHash, "0x") && lowerHex(strings.TrimPrefix(n.GenesisHash, "0x"), 64) && n.GenesisHash != "0x"+strings.Repeat("0", 64)
}

// HeaderDigest binds exact canonical RLP, including all stored SignInfo fields.
// A chain block hash alone does not provide this full-byte binding.
func HeaderDigest(n Network, height uint64, raw []byte) string {
	h := sha256.New()
	h.Write([]byte("cypher-common-lightnode-header-overlay-v1\x00"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n.ChainID)
	h.Write(b[:])
	g, _ := hex.DecodeString(strings.TrimPrefix(n.GenesisHash, "0x"))
	h.Write(g)
	binary.BigEndian.PutUint64(b[:], height)
	h.Write(b[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// Close revokes all capabilities immediately. Active source methods receive
// cancellation and retain their work slots until they actually return. Close
// does not claim that an uncooperative external source has physically stopped.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		for _, l := range s.leases {
			s.revokeLocked(l)
		}
	}
	return nil
}

func (s *Server) revokeLocked(l *lease) {
	if s.leases[l.key] != l {
		return
	}
	delete(s.leases, l.key)
	l.cancel()
	for id, e := range s.cache {
		if e.owner == l.key {
			s.removeCacheLocked(id)
		}
	}
	l.receipts = make(map[string]receipt)
}
func (s *Server) removeCacheLocked(id uint64) {
	if e := s.cache[id]; e != nil {
		delete(s.cache, id)
		s.cacheBytes -= e.size
		if l := s.leases[e.owner]; l != nil {
			if f := l.forwards[e.packet.Digest]; f != nil && f.entry == id {
				f.Retained = false
			}
		}
	}
}
func (s *Server) pruneLocked(now time.Time) {
	for _, l := range s.leases {
		if !now.Before(l.created.Add(leaseLifetime)) || !now.Before(l.idle) {
			s.revokeLocked(l)
		}
	}
	for id, e := range s.cache {
		if !now.Before(e.created.Add(cacheLifetime)) {
			s.removeCacheLocked(id)
		}
	}
	for _, l := range s.leases {
		for nonce, r := range l.receipts {
			if !now.Before(r.expires) || s.cache[r.entry] == nil {
				delete(l.receipts, nonce)
			}
		}
	}
}

func fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	b, _ := json.Marshal(struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message}})
	w.Write(b)
}

var methods = map[string]string{
	"/v1/on": http.MethodPost, "/v1/pull": http.MethodPost,
	"/v1/forward": http.MethodPost, "/v1/ack": http.MethodPost,
	"/v1/status": http.MethodGet, "/v1/off": http.MethodDelete,
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !s.config.Enabled {
		fail(w, 503, "disabled", "Owner has not enabled the local header overlay")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || (host != "127.0.0.1" && host != "::1") || r.Host != s.config.ListenAddr || r.TLS != nil {
		fail(w, 403, "loopback_required", "Exact configured loopback transport and Host required")
		return
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != s.config.AllowedPageOrigin {
		fail(w, 403, "origin_denied", "Exact approved page Origin required")
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", s.config.AllowedPageOrigin)
	w.Header().Set("Vary", "Origin")
	method, found := methods[r.URL.Path]
	if !found || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" {
		fail(w, 404, "route_not_found", "Unknown route or query")
		return
	}
	if r.Method == http.MethodOptions {
		if len(r.Header.Values("Access-Control-Request-Method")) != 1 || r.Header.Get("Access-Control-Request-Method") != method {
			fail(w, 403, "preflight_denied", "Route method denied")
			return
		}
		if len(r.Header.Values("Access-Control-Request-Headers")) > 1 {
			fail(w, 403, "preflight_denied", "Repeated request header list")
			return
		}
		v := r.Header.Get("Access-Control-Request-Headers")
		if len(v) > 1024 {
			fail(w, 403, "preflight_denied", "Header list too large")
			return
		}
		if v != "" {
			for _, h := range strings.Split(v, ",") {
				switch strings.ToLower(strings.TrimSpace(h)) {
				case "authorization", "content-type":
				default:
					fail(w, 403, "preflight_denied", "Request header denied")
					return
				}
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", method)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "60")
		w.WriteHeader(204)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(w, 405, "method_denied", "Route method denied")
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			fail(w, 400, "body_denied", "This route has no request body")
			return
		}
	}
	if r.URL.Path == "/v1/on" {
		s.on(w, r)
		return
	}
	l := s.authenticate(r)
	if l == nil {
		fail(w, 401, "session_required", "Active in-memory session required")
		return
	}
	if r.URL.Path == "/v1/off" {
		s.mu.Lock()
		s.revokeLocked(l)
		s.mu.Unlock()
		w.WriteHeader(204)
		return
	}
	op, status, code := s.admit(r, l, r.URL.Path == "/v1/pull" || r.URL.Path == "/v1/forward")
	if op == nil {
		s.denial(w, l, status, code, "Request admission denied")
		return
	}
	defer op.end()
	if r.URL.Path == "/v1/status" {
		s.status(w, op)
		return
	}
	body, err := readBody(r)
	if len(body) > 0 && !s.charge(op, len(body)) {
		fail(w, 413, "session_budget", "Session byte budget exhausted and revoked")
		return
	}
	if err != nil {
		s.error(w, op, 400, "invalid_body", "Bounded JSON body required")
		return
	}
	switch r.URL.Path {
	case "/v1/pull":
		var p struct {
			UserApproved bool `json:"userApproved"`
		}
		if strictJSON(body, &p) != nil || !p.UserApproved {
			s.error(w, op, 400, "approval_required", "Exact explicitly approved pull required")
			return
		}
		s.pull(w, op)
	case "/v1/forward":
		var p struct {
			UserApproved bool   `json:"userApproved"`
			Packet       Packet `json:"packet"`
		}
		if strictJSON(body, &p) != nil || !p.UserApproved {
			s.error(w, op, 400, "approval_required", "Exact explicitly approved forward required")
			return
		}
		s.forward(w, op, p.Packet)
	case "/v1/ack":
		var p struct {
			UserApproved bool   `json:"userApproved"`
			ReceiptToken string `json:"receiptToken"`
			Digest       string `json:"digest"`
			HeaderRLP    string `json:"headerRLP"`
		}
		if strictJSON(body, &p) != nil || !p.UserApproved {
			s.error(w, op, 400, "approval_required", "Exact explicitly approved acknowledgement required")
			return
		}
		s.ack(w, op, p.ReceiptToken, p.Digest, p.HeaderRLP)
	}
}

func readBody(r *http.Request) ([]byte, error) {
	if len(r.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("content type")
	}
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" || len(params) > 1 || (len(params) == 1 && strings.ToLower(params["charset"]) != "utf-8") || r.ContentLength > maxJSON {
		return nil, errors.New("content type or size")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxJSON+1))
	if err != nil || len(b) > maxJSON {
		return b, errors.New("body too large")
	}
	return b, nil
}

// Reject duplicate keys (including nested ones), excessive nesting, unknown
// fields, null roots, trailing JSON, and noncanonical number coercions.
func strictJSON(b []byte, dst interface{}) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 8 {
			return errors.New("JSON nesting")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON key")
				}
				seen[key] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return errors.New("JSON object required")
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if err := exactJSONFields(b, reflect.TypeOf(dst)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	return nil
}

// encoding/json otherwise accepts case-folded aliases for struct fields. Only
// the exact published JSON tags belong to this protocol, at every nesting level.
func exactJSONFields(b []byte, t reflect.Type) error {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil {
		return err
	}
	fields := make(map[string]reflect.Type)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	for key, value := range object {
		field, ok := fields[key]
		if !ok {
			return errors.New("nonexact JSON field")
		}
		if err := exactJSONFields(value, field); err != nil {
			return err
		}
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (s *Server) on(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	var p struct {
		UserApproved bool `json:"userApproved"`
	}
	if err != nil || strictJSON(body, &p) != nil || !p.UserApproved {
		fail(w, 400, "approval_required", "Explicitly approved connection required")
		return
	}
	if r.Context().Err() != nil {
		fail(w, 410, "request_canceled", "Connection request canceled")
		return
	}
	token, err := randomHex(32)
	if err != nil {
		fail(w, 503, "entropy_unavailable", "Session unavailable")
		return
	}
	key := sha256.Sum256([]byte(token))
	now := s.config.Now()
	s.mu.Lock()
	s.pruneLocked(now)
	if s.closed || len(s.leases) >= maxSessions || s.admissions >= maxAdmissions {
		s.mu.Unlock()
		fail(w, 503, "session_capacity", "Lifetime or active session capacity reached")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &lease{key: key, ctx: ctx, cancel: cancel, created: now, idle: now.Add(idleLifetime), bytes: len(body), forwards: make(map[string]*forwardState), receipts: make(map[string]receipt), consumed: make(map[uint64]bool)}
	s.leases[key] = l
	s.admissions++
	s.mu.Unlock()
	value := struct {
		Kind            string  `json:"kind"`
		SessionToken    string  `json:"sessionToken"`
		ExpiresInMs     int64   `json:"expiresInMs"`
		IdleExpiresInMs int64   `json:"idleExpiresInMs"`
		Network         Network `json:"network"`
	}{Kind, token, leaseLifetime.Milliseconds(), idleLifetime.Milliseconds(), s.config.ExpectedNetwork}
	b, _ := json.Marshal(value)
	s.mu.Lock()
	l.bytes += len(b)
	if r.Context().Err() != nil {
		s.revokeLocked(l)
		s.mu.Unlock()
		fail(w, 410, "request_canceled", "Connection request canceled")
		return
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		s.mu.Lock()
		s.revokeLocked(l)
		s.mu.Unlock()
	}
}

func (s *Server) authenticate(r *http.Request) *lease {
	v := r.Header.Values("Authorization")
	if len(v) != 1 || !strings.HasPrefix(v[0], "Bearer ") || !lowerHex(strings.TrimPrefix(v[0], "Bearer "), 64) {
		return nil
	}
	key := sha256.Sum256([]byte(strings.TrimPrefix(v[0], "Bearer ")))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.config.Now())
	return s.leases[key]
}

type operation struct {
	server    *Server
	lease     *lease
	ctx       context.Context
	cancel    context.CancelFunc
	stopLease func() bool
	source    bool
}

func (s *Server) admit(r *http.Request, l *lease, source bool) (*operation, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.config.Now()
	s.pruneLocked(now)
	if s.closed || s.leases[l.key] != l {
		return nil, 401, "session_required"
	}
	if l.busy || source && s.inFlight >= maxSessions {
		return nil, 409, "request_in_progress"
	}
	cutoff := now.Add(-time.Minute)
	i := 0
	for i < len(l.requests) && !l.requests[i].After(cutoff) {
		i++
	}
	l.requests = l.requests[i:]
	if len(l.requests) >= maxRequests {
		return nil, 429, "rate_limit"
	}
	l.requests = append(l.requests, now)
	l.busy = true
	ctx, cancel := context.WithTimeout(r.Context(), sourceDeadline)
	op := &operation{server: s, lease: l, ctx: ctx, cancel: cancel, source: source}
	op.stopLease = context.AfterFunc(l.ctx, cancel)
	if source {
		s.inFlight++
	}
	return op, 0, ""
}
func (op *operation) end() {
	op.stopLease()
	op.cancel()
	s := op.server
	s.mu.Lock()
	op.lease.busy = false
	if op.source {
		s.inFlight--
	}
	s.mu.Unlock()
}
func (s *Server) currentLocked(op *operation) bool {
	s.pruneLocked(s.config.Now())
	return !s.closed && op.ctx.Err() == nil && s.leases[op.lease.key] == op.lease
}
func (s *Server) charge(op *operation, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.currentLocked(op) {
		return false
	}
	if n < 0 || n > maxSessionBytes-op.lease.bytes {
		s.revokeLocked(op.lease)
		return false
	}
	op.lease.bytes += n
	return true
}
func (s *Server) response(w http.ResponseWriter, op *operation, value interface{}, refresh bool) bool {
	b, err := json.Marshal(value)
	if err != nil || len(b) > maxJSON {
		s.error(w, op, 500, "response_bound", "Response exceeds hard bound")
		return false
	}
	if !s.charge(op, len(b)) {
		fail(w, 410, "session_revoked", "Session revoked, expired, canceled, or exhausted")
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	n, err := w.Write(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || n != len(b) {
		s.revokeLocked(op.lease)
		return false
	}
	if s.currentLocked(op) && refresh {
		op.lease.idle = s.config.Now().Add(idleLifetime)
	}
	return true
}
func (s *Server) error(w http.ResponseWriter, op *operation, status int, code, message string) {
	value := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message}}
	b, _ := json.Marshal(value)
	if !s.charge(op, len(b)) {
		fail(w, 410, "session_revoked", "Session revoked, expired, canceled, or exhausted")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		s.mu.Lock()
		s.revokeLocked(op.lease)
		s.mu.Unlock()
	}
}

// Busy/rate denials still consume their emitted bytes. They never refresh idle,
// add source work, or require an operation slot, so OFF remains available.
func (s *Server) denial(w http.ResponseWriter, l *lease, status int, code, message string) {
	value := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message}}
	b, _ := json.Marshal(value)
	s.mu.Lock()
	s.pruneLocked(s.config.Now())
	if s.leases[l.key] != l {
		s.mu.Unlock()
		fail(w, 401, "session_required", "Active session required")
		return
	}
	if len(b) > maxSessionBytes-l.bytes {
		s.revokeLocked(l)
		s.mu.Unlock()
		fail(w, 413, "session_budget", "Session byte budget exhausted and revoked")
		return
	}
	l.bytes += len(b)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		s.mu.Lock()
		s.revokeLocked(l)
		s.mu.Unlock()
	}
}

func (s *Server) source(op *operation) (View, Window, error) {
	if op.ctx.Err() != nil {
		return nil, Window{}, op.ctx.Err()
	}
	v, err := s.config.Factory(op.ctx)
	if err != nil || v == nil {
		if v != nil {
			v.Close()
		}
		if err == nil {
			err = errors.New("nil owned view")
		}
		return nil, Window{}, err
	}
	if op.ctx.Err() != nil || v.Network() != s.config.ExpectedNetwork {
		v.Close()
		return nil, Window{}, errors.New("source identity or cancellation")
	}
	head, err := v.LatestHeight(op.ctx)
	if err != nil || head > maxSafeInteger || op.ctx.Err() != nil {
		v.Close()
		if err == nil {
			err = errors.New("source head or cancellation")
		}
		return nil, Window{}, err
	}
	win := Window{Last: head}
	if head > 0 {
		win.First = 1
		if head > 31 {
			win.First = head - 31
		}
	}
	return v, win, nil
}
func readRaw(ctx context.Context, v View, height uint64) ([]byte, error) {
	b, err := v.HeaderRLP(ctx, height, maxHeader)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || len(b) == 0 || len(b) > maxHeader {
		return nil, errors.New("source RLP size or cancellation")
	}
	return append([]byte(nil), b...), nil
}
func (s *Server) packet(height uint64, raw []byte) Packet {
	return Packet{1, s.config.ExpectedNetwork, height, base64.StdEncoding.EncodeToString(raw), HeaderDigest(s.config.ExpectedNetwork, height, raw)}
}
func validPacket(p Packet, n Network) ([]byte, error) {
	if p.Version != 1 || p.Network != n || p.Height == 0 || p.Height > maxSafeInteger || !lowerHex(p.Digest, 64) || len(p.HeaderRLP) > base64.StdEncoding.EncodedLen(maxHeader) {
		return nil, errors.New("packet schema")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(p.HeaderRLP)
	if err != nil || len(raw) == 0 || len(raw) > maxHeader || base64.StdEncoding.EncodeToString(raw) != p.HeaderRLP || HeaderDigest(n, p.Height, raw) != p.Digest {
		return nil, errors.New("packet bytes or digest")
	}
	return raw, nil
}

func (s *Server) pull(w http.ResponseWriter, op *operation) {
	v, win, err := s.source(op)
	if err != nil {
		s.error(w, op, 502, "source_unavailable", "Bounded owned source unavailable")
		return
	}
	defer v.Close()
	var packet *Packet
	source := "common"
	nonce := ""
	s.mu.Lock()
	if !s.currentLocked(op) {
		s.mu.Unlock()
		s.error(w, op, 410, "session_revoked", "Session revoked")
		return
	}
	first := !op.lease.sourceObserved
	var candidate *cacheEntry
	if !first {
		for _, e := range s.cache {
			if e.owner == op.lease.key || op.lease.consumed[e.id] {
				continue
			}
			pending := false
			for _, r := range op.lease.receipts {
				if r.entry == e.id {
					pending = true
					break
				}
			}
			if pending {
				continue
			}
			if candidate == nil || e.id < candidate.id {
				cp := *e
				cp.raw = append([]byte(nil), e.raw...)
				candidate = &cp
			}
		}
	}
	s.mu.Unlock()
	if candidate != nil {
		fresh := candidate.packet.Height >= win.First && candidate.packet.Height <= win.Last && win.Last > 0
		if fresh {
			raw, e := readRaw(op.ctx, v, candidate.packet.Height)
			if e != nil {
				s.error(w, op, 502, "source_unavailable", "Retained packet canonical check unavailable")
				return
			}
			fresh = bytes.Equal(raw, candidate.raw)
		}
		s.mu.Lock()
		current := s.currentLocked(op)
		// Pruning can remove an expired entry or revoke its owner. Membership
		// must be observed after that pruning, not through a stale pointer.
		entry := s.cache[candidate.id]
		if !fresh {
			s.removeCacheLocked(candidate.id)
		}
		if fresh && current && entry != nil {
			nonce, err = randomHex(16)
			if err == nil {
				p := candidate.packet
				packet = &p
				source = "forwarded"
				expiry := entry.created.Add(cacheLifetime)
				op.lease.receipts[nonce] = receipt{candidate.id, p.Digest, append([]byte(nil), candidate.raw...), expiry}
			}
		}
		s.mu.Unlock()
		if err != nil {
			s.error(w, op, 503, "entropy_unavailable", "Receipt unavailable")
			return
		}
	}
	if packet == nil && win.Last > 0 {
		raw, e := readRaw(op.ctx, v, win.Last)
		if e != nil {
			s.error(w, op, 502, "source_unavailable", "Latest canonical RLP unavailable within cap")
			return
		}
		p := s.packet(win.Last, raw)
		s.mu.Lock()
		if s.currentLocked(op) && op.lease.lastCommonDigest != p.Digest {
			packet = &p
			op.lease.lastCommonDigest = p.Digest
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	if !s.currentLocked(op) {
		s.mu.Unlock()
		s.error(w, op, 410, "session_revoked", "Session revoked")
		return
	}
	if packet != nil && source == "common" {
		op.lease.sourceObserved = true
	}
	op.lease.latest = win.Last
	s.mu.Unlock()
	var receiptToken *string
	if nonce != "" {
		receiptToken = &nonce
	}
	s.response(w, op, struct {
		Packet       *Packet `json:"packet"`
		Source       string  `json:"source"`
		Window       Window  `json:"window"`
		ReceiptToken *string `json:"receiptToken"`
	}{packet, source, win, receiptToken}, true)
}

func (s *Server) forward(w http.ResponseWriter, op *operation, p Packet) {
	s.mu.Lock()
	if !s.currentLocked(op) {
		s.mu.Unlock()
		s.error(w, op, 410, "session_revoked", "Session revoked")
		return
	}
	if op.lease.forwardAttempts >= maxForwards {
		s.mu.Unlock()
		s.error(w, op, 429, "forward_budget", "Lifetime forward attempts exhausted")
		return
	}
	op.lease.forwardAttempts++
	observed := op.lease.sourceObserved
	s.mu.Unlock()
	raw, err := validPacket(p, s.config.ExpectedNetwork)
	if err != nil || !observed {
		s.error(w, op, 400, "invalid_packet", "Valid packet after a Common source pull required")
		return
	}
	v, win, err := s.source(op)
	if err != nil {
		s.error(w, op, 502, "source_unavailable", "Bounded owned source unavailable")
		return
	}
	defer v.Close()
	if p.Height < win.First || p.Height > win.Last || win.Last == 0 {
		s.error(w, op, 409, "outside_window", "Packet is outside the current recent window")
		return
	}
	canonical, err := readRaw(op.ctx, v, p.Height)
	if err != nil {
		s.error(w, op, 502, "source_unavailable", "Canonical full RLP unavailable")
		return
	}
	if !bytes.Equal(canonical, raw) {
		s.error(w, op, 409, "canonical_mismatch", "Exact canonical full RLP differs")
		return
	}
	encoded, _ := json.Marshal(p)
	size := len(raw) + len(encoded)
	s.mu.Lock()
	if !s.currentLocked(op) {
		s.mu.Unlock()
		s.error(w, op, 410, "session_revoked", "Session revoked")
		return
	}
	var entry *cacheEntry
	if f := op.lease.forwards[p.Digest]; f != nil && f.Retained {
		entry = s.cache[f.entry]
	}
	if entry == nil {
		for len(s.cache) >= maxCacheEntries || s.cacheBytes+size > maxCacheBytes {
			var oldest *cacheEntry
			for _, e := range s.cache {
				if oldest == nil || e.id < oldest.id {
					oldest = e
				}
			}
			if oldest == nil {
				break
			}
			s.removeCacheLocked(oldest.id)
		}
		s.nextEntry++
		entry = &cacheEntry{s.nextEntry, op.lease.key, p, append([]byte(nil), raw...), s.config.Now(), size}
		s.cache[entry.id] = entry
		s.cacheBytes += size
		f := op.lease.forwards[p.Digest]
		if f == nil {
			f = &forwardState{Digest: p.Digest}
			op.lease.forwards[p.Digest] = f
		}
		f.entry = entry.id
		f.Retained = true
	}
	op.lease.latest = win.Last
	f := *op.lease.forwards[p.Digest]
	s.mu.Unlock()
	s.response(w, op, struct {
		Retained                 bool   `json:"retained"`
		Digest                   string `json:"digest"`
		Consumed                 bool   `json:"consumed"`
		ConsumerAcknowledgements int    `json:"consumerAcknowledgements"`
	}{true, p.Digest, f.Consumed, f.ConsumerAcknowledgements}, true)
}

func (s *Server) ack(w http.ResponseWriter, op *operation, nonce, digest, encoded string) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if !lowerHex(nonce, 32) || !lowerHex(digest, 64) || err != nil || len(raw) == 0 || len(raw) > maxHeader || base64.StdEncoding.EncodeToString(raw) != encoded {
		s.error(w, op, 400, "invalid_receipt", "Canonical receipt fields required")
		return
	}
	s.mu.Lock()
	if !s.currentLocked(op) {
		s.mu.Unlock()
		s.error(w, op, 410, "session_revoked", "Session revoked")
		return
	}
	r, exists := op.lease.receipts[nonce]
	delete(op.lease.receipts, nonce)
	e := s.cache[r.entry]
	if !exists || e == nil || e.owner == op.lease.key || !s.config.Now().Before(r.expires) || r.digest != digest || !bytes.Equal(r.raw, raw) || e.packet.Digest != digest || !bytes.Equal(e.raw, raw) {
		s.mu.Unlock()
		s.error(w, op, 409, "receipt_mismatch", "Receipt is single use, lease bound, exact byte bound, and finite")
		return
	}
	if op.lease.consumed[e.id] {
		s.mu.Unlock()
		s.error(w, op, 409, "receipt_replayed", "Packet already acknowledged by this lease")
		return
	}
	op.lease.consumed[e.id] = true
	if owner := s.leases[e.owner]; owner != nil {
		if f := owner.forwards[digest]; f != nil && f.entry == e.id {
			f.Consumed = true
			f.ConsumerAcknowledgements++
		}
	}
	s.mu.Unlock()
	s.response(w, op, struct {
		Acknowledged bool   `json:"acknowledged"`
		Digest       string `json:"digest"`
	}{true, digest}, true)
}

func remaining(until, now time.Time) int64 {
	n := until.Sub(now).Milliseconds()
	if n < 0 {
		return 0
	}
	return n
}
func (s *Server) status(w http.ResponseWriter, op *operation) {
	s.mu.Lock()
	if !s.currentLocked(op) {
		s.mu.Unlock()
		s.error(w, op, 410, "session_revoked", "Session revoked")
		return
	}
	l := op.lease
	now := s.config.Now()
	forwards := make([]forwardState, 0, len(l.forwards))
	for _, f := range l.forwards {
		forwards = append(forwards, *f)
	}
	sort.Slice(forwards, func(i, j int) bool { return forwards[i].Digest < forwards[j].Digest })
	var latest *uint64
	if l.sourceObserved {
		n := l.latest
		latest = &n
	}
	value := struct {
		Kind              string         `json:"kind"`
		Network           Network        `json:"network"`
		SessionActive     bool           `json:"sessionActive"`
		SourceKind        string         `json:"sourceKind"`
		SourceObserved    bool           `json:"sourceObserved"`
		LatestHeight      *uint64        `json:"latestHeight"`
		ExpiresInMs       int64          `json:"expiresInMs"`
		IdleExpiresInMs   int64          `json:"idleExpiresInMs"`
		RequestsRemaining int            `json:"requestsRemaining"`
		BytesUsed         int            `json:"bytesUsed"`
		ForwardAttempts   int            `json:"forwardAttempts"`
		Forwards          []forwardState `json:"forwards"`
		ActiveRequest     bool           `json:"activeRequest"`
	}{Kind, s.config.ExpectedNetwork, true, "common-lightnode-header-overlay", l.sourceObserved, latest, remaining(l.created.Add(leaseLifetime), now), remaining(l.idle, now), maxRequests - len(l.requests), l.bytes, l.forwardAttempts, forwards, false}
	s.mu.Unlock()
	s.response(w, op, value, false)
}

// String intentionally omits capabilities and configured source implementation.
func (s *Server) String() string { return fmt.Sprintf("%s(enabled=%t)", Kind, s.config.Enabled) }
