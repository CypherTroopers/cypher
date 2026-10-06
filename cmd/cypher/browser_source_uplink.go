package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node/browserrelay"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

const (
	sourceBase           = "/relay/v1/mesh/"
	sourceAuthDomain     = "cypher-browser-mesh-source-v1\x00"
	sourcePacketBytes    = 98304
	sourceQueueBytes     = 512 << 10
	sourceQueueFrames    = 64
	sourceBytesPerSecond = 384 << 10
	sourceStreamHistory  = 4096
)

// The source is an outgoing, fixed-origin transport. The browser mesh remains
// the sole owner of native sessions, circuits, role checks and encrypted bytes.
type browserSourceUplink struct {
	mesh    *browserrelay.Mesh
	handler *browserMeshHTTP
	origin  string
	sign    func([]byte) ([]byte, error)
	dialer  websocket.Dialer
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	started bool
	active  *websocket.Conn
	// Private test seam; production keeps the bounded, jittered retry below.
	retryDelay func(int) time.Duration
}

func newBrowserSourceUplink(mesh *browserrelay.Mesh, handler *browserMeshHTTP, origin string, sign func([]byte) ([]byte, error)) *browserSourceUplink {
	ctx, cancel := context.WithCancel(context.Background())
	return &browserSourceUplink{mesh: mesh, handler: handler, origin: origin, sign: sign, ctx: ctx, cancel: cancel, done: make(chan struct{}), dialer: websocket.Dialer{HandshakeTimeout: 5 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 16384, EnableCompression: false}}
}
func (u *browserSourceUplink) Start() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.started || u.ctx.Err() != nil {
		return errors.New("source uplink cannot start twice or after stop")
	}
	if u.mesh == nil || u.handler == nil || u.sign == nil || browserrelay.ValidateMeshGatewayOrigin(u.origin) != nil {
		return errors.New("invalid source uplink configuration")
	}
	u.started = true
	go u.run()
	return nil
}
func (u *browserSourceUplink) Stop() {
	u.cancel()
	u.mu.Lock()
	ws, started := u.active, u.started
	u.mu.Unlock()
	if ws != nil {
		ws.Close()
	}
	if started {
		<-u.done
	}
}
func (u *browserSourceUplink) run() {
	defer close(u.done)
	attempt := 0
	for u.ctx.Err() == nil {
		started := time.Now()
		err := u.connect()
		if u.ctx.Err() != nil {
			return
		}
		// Error strings may include remote-controlled data or secret tokens. Only
		// a fixed diagnostic is emitted, at the bounded reconnect frequency.
		if err != nil {
			log.Debug("Browser source uplink unavailable; retrying")
		}
		if time.Since(started) > time.Minute {
			attempt = 0
		} else if attempt < 4 {
			attempt++
		}
		limit := 2 * time.Second * time.Duration(1<<attempt)
		if limit > 30*time.Second {
			limit = 30 * time.Second
		}
		delay := 2*time.Second + time.Duration(rand.Int63n(int64(limit-2*time.Second+1)))
		if u.retryDelay != nil {
			delay = u.retryDelay(attempt)
		}
		timer := time.NewTimer(delay)
		select {
		case <-u.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (u *browserSourceUplink) connect() error {
	endpoint, err := u.mesh.UplinkEndpoint()
	if err != nil {
		return err
	}
	urlValue, err := url.Parse(u.origin)
	if err != nil {
		return err
	}
	urlValue.Scheme = "wss"
	urlValue.Path = sourceBase + "source"
	ws, response, err := u.dialer.DialContext(u.ctx, urlValue.String(), http.Header{"Origin": []string{u.origin}})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return err
	}
	u.mu.Lock()
	if u.ctx.Err() != nil {
		u.mu.Unlock()
		ws.Close()
		return u.ctx.Err()
	}
	u.active = ws
	u.mu.Unlock()
	defer func() {
		ws.Close()
		u.mu.Lock()
		if u.active == ws {
			u.active = nil
		}
		u.mu.Unlock()
	}()
	ws.SetReadLimit(8192)
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	ws.SetPingHandler(func(string) error { return errors.New("source auth required") })
	ws.SetPongHandler(func(string) error { return errors.New("source auth required") })
	kind, raw, err := ws.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		return errors.New("source challenge unavailable")
	}
	fields, err := publicRelayObject(raw, "kind", "challenge")
	if err != nil {
		return err
	}
	var challengeKind, encoded string
	if json.Unmarshal(fields["kind"], &challengeKind) != nil || challengeKind != "challenge" || json.Unmarshal(fields["challenge"], &encoded) != nil {
		return errors.New("invalid source challenge")
	}
	challenge, err := sourceBase64(encoded, 2048)
	if err != nil {
		return err
	}
	if err = validateSourceChallenge(challenge, u.origin, time.Now()); err != nil {
		return err
	}
	signature, err := u.sign(crypto.Keccak256([]byte(sourceAuthDomain), challenge))
	if err != nil || len(signature) != 65 || signature[64] > 1 {
		return errors.New("source challenge signing failed")
	}
	auth, _ := json.Marshal(map[string]any{"kind": "auth", "endpoint": endpoint, "signatureHex": hex.EncodeToString(signature)})
	if len(auth) > 8192 {
		return errors.New("source auth size")
	}
	_ = ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err = ws.WriteMessage(websocket.TextMessage, auth); err != nil {
		return err
	}
	kind, raw, err = ws.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		return errors.New("source authentication rejected")
	}
	fields, err = publicRelayObject(raw, "kind", "sourceId", "nodeId")
	if err != nil {
		return err
	}
	var readyKind, sourceID, nodeID string
	if json.Unmarshal(fields["kind"], &readyKind) != nil || readyKind != "ready" || json.Unmarshal(fields["sourceId"], &sourceID) != nil || json.Unmarshal(fields["nodeId"], &nodeID) != nil || !sourceHex(sourceID, 64) || sourceID != nodeID {
		return errors.New("invalid source ready identity")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(endpoint.PayloadBase64)
	if err != nil {
		return err
	}
	var own struct {
		SourceID string `json:"sourceId"`
	}
	if json.Unmarshal(payload, &own) != nil || own.SourceID != sourceID {
		return errors.New("source ready differs from native identity")
	}
	s := newSourceSession(u, ws)
	defer s.close()
	return s.run()
}

func validateSourceChallenge(raw []byte, origin string, now time.Time) error {
	if len(raw) > 2048 {
		return errors.New("source challenge size")
	}
	fields, err := publicRelayObject(raw, "version", "origin", "nonce", "expiresAt")
	if err != nil {
		return err
	}
	var version int
	var gotOrigin, nonce string
	var expires int64
	if json.Unmarshal(fields["version"], &version) != nil || version != 1 || json.Unmarshal(fields["origin"], &gotOrigin) != nil || gotOrigin != origin || json.Unmarshal(fields["nonce"], &nonce) != nil || !sourceHex(nonce, 32) || json.Unmarshal(fields["expiresAt"], &expires) != nil || expires <= now.UnixMilli() || expires > now.Add(6*time.Second).UnixMilli() {
		return errors.New("source challenge schema, origin or expiry")
	}
	return nil
}
func sourceHex(s string, n int) bool {
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
func sourceBase64(s string, max int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(max) {
		return nil, errors.New("source payload exceeds limit")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > max || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("invalid source base64")
	}
	return b, nil
}

type sourcePacket struct {
	Kind   string `json:"kind"`
	ID     string `json:"id,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Token  string `json:"token,omitempty"`
	Body   string `json:"body,omitempty"`
	Data   string `json:"data,omitempty"`
}

func decodeSourcePacket(raw []byte) (sourcePacket, error) {
	var p sourcePacket
	if len(raw) > sourcePacketBytes || json.Unmarshal(raw, &p) != nil {
		return p, errors.New("invalid source packet")
	}
	var names []string
	switch p.Kind {
	case "request":
		names = []string{"kind", "id", "method", "path", "token?", "body?"}
	case "open":
		names = []string{"kind", "id", "token"}
	case "message", "ping", "pong":
		names = []string{"kind", "id", "data"}
	case "close":
		names = []string{"kind", "id"}
	default:
		return p, errors.New("unknown source packet")
	}
	if _, err := publicRelayObject(raw, names...); err != nil {
		return p, err
	}
	if !sourceHex(p.ID, 32) {
		return p, errors.New("invalid source request or stream ID")
	}
	return p, nil
}

type sourceRequest struct{ token string }

type sourceSession struct {
	owner                                                             *browserSourceUplink
	ws                                                                *websocket.Conn
	local                                                             *sourceLocalHTTP
	ctx                                                               context.Context
	cancel                                                            context.CancelFunc
	wg                                                                sync.WaitGroup
	mu                                                                sync.Mutex
	closed                                                            bool
	tokens                                                            map[string]bool
	streams                                                           map[string]*sourceStream
	history                                                           map[string]bool
	requests                                                          map[string]*sourceRequest
	queue                                                             chan []byte
	queuedBytes, queuedFrames, incomingBytes, incomingFrames          int
	inBytes, outBytes, inMessages, outMessages, controlIn, controlOut *rate.Limiter
}

func newSourceSession(u *browserSourceUplink, ws *websocket.Conn) *sourceSession {
	ctx, cancel := context.WithCancel(u.ctx)
	s := &sourceSession{owner: u, ws: ws, ctx: ctx, cancel: cancel, tokens: make(map[string]bool), streams: make(map[string]*sourceStream), history: make(map[string]bool), requests: make(map[string]*sourceRequest), queue: make(chan []byte, sourceQueueFrames), inBytes: rate.NewLimiter(sourceBytesPerSecond, sourceQueueBytes), outBytes: rate.NewLimiter(sourceBytesPerSecond, sourceQueueBytes), inMessages: rate.NewLimiter(128, 256), outMessages: rate.NewLimiter(128, 256), controlIn: rate.NewLimiter(32, 80), controlOut: rate.NewLimiter(32, 80)}
	s.local = newSourceLocalHTTP(http.HandlerFunc(s.serveHTTP))
	return s
}

// The handler may commit a new lease after its HTTP caller has timed out. Capture
// issuance before writing to the pipe, so cancelled responses cannot orphan it.
func (s *sourceSession) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "source stopped", 503)
		return
	}
	s.wg.Add(1)
	requestID := r.Header.Get("X-Cypher-Source-Request")
	request := s.requests[requestID]
	s.mu.Unlock()
	defer s.wg.Done()
	if r.Method != "POST" || r.URL.Path != sourceBase+"sessions" {
		s.owner.handler.ServeHTTP(w, r)
		return
	}
	mintedToken := ""
	captured := &sourceMintResponse{header: make(http.Header)}
	s.owner.handler.ServeHTTP(captured, r)
	if captured.status == 201 {
		var minted struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(captured.body.Bytes(), &minted) != nil || !sourceHex(minted.Token, 64) {
			s.fail()
			http.Error(w, "invalid source issuance", 502)
			return
		}
		s.mu.Lock()
		accept := !s.closed && s.ctx.Err() == nil && r.Context().Err() == nil && len(s.tokens) < browserrelay.MeshMaxSessions && (requestID == "" || (request != nil && s.requests[requestID] == request))
		if accept {
			s.tokens[minted.Token] = true
			mintedToken = minted.Token
			if request != nil {
				request.token = minted.Token
			}
		}
		s.mu.Unlock()
		if !accept {
			s.revoke(minted.Token)
			http.Error(w, "source stopped", 503)
			return
		}
	}
	for k, values := range captured.header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	status := captured.status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	if _, err := w.Write(captured.body.Bytes()); err != nil && mintedToken != "" {
		s.mu.Lock()
		delete(s.tokens, mintedToken)
		s.mu.Unlock()
		s.revoke(mintedToken)
	}
}

type sourceMintResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *sourceMintResponse) Header() http.Header { return w.header }
func (w *sourceMintResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *sourceMintResponse) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.body.Len()+len(raw) > 16384 {
		return 0, errors.New("source issuance body limit")
	}
	return w.body.Write(raw)
}

func (s *sourceSession) fail() {
	s.cancel()
	if s.ws != nil {
		s.ws.Close()
	}
}
func (s *sourceSession) send(value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > sourcePacketBytes {
		return errors.New("source packet size")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return context.Canceled
	}
	if s.queuedFrames >= sourceQueueFrames || s.queuedBytes+len(raw) > sourceQueueBytes {
		return errors.New("source send queue full")
	}
	s.queuedBytes += len(raw)
	s.queuedFrames++
	s.queue <- raw
	return nil
}
func (s *sourceSession) run() error {
	s.ws.SetReadLimit(sourcePacketBytes)
	_ = s.ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	s.ws.SetPingHandler(func(payload string) error {
		if len(payload) > 125 || !s.controlIn.Allow() || !s.controlOut.Allow() {
			return errors.New("source control budget")
		}
		return s.ws.WriteControl(websocket.PongMessage, []byte(payload), time.Now().Add(2*time.Second))
	})
	s.ws.SetPongHandler(func(payload string) error {
		if len(payload) > 125 || !s.controlIn.Allow() {
			return errors.New("source control budget")
		}
		return s.ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	})
	s.ws.SetCloseHandler(func(int, string) error {
		if !s.controlIn.Allow() {
			return errors.New("source control budget")
		}
		return nil
	})
	s.wg.Add(2)
	go s.write()
	go s.maintain()
	for {
		kind, raw, err := s.ws.ReadMessage()
		if err != nil {
			return err
		}
		if kind != websocket.TextMessage || !s.inMessages.Allow() || !s.inBytes.AllowN(time.Now(), len(raw)) {
			return errors.New("source input budget or type")
		}
		p, err := decodeSourcePacket(raw)
		if err != nil {
			return err
		}
		switch p.Kind {
		case "request":
			err = s.request(p)
		case "open":
			err = s.open(p)
		case "close":
			s.closeStream(p.ID, true)
		default:
			err = s.input(p)
		}
		if err != nil {
			return err
		}
	}
}
func (s *sourceSession) write() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case raw := <-s.queue:
			ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
			err := s.outMessages.Wait(ctx)
			if err == nil {
				err = s.outBytes.WaitN(ctx, len(raw))
			}
			cancel()
			if err == nil {
				_ = s.ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
				err = s.ws.WriteMessage(websocket.TextMessage, raw)
			}
			s.mu.Lock()
			s.queuedBytes -= len(raw)
			s.queuedFrames--
			s.mu.Unlock()
			if err != nil {
				s.fail()
				return
			}
		}
	}
}
func (s *sourceSession) maintain() {
	defer s.wg.Done()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-tick.C:
			if !s.controlOut.Allow() || s.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(2*time.Second)) != nil {
				s.fail()
				return
			}
			s.pruneTokens()
			if now.Sub(last) >= 30*time.Second {
				envelope, err := s.owner.mesh.UplinkEndpoint()
				if err != nil || s.send(map[string]any{"kind": "advertise", "endpoint": envelope}) != nil {
					s.fail()
					return
				}
				last = now
			}
		}
	}
}
func (s *sourceSession) pruneTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.owner.handler
	h.mu.Lock()
	defer h.mu.Unlock()
	for token := range s.tokens {
		key, _ := browserMeshToken(token)
		lease := h.sessions[key]
		if lease == nil || lease.ctx.Err() != nil || !time.Now().Before(lease.expires) {
			delete(s.tokens, token)
		}
	}
}
func (s *sourceSession) owns(token string) bool {
	if !sourceHex(token, 64) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.tokens[token]
}
func (s *sourceSession) revoke(token string) {
	key, ok := browserMeshToken(token)
	if !ok {
		return
	}
	h := s.owner.handler
	h.mu.Lock()
	if lease := h.sessions[key]; lease != nil {
		lease.cancel()
		delete(h.sessions, key)
	}
	h.mu.Unlock()
}
func (s *sourceSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	if s.ws != nil {
		s.ws.Close()
	}
	s.local.Close()
	s.mu.Lock()
	streams := make([]*sourceStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.mu.Unlock()
	for _, stream := range streams {
		stream.stop()
	}
	s.wg.Wait()
	s.mu.Lock()
	tokens := make([]string, 0, len(s.tokens))
	for token := range s.tokens {
		tokens = append(tokens, token)
	}
	clear(s.tokens)
	clear(s.streams)
	clear(s.requests)
	clear(s.history)
	for len(s.queue) > 0 {
		<-s.queue
	}
	s.queuedBytes = 0
	s.queuedFrames = 0
	s.incomingBytes = 0
	s.incomingFrames = 0
	s.mu.Unlock()
	for _, token := range tokens {
		s.revoke(token)
	}
}

func (s *sourceSession) reply(id string, status int, body []byte) {
	if s.send(map[string]any{"kind": "reply", "id": id, "status": status, "body": base64.StdEncoding.EncodeToString(body)}) != nil {
		s.fail()
	}
}
func (s *sourceSession) request(p sourcePacket) error {
	body, err := sourceBase64(p.Body, 1024)
	if err != nil {
		return err
	}
	needsToken := false
	switch {
	case p.Method == "GET" && (p.Path == sourceBase+"config" || p.Path == sourceBase+"status"):
		if p.Token != "" || len(body) != 0 {
			return errors.New("invalid source metadata")
		}
	case p.Method == "POST" && p.Path == sourceBase+"sessions":
		if p.Token != "" || (len(body) != 0 && string(body) != "{}") {
			return errors.New("invalid source admission")
		}
	case p.Method == "POST" && p.Path == sourceBase+"renew", p.Method == "DELETE" && p.Path == sourceBase+"sessions":
		if len(body) != 0 || !sourceHex(p.Token, 64) {
			return errors.New("invalid source lease request")
		}
		needsToken = true
	default:
		return errors.New("source HTTP path denied")
	}
	if needsToken && !s.owns(p.Token) {
		s.reply(p.ID, 401, []byte("invalid session\n"))
		return nil
	}
	s.mu.Lock()
	if s.closed || s.requests[p.ID] != nil {
		s.mu.Unlock()
		return errors.New("duplicate source request")
	}
	if len(s.requests) >= 8 {
		s.mu.Unlock()
		s.reply(p.ID, 429, []byte("request capacity\n"))
		return nil
	}
	request := &sourceRequest{}
	s.requests[p.ID] = request
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		completed := false
		defer func() {
			s.mu.Lock()
			delete(s.requests, p.ID)
			token := request.token
			if !completed {
				delete(s.tokens, token)
			}
			s.mu.Unlock()
			if !completed && token != "" {
				s.revoke(token)
			}
		}()
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, p.Method, "http://mesh-in-process"+p.Path, bytes.NewReader(body))
		if err != nil {
			s.fail()
			return
		}
		req.Header.Set("Origin", s.owner.origin)
		req.Header.Set("X-Cypher-Source-Request", p.ID)
		if needsToken {
			req.Header.Set("Authorization", "Bearer "+p.Token)
		}
		response, err := s.local.transport.RoundTrip(req)
		if err != nil {
			if s.ctx.Err() == nil {
				s.reply(p.ID, 504, []byte("source request timeout\n"))
			}
			return
		}
		defer response.Body.Close()
		max := 16384
		if p.Path == sourceBase+"status" {
			max = 65536
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, int64(max+1)))
		if err != nil || len(raw) > max {
			s.fail()
			return
		}
		if p.Method == "DELETE" && response.StatusCode == 204 {
			s.mu.Lock()
			delete(s.tokens, p.Token)
			s.mu.Unlock()
		}
		completed = true
		s.reply(p.ID, response.StatusCode, raw)
	}()
	return nil
}

type sourceInput struct {
	kind int
	raw  []byte
}
type sourceStream struct {
	session   *sourceSession
	id, token string
	ws        *websocket.Conn
	input     chan sourceInput
	done      chan struct{}
	once      sync.Once
	closed    bool
}

func (s *sourceSession) open(p sourcePacket) error {
	if !sourceHex(p.Token, 64) {
		return errors.New("invalid source stream token")
	}
	s.mu.Lock()
	if s.closed || s.history[p.ID] || len(s.history) >= sourceStreamHistory {
		s.mu.Unlock()
		return errors.New("source stream ID reused or history full")
	}
	s.history[p.ID] = true
	if !s.tokens[p.Token] || len(s.streams) >= browserrelay.MeshMaxSessions {
		s.mu.Unlock()
		if s.send(map[string]any{"kind": "close", "id": p.ID}) != nil {
			s.fail()
		}
		return nil
	}
	for _, other := range s.streams {
		if other.token == p.Token {
			s.mu.Unlock()
			return errors.New("source token already attached")
		}
	}
	stream := &sourceStream{session: s, id: p.ID, token: p.Token, input: make(chan sourceInput, sourceQueueFrames), done: make(chan struct{})}
	s.streams[p.ID] = stream
	s.wg.Add(1)
	s.mu.Unlock()
	go stream.run()
	return nil
}
func (st *sourceStream) run() {
	s := st.session
	defer s.wg.Done()
	defer s.closeStream(st.id, false)
	dialer := websocket.Dialer{NetDialContext: s.local.listener.DialContext, HandshakeTimeout: 3 * time.Second, ReadBufferSize: 1024, WriteBufferSize: 16384}
	ws, response, err := dialer.DialContext(s.ctx, "ws://mesh-in-process"+sourceBase+"connect", http.Header{"Origin": []string{s.owner.origin}})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return
	}
	s.mu.Lock()
	if st.closed || s.closed {
		s.mu.Unlock()
		ws.Close()
		return
	}
	st.ws = ws
	s.mu.Unlock()
	ws.SetReadLimit(browserrelay.MeshMaxFrameBytes)
	forward := func(kind string, raw []byte) error {
		return s.send(map[string]any{"kind": kind, "id": st.id, "data": base64.StdEncoding.EncodeToString(raw)})
	}
	ws.SetPingHandler(func(raw string) error {
		if len(raw) > 125 {
			return errors.New("inner control size")
		}
		return forward("ping", []byte(raw))
	})
	ws.SetPongHandler(func(raw string) error {
		if len(raw) > 125 {
			return errors.New("inner control size")
		}
		return forward("pong", []byte(raw))
	})
	ws.SetCloseHandler(func(int, string) error { return nil })
	if s.send(map[string]any{"kind": "opened", "id": st.id}) != nil {
		s.fail()
		return
	}
	s.mu.Lock()
	if s.closed || st.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go st.write()
	for {
		kind, raw, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage || len(raw) > browserrelay.MeshMaxFrameBytes {
			s.fail()
			return
		}
		if forward("message", raw) != nil {
			s.fail()
			return
		}
	}
}
func (st *sourceStream) write() {
	s := st.session
	defer s.wg.Done()
	authenticated := false
	for {
		select {
		case <-st.done:
			return
		case <-s.ctx.Done():
			return
		case msg := <-st.input:
			s.mu.Lock()
			ws := st.ws
			closed := st.closed
			s.mu.Unlock()
			err := func() error {
				defer func() { s.mu.Lock(); s.incomingBytes -= len(msg.raw); s.incomingFrames--; s.mu.Unlock() }()
				if closed || ws == nil {
					return net.ErrClosed
				}
				if !authenticated {
					fields, err := publicRelayObject(msg.raw, "token")
					var token string
					if msg.kind != websocket.TextMessage || err != nil || json.Unmarshal(fields["token"], &token) != nil || token != st.token {
						s.fail()
						return errors.New("source stream token differs")
					}
					authenticated = true
				}
				if msg.kind == websocket.TextMessage {
					_ = ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
					return ws.WriteMessage(msg.kind, msg.raw)
				}
				return ws.WriteControl(msg.kind, msg.raw, time.Now().Add(2*time.Second))
			}()
			if err != nil {
				s.closeStream(st.id, false)
				return
			}
		}
	}
}
func (st *sourceStream) stop() {
	st.once.Do(func() {
		s := st.session
		s.mu.Lock()
		st.closed = true
		close(st.done)
		ws := st.ws
		for len(st.input) > 0 {
			msg := <-st.input
			s.incomingBytes -= len(msg.raw)
			s.incomingFrames--
		}
		s.mu.Unlock()
		if ws != nil {
			ws.Close()
		}
	})
}
func (s *sourceSession) closeStream(id string, remote bool) {
	s.mu.Lock()
	st := s.streams[id]
	if st != nil {
		delete(s.streams, id)
		delete(s.tokens, st.token)
	}
	s.mu.Unlock()
	if st == nil {
		return
	}
	st.stop()
	s.revoke(st.token)
	if !remote && s.ctx.Err() == nil {
		if s.send(map[string]any{"kind": "close", "id": id}) != nil {
			s.fail()
		}
	}
}
func (s *sourceSession) input(p sourcePacket) error {
	limit, kind := browserrelay.MeshMaxFrameBytes, websocket.TextMessage
	if p.Kind == "ping" {
		limit, kind = 125, websocket.PingMessage
	} else if p.Kind == "pong" {
		limit, kind = 125, websocket.PongMessage
	}
	raw, err := sourceBase64(p.Data, limit)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[p.ID]
	if st == nil || st.closed {
		if s.history[p.ID] {
			return nil
		}
		return errors.New("unknown source stream")
	}
	if s.incomingFrames >= sourceQueueFrames || s.incomingBytes+len(raw) > sourceQueueBytes || len(st.input) >= sourceQueueFrames {
		return errors.New("source receive queue full")
	}
	s.incomingBytes += len(raw)
	s.incomingFrames++
	st.input <- sourceInput{kind: kind, raw: raw}
	return nil
}

// sourcePipeListener exposes only an in-process connection to the existing
// mesh HTTP handler. It never binds TCP, Unix sockets or a public listener.
// Its finite set also owns hijacked WebSockets, which http.Server.Close alone
// does not close. Closing an uplink tears down every connection in that set.
type sourcePipeListener struct {
	mu          sync.Mutex
	done        chan struct{}
	accept      chan net.Conn
	connections map[*sourcePipeConn]struct{}
	closed      bool
}

type sourcePipeAddr struct{}

func (sourcePipeAddr) Network() string { return "cypher-mesh-in-process" }
func (sourcePipeAddr) String() string  { return "cypher-mesh-in-process" }

type sourcePipeConn struct {
	net.Conn
	owner *sourcePipeListener
	once  sync.Once
}

func (c *sourcePipeConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return err
}

func newSourcePipeListener() *sourcePipeListener {
	return &sourcePipeListener{done: make(chan struct{}), accept: make(chan net.Conn), connections: make(map[*sourcePipeConn]struct{})}
}
func (l *sourcePipeListener) Addr() net.Addr { return sourcePipeAddr{} }
func (l *sourcePipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *sourcePipeListener) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	l.mu.Lock()
	if l.closed || len(l.connections) >= browserrelay.MeshMaxSessions+8 {
		l.mu.Unlock()
		return nil, errors.New("source local connection capacity")
	}
	client, server := net.Pipe()
	owned := &sourcePipeConn{Conn: server, owner: l}
	l.connections[owned] = struct{}{}
	l.mu.Unlock()
	select {
	case l.accept <- owned:
		return client, nil
	case <-ctx.Done():
		client.Close()
		owned.Close()
		return nil, ctx.Err()
	case <-l.done:
		client.Close()
		owned.Close()
		return nil, net.ErrClosed
	}
}
func (l *sourcePipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	active := make([]*sourcePipeConn, 0, len(l.connections))
	for c := range l.connections {
		active = append(active, c)
	}
	l.mu.Unlock()
	for _, c := range active {
		c.Close()
	}
	return nil
}

type sourceLocalHTTP struct {
	listener  *sourcePipeListener
	server    *http.Server
	transport *http.Transport
	done      chan struct{}
}

func newSourceLocalHTTP(handler http.Handler) *sourceLocalHTTP {
	l := newSourcePipeListener()
	s := &sourceLocalHTTP{listener: l, done: make(chan struct{}), server: &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}}
	s.transport = &http.Transport{DialContext: l.DialContext, DisableKeepAlives: true, MaxConnsPerHost: 8, ResponseHeaderTimeout: 3 * time.Second}
	go func() { defer close(s.done); _ = s.server.Serve(l) }()
	return s
}
func (s *sourceLocalHTTP) Close() {
	s.listener.Close()
	s.transport.CloseIdleConnections()
	s.server.Close()
	<-s.done
}
