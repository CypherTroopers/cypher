// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/p2p/enode"
	"github.com/gorilla/websocket"
)

var ErrMeshUnavailable = errors.New("browser mesh unavailable")
var ErrMeshEndpointDisabled = errors.New("browser mesh public endpoint is not configured")

type MeshConfig struct {
	Network             Network
	LocalNode           func() *enode.Node
	SignDigest          func([]byte) ([]byte, error)
	SourceID            string
	PublicGatewayOrigin string
	// OnInbound may perform the native RLPx handshake. It runs in an owned,
	// bounded goroutine; Stop closes its connection and joins the callback.
	OnInbound func(net.Conn, *enode.Node) error
}

type MeshRouteInfo struct {
	CircuitID string   `json:"circuitId"`
	RemoteID  enode.ID `json:"remoteId"`
	RelayIDs  []string `json:"relayIds"`
	SessionID string   `json:"sessionId"`
}

type MeshStatus struct {
	Running       bool            `json:"running"`
	Sessions      int             `json:"sessions"`
	Circuits      int             `json:"circuits"`
	Candidates    int             `json:"candidates"`
	ReceivedBytes uint64          `json:"receivedBytes"`
	SentBytes     uint64          `json:"sentBytes"`
	Routes        []MeshRouteInfo `json:"routes"`
}

type meshRoute struct {
	node    *enode.Node
	session *meshSession
	relays  []string
	expiry  time.Time
}
type meshBucket struct {
	tokens float64
	at     time.Time
}

func (b *meshBucket) take(now time.Time, n int, rate, burst float64) bool {
	if b.at.IsZero() {
		b.at = now
		b.tokens = burst
	}
	b.tokens += now.Sub(b.at).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.at = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Mesh owns only browser-backed byte circuits. It never dials an advertised IP,
// imports chain data, or treats a browser ID as the native RLPx remote identity.
type Mesh struct {
	config                                                       MeshConfig
	mu                                                           sync.Mutex
	ctx                                                          context.Context
	cancel                                                       context.CancelFunc
	wg                                                           sync.WaitGroup
	started, stopped                                             bool
	bootID                                                       string
	advertisement                                                MeshAdvertisement
	advertisedAt                                                 time.Time
	endpoint                                                     MeshAdvertisement
	endpointSequence                                             uint64
	endpointAdvertisedAt                                         time.Time
	uplinkEndpoint                                               MeshAdvertisement
	uplinkAdvertisedAt                                           time.Time
	sessions                                                     map[string]*meshSession
	routes                                                       map[enode.ID]map[string]*meshRoute
	lastRoute                                                    map[enode.ID]string
	circuits                                                     map[string]*meshConn
	in, out                                                      meshBucket
	controlIn, controlOut, controlInMessages, controlOutMessages meshBucket
	rx, tx                                                       uint64
}

func NewMesh(c MeshConfig) (*Mesh, error) {
	if ValidateNetwork(c.Network) != nil || c.LocalNode == nil || c.SignDigest == nil || c.OnInbound == nil {
		return nil, errors.New("mesh requires a network, native identity and inbound handler")
	}
	if c.PublicGatewayOrigin != "" && (ValidateMeshGatewayOrigin(c.PublicGatewayOrigin) != nil || !meshLabel.MatchString(c.SourceID)) {
		return nil, errors.New("invalid mesh public endpoint configuration")
	}
	boot, err := meshID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Mesh{config: c, ctx: ctx, cancel: cancel, bootID: boot, sessions: make(map[string]*meshSession), routes: make(map[enode.ID]map[string]*meshRoute), lastRoute: make(map[enode.ID]string), circuits: make(map[string]*meshConn)}, nil
}

func meshID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (m *Mesh) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.stopped {
		return ErrMeshUnavailable
	}
	ad, err := meshSignAdvertisement(m.config.Network, m.config.LocalNode(), m.bootID, time.Now(), m.config.SignDigest)
	if err != nil {
		return err
	}
	m.advertisement, m.advertisedAt = ad, time.Now()
	if m.config.PublicGatewayOrigin != "" {
		if err := m.refreshEndpointLocked(time.Now()); err != nil {
			return err
		}
	}
	m.started = true
	m.wg.Add(1)
	go m.maintain()
	return nil
}

func (m *Mesh) Stop() error {
	m.mu.Lock()
	m.stopped = true
	m.cancel()
	sessions := make([]*meshSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
	m.wg.Wait()
	return nil
}

func (m *Mesh) maintain() {
	defer m.wg.Done()
	ticker := time.NewTicker(MeshHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-ticker.C:
			m.mu.Lock()
			m.pruneLocked(now)
			if m.config.PublicGatewayOrigin != "" && now.Sub(m.endpointAdvertisedAt) >= 30*time.Second {
				_ = m.refreshEndpointLocked(now)
			}
			if !m.uplinkAdvertisedAt.IsZero() && now.Sub(m.uplinkAdvertisedAt) >= 30*time.Second {
				_ = m.refreshUplinkEndpointLocked(now)
			}
			var expired []*meshConn
			for _, c := range m.circuits {
				if now.After(c.expires) {
					expired = append(expired, c)
				}
			}
			var sessions []*meshSession
			if now.Sub(m.advertisedAt) >= 30*time.Second {
				if ad, err := meshSignAdvertisement(m.config.Network, m.config.LocalNode(), m.bootID, now, m.config.SignDigest); err == nil {
					m.advertisement, m.advertisedAt = ad, now
					for _, s := range m.sessions {
						sessions = append(sessions, s)
					}
				}
			}
			ad := m.advertisement
			m.mu.Unlock()
			for _, c := range expired {
				c.closeWithReason("circuit-expired", true)
			}
			for _, s := range sessions {
				if s.send(MeshFrame{Type: "advertisement", Advertisement: &ad}) != nil {
					s.close()
				}
			}
		}
	}
}

func (m *Mesh) pruneLocked(now time.Time) {
	for id, routes := range m.routes {
		for sid, r := range routes {
			if !r.expiry.After(now) || m.sessions[sid] != r.session {
				delete(routes, sid)
			}
		}
		if len(routes) == 0 {
			delete(m.routes, id)
			delete(m.lastRoute, id)
		}
	}
}

func (m *Mesh) Candidates() []*enode.Node {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now())
	out := make([]*enode.Node, 0, len(m.routes))
	for _, routes := range m.routes {
		for _, r := range routes {
			out = append(out, r.node)
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID().String() < out[j].ID().String() })
	return out
}

func (m *Mesh) Status() MeshStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(time.Now())
	s := MeshStatus{Running: m.started && !m.stopped, Sessions: len(m.sessions), Circuits: len(m.circuits), Candidates: len(m.routes), ReceivedBytes: m.rx, SentBytes: m.tx, Routes: []MeshRouteInfo{}}
	for _, c := range m.circuits {
		s.Routes = append(s.Routes, c.infoCopy())
	}
	return s
}

// Attach accepts only an already-authenticated WebSocket. The caller owns
// Origin checks and renewable session leases, cancelling ctx on lease expiry.
// Every attachment gets a new random generation even for the same browser ID.
func (m *Mesh) Attach(ctx context.Context, browserID string, ws *websocket.Conn) error {
	if ctx == nil || ws == nil || !meshLabel.MatchString(browserID) {
		return errors.New("invalid mesh browser attachment")
	}
	id, err := meshID()
	if err != nil {
		return err
	}
	s := &meshSession{mesh: m, id: id, browserID: browserID, ws: ws, done: make(chan struct{}), out: make(chan []byte, MeshQueueFrames)}
	m.mu.Lock()
	if !m.started || m.stopped || len(m.sessions) >= MeshMaxSessions {
		m.mu.Unlock()
		return ErrMeshUnavailable
	}
	for _, existing := range m.sessions {
		if existing.browserID == browserID {
			m.mu.Unlock()
			return errors.New("browser already attached")
		}
	}
	m.sessions[id] = s
	m.wg.Add(1)
	ad := m.advertisement
	m.mu.Unlock()
	defer m.wg.Done()
	defer s.close()
	ws.SetReadLimit(MeshMaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(MeshHeartbeatTimeout))
	ws.SetPingHandler(func(payload string) error {
		if !s.allowControl(len(payload), false) {
			return errors.New("mesh control budget exceeded")
		}
		return s.writeControl(websocket.PongMessage, []byte(payload))
	})
	ws.SetPongHandler(func(payload string) error {
		if !s.allowControl(len(payload), false) {
			return errors.New("mesh control budget exceeded")
		}
		return ws.SetReadDeadline(time.Now().Add(MeshHeartbeatTimeout))
	})
	ws.SetCloseHandler(func(code int, text string) error {
		if !s.allowControl(len(text)+2, false) {
			return errors.New("mesh control budget exceeded")
		}
		return s.writeControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text))
	})
	if err := s.send(MeshFrame{Type: "hello", BrowserID: browserID, Protocol: MeshProtocol, Advertisement: &ad}); err != nil {
		return err
	}
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); s.writeLoop(ctx) }()
	defer func() { s.close(); <-writerDone }()
	for {
		kind, raw, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if kind != websocket.TextMessage || !s.allowIncoming(len(raw)) {
			return errors.New("mesh inbound budget exceeded")
		}
		f, err := meshDecodeFrame(raw)
		if err != nil || f.Session != s.id {
			return errors.New("invalid or stale mesh session frame")
		}
		if err := m.handle(s, f); err != nil {
			return err
		}
	}
}

func (m *Mesh) handle(s *meshSession, f MeshFrame) error {
	if f.Type == "advertisement" || f.Type == "open" {
		if f.Advertisement == nil || !meshValidRoute(f.Route, s.browserID) {
			return errors.New("invalid mesh advertised route")
		}
		n, expiry, err := meshVerifyAdvertisement(*f.Advertisement, m.config.Network, time.Now())
		if err != nil {
			return err
		}
		local := m.config.LocalNode()
		if local == nil || n.ID() == local.ID() {
			return errors.New("mesh route loops to local node")
		}
		if f.Type == "advertisement" {
			m.mu.Lock()
			if m.stopped || m.sessions[s.id] != s {
				m.mu.Unlock()
				return ErrMeshUnavailable
			}
			m.pruneLocked(time.Now())
			routes := m.routes[n.ID()]
			if routes == nil {
				if len(m.routes) >= MeshMaxCandidates {
					m.mu.Unlock()
					return errors.New("mesh candidate capacity")
				}
				routes = make(map[string]*meshRoute)
				m.routes[n.ID()] = routes
			}
			fresh := routes[s.id] == nil
			if fresh && len(routes) >= MeshMaxRoutesPerCandidate {
				m.mu.Unlock()
				return nil
			}
			routes[s.id] = &meshRoute{node: n, session: s, relays: append([]string(nil), f.Route...), expiry: expiry}
			m.mu.Unlock()
			return nil
		}
		if f.Target != local.ID().String() {
			return errors.New("mesh open has unknown destination")
		}
		m.mu.Lock()
		m.pruneLocked(time.Now())
		known := m.routes[n.ID()][s.id]
		m.mu.Unlock()
		if known == nil {
			return errors.New("mesh open source was not advertised")
		}
		c, err := m.newCircuit(s, f.CircuitID, n, f.Route, false)
		if err != nil {
			_ = s.send(MeshFrame{Type: "close", CircuitID: f.CircuitID, Reason: "capacity"})
			return nil
		}
		c.markReady()
		if err := s.send(MeshFrame{Type: "opened", CircuitID: c.id}); err != nil {
			c.closeWithReason("transport", false)
			return err
		}
		m.mu.Lock()
		if m.stopped {
			m.mu.Unlock()
			c.closeWithReason("stopped", false)
			return ErrMeshUnavailable
		}
		m.wg.Add(1)
		m.mu.Unlock()
		go func() {
			defer m.wg.Done()
			if m.config.OnInbound(c, n) != nil {
				c.Close()
			}
		}()
		return nil
	}
	m.mu.Lock()
	c := m.circuits[s.id+":"+f.CircuitID]
	m.mu.Unlock()
	if c == nil {
		if f.Type != "close" {
			_ = s.send(MeshFrame{Type: "close", CircuitID: f.CircuitID, Reason: "unknown-circuit"})
		}
		return nil
	}
	switch f.Type {
	case "opened":
		if !c.outbound || !c.markReady() {
			c.closeWithReason("unexpected-open", true)
		}
	case "data":
		raw, err := base64.StdEncoding.Strict().DecodeString(f.Data)
		if err != nil || len(raw) == 0 || len(raw) > MeshMaxChunkBytes || base64.StdEncoding.EncodeToString(raw) != f.Data || !c.receive(f.Seq, raw) {
			c.closeWithReason("invalid-data", true)
		}
	case "credit":
		if !c.credit(f.Seq, f.Bytes) {
			c.closeWithReason("invalid-credit", true)
		}
	case "close":
		c.closeWithReason("remote-close", false)
	}
	return nil
}

func (m *Mesh) newCircuit(s *meshSession, id string, remote *enode.Node, relays []string, outbound bool) (*meshConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !meshRandomID.MatchString(id) || m.stopped || m.sessions[s.id] != s || len(m.circuits) >= MeshMaxCircuits || m.circuits[s.id+":"+id] != nil {
		return nil, ErrMeshUnavailable
	}
	count := 0
	for _, c := range m.circuits {
		if c.session == s {
			count++
		}
	}
	if count >= MeshMaxCircuitsPerSession {
		return nil, ErrMeshUnavailable
	}
	c := newMeshConn(m, s, id, remote, relays, outbound)
	m.circuits[s.id+":"+id] = c
	return c, nil
}

func (m *Mesh) Dial(ctx context.Context, node *enode.Node) (net.Conn, error) {
	if ctx == nil || node == nil {
		return nil, ErrMeshUnavailable
	}
	m.mu.Lock()
	m.pruneLocked(time.Now())
	var routes []*meshRoute
	for _, r := range m.routes[node.ID()] {
		routes = append(routes, r)
	}
	ad := m.advertisement
	lastRoute := m.lastRoute[node.ID()]
	m.mu.Unlock()
	if len(routes) == 0 {
		return nil, ErrMeshUnavailable
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].session.id < routes[j].session.id })
	// Advance after every actual attempt, including connections which opened
	// successfully but later failed RLPx authentication or blackholed data.
	// Rotation is bounded by the candidate table and imposes no permanent ban.
	for i, route := range routes {
		if route.session.id == lastRoute {
			routes = append(routes[i+1:], routes[:i+1]...)
			break
		}
	}
	for _, r := range routes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !r.expiry.After(time.Now()) {
			continue
		}
		id, err := meshID()
		if err != nil {
			return nil, err
		}
		path := meshReverseRoute(r.relays)
		c, err := m.newCircuit(r.session, id, r.node, path, true)
		if err != nil {
			continue
		}
		m.mu.Lock()
		if m.routes[node.ID()][r.session.id] == r {
			m.lastRoute[node.ID()] = r.session.id
		}
		m.mu.Unlock()
		err = r.session.send(MeshFrame{Type: "open", CircuitID: id, Target: node.ID().String(), Advertisement: &ad, Route: path})
		if err == nil {
			timer := time.NewTimer(MeshOpenTimeout)
			select {
			case <-c.ready:
				err = nil
			case <-c.done:
				err = ErrMeshUnavailable
			case <-ctx.Done():
				err = ctx.Err()
			case <-timer.C:
				err = errors.New("mesh open timeout")
			}
			timer.Stop()
		}
		if err == nil {
			select {
			case <-c.done:
				err = ErrMeshUnavailable
			default:
				return c, nil
			}
		}
		c.closeWithReason("open-failed", true)
		m.mu.Lock()
		if m.routes[node.ID()][r.session.id] == r {
			delete(m.routes[node.ID()], r.session.id)
		}
		m.pruneLocked(time.Now())
		m.mu.Unlock()
	}
	return nil, ErrMeshUnavailable
}

type meshSession struct {
	mesh                                                         *Mesh
	id, browserID                                                string
	ws                                                           *websocket.Conn
	done                                                         chan struct{}
	once                                                         sync.Once
	mu                                                           sync.Mutex
	out                                                          chan []byte
	queued                                                       int
	inRate, outRate, msgRate                                     meshBucket
	controlIn, controlOut, controlInMessages, controlOutMessages meshBucket
}

func (s *meshSession) send(f MeshFrame) error {
	f.Session = s.id
	raw, err := json.Marshal(f)
	if err != nil || len(raw) > MeshMaxFrameBytes {
		return errors.New("mesh outbound frame too large")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if s.queued+len(raw) > MeshQueueBytes {
		return errors.New("mesh send queue full")
	}
	select {
	case s.out <- raw:
		s.queued += len(raw)
		return nil
	default:
		return errors.New("mesh send queue full")
	}
}
func (s *meshSession) allowIncoming(n int) bool {
	m := s.mesh
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// One frame of arrival jitter above the sender's burst avoids rejecting a
	// compliant stream just because WS delivery batches neighboring frames.
	if !s.msgRate.take(now, 1, 100, 200) || !s.inRate.take(now, n, MeshSessionBytesPerSecond, 2*MeshSessionBytesPerSecond+MeshMaxFrameBytes) || !m.in.take(now, n, MeshTotalBytesPerSecond, 2*MeshTotalBytesPerSecond+MeshMaxFrameBytes) {
		return false
	}
	m.rx += uint64(n)
	return true
}

// Gorilla consumes WS control frames inside ReadMessage. Charge those frames
// explicitly so ping/pong cannot bypass application frame/rate limits.
func (s *meshSession) allowControl(payloadBytes int, outgoing bool) bool {
	if payloadBytes < 0 || payloadBytes > 125 {
		return false
	}
	m := s.mesh
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	localBytes, localMessages, totalBytes, totalMessages := &s.controlIn, &s.controlInMessages, &m.controlIn, &m.controlInMessages
	if outgoing {
		localBytes, localMessages, totalBytes, totalMessages = &s.controlOut, &s.controlOutMessages, &m.controlOut, &m.controlOutMessages
	}
	// Allow a synchronized heartbeat round plus ordinary ping/close traffic at
	// full session capacity. The control byte and data budgets stay unchanged.
	messageRate := max(16.0, 2*float64(MeshMaxSessions)/MeshHeartbeatInterval.Seconds())
	messageBurst := max(32, 2*MeshMaxSessions)
	if !localMessages.take(now, 1, 2, 8) || !totalMessages.take(now, 1, messageRate, float64(messageBurst)) || !localBytes.take(now, payloadBytes+2, 512, 1024) || !totalBytes.take(now, payloadBytes+2, 4096, 8192) {
		return false
	}
	if outgoing {
		m.tx += uint64(payloadBytes)
	} else {
		m.rx += uint64(payloadBytes)
	}
	return true
}
func (s *meshSession) writeControl(kind int, payload []byte) error {
	if !s.allowControl(len(payload), true) {
		return errors.New("mesh control budget exceeded")
	}
	return s.ws.WriteControl(kind, payload, time.Now().Add(3*time.Second))
}
func (s *meshSession) writeLoop(ctx context.Context) {
	defer s.close()
	heartbeat := time.NewTicker(MeshHeartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-s.mesh.ctx.Done():
			return
		case <-heartbeat.C:
			if s.writeControl(websocket.PingMessage, nil) != nil {
				return
			}
		case raw := <-s.out:
			s.mu.Lock()
			s.queued -= len(raw)
			s.mu.Unlock()
			for {
				m := s.mesh
				m.mu.Lock()
				now := time.Now()
				nextSession, nextTotal := s.outRate, m.out
				allowed := nextSession.take(now, len(raw), MeshSessionBytesPerSecond, 2*MeshSessionBytesPerSecond) && nextTotal.take(now, len(raw), MeshTotalBytesPerSecond, 2*MeshTotalBytesPerSecond)
				if allowed {
					s.outRate, m.out = nextSession, nextTotal
				}
				m.mu.Unlock()
				if allowed {
					break
				}
				timer := time.NewTimer(25 * time.Millisecond)
				select {
				case <-timer.C:
				case <-heartbeat.C:
					timer.Stop()
					if s.writeControl(websocket.PingMessage, nil) != nil {
						return
					}
				case <-ctx.Done():
					timer.Stop()
					return
				case <-s.done:
					timer.Stop()
					return
				}
			}
			_ = s.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if s.ws.WriteMessage(websocket.TextMessage, raw) != nil {
				return
			}
			s.mesh.mu.Lock()
			s.mesh.tx += uint64(len(raw))
			s.mesh.mu.Unlock()
		}
	}
}
func (s *meshSession) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.ws.Close()
		m := s.mesh
		m.mu.Lock()
		delete(m.sessions, s.id)
		var circuits []*meshConn
		for _, c := range m.circuits {
			if c.session == s {
				circuits = append(circuits, c)
			}
		}
		m.pruneLocked(time.Now())
		m.mu.Unlock()
		for _, c := range circuits {
			c.closeWithReason("session-closed", false)
		}
		s.mu.Lock()
		for {
			select {
			case raw := <-s.out:
				s.queued -= len(raw)
			default:
				s.mu.Unlock()
				return
			}
		}
	})
}

// Endpoint returns immutable signed bytes. HTTP reads never extend a lease or
// generate signatures; failed refreshes cannot relabel stale data as fresh.
func (m *Mesh) Endpoint() (MeshAdvertisement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started || m.stopped {
		return MeshAdvertisement{}, ErrMeshUnavailable
	}
	if m.config.PublicGatewayOrigin == "" {
		return MeshAdvertisement{}, ErrMeshEndpointDisabled
	}
	if m.endpointSequence == 0 || time.Now().UnixMilli() >= m.endpointAdvertisedAt.UnixMilli()+MeshAdvertisementTTL.Milliseconds() {
		return MeshAdvertisement{}, ErrMeshUnavailable
	}
	return m.endpoint, nil
}
func (m *Mesh) refreshEndpointLocked(now time.Time) error {
	if m.endpointSequence >= MaxSafeInteger || (!m.endpointAdvertisedAt.IsZero() && now.UnixMilli() < m.endpointAdvertisedAt.UnixMilli()) || (!m.uplinkAdvertisedAt.IsZero() && now.Before(m.uplinkAdvertisedAt)) {
		return ErrMeshUnavailable
	}
	envelope, err := meshSignEndpoint(m.config.Network, m.config.LocalNode(), m.config.SourceID, m.config.PublicGatewayOrigin, m.bootID, m.endpointSequence+1, now, m.config.SignDigest)
	if err != nil {
		return err
	}
	m.endpoint, m.endpointSequence, m.endpointAdvertisedAt = envelope, m.endpointSequence+1, now
	return nil
}

// UplinkEndpoint uses the native ID as a globally unique source label. The
// operator's local endpoint retains its configured SourceID. Both envelopes
// share one sequence counter so an older envelope cannot roll back discovery.
func (m *Mesh) UplinkEndpoint() (MeshAdvertisement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started || m.stopped {
		return MeshAdvertisement{}, ErrMeshUnavailable
	}
	if m.config.PublicGatewayOrigin == "" {
		return MeshAdvertisement{}, ErrMeshEndpointDisabled
	}
	if !m.uplinkAdvertisedAt.IsZero() && time.Now().UnixMilli() >= m.uplinkAdvertisedAt.UnixMilli()+MeshAdvertisementTTL.Milliseconds() {
		return MeshAdvertisement{}, ErrMeshUnavailable
	}
	if m.uplinkAdvertisedAt.IsZero() || time.Since(m.uplinkAdvertisedAt) >= 30*time.Second {
		if err := m.refreshUplinkEndpointLocked(time.Now()); err != nil {
			return MeshAdvertisement{}, err
		}
	}
	if time.Now().UnixMilli() >= m.uplinkAdvertisedAt.UnixMilli()+MeshAdvertisementTTL.Milliseconds() {
		return MeshAdvertisement{}, ErrMeshUnavailable
	}
	return m.uplinkEndpoint, nil
}

func (m *Mesh) refreshUplinkEndpointLocked(now time.Time) error {
	if m.endpointSequence >= MaxSafeInteger || now.Before(m.endpointAdvertisedAt) || (!m.uplinkAdvertisedAt.IsZero() && now.Before(m.uplinkAdvertisedAt)) {
		return ErrMeshUnavailable
	}
	node := m.config.LocalNode()
	if node == nil {
		return ErrMeshUnavailable
	}
	envelope, err := meshSignEndpoint(m.config.Network, node, node.ID().String(), m.config.PublicGatewayOrigin, m.bootID, m.endpointSequence+1, now, m.config.SignDigest)
	if err != nil {
		return err
	}
	m.uplinkEndpoint, m.endpointSequence, m.uplinkAdvertisedAt = envelope, m.endpointSequence+1, now
	return nil
}
