package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cypherium/cypher/log"
	quic "github.com/quic-go/quic-go"
)

const quicNextProto = "cypher-rnet-quic-v2"

const (
	quicStreamOpenTimeout      = 5 * time.Second
	quicHandshakeReadTimeout   = 5 * time.Second
	quicFrameHeaderReadTimeout = 5 * time.Second
	quicLargeReservationWait   = 35 * time.Second
	quicFirstStreamTimeout     = 10 * time.Second
	quicMaxIncomingStreams     = 64
	quicMaxInboundPerPeer      = 2
	quicMaxPendingHandshakes   = 256
	quicMaxPendingPerSource    = 32
	quicHandshakeIdleTimeout   = 3 * time.Second
	quicHandshakeMaxPacketSize = 64 * 1024
	quicControlMaxPacketSize   = 512 * 1024
	quicMetadataMaxPacketSize  = 4 * 1024 * 1024
	quicControlReceiveBudget   = 64 * 1024 * 1024
	quicControlPeerBudget      = 1 * 1024 * 1024
	quicMetadataReceiveBudget  = 32 * 1024 * 1024
	quicMetadataPeerBudget     = 4 * 1024 * 1024
	quicLargeDataReceiveBudget = uint64(def_MaxPacketSize)
)

type quicReceiveLimiter struct {
	mu            sync.Mutex
	controlUsed   uint64
	controlPeers  map[string]uint64
	metadataUsed  uint64
	metadataPeers map[string]uint64
	largeUsed     uint64
	largePeers    map[string]bool
	largeQueue    []*quicReceiveWaiter
}

type quicReceiveWaiter struct {
	peer  string
	size  uint64
	ready chan struct{}
}

func (l *quicReceiveLimiter) reserve(peer string, class uint8, size uint32, wait time.Duration) bool {
	return l.reserveContext(context.Background(), peer, class, size, wait)
}

func (l *quicReceiveLimiter) reserveContext(ctx context.Context, peer string, class uint8, size uint32, wait time.Duration) bool {
	if l == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	l.mu.Lock()
	amount := uint64(size)
	if isQUICLargeDataClass(class) {
		if peer == "" || amount > quicLargeDataReceiveBudget {
			l.mu.Unlock()
			return false
		}
		if l.largePeers == nil {
			l.largePeers = make(map[string]bool)
		}
		if l.largePeers[peer] {
			l.mu.Unlock()
			return false
		}
		l.largePeers[peer] = true
		if len(l.largeQueue) == 0 && l.largeUsed+amount <= quicLargeDataReceiveBudget {
			l.largeUsed += amount
			l.mu.Unlock()
			if ctx.Err() != nil {
				l.release(peer, class, size)
				return false
			}
			return true
		}
		if wait <= 0 {
			delete(l.largePeers, peer)
			l.mu.Unlock()
			return false
		}
		pending := &quicReceiveWaiter{peer: peer, size: amount, ready: make(chan struct{})}
		l.largeQueue = append(l.largeQueue, pending)
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-pending.ready:
			if ctx.Err() != nil {
				l.release(peer, class, size)
				return false
			}
			return true
		case <-timer.C:
			if l.cancelLargeWaiter(pending) {
				l.release(peer, class, size)
			}
			return false
		case <-ctx.Done():
			if l.cancelLargeWaiter(pending) {
				l.release(peer, class, size)
			}
			return false
		}
	}
	if peer == "" {
		l.mu.Unlock()
		return false
	}
	if isQUICConsensusControlClass(class) {
		if l.controlPeers == nil {
			l.controlPeers = make(map[string]uint64)
		}
		if amount > quicControlPeerBudget || l.controlPeers[peer]+amount > quicControlPeerBudget ||
			l.controlUsed+amount > quicControlReceiveBudget {
			l.mu.Unlock()
			return false
		}
		l.controlUsed += amount
		l.controlPeers[peer] += amount
	} else {
		if l.metadataPeers == nil {
			l.metadataPeers = make(map[string]uint64)
		}
		if amount > quicMetadataPeerBudget || l.metadataPeers[peer]+amount > quicMetadataPeerBudget ||
			l.metadataUsed+amount > quicMetadataReceiveBudget {
			l.mu.Unlock()
			return false
		}
		l.metadataUsed += amount
		l.metadataPeers[peer] += amount
	}
	l.mu.Unlock()
	return true
}

// cancelLargeWaiter removes an ungranted waiter and immediately re-runs the
// FIFO grant pass. If a concurrent release already granted it, the reservation
// remains owned by the caller and must still be paired with release.
func (l *quicReceiveLimiter) cancelLargeWaiter(pending *quicReceiveWaiter) bool {
	l.mu.Lock()
	for index, candidate := range l.largeQueue {
		if candidate == pending {
			l.largeQueue = append(l.largeQueue[:index], l.largeQueue[index+1:]...)
			delete(l.largePeers, pending.peer)
			l.grantLargeWaitersLocked()
			l.mu.Unlock()
			return false
		}
	}
	l.mu.Unlock()
	<-pending.ready
	return true
}

func (l *quicReceiveLimiter) grantLargeWaitersLocked() {
	for len(l.largeQueue) > 0 {
		pending := l.largeQueue[0]
		if l.largeUsed+pending.size > quicLargeDataReceiveBudget {
			return
		}
		l.largeQueue = l.largeQueue[1:]
		l.largeUsed += pending.size
		close(pending.ready)
	}
}

func (l *quicReceiveLimiter) release(peer string, class uint8, size uint32) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	amount := uint64(size)
	if isQUICLargeDataClass(class) {
		if amount > l.largeUsed {
			l.largeUsed = 0
		} else {
			l.largeUsed -= amount
		}
		delete(l.largePeers, peer)
		l.grantLargeWaitersLocked()
		return
	}
	if isQUICConsensusControlClass(class) {
		if amount > l.controlUsed {
			l.controlUsed = 0
		} else {
			l.controlUsed -= amount
		}
		if amount >= l.controlPeers[peer] {
			delete(l.controlPeers, peer)
		} else {
			l.controlPeers[peer] -= amount
		}
		return
	}
	if amount > l.metadataUsed {
		l.metadataUsed = 0
	} else {
		l.metadataUsed -= amount
	}
	if amount >= l.metadataPeers[peer] {
		delete(l.metadataPeers, peer)
	} else {
		l.metadataPeers[peer] -= amount
	}
}

func isQUICConsensusControlClass(class uint8) bool {
	return class == NetClassHandshake || class == NetClassHotstuffControl
}

func isQUICLargeDataClass(class uint8) bool {
	return class == NetClassProposalBodyBulk || class == NetClassBulkGossip
}

func quicFrameReadTimeout(class uint8, size uint32) time.Duration {
	if class == NetClassHandshake {
		return quicHandshakeReadTimeout
	}
	if !isQUICLargeDataClass(class) {
		timeout := 5*time.Second + time.Duration(size)*time.Second/(2*1024*1024)
		if timeout > 10*time.Second {
			return 10 * time.Second
		}
		return timeout
	}
	timeout := 5*time.Second + time.Duration(size)*time.Second/(10*1024*1024)
	if timeout > 30*time.Second {
		return 30 * time.Second
	}
	return timeout
}

func quicClassPacketLimit(class uint8) (uint32, bool) {
	switch class {
	case NetClassHandshake:
		return quicHandshakeMaxPacketSize, true
	case NetClassHotstuffControl:
		return quicControlMaxPacketSize, true
	case NetClassProposalBodyControl, NetClassCommitteeControl, NetClassCandidateMiner, NetClassHeartbeat:
		return quicMetadataMaxPacketSize, true
	case NetClassProposalBodyBulk, NetClassBulkGossip:
		return def_MaxPacketSize, true
	default:
		return 0, false
	}
}

// NewQUICAddress returns a new Address that has type PlainQUIC with the given
// address addr.
func NewQUICAddress(addr string) Address {
	return NewAddress(PlainQUIC, addr)
}

// NewQUICRouter returns a new Router using QUICHost as the underlying Host.
func NewQUICRouter(sid *ServerIdentity) (*Router, error) {
	return NewQUICRouterWithListenAddr(sid, "")
}

// NewQUICRouterWithListenAddr returns a new Router using QUICHost with the
// given listen address as the underlying Host.
func NewQUICRouterWithListenAddr(sid *ServerIdentity, listenAddr string) (*Router, error) {
	h, err := NewQUICHostWithListenAddr(sid, listenAddr)
	if err != nil {
		return nil, err
	}
	return NewRouter(sid, h), nil
}

type quicEnvelopeResult struct {
	env         *Envelope
	err         error
	reservation *quicReceiveReservation
}

func (result *quicEnvelopeResult) release() {
	if result == nil || result.reservation == nil {
		return
	}
	result.reservation.release()
	result.reservation = nil
}

type quicReceiveReservation struct {
	limiter *quicReceiveLimiter
	peer    string
	class   uint8
	size    uint32
}

func (reservation *quicReceiveReservation) release() {
	if reservation == nil || reservation.limiter == nil {
		return
	}
	reservation.limiter.release(reservation.peer, reservation.class, reservation.size)
	reservation.limiter = nil
}

// QUICConn implements the Conn interface using QUIC. Each outbound message is
// sent on its own QUIC stream, and inbound streams are decoded concurrently so a
// large proposal-body stream cannot block HotStuff control messages behind it.
type QUICConn struct {
	conn *quic.Conn

	closed    bool
	closedMut sync.Mutex

	sendLocks  map[uint8]*sync.Mutex
	sendLockMu sync.Mutex

	recvOnce sync.Once

	recvHandshake   chan quicEnvelopeResult
	recvControl     chan quicEnvelopeResult
	recvMeta        chan quicEnvelopeResult
	recvBulk        chan quicEnvelopeResult
	recvErr         chan error
	expectHandshake bool

	peerAddress    string
	peerPublicKey  []byte
	receiveLimiter *quicReceiveLimiter

	counterSafe
}

func newQUICConn(c *quic.Conn, limiter *quicReceiveLimiter, expectHandshake bool) (*QUICConn, error) {
	if c == nil {
		return nil, fmt.Errorf("nil QUIC connection")
	}
	tlsState := c.ConnectionState().TLS
	if len(tlsState.PeerCertificates) != 1 {
		return nil, fmt.Errorf("QUIC connection has no uniquely authenticated peer certificate")
	}
	identity, err := parseAndVerifyQUICPeerCertificate([][]byte{tlsState.PeerCertificates[0].Raw}, extractQUICPeerChainID(tlsState.PeerCertificates[0]), "", nil)
	if err != nil {
		return nil, err
	}
	return &QUICConn{
		conn:            c,
		sendLocks:       make(map[uint8]*sync.Mutex),
		recvHandshake:   make(chan quicEnvelopeResult, quicMaxIncomingStreams),
		recvControl:     make(chan quicEnvelopeResult, quicMaxIncomingStreams),
		recvMeta:        make(chan quicEnvelopeResult, quicMaxIncomingStreams),
		recvBulk:        make(chan quicEnvelopeResult, quicMaxIncomingStreams),
		recvErr:         make(chan error, 1),
		expectHandshake: expectHandshake,
		peerAddress:     identity.address,
		peerPublicKey:   identity.publicKey,
		receiveLimiter:  limiter,
	}, nil
}

func NewQUICConn(addr Address) (conn *QUICConn, err error) {
	return nil, fmt.Errorf("NewQUICConn requires an authenticated local identity and expected peer key")
}

func newAuthenticatedQUICConn(expected *ServerIdentity, auth *quicPeerAuthenticator) (conn *QUICConn, err error) {
	if expected == nil || expected.Address.ConnType() != PlainQUIC {
		return nil, fmt.Errorf("invalid authenticated QUIC peer identity")
	}
	tlsConfig, err := quicClientTLSConfig(auth, expected)
	if err != nil {
		return nil, err
	}
	netAddr := expected.Address.NetworkAddress()
	for i := 1; i <= MaxRetryConnect; i++ {
		var c *quic.Conn
		c, err = quic.DialAddr(context.Background(), netAddr, tlsConfig, quicTransportConfig())
		if err == nil {
			conn, err = newQUICConn(c, auth.receiveLimiter(), false)
			if err == nil {
				return conn, nil
			}
			_ = c.CloseWithError(1, "peer authentication failed")
		}
		if i < MaxRetryConnect {
			time.Sleep(WaitRetry)
		}
	}
	if err == nil {
		err = ErrTimeout
	}
	return
}

func (c *QUICConn) AuthenticatedPeer() (string, []byte, bool) {
	if c == nil || c.peerAddress == "" || len(c.peerPublicKey) == 0 {
		return "", nil, false
	}
	return c.peerAddress, append([]byte(nil), c.peerPublicKey...), true
}

func classifyReceivedMessage(msg Message) uint8 {
	if cm, ok := msg.(ClassifiedMessage); ok {
		return cm.NetworkClass()
	}
	return NetClassBulkGossip
}

func (c *QUICConn) Receive() (env *Envelope, e error) {
	c.recvOnce.Do(func() {
		go c.acceptStreams()
	})

	for {
		if result, ok := tryQUICResult(c.recvHandshake); ok {
			result.release()
			return result.env, result.err
		}
		if result, ok := tryQUICResult(c.recvControl); ok {
			result.release()
			return result.env, result.err
		}
		if result, ok := tryQUICResult(c.recvMeta); ok {
			result.release()
			return result.env, result.err
		}
		if result, ok := tryQUICResult(c.recvBulk); ok {
			result.release()
			return result.env, result.err
		}

		select {
		case result := <-c.recvHandshake:
			result.release()
			return result.env, result.err
		case result := <-c.recvControl:
			result.release()
			return result.env, result.err
		case result := <-c.recvMeta:
			result.release()
			return result.env, result.err
		case result := <-c.recvBulk:
			result.release()
			return result.env, result.err
		case err := <-c.recvErr:
			return nil, err
		}
	}
}

func tryQUICResult(ch <-chan quicEnvelopeResult) (quicEnvelopeResult, bool) {
	select {
	case result := <-ch:
		return result, true
	default:
		return quicEnvelopeResult{}, false
	}
}

func (c *QUICConn) acceptStreams() {
	first := c.expectHandshake
	for {
		ctx := c.conn.Context()
		cancel := func() {}
		if first {
			ctx, cancel = context.WithTimeout(ctx, quicFirstStreamTimeout)
		}
		stream, err := c.conn.AcceptStream(ctx)
		cancel()
		if err != nil {
			c.reportReceiveError(handleError(err))
			if first {
				_ = c.Close()
			}
			return
		}
		// The first stream on an accepted connection carries ServerIdentity.
		// Decode it before accepting later streams so negotiation cannot be
		// reordered behind a smaller control message.
		if first {
			first = false
			c.receiveStream(stream, true)
			continue
		}
		go c.receiveStream(stream, false)
	}
}

func (c *QUICConn) receiveStream(stream *quic.Stream, first bool) {
	defer stream.Close()
	defer stream.CancelRead(0)

	buff, frameClass, reservation, err := c.receiveRaw(stream, first)
	if err != nil {
		c.reportReceiveError(handleError(err))
		return
	}

	id, body, err := Unmarshal(buff)
	if err != nil {
		reservation.release()
		c.reportReceiveError(err)
		return
	}
	decodedClass := classifyReceivedMessage(body)
	if decodedClass != frameClass {
		reservation.release()
		c.reportReceiveError(fmt.Errorf("QUIC frame class %d does not match decoded message class %d", frameClass, decodedClass))
		return
	}
	result := quicEnvelopeResult{
		env: &Envelope{
			MsgType: id,
			Msg:     body,
		},
		reservation: reservation,
	}

	switch decodedClass {
	case NetClassHandshake:
		c.deliverResult(c.recvHandshake, result)
	case NetClassHotstuffControl:
		c.deliverResult(c.recvControl, result)
	case NetClassProposalBodyControl, NetClassCommitteeControl, NetClassCandidateMiner, NetClassHeartbeat:
		c.deliverResult(c.recvMeta, result)
	default:
		c.deliverResult(c.recvBulk, result)
	}
}

func (c *QUICConn) deliverResult(channel chan<- quicEnvelopeResult, result quicEnvelopeResult) {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	if c.closed {
		result.release()
		return
	}
	select {
	case channel <- result:
	default:
		result.release()
		c.reportReceiveError(fmt.Errorf("QUIC receive queue is full"))
	}
}

func (c *QUICConn) reportReceiveError(err error) {
	select {
	case c.recvErr <- err:
	default:
	}
}

func (c *QUICConn) receiveRaw(stream *quic.Stream, expectHandshake bool) ([]byte, uint8, *quicReceiveReservation, error) {
	headBuf := make([]byte, def_headerSize)
	_ = stream.SetReadDeadline(time.Now().Add(quicFrameHeaderReadTimeout))
	_, err := io.ReadFull(stream, headBuf)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, 0, nil, err
	}

	total, extended, validHeader := decodePacketHeader(headBuf)
	if !validHeader {
		err := fmt.Errorf("Buffer head not match! ")
		log.Info("receiveRaw", "header check fail", "error", err)
		return nil, 0, nil, err
	}
	headerSize := uint64(def_headerSize)
	if extended {
		extendedBuf := make([]byte, def_extendedSize)
		_ = stream.SetReadDeadline(time.Now().Add(quicFrameHeaderReadTimeout))
		_, err := io.ReadFull(stream, extendedBuf)
		_ = stream.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, 0, nil, err
		}
		total = binary.BigEndian.Uint32(extendedBuf)
		headerSize += def_extendedSize
	}

	var classBuf [1]byte
	_ = stream.SetReadDeadline(time.Now().Add(quicFrameHeaderReadTimeout))
	_, err = io.ReadFull(stream, classBuf[:])
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, 0, nil, err
	}
	class := classBuf[0]
	headerSize++
	classLimit, validClass := quicClassPacketLimit(class)
	if !validClass {
		return nil, 0, nil, fmt.Errorf("invalid QUIC frame class %d", class)
	}
	if expectHandshake != (class == NetClassHandshake) {
		return nil, 0, nil, fmt.Errorf("QUIC ServerIdentity must be the first and only handshake frame")
	}
	if total > classLimit {
		return nil, 0, nil, fmt.Errorf("%v sends too big class-%d packet: %v>%v", c.conn.RemoteAddr().String(), class, total, classLimit)
	}
	wait := time.Duration(0)
	if isQUICLargeDataClass(class) {
		wait = quicLargeReservationWait
	}
	if !c.receiveLimiter.reserveContext(c.conn.Context(), c.peerAddress, class, total, wait) {
		return nil, 0, nil, fmt.Errorf("QUIC class-%d receive memory budget exceeded", class)
	}
	reservation := &quicReceiveReservation{limiter: c.receiveLimiter, peer: c.peerAddress, class: class, size: total}
	if err := c.conn.Context().Err(); err != nil {
		reservation.release()
		return nil, 0, nil, handleError(err)
	}

	payload := make([]byte, total)
	_ = stream.SetReadDeadline(time.Now().Add(quicFrameReadTimeout(class, total)))
	read, err := io.ReadFull(stream, payload)
	_ = stream.SetReadDeadline(time.Time{})
	c.updateRx(headerSize + uint64(read))
	if err != nil {
		reservation.release()
		return nil, 0, nil, handleError(err)
	}
	return payload, class, reservation, nil
}

func (c *QUICConn) classLock(class uint8) *sync.Mutex {
	c.sendLockMu.Lock()
	defer c.sendLockMu.Unlock()
	lock := c.sendLocks[class]
	if lock == nil {
		lock = new(sync.Mutex)
		c.sendLocks[class] = lock
	}
	return lock
}

func (c *QUICConn) Send(msg Message) (uint64, error) {
	class := NetClassBulkGossip
	if cm, ok := msg.(ClassifiedMessage); ok {
		class = cm.NetworkClass()
	}

	lock := c.classLock(class)
	lock.Lock()
	defer lock.Unlock()

	b, err := Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("Error marshaling  message: %s", err.Error())
	}
	return c.sendRaw(b, class)
}

func (c *QUICConn) sendRaw(b []byte, class uint8) (uint64, error) {
	classLimit, validClass := quicClassPacketLimit(class)
	if !validClass {
		return 0, fmt.Errorf("invalid QUIC frame class %d", class)
	}
	if uint64(len(b)) > uint64(classLimit) {
		return 0, fmt.Errorf("class-%d packet too large: %d>%d", class, len(b), classLimit)
	}

	ctx, cancel := context.WithTimeout(context.Background(), quicStreamOpenTimeout)
	defer cancel()

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, handleError(err)
	}
	defer stream.Close()

	packetSize := uint32(len(b))
	_ = stream.SetWriteDeadline(time.Now().Add(quicFrameReadTimeout(class, packetSize)))
	defer stream.SetWriteDeadline(time.Time{})
	headBuf := encodePacketHeader(packetSize)

	if _, err := stream.Write(headBuf); err != nil {
		return 0, handleError(err)
	}
	if _, err := stream.Write([]byte{class}); err != nil {
		return uint64(len(headBuf)), handleError(err)
	}

	var sent uint32
	for sent < packetSize {
		n, err := stream.Write(b[sent:])
		if err != nil {
			sentLen := uint64(len(headBuf)) + 1 + uint64(sent)
			c.updateTx(sentLen)
			return sentLen, handleError(err)
		}
		sent += uint32(n)
	}

	sentLen := uint64(len(headBuf)) + 1 + uint64(sent)
	c.updateTx(sentLen)
	return sentLen, nil
}

func (c *QUICConn) Remote() Address {
	return Address("quic://" + c.conn.RemoteAddr().String())
}

func (c *QUICConn) Local() Address {
	return NewQUICAddress(c.conn.LocalAddr().String())
}

func (c *QUICConn) Type() ConnType {
	return PlainQUIC
}

func (c *QUICConn) IsClosed() bool {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	return c.closed
}

func (c *QUICConn) Close() error {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	if c.closed {
		return ErrClosed
	}
	err := c.conn.CloseWithError(0, "closed")
	c.closed = true
	c.releaseQueuedResultsLocked()
	if err != nil {
		handleError(err)
	}
	return err
}

func (c *QUICConn) releaseQueuedResultsLocked() {
	for _, channel := range []chan quicEnvelopeResult{c.recvHandshake, c.recvControl, c.recvMeta, c.recvBulk} {
		for {
			select {
			case result := <-channel:
				result.release()
			default:
				goto nextChannel
			}
		}
	nextChannel:
	}
}

type quicHandshakeGate struct {
	mu        sync.Mutex
	total     int
	bySource  map[string]int
	maxTotal  int
	maxSource int
}

type quicHandshakeLeaseContextKey struct{}

type quicHandshakeLease struct {
	once   sync.Once
	gate   *quicHandshakeGate
	source string
	done   chan struct{}
}

func (lease *quicHandshakeLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		if lease.gate != nil {
			lease.gate.mu.Lock()
			if lease.gate.total > 0 {
				lease.gate.total--
			}
			if lease.gate.bySource[lease.source] <= 1 {
				delete(lease.gate.bySource, lease.source)
			} else {
				lease.gate.bySource[lease.source]--
			}
			lease.gate.mu.Unlock()
		}
		if lease.done != nil {
			close(lease.done)
		}
	})
}

func releaseQUICHandshakeLease(ctx context.Context) {
	if ctx == nil {
		return
	}
	if lease, ok := ctx.Value(quicHandshakeLeaseContextKey{}).(*quicHandshakeLease); ok {
		lease.release()
	}
}

func newQUICHandshakeGate(maxTotal, maxSource int) *quicHandshakeGate {
	return &quicHandshakeGate{
		bySource:  make(map[string]int),
		maxTotal:  maxTotal,
		maxSource: maxSource,
	}
}

func quicHandshakeSource(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(address.String()); err == nil && host != "" {
		return host
	}
	return address.String()
}

// acquire reserves bounded pre-authentication work. quic-go cancels the
// ConnContext when the handshake fails or the connection closes, so every
// successful reservation is released on all TLS success, failure and timeout
// paths without trusting application-level cleanup.
func (gate *quicHandshakeGate) acquire(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if gate == nil || ctx == nil || info == nil {
		return nil, fmt.Errorf("invalid QUIC handshake gate input")
	}
	source := quicHandshakeSource(info.RemoteAddr)
	gate.mu.Lock()
	if gate.total >= gate.maxTotal || gate.bySource[source] >= gate.maxSource {
		gate.mu.Unlock()
		return nil, fmt.Errorf("too many pending QUIC handshakes")
	}
	gate.total++
	gate.bySource[source]++
	gate.mu.Unlock()

	lease := &quicHandshakeLease{gate: gate, source: source, done: make(chan struct{})}
	leasedContext := context.WithValue(ctx, quicHandshakeLeaseContextKey{}, lease)
	go func() {
		timer := time.NewTimer(2*quicHandshakeIdleTimeout + time.Second)
		defer timer.Stop()
		select {
		case <-lease.done:
			return
		case <-ctx.Done():
		case <-timer.C:
		}
		lease.release()
	}()
	return leasedContext, nil
}

// QUICListener implements the Host-interface using QUIC.
type QUICListener struct {
	listener       *quic.Listener
	transport      *quic.Transport
	packetConn     net.PacketConn
	quit           chan bool
	quitListener   chan bool
	listeningLock  sync.Mutex
	listening      bool
	closed         bool
	addr           net.Addr
	conntype       ConnType
	auth           *quicPeerAuthenticator
	receiveLimiter *quicReceiveLimiter
	peerLeaseMu    sync.Mutex
	peerLeases     map[string]uint32
	handshakeGate  *quicHandshakeGate
}

func (t *QUICListener) acquirePeerLease(peer string) bool {
	if t == nil || peer == "" {
		return false
	}
	t.peerLeaseMu.Lock()
	defer t.peerLeaseMu.Unlock()
	if t.peerLeases == nil {
		t.peerLeases = make(map[string]uint32)
	}
	if t.peerLeases[peer] >= quicMaxInboundPerPeer {
		return false
	}
	t.peerLeases[peer]++
	return true
}

func (t *QUICListener) releasePeerLease(peer string) {
	if t == nil || peer == "" {
		return
	}
	t.peerLeaseMu.Lock()
	defer t.peerLeaseMu.Unlock()
	if t.peerLeases[peer] <= 1 {
		delete(t.peerLeases, peer)
		return
	}
	t.peerLeases[peer]--
}

func NewQUICListener(addr Address) (*QUICListener, error) {
	return NewQUICListenerWithListenAddr(addr, "")
}

func NewQUICListenerWithListenAddr(addr Address, listenAddr string) (*QUICListener, error) {
	return newQUICListenerWithAuth(addr, listenAddr, newQUICPeerAuthenticator())
}

func newQUICListenerWithAuth(addr Address, listenAddr string, auth *quicPeerAuthenticator) (*QUICListener, error) {
	if addr.ConnType() != PlainQUIC {
		return nil, errors.New("QUICListener can only listen on QUIC addresses")
	}
	t := &QUICListener{
		conntype:       addr.ConnType(),
		quit:           make(chan bool),
		quitListener:   make(chan bool),
		auth:           auth,
		receiveLimiter: auth.receiveLimiter(),
		peerLeases:     make(map[string]uint32),
		handshakeGate:  newQUICHandshakeGate(quicMaxPendingHandshakes, quicMaxPendingPerSource),
	}
	listenOn, err := getListenAddress(addr, listenAddr)
	if err != nil {
		return nil, err
	}
	packetConn, err := net.ListenPacket("udp", listenOn)
	if err != nil {
		return nil, errors.New("Error opening QUIC UDP socket: " + err.Error())
	}
	transport := &quic.Transport{
		Conn: packetConn,
		// Always require Retry before allocating TLS/BLS verification work for
		// a source address. This prevents spoofed Initial packets from consuming
		// the bounded handshake slots below.
		VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext:         t.handshakeGate.acquire,
	}
	ln, err := transport.Listen(quicServerTLSConfig(auth), quicTransportConfig())
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, errors.New("Error opening quic listener: " + err.Error())
	}
	t.listener = ln
	t.transport = transport
	t.packetConn = packetConn
	t.addr = t.listener.Addr()
	return t, nil
}

func (t *QUICListener) Listen(fn func(Conn)) error {
	receiver := func(tc Conn) {
		go fn(tc)
	}
	return t.listen(receiver)
}

func (t *QUICListener) listen(fn func(Conn)) error {
	t.listeningLock.Lock()
	if t.closed {
		t.listeningLock.Unlock()
		return nil
	}
	log.Info("QUIC Listener Start !!")
	t.listening = true
	t.listeningLock.Unlock()

	for {
		conn, err := t.listener.Accept(context.Background())
		if err != nil {
			select {
			case <-t.quit:
				t.quitListener <- true
				return nil
			default:
			}
			continue
		}
		// Accept returns only after the cryptographic handshake succeeded. The
		// pre-authentication slot is no longer needed; failed handshakes release it
		// through ConnContext cancellation (with a watchdog as a final backstop).
		releaseQUICHandshakeLease(conn.Context())
		authenticated, err := newQUICConn(conn, t.receiveLimiter, true)
		if err != nil {
			_ = conn.CloseWithError(1, "peer authentication failed")
			continue
		}
		if !t.acquirePeerLease(authenticated.peerAddress) {
			_ = authenticated.Close()
			continue
		}
		go func(peer string, accepted *quic.Conn) {
			<-accepted.Context().Done()
			t.releasePeerLease(peer)
		}(authenticated.peerAddress, conn)
		fn(authenticated)
	}
}

func (t *QUICListener) Stop() error {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()

	log.Info("QUIC Listener Stop !!")

	if !t.closed {
		close(t.quit)
	}

	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			if handleError(err) != ErrClosed {
				return err
			}
		}
	}
	if t.transport != nil {
		if err := t.transport.Close(); err != nil && handleError(err) != ErrClosed {
			return err
		}
	}
	if t.packetConn != nil {
		_ = t.packetConn.Close()
	}
	var stop bool
	if t.listening {
		for !stop {
			select {
			case <-t.quitListener:
				stop = true
			case <-time.After(time.Millisecond * 50):
				continue
			}
		}
	}

	t.quit = make(chan bool)
	t.listening = false
	t.closed = true
	return nil
}

func (t *QUICListener) Address() Address {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return NewAddress(t.conntype, t.addr.String())
}

func (t *QUICListener) Listening() bool {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return t.listening
}

func (t *QUICListener) ConfigurePeerAuthentication(chainID uint64, address, privateKeyHex, publicKeyHex string, authorizedPeers map[string][]byte) error {
	if t == nil || t.auth == nil {
		return fmt.Errorf("QUIC listener authentication is unavailable")
	}
	return t.auth.configure(chainID, address, privateKeyHex, publicKeyHex, authorizedPeers)
}

func (t *QUICListener) UpdatePeerAuthorization(authorizedPeers map[string][]byte) error {
	if t == nil || t.auth == nil {
		return fmt.Errorf("QUIC listener authentication is unavailable")
	}
	return t.auth.updateAuthorizedPeers(authorizedPeers)
}

func (t *QUICListener) LocalAuthenticationPublicKey() []byte {
	if t == nil || t.auth == nil {
		return nil
	}
	return t.auth.localPublicKey()
}

// QUICHost implements the Host interface using QUIC connections.
type QUICHost struct {
	sid *ServerIdentity
	*QUICListener
}

func NewQUICHost(sid *ServerIdentity) (*QUICHost, error) {
	return NewQUICHostWithListenAddr(sid, "")
}

func NewQUICHostWithListenAddr(sid *ServerIdentity, listenAddr string) (*QUICHost, error) {
	h := &QUICHost{sid: sid}
	var err error
	h.QUICListener, err = newQUICListenerWithAuth(sid.Address, listenAddr, newQUICPeerAuthenticator())
	return h, err
}

func (t *QUICHost) Connect(si *ServerIdentity) (Conn, error) {
	switch si.Address.ConnType() {
	case PlainQUIC:
		return newAuthenticatedQUICConn(si, t.QUICListener.auth)
	case InvalidConnType:
		return nil, errors.New("This address is not correctly formatted: " + si.Address.String())
	}
	return nil, fmt.Errorf("QUICHost %s can't handle this type of connection: %s", si.Address, si.Address.ConnType())
}

func quicTransportConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  quicHandshakeIdleTimeout,
		KeepAlivePeriod:       15 * time.Second,
		MaxIdleTimeout:        3 * time.Minute,
		MaxIncomingStreams:    quicMaxIncomingStreams,
		MaxIncomingUniStreams: -1,
	}
}
