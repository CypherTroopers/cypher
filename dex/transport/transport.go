package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/cypherium/cypher/dex/protocol"
)

type Handler func(context.Context, uint8, uint8, []byte) error
type Stats struct {
	Pending                               int
	PendingByPeer                         [7]int
	PendingBytesByPeer                    [7]int
	Accepted, Rejected, FailedConnections uint64
	Failure                               string
}
type Transport struct {
	mu              sync.Mutex
	c               Config
	handler         Handler
	store           *store
	disk            diskState
	ctx             context.Context
	cancel          context.CancelFunc
	listener        net.Listener
	conns           map[net.Conn]bool
	wake            [7]chan struct{}
	slots           chan struct{}
	rate            [7]rateWindow
	wg              sync.WaitGroup
	started, closed bool
	failure         error
	stats           Stats
}
type rateWindow struct {
	start time.Time
	count int
}

func hashKey(h protocol.Hash) string { return hex.EncodeToString(h[:]) }
func Open(c Config, h Handler) (*Transport, error) {
	if h == nil {
		return nil, errors.New("transport handler required")
	}
	if c.QueueLimit == 0 {
		c.QueueLimit = 128
	}
	if c.Timeout == 0 {
		c.Timeout = 3 * time.Second
	}
	if c.Retry == 0 {
		c.Retry = 100 * time.Millisecond
	}
	if c.RatePerSecond == 0 {
		c.RatePerSecond = 1024
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.Peers = append([]Peer(nil), c.Peers...)
	c.Certificate.Certificate = [][]byte{bytes.Clone(c.Certificate.Certificate[0])}
	c.Certificate.Leaf = nil
	c.Certificate.OCSPStaple = nil
	c.Certificate.SignedCertificateTimestamps = nil
	c.Certificate.SupportedSignatureAlgorithms = nil
	c.Certificate.PrivateKey = ed25519.PrivateKey(bytes.Clone(c.Certificate.PrivateKey.(ed25519.PrivateKey)))
	store, disk, err := openStore(c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{c: c, handler: h, store: store, disk: disk, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]bool), slots: make(chan struct{}, 16)}
	for i := range t.wake {
		t.wake[i] = make(chan struct{}, 1)
	}
	return t, nil
}
func (t *Transport) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.started {
		return errors.New("transport already started/closed")
	}
	listener, err := net.Listen("tcp", t.c.Peers[t.c.Index].Address)
	if err != nil {
		return err
	}
	t.listener = listener
	t.started = true
	t.wg.Add(1)
	go t.accept()
	for i := 0; i < 7; i++ {
		t.wg.Add(1)
		go t.worker(uint8(i))
	}
	return nil
}
func (t *Transport) Send(to string, kind uint8, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("transport closed")
	}
	if t.failure != nil {
		return t.failure
	}
	dest := -1
	for i, p := range t.c.Peers {
		if p.ID == to {
			dest = i
			break
		}
	}
	if dest < 0 {
		return errors.New("unregistered recipient")
	}
	raw, err := (Frame{t.c.Domain.EpochKey(), t.c.RegistryHash, t.c.Index, uint8(dest), kind, payload}).Encode()
	if err != nil {
		return err
	}
	id := hashKey(ID(raw))
	if _, ok := t.disk.Items[id]; ok {
		return nil
	}
	total, peerBytes, peerItems := len(raw), len(raw), 0
	for _, v := range t.disk.Items {
		total += len(v.Frame)
		if v.Frame[77] == uint8(dest) {
			peerItems++
			peerBytes += len(v.Frame)
		}
	}
	// Retain every accepted frame. A disconnected destination must not consume
	// the slots/bytes needed for other registered peers to form a quorum. The
	// global limits are unchanged, and an older over-quota journal can still be
	// reopened and drained without deleting its durable messages.
	peerLimit, peerByteLimit := peerBudget(t.c.QueueLimit)
	if peerItems >= peerLimit || peerBytes > peerByteLimit {
		return errors.Join(ErrBusy, ErrCapacity)
	}
	if len(t.disk.Items) >= t.c.QueueLimit || total > maxOutboxBytes || t.disk.Next == math.MaxUint64 {
		return ErrCapacity
	}
	next := clone(t.disk)
	next.Items[id] = item{next.Next, raw}
	next.Next++
	if err = t.store.save(next); err != nil {
		t.failure = err
		return err
	}
	t.disk = next
	select {
	case t.wake[dest] <- struct{}{}:
	default:
	}
	return nil
}
func (t *Transport) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stats
	s.Pending = len(t.disk.Items)
	for _, item := range t.disk.Items {
		peer := item.Frame[77]
		s.PendingByPeer[peer]++
		s.PendingBytesByPeer[peer] += len(item.Frame)
	}
	if t.failure != nil {
		s.Failure = t.failure.Error()
	}
	return s
}

func peerBudget(globalCount int) (int, int) {
	// Tiny historical fixtures explicitly test an outbox smaller than one slot
	// per registered member. Production 128/256-slot queues reserve seven equal
	// shares; the byte share still admits the largest legal encoded frame.
	if globalCount < 7 {
		return globalCount, maxOutboxBytes
	}
	return globalCount / 7, maxOutboxBytes / 7
}
func (t *Transport) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		c.Close()
		return false
	}
	t.conns[c] = true
	return true
}
func (t *Transport) untrack(c net.Conn) { c.Close(); t.mu.Lock(); delete(t.conns, c); t.mu.Unlock() }
func (t *Transport) accept() {
	defer t.wg.Done()
	for {
		c, err := t.listener.Accept()
		if err != nil {
			return
		}
		select {
		case t.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		if !t.track(c) {
			<-t.slots
			return
		}
		t.wg.Add(1)
		go func() { defer t.wg.Done(); defer func() { <-t.slots }(); defer t.untrack(c); t.receive(c) }()
	}
}
func (t *Transport) receive(raw net.Conn) {
	raw.SetDeadline(time.Now().Add(t.c.Timeout))
	conn := tls.Server(raw, t.c.tlsConfig(-1))
	if err := conn.HandshakeContext(t.ctx); err != nil {
		t.failed()
		return
	}
	peer := -1
	pin := protocol.Hash(sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw))
	for i, p := range t.c.Peers {
		if pin == p.CertSHA256 {
			peer = i
		}
	}
	f, encoded, err := Read(conn)
	if err != nil || peer < 0 || f.Source != uint8(peer) || f.Destination != t.c.Index || f.Registry != t.c.RegistryHash || f.Epoch != t.c.Domain.EpochKey() {
		t.failed()
		return
	}
	t.mu.Lock()
	r := &t.rate[peer]
	now := time.Now()
	if now.Sub(r.start) >= time.Second {
		r.start = now
		r.count = 0
	}
	r.count++
	allowed := r.count <= t.c.RatePerSecond
	t.mu.Unlock()
	if !allowed {
		t.failed()
		return
	}
	ctx, cancel := context.WithTimeout(t.ctx, t.c.Timeout)
	defer cancel()
	err = t.handler(ctx, uint8(peer), f.Kind, bytes.Clone(f.Payload))
	if errors.Is(err, ErrBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	status := byte(1)
	if err != nil {
		status = 2
	}
	id := ID(encoded)
	ack := append([]byte{status}, id[:]...)
	if err = writeFull(conn, ack); err != nil {
		return
	}
	t.mu.Lock()
	if status == 1 {
		t.stats.Accepted++
	} else {
		t.stats.Rejected++
	}
	t.mu.Unlock()
}
func (t *Transport) failed() { t.mu.Lock(); t.stats.FailedConnections++; t.mu.Unlock() }
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (t *Transport) deliver(peer uint8, v item) (bool, error) {
	// Config validation already requires a numeric loopback endpoint. Select its
	// interface for outbound traffic too; the listener port is never reused.
	host, _, err := net.SplitHostPort(t.c.Peers[t.c.Index].Address)
	if err != nil {
		return false, err
	}
	dialer := net.Dialer{Timeout: t.c.Timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(host)}}
	raw, err := dialer.DialContext(t.ctx, "tcp", t.c.Peers[peer].Address)
	if err != nil {
		return false, err
	}
	if !t.track(raw) {
		return false, context.Canceled
	}
	defer t.untrack(raw)
	raw.SetDeadline(time.Now().Add(t.c.Timeout))
	conn := tls.Client(raw, t.c.tlsConfig(int(peer)))
	if err = conn.HandshakeContext(t.ctx); err != nil {
		return false, err
	}
	if err = writeFull(conn, v.Frame); err != nil {
		return false, err
	}
	var ack [33]byte
	if _, err = io.ReadFull(conn, ack[:]); err != nil {
		return false, err
	}
	id := ID(v.Frame)
	if (ack[0] != 1 && ack[0] != 2) || !bytes.Equal(ack[1:], id[:]) {
		return false, errors.New("invalid transport acknowledgement")
	}
	return true, nil
}
func (t *Transport) worker(peer uint8) {
	defer t.wg.Done()
	var attempted uint64
	timer := time.NewTicker(t.c.Retry)
	defer timer.Stop()
	for {
		t.mu.Lock()
		id, v := pending(t.disk, peer, attempted)
		closed, failed := t.closed, t.failure != nil
		t.mu.Unlock()
		if closed || failed {
			return
		}
		if id != "" {
			attempted = v.Sequence
			ok, err := t.deliver(peer, v)
			if err == nil && ok {
				t.mu.Lock()
				next := clone(t.disk)
				delete(next.Items, id)
				if err = t.store.save(next); err != nil {
					t.failure = err
				} else {
					t.disk = next
				}
				t.mu.Unlock()
				continue
			}
		}
		select {
		case <-t.ctx.Done():
			return
		case <-timer.C:
		case <-t.wake[peer]:
		}
	}
}
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.cancel()
	listener := t.listener
	var cs []net.Conn
	for c := range t.conns {
		cs = append(cs, c)
	}
	t.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
	for _, c := range cs {
		c.Close()
	}
	t.wg.Wait()
	return t.store.lock.Close()
}
