package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/cypherium/cypher/log"
	quic "github.com/quic-go/quic-go"
)

const quicNextProto = "cypher-rnet-quic-v1"

const (
	quicStreamOpenTimeout  = 5 * time.Second
	quicStreamWriteTimeout = 5 * time.Second
	quicMaxIncomingStreams = 1024
)

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
	env *Envelope
	err error
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

	handshakeMu        sync.Mutex
	handshakeDelivered bool
	recvHandshake      chan quicEnvelopeResult
	recvControl        chan quicEnvelopeResult
	recvMeta           chan quicEnvelopeResult
	recvBulk           chan quicEnvelopeResult
	recvErr            chan error

	counterSafe
}

func newQUICConn(c *quic.Conn) *QUICConn {
	return &QUICConn{
		conn:          c,
		sendLocks:     make(map[uint8]*sync.Mutex),
		recvHandshake: make(chan quicEnvelopeResult, 1024),
		recvControl:   make(chan quicEnvelopeResult, 1024),
		recvMeta:      make(chan quicEnvelopeResult, 1024),
		recvBulk:      make(chan quicEnvelopeResult, 1024),
		recvErr:       make(chan error, 1),
	}
}

func NewQUICConn(addr Address) (conn *QUICConn, err error) {
	netAddr := addr.NetworkAddress()
	for i := 1; i <= MaxRetryConnect; i++ {
		var c *quic.Conn
		c, err = quic.DialAddr(context.Background(), netAddr, quicClientTLSConfig(), quicTransportConfig())
		if err == nil {
			conn = newQUICConn(c)
			return
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
			return result.env, result.err
		}
		if result, ok := tryQUICResult(c.recvControl); ok {
			return result.env, result.err
		}
		if result, ok := tryQUICResult(c.recvMeta); ok {
			return result.env, result.err
		}
		if result, ok := tryQUICResult(c.recvBulk); ok {
			return result.env, result.err
		}

		select {
		case result := <-c.recvHandshake:
			return result.env, result.err
		case result := <-c.recvControl:
			return result.env, result.err
		case result := <-c.recvMeta:
			return result.env, result.err
		case result := <-c.recvBulk:
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
	first := true
	for {
		stream, err := c.conn.AcceptStream(context.Background())
		if err != nil {
			c.reportReceiveError(handleError(err))
			return
		}
		// The first stream on an accepted connection carries ServerIdentity.
		// Decode it before accepting later streams so negotiation cannot be
		// reordered behind a smaller control message.
		if first {
			first = false
			c.receiveStream(stream)
			continue
		}
		go c.receiveStream(stream)
	}
}

func (c *QUICConn) receiveStream(stream *quic.Stream) {
	defer stream.Close()

	buff, err := c.receiveRaw(stream)
	if err != nil {
		c.reportReceiveError(handleError(err))
		return
	}

	id, body, err := Unmarshal(buff)
	if err != nil {
		c.reportReceiveError(err)
		return
	}

	result := quicEnvelopeResult{
		env: &Envelope{
			MsgType: id,
			Msg:     body,
		},
	}

	switch classifyReceivedMessage(body) {
	case NetClassHandshake:
		c.recvHandshake <- result
	case NetClassHotstuffControl:
		c.recvControl <- result
	case NetClassProposalBodyControl, NetClassCommitteeControl, NetClassCandidateMiner, NetClassHeartbeat:
		c.recvMeta <- result
	default:
		c.recvBulk <- result
	}
}

func (c *QUICConn) reportReceiveError(err error) {
	select {
	case c.recvErr <- err:
	default:
	}
}

func (c *QUICConn) receiveRaw(stream *quic.Stream) ([]byte, error) {
	headBuf := make([]byte, def_headerSize)
	_ = stream.SetReadDeadline(time.Now().Add(ReadTimeout))
	_, err := io.ReadFull(stream, headBuf)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}

	total, extended, validHeader := decodePacketHeader(headBuf)
	if !validHeader {
		err := fmt.Errorf("Buffer head not match! ")
		log.Info("receiveRaw", "header check fail", "error", err)
		return nil, err
	}
	headerSize := uint64(def_headerSize)
	if extended {
		extendedBuf := make([]byte, def_extendedSize)
		_ = stream.SetReadDeadline(time.Now().Add(ReadTimeout))
		_, err := io.ReadFull(stream, extendedBuf)
		_ = stream.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, err
		}
		total = binary.BigEndian.Uint32(extendedBuf)
		headerSize += def_extendedSize
	}

	if total > def_MaxPacketSize {
		return nil, fmt.Errorf("%v sends too big packet: %v>%v", c.conn.RemoteAddr().String(), total, def_MaxPacketSize)
	}

	b := make([]byte, total)
	var read uint32
	var buffer bytes.Buffer
	for read < total {
		_ = stream.SetReadDeadline(time.Now().Add(ReadTimeout))
		n, err := stream.Read(b)
		_ = stream.SetReadDeadline(time.Time{})
		if n > 0 {
			if _, werr := buffer.Write(b[:n]); werr != nil {
				log.Error("receiveRaw", "Couldn't write to buffer:", werr)
			}
			read += uint32(n)
			b = b[n:]
		}
		if err != nil {
			if read >= total {
				break
			}
			c.updateRx(headerSize + uint64(read))
			return nil, handleError(err)
		}
	}

	c.updateRx(headerSize + uint64(read))
	return buffer.Bytes(), nil
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
	return c.sendRaw(b)
}

func (c *QUICConn) sendRaw(b []byte) (uint64, error) {
	if uint64(len(b)) > uint64(def_MaxPacketSize) {
		return 0, fmt.Errorf("packet too large: %d>%d", len(b), def_MaxPacketSize)
	}

	ctx, cancel := context.WithTimeout(context.Background(), quicStreamOpenTimeout)
	defer cancel()

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, handleError(err)
	}
	defer stream.Close()
	_ = stream.SetWriteDeadline(time.Now().Add(quicStreamWriteTimeout))
	defer stream.SetWriteDeadline(time.Time{})

	packetSize := uint32(len(b))
	headBuf := encodePacketHeader(packetSize)

	if _, err := stream.Write(headBuf); err != nil {
		return 0, handleError(err)
	}

	var sent uint32
	for sent < packetSize {
		n, err := stream.Write(b[sent:])
		if err != nil {
			sentLen := uint64(len(headBuf)) + uint64(sent)
			c.updateTx(sentLen)
			return sentLen, handleError(err)
		}
		sent += uint32(n)
	}

	sentLen := uint64(len(headBuf)) + uint64(sent)
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
	if err != nil {
		handleError(err)
	}
	return err
}

// QUICListener implements the Host-interface using QUIC.
type QUICListener struct {
	listener      *quic.Listener
	quit          chan bool
	quitListener  chan bool
	listeningLock sync.Mutex
	listening     bool
	closed        bool
	addr          net.Addr
	conntype      ConnType
}

func NewQUICListener(addr Address) (*QUICListener, error) {
	return NewQUICListenerWithListenAddr(addr, "")
}

func NewQUICListenerWithListenAddr(addr Address, listenAddr string) (*QUICListener, error) {
	if addr.ConnType() != PlainQUIC {
		return nil, errors.New("QUICListener can only listen on QUIC addresses")
	}
	t := &QUICListener{
		conntype:     addr.ConnType(),
		quit:         make(chan bool),
		quitListener: make(chan bool),
	}
	listenOn, err := getListenAddress(addr, listenAddr)
	if err != nil {
		return nil, err
	}
	ln, err := quic.ListenAddr(listenOn, quicServerTLSConfig(), quicTransportConfig())
	if err != nil {
		return nil, errors.New("Error opening quic listener: " + err.Error())
	}
	t.listener = ln
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
		fn(newQUICConn(conn))
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
	h.QUICListener, err = NewQUICListenerWithListenAddr(sid.Address, listenAddr)
	return h, err
}

func (t *QUICHost) Connect(si *ServerIdentity) (Conn, error) {
	switch si.Address.ConnType() {
	case PlainQUIC:
		return NewQUICConn(si.Address)
	case InvalidConnType:
		return nil, errors.New("This address is not correctly formatted: " + si.Address.String())
	}
	return nil, fmt.Errorf("QUICHost %s can't handle this type of connection: %s", si.Address, si.Address.ConnType())
}

func quicTransportConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:    15 * time.Second,
		MaxIdleTimeout:     3 * time.Minute,
		MaxIncomingStreams: quicMaxIncomingStreams,
	}
}

func quicClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{quicNextProto},
	}
}

func quicServerTLSConfig() *tls.Config {
	cert, err := generateSelfSignedCertificate()
	if err != nil {
		log.Warn("quic certificate generation failed", "err", err)
		return &tls.Config{NextProtos: []string{quicNextProto}}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicNextProto},
	}
}

func generateSelfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
