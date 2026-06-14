package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cypherium/cypher/log"
)

// NewTCPAddress returns a new Address that has type PlainTCP with the given
// address addr.
func NewTCPAddress(addr string) Address {
	return NewAddress(PlainTCP, addr)
}

// NewTCPRouter returns a new Router using TCPHost as the underlying Host.
func NewTCPRouter(sid *ServerIdentity) (*Router, error) {
	return NewTCPRouterWithListenAddr(sid, "")
}

// NewTCPRouterWithListenAddr returns a new Router using TCPHost with the
// given listen address as the underlying Host.
func NewTCPRouterWithListenAddr(sid *ServerIdentity, listenAddr string) (*Router, error) {
	h, err := NewTCPHostWithListenAddr(sid, listenAddr)
	if err != nil {
		return nil, err
	}
	return NewRouter(sid, h), nil
}

// TCPConn implements the Conn interface using plain TCP.
type TCPConn struct {
	conn         net.Conn
	closed       bool
	closedMut    sync.Mutex
	receiveMutex sync.Mutex
	sendMutex    sync.Mutex

	counterSafe
}

func NewTCPConn(addr Address) (conn *TCPConn, err error) {
	netAddr := addr.NetworkAddress()
	for i := 1; i <= MaxRetryConnect; i++ {
		var c net.Conn
		c, err = net.DialTimeout("tcp", netAddr, 3*time.Second)
		if err == nil {
			conn = &TCPConn{conn: c}
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

func (c *TCPConn) Receive() (env *Envelope, e error) {
	buff, err := c.receiveRaw()
	if err != nil {
		return nil, err
	}
	id, body, err := Unmarshal(buff)
	return &Envelope{MsgType: id, Msg: body}, err
}

func (c *TCPConn) setReadDeadline(d time.Duration) {
	if d > 0 {
		c.conn.SetReadDeadline(time.Now().Add(d))
	} else {
		c.conn.SetReadDeadline(time.Time{})
	}
}

func (c *TCPConn) receiveRaw() ([]byte, error) {
	c.receiveMutex.Lock()
	defer c.receiveMutex.Unlock()

	headBuf := make([]byte, def_headerSize)
	c.setReadDeadline(ReadTimeout)
	_, err := io.ReadFull(c.conn, headBuf)
	c.setReadDeadline(0)
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
		c.setReadDeadline(ReadTimeout)
		_, err := io.ReadFull(c.conn, extendedBuf)
		c.setReadDeadline(0)
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
		c.setReadDeadline(ReadTimeout)
		n, err := c.conn.Read(b)
		c.setReadDeadline(0)
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

func (c *TCPConn) Send(msg Message) (uint64, error) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	b, err := Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("Error marshaling  message: %s", err.Error())
	}
	return c.sendRaw(b)
}

func (c *TCPConn) sendRaw(b []byte) (uint64, error) {
	if uint64(len(b)) > uint64(def_MaxPacketSize) {
		return 0, fmt.Errorf("packet too large: %d>%d", len(b), def_MaxPacketSize)
	}

	packetSize := uint32(len(b))
	headBuf := encodePacketHeader(packetSize)

	if _, err := c.conn.Write(headBuf); err != nil {
		return 0, err
	}

	var sent uint32
	for sent < packetSize {
		n, err := c.conn.Write(b[sent:])
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

func (c *TCPConn) Remote() Address {
	return Address("tcp://" + c.conn.RemoteAddr().String())
}

func (c *TCPConn) Local() Address {
	return NewTCPAddress(c.conn.LocalAddr().String())
}

func (c *TCPConn) Type() ConnType {
	return PlainTCP
}

func (c *TCPConn) IsClosed() bool {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	return c.closed
}

func (c *TCPConn) Close() error {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	if c.closed {
		return ErrClosed
	}
	err := c.conn.Close()
	c.closed = true
	if err != nil {
		handleError(err)
	}
	return nil
}

// TCPListener implements the Host-interface using TCP.
type TCPListener struct {
	listener      net.Listener
	quit          chan bool
	quitListener  chan bool
	listeningLock sync.Mutex
	listening     bool
	closed        bool
	addr          net.Addr
	conntype      ConnType
}

func NewTCPListener(addr Address) (*TCPListener, error) {
	return NewTCPListenerWithListenAddr(addr, "")
}

func NewTCPListenerWithListenAddr(addr Address, listenAddr string) (*TCPListener, error) {
	if addr.ConnType() != PlainTCP {
		return nil, errors.New("TCPListener can only listen on TCP addresses")
	}
	t := &TCPListener{
		conntype:     addr.ConnType(),
		quit:         make(chan bool),
		quitListener: make(chan bool),
	}
	listenOn, err := getListenAddress(addr, listenAddr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", listenOn)
	if err != nil {
		return nil, errors.New("Error opening tcp listener: " + err.Error())
	}
	t.listener = ln
	t.addr = t.listener.Addr()
	return t, nil
}

func (t *TCPListener) Listen(fn func(Conn)) error {
	receiver := func(tc Conn) {
		go fn(tc)
	}
	return t.listen(receiver)
}

func (t *TCPListener) listen(fn func(Conn)) error {
	t.listeningLock.Lock()
	if t.closed {
		t.listeningLock.Unlock()
		return nil
	}
	log.Info("TCP Listener Start !!")
	t.listening = true
	t.listeningLock.Unlock()

	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.quit:
				t.quitListener <- true
				return nil
			default:
			}
			continue
		}
		c := TCPConn{conn: conn}
		fn(&c)
	}
}

func (t *TCPListener) Stop() error {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()

	log.Info("TCP Listener Stop !!")

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

func (t *TCPListener) Address() Address {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return NewAddress(t.conntype, t.addr.String())
}

func (t *TCPListener) Listening() bool {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return t.listening
}

// TCPHost implements the Host interface using TCP connections.
type TCPHost struct {
	sid *ServerIdentity
	*TCPListener
}

func NewTCPHost(sid *ServerIdentity) (*TCPHost, error) {
	return NewTCPHostWithListenAddr(sid, "")
}

func NewTCPHostWithListenAddr(sid *ServerIdentity, listenAddr string) (*TCPHost, error) {
	h := &TCPHost{sid: sid}
	var err error
	h.TCPListener, err = NewTCPListenerWithListenAddr(sid.Address, listenAddr)
	return h, err
}

func (t *TCPHost) Connect(si *ServerIdentity) (Conn, error) {
	switch si.Address.ConnType() {
	case PlainTCP:
		return NewTCPConn(si.Address)
	case InvalidConnType:
		return nil, errors.New("This address is not correctly formatted: " + si.Address.String())
	}
	return nil, fmt.Errorf("TCPHost %s can't handle this type of connection: %s", si.Address, si.Address.ConnType())
}
