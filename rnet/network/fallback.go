package network

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypher/log"
)

func NewFallbackRouterWithListenAddr(sid *ServerIdentity, listenAddr string) (*Router, error) {
	h, err := NewFallbackHostWithListenAddr(sid, listenAddr)
	if err != nil {
		return nil, err
	}
	return NewRouter(sid, h), nil
}

type FallbackHost struct {
	sid      *ServerIdentity
	address  Address
	quicHost *QUICHost
	tcpHost  *TCPHost

	mu        sync.Mutex
	listening bool
	closed    bool
}

func NewFallbackHost(sid *ServerIdentity) (*FallbackHost, error) {
	return NewFallbackHostWithListenAddr(sid, "")
}

func NewFallbackHostWithListenAddr(sid *ServerIdentity, listenAddr string) (*FallbackHost, error) {
	raw := sid.Address.String()

	quicSID := NewServerIdentityWithTransport(raw, PlainQUIC)
	tcpSID := NewServerIdentityWithTransport(raw, PlainTCP)

	qh, qerr := NewQUICHostWithListenAddr(quicSID, listenAddr)
	if qerr != nil {
		return nil, fmt.Errorf("fallback host quic listener failed on %s: %v", raw, qerr)
	}

	th, terr := NewTCPHostWithListenAddr(tcpSID, listenAddr)
	if terr != nil {
		if qh != nil {
			_ = qh.Stop()
		}
		return nil, fmt.Errorf("fallback host tcp listener failed on %s: %v", raw, terr)
	}

	h := &FallbackHost{
		sid:      sid,
		address:  NewAddress(PlainQUIC, raw),
		quicHost: qh,
		tcpHost:  th,
	}
	return h, nil
}

func (h *FallbackHost) Connect(si *ServerIdentity) (Conn, error) {
	raw := si.Address.String()

	if h.quicHost != nil {
		quicSID := NewServerIdentityWithTransport(raw, PlainQUIC)
		if conn, err := h.quicHost.Connect(quicSID); err == nil {
			return newFallbackConn(conn, h.tcpHost, raw), nil
		} else {
			log.Warn("fallback transport quic connect failed", "to", raw, "err", err)
		}
	}

	if h.tcpHost != nil {
		tcpSID := NewServerIdentityWithTransport(raw, PlainTCP)
		conn, err := h.tcpHost.Connect(tcpSID)
		if err != nil {
			return nil, err
		}
		return newFallbackConn(conn, h.tcpHost, raw), nil
	}

	return nil, errors.New("fallback host has no available transport")
}

func (h *FallbackHost) Listen(fn func(Conn)) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.listening = true
	h.mu.Unlock()

	errCh := make(chan error, 2)
	started := 0

	if h.quicHost != nil {
		started++
		go func() {
			errCh <- h.quicHost.Listen(fn)
		}()
	}
	if h.tcpHost != nil {
		started++
		go func() {
			errCh <- h.tcpHost.Listen(fn)
		}()
	}

	if started == 0 {
		return errors.New("fallback host has no listeners")
	}

	var firstErr error
	for i := 0; i < started; i++ {
		err := <-errCh
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	h.mu.Lock()
	h.listening = false
	h.mu.Unlock()
	return firstErr
}

func (h *FallbackHost) Stop() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()

	var firstErr error
	if h.quicHost != nil {
		if err := h.quicHost.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if h.tcpHost != nil {
		if err := h.tcpHost.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (h *FallbackHost) Address() Address {
	return h.address
}

func (h *FallbackHost) Listening() bool {
	if h.quicHost != nil && h.quicHost.Listening() {
		return true
	}
	if h.tcpHost != nil && h.tcpHost.Listening() {
		return true
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	return h.listening
}

// Wait until at least one listener reports listening. This helper is not part of
// the Host interface but keeps tests and future callers simple.
func (h *FallbackHost) WaitListening(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if h.Listening() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// FallbackConn wraps the currently active transport. It normally starts on QUIC
// but switches to TCP when the first QUIC send fails. This also covers Router's
// initial ServerIdentity handshake because Router calls Send immediately after
// Host.Connect.
type FallbackConn struct {
	mu      sync.Mutex
	active  Conn
	tcpHost *TCPHost
	raw     string
	closed  bool
}

func newFallbackConn(active Conn, tcpHost *TCPHost, raw string) *FallbackConn {
	return &FallbackConn{active: active, tcpHost: tcpHost, raw: raw}
}

func (c *FallbackConn) dialTCP() (Conn, error) {
	if c.tcpHost == nil {
		return nil, errors.New("fallback tcp transport unavailable")
	}
	tcpSID := NewServerIdentityWithTransport(c.raw, PlainTCP)
	return c.tcpHost.Connect(tcpSID)
}

func (c *FallbackConn) Send(msg Message) (uint64, error) {
	c.mu.Lock()
	active := c.active
	closed := c.closed
	c.mu.Unlock()

	if closed {
		return 0, ErrClosed
	}
	if active == nil {
		return 0, ErrClosed
	}

	// Do not switch transports inside Send.
	// Router.connect owns ServerIdentity negotiation. If a send fails, Router.Send
	// will reconnect and perform the negotiation again before resending.
	return active.Send(msg)
}

func (c *FallbackConn) Receive() (*Envelope, error) {
	for {
		c.mu.Lock()
		active := c.active
		closed := c.closed
		c.mu.Unlock()

		if closed {
			return nil, ErrClosed
		}
		if active == nil {
			return nil, ErrClosed
		}

		env, err := active.Receive()
		if err == nil {
			return env, nil
		}

		// Send may switch the active transport from QUIC to TCP while Receive is
		// blocked on the old QUIC connection. In that case the old connection is
		// deliberately closed to unblock this Receive call. Do not propagate that
		// stale close to Router.handleConn, otherwise the router will close the new
		// TCP fallback connection immediately.
		c.mu.Lock()
		switched := !c.closed && c.active != nil && c.active != active
		c.mu.Unlock()
		if switched {
			continue
		}
		return nil, err
	}
}

func (c *FallbackConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClosed
	}
	c.closed = true
	if c.active != nil {
		return c.active.Close()
	}
	return nil
}

func (c *FallbackConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return true
	}
	if c.active == nil {
		return false
	}
	return c.active.IsClosed()
}

func (c *FallbackConn) Type() ConnType {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return c.active.Type()
	}
	return PlainQUIC
}

func (c *FallbackConn) Remote() Address {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return c.active.Remote()
	}
	return NewAddress(PlainQUIC, c.raw)
}

func (c *FallbackConn) Local() Address {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return c.active.Local()
	}
	return NewAddress(PlainQUIC, "0.0.0.0:0")
}

func (c *FallbackConn) Tx() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return c.active.Tx()
	}
	return 0
}

func (c *FallbackConn) Rx() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return c.active.Rx()
	}
	return 0
}
