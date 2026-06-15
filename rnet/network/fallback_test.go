package network

import (
	"errors"
	"testing"
)

type failingQUICConn struct {
	closed bool
}

func (c *failingQUICConn) Send(Message) (uint64, error) { return 0, errors.New("quic send failed") }
func (c *failingQUICConn) Receive() (*Envelope, error)  { return nil, ErrClosed }
func (c *failingQUICConn) Close() error {
	c.closed = true
	return nil
}
func (c *failingQUICConn) IsClosed() bool { return c.closed }
func (c *failingQUICConn) Type() ConnType { return PlainQUIC }
func (c *failingQUICConn) Remote() Address {
	return NewAddress(PlainQUIC, "127.0.0.1:7102")
}
func (c *failingQUICConn) Local() Address { return NewAddress(PlainQUIC, "127.0.0.1:7104") }
func (c *failingQUICConn) Tx() uint64     { return 0 }
func (c *failingQUICConn) Rx() uint64     { return 0 }

func TestFallbackConnMarksTCPPreferredOnQUICSendFailure(t *testing.T) {
	host := &FallbackHost{}
	active := &failingQUICConn{}
	conn := newFallbackConn(active, "127.0.0.1:7102", func() {
		host.markQUICFailure("127.0.0.1:7102")
	})

	if _, err := conn.Send(&ServerIdentity{}); err == nil {
		t.Fatal("expected QUIC send failure")
	}
	if !host.prefersTCP("127.0.0.1:7102") {
		t.Fatal("TCP was not preferred after QUIC send failure")
	}
	if !active.closed {
		t.Fatal("failed QUIC connection was not closed")
	}
}
