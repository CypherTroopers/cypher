package network

import (
	"errors"
	"testing"
)

type failingQUICConn struct {
	closed  bool
	sendErr error
}

func (c *failingQUICConn) Send(Message) (uint64, error) {
	if c.sendErr != nil {
		return 0, c.sendErr
	}
	return 0, errors.New("quic send failed")
}
func (c *failingQUICConn) Receive() (*Envelope, error) { return nil, ErrClosed }
func (c *failingQUICConn) Close() error {
	c.closed = true
	return nil
}

func TestFallbackConnKeepsQUICOnStreamLocalSendFailure(t *testing.T) {
	host := &FallbackHost{}
	active := &failingQUICConn{sendErr: &quicStreamLocalSendError{err: ErrTimeout}}
	conn := newFallbackConn(active, "127.0.0.1:7102", func() {
		host.markQUICFailure("127.0.0.1:7102")
	})

	if _, err := conn.Send(&ServerIdentity{}); !isQUICStreamLocalSendError(err) {
		t.Fatalf("stream-local failure lost its classification: %v", err)
	}
	if host.prefersTCP("127.0.0.1:7102") {
		t.Fatal("stream-local failure incorrectly selected TCP fallback")
	}
	if active.closed {
		t.Fatal("stream-local failure closed the shared QUIC connection")
	}
}

func TestFallbackConnKeepsQUICOnPermanentMessageFailure(t *testing.T) {
	host := &FallbackHost{}
	active := &failingQUICConn{sendErr: NewPermanentSendError(SendErrorMarshal, errors.New("invalid wire message"))}
	conn := newFallbackConn(active, "127.0.0.1:7102", func() {
		host.markQUICFailure("127.0.0.1:7102")
	})

	if _, err := conn.Send(&ServerIdentity{}); !IsPermanentSendError(err) {
		t.Fatalf("permanent message failure lost its classification: %v", err)
	}
	if host.prefersTCP("127.0.0.1:7102") {
		t.Fatal("permanent message failure incorrectly selected TCP fallback")
	}
	if active.closed {
		t.Fatal("permanent message failure closed a healthy QUIC connection")
	}
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
