package network

import (
	"context"
	"testing"
	"time"
)

type quicClassifiedTestMessage struct {
	Class uint32
	Value uint32
}

func (m *quicClassifiedTestMessage) NetworkClass() uint8 {
	return uint8(m.Class)
}

func TestQUICControlBypassesStalledStream(t *testing.T) {
	RegisterMessage(&quicClassifiedTestMessage{})

	listener, err := NewQUICListener(NewQUICAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()

	accepted := make(chan Conn, 1)
	go func() {
		_ = listener.Listen(func(conn Conn) {
			accepted <- conn
		})
	}()

	client, err := NewQUICConn(NewQUICAddress(listener.addr.String()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for QUIC connection")
	}
	defer server.Close()

	identity := NewServerIdentityWithTransport("127.0.0.1:7102", PlainQUIC)
	if _, err := client.Send(identity); err != nil {
		t.Fatal(err)
	}
	if env, err := receiveQUICForTest(server, 2*time.Second); err != nil {
		t.Fatal(err)
	} else if env.MsgType != ServerIdentityType {
		t.Fatalf("first message type = %v, want ServerIdentity", env.MsgType)
	}

	stalled, err := client.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.CancelWrite(0)
	if _, err := stalled.Write(encodePacketHeader(1024)); err != nil {
		t.Fatal(err)
	}

	control := &quicClassifiedTestMessage{
		Class: uint32(NetClassHotstuffControl),
		Value: 42,
	}
	if _, err := client.Send(control); err != nil {
		t.Fatal(err)
	}

	env, err := receiveQUICForTest(server, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	msg, ok := env.Msg.(*quicClassifiedTestMessage)
	if !ok {
		t.Fatalf("message type = %T, want *quicClassifiedTestMessage", env.Msg)
	}
	if msg.Value != control.Value {
		t.Fatalf("message value = %d, want %d", msg.Value, control.Value)
	}
}

func receiveQUICForTest(conn Conn, timeout time.Duration) (*Envelope, error) {
	type result struct {
		env *Envelope
		err error
	}
	ch := make(chan result, 1)
	go func() {
		env, err := conn.Receive()
		ch <- result{env: env, err: err}
	}()

	select {
	case got := <-ch:
		return got.env, got.err
	case <-time.After(timeout):
		return nil, ErrTimeout
	}
}
