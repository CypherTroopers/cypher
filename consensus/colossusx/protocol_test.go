package colossusx

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
)

func TestMakeProtocolMetadata(t *testing.T) {
	proto := MakeProtocol(Config{}, Handlers{})
	if proto.Name != ProtocolName {
		t.Fatalf("unexpected protocol name: %s", proto.Name)
	}
	if proto.Version != ProtocolVersion {
		t.Fatalf("unexpected protocol version: %d", proto.Version)
	}
	if proto.Length != ProtocolLength {
		t.Fatalf("unexpected protocol length: %d", proto.Length)
	}
}

func TestProtocolPingPong(t *testing.T) {
	var (
		helloSeen int32
		pingSeen  int32
	)
	proto := MakeProtocol(Config{NodeID: "local-node", Network: "devnet"}, Handlers{
		OnHello: func(_ *p2p.Peer, _ *HelloPacket) error {
			atomic.StoreInt32(&helloSeen, 1)
			return nil
		},
		OnPing: func(_ *p2p.Peer, _ *PingPacket) error {
			atomic.StoreInt32(&pingSeen, 1)
			return nil
		},
	})

	a, b := p2p.MsgPipe()
	peer := p2p.NewPeer(enode.ID{}, "remote", nil)
	errCh := make(chan error, 1)
	go func() {
		errCh <- proto.Run(peer, a)
	}()

	// Consume local hello from protocol startup.
	msg, err := b.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read hello: %v", err)
	}
	if msg.Code != HelloMsg {
		t.Fatalf("unexpected first message code: %d", msg.Code)
	}
	if err := msg.Discard(); err != nil {
		t.Fatalf("failed to discard hello payload: %v", err)
	}

	if err := p2p.Send(b, HelloMsg, &HelloPacket{NodeID: "remote", Network: "devnet", Version: "1"}); err != nil {
		t.Fatalf("failed to send hello: %v", err)
	}
	if err := p2p.Send(b, PingMsg, &PingPacket{Timestamp: 123}); err != nil {
		t.Fatalf("failed to send ping: %v", err)
	}

	pong, err := b.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read pong: %v", err)
	}
	if pong.Code != PongMsg {
		t.Fatalf("unexpected pong code: %d", pong.Code)
	}
	if err := pong.Discard(); err != nil {
		t.Fatalf("failed to discard pong payload: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&helloSeen) == 0 || atomic.LoadInt32(&pingSeen) == 0 {
		select {
		case <-deadline:
			t.Fatalf("handlers were not invoked hello=%d ping=%d", helloSeen, pingSeen)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	_ = b.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected protocol loop to terminate with an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("protocol goroutine did not exit")
	}
}
