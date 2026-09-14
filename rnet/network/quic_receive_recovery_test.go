package network

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Use the real Router handshake and receive loop: calling QUICConn.Receive
// alone would miss the connection teardown caused by a stream-local error.
func newQUICReceiveRecoveryRouter(t *testing.T) (*Router, *QUICConn, *ServerIdentity, <-chan *Envelope) {
	t.Helper()
	listener, err := NewQUICListener(NewQUICAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Stop() })
	_, port, err := net.SplitHostPort(listener.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	serverAddress := net.JoinHostPort("127.0.0.1", port)
	const clientAddress = "127.0.0.1:7103"
	const chainID = uint64(10101919)
	serverSecret, serverPublic := newQUICAuthTestKey(t)
	clientSecret, clientPublic := newQUICAuthTestKey(t)
	peers := map[string][]byte{serverAddress: serverPublic.Serialize(), clientAddress: clientPublic.Serialize()}
	serverIdentity := NewServerIdentityWithTransport(serverAddress, PlainQUIC)
	serverIdentity.PublicKey = serverPublic.Serialize()
	router := NewRouter(serverIdentity, &QUICHost{sid: serverIdentity, QUICListener: listener})
	if err := router.ConfigurePeerAuthentication(chainID, serverAddress, serverSecret.SerializeToHexStr(), serverPublic.SerializeToHexStr(), peers); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan *Envelope, 16)
	router.RegisterProcessorFunc(RegisterMessage(&quicClassifiedTestMessage{}), func(env *Envelope) { delivered <- env })
	go router.Start()
	t.Cleanup(func() { _ = router.Stop() })
	clientAuth := newQUICPeerAuthenticator()
	if err := clientAuth.configure(chainID, clientAddress, clientSecret.SerializeToHexStr(), clientPublic.SerializeToHexStr(), peers); err != nil {
		t.Fatal(err)
	}
	client, err := newAuthenticatedQUICConn(serverIdentity, clientAuth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	clientIdentity := NewServerIdentityWithTransport(clientAddress, PlainQUIC)
	clientIdentity.PublicKey = clientPublic.Serialize()
	return router, client, clientIdentity, delivered
}

func quicRecoveryEventually(t *testing.T, timeout time.Duration, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal(description)
		}
		time.Sleep(time.Millisecond)
	}
}

func quicRecoveryControl(t *testing.T, client *QUICConn, delivered <-chan *Envelope, value uint32) {
	t.Helper()
	if _, err := client.Send(&quicClassifiedTestMessage{Class: uint32(NetClassHotstuffControl), Value: value}); err != nil {
		t.Fatalf("control send failed: %v", err)
	}
	select {
	case env := <-delivered:
		msg, ok := env.Msg.(*quicClassifiedTestMessage)
		if !ok || msg.Value != value {
			t.Fatalf("delivered control = %#v, want value %d", env.Msg, value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control was not delivered through the original connection")
	}
}

func TestQUICRouterSurvivesReceiveStreamTimeout(t *testing.T) {
	for _, bodyStarted := range []bool{false, true} {
		t.Run(fmt.Sprintf("bodyStarted=%v", bodyStarted), func(t *testing.T) {
			router, client, identity, delivered := newQUICReceiveRecoveryRouter(t)
			if _, err := client.Send(identity); err != nil {
				t.Fatal(err)
			}
			quicRecoveryControl(t, client, delivered, 1)
			original := router.connection(identity).(*QUICConn)
			stalled, err := client.conn.OpenStreamSync(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer stalled.CancelWrite(1)
			if _, err := stalled.Write(encodePacketHeader(1024)); err != nil {
				t.Fatal(err)
			}
			if bodyStarted {
				if _, err := stalled.Write([]byte{NetClassProposalBodyBulk, 0}); err != nil {
					t.Fatal(err)
				}
				quicRecoveryEventually(t, 2*time.Second, "stalled body did not reserve receive bytes", func() bool {
					original.receiveLimiter.mu.Lock()
					defer original.receiveLimiter.mu.Unlock()
					return original.receiveLimiter.largeUsed == 1024
				})
			}
			quicRecoveryControl(t, client, delivered, 2)
			// CancelRead from the receiver ends the sending stream only after its
			// real read deadline expires. No production timeout is shortened here.
			select {
			case <-stalled.Context().Done():
			case <-time.After(8 * time.Second):
				t.Fatal("stalled stream was not retired after its read deadline")
			}
			quicRecoveryControl(t, client, delivered, 3)
			if got := router.connection(identity); got != original || original.IsClosed() {
				t.Fatal("stream timeout retired the authenticated connection")
			}
			original.receiveLimiter.mu.Lock()
			used, peers := original.receiveLimiter.largeUsed, len(original.receiveLimiter.largePeers)
			original.receiveLimiter.mu.Unlock()
			if used != 0 || peers != 0 {
				t.Fatalf("timed-out stream retained reservations: bytes=%d peers=%d", used, peers)
			}
		})
	}
}

func TestQUICRouterSurvivesReceiveStreamResetAndTruncation(t *testing.T) {
	router, client, identity, delivered := newQUICReceiveRecoveryRouter(t)
	if _, err := client.Send(identity); err != nil {
		t.Fatal(err)
	}
	quicRecoveryControl(t, client, delivered, 1)
	original := router.connection(identity).(*QUICConn)
	// More than the router's four-error threshold; resets and truncated FINs
	// must stay local even when no valid packet separates the errors.
	for index := 0; index < 5; index++ {
		stream, err := client.conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write(append(encodePacketHeader(1024), NetClassProposalBodyBulk, 0)); err != nil {
			t.Fatal(err)
		}
		quicRecoveryEventually(t, 2*time.Second, "stream did not reserve receive bytes", func() bool {
			original.receiveLimiter.mu.Lock()
			defer original.receiveLimiter.mu.Unlock()
			return original.receiveLimiter.largeUsed == 1024
		})
		if index%2 == 0 {
			stream.CancelWrite(quic.StreamErrorCode(42))
		} else if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		quicRecoveryEventually(t, 2*time.Second, "reset stream retained receive bytes", func() bool {
			original.receiveLimiter.mu.Lock()
			defer original.receiveLimiter.mu.Unlock()
			return original.receiveLimiter.largeUsed == 0
		})
	}
	quicRecoveryControl(t, client, delivered, 2)
	if got := router.connection(identity); got != original || original.IsClosed() {
		t.Fatal("stream reset retired the authenticated connection")
	}
	// A real connection failure must still unblock Receive and retire the peer.
	_ = client.Close()
	quicRecoveryEventually(t, 2*time.Second, "closed connection remained registered", func() bool {
		return router.connection(identity) == nil && original.IsClosed()
	})
}

func TestQUICRouterHandshakeReadTimeoutRemainsFatal(t *testing.T) {
	router, client, identity, _ := newQUICReceiveRecoveryRouter(t)
	stream, err := client.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CancelWrite(1)
	if _, err := stream.Write(encodePacketHeader(1024)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.conn.Context().Done():
	case <-time.After(8 * time.Second):
		t.Fatal("incomplete ServerIdentity handshake did not close the connection")
	}
	if router.connection(identity) != nil {
		t.Fatal("incomplete handshake registered a peer connection")
	}
}
