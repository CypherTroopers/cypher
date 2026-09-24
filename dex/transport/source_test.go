package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestOutboundTLSUsesRegisteredListenerIPAndEphemeralPort(t *testing.T) {
	cs := configs(t) // Opt-in and an actual loopback-only namespace are required.
	peers := append([]Peer(nil), cs[0].Peers...)
	for i := range peers {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.%d:0", i+2))
		if err != nil {
			t.Fatal(err)
		}
		peers[i].Address = listener.Addr().String()
		listener.Close()
	}
	hash, err := RegistryCommitment(cs[0].Domain, peers)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		cs[i].Peers, cs[i].RegistryHash = peers, hash
	}
	listener, err := net.Listen("tcp", peers[1].Address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		host, port, err := net.SplitHostPort(raw.RemoteAddr().String())
		_, listenerPort, localErr := net.SplitHostPort(peers[0].Address)
		if err != nil || localErr != nil || host != "127.0.0.2" || port == listenerPort || port == "0" {
			result <- fmt.Errorf("unexpected outbound source %s; listener %s", raw.RemoteAddr(), peers[0].Address)
			return
		}
		conn := tls.Server(raw, cs[1].tlsConfig(0)) // Still require sender's pinned key.
		if err = conn.Handshake(); err != nil {
			result <- err
			return
		}
		frame, encoded, err := Read(conn)
		if err != nil {
			result <- err
			return
		}
		if frame.Source != 0 || frame.Destination != 1 || frame.Registry != hash || frame.Epoch != cs[0].Domain.EpochKey() || !bytes.Equal(frame.Payload, []byte("source selection")) {
			result <- errors.New("source interface changed authenticated frame")
			return
		}
		id := ID(encoded)
		result <- writeFull(conn, append([]byte{1}, id[:]...))
	}()
	sender := openTest(t, cs[0], func(context.Context, uint8, uint8, []byte) error { return nil })
	if err = sender.Start(); err != nil {
		t.Fatal(err)
	}
	if err = sender.Send(peers[1].ID, KindAction, []byte("source selection")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("outbound source observation timed out")
	}
	waitFor(t, func() bool { return sender.Stats().Pending == 0 })
	t.Log("actual pinned TLS accepted source 127.0.0.2 with an ephemeral port; frame identity checks retained")
}
