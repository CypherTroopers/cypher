package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeerBudgetRetainsLargestLegalFrame(t *testing.T) {
	count, size := peerBudget(256)
	if count != 36 || size < 4+MaxFrame || count*7 > 256 || size*7 > maxOutboxBytes {
		t.Fatal("peer reservation weakens global bounds or rejects maximum frame", count, size)
	}
}

func TestOfflinePeerCannotExhaustHealthyTLSOutbox(t *testing.T) {
	cs := configs(t)
	cs[0].QueueLimit = 256 // actual production setting, unchanged global cap
	// Keep the intentionally absent listener out of the sender's ephemeral
	// source-address space. Production uses explicit fixed listener ports;
	// fixture port :0 may otherwise be reused by a successful outbound socket.
	_, port, err := net.SplitHostPort(cs[1].Peers[1].Address)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		cs[i].Peers[1].Address = net.JoinHostPort("127.0.0.2", port)
		cs[i].RegistryHash, err = RegistryCommitment(cs[i].Domain, cs[i].Peers)
		if err != nil {
			t.Fatal(err)
		}
	}
	noop := func(context.Context, uint8, uint8, []byte) error { return nil }
	sender := openTest(t, cs[0], noop)
	limit, _ := peerBudget(cs[0].QueueLimit)
	for i := 0; i < limit; i++ {
		if err := sender.Send(cs[1].Peers[1].ID, KindConsensus, []byte{byte(i), 91}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sender.Send(cs[1].Peers[1].ID, KindConsensus, []byte{255, 91}); !errors.Is(err, ErrBusy) || !errors.Is(err, ErrCapacity) {
		t.Fatal("offline destination did not return explicit bounded backpressure", err)
	}
	var delivered atomic.Int32
	healthy := openTest(t, cs[2], func(context.Context, uint8, uint8, []byte) error { delivered.Add(1); return nil })
	if err := healthy.Start(); err != nil {
		t.Fatal(err)
	}
	if err := sender.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for i := uint32(0); i < 300; i++ {
		var payload [4]byte
		binary.BigEndian.PutUint32(payload[:], i)
		for {
			err := sender.Send(cs[2].Peers[2].ID, KindConsensus, payload[:])
			if err == nil {
				break
			}
			if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
				t.Fatal("healthy peer lost reserved capacity", err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitFor(t, func() bool { return delivered.Load() == 300 && sender.Stats().PendingByPeer[2] == 0 })
	if s := sender.Stats(); s.PendingByPeer[1] != limit || s.Pending != limit || s.Failure != "" {
		t.Fatal("offline messages deleted or transient backpressure poisoned transport", s)
	}
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}
	sender = openTest(t, cs[0], noop)
	if s := sender.Stats(); s.PendingByPeer[1] != limit || s.Pending != limit {
		t.Fatal("cold restart lost accepted offline frames", s)
	}
	var recovered atomic.Int32
	returned := openTest(t, cs[1], func(context.Context, uint8, uint8, []byte) error { recovered.Add(1); return nil })
	if err := returned.Start(); err != nil {
		t.Fatal(err)
	}
	if err := sender.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return recovered.Load() == int32(limit) && sender.Stats().Pending == 0 })
	t.Logf("offline peer retained %d frames; healthy peer delivered 300 > global256; same journal restart and peer return drained all accepted frames", limit)
}
