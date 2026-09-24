package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// A certified child can arrive before its exact parent repair. ErrBusy must
// retain that child without preventing a later parent frame to the same peer.
// This exercises real mutually pinned TLS and the durable transport scheduler;
// consensus authentication is covered separately by replication repair tests.
func TestTLSBusyChildDoesNotBlockLaterParentRepair(t *testing.T) {
	cs := configs(t) // refuses to run outside the opted-in loopback-only namespace
	busy := make(chan struct{}, 1)
	var parentSeen atomic.Bool
	var childAttempts, childAccepted atomic.Int32
	receiver := openTest(t, cs[1], func(_ context.Context, peer, kind uint8, payload []byte) error {
		if peer != 0 || kind != KindExtension || len(payload) != 1 {
			return errors.New("unexpected authenticated repair frame")
		}
		switch payload[0] {
		case 1: // exact parent fixture
			parentSeen.Store(true)
			return nil
		case 2: // child fixture requiring parent
			childAttempts.Add(1)
			if !parentSeen.Load() {
				select {
				case busy <- struct{}{}:
				default:
				}
				return ErrBusy
			}
			childAccepted.Add(1)
			return nil
		default:
			return errors.New("unknown repair fixture")
		}
	})
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	sender := openTest(t, cs[0], func(context.Context, uint8, uint8, []byte) error { return nil })
	if err := sender.Start(); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(cs[1].Peers[1].ID, KindExtension, []byte{2}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-busy:
	case <-time.After(8 * time.Second):
		t.Fatal("child did not reach explicit missing-parent wait")
	}
	if sender.Stats().Pending != 1 || childAccepted.Load() != 0 || parentSeen.Load() {
		t.Fatal("unavailable child was lost or accepted without its parent")
	}
	if err := sender.Send(cs[1].Peers[1].ID, KindExtension, []byte{1}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return parentSeen.Load() && childAccepted.Load() == 1 && sender.Stats().Pending == 0 })
	if childAttempts.Load() < 2 || receiver.Stats().Accepted != 2 || receiver.Stats().Rejected != 0 {
		t.Fatal("child was not retried after parent delivery", childAttempts.Load(), receiver.Stats())
	}
	t.Logf("real TLS child Busy retained; later same-peer parent delivered; child accepted on retry; attempts=%d; durable queue drained", childAttempts.Load())
}
