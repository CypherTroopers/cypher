package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
)

func testReply(q *Request) []byte { return append([]byte("committee receipt:"), q.ID[:]...) }
func testHooks() Hooks {
	return Hooks{ValidateRequest: func(*Request) error { return nil }, ValidateReply: func(q *Request, b []byte) error {
		if !bytes.Equal(b, testReply(q)) {
			return errors.New("forged receipt")
		}
		return nil
	}, Gateway: func(_ context.Context, q *Request) ([]byte, error) { return testReply(q), nil }}
}
func testRelay(t *testing.T, c Config, h Hooks) *Relay {
	t.Helper()
	r, err := New(c, 17, common.HexToHash("0x1234"), h)
	if err != nil {
		t.Fatal(err)
	}
	r.Start()
	t.Cleanup(r.Stop)
	return r
}
func testConnect(t *testing.T, a, b *Relay, aid, bid byte) {
	t.Helper()
	x, y := p2p.MsgPipe()
	done := make(chan struct{}, 2)
	go func() { _ = a.Protocol().Run(p2p.NewPeer(enode.ID{bid}, "b", nil), x); done <- struct{}{} }()
	go func() { _ = b.Protocol().Run(p2p.NewPeer(enode.ID{aid}, "a", nil), y); done <- struct{}{} }()
	t.Cleanup(func() {
		x.Close()
		y.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("relay protocol did not stop")
			}
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		pa := a.peers[enode.ID{bid}]
		a.mu.Unlock()
		b.mu.Lock()
		pb := b.peers[enode.ID{aid}]
		b.mu.Unlock()
		if pa != nil && pb != nil {
			a.mu.Lock()
			ar := pa.ready
			a.mu.Unlock()
			b.mu.Lock()
			br := pb.ready
			b.mu.Unlock()
			if !ar || !br {
				time.Sleep(time.Millisecond)
				continue
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("relay peers not registered")
}
func testRequest() Request {
	return Request{Kind: 1, Generation: common.HexToHash("0x99"), Target: []byte("validator-key"), Payload: []byte("unaltered signed envelope")}
}

// Uses actual negotiated subprotocol Run/ReadMsg/Send hooks and two reverse
// paths, not a topology-only model. The committee is an authenticated hook.
func TestRelayMultiHopConcurrentDedupAndReversePaths(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h := testHooks()
	h.Gateway = func(ctx context.Context, q *Request) ([]byte, error) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return testReply(q), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s := testRelay(t, Config{}, testHooks())
	a := testRelay(t, Config{}, testHooks())
	b := testRelay(t, Config{}, testHooks())
	g := testRelay(t, Config{Gateway: true}, h)
	testConnect(t, s, a, 1, 2)
	testConnect(t, s, b, 1, 3)
	testConnect(t, a, g, 2, 4)
	testConnect(t, b, g, 3, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := s.Do(ctx, testRequest())
			if err == nil && !bytes.HasPrefix(out, []byte("committee receipt:")) {
				err = errors.New("bad response")
			}
			errs <- err
		}()
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("no gateway delivery")
	}
	// Give both paths time to reach the same pending gateway request.
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("gateway calls %d, want one", calls.Load())
	}
	for _, r := range []*Relay{s, a, b, g} {
		r.mu.Lock()
		if r.pendingBytes != 0 || len(r.pending) != 0 || r.waiters != 0 {
			t.Error("pending lease leak")
		}
		r.mu.Unlock()
	}
}

func TestRelayForgedFirstPathCannotBeatValidSecondPath(t *testing.T) {
	failed := make(chan struct{})
	badHooks := testHooks()
	badHooks.Gateway = func(context.Context, *Request) ([]byte, error) { close(failed); return []byte("forged"), nil }
	badHooks.ValidateReply = func(*Request, []byte) error { return nil } // malicious relay
	goodHooks := testHooks()
	goodHooks.Gateway = func(ctx context.Context, q *Request) ([]byte, error) {
		select {
		case <-failed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		time.Sleep(20 * time.Millisecond)
		return testReply(q), nil
	}
	s := testRelay(t, Config{}, testHooks())
	bad := testRelay(t, Config{Gateway: true}, badHooks)
	a := testRelay(t, Config{}, testHooks())
	good := testRelay(t, Config{Gateway: true}, goodHooks)
	testConnect(t, s, bad, 1, 2)
	testConnect(t, s, a, 1, 3)
	testConnect(t, a, good, 3, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, err := s.Do(ctx, testRequest())
	if err != nil || !bytes.HasPrefix(b, []byte("committee receipt:")) {
		t.Fatalf("failover: %q %v", b, err)
	}
}

func TestRelayPendingBytesIndependentOfCount(t *testing.T) {
	entered := make(chan struct{}, 1)
	h := testHooks()
	h.Gateway = func(ctx context.Context, _ *Request) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := testRelay(t, Config{Gateway: true, MaxPendingBytes: MaxPayload + 1024, Timeout: 15 * time.Second}, h)
	q := testRequest()
	q.Payload = bytes.Repeat([]byte{1}, 3<<20)
	done := make(chan error, 1)
	go func() { _, err := r.Do(context.Background(), q); done <- err }()
	<-entered
	other := q
	other.Payload = bytes.Repeat([]byte{2}, 3<<20)
	if _, err := r.Do(context.Background(), other); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("byte exhaustion: %v", err)
	}
	r.mu.Lock()
	if len(r.pending) != 1 || r.pendingBytes > r.config.MaxPendingBytes || r.egressBytes > r.config.MaxPendingBytes {
		t.Error("byte accounting broken")
	}
	r.mu.Unlock()
	r.Stop()
	if err := <-done; err == nil {
		t.Fatal("expired request succeeded")
	}
	r.Stop()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingBytes != 0 || r.egressBytes != 0 || r.workBytes != 0 {
		t.Fatal("shutdown leaked byte leases")
	}
}

func TestRelayTTLSizeQueueAndCacheBounds(t *testing.T) {
	r := testRelay(t, Config{Gateway: true, CacheEntries: 2}, testHooks())
	q := testRequest()
	q.ChainID = r.chainID
	q.Genesis = r.genesis
	q.Expires = uint64(time.Now().Add(time.Second).UnixMilli())
	q.ID = requestID(&q)
	for _, ttl := range []uint64{0, 5} {
		q.Hops = ttl
		if r.check(&q) == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
	q = testRequest()
	q.Payload = make([]byte, MaxPayload+1)
	if _, err := r.Do(context.Background(), q); err == nil {
		t.Fatal("oversize accepted")
	}
	for i := byte(0); i < 5; i++ {
		q = testRequest()
		q.Payload = []byte{i}
		if _, err := r.Do(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	r.mu.Lock()
	if len(r.cache) > 2 || r.cacheBytes > r.config.CacheBytes {
		t.Fatal("cache exceeded bounds")
	}
	p := &peer{out: make(chan frame, 10), done: make(chan struct{})}
	big := testRequest()
	big.Payload = make([]byte, 3<<20)
	if !r.sendLocked(p, requestMsg, big) || !r.sendLocked(p, requestMsg, big) || r.sendLocked(p, requestMsg, big) {
		t.Fatal("queue byte cap not independent of count")
	}
	r.mu.Unlock()
}

func TestRelayNoRouteNoDirectFallback(t *testing.T) {
	var called atomic.Bool
	h := testHooks()
	h.Gateway = func(context.Context, *Request) ([]byte, error) { called.Store(true); return nil, nil }
	r := testRelay(t, Config{}, h)
	if _, err := r.Do(context.Background(), testRequest()); err == nil {
		t.Fatal("unreachable route succeeded")
	}
	if called.Load() {
		t.Fatal("non-gateway invoked egress")
	}
}

func TestRelayPeerRateAndMalformedFrame(t *testing.T) {
	for _, kind := range []string{"rate", "oversize", "wrong-chain"} {
		t.Run(kind, func(t *testing.T) {
			r := testRelay(t, Config{RequestsPerSecond: 1}, testHooks())
			x, y := p2p.MsgPipe()
			defer x.Close()
			defer y.Close()
			done := make(chan error, 1)
			go func() { done <- r.runPeer(p2p.NewPeer(enode.ID{9}, "attacker", nil), x) }()
			msg, err := y.ReadMsg()
			if err != nil {
				t.Fatal(err)
			}
			msg.Discard()
			h := hello{Version, r.chainID, r.genesis}
			if kind == "wrong-chain" {
				h.ChainID++
			}
			if err = p2p.Send(y, helloMsg, h); err != nil {
				t.Fatal(err)
			}
			if kind == "oversize" {
				go y.WriteMsg(p2p.Msg{Code: requestMsg, Size: maxWire + 1, Payload: bytes.NewReader(nil)})
			}
			if kind == "rate" {
				// Unmatched replies are ignored but still consume the peer budget.
				p2p.Send(y, responseMsg, response{ID: common.HexToHash("0x1"), Failed: true})
				go p2p.Send(y, responseMsg, response{ID: common.HexToHash("0x2"), Failed: true})
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("malformed/rate traffic accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRelayFailoverBeyondInitialFanout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			var calls atomic.Int32
			h := testHooks()
			h.Gateway = func(ctx context.Context, q *Request) ([]byte, error) {
				if calls.Add(1) < 3 {
					if timeout {
						<-ctx.Done()
					}
					return nil, ErrUnavailable
				}
				return testReply(q), nil
			}
			s := testRelay(t, Config{Fanout: 1, Timeout: 3 * time.Second}, testHooks())
			for i := byte(2); i < 5; i++ {
				g := testRelay(t, Config{Gateway: true, Timeout: 3 * time.Second}, h)
				testConnect(t, s, g, 1, i)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			if _, err := s.Do(ctx, testRequest()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 3 {
				t.Fatalf("tried %d paths", calls.Load())
			}
		})
	}
}

func TestRelayPerPeerPendingFairnessAndShutdown(t *testing.T) {
	entered := make(chan struct{}, 8)
	h := testHooks()
	h.Gateway = func(ctx context.Context, q *Request) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	g := testRelay(t, Config{Gateway: true, PeerPending: 1}, h)
	a := testRelay(t, Config{}, testHooks())
	b := testRelay(t, Config{}, testHooks())
	testConnect(t, a, g, 1, 3)
	testConnect(t, b, g, 2, 3)
	done := make(chan error, 3)
	go func() { _, err := a.Do(context.Background(), testRequest()); done <- err }()
	<-entered
	q := testRequest()
	q.Payload = []byte("second")
	if _, err := a.Do(context.Background(), q); err == nil {
		t.Fatal("peer quota bypass")
	}
	go func() { _, err := b.Do(context.Background(), q); done <- err }()
	<-entered
	g.mu.Lock()
	if len(g.pending) != 2 {
		t.Error("second peer starved")
	}
	g.mu.Unlock()
	g.Stop() // Must join readers/writers without depending on deferred pipe cleanup.
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not release origin")
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.peers) != 0 || g.pendingBytes != 0 || g.egressBytes != 0 || g.workBytes != 0 {
		t.Fatal("shutdown resources retained")
	}
}
