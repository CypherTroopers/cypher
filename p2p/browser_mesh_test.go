package p2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common/mclock"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/p2p/netutil"
	"golang.org/x/crypto/sha3"
)

func meshServerFixture(t *testing.T, protocol Protocol) *Server {
	t.Helper()
	s := &Server{Config: Config{PrivateKey: newkey(), MaxPeers: 8, MaxPendingPeers: 2, NoDiscovery: true, NoDial: true,
		BrowserMesh: &BrowserMeshConfig{MaxPending: 2, MaxFrameBytes: 64 << 10}, Protocols: []Protocol{protocol}}}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

func meshPairFixture(t *testing.T, a, b *Server, remoteB enode.ID) (net.Conn, net.Conn) {
	t.Helper()
	x, y := net.Pipe()
	left, err := NewBrowserMeshConn(x, BrowserMeshInfo{CircuitID: "fixture-circuit", RemoteID: b.Self().ID(), RelayIDs: []string{"browser-A", "browser-B"}})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewBrowserMeshConn(y, BrowserMeshInfo{CircuitID: "fixture-circuit", RemoteID: remoteB, RelayIDs: []string{"browser-B", "browser-A"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { left.Close(); right.Close() })
	return left, right
}

func TestBrowserMeshAuthenticatedNativePeersExchangeMessages(t *testing.T) {
	payload := []byte("actual RLPx encrypted protocol bytes through browser circuit")
	received := make(chan enode.ID, 2)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	protocol := Protocol{Name: "mesh-fixture", Version: 1, Length: 1, Run: func(p *Peer, rw MsgReadWriter) error {
		if err := Send(rw, 0, payload); err != nil {
			return err
		}
		if err := ExpectMsg(rw, 0, payload); err != nil {
			return err
		}
		received <- p.ID()
		<-release
		return nil
	}}
	a, b := meshServerFixture(t, protocol), meshServerFixture(t, protocol)
	x, y := meshPairFixture(t, a, b, a.Self().ID())
	results := make(chan error, 2)
	go func() { results <- a.SetupConn(x, dynDialedConn, b.Self()) }()
	go func() { results <- b.SetupBrowserMesh(y) }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("RLPx mesh handshake timeout")
		}
	}
	ids := make(map[enode.ID]bool)
	for i := 0; i < 2; i++ {
		select {
		case id := <-received:
			ids[id] = true
		case <-time.After(3 * time.Second):
			t.Fatal("native protocol exchange missing")
		}
	}
	if !ids[a.Self().ID()] || !ids[b.Self().ID()] || a.PeerCount() != 1 || b.PeerCount() != 1 {
		t.Fatal("browser was counted instead of authenticated Common peers")
	}
	info := a.PeersInfo()[0]
	if info.ID != b.Self().ID().String() || info.Network.Transport != "browser-mesh" || info.Network.BrowserMesh == nil || len(info.Network.BrowserMesh.RelayIDs) != 2 || info.Network.BrowserMesh.BytesSent == 0 || info.Network.BrowserMesh.BytesReceived == 0 {
		t.Fatalf("missing native route statistics: %+v", info.Network)
	}
	if _, ok := x.RemoteAddr().(*net.TCPAddr); ok {
		t.Fatal("mesh route impersonated a TCP peer IP")
	}
	once.Do(func() { close(release) })
}

func TestBrowserMeshRejectsWrongAdvertisedIdentity(t *testing.T) {
	protocol := Protocol{Name: "mesh-fixture", Version: 1, Length: 1, Run: func(_ *Peer, rw MsgReadWriter) error { _, err := rw.ReadMsg(); return err }}
	a, b := meshServerFixture(t, protocol), meshServerFixture(t, protocol)
	x, y := meshPairFixture(t, a, b, randomID())
	left := make(chan error, 1)
	go func() { left <- a.SetupConn(x, dynDialedConn, b.Self()) }()
	if err := b.SetupBrowserMesh(y); !errors.Is(err, DiscUnexpectedIdentity) {
		t.Fatalf("wrong source identity accepted: %v", err)
	}
	if b.PeerCount() != 0 {
		t.Fatal("wrong Common joined peer set")
	}
	select {
	case <-left:
	case <-time.After(3 * time.Second):
		t.Fatal("rejected RLPx stream leaked")
	}
}

type meshDialFunc func(context.Context, *enode.Node) (net.Conn, error)

func (f meshDialFunc) Dial(c context.Context, n *enode.Node) (net.Conn, error) { return f(c, n) }

func TestBrowserMeshDialPrefersDirectAndExcludesReserved(t *testing.T) {
	dest := enode.NewV4(&newkey().PublicKey, net.ParseIP("127.0.0.1"), 1234, 1234)
	var direct, mesh int
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	d := &dialScheduler{dialConfig: dialConfig{dialer: meshDialFunc(func(context.Context, *enode.Node) (net.Conn, error) { direct++; return x, nil }), mesh: &BrowserMeshConfig{Dialer: meshDialFunc(func(context.Context, *enode.Node) (net.Conn, error) {
		mesh++
		return nil, errors.New("fixture unavailable")
	})}}}
	if fd, err := d.dialWithMesh(context.Background(), dest, &dialTask{flags: staticDialedConn}); err != nil || fd != x || direct != 1 || mesh != 0 {
		t.Fatal("healthy direct path used mesh")
	}
	d.dialer = meshDialFunc(func(context.Context, *enode.Node) (net.Conn, error) {
		direct++
		return nil, errors.New("direct unavailable")
	})
	task := &dialTask{flags: staticDialedConn}
	if _, err := d.dialWithMesh(context.Background(), dest, task); err == nil || mesh != 1 || !task.meshAttempted {
		t.Fatal("direct failure did not try mesh")
	}
	d.reserved = map[enode.ID]*enode.Node{dest.ID(): dest}
	_, _ = d.dialWithMesh(context.Background(), dest, &dialTask{})
	if mesh != 1 {
		t.Fatal("reserved committee endpoint used browser mesh")
	}
	d.reserved = nil
	d.mesh.HasRoute = func(enode.ID) bool { return true }
	before := direct
	_, _ = d.dialWithMesh(context.Background(), dest, &dialTask{flags: dynDialedConn})
	if direct != before || mesh != 2 {
		t.Fatal("mesh advertisement was used as an arbitrary TCP destination")
	}
	d.mesh.HasRoute = func(enode.ID) bool { return false }
	_, _ = d.dialWithMesh(context.Background(), dest, &dialTask{flags: dynDialedConn, meshOnly: true})
	if direct != before || mesh != 2 {
		t.Fatal("expired mesh candidate became an arbitrary TCP dial")
	}
}

func TestBrowserMeshCandidateKeepsOriginAfterRouteExpiry(t *testing.T) {
	node := enode.NewV4(&newkey().PublicKey, net.ParseIP("192.0.2.1"), 1234, 1234)
	consulted := make(chan struct{}, 1)
	var direct atomic.Int32
	d := newDialScheduler(dialConfig{
		maxDialPeers: 1,
		dialer: meshDialFunc(func(context.Context, *enode.Node) (net.Conn, error) {
			direct.Add(1)
			return nil, errors.New("must not probe advertised IP")
		}),
		mesh: &BrowserMeshConfig{MaxPending: 1, Candidates: enode.IterNodes([]*enode.Node{node}),
			HasRoute: func(enode.ID) bool { consulted <- struct{}{}; return false },
			Dialer: meshDialFunc(func(context.Context, *enode.Node) (net.Conn, error) {
				return nil, errors.New("expired route")
			})},
	}, enode.IterNodes(nil), func(net.Conn, connFlag, *enode.Node) error { return nil })
	select {
	case <-consulted:
	case <-time.After(time.Second):
		d.stop()
		t.Fatal("mesh iterator candidate was not consumed")
	}
	d.stop()
	if direct.Load() != 0 {
		t.Fatal("route expiry erased candidate origin and caused TCP dial")
	}
}

func TestBrowserMeshPendingBudgetAndStop(t *testing.T) {
	s := meshServerFixture(t, Protocol{Name: "mesh-fixture", Version: 1, Length: 1})
	x, y := net.Pipe()
	defer y.Close()
	conn, err := NewBrowserMeshConn(x, BrowserMeshInfo{CircuitID: "pending", RemoteID: randomID(), RelayIDs: []string{"browser-A"}})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate TCP handshakes occupying the shared admission budget.
	s.inboundHandshakeSlots <- struct{}{}
	s.inboundHandshakeSlots <- struct{}{}
	if err := s.SetupBrowserMesh(conn); err == nil {
		t.Fatal("mesh bypassed occupied TCP pending slots")
	}
	<-s.inboundHandshakeSlots
	<-s.inboundHandshakeSlots
	x, y = net.Pipe()
	defer y.Close()
	conn, _ = NewBrowserMeshConn(x, BrowserMeshInfo{CircuitID: "pending-next", RemoteID: randomID(), RelayIDs: []string{"browser-A"}})
	done := make(chan error, 1)
	go func() { done <- s.SetupBrowserMesh(conn) }()
	deadline := time.After(time.Second)
	for len(s.meshPending) == 0 {
		select {
		case <-deadline:
			t.Fatal("mesh pending did not begin")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	s.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stopped unauthenticated stream succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not join pending mesh handshake")
	}
}

func TestBrowserMeshRoleAndAddressRestrictions(t *testing.T) {
	key := newkey()
	own := enode.NewV4(&key.PublicKey, net.ParseIP("127.0.0.1"), 1234, 1234)
	s := &Server{Config: Config{PrivateKey: key, MaxPeers: 8, BrowserMesh: &BrowserMeshConfig{}, ReservedPeerMode: true, ReservedNodes: []*enode.Node{own}}}
	if s.configureBrowserMesh() == nil {
		t.Fatal("reserved local identity enabled mesh")
	}
	s.ReservedNodes = nil
	s.NetRestrict = new(netutil.Netlist)
	if s.configureBrowserMesh() == nil {
		t.Fatal("mesh bypasses NetRestrict")
	}
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	if _, err := NewBrowserMeshConn(x, BrowserMeshInfo{CircuitID: "bad", RemoteID: randomID(), RelayIDs: []string{"duplicate", "duplicate"}}); err == nil {
		t.Fatal("route loop admitted")
	}
}

func TestBrowserMeshPeerLimitConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		total, mesh, pending int
		want                 int
	}{
		{name: "default", total: 50, want: 40},
		{name: "default follows smaller total", total: 8, want: 8},
		{name: "explicit forty", total: 50, mesh: 40, want: 40},
		{name: "explicit smaller", total: 50, mesh: 4, want: 4},
		{name: "above mesh ceiling", total: 50, mesh: 41},
		{name: "above total ceiling", total: 39, mesh: 40},
		{name: "zero total", total: 0},
		{name: "negative mesh", total: 50, mesh: -1},
		{name: "pending ceiling unchanged", total: 50, mesh: 40, pending: 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Config: Config{PrivateKey: newkey(), MaxPeers: tc.total,
				BrowserMesh: &BrowserMeshConfig{MaxPeers: tc.mesh, MaxPending: tc.pending}}}
			err := s.configureBrowserMesh()
			if tc.want == 0 {
				if err == nil {
					t.Fatal("invalid peer limit accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.BrowserMesh.MaxPeers != tc.want || s.BrowserMesh.MaxPending != 4 || cap(s.meshPending) != 4 {
				t.Fatalf("unexpected peer/pending limits: %+v", s.BrowserMesh)
			}
			if s.BrowserMesh.MaxFrameBytes != 4<<20 || s.BrowserMesh.BytesPerSecond != 16<<10 {
				t.Fatalf("peer increase changed frame or throughput limits: %+v", s.BrowserMesh)
			}
		})
	}
}

func TestBrowserMeshPeerLimitSharesOrdinaryBudgets(t *testing.T) {
	remote := enode.NewV4(&newkey().PublicKey, net.ParseIP("127.0.0.1"), 1234, 1234)
	for _, tc := range []struct {
		name                  string
		total, mesh, ordinary int
		inbound               int
		flags                 connFlag
		want                  error
	}{
		{name: "fortieth mesh fits", total: 50, mesh: 39, ordinary: 10, flags: dynDialedConn},
		{name: "forty first mesh refused", total: 50, mesh: 40, flags: dynDialedConn, want: DiscTooManyPeers},
		{name: "ordinary peers fill total", total: 50, mesh: 39, ordinary: 11, flags: dynDialedConn | trustedConn, want: DiscTooManyPeers},
		{name: "smaller total filled", total: 12, mesh: 11, ordinary: 1, flags: dynDialedConn | trustedConn, want: DiscTooManyPeers},
		{name: "last inbound slot fits", total: 50, mesh: 33, inbound: 33, flags: inboundConn},
		{name: "inbound cap still applies", total: 50, mesh: 34, inbound: 34, flags: inboundConn | trustedConn, want: DiscTooManyPeers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Config: Config{PrivateKey: newkey(), MaxPeers: tc.total, BrowserMesh: &BrowserMeshConfig{}}}
			if err := s.configureBrowserMesh(); err != nil {
				t.Fatal(err)
			}
			peers := make(map[enode.ID]*Peer)
			for i := 0; i < tc.mesh+tc.ordinary; i++ {
				p := &Peer{rw: &conn{}}
				if i < tc.mesh {
					// Admission reads only the route address; no live stream is needed.
					p.rw.fd = &browserMeshConn{}
				}
				peers[randomID()] = p
			}
			candidate := &conn{node: remote, flags: tc.flags,
				fd: &browserMeshConn{info: BrowserMeshInfo{RemoteID: remote.ID()}}}
			if err := s.checkBrowserMeshPeer(peers, tc.inbound, candidate); !errors.Is(err, tc.want) {
				t.Fatalf("peer admission = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBrowserMeshFrameCapAndDeadlineAreRouteSpecific(t *testing.T) {
	// Fresh paired frame state, as in existing RLPx frame tests. The send side
	// can represent an ordinary native peer with the larger native frame cap.
	for _, snappy := range []bool{false, true} {
		t.Run(map[bool]string{false: "wire", true: "decoded"}[snappy], func(t *testing.T) {
			var wire bytes.Buffer
			writer := newRLPXFrameRW(&wire, meshFrameSecrets())
			reader := newRLPXFrameRW(&wire, meshFrameSecrets())
			writer.snappy, reader.snappy = snappy, snappy
			reader.frameLimit = 1024
			payload := bytes.Repeat([]byte{7}, 4096)
			if err := writer.WriteMsg(Msg{Code: 0, Size: uint32(len(payload)), Payload: bytes.NewReader(payload)}); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadMsg(); !errors.Is(err, ErrBrowserMeshFrameLimit) {
				t.Fatalf("mesh frame cap not enforced before payload/decompression: %v", err)
			}
		})
	}
	for _, snappy := range []bool{false, true} {
		var output bytes.Buffer
		w := newRLPXFrameRW(&output, meshFrameSecrets())
		w.frameLimit, w.snappy = 1024, snappy
		if err := w.WriteMsg(Msg{Code: 0, Size: 1, Payload: io.LimitReader(&infiniteMeshReader{}, 4096)}); !errors.Is(err, ErrBrowserMeshFrameLimit) || output.Len() != 0 {
			t.Fatal("misdeclared payload bypassed outbound cap")
		}
	}
	if meshFrameTimeout(4<<20, frameWriteTimeout, nil) != frameTransferTimeout(4<<20, frameWriteTimeout) {
		t.Fatal("ordinary TCP deadline changed")
	}
	if got := meshFrameTimeout(4<<20, frameWriteTimeout, &BrowserMeshConfig{BytesPerSecond: 16 << 10}); got != 261*time.Second {
		t.Fatalf("mesh deadline ignores configured throughput: %v", got)
	}
	d := &dialScheduler{dialConfig: dialConfig{clock: new(mclock.Simulated)}}
	d.dialConfig = d.dialConfig.withDefaults()
	id := randomID()
	d.history.add(string(id.Bytes()), d.clock.Now().Add(dialHistoryExpiration))
	d.meshRetryHistory(id)
	if delay := time.Duration(d.history.nextExpiry() - d.clock.Now()); delay < time.Second || delay >= 3*time.Second {
		t.Fatalf("mesh reconnect was not bounded: %v", delay)
	}
}

type infiniteMeshReader struct{}

func meshFrameSecrets() secrets {
	return secrets{AES: zero16, MAC: zero16, IngressMAC: sha3.NewLegacyKeccak256(), EgressMAC: sha3.NewLegacyKeccak256()}
}

func (*infiniteMeshReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 1
	}
	return len(b), nil
}

type meshBlockedPongWriter struct {
	transport
	started chan struct{}
	release chan struct{}
	writes  atomic.Int32
}

func (w *meshBlockedPongWriter) WriteMsg(Msg) error {
	if w.writes.Add(1) == 1 {
		close(w.started)
	}
	<-w.release
	return nil
}

func TestBrowserMeshPingFloodUsesOneBoundedPongWorker(t *testing.T) {
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	id := randomID()
	fd, _ := NewBrowserMeshConn(x, BrowserMeshInfo{CircuitID: "pong-test", RemoteID: id, RelayIDs: []string{"browser"}})
	w := &meshBlockedPongWriter{started: make(chan struct{}), release: make(chan struct{})}
	p := newPeer(log.Root(), &conn{fd: fd, node: newNode(id, ""), transport: w}, nil)
	p.wg.Add(1)
	go p.pingLoop()
	defer func() { close(p.closed); close(w.release); p.wg.Wait() }()
	ping := func() { p.handle(Msg{Code: pingMsg, Payload: bytes.NewReader(nil)}) }
	ping()
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("pong worker did not start")
	}
	for i := 0; i < 10000; i++ {
		ping()
	}
	if w.writes.Load() != 1 || len(p.meshPong) != 1 || cap(p.meshPong) != 1 {
		t.Fatal("ping flood spawned concurrent writes or grew the pong queue")
	}
}

type meshWriteSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *meshWriteSignalConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}

func TestBrowserMeshCloseInterruptsBlockedFrameWrite(t *testing.T) {
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	c := &meshWriteSignalConn{Conn: x, started: make(chan struct{})}
	tpt := &rlpx{fd: c, mesh: &BrowserMeshConfig{BytesPerSecond: 8 << 10}, rw: newRLPXFrameRW(c, meshFrameSecrets())}
	tpt.rw.frameLimit = 4 << 20
	written := make(chan error, 1)
	go func() { written <- tpt.WriteMsg(Msg{Code: 0, Size: 1, Payload: bytes.NewReader([]byte{1})}) }()
	select {
	case <-c.started:
	case <-time.After(time.Second):
		t.Fatal("frame write did not begin")
	}
	closed := make(chan struct{})
	go func() { tpt.close(DiscQuitting); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("mesh close waited on the slow frame write mutex")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked frame unexpectedly completed")
		}
	case <-time.After(time.Second):
		t.Fatal("mesh close did not cancel the blocked writer")
	}
}
