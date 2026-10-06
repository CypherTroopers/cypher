package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/p2p/enode"
)

var ErrBrowserMeshFrameLimit = errors.New("browser mesh frame exceeds route limit")

// BrowserMeshMaxPeers bounds authenticated native peers using browser circuits.
// These peers also consume the ordinary Server.MaxPeers and inbound budgets.
const BrowserMeshMaxPeers = 40

// BrowserMeshConfig opts in an alternative byte-stream path. Browser relays
// never terminate RLPx; both Common endpoints retain their native identities.
type BrowserMeshConfig struct {
	Dialer               NodeDialer
	Candidates           enode.Iterator
	HasRoute             func(enode.ID) bool
	MaxPeers, MaxPending int
	MaxFrameBytes        uint32
	BytesPerSecond       uint64
}

type BrowserMeshInfo struct {
	CircuitID     string   `json:"circuitId"`
	RemoteID      enode.ID `json:"remoteId"`
	RelayIDs      []string `json:"relayIds"`
	BytesReceived uint64   `json:"bytesReceived"`
	BytesSent     uint64   `json:"bytesSent"`
}

// BrowserMeshAddr cannot be mistaken for an advertised or relay TCP/IP address.
type BrowserMeshAddr struct{ info BrowserMeshInfo }

func (a BrowserMeshAddr) Network() string { return "browser-mesh" }
func (a BrowserMeshAddr) String() string  { return "browser-mesh:" + a.info.CircuitID }

type browserMeshConn struct {
	net.Conn
	info          BrowserMeshInfo
	read, written atomic.Uint64
}

func (c *browserMeshConn) LocalAddr() net.Addr { return BrowserMeshAddr{info: c.info} }
func (c *browserMeshConn) RemoteAddr() net.Addr {
	info := c.info
	info.BytesReceived, info.BytesSent = c.read.Load(), c.written.Load()
	return BrowserMeshAddr{info: info}
}
func (c *browserMeshConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(uint64(n))
	return n, err
}
func (c *browserMeshConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Add(uint64(n))
	return n, err
}

// NewBrowserMeshConn binds owner-verified route metadata to an ordered reliable
// stream. The supplied Conn must implement real deadlines and bounded buffering.
func NewBrowserMeshConn(conn net.Conn, info BrowserMeshInfo) (net.Conn, error) {
	validID := func(s string) bool {
		if len(s) == 0 || len(s) > 128 {
			return false
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
		return true
	}
	if conn == nil || reflect.ValueOf(conn).Kind() == reflect.Pointer && reflect.ValueOf(conn).IsNil() || !validID(info.CircuitID) || info.RemoteID == (enode.ID{}) || len(info.RelayIDs) == 0 || len(info.RelayIDs) > 4 {
		return nil, errors.New("invalid browser mesh route")
	}
	seen := make(map[string]bool)
	for _, id := range info.RelayIDs {
		if !validID(id) || seen[id] {
			return nil, errors.New("invalid browser mesh hop")
		}
		seen[id] = true
	}
	info.RelayIDs = append([]string(nil), info.RelayIDs...)
	info.BytesReceived, info.BytesSent = 0, 0
	return &browserMeshConn{Conn: conn, info: info}, nil
}

func browserMeshInfo(conn net.Conn) *BrowserMeshInfo {
	if conn == nil {
		return nil
	}
	addr, ok := conn.RemoteAddr().(BrowserMeshAddr)
	if !ok {
		return nil
	}
	info := addr.info
	info.RelayIDs = append([]string(nil), info.RelayIDs...)
	return &info
}

func (srv *Server) configureBrowserMesh() error {
	if srv.BrowserMesh == nil {
		return nil
	}
	c := *srv.BrowserMesh
	if c.Candidates != nil && (c.HasRoute == nil || c.Dialer == nil) {
		return errors.New("browser mesh candidates require route-aware dialer")
	}
	if c.MaxPeers == 0 {
		c.MaxPeers = min(BrowserMeshMaxPeers, srv.MaxPeers)
	}
	if c.MaxPending == 0 {
		c.MaxPending = 4
	}
	if c.MaxFrameBytes == 0 {
		c.MaxFrameBytes = 4 << 20
	}
	if c.BytesPerSecond == 0 {
		c.BytesPerSecond = 16 << 10
	}
	if c.MaxPeers < 1 || c.MaxPeers > BrowserMeshMaxPeers || c.MaxPeers > srv.MaxPeers || c.MaxPending < 1 || c.MaxPending > 16 || c.MaxFrameBytes < 1024 || c.MaxFrameBytes > 16<<20 || c.BytesPerSecond < 8<<10 || c.BytesPerSecond > 16<<20 {
		return errors.New("invalid browser mesh resource limits")
	}
	if srv.NetRestrict != nil || srv.isReserved(enode.PubkeyToIDV4(&srv.PrivateKey.PublicKey)) {
		return errors.New("browser mesh cannot bypass IP restrictions or serve a reserved identity")
	}
	srv.BrowserMesh = &c
	limit := srv.MaxPendingPeers
	if limit <= 0 {
		limit = defaultMaxPendingPeers
	}
	srv.inboundHandshakeSlots = make(chan struct{}, limit)
	srv.meshPending = make(chan struct{}, c.MaxPending)
	return nil
}

// SetupBrowserMesh is the bounded inbound entrypoint for owner-verified circuits.
// It consumes the same global inbound handshake budget used by TCP SetupConn.
func (srv *Server) SetupBrowserMesh(fd net.Conn) error {
	if fd == nil {
		return errors.New("nil browser mesh connection")
	}
	srv.lock.Lock()
	if !srv.running || srv.BrowserMesh == nil || browserMeshInfo(fd) == nil {
		srv.lock.Unlock()
		fd.Close()
		return errors.New("browser mesh ingress unavailable")
	}
	select {
	case srv.meshPending <- struct{}{}:
	default:
		srv.lock.Unlock()
		fd.Close()
		return errors.New("browser mesh pending capacity")
	}
	srv.loopWG.Add(1)
	quit := srv.quit
	srv.lock.Unlock()
	defer srv.loopWG.Done()
	defer func() { <-srv.meshPending }()
	done := make(chan struct{})
	go func() {
		select {
		case <-quit:
			fd.Close()
		case <-done:
		}
	}()
	defer close(done)
	return srv.SetupConn(fd, inboundConn, nil)
}

func (srv *Server) checkBrowserMeshPeer(peers map[enode.ID]*Peer, inbound int, c *conn) error {
	info := browserMeshInfo(c.fd)
	if info == nil {
		return nil
	}
	if srv.BrowserMesh == nil || info.RemoteID != c.node.ID() || srv.isReserved(c.node.ID()) {
		return DiscUnexpectedIdentity
	}
	// Trusted flags do not enlarge the mesh or ordinary peer budget.
	if len(peers) >= srv.MaxPeers || c.is(inboundConn) && inbound >= srv.maxInboundConns() {
		return DiscTooManyPeers
	}
	n := 0
	for _, p := range peers {
		if browserMeshInfo(p.rw.fd) != nil {
			n++
		}
	}
	if n >= srv.BrowserMesh.MaxPeers {
		return DiscTooManyPeers
	}
	return nil
}

func meshFrameTimeout(size uint32, floor time.Duration, cfg *BrowserMeshConfig) time.Duration {
	if cfg == nil {
		return frameTransferTimeout(size, floor)
	}
	n := 5*time.Second + time.Duration((uint64(size)*uint64(time.Second))/cfg.BytesPerSecond)
	if n < floor {
		n = floor
	}
	if n > 5*time.Minute {
		n = 5 * time.Minute
	}
	return n
}

func (d *dialScheduler) dialWithMesh(ctx context.Context, dest *enode.Node, task *dialTask) (net.Conn, error) {
	task.meshAttempted = task.meshOnly
	hasRoute := d.mesh != nil && d.mesh.HasRoute != nil && d.mesh.HasRoute(dest.ID())
	operatorEndpoint := task.flags&staticDialedConn != 0 || d.reserved[dest.ID()] != nil
	eligible := d.mesh != nil && d.mesh.Dialer != nil && d.reserved[dest.ID()] == nil && (hasRoute || operatorEndpoint)
	// An advertised identity does not prove ownership of its IP. Mesh-only
	// candidates never turn the node into a caller-controlled TCP probe.
	if task.meshOnly || hasRoute && !operatorEndpoint {
		if !eligible {
			return nil, errors.New("browser mesh route unavailable")
		}
		return d.dialMeshOnly(ctx, dest, task)
	}
	directCtx := ctx
	if eligible {
		var cancel context.CancelFunc
		directCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	fd, err := d.dialer.Dial(directCtx, dest)
	if err == nil {
		return fd, nil
	}
	if fd != nil {
		fd.Close()
	}
	if !eligible || ctx.Err() != nil {
		return nil, err
	}
	return d.dialMeshOnly(ctx, dest, task)
}

func (d *dialScheduler) dialMeshOnly(ctx context.Context, dest *enode.Node, task *dialTask) (fd net.Conn, err error) {
	task.meshAttempted = true
	if d.meshDialSlots != nil {
		select {
		case d.meshDialSlots <- struct{}{}:
			task.meshRelease = func() { <-d.meshDialSlots }
		default:
			return nil, errors.New("browser mesh outbound pending capacity")
		}
	}
	defer func() {
		if err != nil && task.meshRelease != nil {
			task.meshRelease()
			task.meshRelease = nil
		}
	}()
	fd, err = d.mesh.Dialer.Dial(ctx, dest)
	if err != nil {
		if fd != nil {
			fd.Close()
		}
		return nil, err
	}
	if fd == nil {
		return nil, errors.New("browser mesh dialer returned no stream")
	}
	info := browserMeshInfo(fd)
	if info == nil || info.RemoteID != dest.ID() {
		fd.Close()
		return nil, fmt.Errorf("browser mesh route does not bind requested native identity")
	}
	return fd, nil
}
