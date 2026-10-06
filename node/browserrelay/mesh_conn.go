// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"encoding/base64"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cypherium/cypher/p2p/enode"
)

type meshChunk struct {
	seq  uint64
	data []byte
}
type meshPending struct {
	seq   uint64
	bytes int
}

// meshConn is a bounded byte stream. Credit is returned only after the local
// native consumer has Read the complete chunk, never merely on WS receipt.
type meshConn struct {
	mesh                                   *Mesh
	session                                *meshSession
	id                                     string
	remote                                 *enode.Node
	relays                                 []string
	outbound                               bool
	expires                                time.Time
	mu                                     sync.Mutex
	readMu, writeMu                        sync.Mutex
	once                                   sync.Once
	done, ready, readChanged, writeChanged chan struct{}
	isReady                                bool
	readDeadline, writeDeadline            time.Time
	queue                                  chan meshChunk
	unreadChunks, unreadBytes              int
	current                                meshChunk
	offset                                 int
	received, sent                         uint64
	pending                                []meshPending
}

func newMeshConn(m *Mesh, s *meshSession, id string, n *enode.Node, relays []string, outbound bool) *meshConn {
	return &meshConn{mesh: m, session: s, id: id, remote: n, relays: append([]string(nil), relays...), outbound: outbound, expires: time.Now().Add(MeshCircuitTTL), done: make(chan struct{}), ready: make(chan struct{}), readChanged: make(chan struct{}, 1), writeChanged: make(chan struct{}, 1), queue: make(chan meshChunk, MeshReceiveChunks)}
}

// MeshConnectionInfo returns immutable route labels separately from the
// advertised native peer. Only the subsequent RLPx handshake authenticates it.
func MeshConnectionInfo(conn net.Conn) (MeshRouteInfo, bool) {
	c, ok := conn.(*meshConn)
	if !ok {
		return MeshRouteInfo{}, false
	}
	return c.infoCopy(), true
}
func (c *meshConn) infoCopy() MeshRouteInfo {
	return MeshRouteInfo{CircuitID: c.id, RemoteID: c.remote.ID(), RelayIDs: append([]string(nil), c.relays...), SessionID: c.session.id}
}
func (c *meshConn) markReady() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return false
	default:
	}
	if c.isReady {
		return false
	}
	c.isReady = true
	close(c.ready)
	return true
}
func (c *meshConn) receive(seq uint64, data []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return false
	default:
	}
	if !c.isReady || seq != c.received+1 {
		return false
	}
	// current is outside the channel while partially read; count it as an
	// outstanding chunk so actual unread storage stays at eight chunks.
	if c.unreadChunks >= MeshReceiveChunks || c.unreadBytes+len(data) > MeshReceiveChunks*MeshMaxChunkBytes {
		return false
	}
	select {
	case c.queue <- meshChunk{seq, data}:
		c.received = seq
		c.unreadChunks++
		c.unreadBytes += len(data)
		return true
	default:
		return false
	}
}
func (c *meshConn) credit(seq uint64, n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return false
	default:
	}
	if len(c.pending) == 0 || c.pending[0].seq != seq || c.pending[0].bytes != n {
		return false
	}
	copy(c.pending, c.pending[1:])
	c.pending = c.pending[:len(c.pending)-1]
	meshWake(c.writeChanged)
	return true
}
func meshWake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
func meshTimer(deadline time.Time) (<-chan time.Time, func()) {
	if deadline.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(time.Until(deadline))
	return t.C, func() { t.Stop() }
}

func (c *meshConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.Lock()
		select {
		case <-c.done:
			c.mu.Unlock()
			return 0, io.EOF
		default:
		}
		deadline := c.readDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if c.current.data != nil {
			n := copy(p, c.current.data[c.offset:])
			c.offset += n
			var credit *meshPending
			if c.offset == len(c.current.data) {
				credit = &meshPending{seq: c.current.seq, bytes: len(c.current.data)}
				c.unreadChunks--
				c.unreadBytes -= len(c.current.data)
				c.current = meshChunk{}
				c.offset = 0
			}
			c.mu.Unlock()
			if credit != nil {
				if c.session.send(MeshFrame{Type: "credit", CircuitID: c.id, Seq: credit.seq, Bytes: credit.bytes}) != nil {
					c.closeWithReason("credit-failed", true)
				}
			}
			return n, nil
		}
		c.mu.Unlock()
		timer, stop := meshTimer(deadline)
		select {
		case chunk := <-c.queue:
			c.mu.Lock()
			select {
			case <-c.done:
				c.mu.Unlock()
				stop()
				return 0, io.EOF
			default:
			}
			c.current = chunk
			c.offset = 0
			c.mu.Unlock()
		case <-c.done:
			stop()
			return 0, io.EOF
		case <-timer:
			stop()
			return 0, os.ErrDeadlineExceeded
		case <-c.readChanged:
		}
		stop()
	}
}

func (c *meshConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		c.mu.Lock()
		select {
		case <-c.done:
			c.mu.Unlock()
			return written, net.ErrClosed
		default:
		}
		deadline := c.writeDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		if len(c.pending) < MeshReceiveChunks && c.isReady {
			n := len(p)
			if n > MeshMaxChunkBytes {
				n = MeshMaxChunkBytes
			}
			c.sent++
			seq := c.sent
			if seq > MaxSafeInteger {
				c.mu.Unlock()
				c.closeWithReason("sequence-exhausted", true)
				return written, net.ErrClosed
			}
			c.pending = append(c.pending, meshPending{seq, n})
			c.mu.Unlock()
			data := base64.StdEncoding.EncodeToString(p[:n])
			if err := c.session.send(MeshFrame{Type: "data", CircuitID: c.id, Seq: seq, Data: data}); err != nil {
				c.closeWithReason("send-failed", true)
				return written, err
			}
			written += n
			p = p[n:]
			continue
		}
		c.mu.Unlock()
		timer, stop := meshTimer(deadline)
		select {
		case <-c.done:
			stop()
			return written, net.ErrClosed
		case <-timer:
			stop()
			return written, os.ErrDeadlineExceeded
		case <-c.writeChanged:
		}
		stop()
	}
	return written, nil
}

func (c *meshConn) Close() error { c.closeWithReason("closed", true); return nil }
func (c *meshConn) closeWithReason(reason string, notify bool) {
	c.once.Do(func() {
		c.mu.Lock()
		close(c.done)
		c.current = meshChunk{}
		c.offset = 0
		c.pending = nil
		c.unreadChunks, c.unreadBytes = 0, 0
		for {
			select {
			case <-c.queue:
				continue
			default:
			}
			break
		}
		c.mu.Unlock()
		c.mesh.mu.Lock()
		delete(c.mesh.circuits, c.session.id+":"+c.id)
		c.mesh.mu.Unlock()
		if notify {
			_ = c.session.send(MeshFrame{Type: "close", CircuitID: c.id, Reason: reason})
		}
	})
}

type meshAddr string

func (a meshAddr) Network() string       { return "browser-mesh" }
func (a meshAddr) String() string        { return string(a) }
func (c *meshConn) LocalAddr() net.Addr  { return meshAddr("browser-mesh-local") }
func (c *meshConn) RemoteAddr() net.Addr { return meshAddr(c.remote.ID().String()) }
func (c *meshConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	meshWake(c.readChanged)
	meshWake(c.writeChanged)
	return nil
}
func (c *meshConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	meshWake(c.readChanged)
	return nil
}
func (c *meshConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	meshWake(c.writeChanged)
	return nil
}

var _ net.Conn = (*meshConn)(nil)
