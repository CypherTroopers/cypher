package p2p

import (
	"fmt"

	"github.com/cypherium/cypher/p2p/enode"
)

const maxReservedNodes = 100

func (srv *Server) validateReservations() error {
	if !srv.ReservedPeerMode {
		if len(srv.ReservedNodes) != 0 || srv.MaxPublicPeers != 0 {
			return fmt.Errorf("reserved nodes/public budget require ReservedPeerMode")
		}
		return nil
	}
	if srv.MaxPeers <= 0 || len(srv.ReservedNodes) > maxReservedNodes || len(srv.ReservedNodes) > srv.MaxPeers {
		return fmt.Errorf("invalid reserved peer cardinality or hard MaxPeers")
	}
	if srv.MaxPublicPeers < 0 || srv.MaxPublicPeers > srv.MaxPeers-len(srv.ReservedNodes) {
		return fmt.Errorf("public peer budget consumes reserved slots")
	}
	seen := make(map[enode.ID]bool)
	for _, n := range srv.ReservedNodes {
		if n == nil || n.Pubkey() == nil || n.IP() == nil || n.TCP() == 0 || seen[n.ID()] {
			return fmt.Errorf("reserved nodes must be unique complete pinned enodes")
		}
		seen[n.ID()] = true
	}
	return nil
}

func (srv *Server) publicPeerLimit() int {
	if srv.MaxPublicPeers != 0 {
		return srv.MaxPublicPeers
	}
	return srv.MaxPeers - len(srv.ReservedNodes)
}

func (srv *Server) isReserved(id enode.ID) bool {
	for _, n := range srv.ReservedNodes {
		if n != nil && n.ID() == id {
			return true
		}
	}
	return false
}

// Called at both admission checkpoints. The early identity is provisional:
// no Peer or permanent reservation is created before the encrypted hello.
// Pending inbound handshakes remain bounded by MaxPendingPeers. Independently
// budgeted outbound pinned dials cannot be occupied by public handshakes.
func (srv *Server) reservedPeerChecks(peers map[enode.ID]*Peer, c *conn) error {
	if peers[c.node.ID()] != nil {
		return DiscAlreadyConnected
	}
	if srv.localnode != nil && c.node.ID() == srv.localnode.ID() {
		return DiscSelf
	}
	if len(peers) >= srv.MaxPeers {
		return DiscTooManyPeers
	}
	if srv.isReserved(c.node.ID()) {
		return nil
	}
	public, inbound := 0, 0
	for id, peer := range peers {
		if !srv.isReserved(id) {
			public++
			if peer.Inbound() {
				inbound++
			}
		}
	}
	if public >= srv.publicPeerLimit() || (c.is(inboundConn) && inbound >= srv.publicPeerLimit()-srv.maxDialedConns()) {
		return DiscTooManyPeers
	}
	return nil
}

// Reserved reports an authenticated, operator-pinned RLPx identity, not BLS
// consensus membership. Only Server's final admission checkpoint sets it.
func (p *Peer) Reserved() bool { return p.rw.is(reservedConn) }
