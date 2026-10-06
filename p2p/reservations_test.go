package p2p

import (
	"net"
	"testing"
	"time"

	"github.com/cypherium/cypher/common/mclock"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/p2p/enode"
)

func reservationNode(t *testing.T) *enode.Node {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30303, 30303)
}

// Four hundred identities exercise the real admission functions. This is an
// in-process admission experiment, not four hundred running node processes.
func TestReservedAdmission400PublicIdentitiesHardCap(t *testing.T) {
	pins := make([]*enode.Node, 6)
	for i := range pins {
		pins[i] = reservationNode(t)
	}
	srv := &Server{Config: Config{ReservedPeerMode: true, MaxPeers: 22, MaxPublicPeers: 16, ReservedNodes: pins}}
	if err := srv.validateReservations(); err != nil {
		t.Fatal(err)
	}
	peers := make(map[enode.ID]*Peer)
	for i := 0; i < 400; i++ {
		n := reservationNode(t)
		flags := staticDialedConn
		if i%2 == 0 {
			flags |= trustedConn
		}
		c := &conn{node: n, flags: flags}
		err := srv.addPeerChecks(peers, 0, c)
		if i < 16 {
			if err != nil {
				t.Fatalf("public %d: %v", i, err)
			}
			peers[n.ID()] = NewPeer(n.ID(), "public", nil)
		} else if err != DiscTooManyPeers {
			t.Fatalf("identity %d bypassed cap: %v", i, err)
		}
	}
	for _, n := range pins {
		c := &conn{node: n, flags: inboundConn}
		if err := srv.postHandshakeChecks(peers, 16, c); err != nil {
			t.Fatalf("reserved provisional rejected: %v", err)
		}
		if c.is(reservedConn) {
			t.Fatal("early claimed identity was promoted")
		}
		if err := srv.addPeerChecks(peers, 16, c); err != nil {
			t.Fatal(err)
		}
		peers[n.ID()] = NewPeer(n.ID(), "reserved", nil)
	}
	if len(peers) != 22 {
		t.Fatal("wrong hard peer count")
	}
	extra := &conn{node: reservationNode(t), flags: trustedConn | staticDialedConn}
	if err := srv.addPeerChecks(peers, 16, extra); err != DiscTooManyPeers {
		t.Fatal("trusted/static escaped hard cap")
	}
	delete(peers, pins[0].ID())
	if err := srv.addPeerChecks(peers, 16, &conn{node: pins[0], flags: inboundConn}); err != nil {
		t.Fatal("reserved reconnect starved", err)
	}
}

func TestReservedDialReconnectWithPublicPoolFull(t *testing.T) {
	pin := newNode(uintID(0x90), "127.0.0.1:30303")
	public := newNode(uintID(0x91), "127.0.0.1:30304")
	runDialTest(t, dialConfig{maxDialPeers: 1, maxActiveDials: 1, reserved: map[enode.ID]*enode.Node{pin.ID(): pin}}, []dialTestRound{
		{peersAdded: []*conn{{node: public, flags: dynDialedConn}}, wantNewDials: []*enode.Node{pin}},
		{succeeded: []enode.ID{pin.ID()}},
		{peersRemoved: []enode.ID{pin.ID()}, update: func(d *dialScheduler) { d.clock.(*mclock.Simulated).Run(dialHistoryExpiration + time.Second) }, wantNewDials: []*enode.Node{pin}},
	})
}

func TestReservedConfigValidation(t *testing.T) {
	n := reservationNode(t)
	for _, c := range []Config{
		{ReservedNodes: []*enode.Node{n}},
		{ReservedPeerMode: true, MaxPeers: 1, ReservedNodes: []*enode.Node{n, n}},
		{ReservedPeerMode: true, MaxPeers: 4, ReservedNodes: []*enode.Node{n}, MaxPublicPeers: 4},
		{ReservedPeerMode: true, MaxPeers: 4, ReservedNodes: []*enode.Node{nil}},
		{ReservedPeerMode: true, MaxPeers: 200, ReservedNodes: make([]*enode.Node, 101)},
	} {
		if (&Server{Config: c}).validateReservations() == nil {
			t.Fatalf("invalid reservation config accepted: %+v", c)
		}
	}
}

func TestReservedNoDialSuppressesPinnedDialLane(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Config: Config{PrivateKey: key, NoDiscovery: true, NoDial: true, ListenAddr: "127.0.0.1:0", MaxPeers: 2, ReservedPeerMode: true, ReservedNodes: []*enode.Node{reservationNode(t)}}}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	if len(srv.dialsched.reserved) != 0 || srv.maxDialedConns() != 0 {
		t.Fatal("NoDial allowed reserved egress")
	}
}
