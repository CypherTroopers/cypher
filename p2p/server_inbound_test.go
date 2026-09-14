package p2p

import (
	"net"
	"testing"
	"time"

	"github.com/cypherium/cypher/common/mclock"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/p2p/netutil"
)

func TestCheckInboundConnAllowsStaticIPGroup(t *testing.T) {
	clock := new(mclock.Simulated)
	sharedIP := net.ParseIP("192.0.2.10")
	staticNodes := []*enode.Node{
		newNode(uintID(0x01), "192.0.2.10:30301"),
		newNode(uintID(0x02), "192.0.2.10:30302"),
		newNode(uintID(0x03), "192.0.2.10:30303"),
	}
	// A duplicate configuration entry must not enlarge the pre-authentication
	// allowance for this address.
	staticNodes = append(staticNodes, staticNodes[0])
	srv := &Server{Config: Config{StaticNodes: staticNodes, clock: clock}}

	const expectedBurst = 3
	for attempt := 1; attempt <= expectedBurst; attempt++ {
		if err := srv.checkInboundConn(nil, sharedIP); err != nil {
			t.Fatalf("configured static IP attempt %d/%d rejected: %v", attempt, expectedBurst, err)
		}
	}
	if err := srv.checkInboundConn(nil, sharedIP); err == nil {
		t.Fatal("configured static IP accepted beyond its bounded burst")
	}

	clock.Run(inboundThrottleTime + time.Second)
	if err := srv.checkInboundConn(nil, sharedIP); err != nil {
		t.Fatalf("configured static IP remained throttled after expiry: %v", err)
	}
}

func TestCheckInboundConnStillThrottlesUnknownIP(t *testing.T) {
	clock := new(mclock.Simulated)
	srv := &Server{Config: Config{clock: clock}}
	remoteIP := net.ParseIP("192.0.2.20")

	if err := srv.checkInboundConn(nil, remoteIP); err != nil {
		t.Fatalf("first inbound attempt rejected: %v", err)
	}
	if err := srv.checkInboundConn(nil, remoteIP); err == nil {
		t.Fatal("second inbound attempt from unknown IP was not throttled")
	}
}

func TestCheckInboundConnAppliesNetRestrictToStaticIP(t *testing.T) {
	clock := new(mclock.Simulated)
	allowed := new(netutil.Netlist)
	allowed.Add("198.51.100.0/24")
	staticNode := newNode(uintID(0x01), "192.0.2.10:30303")
	srv := &Server{Config: Config{
		StaticNodes: []*enode.Node{staticNode},
		NetRestrict: allowed,
		clock:       clock,
	}}

	if err := srv.checkInboundConn(nil, staticNode.IP()); err == nil {
		t.Fatal("static IP bypassed NetRestrict")
	}
}
