package core

import (
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestPoWResultUDPAddrFromCommitteeNodeSupportsIPv6(t *testing.T) {
	addr, err := powResultUDPAddrFromCommitteeNode(&common.Cnode{Address: "[2001:db8::20]:7102"}, 7103)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "[2001:db8::20]:7103" {
		t.Fatalf("addr = %q, want %q", got, "[2001:db8::20]:7103")
	}
}

func TestPoWResultUDPAddrFromCommitteeNodePreservesIPv4(t *testing.T) {
	addr, err := powResultUDPAddrFromCommitteeNode(&common.Cnode{Address: "192.0.2.20:7102"}, 7103)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.String(); got != "192.0.2.20:7103" {
		t.Fatalf("addr = %q, want %q", got, "192.0.2.20:7103")
	}
}
