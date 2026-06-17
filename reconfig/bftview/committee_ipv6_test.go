package bftview

import (
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestCommitteeOutMatchesIPv6Endpoint(t *testing.T) {
	node := &common.Cnode{
		Address:  "[2001:db8::30]:7102",
		CoinBase: "0xvalidator",
	}
	if !committeeOutMatches(node, "[2001:db8::30]:7102") {
		t.Fatal("IPv6 endpoint should match node address")
	}
	if !committeeOutMatches(node, "0xvalidator") {
		t.Fatal("coinbase should still match node")
	}
	if committeeOutMatches(node, "[2001:db8::31]:7102") {
		t.Fatal("different IPv6 endpoint should not match")
	}
}
