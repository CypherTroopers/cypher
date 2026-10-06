package network

import "testing"

func TestAddressSupportsBracketedIPv6(t *testing.T) {
	addr := NewAddress(PlainQUIC, "[2001:db8::1]:7102")
	if !addr.Valid() {
		t.Fatal("IPv6 address should be valid")
	}
	if got := addr.Host(); got != "2001:db8::1" {
		t.Fatalf("host = %q, want %q", got, "2001:db8::1")
	}
	if got := addr.Port(); got != "7102" {
		t.Fatalf("port = %q, want %q", got, "7102")
	}
	if got := addr.NetworkAddressResolved(); got != "[2001:db8::1]:7102" {
		t.Fatalf("resolved address = %q, want %q", got, "[2001:db8::1]:7102")
	}
}

func TestAddressRejectsUnbracketedIPv6HostPort(t *testing.T) {
	addr := NewAddress(PlainQUIC, "2001:db8::1:7102")
	if addr.Valid() {
		t.Fatal("ambiguous unbracketed IPv6 host:port should be invalid")
	}
}
