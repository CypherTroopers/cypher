package network

import (
	"encoding/binary"
	"testing"
)

func TestPacketHeaderSupportsLargeTxBlockProposal(t *testing.T) {
	want := uint32(256 * 1024 * 1024)
	header := encodePacketHeader(want)
	if len(header) != def_headerSize+def_extendedSize {
		t.Fatalf("extended header size mismatch: got %d, want %d", len(header), def_headerSize+def_extendedSize)
	}

	marker, extended, ok := decodePacketHeader(header[:def_headerSize])
	if !ok || !extended {
		t.Fatal("large packet header was not recognized as extended")
	}
	if marker != def_extendedPacketMarker {
		t.Fatalf("packet marker mismatch: got %d, want %d", marker, def_extendedPacketMarker)
	}
	if got := binary.BigEndian.Uint32(header[def_headerSize:]); got != want {
		t.Fatalf("packet size mismatch: got %d, want %d", got, want)
	}
}

func TestPacketHeaderPreservesLegacyEncoding(t *testing.T) {
	want := uint32(10 * 1024 * 1024)
	header := encodePacketHeader(want)
	if len(header) != def_headerSize {
		t.Fatalf("legacy header size mismatch: got %d, want %d", len(header), def_headerSize)
	}

	got, extended, ok := decodePacketHeader(header)
	if !ok || extended {
		t.Fatal("legacy packet header was not recognized")
	}
	if got != want {
		t.Fatalf("packet size mismatch: got %d, want %d", got, want)
	}
}

func TestPacketHeaderRejectsInvalidInput(t *testing.T) {
	tests := [][]byte{
		nil,
		make([]byte, def_headerSize-1),
		make([]byte, def_headerSize),
	}
	for _, header := range tests {
		if _, _, ok := decodePacketHeader(header); ok {
			t.Fatalf("invalid header accepted: %x", header)
		}
	}
}

func TestGetListenAddressSupportsIPv6HostOnly(t *testing.T) {
	addr := NewAddress(PlainQUIC, "[2001:db8::1]:7102")
	tests := []struct {
		listen string
		want   string
	}{
		{"::", "[::]:7102"},
		{"[::1]", "[::1]:7102"},
		{"[::1]:7200", "[::1]:7200"},
		{"0.0.0.0", "0.0.0.0:7102"},
	}
	for _, test := range tests {
		got, err := getListenAddress(addr, test.listen)
		if err != nil {
			t.Fatalf("getListenAddress(%q) failed: %v", test.listen, err)
		}
		if got != test.want {
			t.Fatalf("getListenAddress(%q) = %q, want %q", test.listen, got, test.want)
		}
	}
}
