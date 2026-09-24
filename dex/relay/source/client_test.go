package source

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
	"os"
	"testing"
)

func TestSourceIndependentCodecGolden(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/source_wal.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Empty  struct{ Payload, Checksum, Envelope string } `json:"empty_wal"`
		Bundle struct{ Encoded string }                     `json:"account_bundle"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(walPayload{Version: 1, Bootstrap: string(bytes.Repeat([]byte("11"), 32)), Segments: [][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	sum := protocol.Digest("common-dex/relay-source-wal/v1", p)
	checksum := hex.EncodeToString(sum[:])
	e, err := json.Marshal(walEnvelope{p, checksum})
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != v.Empty.Payload || checksum != v.Empty.Checksum || string(e) != v.Empty.Envelope {
		t.Fatal("independent WAL golden mismatch")
	}
	var root, key protocol.Hash
	var address [20]byte
	for i := range root {
		root[i] = 0x11
		key[i] = 0x33
	}
	for i := range address {
		address[i] = 0x22
	}
	bundle, err := rlp.EncodeToBytes(accountBundle{1, root, address, [][]byte{{0xc0}}, []clxevidence.StorageProof{{Key: key}}})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bundle) != v.Bundle.Encoded {
		t.Fatal("independent account bundle golden mismatch")
	}
}
func TestSourceEndpointBoundary(t *testing.T) {
	for _, v := range []string{"http://127.0.0.1:8080", "http://127.0.0.2:1/", "http://[::1]:65535"} {
		if _, err := endpoint(v); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range []string{"https://127.0.0.1:2", "http://localhost:2", "http://192.0.2.1:2", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://a:b@127.0.0.1:2", "http://127.0.0.1:2/a", "http://127.0.0.1:2?x=y", "http://127.0.0.1:2#x", "http://127.0.0.1:2/a/.."} {
		if _, err := endpoint(v); err == nil {
			t.Fatal("accepted", v)
		}
	}
}
