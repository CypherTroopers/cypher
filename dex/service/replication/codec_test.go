package replication

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

func TestReplicationIndependentGoldenAndBounds(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/process.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]string
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	vote, err := encodeVote([]byte("reference-fixture"), []byte("rlp-structural-only"))
	if err != nil {
		t.Fatal(err)
	}
	record, _ := encode(recordKind, []byte(`{"fixture":1}`))
	for name, raw := range map[string][]byte{"vote": vote, "record": record, "request": request(0x0102030405060708)} {
		expected, e := hex.DecodeString(vector[name])
		if e != nil || !bytes.Equal(expected, raw) {
			t.Fatal("independent golden", name, e)
		}
	}
	for i := 0; i < len(vote); i++ {
		_, body, e := decode(vote[:i])
		if e == nil {
			_, _, e = decodeVote(body)
		}
		if e == nil {
			t.Fatalf("truncated message %d", i)
		}
	}
	if _, _, err = decodeVote(append(vote[9:], 0)); err == nil {
		t.Fatal("trailing vote bytes")
	}
	if _, err = encode(recordKind, make([]byte, transport.MaxPayload)); err == nil {
		t.Fatal("unbounded record")
	}
}
func TestReplicationRejectsIdentityAndBoundsBeforeCrypto(t *testing.T) {
	// Deliberately no registry or collector: these invalid inputs must fail before
	// cryptographic verification or collector access, never succeed via a stub.
	c := &Controller{app: &consensus.Application{}, send: func(string, uint8, []byte) error { return nil }, config: Config{Peers: make([]transport.Peer, 7)}}
	c.config.Peers[0] = transport.Peer{ID: "registered", BLSPublic: hex.EncodeToString(bytes.Repeat([]byte{1}, 64))}
	wire, err := rlp.EncodeToBytes(&hotstuff.HotstuffMessage{Code: hotstuff.MsgVotePrepare, Id: "other", PubKey: bytes.Repeat([]byte{1}, 64)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeVote([]byte("invalid reference"), wire)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Receive(0, raw); err == nil {
		t.Fatal("TLS/vote identity mismatch accepted")
	}
	if err = c.Receive(7, raw); err == nil {
		t.Fatal("unregistered peer accepted")
	}
	broken := append([]byte(header), voteKind, 0xff, 0xff, 0, 0, 0, 1, 0)
	if err = c.Receive(0, broken); err == nil {
		t.Fatal("huge reference accepted")
	}
}

func FuzzReplicationEnvelope(f *testing.F) {
	vote, _ := encodeVote([]byte("reference-fixture"), []byte("rlp-structural-only"))
	f.Add(vote)
	f.Add(request(1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		kind, body, err := decode(raw)
		if err != nil {
			return
		}
		if kind == voteKind {
			ref, vote, err := decodeVote(body)
			if err == nil {
				encoded, e := encodeVote(ref, vote)
				if e != nil || !bytes.Equal(encoded, raw) {
					t.Fatal("noncanonical accepted vote")
				}
			}
		}
	})
}
