package clxevidence_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
)

func renewalHTTP(t *testing.T, f *clxevidence.RollingRenewalFixture) *sourceFixtureHTTP {
	t.Helper()
	requireSourceNetwork(t)
	s := &sourceFixtureHTTP{f: f.RollingFinancialFixture, head: 3}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(raw) > 65536 {
			http.Error(w, "request", 400)
			return
		}
		var req struct {
			ID     uint64
			Method string
			Params []json.RawMessage
		}
		if json.Unmarshal(raw, &req) != nil {
			http.Error(w, "request", 400)
			return
		}
		if req.Method != "eth_getKeyBlockByHash" {
			r.Body = io.NopCloser(bytes.NewReader(raw))
			s.serve(w, r)
			return
		}
		var hash common.Hash
		if len(req.Params) != 1 || json.Unmarshal(req.Params[0], &hash) != nil {
			http.Error(w, "hash", 400)
			return
		}
		h := f.KeyHeaders[protocol.Hash(hash)]
		if h == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "error": map[string]interface{}{"code": -32000}})
			return
		}
		s.mu.Lock()
		mode := s.mode
		s.mu.Unlock()
		number := h.Number.Uint64()
		if mode == "bad_key" {
			number++
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": map[string]interface{}{"keyBlockNumber": number, "difficulty": (*hexutil.Big)(h.Difficulty), "parentHash": h.ParentHash, "nonce": h.Nonce, "mixDigest": h.MixDigest, "timestamp": h.Time, "committeeHash": h.CommitteeHash, "blockType": h.BlockType, "TxBlockNumber": h.T_Number, "hash": common.Hash{250}}})
	}))
	t.Cleanup(s.server.Close)
	return s
}
func TestKeyRenewalSourceHTTPPermutationColdResume(t *testing.T) {
	requireSourceNetwork(t)
	f := clxevidence.RollingPermutationFixtureForTest(t, 260, []uint64{3, 130, 255})
	s := renewalHTTP(t, f)
	dir := filepath.Join(t.TempDir(), "source")
	c := openSource(t, s, dir)
	s.set("bad_key")
	before := c.Current()
	if _, err := c.Advance(context.Background()); err == nil || c.Current() != before {
		t.Fatal("RPC key preimage became authority")
	}
	s.set("")
	segment, err := c.Advance(context.Background())
	if err != nil || segment.Target.Height != 3 || segment.Target.ActivationEnd != 4 || len(segment.Evidence.Order) != 7 {
		t.Fatal("carrier", err)
	}
	c.Close()
	c = openSource(t, s, dir)
	if c.Current() != segment.Target {
		t.Fatal("cold activation boundary changed")
	}
	for _, height := range []uint64{4, 36, 68, 100, 130, 131, 163, 195, 227, 255, 256, 260} {
		s.mu.Lock()
		s.head = height
		s.mu.Unlock()
		for c.Current().Height < height {
			if _, err = c.Advance(context.Background()); err != nil {
				t.Fatalf("advance to %d: %v", height, err)
			}
		}
		if height == 255 {
			c.Close()
			c = openSource(t, s, dir)
			if c.Current().ActivationEnd != 256 {
				t.Fatal("second cold boundary")
			}
		}
	}
	target := c.Current()
	entries, err := c.Entries(context.Background(), target, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	same, got, err := c.BuildRange(context.Background(), target, target.Height, 1, entries[1:])
	if err != nil || got != target || len(same.Headers) != 0 {
		t.Fatal("same-anchor credit after renewal", err)
	}
	verified, got, err := f.Verifier.VerifyRolling(target, 1, same)
	if err != nil || got != target || len(verified.Entries()) != 2 {
		t.Fatal("credit proof", err)
	}
	historical, err := c.AnchorAt(context.Background(), 130, protocol.Hash(f.Blocks[129].Hash()))
	if err != nil || historical.ActivationEnd != 131 {
		t.Fatal("historical pending key", err)
	}
	rangeEvidence, after, err := c.BuildRange(context.Background(), historical, 131, 0, nil)
	if err != nil || after.ActivationEnd != 0 || len(rangeEvidence.PreviousOrder) != 7 {
		t.Fatal("historical boundary", err)
	}
	c.Close()
	c = openSource(t, s, dir)
	if c.Current() != target {
		t.Fatal("full cold replay root/key divergence")
	}
}
func TestKeyRenewalSourceLegacyV3PendingWAL(t *testing.T) {
	requireSourceNetwork(t)
	f := clxevidence.RollingRenewalFixtureForTest(t, 5, []uint64{3})
	s := renewalHTTP(t, f)
	dir := filepath.Join(t.TempDir(), "source")
	c := openSource(t, s, dir)
	base := c.Current()
	c.Close()
	evidence := f.Evidence(t, base, 3, 0, clxevidence.KeyContext{})
	evidence.Entries = nil
	encoded, err := clxevidence.EncodeRollingEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := base.ID()
	payload, err := json.Marshal(struct {
		Version   uint16   `json:"version"`
		Bootstrap string   `json:"bootstrap"`
		Segments  [][]byte `json:"segments"`
	}{1, hex.EncodeToString(id[:]), [][]byte{encoded}})
	if err != nil {
		t.Fatal(err)
	}
	sum := protocol.Digest("common-dex/relay-source-wal/v1", payload)
	raw, _ := json.Marshal(struct {
		Payload  json.RawMessage `json:"payload"`
		Checksum string          `json:"checksum"`
	}{payload, hex.EncodeToString(sum[:])})
	if err = os.WriteFile(filepath.Join(dir, "source-wal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	c = openSource(t, s, dir)
	if c.Current().ActivationEnd != 4 {
		t.Fatal("v3 restored boundary")
	}
	s.mu.Lock()
	s.head = 4
	s.mu.Unlock()
	segment, err := c.Advance(context.Background())
	if err != nil || segment.Target.ActivationEnd != 0 {
		t.Fatal("v3 resumed boundary", err)
	}
	if len(segment.Evidence.Order) != 0 || len(segment.Evidence.PreviousKeyHeader) != 0 {
		t.Fatal("silently partially upgraded old codec")
	}
}
