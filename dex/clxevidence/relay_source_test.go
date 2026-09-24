package clxevidence_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay/source"
)

func requireSourceNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("CYPHER_DEX_SOURCE_DEVNET") != "1" {
		t.Skip("requires explicit isolated source HTTP devnet")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 1 || ifaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("source HTTP test requires fresh loopback-only namespace")
	}
}

type sourceFixtureHTTP struct {
	f            *clxevidence.RollingFinancialFixture
	mu           sync.Mutex
	mode         string
	head         uint64
	server       *httptest.Server
	witnessCalls int
}

func newSourceHTTP(t *testing.T, last uint64) *sourceFixtureHTTP {
	t.Helper()
	requireSourceNetwork(t)
	f := &sourceFixtureHTTP{f: clxevidence.RollingFinancialFixtureForTest(t, last), head: last}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (s *sourceFixtureHTTP) set(mode string) { s.mu.Lock(); defer s.mu.Unlock(); s.mode = mode }
func (s *sourceFixtureHTTP) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	mode, head := s.mode, s.head
	s.mu.Unlock()
	if mode == "oversize" {
		w.WriteHeader(200)
		io.Copy(w, io.LimitReader(&repeatReader{}, source.MaxResponseBytes+1))
		return
	}
	if mode == "redirect" {
		http.Redirect(w, r, s.server.URL, http.StatusFound)
		return
	}
	if mode == "delay" {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(4 * time.Second):
			return
		}
	}
	var req struct {
		ID     uint64            `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "request", 400)
		return
	}
	response := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
	fail := func() { response["error"] = map[string]interface{}{"code": -32000, "message": "fixture unavailable"} }
	switch req.Method {
	case "eth_blockNumber":
		if mode == "huge_head" {
			head = ^uint64(0)
		}
		response["result"] = hexutil.EncodeUint64(head)
	case "eth_getCLXFinalityWitness":
		s.mu.Lock()
		s.witnessCalls++
		s.mu.Unlock()
		if mode == "witness_unavailable" {
			fail()
			break
		}
		var n hexutil.Uint64
		if len(req.Params) != 1 || json.Unmarshal(req.Params[0], &n) != nil || n == 0 || uint64(n) > uint64(len(s.f.Headers)) {
			fail()
			break
		}
		if mode == "partial" && n > 1 {
			fail()
			break
		}
		h := s.f.Headers[uint64(n)-1]
		if mode == "wrong_signature" {
			h.Header = append([]byte(nil), h.Header...)
			h.Header[len(h.Header)-1] ^= 1
		}
		response["result"] = map[string]interface{}{"header": hexutil.Bytes(h.Header), "proposalRef": hexutil.Bytes(h.ProposalRef)}
	case "eth_getProof":
		var address common.Address
		var keys []common.Hash
		var block struct {
			Hash      common.Hash `json:"blockHash"`
			Canonical bool        `json:"requireCanonical"`
		}
		if len(req.Params) != 3 || json.Unmarshal(req.Params[0], &address) != nil || json.Unmarshal(req.Params[1], &keys) != nil || json.Unmarshal(req.Params[2], &block) != nil || !block.Canonical {
			fail()
			break
		}
		var height uint64
		for i, b := range s.f.Blocks {
			if b.Hash() == block.Hash {
				height = uint64(i + 1)
				break
			}
		}
		st := s.f.Sources[height]
		if st == nil {
			fail()
			break
		}
		proof, err := st.GetProof(address)
		if err != nil {
			fail()
			break
		}
		if mode == "bad_account" && len(proof) > 0 {
			proof[0] = append([]byte(nil), proof[0]...)
			proof[0][0] ^= 1
		}
		encode := func(p [][]byte) []string {
			out := make([]string, len(p))
			for i, b := range p {
				out[i] = hexutil.Encode(b)
			}
			return out
		}
		paths := make([]map[string]interface{}, len(keys))
		for i, key := range keys {
			p, err := st.GetStorageProof(address, key)
			if err != nil {
				fail()
				break
			}
			if mode == "missing_slot" {
				p = nil
			}
			paths[i] = map[string]interface{}{"key": "0xffff", "value": "0xffff", "proof": encode(p)}
		}
		// Every claimed value/label is deliberately false. Only the paths may matter.
		response["result"] = map[string]interface{}{"address": common.Address{19: 250}, "accountProof": encode(proof), "balance": "0xffff", "nonce": "0xffff", "codeHash": common.Hash{9}, "storageHash": common.Hash{9}, "storageProof": paths}
	case "eth_getDEXInboxEntries":
		var hash common.Hash
		var start, count hexutil.Uint64
		if len(req.Params) != 3 || json.Unmarshal(req.Params[0], &hash) != nil || json.Unmarshal(req.Params[1], &start) != nil || json.Unmarshal(req.Params[2], &count) != nil {
			fail()
			break
		}
		var height uint64
		for i, b := range s.f.Blocks {
			if b.Hash() == hash {
				height = uint64(i + 1)
				break
			}
		}
		entries := s.f.Entries[height]
		if uint64(start)+uint64(count) > uint64(len(entries)) {
			fail()
			break
		}
		out := make([]string, 0, count)
		for _, entry := range entries[uint64(start) : uint64(start)+uint64(count)] {
			if mode == "entry_domain" {
				entry.DEXID[0] ^= 1
			}
			raw, _ := entry.Encode()
			out = append(out, hexutil.Encode(raw))
		}
		response["result"] = out
	default:
		fail()
	}
	if mode == "wrong_rpc_id" {
		response["id"] = 2
	}
	json.NewEncoder(w).Encode(response)
}

type repeatReader struct{}

func (*repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}
func openSource(t *testing.T, s *sourceFixtureHTTP, dir string) *source.Client {
	t.Helper()
	c, err := source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: s.f.Config})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRelaySourceHTTPProofsAndRestart(t *testing.T) {
	s := newSourceHTTP(t, 3)
	dir := filepath.Join(t.TempDir(), "source")
	c := openSource(t, s, dir)
	base := c.Current()
	segment, err := c.Advance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if segment.Base != base || segment.Target.Height != 3 || segment.Target.InboxCount != 3 {
		t.Fatal("bad authenticated progress")
	}
	anchor := c.Current()
	entries, err := c.Entries(context.Background(), anchor, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	evidence, target, err := c.BuildRange(context.Background(), anchor, anchor.Height, 0, entries)
	if err != nil || len(evidence.Headers) != 0 || target != anchor || len(evidence.Entries) != 3 {
		t.Fatal("same-anchor range", err)
	}
	account, bundle, err := c.Account(context.Background(), anchor, anchor.Custody, []protocol.Hash{protocol.InboxCountStorageKey()})
	if err != nil || !account.Exists || account.Nonce != 0 || account.Balance.Uint64() != 6 || account.Values[0] != (protocol.Hash{31: 3}) || len(bundle) == 0 {
		t.Fatal("RPC labels became authority", account, err)
	}
	h2, err := c.AnchorAt(context.Background(), 2, protocol.Hash(s.f.Blocks[1].Hash()))
	if err != nil || h2.Height != 2 || h2.InboxCount != 3 {
		t.Fatal("historical anchor", err)
	}
	if _, err = c.AnchorAt(context.Background(), 2, protocol.Hash{1}); !errors.Is(err, source.ErrAuthentication) {
		t.Fatal("wrong requested hash", err)
	}
	owned := c.Segments()
	owned[0].Evidence.Headers[0].Header[0] ^= 1
	if c.Segments()[0].Evidence.Headers[0].Header[0] == owned[0].Evidence.Headers[0].Header[0] {
		t.Fatal("segment aliases retained data")
	}
	if _, err = source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: s.f.Config}); err == nil {
		t.Fatal("concurrent writer accepted")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	c = openSource(t, s, dir)
	if c.Current() != anchor || len(c.Segments()) != 1 {
		t.Fatal("restart lost verified chain")
	}
	if _, err = c.Advance(context.Background()); !errors.Is(err, source.ErrUnavailable) {
		t.Fatal("latest fabricated advancement", err)
	}
}
func TestRelaySourceHTTPFailureBoundaries(t *testing.T) {
	s := newSourceHTTP(t, 3)
	for _, mode := range []string{"wrong_signature", "bad_account", "missing_slot", "wrong_rpc_id", "oversize", "redirect", "witness_unavailable"} {
		t.Run(mode, func(t *testing.T) {
			s.set(mode)
			c := openSource(t, s, filepath.Join(t.TempDir(), "source"))
			base := c.Current()
			if _, err := c.Advance(context.Background()); err == nil || c.Current() != base {
				t.Fatal("bad RPC advanced trusted anchor", err)
			} else if mode == "witness_unavailable" && (!errors.Is(err, source.ErrUnavailable) || !strings.Contains(err.Error(), "height=1") || !strings.Contains(err.Error(), "-32000")) {
				t.Fatal("missing first-witness diagnostic", err)
			}
		})
	}
	s.set("partial")
	c := openSource(t, s, filepath.Join(t.TempDir(), "source"))
	segment, err := c.Advance(context.Background())
	if err != nil || segment.Target.Height != 1 {
		t.Fatal("partial finality should retain verified prefix", err)
	}
	s.set("entry_domain")
	if _, err = c.Entries(context.Background(), c.Current(), 0, 1); !errors.Is(err, source.ErrAuthentication) {
		t.Fatal("foreign entry accepted", err)
	}
	s.set("delay")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err = c.Advance(ctx); !errors.Is(err, source.ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatal("caller deadline ignored", err)
	}
	s.set("huge_head")
	s.mu.Lock()
	before := s.witnessCalls
	s.mu.Unlock()
	c = openSource(t, s, filepath.Join(t.TempDir(), "source"))
	if _, err = c.Advance(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	calls := s.witnessCalls - before
	s.mu.Unlock()
	if calls > source.MaxSegmentHeaders {
		t.Fatal("unbounded head discovery", calls)
	}
}
func TestRelaySourceWALFailClosed(t *testing.T) {
	s := newSourceHTTP(t, 2)
	t.Run("foreign_bootstrap", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "source")
		c := openSource(t, s, dir)
		if _, err := c.Advance(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.Close()
		cfg := s.f.Config
		cfg.Genesis = types.CopyHeader(cfg.Genesis)
		cfg.Genesis.Time++
		if _, err := source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: cfg}); err == nil {
			t.Fatal("foreign bootstrap accepted")
		}
	})
	t.Run("corrupt_and_missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "source")
		c := openSource(t, s, dir)
		c.Close()
		path := filepath.Join(dir, "source-wal.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-2] ^= 1
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: s.f.Config}); err == nil {
			t.Fatal("corrupt WAL accepted")
		}
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err = source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: s.f.Config}); err == nil {
			t.Fatal("missing WAL reset trusted state")
		}
	})
	t.Run("failed_save_poison", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "source")
		c := openSource(t, s, dir)
		path := filepath.Join(dir, "source-wal.json")
		if err := os.Rename(path, path+".saved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		base := c.Current()
		if _, err := c.Advance(context.Background()); err == nil || c.Current() != base {
			t.Fatal("failed persist published advance")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".saved", path); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Advance(context.Background()); err == nil {
			t.Fatal("poisoned client continued")
		}
		c.Close()
		reopen := openSource(t, s, dir)
		if reopen.Current() != base {
			t.Fatal("lost old durable base")
		}
	})
	t.Run("unowned_and_symlink", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: s.f.Config}); err == nil {
			t.Fatal("unowned directory accepted")
		}
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if _, err := source.Open(source.Config{Endpoint: s.server.URL, Dir: link, CLX: s.f.Config}); err == nil {
			t.Fatal("symlink accepted")
		}
	})
}

func TestRelaySourceHeaderBoundAndReverifiedWAL(t *testing.T) {
	s := newSourceHTTP(t, 40)
	dir := filepath.Join(t.TempDir(), "source")
	c := openSource(t, s, dir)
	first, err := c.Advance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Target.Height != source.MaxSegmentHeaders || len(first.Evidence.Headers) != source.MaxSegmentHeaders {
		t.Fatal("did not enforce 32-header segment")
	}
	raw, err := clxevidence.EncodeRollingEvidence(first.Evidence)
	if err != nil || len(raw) > source.MaxSegmentBytes {
		t.Fatal("native segment byte budget", err)
	}
	second, err := c.Advance(context.Background())
	if err != nil || second.Target.Height != 40 {
		t.Fatal("second segment", err)
	}
	expected := c.Current()
	c.Close()
	// Simulate a killed write that left partial bytes beside the authenticated
	// two-segment canonical WAL. Reopen must ignore the candidate and retain40.
	orphan := filepath.Join(dir, "source-wal.pending.tmp")
	if err = os.WriteFile(orphan, []byte(`{"payload":{"segments":[`), 0600); err != nil {
		t.Fatal(err)
	}
	c = openSource(t, s, dir)
	if c.Current() != expected || len(c.Segments()) != 2 {
		t.Fatal("multi-segment restart")
	}
	if _, err = os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatal("partial write orphan retained", err)
	}
	c.Close()
	path := filepath.Join(dir, "source-wal.json")
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A recomputed unkeyed checksum is not an authentication proof.
	var envelope struct {
		Payload  json.RawMessage `json:"payload"`
		Checksum string          `json:"checksum"`
	}
	if err = json.Unmarshal(saved, &envelope); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version   uint16   `json:"version"`
		Bootstrap string   `json:"bootstrap"`
		Segments  [][]byte `json:"segments"`
	}
	if err = json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	evidence, err := clxevidence.DecodeRollingEvidence(payload.Segments[0])
	if err != nil {
		t.Fatal(err)
	}
	evidence.Headers[0].Header[len(evidence.Headers[0].Header)-1] ^= 1
	payload.Segments[0], err = clxevidence.EncodeRollingEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := protocol.Digest("common-dex/relay-source-wal/v1", envelope.Payload)
	envelope.Checksum = fmt.Sprintf("%x", sum[:])
	bad, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := source.Open(source.Config{Endpoint: s.server.URL, Dir: dir, CLX: s.f.Config}); err == nil {
		opened.Close()
		t.Fatal("checksum-correct forged finality accepted on reopen")
	}
	if err = os.WriteFile(path, saved, 0600); err != nil {
		t.Fatal(err)
	}
	c = openSource(t, s, dir)
	if c.Current() != expected {
		t.Fatal("valid durable state failed recovery")
	}
}
