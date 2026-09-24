// Package source authenticates ordinary Common HTTP observations from an
// immutable CLX genesis. RPC results do not themselves establish finality.
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

const MaxResponseBytes = 8 * 1024 * 1024
const MaxSegmentHeaders = 32
const MaxSegmentBytes = protocol.MaxNativeCallBytes - protocol.NativeCallHeaderSize - 16

var ErrUnavailable = errors.New("authenticated CLX source data unavailable")
var ErrAuthentication = errors.New("CLX source proof authentication failed")

type Config struct {
	Endpoint, Dir string
	CLX           clxevidence.Config
}
type Segment struct {
	Base, Target clxevidence.Anchor
	Evidence     clxevidence.RollingEvidence
}
type Client struct {
	mu                 sync.Mutex
	endpoint           string
	http               *http.Client
	verifier           *clxevidence.Verifier
	bootstrap, current clxevidence.Anchor
	segments           []Segment
	store              *sourceStore
	closed             bool
	poisoned           error
}

func endpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("numeric loopback HTTP endpoint with explicit port required")
	}
	return u.String(), nil
}
func Open(cfg Config) (*Client, error) {
	address, err := endpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	v, err := clxevidence.New(cfg.CLX)
	if err != nil {
		return nil, err
	}
	base, err := v.BootstrapAnchor()
	if err != nil {
		return nil, err
	}
	store, err := openSourceStore(cfg.Dir)
	if err != nil {
		return nil, err
	}
	c := &Client{endpoint: address, verifier: v, bootstrap: base, current: base, store: store}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second, ResponseHeaderTimeout: 3 * time.Second}
	c.http = &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("source redirects forbidden") }}
	if err = c.restore(); err != nil {
		store.close()
		transport.CloseIdleConnections()
		return nil, err
	}
	return c, nil
}
func (c *Client) ready() error {
	if c.closed {
		return errors.New("CLX source closed")
	}
	if c.poisoned != nil {
		return fmt.Errorf("source durability failed: %w", c.poisoned)
	}
	return nil
}
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.http.CloseIdleConnections()
	return c.store.close()
}
func (c *Client) Current() clxevidence.Anchor { c.mu.Lock(); defer c.mu.Unlock(); return c.current }
func cloneSegment(s Segment) Segment {
	raw, _ := clxevidence.EncodeRollingEvidence(s.Evidence)
	e, _ := clxevidence.DecodeRollingEvidence(raw)
	s.Evidence = e
	return s
}
func (c *Client) Segments() []Segment {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Segment, len(c.segments))
	for i, s := range c.segments {
		out[i] = cloneSegment(s)
	}
	return out
}

func (c *Client) rpc(ctx context.Context, method string, params interface{}, out interface{}) error {
	body, err := json.Marshal(struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      uint64      `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
	}{"2.0", 1, method, params})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(raw) > MaxResponseBytes {
		return errors.New("source HTTP response byte bound")
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrUnavailable, res.StatusCode)
	}
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      uint64          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err = decodeJSON(raw, &response); err != nil {
		return err
	}
	if response.JSONRPC != "2.0" || response.ID != 1 {
		return errors.New("source RPC response identity")
	}
	if response.Error != nil {
		return fmt.Errorf("%w: RPC error %d", ErrUnavailable, response.Error.Code)
	}
	if len(response.Result) == 0 || bytes.Equal(response.Result, []byte("null")) {
		return ErrUnavailable
	}
	return json.Unmarshal(response.Result, out)
}
func (c *Client) witness(ctx context.Context, height uint64) (clxevidence.HeaderWitness, error) {
	var w struct {
		Header      hexutil.Bytes `json:"header"`
		ProposalRef hexutil.Bytes `json:"proposalRef"`
	}
	if height == 0 || height > math.MaxInt64 {
		return clxevidence.HeaderWitness{}, errors.New("explicit source height bound")
	}
	if err := c.rpc(ctx, "eth_getCLXFinalityWitness", []interface{}{hexutil.EncodeUint64(height)}, &w); err != nil {
		return clxevidence.HeaderWitness{}, err
	}
	if len(w.Header) == 0 || len(w.ProposalRef) == 0 || len(w.ProposalRef) > clxevidence.MaxRefBytes || len(w.Header)+len(w.ProposalRef) > clxevidence.MaxHeaderWitnessBytes {
		return clxevidence.HeaderWitness{}, errors.New("source witness byte bound")
	}
	return clxevidence.HeaderWitness{Header: bytes.Clone(w.Header), ProposalRef: bytes.Clone(w.ProposalRef)}, nil
}
func (c *Client) cached(height uint64) (clxevidence.HeaderWitness, bool) {
	for _, s := range c.segments {
		if height > s.Base.Height && height <= s.Target.Height {
			w := s.Evidence.Headers[height-s.Base.Height-1]
			return clxevidence.HeaderWitness{Header: bytes.Clone(w.Header), ProposalRef: bytes.Clone(w.ProposalRef)}, true
		}
	}
	return clxevidence.HeaderWitness{}, false
}
func (c *Client) headers(ctx context.Context, base clxevidence.Anchor, target uint64) ([]clxevidence.HeaderWitness, error) {
	if target < base.Height || target-base.Height > MaxSegmentHeaders {
		return nil, errors.New("source header range bound")
	}
	var out []clxevidence.HeaderWitness
	for height := base.Height + 1; height <= target && height > 0; height++ {
		w, ok := c.cached(height)
		if !ok {
			var err error
			w, err = c.witness(ctx, height)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, w)
	}
	return out, nil
}

type proofResponse struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	StorageProof []struct {
		Proof []hexutil.Bytes `json:"proof"`
	} `json:"storageProof"`
}

func (c *Client) proof(ctx context.Context, hash protocol.Hash, address [20]byte, keys []protocol.Hash) ([][]byte, []clxevidence.StorageProof, error) {
	if hash == (protocol.Hash{}) || len(keys) > clxevidence.MaxAccountStorageSlots {
		return nil, nil, errors.New("source proof request bound")
	}
	encoded := make([]string, len(keys))
	seen := map[protocol.Hash]bool{}
	for i, key := range keys {
		if seen[key] {
			return nil, nil, errors.New("duplicate source slot")
		}
		seen[key] = true
		encoded[i] = common.Hash(key).Hex()
	}
	var response proofResponse
	if err := c.rpc(ctx, "eth_getProof", []interface{}{common.Address(address).Hex(), encoded, map[string]interface{}{"blockHash": common.Hash(hash).Hex(), "requireCanonical": true}}, &response); err != nil {
		return nil, nil, err
	}
	if len(response.AccountProof) > clxevidence.MaxProofNodes || len(response.StorageProof) != len(keys) {
		return nil, nil, errors.New("source proof count")
	}
	account := make([][]byte, len(response.AccountProof))
	for i, p := range response.AccountProof {
		if len(p) == 0 || len(p) > clxevidence.MaxProofNodeBytes {
			return nil, nil, errors.New("source account node bound")
		}
		account[i] = bytes.Clone(p)
	}
	slots := make([]clxevidence.StorageProof, len(keys))
	for i, p := range response.StorageProof {
		if len(p.Proof) > clxevidence.MaxProofNodes {
			return nil, nil, errors.New("source storage path bound")
		}
		slots[i].Key = keys[i]
		for _, node := range p.Proof {
			if len(node) == 0 || len(node) > clxevidence.MaxProofNodeBytes {
				return nil, nil, errors.New("source storage node bound")
			}
			slots[i].Proof = append(slots[i].Proof, bytes.Clone(node))
		}
	}
	return account, slots, nil
}
func (c *Client) rangeWithHeaders(ctx context.Context, base clxevidence.Anchor, start uint64, headers []clxevidence.HeaderWitness, entries []protocol.InboxEntry) (clxevidence.RollingEvidence, clxevidence.Anchor, error) {
	var zero clxevidence.RollingEvidence
	if len(entries) > protocol.MaxDepositsPerCheckpoint {
		return zero, clxevidence.Anchor{}, errors.New("source entry bound")
	}
	keyContext, err := c.keyContext(ctx, base, headers)
	if err != nil {
		return zero, clxevidence.Anchor{}, err
	}
	h, _, _, err := c.verifier.VerifyHeaderContext(base, keyContext, headers)
	if err != nil {
		return zero, clxevidence.Anchor{}, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	hash := base.BlockHash
	if len(headers) > 0 {
		hash = protocol.Hash(h.Hash())
	}
	keys := []protocol.Hash{protocol.InboxCountStorageKey()}
	for _, entry := range entries {
		keys = append(keys, protocol.InboxEntryStorageKey(entry.Index))
	}
	// The public account helper has a 32-slot bound. Inbox ranges retain their
	// existing 128-entry bound by fetching small independent proof batches.
	var account [][]byte
	var paths []clxevidence.StorageProof
	for offset := 0; offset < len(keys); offset += clxevidence.MaxAccountStorageSlots {
		end := offset + clxevidence.MaxAccountStorageSlots
		if end > len(keys) {
			end = len(keys)
		}
		a, p, err := c.proof(ctx, hash, base.Custody, keys[offset:end])
		if err != nil {
			return zero, clxevidence.Anchor{}, err
		}
		if account == nil {
			account = a
		} else if !equalPaths(account, a) {
			return zero, clxevidence.Anchor{}, errors.New("source inconsistent account path")
		}
		paths = append(paths, p...)
	}
	id, err := base.ID()
	if err != nil {
		return zero, clxevidence.Anchor{}, err
	}
	e := clxevidence.RollingEvidence{Base: id, Headers: headers, AccountProof: account, CountProof: paths[0].Proof}
	e.SetKeyContext(keyContext)
	for i, entry := range entries {
		e.Entries = append(e.Entries, clxevidence.EntryProof{Entry: entry, Proof: paths[i+1].Proof})
	}
	_, target, err := c.verifier.VerifyRolling(base, start, e)
	if err != nil {
		return zero, clxevidence.Anchor{}, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return e, target, nil
}
func equalPaths(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
func (c *Client) BuildRange(ctx context.Context, base clxevidence.Anchor, target, start uint64, entries []protocol.InboxEntry) (clxevidence.RollingEvidence, clxevidence.Anchor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(); err != nil {
		return clxevidence.RollingEvidence{}, clxevidence.Anchor{}, err
	}
	headers, err := c.headers(ctx, base, target)
	if err != nil {
		return clxevidence.RollingEvidence{}, clxevidence.Anchor{}, err
	}
	return c.rangeWithHeaders(ctx, base, start, headers, entries)
}
func (c *Client) Advance(ctx context.Context) (Segment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(); err != nil {
		return Segment{}, err
	}
	var head hexutil.Uint64
	if err := c.rpc(ctx, "eth_blockNumber", []interface{}{}, &head); err != nil {
		return Segment{}, err
	}
	if uint64(head) <= c.current.Height {
		return Segment{}, ErrUnavailable
	}
	end := uint64(head)
	if end-c.current.Height > MaxSegmentHeaders {
		end = c.current.Height + MaxSegmentHeaders
	}
	var headers []clxevidence.HeaderWitness
	var unavailable error
	for height := c.current.Height + 1; height <= end && height > 0; height++ {
		w, err := c.witness(ctx, height)
		if err != nil {
			if errors.Is(err, ErrUnavailable) {
				unavailable = fmt.Errorf("%w: witness height=%d: %v", ErrUnavailable, height, err)
				break
			}
			return Segment{}, err
		}
		headers = append(headers, w)
	}
	if len(headers) == 0 && unavailable != nil {
		return Segment{}, unavailable
	}
	for len(headers) > 0 {
		e, target, err := c.rangeWithHeaders(ctx, c.current, 0, headers, nil)
		if err != nil {
			return Segment{}, err
		}
		raw, err := clxevidence.EncodeRollingEvidence(e)
		if err != nil {
			return Segment{}, err
		}
		if len(raw) > MaxSegmentBytes {
			headers = headers[:len(headers)-1]
			continue
		}
		s := Segment{Base: c.current, Target: target, Evidence: e}
		next := append(append([]Segment(nil), c.segments...), s)
		if err = c.save(next); err != nil {
			c.poisoned = err
			return Segment{}, err
		}
		c.current = target
		c.segments = next
		return cloneSegment(s), nil
	}
	return Segment{}, ErrUnavailable
}
func (c *Client) AnchorAt(ctx context.Context, height uint64, hash protocol.Hash) (clxevidence.Anchor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(); err != nil {
		return clxevidence.Anchor{}, err
	}
	if height == 0 {
		if hash != c.bootstrap.BlockHash {
			return clxevidence.Anchor{}, ErrAuthentication
		}
		return c.bootstrap, nil
	}
	if height > c.current.Height {
		return clxevidence.Anchor{}, ErrUnavailable
	}
	base := c.bootstrap
	for _, s := range c.segments {
		if s.Target.Height <= height {
			base = s.Target
		} else {
			break
		}
	}
	headers, err := c.headers(ctx, base, height)
	if err != nil {
		return clxevidence.Anchor{}, err
	}
	_, target, err := c.rangeWithHeaders(ctx, base, 0, headers, nil)
	if err != nil {
		return clxevidence.Anchor{}, err
	}
	if target.BlockHash != hash {
		return clxevidence.Anchor{}, ErrAuthentication
	}
	return target, nil
}

type accountBundle struct {
	Version uint16
	Root    protocol.Hash
	Address [20]byte
	Account [][]byte
	Slots   []clxevidence.StorageProof
}

func (c *Client) Account(ctx context.Context, anchor clxevidence.Anchor, address [20]byte, keys []protocol.Hash) (clxevidence.AccountEvidence, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(); err != nil {
		return clxevidence.AccountEvidence{}, nil, err
	}
	if _, err := c.verifier.VerifyHeaderWitnesses(anchor, nil); err != nil {
		return clxevidence.AccountEvidence{}, nil, err
	}
	account, slots, err := c.proof(ctx, anchor.BlockHash, address, keys)
	if err != nil {
		return clxevidence.AccountEvidence{}, nil, err
	}
	out, err := clxevidence.VerifyAccountStorage(anchor.StateRoot, address, account, slots)
	if err != nil {
		return clxevidence.AccountEvidence{}, nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	raw, err := rlp.EncodeToBytes(accountBundle{1, anchor.StateRoot, address, account, slots})
	if err != nil {
		return clxevidence.AccountEvidence{}, nil, err
	}
	return out, raw, nil
}
func (c *Client) Entries(ctx context.Context, anchor clxevidence.Anchor, start, count uint64) ([]protocol.InboxEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(); err != nil {
		return nil, err
	}
	if count == 0 || count > protocol.MaxDepositsPerCheckpoint || start > protocol.MaxInboxEntries || count > protocol.MaxInboxEntries-start || start+count > anchor.InboxCount {
		return nil, errors.New("source inbox request bounds")
	}
	if _, err := c.verifier.VerifyHeaderWitnesses(anchor, nil); err != nil {
		return nil, err
	}
	var raw []hexutil.Bytes
	if err := c.rpc(ctx, "eth_getDEXInboxEntries", []interface{}{common.Hash(anchor.BlockHash).Hex(), hexutil.EncodeUint64(start), hexutil.EncodeUint64(count)}, &raw); err != nil {
		return nil, err
	}
	if uint64(len(raw)) != count {
		return nil, errors.New("source inbox response count")
	}
	out := make([]protocol.InboxEntry, len(raw))
	for i, b := range raw {
		e, err := protocol.DecodeInboxEntry(b)
		if err != nil {
			return nil, err
		}
		if e.Index != start+uint64(i) || e.ChainID != anchor.ChainID || e.Genesis != anchor.Genesis || e.DEXID != anchor.DEXID || e.Custody != anchor.Custody {
			return nil, ErrAuthentication
		}
		out[i] = e
	}
	return out, nil
}
