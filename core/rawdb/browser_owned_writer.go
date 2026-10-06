// SPDX-License-Identifier: LGPL-3.0-or-later
package rawdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/cypherium/cypher/ethdb"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BrowserOwnedBackend borrows only an optional strict HOT KV capability. It
// exposes the structural writer API, without importing browser module types.
// Creation and capability queries perform no DB IO. The first writer call
// opens one owned immutable hot view; the provider must durably reserve that
// synchronous call before entry. All calls share that view and lifetime caps.
// Driver storage-work and this adapter's structural-work are separate bounded
// monotonic counters. This is neither QC authentication nor a stock DB adapter.
type BrowserOwnedBackend struct {
	db             interface{}
	limits         ethdb.BrowserSnapshotLimits
	mu             sync.Mutex
	lease          *BrowserStoreLease
	closed, active bool
	cancel         context.CancelFunc
	work           int64
	jobCtx         context.Context
	jobCancel      context.CancelFunc
}

func NewBrowserOwnedBackend(db interface{}, limits ethdb.BrowserSnapshotLimits) (*BrowserOwnedBackend, error) {
	if e := limits.Validate(); e != nil {
		return nil, e
	}
	if _, e := browserCapability(db); e != nil {
		return nil, e
	}
	jobCtx, jobCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	return &BrowserOwnedBackend{db: db, limits: limits, jobCtx: jobCtx, jobCancel: jobCancel}, nil
}
func (b *BrowserOwnedBackend) BrowserOwnedSnapshotCapabilityVersion() uint32 {
	if b == nil {
		return 0
	}
	return ethdb.BrowserSnapshotCapabilityV1
}
func (b *BrowserOwnedBackend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	b.closed = true
	b.jobCancel()
	if b.cancel != nil {
		b.cancel()
	}
	s := b.lease
	active := b.active
	b.mu.Unlock()
	if s != nil && !active {
		return s.Close()
	}
	return nil
}
func (b *BrowserOwnedBackend) run(ctx context.Context, w io.Writer, max int64, fn func(context.Context, *BrowserStoreLease) error) (err error) {
	if b == nil || browserNil(ctx) || browserNil(w) {
		return ethdb.ErrBrowserSnapshotMalformed
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if max <= 0 || max > b.limits.MaxValueBytes {
		return ethdb.ErrBrowserSnapshotLimit
	}
	b.mu.Lock()
	alreadyClosed := b.closed
	b.mu.Unlock()
	if alreadyClosed {
		return ethdb.ErrBrowserSnapshotClosed
	}
	if e := b.jobCtx.Err(); e != nil {
		return e
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	// This bounded callback only cancels the active per-read context. It never
	// starts a backend read or releases an in-flight view. Lease lifetime is
	// independent of the first primitive/ON request context.
	stopJob := context.AfterFunc(b.jobCtx, cancel)
	defer stopJob()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ethdb.ErrBrowserSnapshotClosed
	}
	if b.active {
		b.mu.Unlock()
		return ethdb.ErrBrowserSnapshotLimit
	}
	b.active = true
	b.cancel = cancel
	s := b.lease
	b.mu.Unlock()
	completed := false
	held := false
	defer func() {
		if held {
			s.unretain()
		}
	}()
	defer func() {
		b.mu.Lock()
		b.active = false
		b.cancel = nil
		closed := b.closed || !completed
		if closed {
			b.closed = true
			b.jobCancel()
		}
		owned := b.lease
		b.mu.Unlock()
		if closed && owned != nil {
			_ = owned.Close()
		}
	}()
	if s == nil {
		var e error
		s, e = OpenBrowserStoreLease(call, b.db, b.limits)
		if e != nil {
			return e
		}
		b.mu.Lock()
		closed := b.closed
		b.lease = s
		b.mu.Unlock()
		if closed {
			_ = s.Close()
			return ethdb.ErrBrowserSnapshotClosed
		}
	}
	if e := call.Err(); e != nil {
		return e
	}
	if e := s.retain(); e != nil {
		return e
	}
	held = true
	if e := fn(call, s); e != nil {
		return e
	}
	if e := call.Err(); e != nil {
		return e
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return ethdb.ErrBrowserSnapshotClosed
	}
	completed = true
	return nil
}
func (b *BrowserOwnedBackend) step(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ethdb.ErrBrowserSnapshotClosed
	}
	if b.work >= b.limits.MaxWork {
		return ethdb.ErrBrowserSnapshotLimit
	}
	b.work++
	return nil
}
func browserWrite(ctx context.Context, w io.Writer, raw []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	n, e := w.Write(raw)
	if ce := ctx.Err(); ce != nil {
		return ce
	}
	if e != nil {
		return e
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}
func (b *BrowserOwnedBackend) WriteBrowserChainID(ctx context.Context, w io.Writer, max int64) error {
	if max < 8 {
		return ethdb.ErrBrowserSnapshotLimit
	}
	return b.run(ctx, w, max, func(call context.Context, s *BrowserStoreLease) error {
		raw, e := s.ReadChainConfigRaw(call)
		if e != nil {
			return e
		}
		id, e := b.chainID(call, raw.JSON)
		if e != nil {
			return e
		}
		var out [8]byte
		binary.BigEndian.PutUint64(out[:], id)
		return browserWrite(call, w, out[:])
	})
}
func (b *BrowserOwnedBackend) WriteBrowserHeaderRLP(ctx context.Context, wanted uint64, w io.Writer, max int64) error {
	return b.run(ctx, w, max, func(call context.Context, s *BrowserStoreLease) error {
		raw, e := s.ReadHeaderRawBounded(call, wanted, max)
		if e != nil {
			return e
		}
		if int64(len(raw.HeaderRLP)) > max {
			return ethdb.ErrBrowserSnapshotLimit
		}
		root, e := b.item(call, raw.HeaderRLP, 0, 0)
		if e != nil {
			return e
		}
		if !root.list || root.end != len(raw.HeaderRLP) {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		return browserWrite(call, w, raw.HeaderRLP)
	})
}
func (b *BrowserOwnedBackend) WriteBrowserBlockRLP(ctx context.Context, wanted uint64, w io.Writer, max int64) error {
	return b.run(ctx, w, max, func(call context.Context, s *BrowserStoreLease) error {
		raw, e := s.ReadBlockRawBounded(call, wanted, max)
		if e != nil {
			return e
		}
		header, e := b.item(call, raw.HeaderRLP, 0, 0)
		if e != nil {
			return e
		}
		if !header.list || header.end != len(raw.HeaderRLP) {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		body, e := b.item(call, raw.BodyRLP, 0, 0)
		if e != nil {
			return e
		}
		if !body.list || body.end != len(raw.BodyRLP) {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		// This revision's Body is tx, sidecars, uncles, batches, refs, rewards.
		// extblock is header plus those six explicit components in that order.
		// Split only raw slices; never DecodeRLP or treat encoded Body as one field.
		var fields [7][]byte
		fields[0] = raw.HeaderRLP
		cursor := body.payload
		for i := 1; i < 7; i++ {
			if cursor >= body.end {
				return ethdb.ErrBrowserSnapshotMalformed
			}
			part, e := browserFrame(raw.BodyRLP, cursor)
			if e != nil || !part.list {
				if e != nil {
					return e
				}
				return ethdb.ErrBrowserSnapshotMalformed
			}
			fields[i] = raw.BodyRLP[cursor:part.end]
			cursor = part.end
		}
		if cursor != body.end {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		payload := uint64(0)
		for _, f := range fields {
			payload += uint64(len(f))
		}
		prefix := browserListPrefix(payload)
		if uint64(len(prefix))+payload > uint64(max) {
			return ethdb.ErrBrowserSnapshotLimit
		}
		if e = browserWrite(call, w, prefix); e != nil {
			return e
		}
		for _, f := range fields {
			if e = browserWrite(call, w, f); e != nil {
				return e
			}
		}
		return nil
	})
}

type browserRLPItem struct {
	payload, end int
	list         bool
}

func browserFrame(raw []byte, start int) (browserRLPItem, error) {
	bad := ethdb.ErrBrowserSnapshotMalformed
	if start < 0 || start >= len(raw) {
		return browserRLPItem{}, bad
	}
	v := raw[start]
	p := start + 1
	n := uint64(0)
	list := false
	switch {
	case v < 0x80:
		return browserRLPItem{start, start + 1, false}, nil
	case v <= 0xb7:
		n = uint64(v - 0x80)
	case v <= 0xbf:
		count := int(v - 0xb7)
		if count > 8 || count > len(raw)-p || raw[p] == 0 {
			return browserRLPItem{}, bad
		}
		for i := 0; i < count; i++ {
			n = n<<8 | uint64(raw[p+i])
		}
		p += count
		if n <= 55 {
			return browserRLPItem{}, bad
		}
	case v <= 0xf7:
		list = true
		n = uint64(v - 0xc0)
	default:
		list = true
		count := int(v - 0xf7)
		if count > 8 || count > len(raw)-p || raw[p] == 0 {
			return browserRLPItem{}, bad
		}
		for i := 0; i < count; i++ {
			n = n<<8 | uint64(raw[p+i])
		}
		p += count
		if n <= 55 {
			return browserRLPItem{}, bad
		}
	}
	if n > uint64(len(raw)-p) {
		return browserRLPItem{}, bad
	}
	end := p + int(n)
	if !list && n == 1 && raw[p] < 0x80 {
		return browserRLPItem{}, bad
	}
	return browserRLPItem{p, end, list}, nil
}
func (b *BrowserOwnedBackend) item(ctx context.Context, raw []byte, start, depth int) (browserRLPItem, error) {
	if depth > 32 {
		return browserRLPItem{}, ethdb.ErrBrowserSnapshotLimit
	}
	if e := b.step(ctx); e != nil {
		return browserRLPItem{}, e
	}
	part, e := browserFrame(raw, start)
	if e != nil {
		return browserRLPItem{}, e
	}
	if part.list {
		for p := part.payload; p < part.end; {
			child, e := b.item(ctx, raw, p, depth+1)
			if e != nil {
				return browserRLPItem{}, e
			}
			if child.end > part.end {
				return browserRLPItem{}, ethdb.ErrBrowserSnapshotMalformed
			}
			p = child.end
		}
	}
	return part, nil
}
func browserListPrefix(size uint64) []byte {
	var out [9]byte
	if size <= 55 {
		out[0] = 0xc0 + byte(size)
		return out[:1]
	}
	count := 0
	v := size
	for v > 0 {
		count++
		v >>= 8
	}
	out[0] = 0xf7 + byte(count)
	for i := count; i > 0; i-- {
		out[i] = byte(size)
		size >>= 8
	}
	return out[:count+1]
}

// The 1 MiB already owned storage JSON is lexically preflighted before Token:
// each raw string is <=4KiB before Token. Decoded keys are then capped at
// 256 bytes and object entries at 256, depth<=32,
// nodes/work <= caller's finite cap. String/map bookkeeping is bounded separately
// from driver payload buffers. Duplicate decoded keys at every object are
// rejected; only a canonical unsigned decimal uint64 chainId is representable.
func (b *BrowserOwnedBackend) chainID(ctx context.Context, raw []byte) (uint64, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return 0, ethdb.ErrBrowserSnapshotLimit
	}
	for i := 0; i < len(raw); i++ {
		if i%256 == 0 {
			if e := ctx.Err(); e != nil {
				return 0, e
			}
		}
		if raw[i] != '"' {
			continue
		}
		start := i
		i++
		for ; i < len(raw); i++ {
			if i-start > 4096 {
				return 0, ethdb.ErrBrowserSnapshotLimit
			}
			if i%256 == 0 {
				if e := ctx.Err(); e != nil {
					return 0, e
				}
			}
			if raw[i] == '\\' {
				i++
				continue
			}
			if raw[i] == '"' {
				break
			}
		}
		if i >= len(raw) {
			return 0, ethdb.ErrBrowserSnapshotMalformed
		}
		if i-start > 4096 {
			return 0, ethdb.ErrBrowserSnapshotLimit
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, e := dec.Token()
	if e != nil || tok != json.Delim('{') {
		return 0, ethdb.ErrBrowserSnapshotMalformed
	}
	var id uint64
	found := false
	if e = b.jsonObject(ctx, dec, 0, true, &id, &found); e != nil {
		return 0, e
	}
	if tok, e = dec.Token(); e != io.EOF {
		return 0, ethdb.ErrBrowserSnapshotMalformed
	}
	if !found {
		return 0, ethdb.ErrBrowserSnapshotMissing
	}
	return id, nil
}
func (b *BrowserOwnedBackend) jsonObject(ctx context.Context, d *json.Decoder, depth int, top bool, id *uint64, found *bool) error {
	if depth > 32 {
		return ethdb.ErrBrowserSnapshotLimit
	}
	keys := map[string]struct{}{}
	for d.More() {
		if e := b.step(ctx); e != nil {
			return e
		}
		tok, e := d.Token()
		if e != nil {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		key, ok := tok.(string)
		if !ok {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		if len(key) > 256 || len(keys) >= 256 {
			return ethdb.ErrBrowserSnapshotLimit
		}
		if _, seen := keys[key]; seen {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		keys[key] = struct{}{}
		tok, e = d.Token()
		if e != nil {
			return ethdb.ErrBrowserSnapshotMalformed
		}
		if top && key == "chainId" {
			number, ok := tok.(json.Number)
			if !ok {
				return ethdb.ErrBrowserSnapshotUnsupported
			}
			s := string(number)
			if s == "" || len(s) > 20 || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 || (len(s) > 1 && s[0] == '0') {
				return ethdb.ErrBrowserSnapshotUnsupported
			}
			v, e := strconv.ParseUint(s, 10, 64)
			if e != nil {
				return ethdb.ErrBrowserSnapshotUnsupported
			}
			*id = v
			*found = true
		}
		if e = b.jsonValue(ctx, d, tok, depth+1, id, found); e != nil {
			return e
		}
	}
	tok, e := d.Token()
	if e != nil || tok != json.Delim('}') {
		return ethdb.ErrBrowserSnapshotMalformed
	}
	return nil
}
func (b *BrowserOwnedBackend) jsonValue(ctx context.Context, d *json.Decoder, tok json.Token, depth int, id *uint64, found *bool) error {
	if depth > 32 {
		return ethdb.ErrBrowserSnapshotLimit
	}
	if e := b.step(ctx); e != nil {
		return e
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			return b.jsonObject(ctx, d, depth, false, id, found)
		case '[':
			for d.More() {
				v, e := d.Token()
				if e != nil {
					return ethdb.ErrBrowserSnapshotMalformed
				}
				if e = b.jsonValue(ctx, d, v, depth+1, id, found); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ethdb.ErrBrowserSnapshotMalformed
			}
			return nil
		default:
			return ethdb.ErrBrowserSnapshotMalformed
		}
	}
	return nil
}
