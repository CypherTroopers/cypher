// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/node/lightnode"
	"github.com/cypherium/cypher/rlp"
)

// These are synthetic, structurally valid headers, never live chain evidence.
type exporterFixture struct {
	mu                    sync.Mutex
	network               Network
	key                   *ecdsa.PrivateKey
	clock                 *atomic.Int64
	head                  uint64
	headers               map[uint64][]byte
	failure, closeFailure error
	opens, closes         atomic.Int32
}

type exporterFixtureView struct {
	fixture      *exporterFixture
	network      Network
	head         uint64
	headers      map[uint64][]byte
	closeFailure error
	closed       atomic.Bool
}

func (f *exporterFixture) factory(ctx context.Context) (lightnode.View, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return nil, f.failure
	}
	f.opens.Add(1)
	headers := make(map[uint64][]byte, len(f.headers))
	for h, raw := range f.headers {
		headers[h] = append([]byte(nil), raw...)
	}
	return &exporterFixtureView{fixture: f, network: f.network, head: f.head, headers: headers, closeFailure: f.closeFailure}, nil
}

func (v *exporterFixtureView) Network() lightnode.Network { return v.network }
func (v *exporterFixtureView) LatestHeight(ctx context.Context) (uint64, error) {
	return v.head, ctx.Err()
}
func (v *exporterFixtureView) HeaderRLP(ctx context.Context, height uint64, max int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if max != MaxHeaderBytes || v.closed.Load() {
		return nil, errors.New("fixture invalid read")
	}
	raw, ok := v.headers[height]
	if !ok {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	return append([]byte(nil), raw...), nil
}
func (v *exporterFixtureView) Close() error {
	if v.closed.CompareAndSwap(false, true) {
		v.fixture.closes.Add(1)
	}
	return v.closeFailure
}

func newExporterFixture(t *testing.T, head uint64) (*Exporter, *exporterFixture) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &exporterFixture{network: Network{ChainID: 10101919, GenesisHash: "0x" + strings.Repeat("1", 64)}, key: key,
		clock: &atomic.Int64{}, head: head, headers: make(map[uint64][]byte)}
	f.clock.Store(1800000000000)
	parent := common.HexToHash(f.network.GenesisHash)
	for height := uint64(1); height <= head; height++ {
		h := &types.Header{Number: new(big.Int).SetUint64(height), Difficulty: big.NewInt(1), ParentHash: parent, Extra: []byte("browser exporter fixture")}
		h.SignInfo.Signature = []byte{1, 2, 3}
		raw, err := rlp.EncodeToBytes(h)
		if err != nil {
			t.Fatal(err)
		}
		f.headers[height], parent = raw, h.Hash()
	}
	e, err := New(Config{Factory: f.factory, Network: f.network, SourceID: "fixture-source", KeyID: "fixture-key", SigningKey: key,
		Now: func() time.Time { return time.UnixMilli(f.clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e, f
}

func exporterManifest(t *testing.T, e *Exporter, f *exporterFixture) (Envelope, Manifest) {
	t.Helper()
	envelope, err := e.Head()
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifyManifest(envelope, "fixture-key", &f.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, m
}

func TestExporterPublishesOneCompleteOwnedWindow(t *testing.T) {
	e, f := newExporterFixture(t, 40)
	configuration := e.SourceConfiguration()
	if configuration.Network != f.network || configuration.SourceID != "fixture-source" || configuration.KeyID != "fixture-key" || configuration.MaxHeaders != 32 || configuration.MaxHeaderBytes != 8192 || len(configuration.PublicKey.KeyOps) != 1 || configuration.PublicKey.KeyOps[0] != "verify" {
		t.Fatalf("invalid public configuration: %+v", configuration)
	}
	configuration.PublicKey.KeyOps[0] = "sign"
	if e.SourceConfiguration().PublicKey.KeyOps[0] != "verify" {
		t.Fatal("caller mutated source configuration")
	}
	_, m := exporterManifest(t, e, f)
	if m.HeadHeight != 40 || len(m.Entries) != 32 || m.Entries[0].Height != 9 || m.Sequence != "1" || f.opens.Load() != 1 || f.closes.Load() != 1 {
		t.Fatalf("unexpected complete observation: %+v opens=%d closes=%d", m, f.opens.Load(), f.closes.Load())
	}
	for _, entry := range m.Entries {
		packet, err := e.Header(entry.Digest)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(packet.HeaderRLP)
		if err != nil || !bytes.Equal(raw, f.headers[entry.Height]) || len(raw) != entry.RawBytes || lightnode.HeaderDigest(f.network, entry.Height, raw) != entry.Digest {
			t.Fatal("published bytes differ from immutable source")
		}
	}
	for i := 0; i < 100; i++ {
		_, _ = e.Head()
		_, _ = e.Header(m.Entries[0].Digest)
		_ = e.Status()
	}
	if f.opens.Load() != 1 {
		t.Fatal("readers opened new snapshots")
	}
	if _, err := e.Header(lightnode.HeaderDigest(f.network, 1, f.headers[1])); !errors.Is(err, ErrNotInWindow) {
		t.Fatal("outside-window object served")
	}
}

func TestExporterEmptyHeadAndBootIdentity(t *testing.T) {
	e, f := newExporterFixture(t, 0)
	_, m := exporterManifest(t, e, f)
	if m.Entries == nil || len(m.Entries) != 0 || m.HeadHash != f.network.GenesisHash || m.HeadHeight != 0 {
		t.Fatalf("genesis observation is not explicit: %+v", m)
	}
	other, _ := newExporterFixture(t, 0)
	if e.Status().SourceBootID == other.Status().SourceBootID {
		t.Fatal("source restart reused boot ID")
	}
}

func TestExporterSameBlockHashNewSignInfoAndReorg(t *testing.T) {
	e, f := newExporterFixture(t, 3)
	_, before := exporterManifest(t, e, f)
	old := before.Entries[2]
	f.mu.Lock()
	var header types.Header
	if err := rlp.DecodeBytes(f.headers[3], &header); err != nil {
		t.Fatal(err)
	}
	header.SignInfo.FHSFinalityProof = []byte("changed complete SignInfo")
	raw, _ := rlp.EncodeToBytes(&header)
	f.headers[3] = raw
	f.mu.Unlock()
	f.clock.Add(2000)
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, after := exporterManifest(t, e, f)
	if after.Entries[2].BlockHash != old.BlockHash || after.Entries[2].Digest == old.Digest || after.Sequence != "2" {
		t.Fatal("same-hash SignInfo replacement was not published")
	}
	if _, err := e.Header(old.Digest); !errors.Is(err, ErrNotInWindow) {
		t.Fatal("old full-byte object remains advertised")
	}
	f.mu.Lock()
	header.Extra = []byte("reorg replacement")
	raw, _ = rlp.EncodeToBytes(&header)
	f.headers[3] = raw
	f.mu.Unlock()
	f.clock.Add(2000)
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, reorg := exporterManifest(t, e, f)
	if reorg.HeadHash == after.HeadHash || reorg.Sequence != "3" {
		t.Fatal("reorg observation was not updated")
	}
}

func TestExporterFailedCycleNeverExtendsFreshness(t *testing.T) {
	for _, test := range []struct {
		name, code string
		mutate     func(*exporterFixture)
	}{
		{"factory", "unsupported_source", func(f *exporterFixture) { f.failure = ethdb.ErrBrowserSnapshotUnsupported }},
		{"budget", "source_limit", func(f *exporterFixture) { f.failure = ethdb.ErrBrowserSnapshotLimit }},
		{"missing", "source_unavailable", func(f *exporterFixture) { delete(f.headers, 2) }},
		{"network", "network_mismatch", func(f *exporterFixture) { f.network.ChainID++ }},
		{"oversize", "unsupported_header_size", func(f *exporterFixture) { f.headers[2] = make([]byte, MaxHeaderBytes+1) }},
		{"malformed", "invalid_header", func(f *exporterFixture) { f.headers[2] = []byte{0xff} }},
		{"height", "invalid_header", func(f *exporterFixture) { f.headers[2] = f.headers[1] }},
		{"close", "source_close_failed", func(f *exporterFixture) { f.closeFailure = errors.New("private path must not be exposed") }},
		{"parent", "source_inconsistent", func(f *exporterFixture) {
			var h types.Header
			_ = rlp.DecodeBytes(f.headers[2], &h)
			h.ParentHash = common.HexToHash("0xabc")
			f.headers[2], _ = rlp.EncodeToBytes(&h)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, f := newExporterFixture(t, 3)
			before, bm := exporterManifest(t, e, f)
			f.mu.Lock()
			test.mutate(f)
			f.mu.Unlock()
			f.clock.Add(2000)
			if err := e.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("failed source result=%v", err)
			}
			after, err := e.Head()
			if err != nil || after != before {
				t.Fatal("failed cycle replaced the existing signed observation")
			}
			s := e.Status()
			if s.Healthy || s.State != "degraded" || s.ErrorCode != test.code || s.Sequence != bm.Sequence || s.ExpiresAt != bm.ExpiresAt || f.opens.Load() != f.closes.Load() {
				t.Fatalf("failure state or lease leak: %+v opens=%d closes=%d", s, f.opens.Load(), f.closes.Load())
			}
			f.clock.Store(bm.ExpiresAt)
			if _, err := e.Head(); !errors.Is(err, ErrUnavailable) {
				t.Fatal("expired manifest served after source failure")
			}
			if _, err := e.Header(bm.Entries[0].Digest); !errors.Is(err, ErrUnavailable) {
				t.Fatal("expired header served")
			}
		})
	}
}

func TestExporterClockRollbackSequenceAndKeyOwnership(t *testing.T) {
	e, f := newExporterFixture(t, 2)
	_, before := exporterManifest(t, e, f)
	f.clock.Add(-1)
	if err := e.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) || e.Status().ErrorCode != "clock_regression" || f.opens.Load() != 1 {
		t.Fatal("rollback acquired a view or moved observation backwards")
	}
	if _, err := e.Head(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("future-dated cached observation served after clock rollback")
	}
	f.clock.Store(before.ObservedAt + 2000)
	// Keep the original public key and mutate the caller-owned scalar only.
	f.key.D.SetInt64(1)
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatal("caller key mutation affected exporter", err)
	}
	_, after := exporterManifest(t, e, f)
	if after.Sequence != "2" || after.ObservedAt <= before.ObservedAt {
		t.Fatal("failed observation consumed sequence or advanced time")
	}
}

type exporterBlockingView struct {
	lightnode.View
	entered chan struct{}
	release chan struct{}
}

func (v *exporterBlockingView) LatestHeight(ctx context.Context) (uint64, error) {
	close(v.entered)
	<-ctx.Done()
	if v.release != nil {
		<-v.release
	}
	return 0, ctx.Err()
}

func TestExporterStopCancelsJoinsAndForbidsLatePublication(t *testing.T) {
	e, f := newExporterFixture(t, 2)
	entered, release := make(chan struct{}), make(chan struct{})
	e.config.Factory = func(ctx context.Context) (lightnode.View, error) {
		v, err := f.factory(ctx)
		return &exporterBlockingView{View: v, entered: entered, release: release}, err
	}
	refresh := make(chan error, 1)
	go func() { refresh <- e.Refresh(context.Background()) }()
	<-entered
	stopped := make(chan struct{})
	go func() { _ = e.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned while its source was still running")
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := e.Head(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("publication survived stop")
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join canceled source")
	}
	if err := <-refresh; !errors.Is(err, ErrUnavailable) || f.opens.Load() != f.closes.Load() {
		t.Fatal("canceled observation or owned view leaked", err)
	}
	if e.Status().State != "stopped" || e.Stop() != nil || !errors.Is(e.Refresh(context.Background()), ErrUnavailable) || !errors.Is(e.Start(), ErrUnavailable) {
		t.Fatal("stop is not final and idempotent")
	}
}

func TestExporterTimeoutStartFailureAndConcurrentReaders(t *testing.T) {
	e, f := newExporterFixture(t, 32)
	oldFactory := e.config.Factory
	e.config.SourceTimeout = 10 * time.Millisecond
	e.config.Factory = func(ctx context.Context) (lightnode.View, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := e.Start(); !errors.Is(err, context.DeadlineExceeded) || e.Status().Running || e.Status().ErrorCode != "source_timeout" {
		t.Fatalf("failed Start created a poller: %v %+v", err, e.Status())
	}
	e.config.Factory, e.config.SourceTimeout = oldFactory, 2*time.Second
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e.Start(), ErrUnavailable) {
		t.Fatal("duplicate Start was accepted")
	}
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 50; j++ {
				envelope, err := e.Head()
				if err != nil {
					t.Error(err)
					return
				}
				m, err := VerifyManifest(envelope, "fixture-key", &f.key.PublicKey)
				if err != nil || len(m.Entries) != 32 {
					t.Error("partial or invalid publication", err)
					return
				}
				if _, err := e.Header(m.Entries[0].Digest); err != nil {
					t.Error(err)
				}
				_ = e.Status()
			}
		}()
	}
	for i := 0; i < 5; i++ {
		f.clock.Add(2000)
		if err := e.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	if err := e.Stop(); err != nil || f.opens.Load() != f.closes.Load() {
		t.Fatal("source views leaked", err)
	}
}

type exporterCountedView struct {
	lightnode.View
	active *atomic.Int32
}

func (v *exporterCountedView) Close() error {
	err := v.View.Close()
	v.active.Add(-1)
	return err
}

func TestExporterConcurrentRefreshSerializesOwnedViews(t *testing.T) {
	e, f := newExporterFixture(t, 4)
	var active atomic.Int32
	e.config.Factory = func(ctx context.Context) (lightnode.View, error) {
		if active.Add(1) != 1 {
			t.Error("more than one source view is active")
		}
		v, err := f.factory(ctx)
		return &exporterCountedView{View: v, active: &active}, err
	}
	var calls sync.WaitGroup
	for i := 0; i < 12; i++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			if err := e.Refresh(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	calls.Wait()
	if active.Load() != 0 || f.opens.Load() != f.closes.Load() || e.Status().Sequence != "13" {
		t.Fatalf("serialized refresh leaked or lost a sequence: %+v", e.Status())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := f.opens.Load()
	if err := e.Refresh(ctx); !errors.Is(err, context.Canceled) || f.opens.Load() != before {
		t.Fatal("canceled refresh acquired a source view", err)
	}
}

func TestExporterPollsBeyondInitialWindow(t *testing.T) {
	e, f := newExporterFixture(t, 40)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var parent types.Header
	if err := rlp.DecodeBytes(f.headers[40], &parent); err != nil {
		t.Fatal(err)
	}
	next := &types.Header{Number: big.NewInt(41), Difficulty: big.NewInt(1), ParentHash: parent.Hash()}
	raw, err := rlp.EncodeToBytes(next)
	if err != nil {
		t.Fatal(err)
	}
	f.headers[41], f.head = raw, 41
	f.mu.Unlock()
	f.clock.Add(2000)
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("poller did not observe the advancing window")
		case <-tick.C:
			if e.Status().HeadHeight != 41 {
				continue
			}
			_, m := exporterManifest(t, e, f)
			if m.Entries[0].Height != 10 || m.Entries[31].Height != 41 || m.Sequence != "3" {
				t.Fatalf("invalid next window: %+v", m)
			}
			_ = e.Stop()
			if f.opens.Load() != f.closes.Load() {
				t.Fatal("poller view was not closed")
			}
			return
		}
	}
}
