// SPDX-License-Identifier: LGPL-3.0-or-later
package lightnode

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/rlp"
	"math/big"
	"sync/atomic"
	"testing"
)

// Synthetic storage fixture exercises the native adapter against real rawdb
// lease/helper code. It is not a live model, network, finality or driver test.
type nativeFixtureDB struct {
	ethdb.Database
	data  map[string][]byte
	opens int
	gets  int
	view  *nativeFixtureView
}

func (d *nativeFixtureDB) BrowserSnapshotCapabilityVersion() uint32 {
	return ethdb.BrowserSnapshotCapabilityV1
}
func (d *nativeFixtureDB) BrowserRecentSnapshotCapabilityVersion() uint32 {
	return ethdb.BrowserRecentSnapshotCapabilityV1
}
func (d *nativeFixtureDB) Get([]byte) ([]byte, error) {
	d.gets++
	return nil, errors.New("ordinary Get forbidden")
}
func (d *nativeFixtureDB) NewBrowserSnapshot(_ context.Context, _ ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	d.opens++
	copyData := make(map[string][]byte, len(d.data))
	for k, v := range d.data {
		copyData[k] = append([]byte(nil), v...)
	}
	d.view = &nativeFixtureView{data: copyData, id: [32]byte{1}}
	return d.view, nil
}

type nativeFixtureView struct {
	data   map[string][]byte
	id     [32]byte
	reads  int
	closed atomic.Int32
}

func (v *nativeFixtureView) BrowserViewID() [32]byte { return v.id }
func (v *nativeFixtureView) Close() error            { v.closed.Add(1); return nil }
func (v *nativeFixtureView) read(ctx context.Context, key []byte, max int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.reads++
	raw, ok := v.data[string(key)]
	if !ok {
		return nil, ethdb.ErrBrowserSnapshotMissing
	}
	if int64(len(raw)) > max {
		return nil, ethdb.ErrBrowserSnapshotLimit
	}
	return append([]byte(nil), raw...), nil
}
func (v *nativeFixtureView) ReadBrowserRecord(ctx context.Context, key []byte, _ string, _ uint64, max int64) ([]byte, error) {
	return v.read(ctx, key, max)
}
func (v *nativeFixtureView) ReadBrowserRecentRecord(ctx context.Context, key []byte, _ string, max int64) ([]byte, error) {
	return v.read(ctx, key, max)
}
func nativeFixtureCanonical(height uint64) string {
	key := make([]byte, 10)
	key[0] = 'h'
	binary.BigEndian.PutUint64(key[1:9], height)
	key[9] = 'n'
	return string(key)
}
func nativeFixtureHeader(height uint64, hash common.Hash) string {
	key := make([]byte, 41)
	key[0] = 'h'
	binary.BigEndian.PutUint64(key[1:9], height)
	copy(key[9:], hash[:])
	return string(key)
}
func nativeFixtureHeaderBytes(height uint64) (*types.Header, []byte) {
	h := &types.Header{Number: new(big.Int).SetUint64(height), Difficulty: big.NewInt(1), Extra: []byte("native fixture")}
	h.SignInfo.Signature = []byte{1, 2, 3}
	h.SignInfo.Exceptions = []byte{0}
	h.SignInfo.LeaderID = "fixture"
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		panic(err)
	}
	return h, raw
}
func nativeFixture(height uint64) (*nativeFixtureDB, common.Hash, []byte) {
	genesis := common.HexToHash("0xabc123")
	header, raw := nativeFixtureHeaderBytes(height)
	hash := header.Hash()
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], height)
	d := &nativeFixtureDB{data: map[string][]byte{
		nativeFixtureCanonical(0):               genesis.Bytes(),
		"ethereum-config-" + string(genesis[:]): []byte(`{"chainId":10101919,"other":{"kept":"opaque"}}`),
		"LastBlock":                             hash.Bytes(), "H" + string(hash[:]): append([]byte(nil), number[:]...),
	}}
	if height > 0 {
		for offset := uint64(0); offset < 32 && offset < height; offset++ {
			h := height - offset
			item, itemRaw := nativeFixtureHeaderBytes(h)
			itemHash := item.Hash()
			d.data[nativeFixtureCanonical(h)] = itemHash.Bytes()
			d.data[nativeFixtureHeader(h, itemHash)] = append([]byte(nil), itemRaw...)
		}
	}
	if height == 0 {
		d.data["LastBlock"] = genesis.Bytes()
		d.data["H"+string(genesis[:])] = make([]byte, 8)
	}
	return d, genesis, raw
}
func TestNativeFactoryNoIOUntilAdmittedAndSnapshotNetwork(t *testing.T) {
	d, genesis, _ := nativeFixture(70)
	factory := NativeFactory(d)
	if d.opens != 0 || d.gets != 0 {
		t.Fatal("factory construction read storage")
	}
	v, err := factory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if n := v.Network(); n.ChainID != 10101919 || n.GenesisHash != genesis.Hex() {
		t.Fatalf("network %+v", n)
	}
	// Live DB mutation does not alter the captured view's network or head.
	d.data["LastBlock"] = common.HexToHash("0x999").Bytes()
	if h, err := v.LatestHeight(context.Background()); err != nil || h != 70 {
		t.Fatalf("head %d %v", h, err)
	}
	if d.opens != 1 || d.gets != 0 {
		t.Fatalf("opens %d ordinary %d", d.opens, d.gets)
	}
}
func TestNativeRecentWindowAndExactHeaderBytes(t *testing.T) {
	d, _, _ := nativeFixture(70)
	v, err := NativeFactory(d)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, h := range []uint64{39, 70} {
		_, want := nativeFixtureHeaderBytes(h)
		got, err := v.HeaderRLP(context.Background(), h, NativeMaxHeaderBytes)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("height %d bytes %x err %v", h, got, err)
		}
	}
	for _, h := range []uint64{0, 38, 71, ^uint64(0)} {
		if _, err := v.HeaderRLP(context.Background(), h, NativeMaxHeaderBytes); !errors.Is(err, ethdb.ErrBrowserSnapshotMissing) {
			t.Fatalf("outside height %d: %v", h, err)
		}
	}
	reads := d.view.reads
	for _, cap := range []int{-1, 0, NativeMaxHeaderBytes + 1} {
		if _, err := v.HeaderRLP(context.Background(), 70, cap); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
			t.Fatal(err)
		}
	}
	if d.view.reads != reads {
		t.Fatal("invalid byte cap read storage")
	}
}
func TestNativeHeaderCapAndMissingMetadataFailClosed(t *testing.T) {
	for _, name := range []string{"genesis", "config", "large-header"} {
		t.Run(name, func(t *testing.T) {
			d, genesis, _ := nativeFixture(70)
			if name == "genesis" {
				delete(d.data, nativeFixtureCanonical(0))
			}
			if name == "config" {
				delete(d.data, "ethereum-config-"+string(genesis[:]))
			}
			if name == "large-header" {
				hash := common.BytesToHash(d.data["LastBlock"])
				d.data[nativeFixtureHeader(70, hash)] = make([]byte, NativeMaxHeaderBytes+1)
			}
			v, err := NativeFactory(d)(context.Background())
			if name == "large-header" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = v.HeaderRLP(context.Background(), 70, NativeMaxHeaderBytes)
				if _, closedErr := v.LatestHeight(context.Background()); !errors.Is(closedErr, ethdb.ErrBrowserSnapshotClosed) {
					t.Fatal("failed source returned cached head", closedErr)
				}
				_ = v.Close()
			}
			if err == nil {
				t.Fatal("missing/oversized native record accepted")
			}
			if d.gets != 0 || d.view.closed.Load() != 1 {
				t.Fatalf("ordinary %d close %d", d.gets, d.view.closed.Load())
			}
		})
	}
}

type nativeOldDriver struct {
	ethdb.Database
	opens int
}

func (d *nativeOldDriver) BrowserSnapshotCapabilityVersion() uint32 {
	return ethdb.BrowserSnapshotCapabilityV1
}
func (d *nativeOldDriver) NewBrowserSnapshot(context.Context, ethdb.BrowserSnapshotLimits) (ethdb.BrowserSnapshot, error) {
	d.opens++
	return nil, errors.New("must not open")
}
func TestNativeUnsupportedBeforeSnapshotAndCancelBeforeIO(t *testing.T) {
	d := &nativeOldDriver{}
	if _, err := NativeFactory(d)(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) || d.opens != 0 {
		t.Fatalf("%v opens %d", err, d.opens)
	}
	if _, err := NativeFactory(nil)(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotUnsupported) {
		t.Fatal(err)
	}
	db, _, _ := nativeFixture(70)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NativeFactory(db)(ctx); !errors.Is(err, context.Canceled) || db.opens != 0 {
		t.Fatalf("%v opens %d", err, db.opens)
	}
}
func TestNativeZeroAndMaximumHeadArithmetic(t *testing.T) {
	for _, height := range []uint64{0, 1, nativeMaxSafeInteger} {
		d, _, _ := nativeFixture(height)
		v, err := NativeFactory(d)(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got, err := v.LatestHeight(context.Background()); err != nil || got != height {
			t.Fatalf("%d %v", got, err)
		}
		if height == 0 {
			if _, err := v.HeaderRLP(context.Background(), 0, NativeMaxHeaderBytes); !errors.Is(err, ethdb.ErrBrowserSnapshotMissing) {
				t.Fatal(err)
			}
		} else if _, err := v.HeaderRLP(context.Background(), height, NativeMaxHeaderBytes); err != nil {
			t.Fatal(err)
		}
		_ = v.Close()
		_ = v.Close()
		if d.view.closed.Load() != 1 {
			t.Fatal("double release")
		}
		if _, err := v.LatestHeight(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotClosed) {
			t.Fatal(err)
		}
	}
	d, _, _ := nativeFixture(^uint64(0))
	v, err := NativeFactory(d)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.LatestHeight(context.Background()); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) || d.view.closed.Load() != 1 {
		t.Fatalf("unsafe browser height %v close %d", err, d.view.closed.Load())
	}
}
func TestNativeChainIDRejectsCoercionDuplicateAndTrailing(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"chainId":0}`, `{"chainId":"1"}`, `{"chainId":-1}`, `{"chainId":1e2}`, `{"chainId":18446744073709551616}`, `{"chainId":9007199254740992}`, `{"chainId":1,"chainId":2}`, `{"chainId":1} {}`, `{"chainId":1,"x":0,"x":1}`} {
		if _, err := nativeChainID([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if n, err := nativeChainID([]byte(`{"chainId":9007199254740991}`)); err != nil || n != nativeMaxSafeInteger {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := nativeChainID(make([]byte, nativeMaxConfigBytes+1)); !errors.Is(err, ethdb.ErrBrowserSnapshotLimit) {
		t.Fatal(err)
	}
	if err := nativeSnapshotLimits().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSemanticHashChecksAndSignInfoBytesPreserved(t *testing.T) {
	h, original := nativeFixtureHeaderBytes(70)
	originalHash := h.Hash()
	h.SignInfo.Signature = []byte{9, 8, 7, 6}
	h.SignInfo.FHSFinalityProof = []byte{0xaa, 0xbb}
	changed, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	if h.Hash() != originalHash || bytes.Equal(changed, original) {
		t.Fatal("fixture did not preserve proposal hash while changing SignInfo")
	}
	d, _, _ := nativeFixture(70)
	d.data[nativeFixtureHeader(70, originalHash)] = changed
	v, err := NativeFactory(d)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.HeaderRLP(context.Background(), 70, NativeMaxHeaderBytes)
	_ = v.Close()
	if err != nil || !bytes.Equal(got, changed) {
		t.Fatal("complete SignInfo RLP not preserved", err)
	}
	for _, name := range []string{"invalid-rlp", "number-mismatch", "hash-mismatch"} {
		t.Run(name, func(t *testing.T) {
			d, _, _ := nativeFixture(70)
			hash := common.BytesToHash(d.data["LastBlock"])
			bad := []byte{0xff}
			if name != "invalid-rlp" {
				h, _ := nativeFixtureHeaderBytes(70)
				if name == "number-mismatch" {
					h.Number.SetUint64(69)
				} else {
					h.Extra = []byte("different proposal")
				}
				bad, err = rlp.EncodeToBytes(h)
				if err != nil {
					t.Fatal(err)
				}
			}
			d.data[nativeFixtureHeader(70, hash)] = bad
			v, err := NativeFactory(d)(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.HeaderRLP(context.Background(), 70, NativeMaxHeaderBytes); err == nil {
				t.Fatal("corrupt stored header accepted")
			}
			_ = v.Close()
			if d.view.closed.Load() != 1 {
				t.Fatal("bad source view not closed exactly once")
			}
		})
	}
}
