package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/reconfig/bftview"
)

func archiveFixture(t *testing.T, count int, claimCount int) (*checkpoint.Epoch, protocol.Domain, common.Address, protocol.Hash, [][]byte) {
	return archiveFixtureSchema(t, count, claimCount, 5)
}
func archiveFixtureSchema(t *testing.T, count int, claimCount int, schema uint16) (*checkpoint.Epoch, protocol.Domain, common.Address, protocol.Hash, [][]byte) {
	t.Helper()
	keys := make([]bls.SecretKey, 7)
	nodes := make([]*common.Cnode, 7)
	for i := range keys {
		if err := keys[i].SetDecString(fmt.Sprint(9200 + i)); err != nil {
			t.Fatal(err)
		}
		nodes[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 31000+i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address{19: byte(i + 1)}.Hex()}
	}
	d := protocol.Domain{Version: 1, ChainID: 9002, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: nodes}).RlpHash())}
	e, err := checkpoint.NewEpoch(d, 1, math.MaxUint64, nodes)
	if err != nil {
		t.Fatal(err)
	}
	custody, genesis := common.Address{19: 240}, protocol.Hash{3}
	previous, financePrevious, pre := protocol.Hash{}, protocol.Hash{}, genesis
	var all [][]byte
	for h := 1; h <= count; h++ {
		var post protocol.Hash
		binary.BigEndian.PutUint64(post[24:], uint64(h+100))
		cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: d.ChainID, Genesis: d.Genesis, DEXID: d.DEXID, Epoch: 1, Committee: d.Committee, Sequence: uint64(h), Previous: previous, PreRoot: pre, PostRoot: post, FirstBlock: uint64(h), LastBlock: uint64(h), CLXHeight: 1, CLXHash: protocol.Hash{5}, DataRoot: post, DataSchema: schema}
		f := protocol.FinanceSummary{Version: 1, Domain: d, Custody: [20]byte(custody), Sequence: uint64(h), Previous: financePrevious}
		var claims []protocol.Claim
		var leaves []protocol.Hash
		for j := 0; j < claimCount; j++ {
			var id protocol.Hash
			binary.BigEndian.PutUint64(id[16:24], uint64(h))
			binary.BigEndian.PutUint64(id[24:], uint64(j+1))
			c := protocol.Claim{Domain: d, Sequence: uint64(h), Kind: protocol.Withdrawal, ID: id, Owner: [20]byte{19: 7}, Recipient: [20]byte{19: byte(j + 20)}, Amount: protocol.Amount{31: 1}}
			leaf, err := c.Hash()
			if err != nil {
				t.Fatal(err)
			}
			claims = append(claims, c)
			leaves = append(leaves, leaf)
		}
		cp.WithdrawalRoot, _, err = protocol.BuildCountedTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		cp.WithdrawalTotal = protocol.Amount{31: byte(claimCount)}
		f.WithdrawalTotal = cp.WithdrawalTotal
		raw := auditBundle(t, d, nodes, keys, cp, f, claims...)
		all = append(all, raw)
		bundle, _ := checkpoint.DecodeSettlementBundle(raw)
		actual, _ := protocol.DecodeCheckpoint(bundle.Checkpoint)
		previous, _ = actual.Hash()
		financePrevious = actual.FundingRef
		pre = post
	}
	return e, d, custody, genesis, all
}

func TestBundleArchiveBoundedHotColdAndOldRights(t *testing.T) {
	e, _, custody, genesis, raw := archiveFixture(t, 40, 1)
	dir := filepath.Join(t.TempDir(), "bundles")
	a, err := openBundleArchive(dir, e, custody, genesis, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range raw {
		if _, err = a.accept(b, true); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.hot) != MaxBundleHotRecords || len(a.index) != 40 {
		t.Fatal("hot/all separation")
	}
	bytes := a.bytes
	if _, err = a.accept(raw[0], true); err != nil || a.bytes != bytes || len(a.index) != 40 {
		t.Fatal("exact repeat changed state", err)
	}
	if _, err = openBundleArchive(dir, e, custody, genesis, 4096); err == nil {
		t.Fatal("two archive owners")
	}
	if err = a.close(); err != nil {
		t.Fatal(err)
	}
	a, err = openBundleArchive(dir, e, custody, genesis, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if len(a.hot) != 16 || len(a.index) != 40 {
		t.Fatal("cold bounded replay")
	}
	b, _, err := a.get(1)
	if err != nil || len(b.Withdrawals()) != 1 || b.Withdrawals()[0].Claim.Sequence != 1 {
		t.Fatal("old unpaid claim lost", err)
	}
	before := len(a.index)
	a.bytes = MaxBundleArchiveBytes
	if _, err = a.accept(raw[0], true); err != nil {
		t.Fatal("exact repeat at quota", err)
	}
	if _, err = a.accept(make([]byte, checkpoint.MaxSettlementBundleBytes+1), true); !errors.Is(err, ErrCapacity) || len(a.index) != before {
		t.Fatal("oversize mutated archive")
	}
}

func TestBundleArchiveCrashBoundaries(t *testing.T) {
	e, _, custody, genesis, raw := archiveFixture(t, 2, 1)
	for _, stage := range []string{"bundle-synced-before-rename", "bundle-renamed-before-dir-sync", "bundle-dir-synced-before-publication"} {
		t.Run(stage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundles")
			a, err := openBundleArchive(dir, e, custody, genesis, 4096)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.accept(raw[0], true); err != nil {
				t.Fatal(err)
			}
			a.hook = func(s string) error {
				if s == stage {
					return errors.New("selected crash")
				}
				return nil
			}
			if _, err = a.accept(raw[1], true); err == nil {
				t.Fatal("fault not injected")
			}
			a.close()
			a, err = openBundleArchive(dir, e, custody, genesis, 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			want := 2
			if stage == "bundle-synced-before-rename" {
				want = 1
			}
			if len(a.index) != want {
				t.Fatal("wrong recovered publication", len(a.index), want)
			}
			if _, err = a.accept(raw[1], true); err != nil || len(a.index) != 2 {
				t.Fatal("retry not exactly once", err)
			}
		})
	}
}

func TestBundleArchiveRejectsMissingTamperedForeignAndQuota(t *testing.T) {
	e, _, custody, genesis, raw := archiveFixture(t, 3, 0)
	for _, name := range []string{"missing", "corrupt", "foreign-root", "symlink", "quota"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundles")
			a, err := openBundleArchive(dir, e, custody, genesis, 4096)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range raw[:2] {
				if _, err = a.accept(b, true); err != nil {
					t.Fatal(err)
				}
			}
			if name == "quota" {
				a.bytes = MaxBundleArchiveBytes
				if _, err = a.accept(raw[2], true); !errors.Is(err, ErrCapacity) || len(a.index) != 2 {
					t.Fatal("finite quota bypass", err)
				}
				a.close()
				return
			}
			a.close()
			switch name {
			case "missing":
				if err = os.Remove(filepath.Join(dir, bundleName(1))); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				b := append([]byte(nil), raw[1]...)
				b[len(b)-1] ^= 1
				if err = os.WriteFile(filepath.Join(dir, bundleName(2)), b, 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-root":
				genesis[0] ^= 1
				defer func() { genesis[0] ^= 1 }()
			case "symlink":
				if err = os.Rename(filepath.Join(dir, bundleName(1)), filepath.Join(dir, "hidden")); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink("hidden", filepath.Join(dir, bundleName(1))); err != nil {
					t.Fatal(err)
				}
			}
			if a, err = openBundleArchive(dir, e, custody, genesis, 4096); err == nil {
				a.close()
				t.Fatal("unsafe history accepted")
			}
		})
	}
}

func TestContinuousClaimScanBoundAndDeferredFairness(t *testing.T) {
	e, d, custody, genesis, raw := archiveFixture(t, 12, 10)
	a, err := openBundleArchive(filepath.Join(t.TempDir(), "bundles"), e, custody, genesis, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	for _, b := range raw {
		if _, err = a.accept(b, true); err != nil {
			t.Fatal(err)
		}
	}
	c, backend, signer := fixtureConfig(t)
	c.Domain, c.Custody = d, custody
	r := openFixture(t, c, backend, signer, filepath.Join(t.TempDir(), "relay"))
	defer r.Close()
	n := &Network{cfg: NetworkConfig{Relay: c, DeferredRecipients: []common.Address{{19: 20}}}, archive: a}
	for tick := 0; tick < 24; tick++ {
		before := len(r.Status())
		if err = n.planContinuousBundles(context.Background(), r, clxevidence.Anchor{}, settlement.RollingStatus{}, 12); err != nil {
			t.Fatal(err)
		}
		if len(r.Status())-before > 8 {
			t.Fatal("claim jobs per tick unbounded")
		}
	}
	if len(r.Status()) != 12*9 {
		t.Fatal("old claims starved", len(r.Status()))
	}
	n.cfg.DeferredRecipients = nil
	for tick := 0; tick < 24; tick++ {
		if err = n.planContinuousBundles(context.Background(), r, clxevidence.Anchor{}, settlement.RollingStatus{}, 12); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.Status()) != 120 {
		t.Fatal("deferred old claims lost", len(r.Status()))
	}
	if len(backend.sent) != 0 || signer.calls != 0 {
		t.Fatal("discovery directly sent or signed")
	}
}

func TestBundleArchiveSchemaBoundToDeploymentVersion(t *testing.T) {
	for _, version := range []uint16{4, 5} {
		for _, schema := range []uint16{5, 6} {
			t.Run(fmt.Sprintf("config%d-schema%d", version, schema), func(t *testing.T) {
				e, _, custody, genesis, raw := archiveFixtureSchema(t, 1, 1, schema)
				a, err := openBundleArchiveVersion(filepath.Join(t.TempDir(), "bundles"), e, custody, genesis, 4096, version)
				if err != nil {
					t.Fatal(err)
				}
				defer a.close()
				_, err = a.accept(raw[0], true)
				if (err == nil) != (schema == version+1) {
					t.Fatalf("config%d accepted schema%d=%v", version, schema, err)
				}
				if n := (&Network{archive: a}).expectedCheckpointSchema(); n != version+1 {
					t.Fatal("observation lost archive schema binding")
				}
			})
		}
	}
}

func TestAncestryBundleArchiveColdRestartAndLegacyRefusal(t *testing.T) {
	e, _, custody, genesis, raw := archiveFixtureSchema(t, 20, 1, 6)
	dir := filepath.Join(t.TempDir(), "bundles")
	a, err := openBundleArchiveVersion(dir, e, custody, genesis, 4096, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range raw {
		if _, err = a.accept(b, true); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.hot) != MaxBundleHotRecords {
		t.Fatal("hot history bound changed")
	}
	if err = a.close(); err != nil {
		t.Fatal(err)
	}
	if old, err := openBundleArchive(dir, e, custody, genesis, 4096); err == nil {
		old.close()
		t.Fatal("version5 archive silently opened as legacy version4")
	}
	a, err = openBundleArchiveVersion(dir, e, custody, genesis, 4096, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	old, _, err := a.get(1)
	if err != nil || old.Checkpoint().DataSchema != 6 || len(old.Withdrawals()) != 1 {
		t.Fatal("old unpaid bundle rights lost", err)
	}
	before := a.bytes
	if _, err = a.accept(raw[0], true); err != nil || a.bytes != before || len(a.index) != 20 {
		t.Fatal("cold exact retry changed archive", err)
	}
}
