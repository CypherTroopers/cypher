package clxevidence

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

// RollingFinancialFixture is unit-generated signed CLX evidence and real MPT
// state, not a live CLX network. Every target's descendant is the actual next
// signed block in this fixture, including at segment boundaries.
type RollingFinancialFixture struct {
	Config   Config
	Verifier *Verifier
	Headers  []HeaderWitness
	Blocks   []*types.Block
	Sources  map[uint64]*state.StateDB
	Entries  map[uint64][]protocol.InboxEntry
}

func RollingFinancialFixtureForTest(t *testing.T, last uint64) *RollingFinancialFixture {
	return RollingPlannerFixtureForTest(t, last, nil)
}

// RollingPlannerFixtureForTest permits test-only authenticated native storage
// mutations before each signed block. It does not bypass proof verification.
func RollingPlannerFixtureForTest(t *testing.T, last uint64, mutate func(uint64, *state.StateDB, *RollingFinancialFixture)) *RollingFinancialFixture {
	return rollingVersionFixtureForTest(t, last, mutate, 3)
}

func ContinuousFinancialFixtureForTest(t *testing.T, last uint64) *RollingFinancialFixture {
	return rollingVersionFixtureForTest(t, last, nil, 4)
}

func rollingVersionFixtureForTest(t *testing.T, last uint64, mutate func(uint64, *state.StateDB, *RollingFinancialFixture), version uint16) *RollingFinancialFixture {
	t.Helper()
	if last == 0 || last > 300 {
		t.Fatal("rolling fixture height bound")
	}
	f := testFixture(t)
	c := f.config
	cfg := *c.ChainConfig
	cfg.FixedCommittee = true
	var secret [32]byte
	secret[31] = 41
	oracle, err := crypto.ToECDSA(secret[:])
	if err != nil {
		t.Fatal(err)
	}
	seed, err := protocol.NativeMarketSeed([20]byte(crypto.PubkeyToAddress(oracle.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	dexNodes := make([]common.Cnode, 7)
	for i, m := range c.Epochs[0].Members {
		dexNodes[i] = *m
		dexNodes[i].CoinBase = common.Address{19: byte(i + 1)}.Hex()
	}
	cfg.DEXDevnet = &params.DEXDevnetConfig{Version: version, ActivationBlock: 1, DEXID: common.Hash(c.DEXID), GenesisSeed: common.Hash(seed), Custody: params.DEXSettlementAddress, Committee: dexNodes, MaxCheckpoints: 128}
	if version == 4 {
		cfg.DEXDevnet.MaxCheckpoints = 4096
	}
	if err := cfg.ValidateDEXDevnet(); err != nil {
		t.Fatal(err)
	}
	c.ChainConfig = &cfg
	c.Custody = params.DEXSettlementAddress
	c.Genesis = types.CopyHeader(c.Genesis)
	c.Genesis.MixDigest, err = params.FairHotstuffGenesisCommitment(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Genesis.Root = types.EmptyRootHash
	v, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	f.config, f.v = c, v
	r := &RollingFinancialFixture{Config: c, Verifier: v, Sources: map[uint64]*state.StateDB{}, Entries: map[uint64][]protocol.InboxEntry{}}
	disk := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { disk.Close() })
	db := state.NewDatabase(disk)
	current, err := state.New(types.EmptyRootHash, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := []protocol.InboxEntry{}
	total := new(big.Int)
	parent := c.Genesis.Hash()
	var parentQC *hotstuff.SignedState
	qcs := make([]*hotstuff.SignedState, 0, last+1)
	for height := uint64(1); height <= last+1; height++ {
		amounts := []uint64{}
		if height == 1 {
			amounts = []uint64{1, 2, 3}
		} else if height == 65 {
			amounts = []uint64{4}
		} else if height == 130 {
			amounts = []uint64{5}
		} else if height == 257 {
			amounts = []uint64{6}
		}
		for _, amount := range amounts {
			index := uint64(len(entries))
			bucket := protocol.InboxTrader
			if index == 1 {
				bucket = protocol.InboxSupport
			}
			if index == 2 {
				bucket = protocol.InboxInsurance
			}
			entry := protocol.InboxEntry{Version: 2, ChainID: c.ChainID, Genesis: protocol.Hash(c.Genesis.Hash()), DEXID: c.DEXID, Custody: [20]byte(c.Custody), Sender: [20]byte{1}, Nonce: index, PayloadHash: protocol.Digest("rolling-unit-funding", []byte{byte(index)}), Index: index, Owner: [20]byte{1}, Amount: protocol.Amount{31: byte(amount)}, Bucket: bucket}
			if err := entry.Validate(); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, entry)
			total.Add(total, new(big.Int).SetUint64(amount))
			h, _ := entry.Hash()
			current.SetState(c.Custody, common.Hash(protocol.InboxEntryStorageKey(index)), common.Hash(h))
		}
		current.SetBalance(c.Custody, total)
		var count common.Hash
		binary.BigEndian.PutUint64(count[24:], uint64(len(entries)))
		current.SetState(c.Custody, common.Hash(protocol.InboxCountStorageKey()), count)
		if mutate != nil {
			mutate(height, current, r)
		}
		root, err := current.Commit(false)
		if err != nil {
			t.Fatal(err)
		}
		if err = db.TrieDB().Commit(root, false, nil); err != nil {
			t.Fatal(err)
		}
		current, err = state.New(root, db, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Sources[height] = current.Copy()
		r.Entries[height] = append([]protocol.InboxEntry(nil), entries...)
		leader, err := LeaderIndex(c.Seed, c.ChainID, height, v.epochs[0].committeeHash)
		if err != nil {
			t.Fatal(err)
		}
		block := types.NewBlockWithHeader(&types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(height), Difficulty: big.NewInt(1), Root: root, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, KeyHash: v.epochs[0].keyHash, Time: height})
		parentID := common.Hash{}
		if parentQC != nil {
			id, err := hotstuff.SignedStateID(parentQC)
			if err != nil {
				t.Fatal(err)
			}
			parentID = id.Hash()
		}
		ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(c.ChainID, height, common.BigToHash(new(big.Int).SetUint64(height)), v.epochs[0].leaders[leader], block, types.HotstuffProposalExtraHash(nil), parentID)
		if err != nil {
			t.Fatal(err)
		}
		qc := f.sign(t, ref)
		block.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		r.Blocks = append(r.Blocks, block)
		qcs = append(qcs, qc)
		parent = block.Hash()
		parentQC = qc
	}
	for i := uint64(0); i < last; i++ {
		child, err := hotstuff.EncodeSignedState(qcs[i+1])
		if err != nil {
			t.Fatal(err)
		}
		proof, err := rlp.EncodeToBytes(finalityEnvelope{Version: 2, QCs: [][]byte{child}})
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Blocks[i].SetFHSFinalityProof(proof); err != nil {
			t.Fatal(err)
		}
		witness, err := BuildHeaderWitness(c.ChainID, r.Blocks[i])
		if err != nil {
			t.Fatal(err)
		}
		r.Headers = append(r.Headers, witness)
	}
	return r
}

func (f *RollingFinancialFixture) Evidence(t *testing.T, base Anchor, target, cursor uint64, includeEntries bool) RollingEvidence {
	t.Helper()
	if target < base.Height || target > uint64(len(f.Headers)) || target-base.Height > MaxAncestryBlocks || cursor > uint64(len(f.Entries[target])) {
		t.Fatal("rolling fixture evidence range")
	}
	var entries []protocol.InboxEntry
	if includeEntries {
		entries = f.Entries[target][cursor:]
	}
	id, err := base.ID()
	if err != nil {
		t.Fatal(err)
	}
	e, err := BuildRollingEvidence(id, f.Headers[base.Height:target], f.Sources[target], entries, f.Config.Custody)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
