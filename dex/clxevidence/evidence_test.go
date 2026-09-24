package clxevidence

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

// This fixture signs real CLX codecs but is a unit fixture, not an actual CLX
// transaction/finality experiment. That separate gate uses process-produced data.
type fixture struct {
	config   Config
	v        *Verifier
	keys     []bls.SecretKey
	entries  []protocol.InboxEntry
	state    *state.StateDB
	block    *types.Block
	evidence RangeEvidence
}

func testFixture(t *testing.T) *fixture {
	t.Helper()
	f := new(fixture)
	cfg := &params.ChainConfig{ChainID: big.NewInt(10101919), FairHotstuff: true, FairHotstuffSeed: common.Hash{6}, GenCommittee: make(params.GenesisCommittee)}
	members := make([]*common.Cnode, 7)
	for i := 0; i < 7; i++ {
		var key bls.SecretKey
		if err := key.SetDecString(fmt.Sprint(1200 + i)); err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, key)
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 31000+i), CoinBase: fmt.Sprintf("unit-clx-%d", i), Public: key.GetPublicKey().SerializeToHexStr()}
		cfg.GenCommittee[i] = *members[i]
	}
	commit, err := params.FairHotstuffGenesisCommitment(cfg)
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{Number: new(big.Int), Difficulty: big.NewInt(1), Root: types.EmptyRootHash, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, MixDigest: commit}
	f.config = Config{ChainID: cfg.ChainID.Uint64(), Genesis: genesis, ChainConfig: cfg, Seed: cfg.FairHotstuffSeed, DEXID: protocol.Hash{2}, Custody: common.Address{9}, Epochs: []CommitteeEpoch{{First: 1, End: math.MaxUint64, KeyHash: common.Hash{7}, Members: members}}}
	f.v, err = New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		f.entries = append(f.entries, protocol.InboxEntry{Version: 2, ChainID: f.config.ChainID, Genesis: protocol.Hash(genesis.Hash()), DEXID: f.config.DEXID, Custody: [20]byte(f.config.Custody), Sender: [20]byte{1}, Nonce: uint64(i), PayloadHash: protocol.Hash{5, byte(i)}, Index: uint64(i), Owner: [20]byte{1}, Amount: protocol.Amount{31: byte(i + 1)}, Bucket: uint8(i + 1)})
	}
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.SetBalance(f.config.Custody, big.NewInt(6))
	var count common.Hash
	binary.BigEndian.PutUint64(count[24:], uint64(len(f.entries)))
	st.SetState(f.config.Custody, common.Hash(protocol.InboxCountStorageKey()), count)
	for _, entry := range f.entries {
		hash, _ := entry.Hash()
		st.SetState(f.config.Custody, common.Hash(protocol.InboxEntryStorageKey(entry.Index)), common.Hash(hash))
	}
	root, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	f.state, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.block = f.makeBlock(t, genesis.Hash(), root)
	f.evidence, err = BuildRangeEvidence([][]byte{f.block.EncodeToBytes()}, f.state, f.entries)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) sign(t *testing.T, r *types.HotstuffProposalRef) *hotstuff.SignedState {
	t.Helper()
	raw := r.EncodeToBytes()
	var aggregate *bls.Sign
	for i := 0; i < 5; i++ {
		sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.keys[i].GetPublicKey(), raw, f.config.ChainID, hotstuff.MsgVotePrepare, r.ViewID, r.LeaderID)
		if err != nil {
			t.Fatal(err)
		}
		if aggregate == nil {
			aggregate = sig
		} else {
			aggregate.Add(sig)
		}
	}
	return &hotstuff.SignedState{State: raw, Sign: aggregate.Serialize(), Mask: []byte{31}, ViewID: r.ViewID, LeaderID: r.LeaderID, Number: r.ViewNumber}
}
func (f *fixture) makeBlock(t *testing.T, parent, root common.Hash) *types.Block {
	t.Helper()
	e := &f.v.epochs[0]
	leader, _ := LeaderIndex(f.config.Seed, f.config.ChainID, 1, e.committeeHash)
	b := types.NewBlockWithHeader(&types.Header{ParentHash: parent, Number: big.NewInt(1), Difficulty: big.NewInt(1), Root: root, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, KeyHash: e.keyHash, Time: 1})
	r, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(f.config.ChainID, 1, common.Hash{1}, e.leaders[leader], b, types.HotstuffProposalExtraHash(nil), common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	q := f.sign(t, r)
	b.SetFHSSignature(q.Sign, q.Mask, q.ViewID, q.LeaderID, q.Number, r.ExtraHash, r.ParentQCID)
	child := *r
	child.Number = 2
	child.ViewNumber = 2
	child.ViewID = common.Hash{2}
	child.ParentHash = r.BlockHash
	child.BlockHash = common.Hash{80}
	pid, _ := hotstuff.SignedStateID(q)
	child.ParentQCID = pid.Hash()
	leader, _ = LeaderIndex(f.config.Seed, f.config.ChainID, 2, e.committeeHash)
	child.LeaderID = e.leaders[leader]
	cq := f.sign(t, &child)
	encoded, _ := hotstuff.EncodeSignedState(cq)
	proof, err := rlp.EncodeToBytes(finalityEnvelope{Version: 2, QCs: [][]byte{encoded}})
	if err != nil {
		t.Fatal(err)
	}
	if err = b.SetFHSFinalityProof(proof); err != nil {
		t.Fatal(err)
	}
	return b
}
func clonedEvidence(t *testing.T, e RangeEvidence) RangeEvidence {
	t.Helper()
	raw, err := EncodeRangeEvidence(e)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeRangeEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRejectUnfinalizedOrphanAndSameHashSignInfoBeforeCredit(t *testing.T) {
	f := testFixture(t)
	raw, err := os.ReadFile("../testdata/inbox.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Cases []struct {
			Name     string
			Accepted bool
		} `json:"finality_cases"`
	}
	if err = json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	for _, tc := range golden.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Accepted {
				t.Fatal("negative golden changed")
			}
			e := clonedEvidence(t, f.evidence)
			start := uint64(0)
			v := f.v
			switch tc.Name {
			case "unfinalized_target", "single_qc_only":
				b := types.DecodeToBlock(e.Blocks[0])
				if err := b.SetFHSFinalityProof(nil); err != nil {
					t.Fatal(err)
				}
				e.Blocks[0] = b.EncodeToBytes()
			case "orphan_parent":
				e.Blocks[0] = f.makeBlock(t, common.Hash{44}, f.block.Root()).EncodeToBytes()
			case "forged_sign_info_same_hash":
				b := types.DecodeToBlock(e.Blocks[0])
				old := b.Hash()
				b.SignInfo().Signature[0] ^= 1
				if b.Hash() != old {
					t.Fatal("test did not preserve header hash")
				}
				e.Blocks[0] = b.EncodeToBytes()
			case "terminal_view_gap":
				b := types.DecodeToBlock(e.Blocks[0])
				var env finalityEnvelope
				if err := rlp.DecodeBytes(b.FHSFinalityProof(), &env); err != nil {
					t.Fatal(err)
				}
				q, _ := hotstuff.DecodeSignedState(env.QCs[0])
				r, _ := types.DecodeHotstuffProposalRef(q.State)
				r.ViewNumber = 3
				r.ViewID = common.Hash{3}
				index, _ := LeaderIndex(v.seed, v.chainID, 3, v.epochs[0].committeeHash)
				r.LeaderID = v.epochs[0].leaders[index]
				env.QCs[0], _ = hotstuff.EncodeSignedState(f.sign(t, r))
				proof, _ := rlp.EncodeToBytes(env)
				b.SetFHSFinalityProof(proof)
				e.Blocks[0] = b.EncodeToBytes()
			case "forged_committee":
				c := f.config
				c.Epochs = append([]CommitteeEpoch(nil), c.Epochs...)
				c.Epochs[0].Members = append([]*common.Cnode(nil), c.Epochs[0].Members...)
				n := *c.Epochs[0].Members[0]
				n.Public = c.Epochs[0].Members[1].Public
				c.Epochs[0].Members[0] = &n
				if _, err := New(c); err == nil {
					t.Fatal("self-declared committee accepted")
				}
				return
			case "wrong_genesis":
				c := f.config
				c.Genesis = types.CopyHeader(c.Genesis)
				c.Genesis.Time++
				var err error
				v, err = New(c)
				if err != nil {
					t.Fatal(err)
				}
			case "entry_amount":
				e.Entries[0].Entry.Amount[31]++
			case "entry_owner":
				e.Entries[0].Entry.Owner[0]++
			case "entry_custody":
				e.Entries[0].Entry.Custody[0]++
			case "entry_payload":
				e.Entries[0].Entry.PayloadHash[0]++
			case "bad_storage_proof":
				e.Entries[0].Proof[0][0] ^= 1
			case "cursor_gap":
				start = 1
			default:
				t.Fatal("unknown negative golden", tc.Name)
			}
			if result, err := v.VerifyRange(start, e); err == nil || result != nil {
				t.Fatal("untrusted deposit evidence produced credit capability")
			}
		})
	}
}

func TestVerifiedInboxStateProofRoundTripAndOwnership(t *testing.T) {
	f := testFixture(t)
	e := clonedEvidence(t, f.evidence)
	verified, err := f.v.VerifyRange(0, e)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Count() != 3 || len(verified.Entries()) != 3 || verified.Header().Hash() != f.block.Hash() {
		t.Fatal("verified range mismatch")
	}
	entries := verified.Entries()
	entries[0].Amount[31]++
	header := verified.Header()
	header.Root[0] ^= 1
	e.Entries[0].Entry.Owner[0]++
	e.Blocks[0][0] ^= 1
	if verified.Entries()[0] != f.entries[0] || verified.Header().Root != f.block.Root() {
		t.Fatal("verified evidence mutable alias")
	}
	sub, err := BuildRangeEvidence(f.evidence.Blocks, f.state, f.entries[1:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.v.VerifyRange(1, sub); err != nil {
		t.Fatal(err)
	}
}

func TestLeaderElectionIndependentGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/inbox.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Seed      string `json:"leader_seed"`
		Committee string `json:"leader_committee"`
		ChainID   uint64 `json:"chain_id"`
		Leaders   []struct {
			View  uint64
			Index uint
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.Seed)
	committee, _ := hex.DecodeString(v.Committee)
	for _, row := range v.Leaders {
		index, err := LeaderIndex(common.BytesToHash(seed), v.ChainID, row.View, common.BytesToHash(committee))
		if err != nil || index != row.Index {
			t.Fatal("CLX leader golden mismatch", row.View, err)
		}
	}
}

func TestEmptyRangeAuthenticatesCountAndAnchor(t *testing.T) {
	f := testFixture(t)
	e, err := BuildRangeEvidence(f.evidence.Blocks, f.state, nil, f.config.Custody)
	if err != nil {
		t.Fatal(err)
	}
	for _, cursor := range []uint64{0, 3} {
		verified, err := f.v.VerifyRange(cursor, clonedEvidence(t, e))
		if err != nil || verified.Count() != 3 || len(verified.Entries()) != 0 || verified.Header().Hash() != f.block.Hash() {
			t.Fatal("empty range did not authenticate nonzero count", err)
		}
	}
	if _, err := f.v.VerifyRange(4, e); err == nil {
		t.Fatal("empty range beyond count")
	}
	e.CountProof = nil
	if _, err := f.v.VerifyRange(0, e); err == nil {
		t.Fatal("missing nonempty storage proof")
	}

	// A real custody account whose storage trie is empty authenticates count=0.
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.SetNonce(f.config.Custody, 1)
	root, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	st, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := f.makeBlock(t, f.config.Genesis.Hash(), root)
	empty, err := BuildRangeEvidence([][]byte{b.EncodeToBytes()}, st, nil, f.config.Custody)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.v.VerifyRange(0, clonedEvidence(t, empty))
	if err != nil || verified.Count() != 0 || len(verified.Entries()) != 0 || verified.Header().Hash() != b.Hash() {
		t.Fatal("empty storage root did not authenticate zero count", err)
	}
	if new(VerifiedRange).Header() != nil {
		t.Fatal("zero capability has a header")
	}
}

func FuzzDecodeRangeEvidence(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0})
	f.Add([]byte{0xc5, 1, 0xc0, 0xc0, 0xc0, 0xc0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxEvidenceBytes+1 {
			return
		}
		e, err := DecodeRangeEvidence(raw)
		if err != nil {
			return
		}
		reencoded, err := EncodeRangeEvidence(e)
		if err != nil || !bytes.Equal(raw, reencoded) {
			t.Fatal("noncanonical evidence decoded", err)
		}
	})
}

func TestEvidenceBoundsAndTrustedConfig(t *testing.T) {
	f := testFixture(t)
	for _, change := range []func(*RangeEvidence){func(e *RangeEvidence) { e.Blocks = make([][]byte, MaxAncestryBlocks+1) }, func(e *RangeEvidence) { e.AccountProof = make([][]byte, MaxProofNodes+1) }, func(e *RangeEvidence) { e.CountProof[0] = make([]byte, MaxProofNodeBytes+1) }, func(e *RangeEvidence) { e.Entries = make([]EntryProof, 129) }, func(e *RangeEvidence) { e.Blocks[0] = make([]byte, MaxBlockBytes+1) }} {
		e := clonedEvidence(t, f.evidence)
		change(&e)
		if _, err := f.v.VerifyRange(0, e); err == nil {
			t.Fatal("unbounded evidence accepted")
		}
	}
	raw, err := EncodeRangeEvidence(f.evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), 0), raw[:len(raw)-1], make([]byte, MaxEvidenceBytes+1)} {
		if _, err := DecodeRangeEvidence(bad); err == nil {
			t.Fatal("noncanonical evidence accepted")
		}
	}
	c := f.config
	c.Genesis = types.CopyHeader(c.Genesis)
	c.Genesis.MixDigest[0] ^= 1
	if _, err := New(c); err == nil {
		t.Fatal("unauthenticated chain configuration")
	}
	c = f.config
	c.Seed[0] ^= 1
	if _, err := New(c); err == nil {
		t.Fatal("changed leader seed")
	}
	copyConfig := f.config
	copyConfig.Epochs = append([]CommitteeEpoch(nil), f.config.Epochs...)
	copyConfig.Epochs[0].End = 2
	limited, err := New(copyConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = limited.VerifyRange(0, f.evidence); err == nil {
		t.Fatal("expired committee verified child")
	}
	duplicate := clonedEvidence(t, f.evidence)
	duplicate.AccountProof = append(duplicate.AccountProof, bytes.Clone(duplicate.AccountProof[0]))
	if _, err = f.v.VerifyRange(0, duplicate); err == nil {
		t.Fatal("duplicate MPT path node")
	}
}

func TestVerifierOwnsTrustedSnapshot(t *testing.T) {
	f := testFixture(t)
	want := f.block.Hash()
	f.config.Genesis.Time++
	f.config.ChainConfig.FairHotstuffSeed[0] ^= 1
	f.config.ChainConfig.GenCommittee[0] = *f.config.Epochs[0].Members[1]
	f.config.Epochs[0].Members[0].Address = "127.0.0.1:1"
	f.config.Epochs[0].Members[0].Public = "invalid after registration"
	f.config.Epochs[0].KeyHash[0] ^= 1
	verified, err := f.v.VerifyRange(0, f.evidence)
	if err != nil || verified.Header().Hash() != want {
		t.Fatal("trusted verifier snapshot aliases caller configuration", err)
	}
}
