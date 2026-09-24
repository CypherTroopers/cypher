package settlement

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

// Signed source evidence and StateDB are real codecs/cryptography, but this is
// a unit fixture. Only the separate process gate proves actual CLX consensus.
type rollingNativeFixture struct {
	f             *fixture
	config        *params.ChainConfig
	ctx           NativeContext
	state, source *state.StateDB
	verifier      *clxevidence.Verifier
	headers       []clxevidence.HeaderWitness
	blocks        []*types.Block
	entries       []protocol.InboxEntry
}

func newRollingNativeFixture(t *testing.T, empty ...bool) *rollingNativeFixture {
	return newRollingNativeFixtureVersion(t, 3, empty...)
}

func newRollingNativeFixtureVersion(t *testing.T, version uint16, empty ...bool) *rollingNativeFixture {
	t.Helper()
	f := newFixture(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(10101919), FairHotstuff: true, FixedCommittee: true, FairHotstuffSeed: common.Hash{42}, GenCommittee: make(params.GenesisCommittee)}
	nodes := make([]common.Cnode, 7)
	for i, n := range f.nodes {
		n.CoinBase = common.Address{19: byte(i + 1)}.Hex()
		nodes[i] = *n
		cfg.GenCommittee[i] = *n
	}
	cfg.DEXDevnet = &params.DEXDevnetConfig{Version: version, ActivationBlock: 1, DEXID: common.Hash{22}, GenesisSeed: common.Hash{23}, Custody: params.DEXSettlementAddress, Committee: nodes, MaxCheckpoints: 128}
	commit, err := params.FairHotstuffGenesisCommitment(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.SetNonce(params.DEXSettlementAddress, 1)
	st.AddBalance(f.alice, clx(100))
	st.AddBalance(f.bob, clx(100))
	st.AddBalance(f.sponsor, clx(25))
	root, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	st, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{Number: new(big.Int), Difficulty: big.NewInt(1), Root: root, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, MixDigest: commit}
	r := &rollingNativeFixture{f: f, config: cfg, state: st}
	r.ctx = NativeContext{Sender: f.alice, BlockNumber: 1, Value: new(big.Int), Genesis: genesis, GenesisKeyHash: common.Hash{7}, GetHash: func(uint64) common.Hash { return common.Hash{} }}
	for i, fund := range []struct {
		sender common.Address
		op     uint8
		amount int64
	}{{f.alice, 1, 100}, {f.bob, 1, 100}, {f.sponsor, 2, 20}, {f.sponsor, 3, 5}} {
		if len(empty) > 0 && empty[0] {
			break
		}
		ctx := r.ctx
		ctx.Sender = fund.sender
		ctx.Nonce = uint64(i)
		ctx.Value = clx(fund.amount)
		call, _ := (protocol.NativeCall{Operation: fund.op}).Encode()
		// The VM performs this authenticated value transfer before RunNative.
		st.SubBalance(fund.sender, ctx.Value)
		st.AddBalance(params.DEXSettlementAddress, ctx.Value)
		out, err := RunNative(st, cfg, ctx, call)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := protocol.DecodeInboxEntry(out)
		if err != nil {
			t.Fatal(err)
		}
		r.entries = append(r.entries, entry)
	}
	root, err = st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	r.state, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.source = r.state.Copy()
	a, err := loadNative(r.state, cfg, r.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	f.cfg.Domain = a.domain
	f.cfg.Custody = params.DEXSettlementAddress
	f.cfg.GenesisRoot = a.nativeRoot
	r.verifier, err = a.nativeCLXVerifier(cfg, r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	committee := (&bftview.Committee{List: f.nodes}).RlpHash()
	sign := func(ref *types.HotstuffProposalRef) *hotstuff.SignedState {
		var aggregate *bls.Sign
		for i := 0; i < 5; i++ {
			sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.keys[i].GetPublicKey(), ref.EncodeToBytes(), cfg.ChainID.Uint64(), hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID)
			if err != nil {
				t.Fatal(err)
			}
			if aggregate == nil {
				aggregate = sig
			} else {
				aggregate.Add(sig)
			}
		}
		return &hotstuff.SignedState{State: ref.EncodeToBytes(), Sign: aggregate.Serialize(), Mask: []byte{31}, ViewID: ref.ViewID, LeaderID: ref.LeaderID, Number: ref.ViewNumber}
	}
	var qcs []*hotstuff.SignedState
	parent := genesis.Hash()
	for h := uint64(1); h <= 66; h++ {
		leader, err := clxevidence.LeaderIndex(cfg.FairHotstuffSeed, cfg.ChainID.Uint64(), h, committee)
		if err != nil {
			t.Fatal(err)
		}
		b := types.NewBlockWithHeader(&types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(h), Difficulty: big.NewInt(1), Root: root, TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, KeyHash: r.ctx.GenesisKeyHash, Time: h})
		pid := common.Hash{}
		if len(qcs) > 0 {
			id, _ := hotstuff.SignedStateID(qcs[len(qcs)-1])
			pid = id.Hash()
		}
		ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(cfg.ChainID.Uint64(), h, common.BigToHash(new(big.Int).SetUint64(h)), bftview.GetNodeID(f.nodes[leader].Address, f.nodes[leader].Public), b, types.HotstuffProposalExtraHash(nil), pid)
		if err != nil {
			t.Fatal(err)
		}
		qc := sign(ref)
		qcs = append(qcs, qc)
		b.SetFHSSignature(qc.Sign, qc.Mask, qc.ViewID, qc.LeaderID, qc.Number, ref.ExtraHash, ref.ParentQCID)
		r.blocks = append(r.blocks, b)
		parent = b.Hash()
	}
	for i := 0; i < 65; i++ {
		raw, _ := hotstuff.EncodeSignedState(qcs[i+1])
		proof, _ := rlp.EncodeToBytes(struct {
			Version uint32
			QCs     [][]byte
		}{2, [][]byte{raw}})
		if err := r.blocks[i].SetFHSFinalityProof(proof); err != nil {
			t.Fatal(err)
		}
		w, err := clxevidence.BuildHeaderWitness(cfg.ChainID.Uint64(), r.blocks[i])
		if err != nil {
			t.Fatal(err)
		}
		r.headers = append(r.headers, w)
	}
	r.ctx.BlockNumber = 100
	r.ctx.GetHash = func(h uint64) common.Hash {
		if h == 0 {
			return genesis.Hash()
		}
		if h > uint64(len(r.blocks)) {
			return common.Hash{}
		}
		return r.blocks[h-1].Hash()
	}
	return r
}

func (r *rollingNativeFixture) evidence(t *testing.T, base clxevidence.Anchor, end uint64) clxevidence.RollingEvidence {
	t.Helper()
	id, err := base.ID()
	if err != nil {
		t.Fatal(err)
	}
	e, err := clxevidence.BuildRollingEvidence(id, r.headers[base.Height:end], r.source, nil, r.config.DEXDevnet.Custody)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func (r *rollingNativeFixture) update(t *testing.T, base clxevidence.Anchor, end uint64, continuation []clxevidence.HeaderWitness) (clxevidence.Anchor, []byte) {
	t.Helper()
	raw, err := EncodeNativeAnchorUpdate(r.evidence(t, base, end), continuation)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RunNative(r.state, r.config, r.ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 33 || out[32] != 0 {
		t.Fatal("new anchor result", out)
	}
	a, err := ReadNativeAnchor(r.state, r.config.DEXDevnet.Custody, end)
	if err != nil {
		t.Fatal(err)
	}
	return a, raw
}

type countingNativeState struct {
	*state.StateDB
	writes, logs int
	failAt       int
}

func (s *countingNativeState) SetState(a common.Address, k, v common.Hash) {
	s.writes++
	s.StateDB.SetState(a, k, v)
}
func (s *countingNativeState) AddLog(l *types.Log) { s.logs++; s.StateDB.AddLog(l) }
func (s *countingNativeState) Error() error {
	if s.failAt > 0 && s.writes >= s.failAt {
		return errors.New("injected state failure")
	}
	return s.StateDB.Error()
}

func TestNativeRollingStagingHistoricalCheckpointClaimsRestartAndRollback(t *testing.T) {
	testNativeRollingClaimsSchema(t, 3)
}
func TestNativeContinuousHistoricalCheckpointClaimsRestartAndRollback(t *testing.T) {
	testNativeRollingClaimsSchema(t, 4)
}
func TestNativeAncestryHistoricalCheckpointClaimsRestartAndRollback(t *testing.T) {
	testNativeRollingClaimsSchema(t, 5)
}

func testNativeRollingClaimsSchema(t *testing.T, version uint16) {
	r := newRollingNativeFixtureVersion(t, version)
	schema := version + 1
	custody := r.config.DEXDevnet.Custody
	base, err := r.verifier.BootstrapAnchor()
	if err != nil {
		t.Fatal(err)
	}
	getHashCalls := 0
	getHash := r.ctx.GetHash
	r.ctx.GetHash = func(h uint64) common.Hash {
		getHashCalls++
		if r.ctx.BlockNumber-h > 64 {
			t.Fatal("unbounded GetHash", h)
		}
		return getHash(h)
	}
	a16, raw16 := r.update(t, base, 16, nil)
	if _, err := r.f.a.nativeAccept(r.config, r.ctx, protocol.Checkpoint{DataSchema: schema, Sequence: 1, CLXHeight: 16, CLXHash: protocol.Hash(r.blocks[15].Hash())}, protocol.FinanceSummary{}, nil, nil); err == nil {
		t.Fatal("staged anchor admitted checkpoint")
	}
	if getHashCalls != 0 {
		t.Fatal("old anchor used GetHash")
	}
	status, _ := ReadNativeRollingStatus(r.state, custody)
	if status != (RollingStatus{16, 0, 1}) {
		t.Fatal(status)
	}
	a32, _ := r.update(t, a16, 32, nil)
	a48, _ := r.update(t, a32, 48, nil)
	_, _ = r.update(t, a48, 64, nil)
	status, _ = ReadNativeRollingStatus(r.state, custody)
	if status != (RollingStatus{64, 64, 4}) || getHashCalls != 2 {
		t.Fatal(status, getHashCalls)
	}
	// A permissionless relayer skipped height20; its eventual checkpoint can
	// recover by proving20→the already retained32, without changing the tip.
	_, _ = r.update(t, a16, 20, r.headers[20:32])
	status, _ = ReadNativeRollingStatus(r.state, custody)
	if status != (RollingStatus{64, 64, 5}) {
		t.Fatal(status)
	}
	// Exact replay has no writes or events even after externally forced surplus.
	r.state.AddBalance(custody, big.NewInt(1))
	counted := &countingNativeState{StateDB: r.state}
	out, err := RunNative(counted, r.config, r.ctx, raw16)
	if err != nil || len(out) != 33 || out[32] != 1 || counted.writes != 0 || counted.logs != 0 {
		t.Fatal("replay", err, counted.writes, counted.logs)
	}
	// Checkpoint source20 is older than GetHash's window, but retained/confirmed.
	r.ctx.BlockNumber = 300
	r.ctx.GetHash = func(uint64) common.Hash { t.Fatal("schema4 checkpoint read live ancestor"); return common.Hash{} }
	a, err := openNative(r.state, r.config, r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.f.a = a
	inbox, err := protocol.InboxEntriesRoot(r.entries)
	if err != nil {
		t.Fatal(err)
	}
	summary := protocol.FinanceSummary{Version: 1, Domain: a.domain, Custody: [20]byte(custody), Sequence: 1, DepositTotal: coins(200), WithdrawalTotal: coins(10)}
	cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: a.domain.ChainID, Genesis: a.domain.Genesis, DEXID: a.domain.DEXID, Epoch: 1, Committee: a.domain.Committee, Sequence: 1, PreRoot: a.nativeRoot, PostRoot: protocol.Hash{88}, FirstBlock: 1, LastBlock: 1, CLXHeight: 20, CLXHash: protocol.Hash(r.blocks[19].Hash()), InboxEnd: 4, InboxRoot: inbox, DataRoot: protocol.Hash{89}, DataSchema: schema}
	if version == 5 {
		empty, e := (protocol.HistoryFrontier{}).Root()
		if e != nil {
			t.Fatal(e)
		}
		cp.DataRoot, e = protocol.HistoryDataRoot(cp.DataRoot, empty, 0)
		if e != nil {
			t.Fatal(e)
		}
		want, e := protocol.NativeGenesisRootV4(protocol.Hash(r.config.DEXDevnet.GenesisSeed), a.domain, [20]byte(custody))
		if e != nil || a.nativeRoot != want {
			t.Fatal("ancestry changed financial state6 genesis", e)
		}
	}
	claim := protocol.Claim{Domain: a.domain, Kind: protocol.Withdrawal, Sequence: 1, ID: protocol.Hash{90}, Owner: [20]byte(r.f.alice), Recipient: [20]byte(r.f.alice), Amount: coins(10)}
	cp.WithdrawalRoot, _ = manifest(t, []protocol.Claim{claim})
	bind(t, &cp, summary)
	raw, err := protocol.EncodeNativeCheckpoint(cp, summary, r.f.proof(t, cp), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RunNative(r.state, r.config, r.ctx, raw); err != nil {
		t.Fatal("old retained checkpoint", err)
	}
	bad, err := protocol.EncodeNativeCheckpoint(cp, summary, r.f.proof(t, cp), []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	before := r.state.IntermediateRoot(false)
	if _, err = RunNative(r.state, r.config, r.ctx, bad); err == nil || r.state.IntermediateRoot(false) != before {
		t.Fatal("schema4 duplicate evidence accepted/mutated", err)
	}
	oldSchema := cp
	oldSchema.DataSchema = schema - 1
	oldRaw, err := protocol.EncodeNativeCheckpoint(oldSchema, summary, r.f.proof(t, oldSchema), nil)
	if err != nil {
		t.Fatal(err)
	}
	before = r.state.IntermediateRoot(false)
	if _, err = RunNative(r.state, r.config, r.ctx, oldRaw); err == nil || r.state.IntermediateRoot(false) != before {
		t.Fatal("config3 accepted schema3", err)
	}
	// Cold StateDB reopening preserves both anchor history and accepted claims.
	root, err := r.state.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	db := r.state.Database()
	if err = db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	r.state, err = state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadNativeRollingStatus(r.state, custody); err != nil || got != status {
		t.Fatal("restart", got, err)
	}
	claimRaw, err := protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Record-capacity failure must not erase old claim rights. The metadata is
	// deliberately filled as a unit fault injection rather than1024 signatures.
	r.state.SetState(custody, RollingMetadataStorageKey(), (RollingStatus{1024, 64, 1024}).encode())
	if _, err = RunNative(r.state, r.config, r.ctx, claimRaw); err != nil {
		t.Fatal("old claim at anchor capacity", err)
	}
	if got := r.state.GetBalance(custody); got.Cmp(new(big.Int).Add(clx(215), big.NewInt(1))) != 0 {
		t.Fatal("native custody", got)
	}
	if _, err = RunNative(r.state, r.config, r.ctx, claimRaw); err != nil {
		t.Fatal("claim replay", err)
	}
	nullSlot, _ := ClaimNullifierStorageKey(claim)
	if r.state.GetState(custody, nullSlot) == (common.Hash{}) {
		t.Fatal("missing native nullifier")
	}
}

func TestNativeRollingNegativeInputsAndWriteBudget(t *testing.T) {
	r := newRollingNativeFixture(t)
	custody := r.config.DEXDevnet.Custody
	base, _ := r.verifier.BootstrapAnchor()
	a16, _ := r.update(t, base, 16, nil)
	a32, _ := r.update(t, a16, 32, nil)
	e := r.evidence(t, a32, 48)
	raw, err := EncodeNativeAnchorUpdate(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	reject := func(name string, input []byte, ctx NativeContext) {
		t.Helper()
		before := r.state.IntermediateRoot(false)
		if _, err := RunNative(r.state, r.config, ctx, input); err == nil {
			t.Fatal(name, "accepted")
		}
		if r.state.IntermediateRoot(false) != before {
			t.Fatal(name, "mutated")
		}
	}
	wrong := r.ctx
	wrong.GetHash = func(uint64) common.Hash { return common.Hash{99} }
	reject("wrong recent branch", raw, wrong)
	wrong = r.ctx
	wrong.BlockNumber = 48
	reject("current target", raw, wrong)
	bad := e
	bad.Base = protocol.Hash{77}
	b, _ := EncodeNativeAnchorUpdate(bad, nil)
	reject("unknown base", b, r.ctx)
	bad = e
	bad.AccountProof = [][]byte{{0xc0}}
	b, _ = EncodeNativeAnchorUpdate(bad, nil)
	reject("bad MPT", b, r.ctx)
	counted := &countingNativeState{StateDB: r.state, failAt: 4}
	before := r.state.IntermediateRoot(false)
	if _, err = RunNative(counted, r.config, r.ctx, raw); err == nil || r.state.IntermediateRoot(false) != before {
		t.Fatal("storage failure rollback", err)
	}
	counted = &countingNativeState{StateDB: r.state}
	if _, err = RunNative(counted, r.config, r.ctx, raw); err != nil || counted.writes > 16 || counted.writes != 12 {
		t.Fatal("write budget", counted.writes, err)
	}
	// Same target with a different body conflicts even if its anchor is equal.
	b, _ = EncodeNativeAnchorUpdate(r.evidence(t, a16, 48), nil)
	reject("occupied height conflict", b, r.ctx)
	// A missing/wrong retained descendant cannot certify a skipped height.
	b, _ = EncodeNativeAnchorUpdate(r.evidence(t, a16, 20), r.headers[20:31])
	reject("unretained descendant", b, r.ctx)
	continuation := append([]clxevidence.HeaderWitness(nil), r.headers[20:32]...)
	continuation[0].Header = append([]byte(nil), continuation[0].Header...)
	continuation[0].Header[len(continuation[0].Header)-1] ^= 1
	b, _ = EncodeNativeAnchorUpdate(r.evidence(t, a16, 20), continuation)
	reject("alternate continuation", b, r.ctx)
	// A full anchor index rejects further insertions without touching history.
	r.state.SetState(custody, RollingMetadataStorageKey(), (RollingStatus{1024, 48, 1024}).encode())
	b, _ = EncodeNativeAnchorUpdate(r.evidence(t, a16, 20), r.headers[20:32])
	reject("anchor history capacity", b, r.ctx)
}

func TestIndependentNativeRollingStorageAndEnvelopeGolden(t *testing.T) {
	raw, err := os.ReadFile("../testdata/native_rolling.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Seed, Domain, Custody string
		GenesisRoot           string `json:"genesis_root"`
		Slots                 []struct {
			Name   string
			Height uint64
			Index  uint32
			Key    string
		}
		Metadata struct {
			Tip, Confirmed, Count uint64
			Encoded               string
		}
		IDLookup struct {
			AnchorID string `json:"anchor_id"`
			Key      string
		} `json:"id_lookup"`
		BodyVectors []struct {
			Evidence, Encoded string
			Continuation      [][]string
		} `json:"body_vectors"`
		AnchorCall struct {
			Body, Encoded string
			PayloadHash   string `json:"payload_hash"`
		} `json:"anchor_call"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var domain protocol.Domain
	b := decode(v.Domain)
	domain.Version = binary.BigEndian.Uint16(b[:2])
	domain.ChainID = binary.BigEndian.Uint64(b[2:10])
	copy(domain.Genesis[:], b[10:42])
	copy(domain.DEXID[:], b[42:74])
	domain.Epoch = binary.BigEndian.Uint64(b[74:82])
	copy(domain.Committee[:], b[82:114])
	var seed protocol.Hash
	copy(seed[:], decode(v.Seed))
	var custody [20]byte
	copy(custody[:], decode(v.Custody))
	root, err := protocol.NativeGenesisRootV3(seed, domain, custody)
	if err != nil || hex.EncodeToString(root[:]) != v.GenesisRoot {
		t.Fatal("root golden", err)
	}
	old, _ := protocol.NativeGenesisRoot(seed, domain, custody)
	if old == root {
		t.Fatal("root domains collide")
	}
	for _, slot := range v.Slots {
		if hex.EncodeToString(key(slot.Name, slot.Height, slot.Index).Bytes()) != slot.Key {
			t.Fatal("slot", slot.Name, slot.Index)
		}
	}
	meta := (RollingStatus{v.Metadata.Tip, v.Metadata.Confirmed, v.Metadata.Count}).encode()
	if hex.EncodeToString(meta[:]) != v.Metadata.Encoded {
		t.Fatal("metadata golden")
	}
	var id protocol.Hash
	copy(id[:], decode(v.IDLookup.AnchorID))
	if hex.EncodeToString(RollingAnchorIDStorageKey(id).Bytes()) != v.IDLookup.Key {
		t.Fatal("ID slot golden")
	}
	for _, body := range v.BodyVectors {
		var continuation []clxevidence.HeaderWitness
		for _, pair := range body.Continuation {
			continuation = append(continuation, clxevidence.HeaderWitness{Header: decode(pair[0]), ProposalRef: decode(pair[1])})
		}
		encoded, err := rlp.EncodeToBytes(anchorUpdateEnvelope{1, decode(body.Evidence), continuation})
		if err != nil || hex.EncodeToString(encoded) != body.Encoded {
			t.Fatal("body framing golden", err)
		}
		if _, _, err := DecodeAnchorUpdate(encoded); err == nil {
			t.Fatal("opaque invalid evidence accepted")
		}
	}
	call, err := (protocol.NativeCall{Operation: protocol.NativeAnchorUpdate, Body: decode(v.AnchorCall.Body)}).Encode()
	if err != nil || hex.EncodeToString(call) != v.AnchorCall.Encoded {
		t.Fatal("call golden", err)
	}
	hash := protocol.NativePayloadHash(call)
	if hex.EncodeToString(hash[:]) != v.AnchorCall.PayloadHash {
		t.Fatal("payload golden")
	}
}

func TestNativeRollingInitialWriteBudgetAndCodecBounds(t *testing.T) {
	r := newRollingNativeFixture(t, true)
	base, _ := r.verifier.BootstrapAnchor()
	e := r.evidence(t, base, 1)
	raw, err := EncodeNativeAnchorUpdate(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.ctx.BlockNumber = 2
	r.state.AddBalance(r.config.DEXDevnet.Custody, big.NewInt(1))
	count := &countingNativeState{StateDB: r.state}
	if _, err = RunNative(count, r.config, r.ctx, raw); err != nil || count.writes != 15 || count.logs != 1 {
		t.Fatal("initial config/root/surplus+12 record writes", count.writes, count.logs, err)
	}
	status, _ := ReadNativeRollingStatus(r.state, r.config.DEXDevnet.Custody)
	if status != (RollingStatus{1, 1, 1}) {
		t.Fatal(status)
	}
	cfg2 := *r.config
	d2 := *r.config.DEXDevnet
	d2.Version = 2
	cfg2.DEXDevnet = &d2
	before := r.state.IntermediateRoot(false)
	if _, err = RunNative(r.state, &cfg2, r.ctx, raw); err == nil || r.state.IntermediateRoot(false) != before {
		t.Fatal("config2 accepted opcode6", err)
	}
	if c3, c2 := r.config.DEXDevnet, cfg2.DEXDevnet; c3.Version == c2.Version {
		t.Fatal("fixture alias")
	}
	commit3, _ := params.FairHotstuffGenesisCommitment(r.config)
	commit2, _ := params.FairHotstuffGenesisCommitment(&cfg2)
	if commit3 == commit2 {
		t.Fatal("config version omitted genesis commitment")
	}
	badConfig := *r.config
	bd := *r.config.DEXDevnet
	// Version 5 explicitly adds ancestry proofs. Unknown versions still cannot
	// inherit rolling or continuous behavior merely by being numerically newer.
	bd.Version = 6
	badConfig.DEXDevnet = &bd
	if badConfig.ValidateDEXDevnet() == nil {
		t.Fatal("future config accepted")
	}
	body, _ := EncodeAnchorUpdate(e, nil)
	var envelope anchorUpdateEnvelope
	if err = rlp.DecodeBytes(body, &envelope); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"trailing": append(append([]byte(nil), body...), 0), "oversize": make([]byte, protocol.MaxNativeCallBytes)}
	envelope.Version = 2
	cases["wrong version"], _ = rlp.EncodeToBytes(envelope)
	envelope.Version = 1
	envelope.Continuation = make([]clxevidence.HeaderWitness, 64)
	for i := range envelope.Continuation {
		envelope.Continuation[i] = clxevidence.HeaderWitness{Header: []byte{1}, ProposalRef: []byte{1}}
	}
	cases["aggregate header bound"], _ = rlp.EncodeToBytes(envelope)
	envelope.Continuation = []clxevidence.HeaderWitness{{Header: []byte{1}, ProposalRef: make([]byte, clxevidence.MaxRefBytes+1)}}
	cases["ref bound"], _ = rlp.EncodeToBytes(envelope)
	envelope.Continuation = []clxevidence.HeaderWitness{{Header: make([]byte, clxevidence.MaxHeaderWitnessBytes), ProposalRef: []byte{1}}}
	cases["witness bound"], _ = rlp.EncodeToBytes(envelope)
	zero := e
	zero.Headers = nil
	er, _ := clxevidence.EncodeRollingEvidence(zero)
	cases["zero advance"], _ = rlp.EncodeToBytes(anchorUpdateEnvelope{1, er, nil})
	for name, b := range cases {
		if _, _, err := DecodeAnchorUpdate(b); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	for _, bad := range []RollingStatus{{1, 2, 1}, {0, 0, 1}, {1, 0, 0}, {1, 0, 2}, {1025, 1, 1025}} {
		if _, err = decodeRollingStatus(bad.encode()); err == nil {
			t.Fatal("metadata", bad)
		}
	}
	badMeta := (RollingStatus{1, 1, 1}).encode()
	badMeta[31] = 1
	if _, err = decodeRollingStatus(badMeta); err == nil {
		t.Fatal("metadata reserved bytes")
	}
	if _, err = RollingAnchorStorageKeys(0); err == nil {
		t.Fatal("implicit genesis storage keys")
	}
	if _, err = CheckpointHistoryStorageKey(4097); err == nil {
		t.Fatal("history proof slot bound")
	}
	keys, err := RollingAnchorStorageKeys(1)
	if err != nil || len(keys) != 10 {
		t.Fatal("anchor proof keys", err)
	}
	if RequiredNativeGas(raw) != 12000000+40*uint64(len(raw)) {
		t.Fatal("anchor gas rule")
	}
}
