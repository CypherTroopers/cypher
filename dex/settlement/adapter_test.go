package settlement

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type fixture struct {
	a                   *Adapter
	cfg                 Config
	keys                []bls.SecretKey
	nodes               []*common.Cnode
	alice, bob, sponsor common.Address
	anchor              checkpoint.FinalizedAnchor
}

func amount(n string) protocol.Amount {
	v, ok := new(big.Int).SetString(n, 10)
	if !ok {
		panic("amount")
	}
	a, err := protocol.AmountFromBig(v)
	if err != nil {
		panic(err)
	}
	return a
}
func coins(n int64) protocol.Amount {
	a, err := protocol.AmountFromBig(clx(n))
	if err != nil {
		panic(err)
	}
	return a
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{alice: common.Address{1}, bob: common.Address{2}, sponsor: common.Address{3}, anchor: checkpoint.FinalizedAnchor{Height: 100, Hash: protocol.Hash{50}}}
	for i := 0; i < 7; i++ {
		var k bls.SecretKey
		if err := k.SetDecString(fmt.Sprint(i + 1)); err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, k)
		f.nodes = append(f.nodes, &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 25000+i), CoinBase: fmt.Sprintf("fixture-%d", i), Public: k.GetPublicKey().SerializeToHexStr()})
	}
	d := protocol.Domain{Version: 1, ChainID: 10101919, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: f.nodes}).RlpHash())}
	epoch, err := checkpoint.NewEpoch(d, 1, 101, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.AddBalance(f.alice, clx(100))
	st.AddBalance(f.bob, clx(100))
	st.AddBalance(f.sponsor, clx(25))
	f.cfg = Config{Devnet: true, Custody: common.Address{9}, Domain: d, GenesisRoot: protocol.Hash{3}, Epochs: []*checkpoint.Epoch{epoch}, FinalizedAnchors: []checkpoint.FinalizedAnchor{f.anchor}, MaxCheckpoints: 100}
	f.a, err = NewDevnet(st, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) fund(t *testing.T) {
	t.Helper()
	if _, err := f.a.Deposit(f.alice, coins(100), f.anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Deposit(f.bob, coins(100), f.anchor); err != nil {
		t.Fatal(err)
	}
	if err := f.a.FundPool(Support, f.sponsor, coins(20)); err != nil {
		t.Fatal(err)
	}
	if err := f.a.FundPool(Insurance, f.sponsor, coins(5)); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) next(t *testing.T, end uint64) (protocol.Checkpoint, protocol.FinanceSummary) {
	t.Helper()
	s := f.a.Status()
	_, inbox, total, err := f.a.Inbox(s.InboxCursor, end, f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	seq := s.Sequence + 1
	summary := protocol.FinanceSummary{Version: 1, Domain: f.cfg.Domain, Custody: [20]byte(f.cfg.Custody), Sequence: seq, Previous: s.Summary, DepositTotal: total}
	if seq >= 14 && seq%10 == 4 {
		summary.RewardPeriod = seq / 10
		summary.FeePeriodFirst = seq - 13
		summary.FeePeriodLast = seq - 4
		summary.ParticipationRoot = protocol.Hash{70, byte(seq)}
	}
	cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: f.cfg.Domain.ChainID, Genesis: f.cfg.Domain.Genesis, DEXID: f.cfg.Domain.DEXID, Epoch: 1, Committee: f.cfg.Domain.Committee, Sequence: seq, Previous: s.Hash, PreRoot: s.Root, PostRoot: protocol.Hash{4, byte(seq)}, FirstBlock: seq, LastBlock: seq, CLXHeight: f.anchor.Height, CLXHash: f.anchor.Hash, InboxStart: s.InboxCursor, InboxEnd: end, InboxRoot: inbox, RewardPeriod: summary.RewardPeriod, DataRoot: protocol.Hash{80, byte(seq)}, DataSchema: 2}
	return cp, summary
}
func (f *fixture) proof(t *testing.T, c protocol.Checkpoint) []byte {
	t.Helper()
	if c.DataSchema == 6 {
		return f.historyProof(t, c)
	}
	hash, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(r *types.HotstuffProposalRef) *hotstuff.SignedState {
		raw := r.EncodeToBytes()
		var aggregate *bls.Sign
		for i := 0; i < 5; i++ {
			sig, err := hotstuff.SignFHSSignatureWithContext(&f.keys[i], f.keys[i].GetPublicKey(), raw, r.ChainID, hotstuff.MsgVotePrepare, r.ViewID, r.LeaderID)
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
	view := c.Sequence*2 - 1
	parent := common.Hash(c.Previous)
	if parent == (common.Hash{}) {
		parent = common.Hash{99}
	}
	r := &types.HotstuffProposalRef{Version: types.HotstuffProposalRefVersion, ChainID: c.ChainID, Number: c.LastBlock, ViewNumber: view, ViewID: common.Hash{byte(view), 42}, LeaderID: bftview.GetNodeID(f.nodes[(view-1)%7].Address, f.nodes[(view-1)%7].Public), BlockHash: common.Hash(hash), ParentHash: parent, StateRoot: common.Hash(c.PostRoot), BodyHash: common.Hash(c.DataRoot), BodySize: 8, ExtraHash: types.HotstuffProposalExtraHash(nil), KeyHash: common.Hash(c.Domain().EpochKey()), Time: c.LastBlock}
	target := sign(r)
	id, _ := hotstuff.SignedStateID(target)
	r.Number++
	r.Time++
	r.ViewNumber++
	r.ViewID = common.Hash{byte(view + 1), 42}
	r.LeaderID = bftview.GetNodeID(f.nodes[view%7].Address, f.nodes[view%7].Public)
	r.ParentHash = r.BlockHash
	r.BlockHash = common.Hash(protocol.Digest("fixture/child", r.BlockHash[:]))
	r.ParentQCID = id.Hash()
	raw, err := checkpoint.EncodeProof(checkpoint.Proof{Target: target, Descendants: []*hotstuff.SignedState{sign(r)}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func bind(t *testing.T, c *protocol.Checkpoint, s protocol.FinanceSummary) {
	t.Helper()
	h, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	c.FundingRef = h
	c.WithdrawalTotal = s.WithdrawalTotal
	reward := new(big.Int).Add(s.RewardFromFees.Big(), s.RewardFromSupport.Big())
	c.RewardTotal, _ = protocol.AmountFromBig(reward)
	c.RewardPeriod = s.RewardPeriod
}
func manifest(t *testing.T, claims []protocol.Claim) (protocol.Hash, [][]protocol.Hash) {
	t.Helper()
	var leaves []protocol.Hash
	for _, c := range claims {
		h, err := c.Hash()
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, h)
	}
	root, paths, err := protocol.BuildCountedTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	return root, paths
}
func (f *fixture) accept(t *testing.T, c protocol.Checkpoint, s protocol.FinanceSummary) {
	t.Helper()
	bind(t, &c, s)
	if _, err := f.a.Accept(c, s, f.proof(t, c)); err != nil {
		t.Fatal(err)
	}
}
func balances(t *testing.T, a *Adapter) map[Bucket]protocol.Amount {
	t.Helper()
	b, err := a.Balances()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNativeStateDBVerticalAccountingClaimsAndRestart(t *testing.T) {
	f := newFixture(t)
	f.fund(t)
	if got := f.a.st.GetBalance(f.cfg.Custody); got.Cmp(clx(225)) != 0 {
		t.Fatal("actual custody native balance", got)
	}
	var final protocol.Checkpoint
	var summary protocol.FinanceSummary
	var withdrawals, rewards []protocol.Claim
	var wp, rp [][]protocol.Hash
	for seq := uint64(1); seq <= 14; seq++ {
		c, s := f.next(t, 2)
		if seq == 2 {
			s.CollectedFees = amount("84000000000000000")
		}
		if seq == 14 {
			s.WithdrawalTotal = coins(10)
			s.RewardFromFees = amount("42000000000000000")
			s.RewardFromSupport = amount("958000000000000000")
			withdrawals = []protocol.Claim{{Domain: f.cfg.Domain, Sequence: 14, Kind: protocol.Withdrawal, ID: protocol.Hash{1}, Owner: [20]byte(f.alice), Recipient: [20]byte(f.alice), Amount: coins(10)}}
			for i, value := range []string{"500000000000000000", "250000000000000000", "250000000000000000"} {
				rewards = append(rewards, protocol.Claim{Domain: f.cfg.Domain, Sequence: 14, Kind: protocol.Reward, ID: protocol.Hash{byte(i + 2)}, Owner: [20]byte{byte(20 + i)}, Recipient: [20]byte{byte(20 + i)}, Amount: amount(value), Period: 1})
			}
			c.WithdrawalRoot, wp = manifest(t, withdrawals)
			c.RewardRoot, rp = manifest(t, rewards)
			bind(t, &c, s)
			final, summary = c, s
		}
		f.accept(t, c, s)
	}
	before := balances(t, f.a)
	result, err := f.a.Accept(final, summary, nil)
	if err != nil || !result.Replay || !reflect.DeepEqual(before, balances(t, f.a)) {
		t.Fatal("checkpoint replay changed finance", err)
	}
	// A CLX execution snapshot reverts both native payment and its storage nullifier.
	snapshot := f.a.st.Snapshot()
	if replay, err := f.a.Claim(withdrawals[0], 0, 1, wp[0]); err != nil || replay {
		t.Fatal(err)
	}
	if f.a.st.GetBalance(f.alice).Cmp(clx(10)) != 0 {
		t.Fatal("native withdrawal not paid")
	}
	f.a.st.RevertToSnapshot(snapshot)
	if f.a.st.GetBalance(f.alice).Sign() != 0 {
		t.Fatal("native transfer survived revert")
	}
	if replay, err := f.a.Claim(withdrawals[0], 0, 1, wp[0]); err != nil || replay {
		t.Fatal("nullifier survived revert", err)
	}
	for i, c := range rewards {
		if _, err := f.a.Claim(c, uint32(i), 3, rp[i]); err != nil {
			t.Fatal(err)
		}
	}
	if f.a.st.GetBalance(f.cfg.Custody).Cmp(clx(214)) != 0 {
		t.Fatal("final native custody")
	}
	want := map[Bucket]protocol.Amount{Unconsumed: {}, Trader: amount("189916000000000000000"), Fees: amount("42000000000000000"), Support: amount("19042000000000000000"), Insurance: coins(5), Dust: {}, Withdrawals: {}, Rewards: {}}
	if !reflect.DeepEqual(balances(t, f.a), want) {
		t.Fatalf("buckets: %#v", balances(t, f.a))
	}
	// Commit and reconstruct StateDB with a fresh trie/state cache.
	root, err := f.a.st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.st.Database().TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	st, err := state.New(root, state.NewDatabase(rawdb.NewDatabase(f.a.st.Database().TrieDB().DiskDB())), nil)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDevnet(st, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status() != f.a.Status() {
		t.Fatal("accepted history lost")
	}
	if replay, err := reopened.Claim(withdrawals[0], 0, 1, wp[0]); err != nil || !replay {
		t.Fatal("restart double-claim protection", err)
	}
	if st.GetBalance(f.alice).Cmp(clx(10)) != 0 {
		t.Fatal("duplicate native payment")
	}
	if result, err := reopened.Accept(final, summary, nil); err != nil || !result.Replay {
		t.Fatal("restart checkpoint history", err)
	}
	changed := f.cfg
	changed.MaxCheckpoints--
	if _, err := NewDevnet(st, changed); err == nil {
		t.Fatal("registry/config replacement")
	}
}

func TestNativeFailureAtomicityAndFinalizedInbox(t *testing.T) {
	f := newFixture(t)
	before := f.a.Status()
	if _, err := f.a.Deposit(f.alice, coins(101), f.anchor); err == nil {
		t.Fatal("unfunded deposit")
	}
	if f.a.Status() != before || f.a.st.GetBalance(f.alice).Cmp(clx(100)) != 0 || f.a.st.GetBalance(f.cfg.Custody).Sign() != 0 {
		t.Fatal("failed deposit mutated state")
	}
	if _, err := f.a.Deposit(f.cfg.Custody, coins(1), f.anchor); err == nil {
		t.Fatal("custody self-credit")
	}
	unknown := checkpoint.FinalizedAnchor{Height: 99, Hash: protocol.Hash{91}}
	if _, err := f.a.Deposit(f.alice, coins(1), unknown); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.a.Inbox(0, 1, f.anchor); err == nil {
		t.Fatal("unfinalized deposit consumed")
	}
	g := newFixture(t)
	g.fund(t)
	c, s := g.next(t, 2)
	s.DepositTotal = coins(201)
	bind(t, &c, s)
	old := g.a.Status()
	oldBuckets := balances(t, g.a)
	res, err := g.a.Accept(c, s, nil)
	if err == nil || res.Verification.SignatureChecks != 0 || old != g.a.Status() || !reflect.DeepEqual(oldBuckets, balances(t, g.a)) {
		t.Fatal("self-reported deposit amount accepted/mutated", err)
	}
	c, s = g.next(t, 2)
	s.CollectedFees = coins(201)
	bind(t, &c, s)
	res, err = g.a.Accept(c, s, nil)
	if err == nil || res.Verification.SignatureChecks != 0 {
		t.Fatal("unfunded fee transfer")
	}
	c, s = g.next(t, 2)
	bind(t, &c, s)
	bad := g.proof(t, c)
	bad[len(bad)-1] ^= 1
	if _, err = g.a.Accept(c, s, bad); err == nil {
		t.Fatal("bad signature accepted")
	}
	if old != g.a.Status() || !reflect.DeepEqual(oldBuckets, balances(t, g.a)) {
		t.Fatal("signature failure changed state")
	}
	g.accept(t, c, s)
	c, s = g.next(t, 2)
	c.InboxStart = 0
	bind(t, &c, s)
	if _, err = g.a.Accept(c, s, nil); err == nil {
		t.Fatal("duplicate deposits consumed")
	}
}

func TestClaimsCannotExceedReservedOrChangeRecipient(t *testing.T) {
	f := newFixture(t)
	f.fund(t)
	c, s := f.next(t, 2)
	s.WithdrawalTotal = coins(10)
	claims := []protocol.Claim{{Domain: f.cfg.Domain, Sequence: 1, Kind: protocol.Withdrawal, ID: protocol.Hash{1}, Owner: [20]byte(f.alice), Recipient: [20]byte(f.alice), Amount: coins(6)}, {Domain: f.cfg.Domain, Sequence: 1, Kind: protocol.Withdrawal, ID: protocol.Hash{2}, Owner: [20]byte(f.bob), Recipient: [20]byte(f.bob), Amount: coins(6)}}
	root, paths := manifest(t, claims)
	c.WithdrawalRoot = root
	f.accept(t, c, s)
	changed := claims[0]
	changed.Recipient[0] ^= 4
	if _, err := f.a.Claim(changed, 0, 2, paths[0]); err == nil {
		t.Fatal("recipient changed")
	}
	if _, err := f.a.Claim(claims[0], 0, 2, paths[0]); err != nil {
		t.Fatal(err)
	}
	before := balances(t, f.a)
	if _, err := f.a.Claim(claims[1], 1, 2, paths[1]); err == nil {
		t.Fatal("leaf sums over reserve accepted")
	}
	if !reflect.DeepEqual(before, balances(t, f.a)) || f.a.st.GetBalance(f.bob).Sign() != 0 {
		t.Fatal("failed claim changed state")
	}
	if replay, err := f.a.Claim(claims[0], 0, 2, paths[0]); err != nil || !replay {
		t.Fatal("duplicate claim not idempotent", err)
	}
}

func TestRewardPeriodAndSourceBounds(t *testing.T) {
	f := newFixture(t)
	if _, err := f.a.Deposit(f.alice, coins(100), f.anchor); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq < 14; seq++ {
		c, s := f.next(t, 1)
		f.accept(t, c, s)
	}
	c, s := f.next(t, 1)
	s.RewardFromSupport = coins(1)
	c.RewardRoot = protocol.Hash{2}
	bind(t, &c, s)
	before := f.a.Status()
	if _, err := f.a.Accept(c, s, nil); err == nil {
		t.Fatal("unsupported reward emission")
	}
	if f.a.Status() != before {
		t.Fatal("failed reward advanced period")
	}
	c, s = f.next(t, 1)
	f.accept(t, c, s)
	if f.a.Status().RewardPeriod != 1 {
		t.Fatal("zero budget period failed")
	}
	c, s = f.next(t, 1)
	s.RewardPeriod = 1
	s.FeePeriodFirst = 1
	s.FeePeriodLast = 10
	s.ParticipationRoot = protocol.Hash{4}
	bind(t, &c, s)
	if _, err := f.a.Accept(c, s, nil); err == nil {
		t.Fatal("period replay accepted")
	}
}

func TestPeriodExcludesSubsequentFeesAndAllowsDelayedClose(t *testing.T) {
	f := newFixture(t)
	if _, err := f.a.Deposit(f.alice, coins(100), f.anchor); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 14; seq++ {
		c, s := f.next(t, 1)
		// Explicitly defer period close beyond the earliest permitted checkpoint14.
		s.RewardPeriod = 0
		s.FeePeriodFirst = 0
		s.FeePeriodLast = 0
		s.ParticipationRoot = protocol.Hash{}
		if seq == 2 {
			s.CollectedFees = coins(1)
		}
		if seq == 11 {
			s.CollectedFees = coins(3)
		}
		f.accept(t, c, s)
	}
	c, s := f.next(t, 1)
	s.RewardPeriod = 1
	s.FeePeriodFirst = 1
	s.FeePeriodLast = 10
	s.ParticipationRoot = protocol.Hash{8}
	s.RewardFromFees = amount("600000000000000000")
	c.RewardRoot = protocol.Hash{9}
	bind(t, &c, s)
	before := f.a.Status()
	result, err := f.a.Accept(c, s, nil)
	if err == nil || result.Verification.SignatureChecks != 0 {
		t.Fatal("later fees inflated prior-period budget", err)
	}
	if f.a.Status() != before {
		t.Fatal("failed close changed status")
	}
	s.RewardFromFees = amount("500000000000000000")
	f.accept(t, c, s)
	if f.a.Status().RewardPeriod != 1 || balances(t, f.a)[Fees] != amount("3500000000000000000") {
		t.Fatal("delayed close/source accounting")
	}
}

func TestInsuranceDustAndNativeTransferFailureAreAtomic(t *testing.T) {
	f := newFixture(t)
	f.fund(t)
	c, s := f.next(t, 2)
	s.InsuranceUsed = coins(6)
	bind(t, &c, s)
	if result, err := f.a.Accept(c, s, nil); err == nil || result.Verification.SignatureChecks != 0 {
		t.Fatal("unfunded insurance")
	}
	s.InsuranceUsed = coins(5)
	s.FundingDust = coins(1)
	s.WithdrawalTotal = coins(10)
	claim := protocol.Claim{Domain: f.cfg.Domain, Sequence: 1, Kind: protocol.Withdrawal, ID: protocol.Hash{7}, Owner: [20]byte(f.alice), Recipient: [20]byte(f.alice), Amount: coins(10)}
	root, paths := manifest(t, []protocol.Claim{claim})
	c.WithdrawalRoot = root
	f.accept(t, c, s)
	values := balances(t, f.a)
	if values[Insurance] != (protocol.Amount{}) || values[Dust] != coins(1) || values[Trader] != coins(194) {
		t.Fatal("insurance/dust conservation", values)
	}
	// Force a recipient-side native uint256 overflow; claim storage must roll back.
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	f.a.st.SetBalance(f.alice, max)
	if _, err := f.a.Claim(claim, 0, 1, paths[0]); err == nil {
		t.Fatal("recipient overflow")
	}
	if !reflect.DeepEqual(values, balances(t, f.a)) {
		t.Fatal("transfer failure consumed reserve")
	}
	f.a.st.SetBalance(f.alice, new(big.Int))
	if replay, err := f.a.Claim(claim, 0, 1, paths[0]); err != nil || replay {
		t.Fatal("failed transfer consumed nullifier", err)
	}
}

func TestStateDBDiskReopenPreservesNativeClaims(t *testing.T) {
	f := newFixture(t)
	path := t.TempDir()
	db, err := rawdb.NewLevelDBDatabase(path, 16, 16, "dex-devnet-test")
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []common.Address{f.alice, f.bob} {
		st.AddBalance(address, clx(100))
	}
	st.AddBalance(f.sponsor, clx(25))
	f.a, err = NewDevnet(st, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.fund(t)
	c, s := f.next(t, 2)
	s.WithdrawalTotal = coins(10)
	claim := protocol.Claim{Domain: f.cfg.Domain, Sequence: 1, Kind: protocol.Withdrawal, ID: protocol.Hash{1}, Owner: [20]byte(f.alice), Recipient: [20]byte(f.alice), Amount: coins(10)}
	root, paths := manifest(t, []protocol.Claim{claim})
	c.WithdrawalRoot = root
	bind(t, &c, s)
	f.accept(t, c, s)
	if _, err = f.a.Claim(claim, 0, 1, paths[0]); err != nil {
		t.Fatal(err)
	}
	status := f.a.Status()
	stateRoot, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Database().TrieDB().Commit(stateRoot, false, nil); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = rawdb.NewLevelDBDatabase(path, 16, 16, "dex-devnet-test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err = state.New(stateRoot, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewDevnet(st, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status() != status || st.GetBalance(f.alice).Cmp(clx(10)) != 0 || st.GetBalance(f.cfg.Custody).Cmp(clx(215)) != 0 {
		t.Fatal("disk reopen lost native/storage state")
	}
	if replay, err := a.Claim(claim, 0, 1, paths[0]); err != nil || !replay {
		t.Fatal("disk reopen double payment", err)
	}
	if accepted, err := a.Accept(c, s, nil); err != nil || !accepted.Replay {
		t.Fatal("disk reopen accepted history", err)
	}
	if _, err := a.GetDeposit(1); err != nil {
		t.Fatal("disk reopen inbox", err)
	}
}

func TestEmptyCustodyHistorySurvivesEIP161Commit(t *testing.T) {
	f := newFixture(t)
	if f.a.st.GetBalance(f.cfg.Custody).Sign() != 0 {
		t.Fatal("unexpected initial funds")
	}
	root, err := f.a.st.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New(root, f.a.st.Database(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewDevnet(st, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exist(f.cfg.Custody) || st.GetNonce(f.cfg.Custody) != 1 || a.get("config", 0) == (common.Hash{}) {
		t.Fatal("EIP-161 erased unfunded custody registry/storage")
	}
}

func TestCustodyBindingRejectsCrossInstanceFinancialProof(t *testing.T) {
	f := newFixture(t)
	f.fund(t)
	c, s := f.next(t, 2)
	before := f.a.Status()
	values := balances(t, f.a)
	s.Custody[0]++
	bind(t, &c, s)
	if _, err := f.a.Accept(c, s, nil); err == nil || err.Error() != "finance summary connection mismatch" {
		t.Fatal("cross-custody summary not rejected before proof processing", err)
	}
	if f.a.Status() != before || !reflect.DeepEqual(values, balances(t, f.a)) {
		t.Fatal("cross-custody proof changed accounting")
	}
	d, err := f.a.GetDeposit(0)
	if err != nil {
		t.Fatal(err)
	}
	root, err := protocol.DepositInboxRoot([]protocol.Deposit{d})
	if err != nil {
		t.Fatal(err)
	}
	d.Custody[0]++
	other, err := protocol.DepositInboxRoot([]protocol.Deposit{d})
	if err != nil || root == other {
		t.Fatal("deposit commitment does not bind native custody", err)
	}
}

func TestRevertedInitializationInvalidatesAdapter(t *testing.T) {
	f := newFixture(t)
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.AddBalance(f.alice, clx(1))
	snapshot := st.Snapshot()
	a, err := NewDevnet(st, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	st.RevertToSnapshot(snapshot)
	if _, err := a.Deposit(f.alice, coins(1), f.anchor); err == nil {
		t.Fatal("adapter with reverted initialization accepted a deposit")
	}
	if st.GetBalance(f.alice).Cmp(clx(1)) != 0 || st.GetBalance(f.cfg.Custody).Sign() != 0 {
		t.Fatal("invalid adapter moved native funds")
	}
}
