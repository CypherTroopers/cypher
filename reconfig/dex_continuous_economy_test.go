package reconfig_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/params"
)

type continuousEconomy struct {
	fixture      *continuousFixture
	certificates map[uint64][]rewards.Certificate
	feed         uint64
}

func (f *continuousFixture) checkpoint(t *testing.T, height uint64) testnet.Response {
	t.Helper()
	var result testnet.Response
	if err := f.children[0].cli.http("GET", fmt.Sprintf("/v1/checkpoint?height=%d", height), nil, &result); err != nil {
		t.Fatal(err)
	}
	if result.Checkpoint == nil || result.Checkpoint.Sequence != height {
		t.Fatal("checkpoint API height mismatch")
	}
	epoch, err := checkpoint.NewEpoch(f.init.Domain, 1, ^uint64(0), f.init.Members)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = epoch.Verify(*result.Checkpoint, result.Proof); err != nil {
		t.Fatal("checkpoint API unauthenticated", err)
	}
	var financial devnet.FinancialState
	if err = json.Unmarshal(result.State, &financial); err != nil {
		t.Fatal(err)
	}
	root, err := financial.Root()
	if err != nil || root != result.Checkpoint.PostRoot || financial.Version != 5 {
		t.Fatal("financial API state/root mismatch", err)
	}
	for _, c := range f.children[1:] {
		if c == nil || c.stopped {
			continue
		}
		var other testnet.Response
		if err = c.cli.http("GET", fmt.Sprintf("/v1/checkpoint?height=%d", height), nil, &other); err != nil {
			t.Fatal(err)
		}
		if other.Checkpoint == nil || *other.Checkpoint != *result.Checkpoint || !bytes.Equal(other.State, result.State) {
			t.Fatalf("ordinary DEX root/state divergence height=%d node=%d", height, c.index)
		}
	}
	return result
}
func (f *continuousFixture) financial(t *testing.T, height uint64) (devnet.FinancialState, engine.State) {
	t.Helper()
	r := f.checkpoint(t, height)
	var financial devnet.FinancialState
	var market engine.State
	if err := json.Unmarshal(r.State, &financial); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(financial.Engine, &market); err != nil {
		t.Fatal(err)
	}
	if market.Height != height || financial.RollingAnchor == nil || financial.Participation == nil {
		t.Fatal("rolling financial state incomplete")
	}
	return financial, market
}
func (f *continuousFixture) minimumHeight(t *testing.T) (certified, finalized uint64) {
	t.Helper()
	certified, finalized = ^uint64(0), ^uint64(0)
	for _, s := range f.statuses(t) {
		if s.Certified < certified {
			certified = s.Certified
		}
		if s.Finalized < finalized {
			finalized = s.Finalized
		}
	}
	return
}

// Selection follows the authenticated certified proposal, not the number of
// records retained locally. Old-view certificates stay in each collector WAL.
func continuousSelectCertificates(registry *rewards.Registry, ref *types.HotstuffProposalRef, all []rewards.Certificate) ([]rewards.Certificate, error) {
	var selected []rewards.Certificate
	seen := map[uint8]bool{}
	for _, cert := range all {
		if err := registry.VerifyCertificate(cert); err != nil {
			return nil, err
		}
		duty := cert.Duty
		if duty.Height != ref.Number || duty.Period != (ref.Number-1)/rewards.PeriodBlocks+1 {
			return nil, fmt.Errorf("participation API returned foreign height/period")
		}
		if duty.View != ref.ViewNumber || duty.ProposalID != protocol.Hash(ref.ProposalID()) {
			continue
		}
		if seen[duty.Participant] {
			return nil, fmt.Errorf("duplicate participation duty")
		}
		seen[duty.Participant] = true
		selected = append(selected, cert)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Duty.Participant < selected[j].Duty.Participant })
	return selected, nil
}
func (e *continuousEconomy) collect(t *testing.T, height uint64) []rewards.Certificate {
	t.Helper()
	f := e.fixture
	expected := map[uint8]bool{}
	recipients := make([][20]byte, len(f.init.Members))
	for i, m := range f.init.Members {
		recipients[i] = [20]byte(common.HexToAddress(m.CoinBase))
	}
	registry, err := rewards.NewRegistry(f.init.Domain, f.init.Members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.children {
		if c != nil && !c.stopped {
			expected[uint8(c.index)] = true
		}
	}
	record := f.certifiedRecord(t, height)
	if record == nil {
		t.Fatal("participation lacks certified proposal")
	}
	ref, err := types.DecodeHotstuffProposalRef(record.Ref)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	var result []rewards.Certificate
	lastCounts := ""
	for time.Now().Before(deadline) {
		complete := true
		counts := ""
		for _, c := range f.children {
			if c == nil || c.stopped {
				continue
			}
			var answer testnet.Response
			if err := c.cli.http("GET", fmt.Sprintf("/v1/participation?height=%d", height), nil, &answer); err != nil {
				t.Fatal(err)
			}
			if answer.ReceiptErrors != 0 {
				t.Fatalf("authenticated participation delivery errors height=%d node=%d errors=%d", height, c.index, answer.ReceiptErrors)
			}
			selected, err := continuousSelectCertificates(registry, ref, answer.Certificates)
			if err != nil {
				t.Fatal(err)
			}
			found := map[uint8]bool{}
			for _, cert := range selected {
				found[cert.Duty.Participant] = true
			}
			if len(found) != len(expected) {
				complete = false
			}
			for participant := range expected {
				if !found[participant] {
					complete = false
				}
			}
			counts += fmt.Sprintf(" node%d=%d/%d", c.index, len(selected), len(answer.Certificates))
			if c.index == 0 {
				result = selected
			}
		}
		if counts != lastCounts {
			t.Logf("CONTINUOUS_PARTICIPATION_CANDIDATES height=%d certifiedView=%d proposal=%x selected/retained:%s oldViewEvidenceRetained=true", height, ref.ViewNumber, ref.ProposalID(), counts)
			lastCounts = counts
		}
		if complete {
			t.Logf("CONTINUOUS_PARTICIPATION height=%d period=%d authenticatedParticipants=%d", height, (height-1)/10+1, len(result))
			return result
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("participation delivery deadline height=%d certifiedView=%d have=%d want=%d", height, ref.ViewNumber, len(result), len(expected))
	return nil
}
func (e *continuousEconomy) commit(t *testing.T, height uint64) {
	t.Helper()
	f := e.fixture
	period := (height-1)/10 + 1
	duty := (period-1)*10 + 5
	certs := e.collect(t, duty)
	f.actionNonce[2]++
	raw, err := devnet.EncodeParticipationAction(engine.Action{Version: 1, Epoch: f.init.Domain.EpochKey(), Owner: [20]byte(f.owners[2]), Nonce: f.actionNonce[2]}, f.keys[2], certs)
	if err != nil {
		t.Fatal(err)
	}
	f.admit(t, height, raw)
	e.certificates[period] = certs
}
func (e *continuousEconomy) close(t *testing.T, height, period uint64) {
	t.Helper()
	f := e.fixture
	grace := period*10 + 4
	f.waitDEX(t, height-1, grace)
	pkg := rewards.ClosePackage{Period: period, Certificates: e.certificates[period]}
	if len(pkg.Certificates) < 5 {
		t.Fatal("period lacks committed authenticated participant set")
	}
	for h := (period-1)*10 + 1; h <= period*10; h++ {
		r := f.checkpoint(t, h)
		pkg.Blocks = append(pkg.Blocks, rewards.FinalizedBlock{Checkpoint: *r.Checkpoint, Proof: r.Proof})
	}
	r := f.checkpoint(t, grace)
	pkg.Blocks = append(pkg.Blocks, rewards.FinalizedBlock{Checkpoint: *r.Checkpoint, Proof: r.Proof})
	f.actionNonce[2]++
	raw, err := devnet.EncodeRewardAction(engine.Action{Version: 1, Epoch: f.init.Domain.EpochKey(), Owner: [20]byte(f.owners[2]), Nonce: f.actionNonce[2]}, f.keys[2], pkg)
	if err != nil {
		t.Fatal(err)
	}
	f.admit(t, height, raw)
	t.Logf("CONTINUOUS_REWARD_CLOSE period=%d actionHeight=%d packageBytes=%d participants=%d grace=%d", period, height, len(raw), len(pkg.Certificates), grace)
}

// Each observed partial source update is finalized with an ordinary signed
// action before the relay plans the next segment. No test-generated proof or
// cursor mutation is used. The explicitly selected slot count is a fixture
// bound, not a consensus or proof-limit change. Slot6 commits participation.
func (e *continuousEconomy) catchup(t *testing.T, base, expectedCursor, slots uint64) {
	t.Helper()
	e.catchupPrefix(t, base, expectedCursor, slots)
	e.requireInboxParent(t, base+slots, expectedCursor)
}

// Only flatCatchup may extend this prefix with its existing55/57 slots.
func (e *continuousEconomy) catchupPrefix(t *testing.T, base, expectedCursor, slots uint64) uint64 {
	t.Helper()
	f := e.fixture
	lastInbox := uint64(0)
	committed := false
	for offset := uint64(1); offset <= slots; offset++ {
		height := base + offset
		certified, finalized := f.minimumHeight(t)
		cursor := uint64(0)
		if finalized > 0 {
			_, market := f.financial(t, finalized)
			cursor = market.InboxCursor
		}
		if certified >= height {
			record := f.certifiedRecord(t, height)
			if record == nil || !bytes.HasPrefix(record.Actions, []byte("CDXA")) {
				t.Fatal("unexpected concurrent non-inbox action")
			}
			lastInbox = height
			continue
		}
		if offset >= 6 && !committed {
			e.commit(t, height)
			committed = true
		} else if cursor < expectedCursor && lastInbox <= finalized {
			f.waitDEX(t, height, 0)
			record := f.certifiedRecord(t, height)
			if record != nil && !bytes.HasPrefix(record.Actions, []byte("CDXA")) {
				t.Fatal("automatic source step is not CDXA")
			}
			lastInbox = height
		} else if base == 0 && offset == 2 {
			e.oracle(t, height, 100)
		} else {
			t.Logf("CONTINUOUS_SOURCE_DESCENDANT height=%d certifiedInbox=%d actualFinalized=%d importedCursor=%d targetCursor=%d", height, lastInbox, finalized, cursor, expectedCursor)
			f.admit(t, height, f.sign(t, 2, engine.Noop, nil))
		}
	}
	if !committed {
		t.Fatal("bounded catchup left no authenticated participation commitment slot")
	}
	return lastInbox
}

func (e *continuousEconomy) requireInboxParent(t *testing.T, height, expectedCursor uint64) {
	t.Helper()
	f := e.fixture
	_, finalized := f.minimumHeight(t)
	record := f.certifiedRecord(t, height)
	var financial devnet.FinancialState
	var market engine.State
	if err := json.Unmarshal(record.State, &financial); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(financial.Engine, &market); err != nil {
		t.Fatal(err)
	}
	if market.InboxCursor != expectedCursor || financial.RollingAnchor == nil {
		t.Fatalf("catchup authenticated parent bound: certified=%d finalized=%d cursor=%d expected=%d; market actions NOT_RUN", height, finalized, market.InboxCursor, expectedCursor)
	}
	t.Logf("CONTINUOUS_SOURCE_INTERVAL certifiedParent=%d actualFinalized=%d anchor=%d cursor=%d total=%s authenticatedParent=true NOT_FINALITY=true", height, finalized, financial.RollingAnchor.Height, market.InboxCursor, market.Total)
}

func (e *continuousEconomy) oracle(t *testing.T, height uint64, price int64) {
	t.Helper()
	e.feed++
	f := e.fixture
	f.admit(t, height, f.sign(t, 2, engine.Oracle, func(a *engine.Action) {
		a.Price = engine.Amount(nativeUnits(price).String())
		a.FeedSequence = e.feed
		a.ValidUntil = height + 90
		a.FundingRate = 100
	}))
}
func (e *continuousEconomy) order(t *testing.T, height uint64, who int, id uint64, side int8, price int64) {
	t.Helper()
	f := e.fixture
	f.admit(t, height, f.sign(t, who, engine.Place, func(a *engine.Action) {
		a.OrderID = id
		a.Side = side
		a.Quantity = 100000000
		a.Price = engine.Amount(nativeUnits(price).String())
	}))
}
func (e *continuousEconomy) withdraw(t *testing.T, height uint64, recipient common.Address) {
	t.Helper()
	f := e.fixture
	f.admit(t, height, f.sign(t, 0, engine.Withdraw, func(a *engine.Action) {
		a.Amount = engine.Amount(nativeUnits(10).String())
		a.Recipient = [20]byte(recipient)
	}))
}
func (e *continuousEconomy) cycle(t *testing.T, cycle, base, expectedCursor uint64, closeTail func(func() uint64)) {
	t.Helper()
	f := e.fixture
	e.catchup(t, base, expectedCursor, 7)
	e.order(t, base+8, 1, cycle*2-1, -1, 100)
	e.order(t, base+9, 0, cycle*2-1, 1, 100)
	f.admit(t, base+10, f.sign(t, 2, engine.Funding, nil))
	e.oracle(t, base+11, 110)
	e.order(t, base+12, 0, cycle*2, -1, 110)
	e.order(t, base+13, 1, cycle*2, 1, 110)
	if cycle == 1 {
		e.withdraw(t, base+14, f.owners[3])
	} else {
		e.close(t, base+14, base/10)
	}
	f.admit(t, base+15, f.sign(t, 2, engine.Noop, nil))
	e.commit(t, base+16)
	if cycle == 1 {
		f.admit(t, base+17, f.sign(t, 2, engine.Noop, nil))
	} else {
		e.withdraw(t, base+17, f.owners[0])
	}
	tail := func() uint64 {
		e.close(t, base+18, base/10+1)
		e.oracle(t, base+19, 100)
		f.admit(t, base+20, f.sign(t, 2, engine.Noop, nil))
		f.waitDEX(t, base+20, base+18)
		return base + 18
	}
	if closeTail != nil {
		closeTail(tail)
	} else {
		tail()
	}
	// Matching/funding/price actions are ordinary descendants of the authenticated
	// import parent. Their real finalized boundary, not a fixed QC gap, now proves
	// that the original imported cursor became final as well.
	_, imported := f.financial(t, base+7)
	if imported.InboxCursor != expectedCursor {
		t.Fatal("finalized imported cursor differs from certified parent")
	}
	financial, market := f.financial(t, base+18)
	if market.RewardPeriod != base/10+1 || market.InboxCursor != expectedCursor || market.PendingFunding != 0 || len(market.Orders) != 0 {
		t.Fatal("cycle financial boundary mismatch")
	}
	for _, a := range market.Accounts {
		if len(a.Lots) != 0 {
			t.Fatal("cycle retained an open position")
		}
	}
	t.Logf("CONTINUOUS_CYCLE cycle=%d DEXFinalized=%d CLXAnchor=%d inbox=%d fees=%s support=%s total=%s withdrawalReserved=%s rewardReserved=%s", cycle, base+18, financial.RollingAnchor.Height, market.InboxCursor, market.Fees, market.Support, market.Total, market.WithdrawReserved, market.RewardReserved)
}

// This explicit input interval gives bounded source proofs time to catch up
// while all positions stay flat. It earns two independently funded periods;
// it does not waive a reward deadline or increase any proof/record size limit.
func (e *continuousEconomy) flatCatchup(t *testing.T) {
	t.Helper()
	f := e.fixture
	lastInbox := e.catchupPrefix(t, 40, 8, 13)
	e.close(t, 54, 4)
	lastInbox = e.flatSourceSlot(t, 55, lastInbox, 8)
	e.commit(t, 56)
	e.flatSourceSlot(t, 57, lastInbox, 8)
	e.requireInboxParent(t, 57, 8)
	e.close(t, 58, 5)
	e.oracle(t, 59, 100)
	f.admit(t, 60, f.sign(t, 2, engine.Noop, nil))
	f.waitDEX(t, 60, 58)
	financial, market := f.financial(t, 58)
	if market.InboxCursor != 8 || market.RewardPeriod != 5 || market.PendingFunding != 0 || len(market.Orders) != 0 {
		t.Fatal("flat catchup financial boundary")
	}
	for _, account := range market.Accounts {
		if len(account.Lots) != 0 {
			t.Fatal("flat catchup has an open position")
		}
	}
	t.Logf("CONTINUOUS_FLAT_CATCHUP finalized=58 anchor=%d cursor=%d periods=5 total=%s support=%s noPositions=true", financial.RollingAnchor.Height, market.InboxCursor, market.Total, market.Support)
}
func (f *continuousFixture) fundMore(t *testing.T) {
	t.Helper()
	raw, err := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for who := 0; who < 2; who++ {
		f.send(t, who, params.DEXSettlementAddress, nativeUnits(20), raw, 500000)
	}
}
func (f *continuousFixture) joinSeventh(t *testing.T) {
	t.Helper()
	if f.children[6] != nil {
		t.Fatal("seventh DEX already activated")
	}
	certified, finalized := f.minimumHeight(t)
	before, market := f.financial(t, finalized)
	var snapshot struct {
		Height uint64
		Bytes  []byte
	}
	if err := f.children[0].cli.http("GET", fmt.Sprintf("/v1/snapshot?height=%d", finalized), nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Height != finalized || len(snapshot.Bytes) == 0 {
		t.Fatal("snapshot API returned no finalized data")
	}
	path := filepath.Join(f.root, "seventh-bootstrap.json")
	if err := os.WriteFile(path, snapshot.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	f.children[6] = startFinancialCLI(t, f.binary, f.root, f.identity[6], f.init, f.network.Fixture.Genesis, 6, func(m *service.Manifest) {
		m.BootstrapSnapshotFile = path
		m.Finance.ReceiptHeights = []uint64{25, 35, 45, 55, 65, 75, 85, 95}
	})
	f.connectParent(t, f.children[6])
	f.waitDEX(t, certified, finalized)
	after, m2 := f.financial(t, finalized)
	a, _ := before.Root()
	b, _ := after.Root()
	if a != b || m2.InboxCursor != market.InboxCursor || !bytes.Equal(before.Engine, after.Engine) {
		t.Fatal("seventh snapshot changed finalized financial state")
	}
	t.Logf("CONTINUOUS_SEVENTH_JOIN finalized=%d certified=%d snapshotBytes=%d root=%x cursor=%d committedCertificates=%d ownVoteKey=true freshOwnWAL=true importedPeerSafety=false", finalized, certified, len(snapshot.Bytes), a, market.InboxCursor, len(before.Participation.Entries))
}
