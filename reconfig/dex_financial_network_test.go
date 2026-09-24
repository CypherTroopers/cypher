package reconfig_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

// nativeLedger independently tracks wallet movements, TX gas and the existing
// Common reward/burn split. Native custody never pays the relayer's gas.
type nativeLedger struct {
	network           *reconfig.FHSNativeNetwork
	common            *nativeCommonNode
	clients           []*rpc.Client
	nonces            map[common.Address]uint64
	wallets           map[common.Address]*big.Int
	gas, reward, burn *big.Int
	height            uint64
	txs               types.Transactions
	approverOverride  common.Address // One independent normal-Common relay; never a DEX vote key.
}

func newNativeLedger(t *testing.T, n *reconfig.FHSNativeNetwork, c *nativeCommonNode) *nativeLedger {
	l := &nativeLedger{network: n, common: c, nonces: map[common.Address]uint64{}, wallets: map[common.Address]*big.Int{}, gas: new(big.Int), reward: new(big.Int), burn: new(big.Int)}
	for addr, a := range n.Fixture.Genesis.Alloc {
		l.wallets[addr] = new(big.Int).Set(a.Balance)
	}
	l.connect(t)
	return l
}
func (l *nativeLedger) connect(t *testing.T) {
	for _, c := range l.clients {
		c.Close()
	}
	l.clients = nil
	for _, url := range l.network.Endpoints() {
		client, err := rpc.DialHTTP(url)
		if err != nil {
			t.Fatal(err)
		}
		l.clients = append(l.clients, client)
		t.Cleanup(client.Close)
	}
}

func (l *nativeLedger) restart(t *testing.T, whileDown ...func()) {
	t.Helper()
	before := l.projection(t)
	oldPIDs := l.network.PIDs()
	l.network.Stop()
	for _, work := range whileDown {
		work()
	}
	l.network.Restart()
	l.connect(t)
	after := l.projection(t)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("CLX crash restart changed canonical settlement")
	}
	for _, tx := range l.txs {
		first := nativeWaitReceipt(t, l.clients[0], tx.Hash())
		for _, c := range l.clients[1:] {
			if !reflect.DeepEqual(first, nativeWaitReceipt(t, c, tx.Hash())) {
				t.Fatal("CLX restart receipt mismatch")
			}
		}
	}
	l.reconcile(t)
	t.Logf("CLX_CRASH_REOPEN height=%d oldPIDs=%v newPIDs=%v root=%s", l.height, oldPIDs, l.network.PIDs(), before.Header.Root.Hex())
}
func (l *nativeLedger) add(addr common.Address, amount *big.Int) {
	if l.wallets[addr] == nil {
		l.wallets[addr] = new(big.Int)
	}
	l.wallets[addr].Add(l.wallets[addr], amount)
}
func (l *nativeLedger) send(t *testing.T, key *ecdsa.PrivateKey, to common.Address, value *big.Int, data []byte, gas uint64, successful bool) *types.Transaction {
	t.Helper()
	payer := crypto.PubkeyToAddress(key.PublicKey)
	nonce := l.nonces[payer]
	tx, err := types.SignTx(types.NewTransaction(nonce, to, value, gas, big.NewInt(params.FixedBaseFeePerGas*2), data), types.NewEIP155Signer(l.network.Fixture.Genesis.Config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.common.Submit(tx); err != nil {
		t.Fatal(err)
	}
	r := nativeWaitReceipt(t, l.clients[0], tx.Hash())
	expected := uint64(0)
	if successful {
		expected = 1
	}
	if uint64(r.Status) != expected {
		t.Fatalf("native TX status=%d expected=%d tx=%s", r.Status, expected, tx.Hash().Hex())
	}
	for _, other := range l.clients[1:] {
		actual := nativeWaitReceipt(t, other, tx.Hash())
		if !reflect.DeepEqual(actual, r) {
			t.Fatal("financial CLX receipt differs")
		}
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(uint64(r.GasUsed)), (*big.Int)(r.EffectiveGasPrice))
	share := new(big.Int).Quo(new(big.Int).Set(fee), big.NewInt(5))
	approver := crypto.PubkeyToAddress(l.network.Fixture.OperatorKey.PublicKey)
	if l.approverOverride != (common.Address{}) {
		approver = l.approverOverride
	}
	if r.CommonTxRewardRecipient != l.network.Fixture.RewardRecipient || r.CommonTxApprover != approver || r.CommonTxApproverReward == nil || (*big.Int)(r.CommonTxApproverReward).Cmp(share) != 0 {
		t.Fatal("financial TX Common fee accounting mismatch")
	}
	l.gas.Add(l.gas, fee)
	l.reward.Add(l.reward, share)
	l.burn.Add(l.burn, new(big.Int).Sub(fee, share))
	l.add(payer, new(big.Int).Neg(fee))
	l.add(r.CommonTxRewardRecipient, share)
	if successful {
		l.add(payer, new(big.Int).Neg(new(big.Int).Set(value)))
		l.add(to, value)
	}
	l.nonces[payer]++
	l.txs = append(l.txs, tx)
	if uint64(r.BlockNumber) > l.height {
		l.height = uint64(r.BlockNumber)
	}
	t.Logf("CLX_FINALIZED tx=%s height=%d hash=%s status=%d payer=%s gas=%d value=%s", tx.Hash().Hex(), r.BlockNumber, r.BlockHash.Hex(), r.Status, payer.Hex(), r.GasUsed, value)
	return tx
}
func (l *nativeLedger) projection(t *testing.T) nativeProjection {
	t.Helper()
	l.network.WaitFinalized(l.height)
	var p nativeProjection
	ref := hexutil.EncodeUint64(l.height)
	if err := l.clients[0].Call(&p, "dexfixture_projection", ref); err != nil {
		t.Fatal(err)
	}
	for _, c := range l.clients[1:] {
		var other nativeProjection
		if err := c.Call(&other, "dexfixture_projection", ref); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p, other) {
			t.Fatal("financial CLX state/receipt/native projection differs")
		}
	}
	if p.Engine != (engine.ProcessMetrics{}) {
		t.Fatal("CLX process ran DEX execution")
	}
	return p
}
func (l *nativeLedger) reconcile(t *testing.T) {
	t.Helper()
	p := l.projection(t)
	addresses := make([]common.Address, 0, len(l.wallets))
	for who := range l.wallets {
		addresses = append(addresses, who)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Hex() < addresses[j].Hex() })
	for _, who := range addresses {
		want := l.wallets[who]
		var got hexutil.Big
		if err := l.clients[0].Call(&got, "eth_getBalance", who, hexutil.EncodeUint64(l.height)); err != nil {
			t.Fatal(err)
		}
		if (*big.Int)(&got).Cmp(want) != 0 {
			t.Fatalf("native ledger mismatch account=%s actual=%s expected=%s", who.Hex(), (*big.Int)(&got), want)
		}
		initial := new(big.Int)
		if alloc, ok := l.network.Fixture.Genesis.Alloc[who]; ok {
			initial.Set(alloc.Balance)
		}
		t.Logf("NATIVE_BALANCE height=%d account=%s initial=%s final=%s delta=%s", l.height, who.Hex(), initial, want, new(big.Int).Sub(new(big.Int).Set(want), initial))
	}
	t.Logf("NATIVE_LEDGER_RECONCILED height=%d custody=%s gas=%s commonReward=%s burn=%s accounts=%d engine=0/0/0", l.height, p.Balance, l.gas, l.reward, l.burn, len(l.wallets))
}
func (l *nativeLedger) syncSource(t *testing.T) {
	t.Helper()
	var blocks types.Blocks
	start := l.common.Service.BlockChain().CurrentBlock().NumberU64() + 1
	for height := start; height <= l.height; height++ {
		var raw hexutil.Bytes
		if err := l.clients[0].Call(&raw, "dexfixture_block", hexutil.Uint64(height)); err != nil {
			t.Fatal(err)
		}
		var block types.Block
		if err := rlp.DecodeBytes(raw, &block); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, &block)
	}
	before := engine.Metrics()
	if len(blocks) > 0 {
		if i, err := l.common.Service.BlockChain().InsertChain(blocks); err != nil {
			t.Fatalf("source Common replay i=%d: %v", i, err)
		}
	}
	if engine.Metrics() != before {
		t.Fatal("settlement replay ran DEX engine")
	}
}

func TestFHSNativeFinancialTwoDomainSockets(t *testing.T) {
	runFHSNativeFinancial(t, false)
}
func TestFHSNativeFinancialOrdinaryCLI(t *testing.T) {
	if os.Getenv("CYPHER_DEX_CLI_BINARY") == "" {
		t.Skip("separately built normal CLI required")
	}
	runFHSNativeFinancial(t, true)
}
func runFHSNativeFinancial(t *testing.T, ordinaryCLI bool) {
	if os.Getenv("CYPHER_DEX_FINANCIAL_DEVNET") != "1" || os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" {
		t.Skip("isolated financial two-domain socket opt-in")
	}
	root := t.TempDir()
	children := make([]*dexFinancialChild, 7)
	members := make([]*common.Cnode, 7)
	nodes := make([]common.Cnode, 7)
	peers := make([]transport.Peer, 7)
	recipients := make([][20]byte, 7)
	for i := range children {
		children[i] = startDEXFinancialChild(t, filepath.Join(root, fmt.Sprintf("dex%d", i)), i)
		members[i] = children[i].identity.Member
		nodes[i] = *members[i]
		peers[i] = children[i].identity.Peer
		recipients[i] = peers[i].RewardRecipient
	}
	keys := make([]*ecdsa.PrivateKey, 4)
	owners := make([]common.Address, 4)
	alloc := core.GenesisAlloc{}
	for i := range keys {
		var err error
		keys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		owners[i] = crypto.PubkeyToAddress(keys[i].PublicKey)
		if i < 3 {
			alloc[owners[i]] = core.GenesisAccount{Balance: nativeUnits(1000)}
		}
	}
	seed, err := protocol.NativeMarketSeed([20]byte(owners[2]))
	if err != nil {
		t.Fatal(err)
	}
	dexcfg := &params.DEXDevnetConfig{Version: 2, ActivationBlock: 1, DEXID: common.Hash(protocol.Digest("financial-native-socket", []byte(t.Name()))), GenesisSeed: common.Hash(seed), Custody: params.DEXSettlementAddress, Committee: nodes, MaxCheckpoints: 128}
	network := reconfig.NewFHSNativeNetwork(t, dexcfg, alloc)
	syncPeers := nativeSyncPeers()
	// Reserve enough inbound slots (MaxPeers minus outbound dial reservations)
	// for seven normal parents and the separate DEX-OFF verifier.
	syncPeers.MaxPeers = 16
	commonNode := startFHSRewardCommon(t, network.Fixture, nativeCommonOptions{P2P: syncPeers})
	ledger := newNativeLedger(t, network, commonNode)
	var fundingTX *types.Transaction
	for _, f := range []struct {
		who   int
		op    uint8
		value int64
	}{{0, protocol.NativeDeposit, 100}, {1, protocol.NativeDeposit, 100}, {2, protocol.NativeSupport, 20}, {2, protocol.NativeInsurance, 5}} {
		raw, err := (protocol.NativeCall{Operation: f.op}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		tx := ledger.send(t, keys[f.who], params.DEXSettlementAddress, nativeUnits(f.value), raw, 500000, true)
		if fundingTX == nil {
			fundingTX = tx
		}
	}
	p := ledger.projection(t)
	if p.Balance.Cmp(nativeUnits(225)) != 0 || p.Status.Deposits != 4 {
		t.Fatal("native financial funding mismatch")
	}
	ledger.reconcile(t)
	chain := network.Fixture.Genesis.Config
	genesis := network.Fixture.Genesis.ToBlock(nil).Header()
	domain := protocol.Domain{Version: 1, ChainID: chain.ChainID.Uint64(), Genesis: protocol.Hash(genesis.Hash()), DEXID: protocol.Hash(dexcfg.DEXID), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	clx := clxevidence.Config{ChainID: domain.ChainID, Genesis: genesis, ChainConfig: chain, Seed: chain.FairHotstuffSeed, DEXID: domain.DEXID, Custody: dexcfg.Custody, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: ^uint64(0), KeyHash: network.Fixture.KeyBlock.Hash(), Members: network.Fixture.Committee}}}
	verifier, err := clxevidence.New(clx)
	if err != nil {
		t.Fatal(err)
	}
	evidence := nativeEvidence(t, ledger.clients[0], p)
	if _, err = verifier.VerifyRange(0, evidence); err != nil {
		t.Fatal(err)
	}
	marketConfig := engine.Config{Domain: domain, Oracle: [20]byte(owners[2]), Custody: [20]byte(dexcfg.Custody), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true}
	market, err := engine.New(marketConfig)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	execution := &devnet.Execution{Market: market, Registry: registry, Native: &devnet.NativeContext{Seed: seed, Verifier: verifier}}
	init := testnet.Init{Domain: domain, Members: members, Peers: peers, Market: marketConfig, CLX: clx, MaxHeight: 128, ParticipationHeight: 5, TimeoutMillis: 3000}
	for i, c := range children {
		if ordinaryCLI {
			c.kill(t)
			children[i] = startFinancialCLI(t, os.Getenv("CYPHER_DEX_CLI_BINARY"), root, c.identity, init, network.Fixture.Genesis, i)
		} else {
			c.ok(t, testnet.Request{Op: "init", Init: &init})
		}
	}
	inbox, err := devnet.EncodeInboxAction(evidence)
	if err != nil {
		t.Fatal(err)
	}
	// The operator fixture assigns heights. The actual signed bytes enter HTTP,
	// are authenticated/durably admitted, and propagate over mutual TLS.
	admit := func(height uint64, raw []byte) {
		children[0].ok(t, testnet.Request{Op: "action", Height: height, Raw: raw})
		if ordinaryCLI {
			// This client waits for a certified result to preserve the financial
			// scenario order. No public API accepts its expected height.
			waitDEXFinancial(t, children, func(all []testnet.Response) bool {
				for _, r := range all {
					if r.Status == nil || r.Status.Certified < height {
						return false
					}
				}
				return true
			})
		}
	}
	nonce := [4]uint64{}
	sign := func(who int, kind uint8, change func(*engine.Action)) []byte {
		nonce[who]++
		a := engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: [20]byte(owners[who]), Nonce: nonce[who], Kind: kind}
		if change != nil {
			change(&a)
		}
		raw, err := engine.Sign(a, keys[who])
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	order := func(id uint64, side int8, price int64) func(*engine.Action) {
		return func(a *engine.Action) {
			a.OrderID = id
			a.Side = side
			a.Quantity = 100000000
			a.Price = engine.Amount(nativeUnits(price).String())
		}
	}
	admit(1, inbox)
	admit(2, sign(2, engine.Noop, nil))
	admit(3, sign(2, engine.Oracle, func(a *engine.Action) {
		a.Price = engine.Amount(nativeUnits(100).String())
		a.FeedSequence = 1
		a.FundingRate = 100
		a.ValidUntil = 100
	}))
	admit(4, sign(1, engine.Place, order(1, -1, 100)))
	admit(5, sign(0, engine.Place, order(1, 1, 100)))
	statuses := waitDEXFinancial(t, children, func(all []testnet.Response) bool {
		for _, r := range all {
			if r.Status == nil || r.Status.Certified < 5 || len(r.Certificates) != 7 {
				return false
			}
		}
		return true
	})
	nonce[2]++
	participationAction, err := devnet.EncodeParticipationAction(engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: [20]byte(owners[2]), Nonce: nonce[2]}, keys[2], statuses[0].Certificates)
	if err != nil {
		t.Fatal(err)
	}
	admit(6, participationAction)
	for height := uint64(7); height <= 9; height++ {
		admit(height, sign(2, engine.Noop, nil))
	}
	admit(10, sign(2, engine.Funding, nil))
	admit(11, sign(2, engine.Oracle, func(a *engine.Action) {
		a.Price = engine.Amount(nativeUnits(110).String())
		a.FeedSequence = 2
		a.FundingRate = 100
		a.ValidUntil = 100
	}))
	admit(12, sign(0, engine.Place, order(2, -1, 110)))
	admit(13, sign(1, engine.Place, order(2, 1, 110)))
	admit(14, sign(0, engine.Withdraw, func(a *engine.Action) {
		a.Amount = engine.Amount(nativeUnits(10).String())
		a.Recipient = [20]byte(owners[3])
	}))
	for height := uint64(15); height <= 17; height++ {
		admit(height, sign(2, engine.Noop, nil))
	}
	waitDEXFinancial(t, children, func(all []testnet.Response) bool {
		for _, r := range all {
			if r.Status == nil || r.Status.Finalized < 14 {
				return false
			}
		}
		return true
	})
	pkg := rewards.ClosePackage{Period: 1, Certificates: statuses[0].Certificates}
	sort.Slice(pkg.Certificates, func(i, j int) bool {
		a, b := pkg.Certificates[i].Duty, pkg.Certificates[j].Duty
		if a.Height != b.Height {
			return a.Height < b.Height
		}
		return a.Participant < b.Participant
	})
	for h := uint64(1); h <= 14; h++ {
		if h > 10 && h != 14 {
			continue
		}
		r := children[0].ok(t, testnet.Request{Op: "checkpoint", Height: h})
		pkg.Blocks = append(pkg.Blocks, rewards.FinalizedBlock{Checkpoint: *r.Checkpoint, Proof: r.Proof})
	}
	if ordinaryCLI {
		exerciseDEXRewardOmission(t, children, execution, pkg, engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: [20]byte(owners[2]), Nonce: nonce[2] + 1}, keys[2])
	}
	nonce[2]++
	rewardAction, err := devnet.EncodeRewardAction(engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: [20]byte(owners[2]), Nonce: nonce[2]}, keys[2], pkg)
	if err != nil {
		t.Fatal(err)
	}
	admit(18, rewardAction)
	admit(19, sign(2, engine.Noop, nil))
	admit(20, sign(2, engine.Noop, nil))
	waitDEXFinancial(t, children, func(all []testnet.Response) bool {
		for _, r := range all {
			if r.Status == nil || r.Status.Finalized < 18 {
				return false
			}
		}
		return true
	})
	var withdrawals, rewardClaims []protocol.Claim
	var finalState []byte
	var exactCheckpoint, conflictingCheckpoint []byte
	evidenceRaw, err := clxevidence.EncodeRangeEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CLX_INBOX_EVIDENCE anchorHeight=%d anchor=%s stateRoot=%s evidenceKeccak=%s bytes=%d blocks=%d entries=%d", p.Header.Number.Uint64(), p.Header.Hash().Hex(), p.Header.Root.Hex(), crypto.Keccak256Hash(evidenceRaw).Hex(), len(evidenceRaw), len(evidence.Blocks), len(evidence.Entries))
	for i, item := range evidence.Entries {
		entryHash, err := item.Entry.Hash()
		if err != nil {
			t.Fatal(err)
		}
		id, err := item.Entry.SourceID()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CLX_INBOX_ENTRY index=%d depositID=%x entryHash=%x tx=%s owner=%s amount=%s bucket=%d anchor=%s", item.Entry.Index, id, entryHash, ledger.txs[i].Hash().Hex(), common.Address(item.Entry.Owner).Hex(), item.Entry.Amount.Big(), item.Entry.Bucket, p.Header.Hash().Hex())
	}
	for h := uint64(1); h <= 18; h++ {
		r := children[0].ok(t, testnet.Request{Op: "checkpoint", Height: h})
		for _, other := range children[1:] {
			v := other.ok(t, testnet.Request{Op: "checkpoint", Height: h})
			if *v.Checkpoint != *r.Checkpoint || !reflect.DeepEqual(v.State, r.State) {
				t.Fatalf("financial DEX divergence height=%d", h)
			}
		}
		f, s, err := execution.Decode(r.State)
		if err != nil {
			t.Fatal(err)
		}
		if s.Height != h {
			t.Fatal("financial checkpoint/state height")
		}
		var proof []byte
		if h == 1 {
			proof = evidenceRaw
		}
		call, err := protocol.EncodeNativeCheckpoint(*r.Checkpoint, *f.Finance, r.Proof, proof)
		if err != nil {
			t.Fatal(err)
		}
		checkpointTX := ledger.send(t, network.Fixture.SenderKey, params.DEXSettlementAddress, new(big.Int), call, 16_000_000, true)
		withdrawals = append(withdrawals, f.Withdrawals...)
		rewardClaims = append(rewardClaims, f.Rewards...)
		if h == 18 {
			finalState = r.State
			exactCheckpoint = append([]byte(nil), call...)
			bad := *r.Checkpoint
			bad.PostRoot[0] ^= 1
			conflictingCheckpoint, err = protocol.EncodeNativeCheckpoint(bad, *f.Finance, r.Proof, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		hash, _ := r.Checkpoint.Hash()
		t.Logf("DEX_FINALIZED_AND_CLX_SETTLED sequence=%d checkpoint=%x root=%x clxAnchor=%x finance=%x finalityEvidenceKeccak=%s finalityBytes=%d calldataBytes=%d clxTX=%s", h, hash, r.Checkpoint.PostRoot, r.Checkpoint.CLXHash, r.Checkpoint.FundingRef, crypto.Keccak256Hash(r.Proof).Hex(), len(r.Proof), len(call), checkpointTX.Hash().Hex())
	}
	if len(withdrawals) != 1 || len(rewardClaims) != 7 {
		t.Fatal("financial claim set mismatch")
	}
	// Independent relayers pay their own normal gas. Exact checkpoint replay
	// is idempotent; a different payload at the accepted sequence reverts.
	beforeReplay := ledger.projection(t)
	ledger.send(t, keys[0], params.DEXSettlementAddress, new(big.Int), exactCheckpoint, 16_000_000, true)
	ledger.send(t, keys[1], params.DEXSettlementAddress, new(big.Int), conflictingCheckpoint, 16_000_000, false)
	afterReplay := ledger.projection(t)
	if !reflect.DeepEqual(beforeReplay.Buckets, afterReplay.Buckets) || beforeReplay.Status != afterReplay.Status || beforeReplay.Balance.Cmp(afterReplay.Balance) != 0 {
		t.Fatal("checkpoint relays changed reserved funds")
	}
	ledger.restart(t) // accepted checkpoint and reservations survive SIGKILL
	for _, set := range [][]protocol.Claim{withdrawals, rewardClaims} {
		leaves := make([]protocol.Hash, len(set))
		for i, c := range set {
			leaves[i], err = c.Hash()
			if err != nil {
				t.Fatal(err)
			}
		}
		_, paths, err := protocol.BuildCountedTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		for i, claim := range set {
			call, err := protocol.EncodeNativeClaim(claim, uint32(i), uint32(len(set)), paths[i])
			if err != nil {
				t.Fatal(err)
			}
			originalSubmit := commonNode.Submit
			if ordinaryCLI && claim.Kind == protocol.Withdrawal && i == 0 {
				ledger.syncSource(t)
				commonNode.Submit, ledger.approverOverride = financialCombinedRPC(t, children[0], commonNode, network.Fixture, ledger.height, ledger.clients[0])
			}
			ledger.send(t, network.Fixture.SenderKey, params.DEXSettlementAddress, new(big.Int), call, 500000, true)
			commonNode.Submit = originalSubmit
			ledger.approverOverride = common.Address{}
			ledger.add(params.DEXSettlementAddress, new(big.Int).Neg(claim.Amount.Big()))
			ledger.add(common.Address(claim.Recipient), claim.Amount.Big())
			t.Logf("CLAIM_PAID id=%x recipient=%s amount=%s kind=%d", claim.ID, common.Address(claim.Recipient).Hex(), claim.Amount.Big(), claim.Kind)
		}
	}
	p = ledger.projection(t)
	if p.Balance.Cmp(nativeUnits(214)) != 0 || p.Status.Sequence != 18 || p.Buckets[settlement.Trader].Big().String() != "189916000000000000000" || p.Buckets[settlement.Fees].Big().String() != "64000000000000000" || p.Buckets[settlement.Support].Big().String() != "19020000000000000000" || p.Buckets[settlement.Insurance].Big().Cmp(nativeUnits(5)) != 0 {
		t.Fatalf("native financial final buckets: %+v", p)
	}
	if _, _, err = execution.Decode(finalState); err != nil {
		t.Fatal(err)
	}
	ledger.reconcile(t)
	ledger.restart(t, func() {
		// CLX finality is unavailable. DEX can certify explicitly authorized
		// work against already authenticated collateral; it cannot pay a new
		// CLX claim. Retained states remain within the configured 128 horizon.
		for h := uint64(21); h <= 23; h++ {
			admit(h, sign(2, engine.Noop, nil))
		}
		waitDEXFinancial(t, children, func(all []testnet.Response) bool {
			for _, r := range all {
				if r.Status == nil || r.Status.Certified < 23 || r.Status.Finalized < 22 || r.Status.Certified > init.MaxHeight {
					return false
				}
			}
			return true
		})
		t.Log("CLX_ALL_STOPPED DEX_finalized>=22 CLX_accepted_sequence=18; no native payout callback; finite retention horizon=128")
	}) // native payment, nullifier and receipt recover together
	nextHeight := uint64(24)
	{
		faultActions := make(map[uint64][]byte)
		nextHeight = exerciseDEXFinancialFaults(t, children, init, nextHeight, func(height uint64) []byte {
			if raw, ok := faultActions[height]; ok {
				return raw
			}
			raw := sign(2, engine.Noop, nil)
			faultActions[height] = raw
			return raw
		})
		t.Logf("FINANCIAL_DEX_FAULTS nextUnusedHeight=%d", nextHeight)
	}
	nextHeight = exerciseDEXFinancialEconomy(t, children, init, nextHeight, sign)
	t.Logf("FINANCIAL_ECONOMIC_FAULTS nextUnusedHeight=%d", nextHeight)
	// DEX all-stop cannot stop ordinary CLX transfer/finality or grant a claim.
	for _, c := range children {
		c.kill(t)
	}
	ledger.send(t, network.Fixture.SenderKey, common.HexToAddress("0xdad1"), big.NewInt(1), nil, 21000, true)
	claim := withdrawals[0]
	call, err := protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger.send(t, network.Fixture.SenderKey, params.DEXSettlementAddress, new(big.Int), call, 500000, true) // exact claim replay, no second payout
	claim.Recipient[0] ^= 1
	call, err = protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger.send(t, network.Fixture.SenderKey, params.DEXSettlementAddress, new(big.Int), call, 500000, false)
	ledger.reconcile(t)
	ledger.syncSource(t)
	if ordinaryCLI {
		verifyFinancialCommonSync(t, children, commonNode, ledger.height)
	}
	nativeSyncOffCommon(t, network.Fixture, commonNode, ledger.height)
	nativeProbeRPCParity(t, network.Fixture, commonNode, fundingTX)
	t.Logf("FINANCIAL_TWO_DOMAIN_TRACE_PASS ordinaryCLI=%v clxProcesses=%v dexSidecars=7 RPCCommon=1 independentDEXOffSyncCommon=1; normal CLI mode additionally has 7 supervising Common processes; isolated loopback, not WAN", ordinaryCLI, network.PIDs())
}
