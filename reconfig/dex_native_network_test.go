package reconfig_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

func nativeUnits(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }
func nativeSignedTX(t *testing.T, key *ecdsa.PrivateKey, chain *big.Int, nonce uint64, op uint8, value int64, gas uint64) *types.Transaction {
	t.Helper()
	data, err := (protocol.NativeCall{Operation: op}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(types.NewTransaction(nonce, params.DEXSettlementAddress, nativeUnits(value), gas, big.NewInt(params.FixedBaseFeePerGas*2), data), types.NewEIP155Signer(chain), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

type nativeReceipt struct {
	BlockHash               common.Hash    `json:"blockHash"`
	BlockNumber             hexutil.Uint64 `json:"blockNumber"`
	Status                  hexutil.Uint64 `json:"status"`
	GasUsed                 hexutil.Uint64 `json:"gasUsed"`
	EffectiveGasPrice       *hexutil.Big   `json:"effectiveGasPrice"`
	CommonTxApprover        common.Address `json:"commonTxApprover"`
	CommonTxRewardRecipient common.Address `json:"commonTxRewardRecipient"`
	CommonTxApproverReward  *hexutil.Big   `json:"commonTxApproverReward"`
	Logs                    []*types.Log   `json:"logs"`
}

func nativeWaitReceipt(t *testing.T, c *rpc.Client, hash common.Hash) nativeReceipt {
	t.Helper()
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		var receipt *nativeReceipt
		if err := c.Call(&receipt, "eth_getTransactionReceipt", hash); err != nil {
			t.Fatal(err)
		}
		if receipt != nil {
			return *receipt
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("native receipt timeout tx=%s", hash.Hex())
		}
	}
}
func nativeEvidence(t *testing.T, c *rpc.Client, p nativeProjection) clxevidence.RangeEvidence {
	t.Helper()
	e := clxevidence.RangeEvidence{}
	for i := uint64(1); i <= p.Header.Number.Uint64(); i++ {
		var raw hexutil.Bytes
		if err := c.Call(&raw, "dexfixture_block", hexutil.Uint64(i)); err != nil {
			t.Fatal(err)
		}
		e.Blocks = append(e.Blocks, raw)
	}
	keys := []string{common.Hash(protocol.InboxCountStorageKey()).Hex()}
	for _, entry := range p.Entries {
		keys = append(keys, common.Hash(protocol.InboxEntryStorageKey(entry.Index)).Hex())
	}
	var proof ethapi.AccountResult
	if err := c.Call(&proof, "eth_getProof", params.DEXSettlementAddress, keys, rpc.BlockNumberOrHashWithHash(p.Header.Hash(), true)); err != nil {
		t.Fatal(err)
	}
	decode := func(paths []string) [][]byte {
		out := make([][]byte, len(paths))
		for i, p := range paths {
			b, err := hexutil.Decode(p)
			if err != nil {
				t.Fatal(err)
			}
			out[i] = b
		}
		return out
	}
	e.AccountProof = decode(proof.AccountProof)
	e.CountProof = decode(proof.StorageProof[0].Proof)
	for i, entry := range p.Entries {
		e.Entries = append(e.Entries, clxevidence.EntryProof{Entry: entry, Proof: decode(proof.StorageProof[i+1].Proof)})
	}
	return e
}

func TestFHSNativeDepositRPCFinalityEvidence(t *testing.T) {
	if os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" {
		t.Skip("isolated real CLX process test opt-in")
	}
	keys := make([]*ecdsa.PrivateKey, 3)
	owners := make([]common.Address, 3)
	alloc := core.GenesisAlloc{}
	for i := range keys {
		var err error
		keys[i], err = crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		owners[i] = crypto.PubkeyToAddress(keys[i].PublicKey)
		alloc[owners[i]] = core.GenesisAccount{Balance: nativeUnits(1000)}
	}
	members := make([]*common.Cnode, 7)
	nodes := make([]common.Cnode, 7)
	recipients := make([][20]byte, 7)
	for i := range members {
		var secret bls.SecretKey
		secret.SetByCSPRNG()
		recipients[i][19] = byte(101 + i)
		nodes[i] = common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 34000+i), Public: secret.GetPublicKey().SerializeToHexStr(), CoinBase: common.Address(recipients[i]).Hex()}
		members[i] = &nodes[i]
	}
	marketSeed, err := protocol.NativeMarketSeed([20]byte(owners[2]))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &params.DEXDevnetConfig{Version: 2, ActivationBlock: 1, DEXID: common.Hash(protocol.Digest("native-rpc-devnet", []byte(t.Name()))), GenesisSeed: common.Hash(marketSeed), Custody: params.DEXSettlementAddress, Committee: nodes, MaxCheckpoints: 128}
	network := reconfig.NewFHSNativeNetwork(t, cfg, alloc)
	commonNode := startFHSRewardCommon(t, network.Fixture, nativeCommonOptions{P2P: nativeSyncPeers()})
	endpoints := network.Endpoints()
	clients := make([]*rpc.Client, 7)
	for i, endpoint := range endpoints {
		var err error
		clients[i], err = rpc.DialHTTP(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(clients[i].Close)
	}
	chain := network.Fixture.Genesis.Config
	txs := []*types.Transaction{nativeSignedTX(t, keys[0], chain.ChainID, 0, protocol.NativeDeposit, 100, 500000), nativeSignedTX(t, keys[1], chain.ChainID, 0, protocol.NativeDeposit, 100, 500000), nativeSignedTX(t, keys[2], chain.ChainID, 0, protocol.NativeSupport, 20, 500000), nativeSignedTX(t, keys[2], chain.ChainID, 1, protocol.NativeInsurance, 5, 500000)}
	for _, tx := range txs {
		if err := commonNode.Submit(tx); err != nil {
			t.Fatal(err)
		}
	}
	var target uint64
	gasByOwner := map[common.Address]*big.Int{}
	totalReward := new(big.Int)
	totalBurn := new(big.Int)
	for _, tx := range txs {
		r := nativeWaitReceipt(t, clients[0], tx.Hash())
		if uint64(r.Status) != types.ReceiptStatusSuccessful || len(r.Logs) != 1 || r.Logs[0].Topics[0] != settlement.NativeFundingTopic {
			t.Fatalf("native receipt failed %+v", r)
		}
		if uint64(r.BlockNumber) > target {
			target = uint64(r.BlockNumber)
		}
		payer, err := types.Sender(types.NewEIP155Signer(chain.ChainID), tx)
		if err != nil {
			t.Fatal(err)
		}
		fee := new(big.Int).Mul(new(big.Int).SetUint64(uint64(r.GasUsed)), (*big.Int)(r.EffectiveGasPrice))
		if gasByOwner[payer] == nil {
			gasByOwner[payer] = new(big.Int)
		}
		gasByOwner[payer].Add(gasByOwner[payer], fee)
		if r.CommonTxApprover != crypto.PubkeyToAddress(network.Fixture.OperatorKey.PublicKey) || r.CommonTxRewardRecipient != network.Fixture.RewardRecipient || (*big.Int)(r.CommonTxApproverReward).Cmp(new(big.Int).Div(new(big.Int).Set(fee), big.NewInt(5))) != 0 {
			t.Fatal("native gas admission reward mismatch")
		}
		totalReward.Add(totalReward, (*big.Int)(r.CommonTxApproverReward))
		totalBurn.Add(totalBurn, new(big.Int).Sub(fee, (*big.Int)(r.CommonTxApproverReward)))
		for _, other := range clients[1:] {
			if actual := nativeWaitReceipt(t, other, tx.Hash()); !reflect.DeepEqual(actual, r) {
				t.Fatal("native receipts differ across validators")
			}
		}
		t.Logf("CLX_FINALIZED tx=%s height=%d hash=%s status=%d gas=%d payer=%s commonRecipient=%s", tx.Hash().Hex(), r.BlockNumber, r.BlockHash.Hex(), r.Status, r.GasUsed, payer.Hex(), r.CommonTxRewardRecipient.Hex())
	}
	network.WaitFinalized(target)
	ref := hexutil.EncodeUint64(target)
	var projection nativeProjection
	if err := clients[0].Call(&projection, "dexfixture_projection", ref); err != nil {
		t.Fatal(err)
	}
	if projection.Engine != (engine.ProcessMetrics{}) {
		t.Fatal("CLX unexpectedly executed DEX engine")
	}
	if projection.Status.Deposits != 4 || projection.Balance.Cmp(nativeUnits(225)) != 0 || projection.Buckets[settlement.Unconsumed].Big().Cmp(nativeUnits(200)) != 0 || projection.Buckets[settlement.Support].Big().Cmp(nativeUnits(20)) != 0 || projection.Buckets[settlement.Insurance].Big().Cmp(nativeUnits(5)) != 0 {
		t.Fatalf("native source accounting %+v", projection)
	}
	for _, c := range clients[1:] {
		var actual nativeProjection
		if err := c.Call(&actual, "dexfixture_projection", ref); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, projection) {
			t.Fatal("native projection roots/buckets mismatch")
		}
	}
	for i, owner := range owners {
		var got hexutil.Big
		if err := clients[0].Call(&got, "eth_getBalance", owner, ref); err != nil {
			t.Fatal(err)
		}
		paid := int64(100)
		if i == 2 {
			paid = 25
		}
		want := new(big.Int).Sub(nativeUnits(1000-paid), gasByOwner[owner])
		if (*big.Int)(&got).Cmp(want) != 0 {
			t.Fatalf("wallet/gas mismatch owner=%s got=%s want=%s", owner, (*big.Int)(&got), want)
		}
	}
	var rewardBalance hexutil.Big
	if err := clients[0].Call(&rewardBalance, "eth_getBalance", network.Fixture.RewardRecipient, ref); err != nil {
		t.Fatal(err)
	}
	if (*big.Int)(&rewardBalance).Cmp(new(big.Int).Add(big.NewInt(123), totalReward)) != 0 {
		t.Fatal("Common reward balance mismatch")
	}
	genesis := network.Fixture.Genesis.ToBlock(nil).Header()
	domain := protocol.Domain{Version: 1, ChainID: chain.ChainID.Uint64(), Genesis: protocol.Hash(genesis.Hash()), DEXID: protocol.Hash(cfg.DEXID), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	verifier, err := clxevidence.New(clxevidence.Config{ChainID: domain.ChainID, Genesis: genesis, ChainConfig: chain, Seed: chain.FairHotstuffSeed, DEXID: domain.DEXID, Custody: cfg.Custody, Epochs: []clxevidence.CommitteeEpoch{{First: 1, End: ^uint64(0), KeyHash: network.Fixture.KeyBlock.Hash(), Members: network.Fixture.Committee}}})
	if err != nil {
		t.Fatal(err)
	}
	// Source Common reexecutes the committee's canonical blocks through the
	// ordinary full block import. The independent follower uses ETH downloader.
	var blocks types.Blocks
	for height := uint64(1); height <= target; height++ {
		var raw hexutil.Bytes
		if err := clients[0].Call(&raw, "dexfixture_block", hexutil.Uint64(height)); err != nil {
			t.Fatal(err)
		}
		var block types.Block
		if err := rlp.DecodeBytes(raw, &block); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, &block)
	}
	beforeSync := engine.Metrics()
	if index, err := commonNode.Service.BlockChain().InsertChain(blocks); err != nil {
		t.Fatalf("source Common ordinary block replay index=%d: %v", index, err)
	}
	if engine.Metrics() != beforeSync {
		t.Fatal("CLX block replay invoked DEX engine")
	}
	nativeSyncOffCommon(t, network.Fixture, commonNode, target)
	evidence := nativeEvidence(t, clients[0], projection)
	verified, err := verifier.VerifyRange(0, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Count() != 4 {
		t.Fatal("verified count")
	}
	market, err := engine.New(engine.Config{Domain: domain, Oracle: [20]byte(owners[2]), Custody: [20]byte(cfg.Custody), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	execution := &devnet.Execution{Market: market, Registry: registry, Native: &devnet.NativeContext{Seed: protocol.Hash(cfg.GenesisSeed), Verifier: verifier}}
	initial, root, err := execution.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	action, err := devnet.EncodeInboxAction(evidence)
	if err != nil {
		t.Fatal(err)
	}
	result, err := execution.Execute(initial, action, consensus.ExecutionContext{Domain: domain, Height: 1, ParentRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := execution.Decode(result.State)
	if err != nil {
		t.Fatal(err)
	}
	if state.Total != "225000000000000000000" || state.InboxCursor != 4 || result.CLXHash != protocol.Hash(projection.Header.Hash()) {
		t.Fatal("proof-driven financial credit mismatch")
	}
	if _, err = execution.Execute(result.State, action, consensus.ExecutionContext{Domain: domain, Height: 2, ParentRoot: result.PostRoot}); err == nil {
		t.Fatal("duplicate native proof credited twice")
	}
	t.Logf("CLX7 pids=%v; ordinary RPC/admission/TxQUIC/FHS native custody=225 CLX; gas=%s reward=%s burn=%s; finality+inclusion verified anchor=%s; schema3 DEX credit=225 CLX; observed CLX engine instances/actions/inbox imports=0/0/0", network.PIDs(), new(big.Int).Add(totalReward, totalBurn), totalReward, totalBurn, projection.Header.Hash().Hex())
}
