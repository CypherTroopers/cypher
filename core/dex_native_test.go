package core

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
)

type nativeTXChain struct{ genesis *types.Block }

func (c nativeTXChain) Engine() consensus.Engine { return colossusX.NewFaker() }
func (c nativeTXChain) GetHeader(hash common.Hash, n uint64) *types.Header {
	if n == 0 && hash == c.genesis.Hash() {
		return c.genesis.Header()
	}
	return nil
}
func (c nativeTXChain) GetHeaderByNumber(n uint64) *types.Header {
	if n == 0 {
		return c.genesis.Header()
	}
	return nil
}

type nativeTXFixture struct {
	config *params.ChainConfig
	st     *state.StateDB
	chain  nativeTXChain
	key    *ecdsa.PrivateKey
	sender common.Address
	header *types.Header
}

func newNativeTXFixture(t *testing.T, accessLimit uint64, activation ...uint64) *nativeTXFixture {
	return newNativeTXVersionFixture(t, accessLimit, 2, activation...)
}

func newNativeTXVersionFixture(t *testing.T, accessLimit uint64, version uint16, activation ...uint64) *nativeTXFixture {
	t.Helper()
	cfg := *params.TestChainConfig
	cfg.ChainID = big.NewInt(10101919)
	cfg.FixedCommittee = true
	cfg.FairHotstuff = true
	cfg.FairHotstuffSeed = common.Hash{42}
	cfg.GenCommittee = make(params.GenesisCommittee)
	var nodes []common.Cnode
	for i := 0; i < 7; i++ {
		var k bls.SecretKey
		if err := k.SetDecString(fmt.Sprint(801 + i)); err != nil {
			t.Fatal(err)
		}
		node := common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 27000+i), Public: k.GetPublicKey().SerializeToHexStr(), CoinBase: common.Address{19: byte(i + 10)}.Hex()}
		nodes = append(nodes, node)
		cfg.GenCommittee[i] = node
	}
	cfg.DEXDevnet = &params.DEXDevnetConfig{Version: version, ActivationBlock: 1, DEXID: common.Hash{22}, GenesisSeed: common.Hash{23}, Custody: params.DEXSettlementAddress, Committee: nodes, MaxCheckpoints: 100}
	if len(activation) > 0 {
		cfg.DEXDevnet.ActivationBlock = activation[0]
	}
	if accessLimit > 0 {
		cfg.NativeParallel = params.SolanaScaleEVMParallelConfig()
		cfg.NativeParallel.MaxAccessesPerTransaction = accessLimit
		cfg.SetModernForkConfig(modernCompatGenesis(9).Config.ModernForkConfig())
	}
	key, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000077")
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	commit, err := params.FairHotstuffGenesisCommitment(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := rawdb.NewMemoryDatabase()
	g := &Genesis{Config: &cfg, Mixhash: commit, GasLimit: 64000000, Difficulty: big.NewInt(1), Alloc: GenesisAlloc{sender: {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(25), nil)}}}
	genesis, err := g.Commit(db)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New(genesis.Root(), state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(1), ParentHash: genesis.Hash(), GasLimit: 64000000, Difficulty: big.NewInt(1), Time: 1}
	return &nativeTXFixture{&cfg, st, nativeTXChain{genesis}, key, sender, header}
}
func (f *nativeTXFixture) tx(t *testing.T, nonce uint64, value *big.Int, gas uint64, data []byte) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTransaction(nonce, params.DEXSettlementAddress, value, gas, big.NewInt(params.FixedTransferGasPricePerGas), data), types.NewEIP155Signer(f.config.ChainID), f.key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}
func (f *nativeTXFixture) apply(t *testing.T, tx *types.Transaction, debug vm.Config) (*types.Receipt, error) {
	t.Helper()
	f.st.Prepare(tx.Hash(), common.Hash{1}, int(tx.Nonce()))
	var gas uint64
	author := common.Address{33}
	return ApplyTransaction(f.config, f.chain, &author, new(GasPool).AddGas(64000000), f.st, f.header, tx, &gas, debug)
}

func TestDEXNativeSignedTransactionValueReceiptReplayAndRestart(t *testing.T) {
	f := newNativeTXFixture(t, 1000)
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	value := big.NewInt(123456)
	tx := f.tx(t, 0, value, 600000, call)
	receipt, err := f.apply(t, tx, vm.Config{})
	if err != nil || receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("native deposit: receipt=%+v err=%v", receipt, err)
	}
	if receipt.GasUsed <= params.TxGas || receipt.GasUsed >= tx.Gas() || len(receipt.Logs) != 1 || receipt.Logs[0].Topics[0] != settlement.NativeFundingTopic || f.st.GetNonce(f.sender) != 1 || f.st.GetBalance(params.DEXSettlementAddress).Cmp(value) != 0 {
		t.Fatal("native receipt/value/nonce/gas")
	}
	entry, err := settlement.ReadNativeEntry(f.st, params.DEXSettlementAddress, 0)
	if err != nil || entry.Sender != [20]byte(f.sender) || entry.Owner != [20]byte(f.sender) || entry.Nonce != 0 || entry.Genesis != protocol.Hash(f.chain.genesis.Hash()) || entry.Amount.Big().Cmp(value) != 0 {
		t.Fatal("stable authenticated inbox", err)
	}
	if _, err = f.apply(t, tx, vm.Config{}); err == nil {
		t.Fatal("signed transaction replay accepted")
	}
	root, err := f.st.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	f.st, err = state.New(root, f.st.Database(), nil)
	if err != nil {
		t.Fatal(err)
	}
	read, err := settlement.ReadNativeEntry(f.st, params.DEXSettlementAddress, 0)
	if err != nil || read != entry {
		t.Fatal("restart changed inbox", err)
	}
	status, buckets, surplus, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || status.Deposits != 1 || buckets[settlement.Unconsumed].Big().Cmp(value) != 0 || surplus.Big().Sign() != 0 {
		t.Fatal("native storage", err)
	}
}

func TestDEXNativeFundingSourceIdentityBindsSignedValue(t *testing.T) {
	f := newNativeTXFixture(t, 1000)
	initial := f.st.Copy()
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	var first protocol.InboxEntry
	var firstID protocol.Hash
	for _, value := range []int64{1, 2} {
		// These are alternative executions of the same genesis state, sender and
		// nonce. The test does not rely on nonce-replay rejection for identity.
		f.st = initial.Copy()
		tx := f.tx(t, 0, big.NewInt(value), 600000, call)
		receipt, err := f.apply(t, tx, vm.Config{})
		if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatal("alternative funding transaction", receipt, err)
		}
		entry, err := settlement.ReadNativeEntry(f.st, params.DEXSettlementAddress, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, err := entry.SourceID()
		if err != nil {
			t.Fatal(err)
		}
		if value == 1 {
			first, firstID = entry, id
			continue
		}
		if entry.Sender != first.Sender || entry.Nonce != first.Nonce || entry.Index != first.Index || entry.Amount == first.Amount || entry.PayloadHash == first.PayloadHash || id == firstID {
			t.Fatal("signed TX.value did not change funding payload/source identity")
		}
	}
}

func TestDEXNativeRevertOOGAndMalformedCallsPreserveFunds(t *testing.T) {
	f := newNativeTXFixture(t, 0)
	valid, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	for i, test := range []struct {
		name  string
		input []byte
		value int64
		gas   uint64
	}{{"empty", nil, 5, 600000}, {"wrong-value", valid, 0, 600000}, {"out-of-gas", valid, 5, 22000}, {"trailing", append(append([]byte(nil), valid...), 0), 5, 600000}} {
		t.Run(test.name, func(t *testing.T) {
			receipt, err := f.apply(t, f.tx(t, uint64(i), big.NewInt(test.value), test.gas, test.input), vm.Config{})
			if err != nil || receipt.Status != types.ReceiptStatusFailed || len(receipt.Logs) != 0 {
				t.Fatal("expected execution failure", receipt, err)
			}
			if f.st.GetBalance(params.DEXSettlementAddress).Sign() != 0 || f.st.GetNonce(f.sender) != uint64(i+1) {
				t.Fatal("revert balance/nonce")
			}
			status, _, _, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
			if err != nil || status.Deposits != 0 {
				t.Fatal("failed call retained inbox", err)
			}
		})
	}
}

func TestDEXNativeSimulationTraceAndForcedSurplus(t *testing.T) {
	f := newNativeTXFixture(t, 0)
	call, _ := (protocol.NativeCall{Operation: protocol.NativeSupport}).Encode()
	tx := f.tx(t, 0, big.NewInt(25), 600000, call)
	before := new(big.Int).Set(f.st.GetBalance(f.sender))
	simulation := f.st.Copy()
	msg, err := tx.AsMessage(types.NewEIP155Signer(f.config.ChainID))
	if err != nil {
		t.Fatal(err)
	}
	author := common.Address{33}
	ctx := NewEVMContextWithConfig(f.config, msg, f.header, f.chain, &author)
	logger := vm.NewStructLogger(nil)
	evm := vm.NewEVM(ctx, simulation, f.config, vm.Config{Debug: true, Tracer: logger})
	result, err := ApplyMessage(evm, msg, new(GasPool).AddGas(64000000))
	if err != nil || result.Failed() || len(logger.Output()) != protocol.InboxEntrySize {
		t.Fatal("simulation/trace", result, err)
	}
	if f.st.GetBalance(f.sender).Cmp(before) != 0 || f.st.GetBalance(params.DEXSettlementAddress).Sign() != 0 {
		t.Fatal("simulation persisted credit")
	}
	// A forced native transfer is not a deposit or reward source. Exercise a
	// value above u128 to ensure the financial bucket bound cannot freeze it.
	forced := new(big.Int).Lsh(big.NewInt(1), 160)
	f.st.AddBalance(params.DEXSettlementAddress, forced)
	receipt, err := f.apply(t, tx, vm.Config{})
	if err != nil || receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("surplus froze custody", err)
	}
	_, buckets, surplus, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || surplus.Big().Cmp(forced) != 0 || buckets[settlement.Support].Big().Cmp(big.NewInt(25)) != 0 || buckets[settlement.Fees].Big().Sign() != 0 {
		t.Fatal("surplus source confusion", err)
	}
}

func TestDEXNativeUsesResourceRecordingAndGenesisActivation(t *testing.T) {
	f := newNativeTXFixture(t, 2)
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	tx := f.tx(t, 0, big.NewInt(1), 600000, call)
	if _, err := f.apply(t, tx, vm.Config{}); err == nil {
		t.Fatal("native bypassed StateDB access recorder")
	}
	if f.st.GetNonce(f.sender) != 0 || f.st.GetBalance(params.DEXSettlementAddress).Sign() != 0 {
		t.Fatal("resource failure did not revert block execution")
	}
	if !vm.IsPrecompiledContract(params.DEXSettlementAddress, f.config.CypheriumRules(big.NewInt(1), 1)) {
		t.Fatal("estimate mistakes native custody for EOA")
	}
	if vm.IsPrecompiledContract(params.DEXSettlementAddress, params.TestChainConfig.Rules(big.NewInt(1))) {
		t.Fatal("DEX enabled by local default")
	}
}

func TestDEXNativeSelfDestructSurplusAndWrongChainSignature(t *testing.T) {
	f := newNativeTXFixture(t, 0)
	contract := common.Address{70}
	code := append([]byte{0x73}, params.DEXSettlementAddress[:]...)
	code = append(code, 0xff)
	f.st.SetCode(contract, code)
	f.st.SetNonce(contract, 1)
	f.st.AddBalance(contract, big.NewInt(19))
	tx, err := types.SignTx(types.NewTransaction(0, contract, new(big.Int), 100000, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.NewEIP155Signer(f.config.ChainID), f.key)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.apply(t, tx, vm.Config{})
	if err != nil || receipt.Status != types.ReceiptStatusSuccessful || f.st.GetBalance(params.DEXSettlementAddress).Cmp(big.NewInt(19)) != 0 {
		t.Fatal("selfdestruct fixture", err)
	}
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	wrong, err := types.SignTx(types.NewTransaction(1, params.DEXSettlementAddress, big.NewInt(1), 600000, big.NewInt(params.FixedTransferGasPricePerGas), call), types.NewEIP155Signer(big.NewInt(9)), f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.apply(t, wrong, vm.Config{}); err == nil {
		t.Fatal("foreign chain signed deposit admitted")
	}
	if f.st.GetNonce(f.sender) != 1 {
		t.Fatal("invalid signature consumed nonce")
	}
	receipt, err = f.apply(t, f.tx(t, 1, big.NewInt(7), 600000, call), vm.Config{})
	if err != nil || receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("forced surplus blocks deposit", err)
	}
	status, buckets, surplus, err := settlement.NativeStatus(f.st, params.DEXSettlementAddress)
	if err != nil || status.Deposits != 1 || buckets[settlement.Unconsumed].Big().Cmp(big.NewInt(7)) != 0 || surplus.Big().Cmp(big.NewInt(19)) != 0 {
		t.Fatal("selfdestruct credited as fee/deposit", err)
	}
}

func TestDEXNativeSimulationResourceAdmissionMatchesExecution(t *testing.T) {
	f := newNativeTXFixture(t, 2)
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	tx := f.tx(t, 0, big.NewInt(7), 600000, call)
	msg, err := tx.AsMessage(types.NewEIP155Signer(f.config.ChainID))
	if err != nil {
		t.Fatal(err)
	}
	simulation := f.st.Copy()
	before := new(big.Int).Set(simulation.GetBalance(f.sender))
	author := common.Address{33}
	ctx := NewEVMContextWithConfig(f.config, msg, f.header, f.chain, &author)
	evm, check := NewEVMForNativeSimulation(ctx, simulation, f.config, vm.Config{}, msg.To())
	_, _ = ApplyMessage(evm, msg, new(GasPool).AddGas(64000000))
	if err = check(); err == nil {
		t.Fatal("simulation bypassed canonical resource admission")
	}
	if err2 := check(); err2 != err {
		t.Fatal("resource check is not idempotent")
	}
	if simulation.GetBalance(f.sender).Cmp(before) != 0 || simulation.GetNonce(f.sender) != 0 || simulation.GetBalance(params.DEXSettlementAddress).Sign() != 0 {
		t.Fatal("simulation resource error was not atomic")
	}
	if f.st.GetBalance(f.sender).Cmp(before) != 0 || f.st.GetNonce(f.sender) != 0 {
		t.Fatal("simulation modified canonical state")
	}
}

func TestDEXNativeActivationAndReservedGenesisAreConsensusBound(t *testing.T) {
	f := newNativeTXFixture(t, 0, 2)
	call, _ := (protocol.NativeCall{Operation: protocol.NativeDeposit}).Encode()
	receipt, err := f.apply(t, f.tx(t, 0, big.NewInt(5), 600000, call), vm.Config{})
	if err != nil || receipt.Status != types.ReceiptStatusFailed {
		t.Fatal("preactivation native call admitted", err)
	}
	f.header.Number = big.NewInt(2)
	receipt, err = f.apply(t, f.tx(t, 1, big.NewInt(5), 600000, call), vm.Config{})
	if err != nil || receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("activation boundary rejected", err)
	}
	for _, reserved := range []GenesisAccount{{Balance: new(big.Int)}, {Balance: big.NewInt(1)}, {Balance: new(big.Int), Code: []byte{0}}, {Balance: new(big.Int), Storage: map[common.Hash]common.Hash{{1}: {2}}}} {
		g := &Genesis{Config: f.config, Mixhash: f.chain.genesis.Header().MixDigest, Difficulty: big.NewInt(1), Alloc: GenesisAlloc{params.DEXSettlementAddress: reserved}}
		if _, err := g.Commit(rawdb.NewMemoryDatabase()); err == nil {
			t.Fatal("genesis allocated protocol-owned custody")
		}
	}
	changed := *f.config
	dex := *f.config.DEXDevnet
	dex.ActivationBlock++
	changed.DEXDevnet = &dex
	g := &Genesis{Config: &changed, Mixhash: f.chain.genesis.Header().MixDigest, Difficulty: big.NewInt(1), Alloc: GenesisAlloc{}}
	if _, err := g.Commit(rawdb.NewMemoryDatabase()); err == nil {
		t.Fatal("native activation changed without genesis commitment")
	}
	input := make([]byte, protocol.MaxNativeCallBytes)
	input[6] = protocol.NativeCheckpoint
	if settlement.RequiredNativeGas(input)+params.TxGas+uint64(len(input))*params.TxDataNonZeroGasEIP2028 > params.MaxTxGas {
		t.Fatal("native maximum input cannot fit Osaka gas cap")
	}
}
