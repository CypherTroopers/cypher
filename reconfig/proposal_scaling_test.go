package reconfig

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestHighBacklogProposalIsChunked(t *testing.T) {
	if got := blockMaxTxCount(types.FastTx_Block); got != 16384 {
		t.Fatalf("fast proposal tx limit = %d, want 16384", got)
	}
	if got := blockMaxTxCount(types.SlowTx_Block); got != 16384 {
		t.Fatalf("slow proposal tx limit = %d, want 16384", got)
	}
	if got := blockProposalLimit(types.FastTx_Block, 250000); got != 512 {
		t.Fatalf("high-backlog per-account limit = %d, want 512", got)
	}
	if got := blockProposalLimit(types.SlowTx_Block, 250000); got != 512 {
		t.Fatalf("high-backlog slow per-account limit = %d, want 512", got)
	}
	const singleSenderBurst = 20000
	if blocks := (singleSenderBurst + fastPerAccountTierLarge - 1) / fastPerAccountTierLarge; blocks != 40 {
		t.Fatalf("%d sequential transactions require %d bounded proposals, want 40", singleSenderBurst, blocks)
	}
	const submitted = 250000
	blocks := (submitted + int(fastBlockMaxTxCount) - 1) / int(fastBlockMaxTxCount)
	if blocks != 16 {
		t.Fatalf("%d transactions require %d proposal chunks, want 16", submitted, blocks)
	}
}

func TestGenesisNativeProposalUsesRaisedConsensusCeilings(t *testing.T) {
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	if got := blockMaxTxCountForConfig(config, types.FastTx_Block); got != config.NativeParallel.MaxTransactionsPerBlock {
		t.Fatalf("native block transaction limit = %d, want %d", got, config.NativeParallel.MaxTransactionsPerBlock)
	}
	if got := proposalByteLimit(config, types.FastTx_Block); got != config.NativeParallel.MaxBlockBytes {
		t.Fatalf("native proposal byte limit = %d, want %d", got, config.NativeParallel.MaxBlockBytes)
	}
	serialLimit := params.FairHotstuffEVMWorkLimitsForConfig(config).TransactionsPerSender
	if got := blockProposalLimitForConfig(config, types.FastTx_Block, 1_000_000); uint64(got) != serialLimit {
		t.Fatalf("EVM per-sender proposal limit = %d, want %d", got, serialLimit)
	}
	maxTx, perAccount := proposalPoolScanLimitsForConfig(config, types.FastTx_Block, 1_000_000, false)
	if uint64(maxTx) != config.NativeParallel.MaxTransactionsPerBlock {
		t.Fatalf("native proposal scan limit = %d, want %d", maxTx, config.NativeParallel.MaxTransactionsPerBlock)
	}
	if uint64(perAccount) != serialLimit {
		t.Fatalf("EVM proposal per-account scan limit = %d, want %d", perAccount, serialLimit)
	}
	maxTx, perAccount = proposalPoolScanLimitsForConfig(config, types.FastTx_Block, 1_000_000, true)
	if uint64(maxTx) != 2*config.NativeParallel.MaxTransactionsPerBlock || uint64(perAccount) != 2*serialLimit {
		t.Fatalf("two-chain EVM proposal scan limits = %d/%d, want %d/%d", maxTx, perAccount, 2*config.NativeParallel.MaxTransactionsPerBlock, 2*serialLimit)
	}
}

func TestEVMOnlyProposalRoutesBothResourceLanesToStandardEVM(t *testing.T) {
	strict := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	evmOnly := strict
	if useNativeProposalBuilder(evmOnly, types.FastTx_Block) || useNativeProposalBuilder(evmOnly, types.SlowTx_Block) {
		t.Fatal("EVM-only genesis selected the native builder for a transaction lane")
	}
	if !isEVMOnlyProposalMode(evmOnly) {
		t.Fatal("EVM-only genesis did not select the EVM work limits and meter")
	}
	if useNativeProposalBuilder(&params.ChainConfig{}, types.FastTx_Block) {
		t.Fatal("legacy network selected the native proposal builder")
	}
	retired := *evmOnly.NativeParallel
	retired.RequireNativeTransactions = true
	invalid := &params.ChainConfig{NativeParallel: &retired}
	if useNativeProposalBuilder(invalid, types.FastTx_Block) || useNativeProposalBuilder(invalid, types.SlowTx_Block) || !isEVMOnlyProposalMode(invalid) {
		t.Fatal("retired strict flag re-enabled the public native proposal builder")
	}

	wantLimit := params.FairHotstuffEVMWorkLimitsForConfig(evmOnly).Transactions
	for _, blockType := range []uint8{types.FastTx_Block, types.SlowTx_Block} {
		if got := blockMaxTxCountForConfig(evmOnly, blockType); got != wantLimit {
			t.Fatalf("EVM-only %s scan limit = %d, want %d", readableTxBlockType(blockType), got, wantLimit)
		}
	}
	wantClasses := map[uint8][]core.TxResourceClass{
		types.FastTx_Block: {core.TxClassNative, core.TxClassERC20, core.TxClassSmallCall},
		types.SlowTx_Block: {core.TxClassDex, core.TxClassDeploy, core.TxClassHeavy, core.TxClassData},
	}
	for blockType, want := range wantClasses {
		got := pendingClassesForBlockType(blockType)
		if len(got) != len(want) {
			t.Fatalf("EVM-only %s resource classes = %v, want %v", readableTxBlockType(blockType), got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("EVM-only %s resource classes = %v, want %v", readableTxBlockType(blockType), got, want)
			}
		}
	}
}

func TestEVMOnlyProposalResourceClassesUseConfiguredBlockCeiling(t *testing.T) {
	config := &params.ChainConfig{NativeParallel: params.SolanaScaleNativeParallelConfig()}
	config.NativeParallel.RequireNativeTransactions = false
	const gasTarget = uint64(9_000_000)
	budget := newTxResourceBudgetForConfig(config, types.SlowTx_Block, gasTarget, backlogEmergencyDrainPendingThreshold)
	wantTx := config.NativeParallel.MaxTransactionsPerBlock
	for _, class := range []core.TxResourceClass{core.TxClassDeploy, core.TxClassHeavy, core.TxClassData, core.TxClassDex} {
		if got := budget.txCaps[class]; got != wantTx {
			t.Fatalf("class %s transaction cap = %d, want %d", class, got, wantTx)
		}
		if got := budget.gasCaps[class]; got != gasTarget {
			t.Fatalf("class %s gas cap = %d, want %d", class, got, gasTarget)
		}
	}
}

func TestFHSAdmissionBatchLimitPreservesDeterministicNoncePrefixes(t *testing.T) {
	firstAddress := common.Address{1}
	secondAddress := common.Address{2}
	to := common.Address{9}
	first := types.Transactions{
		types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(1, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(2, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
	}
	second := types.Transactions{
		types.NewTransaction(3, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(4, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
	}
	batchA, batchB, batchC := common.Hash{0xa}, common.Hash{0xb}, common.Hash{0xc}
	batchByTx := map[common.Hash]common.Hash{
		first[0].Hash():  batchA,
		first[1].Hash():  batchA,
		first[2].Hash():  batchB,
		second[0].Hash(): batchC,
		second[1].Hash(): batchA,
	}
	// Insert addresses in reverse order to ensure map iteration cannot decide
	// which certificate consumes the bound.
	got := limitFHSAdmissionBatchPrefixes(AddressTxes{secondAddress: second, firstAddress: first}, 2, func(tx *types.Transaction) (common.Hash, bool) {
		id, ok := batchByTx[tx.Hash()]
		return id, ok
	})
	if len(got[firstAddress]) != 2 {
		t.Fatalf("first sender prefix length = %d, want 2", len(got[firstAddress]))
	}
	if len(got[secondAddress]) != len(second) {
		t.Fatalf("higher-yield second sender prefix length = %d, want %d", len(got[secondAddress]), len(second))
	}

	delete(batchByTx, first[1].Hash())
	got = limitFHSAdmissionBatchPrefixes(AddressTxes{firstAddress: first}, 2, func(tx *types.Transaction) (common.Hash, bool) {
		id, ok := batchByTx[tx.Hash()]
		return id, ok
	})
	if len(got[firstAddress]) != 1 {
		t.Fatalf("sender suffix survived missing earlier admission: got prefix %d, want 1", len(got[firstAddress]))
	}
}

func TestProposalSenderUsesProposalForkSigner(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1337)
	config := *params.TestChainConfig
	config.ChainID = new(big.Int).Set(chainID)
	config.EIP155Block = big.NewInt(10)
	config.SetModernForkConfig(&params.ModernForkConfig{
		BerlinBlock: big.NewInt(10),
		LondonBlock: big.NewInt(10),
	})
	defer config.SetModernForkConfig(nil)

	to := common.HexToAddress("0x5555555555555555555555555555555555555555")
	tx, err := types.SignTx(types.NewDynamicFeeTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(20),
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(1),
	}), types.NewLondonSigner(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proposalTransactionSender(&config, big.NewInt(9), tx); err == nil {
		t.Fatal("typed transaction unexpectedly recovered with the pre-London parent signer")
	}
	from, err := proposalTransactionSender(&config, big.NewInt(10), tx)
	if err != nil {
		t.Fatalf("typed transaction rejected at proposal fork height: %v", err)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey); from != want {
		t.Fatalf("proposal sender = %s, want %s", from, want)
	}
}

func TestFHSPipelineScansPastCertifiedSenderWindow(t *testing.T) {
	maxTx, perAccount := proposalPoolScanLimits(types.FastTx_Block, 20_000, true)
	if maxTx != 2*params.MaxTxCountPerBlock || perAccount != 2*params.MaxTxCountPerSenderPerBlock {
		t.Fatalf("FHS scan limits = %d/%d, want %d/%d", maxTx, perAccount, 2*params.MaxTxCountPerBlock, 2*params.MaxTxCountPerSenderPerBlock)
	}
	maxTx, perAccount = proposalPoolScanLimits(types.FastTx_Block, 20_000, false)
	if maxTx != params.MaxTxCountPerBlock || perAccount != params.MaxTxCountPerSenderPerBlock {
		t.Fatalf("non-FHS scan limits = %d/%d, want %d/%d", maxTx, perAccount, params.MaxTxCountPerBlock, params.MaxTxCountPerSenderPerBlock)
	}

	address := common.Address{1}
	txs := make(types.Transactions, 2*params.MaxTxCountPerSenderPerBlock)
	for index := range txs {
		txs[index] = types.NewTransaction(uint64(index), address, new(big.Int), 21_000, big.NewInt(1), nil)
	}
	chain := newProposedChain()
	now := time.Now()
	chain.recordProposedTransactions(txs[:params.MaxTxCountPerSenderPerBlock], now)
	available := chain.withoutProposedTxes(AddressTxes{address: txs}, now)
	available = limitAddressTxes(available, params.MaxTxCountPerSenderPerBlock)
	got := available[address]
	if len(got) != params.MaxTxCountPerSenderPerBlock || got[0].Nonce() != params.MaxTxCountPerSenderPerBlock || got[len(got)-1].Nonce() != 2*params.MaxTxCountPerSenderPerBlock-1 {
		t.Fatalf("next certified sender window = len %d nonces %d..%d", len(got), got[0].Nonce(), got[len(got)-1].Nonce())
	}
}

func TestFHSPipelineScansPastCertifiedGasWindow(t *testing.T) {
	const blockGasTarget = uint64(1_000_000)
	if got := proposalPoolScanGasTarget(blockGasTarget, true); got != 2*blockGasTarget {
		t.Fatalf("FHS scan gas target = %d, want %d", got, 2*blockGasTarget)
	}
	if got := proposalPoolScanGasTarget(blockGasTarget, false); got != blockGasTarget {
		t.Fatalf("non-FHS scan gas target = %d, want %d", got, blockGasTarget)
	}
	if got := proposalPoolScanGasTarget(math.MaxUint64, true); got != math.MaxUint64 {
		t.Fatalf("overflowing FHS scan gas target = %d, want saturation", got)
	}
}

func TestFHSProposalUsesConsensusWorkMeterBoundary(t *testing.T) {
	limits := params.FairHotstuffWorkLimits()
	env := &work{fhsWorkMeter: core.NewFHSBlockWorkMeter()}
	atLimit := types.NewTransaction(0, common.Address{1}, new(big.Int), limits.DeclaredGas, big.NewInt(1), nil)
	next, err := env.nextFHSWorkMeter(0, atLimit)
	if err != nil {
		t.Fatalf("proposal rejected exact declared-gas consensus boundary: %v", err)
	}
	env.fhsWorkMeter = next // mirrors installation after successful execution
	if _, err := env.nextFHSWorkMeter(1, types.NewTransaction(1, common.Address{1}, new(big.Int), 1, big.NewInt(1), nil)); err == nil || !strings.Contains(err.Error(), "declared gas") {
		t.Fatalf("proposal accepted transaction beyond declared-gas consensus boundary: %v", err)
	}

	// Failed execution does not install its speculative meter snapshot.
	env = &work{fhsWorkMeter: core.NewFHSBlockWorkMeter()}
	if _, err := env.nextFHSWorkMeter(0, atLimit); err != nil {
		t.Fatal(err)
	}
	if _, err := env.nextFHSWorkMeter(0, atLimit); err != nil {
		t.Fatalf("uncommitted candidate consumed proposal work budget: %v", err)
	}

	// Non-FHS proposal construction remains outside these consensus rules.
	if next, err := (&work{}).nextFHSWorkMeter(0, atLimit); err != nil || next != nil {
		t.Fatalf("non-FHS work meter result = (%v,%v), want (nil,nil)", next, err)
	}
}

func TestFHSProposalMetersFinalRewardSidecar(t *testing.T) {
	tx := types.NewTransaction(0, common.Address{1}, new(big.Int), params.TxGas, big.NewInt(1), nil)
	seed := func(t *testing.T) *core.FHSBlockWorkMeter {
		t.Helper()
		env := &work{fhsWorkMeter: core.NewFHSBlockWorkMeter()}
		next, err := env.nextFHSWorkMeter(0, tx)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	txHash := tx.Hash()
	approver := common.Address{2}
	admission := &types.CommonTxAdmissionBatch{ChainID: big.NewInt(1), GenesisHash: common.Hash{1}, Miner: approver, Timestamp: 1, TxHashes: []common.Hash{txHash}, Signature: make([]byte, 65)}
	admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	admission.AdmissionID = types.CommonTxAdmissionID(admission)
	refs := []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}
	reward := &types.CommonTxReward{TxHash: txHash, Approver: approver, ApproverReward: big.NewInt(1), Burn: big.NewInt(1)}
	if err := addFHSProposalSidecarWork(seed(t), []*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{reward}); err != nil {
		t.Fatalf("normal final proposal sidecars rejected: %v", err)
	}

	huge := &types.CommonTxReward{
		TxHash:         txHash,
		Approver:       approver,
		ApproverReward: new(big.Int).Lsh(big.NewInt(1), uint(params.MaxFHSCommonTxRewardBytesPerReward*8)),
		Burn:           new(big.Int),
	}
	if err := addFHSProposalSidecarWork(seed(t), []*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{huge}); err == nil || !strings.Contains(err.Error(), "reward 0 payload exceeds per-entry maximum") {
		t.Fatalf("proposal accepted oversized final reward sidecar: %v", err)
	}
	if err := addFHSProposalSidecarWork(seed(t), []*types.CommonTxAdmissionBatch{admission}, refs, []*types.CommonTxReward{reward, reward}); err == nil || !strings.Contains(err.Error(), "does not match admission reference count") {
		t.Fatalf("proposal accepted unrelated final rewards: %v", err)
	}
}

func TestFailedOnlyProposalRemainsPublishableForCleanup(t *testing.T) {
	// The build condition is intentionally expressed here at its boundary: a
	// failed-only selection must not take the ordinary no-work early return,
	// otherwise publication-gated failed transaction removal is unreachable.
	for _, test := range []struct {
		name          string
		txCount       int
		failedCount   int
		allowFinality bool
		wantNoWork    bool
	}{
		{name: "no work", wantNoWork: true},
		{name: "failed only", failedCount: 1},
		{name: "transaction", txCount: 1},
		{name: "finality child", allowFinality: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotNoWork := proposalHasNoPublishableWork(test.txCount, test.failedCount, test.allowFinality)
			if gotNoWork != test.wantNoWork {
				t.Fatalf("no-work decision = %t, want %t", gotNoWork, test.wantNoWork)
			}
		})
	}
}

func TestProposalNoWorkLaneSelectionAndRetryPolicy(t *testing.T) {
	realPrimary := errors.New("primary execution failure")
	realFallback := errors.New("fallback execution failure")
	wrappedNoWork := fmt.Errorf("lane empty: %w", errProposalNoWork)

	for _, test := range []struct {
		name     string
		primary  error
		fallback error
		want     error
	}{
		{name: "both empty", primary: errProposalNoWork, fallback: wrappedNoWork, want: errProposalNoWork},
		{name: "primary empty fallback failed", primary: errProposalNoWork, fallback: realFallback, want: realFallback},
		{name: "primary failed fallback empty", primary: realPrimary, fallback: errProposalNoWork, want: realPrimary},
		{name: "both failed preserves fallback", primary: realPrimary, fallback: realFallback, want: realFallback},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := proposalLaneBuildError(test.primary, test.fallback)
			if !errors.Is(got, test.want) {
				t.Fatalf("selected lane error = %v, want %v", got, test.want)
			}
		})
	}

	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "success"},
		{name: "empty", err: errProposalNoWork},
		{name: "wrapped empty", err: wrappedNoWork},
		{name: "stale view", err: hotstuff.ErrOldState},
		{name: "real failure", err: realPrimary, want: true},
	} {
		t.Run("retry "+test.name, func(t *testing.T) {
			if got := shouldRetryFHSProposalBuild(test.err); got != test.want {
				t.Fatalf("retry decision for %v = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestProposedTransactionExpiryWakesWithoutMaintenanceScan(t *testing.T) {
	chain := newProposedChain()
	start := time.Unix(1_800_000_000, 0)
	address := common.Address{1}
	tx := types.NewTransaction(0, address, new(big.Int), params.TxGas, big.NewInt(1), nil)
	chain.recordProposedTransactions(types.Transactions{tx}, start)
	wantExpiry := start.Add(proposedTxTTL)
	if chain.nextProposedExpiry != wantExpiry {
		t.Fatalf("next proposed expiry = %s, want %s", chain.nextProposedExpiry, wantExpiry)
	}

	atBoundary := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(atBoundary, wantExpiry); len(got) != 0 {
		t.Fatal("proposed transaction expired before its strict TTL boundary")
	}
	revision := chain.revision
	afterExpiry := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(afterExpiry, wantExpiry.Add(time.Nanosecond)); len(got[address]) != 1 {
		t.Fatal("expired proposed transaction remained excluded")
	}
	if chain.revision != revision+1 || !chain.nextProposedExpiry.IsZero() {
		t.Fatalf("expired exclusion state = revision %d expiry %s, want revision %d and zero expiry",
			chain.revision, chain.nextProposedExpiry, revision+1)
	}
}

func TestCertifiedProposedTransactionRemainsExcludedUntilCommit(t *testing.T) {
	chain := newProposedChain()
	start := time.Unix(1_800_000_000, 0)
	address := common.Address{2}
	tx := types.NewTransaction(0, address, new(big.Int), params.TxGas, big.NewInt(1), nil)
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), Difficulty: big.NewInt(1),
	}).WithBody(types.Transactions{tx}, nil)

	chain.head = block
	chain.recordProposedTransactions(block.Transactions(), start)
	if chain.nextProposedExpiry.IsZero() {
		t.Fatal("speculative transaction has no expiry")
	}
	revision := chain.revision
	chain.adoptCertified(block)
	if chain.revision != revision+1 {
		t.Fatalf("certification revision = %d, want %d", chain.revision, revision+1)
	}
	if len(chain.proposedTxes) != 0 || len(chain.certifiedTxes) != 1 || !chain.nextProposedExpiry.IsZero() {
		t.Fatalf("certified exclusion state = proposed %d certified %d expiry %s",
			len(chain.proposedTxes), len(chain.certifiedTxes), chain.nextProposedExpiry)
	}
	afterOldTTL := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(afterOldTTL, start.Add(1000*proposedTxTTL)); len(got) != 0 {
		t.Fatal("certified transaction expired before commit")
	}

	chain.markCommitted(block)
	if len(chain.certifiedTxes) != 0 {
		t.Fatal("committed transaction remained in certified exclusion set")
	}
	afterCommit := AddressTxes{address: types.Transactions{tx}}
	if got := chain.withoutProposedTxes(afterCommit, start.Add(1000*proposedTxTTL)); len(got[address]) != 1 {
		t.Fatal("committed transaction remained excluded")
	}
}

func TestProposalNoWorkWatermarkQuiescesIdenticalMaintenanceInputs(t *testing.T) {
	for _, fairHotstuff := range []bool{false, true} {
		mode := "legacy"
		if fairHotstuff {
			mode = "fhs"
		}
		t.Run(mode, func(t *testing.T) {
			proposedExpiry := time.Unix(1_900_000_000, 0)
			base := proposalWorkStamp{
				fairHotstuff:      fairHotstuff,
				poolRevision:      11,
				candidateRevision: 7,
				proposedRevision:  9,
				proposedExpiry:    proposedExpiry,
				parentNumber:      20,
				parentHash:        common.HexToHash("0x20"),
				keyNumber:         3,
				keyHash:           common.HexToHash("0x30"),
				view: bftview.View{
					TxNumber: 20, TxHash: common.HexToHash("0x20"),
					KeyNumber: 3, KeyHash: common.HexToHash("0x30"),
					CommitteeHash: common.HexToHash("0xc0"), LeaderIndex: 2,
					NoDone: true, Round: 4, ViewNumber: 21,
				},
				proposalView:     21,
				proposalViewID:   common.HexToHash("0x2100"),
				proposalLeaderID: "leader",
			}
			service := new(Service)
			if !service.rememberProposalNoWorkIfCurrent(base, base, true) {
				t.Fatal("failed to install exact no-work watermark")
			}
			if !service.proposalNoWorkMatchesCurrent(base, base, true) {
				t.Fatal("identical maintenance input did not remain quiescent")
			}
			if proposalNoWorkExpiryElapsed(base, proposedExpiry) {
				t.Fatal("proposed exclusion expired at the cleanup boundary")
			}
			if !proposalNoWorkExpiryElapsed(base, proposedExpiry.Add(time.Nanosecond)) {
				t.Fatal("expired proposed exclusion did not wake maintenance")
			}

			mutations := []struct {
				name   string
				mutate func(*proposalWorkStamp)
			}{
				{name: "txpool revision", mutate: func(s *proposalWorkStamp) { s.poolRevision++ }},
				{name: "candidate revision", mutate: func(s *proposalWorkStamp) { s.candidateRevision++ }},
				{name: "proposed exclusion revision", mutate: func(s *proposalWorkStamp) { s.proposedRevision++ }},
				{name: "proposed exclusion expiry", mutate: func(s *proposalWorkStamp) { s.proposedExpiry = s.proposedExpiry.Add(time.Millisecond) }},
				{name: "parent", mutate: func(s *proposalWorkStamp) { s.parentNumber++; s.parentHash = common.HexToHash("0x21") }},
				{name: "key head", mutate: func(s *proposalWorkStamp) { s.keyNumber++; s.keyHash = common.HexToHash("0x31") }},
				{name: "view", mutate: func(s *proposalWorkStamp) { s.view.ViewNumber++ }},
				{name: "finality", mutate: func(s *proposalWorkStamp) { s.finality = !s.finality }},
				{name: "key interval", mutate: func(s *proposalWorkStamp) {
					s.keyblockReady = !s.keyblockReady
					s.keyblockPending = s.keyblockReady
				}},
				{name: "proposal view", mutate: func(s *proposalWorkStamp) { s.proposalView++; s.proposalViewID = common.HexToHash("0x2200") }},
				{name: "proposal leader", mutate: func(s *proposalWorkStamp) { s.proposalLeaderID = "next-leader" }},
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					service.clearProposalNoWork()
					if !service.rememberProposalNoWorkIfCurrent(base, base, true) {
						t.Fatal("failed to reinstall no-work watermark")
					}
					current := base
					mutation.mutate(&current)
					if service.proposalNoWorkMatchesCurrent(base, current, true) {
						t.Fatal("changed proposal input remained quiescent")
					}
					service.muProposalNoWork.Lock()
					marker := service.proposalNoWork
					service.muProposalNoWork.Unlock()
					if marker != nil {
						t.Fatal("changed proposal input did not clear no-work watermark")
					}
				})
			}

			// Crossing the keyblock interval is real work while the current view is
			// still in tx mode, so it must not install a suppressing marker.
			intervalReady := base
			intervalReady.keyblockReady = true
			intervalReady.keyblockPending = true
			if service.rememberProposalNoWorkIfCurrent(intervalReady, intervalReady, true) {
				t.Fatal("pending keyblock trigger installed a no-work watermark")
			}
			service.muProposalNoWork.Lock()
			pendingMarker := service.proposalNoWork
			service.muProposalNoWork.Unlock()
			if pendingMarker != nil {
				t.Fatal("pending keyblock trigger left a no-work watermark")
			}

			// Local proposal-mode changes cannot suppress a due fixed keyblock.
			afterKeyWake := intervalReady
			afterKeyWake.view.NoDone = false
			if service.rememberProposalNoWorkIfCurrent(afterKeyWake, afterKeyWake, true) {
				t.Fatal("keyblock wake installed a no-work watermark")
			}

			// A new canonical key head resets the interval and may quiesce normally.
			afterKeyCommit := afterKeyWake
			afterKeyCommit.keyNumber++
			afterKeyCommit.keyHash = common.HexToHash("0x31")
			afterKeyCommit.keyblockReady = false
			afterKeyCommit.keyblockPending = false
			if !service.rememberProposalNoWorkIfCurrent(afterKeyCommit, afterKeyCommit, true) {
				t.Fatal("failed to install post-keyblock-commit watermark")
			}
			if !service.proposalNoWorkMatchesCurrent(afterKeyCommit, afterKeyCommit, true) {
				t.Fatal("post-keyblock-commit no-work state did not quiesce")
			}

			// A stale concurrent comparison must not erase a newer bounded marker.
			newer := afterKeyCommit
			newer.poolRevision++
			if !service.rememberProposalNoWorkIfCurrent(newer, newer, true) {
				t.Fatal("failed to replace bounded watermark")
			}
			if service.proposalNoWorkMatchesCurrent(afterKeyCommit, afterKeyCommit, true) {
				t.Fatal("stale comparison matched newer watermark")
			}
			service.muProposalNoWork.Lock()
			kept := service.proposalNoWork != nil && *service.proposalNoWork == newer
			service.muProposalNoWork.Unlock()
			if !kept {
				t.Fatal("stale comparison erased newer watermark")
			}
		})
	}
}

func TestProposalBodyWaitTimeoutScalesWithBody(t *testing.T) {
	if got := proposalBodyWaitTimeout(0); got != 2*time.Second {
		t.Fatalf("empty body timeout = %s, want 2s", got)
	}
	if got := proposalBodyWaitTimeout(16 * 1024 * 1024); got != 10*time.Second {
		t.Fatalf("16MiB body timeout = %s, want 10s", got)
	}
	if got := proposalBodyWaitTimeout(256 * 1024 * 1024); got != 30*time.Second {
		t.Fatalf("large body timeout = %s, want 30s cap", got)
	}
}

func TestProposalGenerationRejectsStaleConstruction(t *testing.T) {
	parent := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(9), Root: common.HexToHash("0x900"), Difficulty: big.NewInt(1),
	})
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number: big.NewInt(3), Difficulty: big.NewInt(1),
	})
	chain := newProposedChain()
	chain.clear(parent)
	generation := proposalGeneration{
		proposedRevision:            chain.revision,
		admissionFinalityGeneration: 7,
		parentHash:                  parent.Hash(),
		parentRoot:                  parent.Root(),
		parentNumber:                parent.NumberU64(),
		keyHash:                     keyBlock.Hash(),
		keyNumber:                   keyBlock.NumberU64(),
	}
	if !generation.matches(chain.revision, 7, parent, keyBlock) {
		t.Fatal("fresh proposal generation was rejected")
	}
	if generation.matches(chain.revision, 8, parent, keyBlock) {
		t.Fatal("proposal generation survived an admission-finality publication")
	}

	child := types.NewBlockWithHeader(&types.Header{
		ParentHash: parent.Hash(), Number: big.NewInt(10), Root: common.HexToHash("0x901"), Difficulty: big.NewInt(1),
	})
	chain.extend(child)
	if generation.matches(chain.revision, 7, parent, keyBlock) {
		t.Fatal("proposal generation survived a concurrent proposed-chain update")
	}
	if generation.matches(generation.proposedRevision, 7, child, keyBlock) {
		t.Fatal("proposal generation survived a parent change")
	}
	nextKeyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number: big.NewInt(4), Difficulty: big.NewInt(1),
	})
	if generation.matches(generation.proposedRevision, 7, parent, nextKeyBlock) {
		t.Fatal("proposal generation survived a key-committee change")
	}
}

func proposalBuildRequestForTest(view uint64) *hotstuff.FHSProposalBuildRequest {
	state := []byte{byte(view), 0xa5}
	return &hotstuff.FHSProposalBuildRequest{
		Key: hotstuff.FHSProposalBuildKey{
			RequestID:          view,
			ViewNumber:         view,
			ViewID:             common.BigToHash(new(big.Int).SetUint64(view)),
			LeaderID:           "leader",
			CurrentStateDigest: hotstuff.StateDigest(state),
		},
		CurrentState: state,
	}
}

func TestProposalBuildSchedulerKeepsOnlyLatestWaitingView(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalBuildJobs:            make(chan *proposalBuildJob, proposalBuildQueueCapacity),
		proposalBuildResults:         make(chan *hotstuff.FHSProposalBuildResult, proposalBuildWorkers+1),
		proposalValidationGeneration: 1,
	}
	first := proposalBuildRequestForTest(11)
	if err := service.ScheduleFHSProposalBuild(first); err != nil {
		t.Fatal(err)
	}
	firstJob := <-service.proposalBuildJobs // simulate the first non-interruptible worker starting
	second := proposalBuildRequestForTest(12)
	if err := service.ScheduleFHSProposalBuild(second); err != nil {
		t.Fatal(err)
	}
	secondJob := <-service.proposalBuildJobs
	service.proposalBuildJobs <- secondJob // leave it waiting so the next request must replace it
	third := proposalBuildRequestForTest(13)
	if err := service.ScheduleFHSProposalBuild(third); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstJob.ctx.Done():
	default:
		t.Fatal("superseded running proposal construction was not cancelled")
	}
	select {
	case <-secondJob.ctx.Done():
	default:
		t.Fatal("superseded queued proposal construction was not cancelled")
	}
	if len(service.proposalBuildJobs) != 1 || service.activeProposalBuild == nil || service.activeProposalBuild.key != third.Key {
		t.Fatalf("latest-wins scheduler state: queued=%d active=%#v", len(service.proposalBuildJobs), service.activeProposalBuild)
	}
	if proposalBuildWorkers != 2 || cap(service.proposalBuildJobs) != 1 {
		t.Fatalf("proposal construction bounds = workers %d queue %d, want 2/1", proposalBuildWorkers, cap(service.proposalBuildJobs))
	}
}

func TestEpochTransitionGateRejectsBuildsUntilSyncCommitFinishes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		proposalBuildJobs:            make(chan *proposalBuildJob, 1),
		activeProposalBuild:          &proposalBuildControl{cancel: cancel},
	}
	service.invalidateProposalBuildsForEpochTransition()
	if atomic.LoadInt32(&service.fhsEpochTransition) == 0 || service.proposalValidationGeneration != 2 || service.activeProposalBuild != nil {
		t.Fatal("epoch transition did not invalidate the old proposal generation")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("epoch transition did not cancel the active proposal worker")
	}
	request := proposalBuildRequestForTest(12)
	if err := service.ScheduleFHSProposalBuild(request); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("build scheduled between before-hook and canonical key mutation: %v", err)
	}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatal(err)
	}
	service.finishFHSFinalizedSyncKeyCommit(nil, core.FHSFinalizedSyncPreCommitFailed)
	if atomic.LoadInt32(&service.fhsEpochTransition) != 0 {
		t.Fatal("failed sync commit did not release the epoch transition gate")
	}
	if err := service.ScheduleFHSProposalBuild(request); err != nil {
		t.Fatalf("build did not resume after sync commit cleanup: %v", err)
	}
}

func TestSyncEpochTransitionFailsFastBehindLivePublication(t *testing.T) {
	service := &Service{runningState: 1}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationHighQC); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	acquired, err := service.beforeFHSFinalizedSyncKeyCommit(nil, nil)
	if acquired {
		t.Fatal("contended sync transition claimed the live publication barrier")
	}
	if !errors.Is(err, errFHSValidationPublicationBusy) {
		t.Fatalf("contended sync transition error = %v, want %v", err, errFHSValidationPublicationBusy)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("contended sync transition waited behind live publication for %s", elapsed)
	}
	if atomic.LoadInt32(&service.fhsValidationPublicationOwner) != int32(fhsValidationPublicationHighQC) {
		t.Fatal("contended sync transition changed the live publication owner")
	}
	waitStarted := make(chan struct{})
	waitReturned := make(chan struct{})
	go func() {
		close(waitStarted)
		service.waitFHSValidationPublication()
		close(waitReturned)
	}()
	<-waitStarted
	select {
	case <-waitReturned:
		t.Fatal("publication wait returned before the live owner released the barrier")
	case <-time.After(20 * time.Millisecond):
	}
	if !service.releaseFHSValidationPublication(fhsValidationPublicationHighQC) {
		t.Fatal("failed to release live publication after contention test")
	}
	select {
	case <-waitReturned:
	case <-time.After(time.Second):
		t.Fatal("publication wait did not return after live owner release")
	}
	if err := service.tryAcquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatalf("sync transition did not acquire after live publication released: %v", err)
	}
	if atomic.LoadInt32(&service.fhsValidationPublicationOwner) != int32(fhsValidationPublicationSyncTransition) {
		t.Fatal("retry did not install the sync transition publication owner")
	}
	if !service.releaseFHSValidationPublication(fhsValidationPublicationSyncTransition) {
		t.Fatal("failed to release sync publication after successful retry")
	}
}

func TestEpochTransitionPostCanonicalFailureStaysFailClosed(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		fhsEpochTransition:           1,
	}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatal(err)
	}
	service.finishFHSFinalizedSyncKeyCommit(nil, core.FHSFinalizedSyncCanonicalAfterFailed)
	if atomic.LoadInt32(&service.runningState) != 0 {
		t.Fatal("post-canonical lifecycle failure left consensus running")
	}
	if atomic.LoadInt32(&service.fhsEpochTransition) == 0 {
		t.Fatal("post-canonical lifecycle failure reopened the epoch transition gate")
	}
	if atomic.LoadUint64(&service.proposalValidationGeneration) != 2 {
		t.Fatal("post-canonical lifecycle failure did not invalidate in-flight work")
	}
}

func TestEpochTransitionSuccessfulCommitReopensGate(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		fhsEpochTransition:           1,
	}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationSyncTransition); err != nil {
		t.Fatal(err)
	}
	service.finishFHSFinalizedSyncKeyCommit(nil, core.FHSFinalizedSyncCompleted)
	if atomic.LoadInt32(&service.runningState) != 1 {
		t.Fatal("successful lifecycle completion stopped consensus")
	}
	if atomic.LoadInt32(&service.fhsEpochTransition) != 0 {
		t.Fatal("successful lifecycle completion did not reopen the epoch transition gate")
	}
}

func proposalValidationPublicationFixture() (*Service, *hotstuff.FHSProposalValidationResult) {
	viewID := common.HexToHash("0x200")
	parentHash := common.HexToHash("0x100")
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: parentHash,
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
	})
	ref := &types.HotstuffProposalRef{
		Version:    types.HotstuffProposalRefVersion,
		ChainID:    1,
		Number:     block.NumberU64(),
		ViewNumber: 2,
		ViewID:     viewID,
		LeaderID:   "leader",
		BlockHash:  block.Hash(),
		ParentHash: parentHash,
		BodyHash:   common.HexToHash("0x300"),
		BodySize:   1,
		ExtraHash:  types.HotstuffProposalExtraHash(nil),
	}
	key := hotstuff.FHSProposalValidationKey{
		RequestID: 1, ViewNumber: ref.ViewNumber, ViewID: ref.ViewID,
		LeaderID: ref.LeaderID, ProposalID: ref.ProposalID(),
	}
	output := &proposalValidationOutput{
		ref: ref,
		verified: &core.VerifiedProposal{
			ProposalID: key.ProposalID, ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
			Block: block, ParentHash: parentHash, ParentNumber: 0,
		},
		serviceGeneration:    1,
		validationGeneration: 1,
	}
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		activeProposalValidations: map[common.Hash]*proposalValidationControl{
			viewID: {key: key, generation: 1},
		},
		proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
		verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
		fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
		pacetMakerTimer:      &paceMakerTimer{},
	}
	return service, &hotstuff.FHSProposalValidationResult{Key: key, ApplicationData: output}
}

func TestFHSProposalValidationApplyTransfersPublicationBarrier(t *testing.T) {
	service, result := proposalValidationPublicationFixture()
	if err := service.ApplyFHSProposalValidation(result); err != nil {
		t.Fatalf("apply verified proposal: %v", err)
	}
	if service.muFHSValidationPublication.TryLock() {
		service.muFHSValidationPublication.Unlock()
		t.Fatal("sync transition entered between validation Apply and manager vote completion")
	}
	service.FinishFHSProposalValidation(result)
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("validation publication barrier remained locked after manager Finish")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestFHSProposalValidationApplyFailureReleasesPublicationBarrier(t *testing.T) {
	service, result := proposalValidationPublicationFixture()
	output := result.ApplicationData.(*proposalValidationOutput)
	output.serviceGeneration++
	if err := service.ApplyFHSProposalValidation(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("stale proposal validation error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("failed proposal validation retained the publication barrier")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestFHSHighQCFinishReleasesOnlyExactPublication(t *testing.T) {
	service := new(Service)
	result := &hotstuff.FHSHighQCValidationResult{Key: hotstuff.FHSHighQCValidationKey{RequestID: 1}}
	other := &hotstuff.FHSHighQCValidationResult{Key: result.Key}
	if err := service.acquireFHSValidationPublication(fhsValidationPublicationHighQC); err != nil {
		t.Fatal(err)
	}
	service.activeHighQCValidationPublish = result
	service.FinishFHSHighQCValidation(other)
	if service.muFHSValidationPublication.TryLock() {
		service.muFHSValidationPublication.Unlock()
		t.Fatal("mismatched HighQC result released the publication barrier")
	}
	service.FinishFHSHighQCValidation(result)
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("exact HighQC manager completion did not release the publication barrier")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestFHSHighQCApplyFailureReleasesPublicationBarrier(t *testing.T) {
	key := hotstuff.FHSHighQCValidationKey{RequestID: 1, TargetView: 2, QCID: common.HexToHash("0x1")}
	service := &Service{proposalValidationGeneration: 1}
	result := &hotstuff.FHSHighQCValidationResult{
		Key: key,
		ApplicationData: &fhsHighQCValidationOutput{
			key: key, serviceGeneration: 1,
		},
	}
	if err := service.ApplyFHSHighQCValidation(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("stopped HighQC validation error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if !service.muFHSValidationPublication.TryLock() {
		t.Fatal("failed HighQC validation retained the publication barrier")
	}
	service.muFHSValidationPublication.Unlock()
}

func TestProposalCadenceConcurrentWorkerReadAndPublish(t *testing.T) {
	service := new(Service)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(2)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				now := time.Unix(0, int64(offset*1000+i+1))
				service.muProposalCadence.Lock()
				service.lastProposeTime = now
				service.lastFastBlockTime = now
				service.lastSlowBlockTime = now
				service.muProposalCadence.Unlock()
			}
		}(worker)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				service.shouldEmitFastBlock(time.Now())
				service.shouldEmitSlowBlock(time.Now(), i)
			}
		}()
	}
	wg.Wait()
}

func TestStoppedServiceWriteAndBroadcastFailClosed(t *testing.T) {
	service := &Service{}
	msg := &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose}
	if err := service.Write("self", msg); !errors.Is(err, types.ErrNotRunning) {
		t.Fatalf("stopped Write error = %v, want %v", err, types.ErrNotRunning)
	}
	errs := service.Broadcast(msg)
	if len(errs) != 1 || !errors.Is(errs[0], types.ErrNotRunning) {
		t.Fatalf("stopped Broadcast errors = %v, want %v", errs, types.ErrNotRunning)
	}
}

func proposalBuildApplyFixture(key hotstuff.FHSProposalBuildKey) (*Service, *proposalBuildOutput, *hotstuff.FHSProposalBuildResult) {
	body := &proposalBodyMsg{ProposalID: common.HexToHash("0x11"), BodyHash: common.HexToHash("0x12"), BodySize: 1}
	manifest := &proposalBodyMsg{ProposalID: body.ProposalID, BodyHash: body.BodyHash, BodySize: 1, Type: proposalBodyMsgManifest}
	output := &proposalBuildOutput{
		key:                    key,
		proposalRef:            []byte{0x01},
		body:                   body,
		manifest:               manifest,
		serviceGeneration:      1,
		constructionGeneration: 7,
	}
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		activeProposalBuild:          &proposalBuildControl{key: key, generation: 7},
		proposalManifestSlots:        make(chan struct{}, 1),
		proposalManifestJobs:         make(chan *proposalManifestDispatch, 1),
		proposalFailedTxSlots:        make(chan struct{}, 1),
		proposalFailedTxJobs:         make(chan *proposalFailedTxCleanup, 1),
	}
	result := &hotstuff.FHSProposalBuildResult{Key: key, TProposal: []byte{0x01}, ApplicationData: output}
	return service, output, result
}

func TestProposalBuildTimeoutOnlyViewAdvancePublishesNothing(t *testing.T) {
	request := proposalBuildRequestForTest(12)
	service, output, result := proposalBuildApplyFixture(request.Key)
	service.currentView.ViewNumber = 10 // request targets 12; exact next view is 11
	service.replicaView = &service.currentView

	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, nil, nil)
	committee := &bftview.Committee{List: []*common.Cnode{{Address: "127.0.0.1:1", Public: "01"}}}
	keyBlock := types.NewKeyBlock(&types.KeyBlockHeader{
		Number: big.NewInt(2), Difficulty: big.NewInt(1), CommitteeHash: committee.RlpHash(),
	})
	output.keyCandidate = &keyProposalCandidate{}
	output.keyBlock = keyBlock
	output.committee = committee

	err := service.ApplyFHSProposalBuild(result)
	if !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("timeout-stale Apply error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if len(service.proposalManifestJobs) != 0 || len(service.proposalManifestSlots) != 0 ||
		bftview.LoadMember(keyBlock.NumberU64(), keyBlock.Hash(), true) != nil {
		t.Fatal("timeout-stale result dispatched a manifest or stored a committee")
	}

	txService, txOutput, txResult := proposalBuildApplyFixture(request.Key)
	txService.currentView.ViewNumber = 10
	txService.replicaView = &txService.currentView
	txOutput.txCandidate = &txProposalCandidate{
		failedTxes: types.Transactions{types.NewTransaction(0, common.HexToAddress("0x1"), big.NewInt(1), 21_000, big.NewInt(1), nil)},
	}
	if err := txService.ApplyFHSProposalBuild(txResult); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("timeout-stale tx Apply error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if len(txService.proposalManifestJobs) != 0 || len(txService.proposalManifestSlots) != 0 ||
		len(txService.proposalFailedTxJobs) != 0 || len(txService.proposalFailedTxSlots) != 0 {
		t.Fatal("timeout-stale tx result published proposed-chain maintenance, manifest, or failed-TX GC")
	}
}

func TestProposalBuildQueueSaturationFailsBeforePublication(t *testing.T) {
	request := proposalBuildRequestForTest(11)
	service, output, result := proposalBuildApplyFixture(request.Key)
	output.txCandidate = &txProposalCandidate{}
	service.proposalManifestSlots <- struct{}{} // reserve the sole slot for earlier accepted work

	err := service.ApplyFHSProposalBuild(result)
	if err == nil || err.Error() != "proposal manifest dispatch queue saturated" {
		t.Fatalf("saturated Apply error = %v", err)
	}
	if len(service.proposalManifestJobs) != 0 || len(service.proposalManifestSlots) != 1 {
		t.Fatal("queue saturation consumed a reservation or published a manifest")
	}
}

func TestProposalBuildStopInvalidatesCompletionBeforePublication(t *testing.T) {
	request := proposalBuildRequestForTest(11)
	service, output, result := proposalBuildApplyFixture(request.Key)
	output.txCandidate = &txProposalCandidate{}
	service.setRunState(0)
	if err := service.ApplyFHSProposalBuild(result); !errors.Is(err, hotstuff.ErrOldState) {
		t.Fatalf("stopped construction Apply error = %v, want %v", err, hotstuff.ErrOldState)
	}
	if service.activeProposalBuild != nil || len(service.proposalManifestJobs) != 0 || len(service.proposalFailedTxJobs) != 0 {
		t.Fatal("stopped construction remained active or published maintenance")
	}
}

func TestProposalBuildPublicationBarrierLinearizesStop(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 1,
		proposalBuildJobs:            make(chan *proposalBuildJob, 1),
	}
	output := &proposalBuildOutput{publicationLocksHeld: true}
	result := &hotstuff.FHSProposalBuildResult{ApplicationData: output}
	service.muProposalBuild.Lock()
	service.muCurrentView.Lock()

	started := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		close(started)
		service.setRunState(0)
		close(stopped)
	}()
	<-started
	select {
	case <-stopped:
		t.Fatal("Stop crossed the Apply-to-Broadcast publication barrier")
	case <-time.After(20 * time.Millisecond):
	}
	service.FinishFHSProposalBuild(result)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete after proposal publication finished")
	}
	if service.runningState != 0 || output.publicationLocksHeld {
		t.Fatal("publication barrier did not release into the stopped generation")
	}
}

func TestProposalManifestDispatcherDropsPriorLifecycleGeneration(t *testing.T) {
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 2,
		proposalManifestSlots:        make(chan struct{}, 1),
		proposalManifestJobs:         make(chan *proposalManifestDispatch, 1),
	}
	service.proposalManifestSlots <- struct{}{}
	go service.proposalManifestDispatchWorker()
	service.proposalManifestJobs <- &proposalManifestDispatch{
		body:              &proposalBodyMsg{ProposalID: common.HexToHash("0x1")},
		destinations:      []string{"would-panic-without-generation-check"},
		serviceGeneration: 1,
	}
	deadline := time.After(time.Second)
	for len(service.proposalManifestSlots) != 0 {
		select {
		case <-deadline:
			t.Fatal("stale manifest dispatch reservation was not released")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestProposalFailedTxCleanupRunsExactlyOnceForAcceptedGeneration(t *testing.T) {
	called := make(chan types.Transactions, 1)
	service := &Service{
		runningState:                 1,
		proposalValidationGeneration: 3,
		proposalFailedTxSlots:        make(chan struct{}, 1),
		proposalFailedTxJobs:         make(chan *proposalFailedTxCleanup, 1),
		removeFailedProposalTxs: func(txs types.Transactions) {
			called <- append(types.Transactions(nil), txs...)
		},
	}
	txs := types.Transactions{types.NewTransaction(0, common.HexToAddress("0x1"), big.NewInt(1), 21_000, big.NewInt(1), nil)}
	service.proposalFailedTxSlots <- struct{}{}
	go service.proposalFailedTxCleanupWorker()
	service.proposalFailedTxJobs <- &proposalFailedTxCleanup{txs: txs, serviceGeneration: 3}
	select {
	case got := <-called:
		if len(got) != 1 || got[0].Hash() != txs[0].Hash() {
			t.Fatalf("failed-TX cleanup payload = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted failed-TX cleanup did not run")
	}
	select {
	case duplicate := <-called:
		t.Fatalf("failed-TX cleanup ran more than once: %v", duplicate)
	case <-time.After(20 * time.Millisecond):
	}
}
