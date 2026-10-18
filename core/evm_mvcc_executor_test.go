package core

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

func evmMVCTestConfig() *params.ChainConfig {
	config := stateProcessorOsakaTestConfig()
	config.NativeParallel = params.SolanaScaleNativeParallelConfig()
	config.NativeParallel.RequireNativeTransactions = false
	return config
}

// These are parametric sizing assumptions, not measurements of deployed DEX or
// perpetual contracts. Projection uses arithmetic only, never a 500k-tx fixture.
func TestEVMSyntheticMixedCapacityModel(t *testing.T) {
	limits := params.SolanaScaleEVMParallelConfig()
	type assumedClass struct{ accesses, gas, signed, retainedLogs uint64 }
	classes := []assumedClass{{3, 21_000, 114, 0}, {20, 150_000, 300, 1715}, {40, 250_000, 400, 956}}
	for _, mix := range []struct {
		name   string
		ratios [3]uint64
	}{{"20_30_50", [3]uint64{2, 3, 5}}, {"60_20_20", [3]uint64{6, 2, 2}}, {"10_10_80", [3]uint64{1, 1, 8}}} {
		for _, scale := range []struct {
			name string
			num  uint64
		}{{"low", 1}, {"base", 2}, {"heavy", 4}} {
			t.Run(mix.name+"/"+scale.name, func(t *testing.T) {
				var projected assumedClass
				for index, class := range classes {
					count := uint64(500_000) * mix.ratios[index] / 10
					// Keep the ordinary signed transfer and intrinsic gas fixed;
					// scale the richer classes' resource work above that floor.
					if index != 0 {
						class.accesses = class.accesses * scale.num / 2
						class.gas = params.TxGas + (class.gas-params.TxGas)*scale.num/2
						class.signed = classes[0].signed + (class.signed-classes[0].signed)*scale.num/2
						class.retainedLogs = class.retainedLogs * scale.num / 2
					}
					projected.accesses += count * class.accesses
					projected.gas += count * class.gas
					projected.signed += count * class.signed
					projected.retainedLogs += count * class.retainedLogs
				}
				if mix.name == "20_30_50" && scale.name == "base" {
					if projected != (assumedClass{13_300_000, 87_100_000_000, 156_400_000, 496_250_000}) {
						t.Fatalf("incorrect reference projection: %+v", projected)
					}
					if projected.accesses <= limits.MaxAccessesPerBlock || projected.retainedLogs <= limits.MaxLogBytesPerBlock {
						t.Fatal("reference projection unexpectedly fits current access/log ceilings")
					}
				}
				// A transaction count is a per-block capacity. Converting it to TPS
				// additionally requires a measured/assumed block duration.
				byAccess := limits.MaxAccessesPerBlock * 500_000 / projected.accesses
				byLogs := limits.MaxLogBytesPerBlock * 500_000 / projected.retainedLogs
				bySigned := limits.MaxBlockBytes * 500_000 / projected.signed
				for _, bound := range []struct{ count, projected, limit uint64 }{
					{byAccess, projected.accesses, limits.MaxAccessesPerBlock},
					{byLogs, projected.retainedLogs, limits.MaxLogBytesPerBlock},
					{bySigned, projected.signed, limits.MaxBlockBytes},
				} {
					if bound.count*bound.projected > bound.limit*500_000 || (bound.count+1)*bound.projected <= bound.limit*500_000 {
						t.Fatalf("incorrect projected boundary: %+v", bound)
					}
				}
				t.Logf("assumed 500k tx: accesses=%d gas=%d signedB=%d retainedLogB=%d; independent block capacities access=%d logs=%d signed-only=%d (framing/sidecars excluded)", projected.accesses, projected.gas, projected.signed, projected.retainedLogs, byAccess, byLogs, bySigned)
			})
		}
	}
	t.Run("integrated_profiles", testEVMSyntheticMixedProfiles)
	const committeeBytes, gib = uint64(8_000_000_000), uint64(1 << 30)
	if committeeBytes/gib != 7 || nativeExecutionMemoryBudget != 2*gib || committeeBytes <= nativeExecutionMemoryBudget {
		t.Fatal("decimal hardware budget and local execution lease were conflated")
	}
	t.Logf("committee hardware=%d decimal bytes (%.3f GiB); execution lease=%d bytes; neither is a process RSS observation", committeeBytes, float64(committeeBytes)/float64(gib), nativeExecutionMemoryBudget)
}

// evmSyntheticSidecarSize projects encoded components from one bounded 512-item
// certificate. A partially selected last certificate is still charged in full.
// These fixtures measure encoding, not admission signatures or reward validity.
type evmSyntheticSidecarSize struct {
	certificate uint64
	rewards     [3]uint64
	receipts    [3]uint64
}

func evmSyntheticSidecarSample(t *testing.T, chainID *big.Int) evmSyntheticSidecarSize {
	t.Helper()
	const count = types.MaxCommonTxAdmissionBatchItems
	hashes := make([]common.Hash, count)
	refs := make([]types.CommonTxAdmissionRef, count)
	rewards := make([]*types.CommonTxReward, count)
	key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", 1))
	if err != nil {
		t.Fatal(err)
	}
	signer := types.LatestSignerForChainID(chainID)
	gas := [3]uint64{params.TxGas, 150_000, 250_000}
	result := evmSyntheticSidecarSize{}
	// One-log shapes realize the assumed retained charges exactly. Retained
	// logs include 256 B per object, while receipt RLP includes the bloom and
	// framing instead. Measure both, rather than assigning 1024 B to every tx.
	for class, dataBytes := range []int{0, 1431, 672} {
		var logs []*types.Log
		if class != 0 {
			logs = []*types.Log{{Address: common.Address{1}, Data: make([]byte, dataBytes)}}
		}
		for txType := uint8(0); txType <= types.SetCodeTxType; txType++ {
			receipt := &types.Receipt{Type: txType, Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: 1 << 44, Logs: logs}
			measured, err := measureExecutionOutput(receipt)
			if err != nil || measured.logRetained != [3]uint64{0, 1715, 956}[class] {
				t.Fatalf("representative receipt/log class=%d type=%d retained=%d error=%v", class, txType, measured.logRetained, err)
			}
			result.receipts[class] = max(result.receipts[class], measured.receiptEntry)
		}
	}
	for index := range hashes {
		class := 0
		if index%10 >= 2 {
			class = 1
		}
		if index%10 >= 5 {
			class = 2
		}
		tx, err := types.SignTx(types.NewTransaction(uint64(index), common.Address{1}, new(big.Int), gas[class], big.NewInt(params.FixedTransferGasPricePerGas), nil), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		hashes[index], refs[index].Item = tx.Hash(), uint16(index)
		fee := new(big.Int).Mul(new(big.Int).SetUint64(gas[class]), big.NewInt(params.FixedTransferGasPricePerGas))
		reward := new(big.Int).Div(new(big.Int).Set(fee), big.NewInt(5))
		rewards[index] = &types.CommonTxReward{Version: types.CommonRPCVersionV2, TxHash: tx.Hash(), Approver: common.Address{2}, RewardRecipient: common.Address{3}, ApproverReward: reward, Burn: new(big.Int).Sub(fee, reward)}
		encoded, err := rlp.EncodeToBytes(rewards[index])
		if err != nil {
			t.Fatal(err)
		}
		result.rewards[class] = uint64(len(encoded))
	}
	batch := &types.CommonTxAdmissionBatch{Version: types.CommonRPCVersionV2, ChainID: chainID, GenesisHash: common.Hash{1}, TxRoot: types.DeriveCommonTxAdmissionTxRoot(hashes), AdmissionID: common.Hash{2}, Miner: common.Address{2}, RewardRecipient: common.Address{3}, KeyBlockNumber: ^uint64(0), Timestamp: ^uint64(0), TxHashes: hashes, Signature: make([]byte, 65)}
	encoded, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	result.certificate = uint64(len(encoded))
	encodedRefs, err := rlp.EncodeToBytes(refs)
	if err != nil || uint64(len(encodedRefs)) != rlpListSizeChecked(evmSyntheticRefContent(count)) {
		t.Fatalf("512-reference arithmetic differs from canonical RLP: bytes=%d error=%v", len(encodedRefs), err)
	}
	for _, rank := range []uint32{127, 128, 255, 256} {
		for index := range refs {
			refs[index].Batch = rank
		}
		encoded, err := rlp.EncodeToBytes(refs)
		start := uint64(rank) * count
		content := evmSyntheticRefContent(start+count) - evmSyntheticRefContent(start)
		if err != nil || uint64(len(encoded)) != rlpListSizeChecked(content) {
			t.Fatalf("reference batch rank %d arithmetic differs from canonical RLP", rank)
		}
	}
	var rewardContent uint64
	for _, reward := range rewards {
		entry, err := rlp.EncodeToBytes(reward)
		if err != nil {
			t.Fatal(err)
		}
		rewardContent += uint64(len(entry))
	}
	encodedRewards, err := rlp.EncodeToBytes(rewards)
	if err != nil || uint64(len(encodedRewards)) != rlpListSizeChecked(rewardContent) {
		t.Fatalf("512-reward arithmetic differs from canonical RLP: bytes=%d error=%v", len(encodedRewards), err)
	}
	// The old 116/149 B per transaction figures are lower bounds: 33 B per
	// certificate hash + 3 B minimal reference + 80 B minimal reward; the
	// manifest adds another 33 B hash. Neither includes transaction body items.
	minimum := &types.CommonTxReward{Version: types.CommonRPCVersionV2, Approver: common.Address{2}, RewardRecipient: common.Address{3}, ApproverReward: new(big.Int), Burn: new(big.Int)}
	minimumReward, err := rlp.EncodeToBytes(minimum)
	minimumRef, refErr := rlp.EncodeToBytes(types.CommonTxAdmissionRef{})
	if err != nil || refErr != nil || len(minimumReward) != 80 || len(minimumRef) != 3 {
		t.Fatalf("minimum component sizes: reward=%d ref=%d errors=%v/%v", len(minimumReward), len(minimumRef), err, refErr)
	}
	t.Logf("measured RLP sample: signed transactions=%d full certificateB=%d referenceListB=%d declared-gas rewardEntryB=%v rewardListB=%d representativeReceiptEntryB=%v; receipt shapes assume zero topics and one log for each richer class, maximum configured cumulative gas width and worst type0-4 envelope, not arbitrary-contract guarantees; 116 canonical-sidecar/149 manifest-component B per tx are incomplete lower bounds", count, result.certificate, len(encodedRefs), result.rewards, len(encodedRewards), result.receipts)
	return result
}

// Only the number of certificates is visited. There is no n-transaction slice.
// Reference integer widths grow at 128/256 for items and 128/256/... for batches.
func evmSyntheticRefContent(n uint64) uint64 {
	integerSize := func(value uint64) uint64 {
		if value < 128 {
			return 1
		}
		width := uint64(0)
		for value != 0 {
			width++
			value >>= 8
		}
		return 1 + width
	}
	var content uint64
	for batch := uint64(0); n != 0; batch++ {
		count := n
		if count > types.MaxCommonTxAdmissionBatchItems {
			count = types.MaxCommonTxAdmissionBatchItems
		}
		for _, group := range []struct{ first, end, width uint64 }{{0, 128, 1}, {128, 256, 2}, {256, 512, 3}} {
			end := count
			if end > group.end {
				end = group.end
			}
			if end > group.first {
				content += (end - group.first) * (1 + integerSize(batch) + group.width)
			}
		}
		n -= count
	}
	return content
}

func testEVMSyntheticMixedProfiles(t *testing.T) {
	fixtureConfig, _, block := evmSyntheticMixedFixture(t, 20, false)
	encodedGenesis, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis Genesis
	if err := json.Unmarshal(encodedGenesis, &genesis); err != nil || genesis.Config == nil || genesis.Config.NativeParallel == nil {
		t.Fatalf("read actual root genesis limits: %v", err)
	}
	// Keep the unchanged default profile as the historical capacity control.
	config, baseline := genesis.Config, params.SolanaScaleEVMParallelConfig()
	t.Cleanup(func() {
		config.SetModernForkConfig(nil)
		fixtureConfig.SetModernForkConfig(nil)
	})
	if !config.IsOsaka(block.Number(), block.Time()) || config.GetMaxCodeSize(block.Number()) != 128*1024 {
		t.Fatal("capacity reservations require the actual Osaka/128 KiB root genesis profile")
	}
	if err := baseline.Validate(); err != nil {
		t.Fatalf("default capacity control is invalid: %v", err)
	}
	sidecars := evmSyntheticSidecarSample(t, config.ChainID)
	t.Logf("reservation source: root genesis codeLimitB=%d; execution fixture codeLimitB=%d; fork EIP150=%t Berlin=%t Osaka=%t; W includes base64KiB +4*gas-bounded aggregate live EVM memory +2*output cap +log cap +signed size +access cap*(2048+512) +gas-bounded code images", config.GetMaxCodeSize(block.Number()), fixtureConfig.GetMaxCodeSize(block.Number()), config.IsEIP150(block.Number()), config.IsBerlin(block.Number()), config.IsOsaka(block.Number(), block.Time()))
	candidate := *params.FHS250msResearchEVMParallelConfig()
	if err := candidate.Validate(); err != nil {
		t.Fatalf("test-only candidate violates existing configuration checks: %v", err)
	}
	for _, profile := range []struct {
		name      string
		n, millis uint64
		limits    *params.NativeParallelConfig
		wantFits  bool
	}{{"default_caps_1s", 500_000, 1000, baseline, false}, {"default_caps_250ms", 125_000, 250, baseline, false}, {"opt_in_research_250ms", 125_000, 250, &candidate, true}} {
		t.Run(profile.name, func(t *testing.T) {
			local := *config
			local.NativeParallel = profile.limits
			local.SetModernForkConfig(config.ModernForkConfig())
			defer local.SetModernForkConfig(nil)
			n := profile.n
			// Parametric base assumptions: access 26.6, gas 174200, signed
			// payload 312.8 B, retained logs 992.5 B per transaction. Receipt
			// widths come from the bounded one-log sample, not the 512 B reserve.
			accesses, gas, signed, logs := n*266/10, n*174_200, n*3128/10, n*9925/10
			receipts := rlpListSizeChecked(n * (2*sidecars.receipts[0] + 3*sidecars.receipts[1] + 5*sidecars.receipts[2]) / 10)
			if n == 500_000 {
				accessOnly, logsOnly := *baseline, *baseline
				accessOnly.MaxAccessesPerBlock = accesses
				logsOnly.MaxLogBytesPerBlock, logsOnly.MaxReceiptBytesPerBlock = logs, logs
				accessErr, logsErr := accessOnly.Validate(), logsOnly.Validate()
				if accesses*params.NativePlanningMemoryPerAccess <= nativeExecutionMemoryBudget || logs <= params.NativeParallelHardMaxBlockBytes || accessErr == nil || logsErr == nil {
					t.Fatal("1s base mix must exceed combined planning-memory and hard receipt/log guards independently")
				}
				t.Logf("1s model cannot fit by raising baseline genesis knobs: access planning aloneB=%d exceeds leaseB=%d (raw access hard ceiling=%d is not binding); logsB=%d exceeds hard receipt maximumB=%d with log<=receipt invariant; access-only Validate=%v; log-only Validate=%v", accesses*params.NativePlanningMemoryPerAccess, nativeExecutionMemoryBudget, params.NativeParallelHardMaxAccesses, logs, params.NativeParallelHardMaxBlockBytes, accessErr, logsErr)
			}
			batches := (n + types.MaxCommonTxAdmissionBatchItems - 1) / types.MaxCommonTxAdmissionBatchItems
			rewardContent := n * (2*sidecars.rewards[0] + 3*sidecars.rewards[1] + 5*sidecars.rewards[2]) / 10
			commonBytes := rlpListSizeChecked(batches*sidecars.certificate) + rlpListSizeChecked(evmSyntheticRefContent(n)) + rlpListSizeChecked(rewardContent)
			// Favorable co-selection packs almost every certificate's 512 hashes
			// into this proposal. Valid scattered selection can adopt only one
			// item from each full certificate; no count-only fit covers that case.
			fragmentedCertificates := rlpListSizeChecked(n * sidecars.certificate)
			if fragmentedCertificates <= profile.limits.MaxBlockBytes {
				t.Fatal("full-certificate fragmentation should independently exceed the body ceiling")
			}
			// Signed payloads are not generally canonical body items. Reserve
			// four extra bytes per item (up to the 1 MiB transaction ceiling),
			// a 64 KiB assumed header/uncle allowance and finality-proof reserve.
			body := rlpListSizeChecked(rlpListSizeChecked(signed+4*n) + commonBytes + 64*1024 + params.FairHotstuffFinalityProofReserveBytes + 1)
			manifestComponents := rlpListSizeChecked(33*n) + commonBytes
			fits := n <= profile.limits.MaxTransactionsPerBlock && accesses <= profile.limits.MaxAccessesPerBlock && gas <= profile.limits.MaxComputePerBlock && logs <= profile.limits.MaxLogBytesPerBlock && receipts <= profile.limits.MaxReceiptBytesPerBlock && body <= profile.limits.MaxBlockBytes && rewardContent <= profile.limits.MaxBlockBytes/4
			if fits != profile.wantFits || n*1000 != 500_000*profile.millis {
				t.Fatalf("unexpected assumed envelope fit=%t profile=%+v", fits, profile)
			}
			var representative uint64
			weights := make([]uint64, len(block.Transactions()))
			for index, tx := range block.Transactions() {
				weight := evmRuntimeTransactionMemoryWeight(&local, block.Header(), tx)
				weights[index] = weight
				if weight > representative {
					representative = weight
				}
			}
			maximumTx := types.NewTransaction(0, common.Address{1}, new(big.Int), params.MaxTxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
			maximum := evmRuntimeTransactionMemoryWeight(&local, block.Header(), maximumTx)
			// Account for maximum signed size arithmetically, without allocating
			// a 1 MiB payload. Osaka caps gas at MaxTxGas; earlier forks differ.
			maximum += profile.limits.MaxTransactionBytes - uint64(maximumTx.Size())
			for _, count := range []uint64{n, profile.limits.MaxTransactionsPerBlock} {
				h := evmRuntimeRetainedMemoryWeight(&local, int(count))
				want := uint64(params.NativePlanningMemoryPerAccess)*min(count*profile.limits.MaxAccessesPerTransaction, profile.limits.MaxAccessesPerBlock) + count*(params.NativePlanningMemoryPerTransaction+params.NativeReceiptMemoryReservePerTransaction) + min(count*profile.limits.MaxLogBytesPerTransaction, profile.limits.MaxLogBytesPerBlock)
				if h != want || h+representative >= nativeExecutionMemoryBudget || h+maximum >= nativeExecutionMemoryBudget {
					t.Fatalf("retained H or H+singleW feasibility differs: count=%d H=%d want=%d representative=%d maximum=%d", count, h, want, representative, maximum)
				}
				// H+singleW proves that one transaction can be scheduled. The parallel
				// pass reserves H+maximumBatchWeight, which can include several W's.
				// Use only the existing 20-transaction sample's scalar reservations.
				var maximumBatch uint64
				for start := 0; start < len(weights); {
					end, batch := evmOptimisticMemoryBatchEndWithin(start, weights, nativeExecutionMemoryBudget-h)
					if end <= start || end-start > evmOptimisticMicroBatch || h+batch > nativeExecutionMemoryBudget {
						t.Fatalf("invalid reservation window: count=%d H=%d start=%d end=%d batch=%d", count, h, start, end, batch)
					}
					maximumBatch = max(maximumBatch, batch)
					start = end
				}
				if maximumBatch <= representative {
					t.Fatal("bounded sample must distinguish a parallel batch from one transaction reservation")
				}
				// Maximum-gas/size envelopes are scalar weights, not allocated
				// transactions. Check both the exact batch boundary and progress.
				worst := make([]uint64, evmOptimisticMicroBatch+1)
				for index := range worst {
					worst[index] = maximum
				}
				end, worstBatch := evmOptimisticMemoryBatchEndWithin(0, worst, nativeExecutionMemoryBudget-h)
				wantEnd := min(uint64(evmOptimisticMicroBatch), (nativeExecutionMemoryBudget-h)/maximum)
				if uint64(end) != wantEnd || end == 0 || worstBatch != uint64(end)*maximum || h+worstBatch > nativeExecutionMemoryBudget || (end < evmOptimisticMicroBatch && h+worstBatch+maximum <= nativeExecutionMemoryBudget) {
					t.Fatalf("maximum-weight batch boundary: H=%d W=%d end=%d batch=%d", h, maximum, end, worstBatch)
				}
				t.Logf("maximum Osaka signed-size reservation: count=%d H=%d Wmax=%d simultaneousMaximumTransactions=%d maximumBatchB=%d HplusMaximumBatchB=%d; next maximum transaction cannot enter this batch; scalar weights allocate no large payload", count, h, maximum, end, worstBatch, h+worstBatch)
				t.Logf("reservation feasibility only: count=%d H=%d representativeSingleW=%d HplusRepresentativeSingleW=%d maximumAllowedOsakaSingleW=%d HplusMaximumSingleW=%d bounded20TxMaximumBatchWeight=%d HplusSampleMaximumBatchWeight=%d; production leases H+maximumBatchWeight, aggregate lease weights<=%dB; these are accounting weights, not physical heap/RSS bounds", count, h, representative, h+representative, maximum, h+maximum, maximumBatch, h+maximumBatch, nativeExecutionMemoryBudget)
				for _, ram := range []uint64{8_000_000_000, 16_000_000_000, 32_000_000_000} {
					t.Logf("scheduler-only subtraction: RAMdecimalB=%d fullExecutionLeaseB=%d residualB=%d; retained certified StateDB/results, parent/build/replay copies, DB/cache/state/txpool/WAL/network/sidecar copies/Go runtime/OS remain unbudgeted; this residual is not available RSS or a node-fit prediction", ram, nativeExecutionMemoryBudget, ram-nativeExecutionMemoryBudget)
				}
			}
			t.Logf("ASSUMED 20/30/50 occupancy tx=%d durationMs=%d accesses=%d/%d signedB=%d retainedLogB=%d/%d assumedReceiptListB=%d/%d gas=%d/%d commonSidecarB=%d rewardPayloadB=%d/%d canonicalBodyEnvelopeB=%d/%d manifestComponentsB=%d (header/blob/transport excluded) aggregateFits=%t; critical path/dependency depth require a state graph", n, profile.millis, accesses, profile.limits.MaxAccessesPerBlock, signed, logs, profile.limits.MaxLogBytesPerBlock, receipts, profile.limits.MaxReceiptBytesPerBlock, gas, profile.limits.MaxComputePerBlock, commonBytes, rewardContent, profile.limits.MaxBlockBytes/4, body, profile.limits.MaxBlockBytes, manifestComponents, fits)
			t.Logf("certificate layout sensitivity: favorable co-selection assumes%d full512-hash certificates with only the last partial; one selected item per full certificate instead requires%d certificates and%d certificate-list bytes before transactions/references/rewards, exceeding body cap%d. aggregateFits is conditional on the favorable layout", batches, n, fragmentedCertificates, profile.limits.MaxBlockBytes)
		})
	}
	testEVMSyntheticMixedBlobAndLanes(t, config, block, sidecars)
	t.Run("research_actual_lane_budgets", func(t *testing.T) { testEVMResearchActualLaneBudgets(t, config, genesis.GasLimit, block, sidecars) })
	t.Run("four_slot_rate_budget", func(t *testing.T) {
		// One fast transfer-only proposal and three slow proposals serve this
		// exact assumed second. Count each proposal's own certificate rounding.
		counts := [4][3]uint64{{100_000, 0, 0}, {0, 50_000, 83_334}, {0, 50_000, 83_333}, {0, 50_000, 83_333}}
		var total, accesses, gas, signed, logs, certificates, commonBytes uint64
		for _, classes := range counts {
			n := classes[0] + classes[1] + classes[2]
			batches := (n + types.MaxCommonTxAdmissionBatchItems - 1) / types.MaxCommonTxAdmissionBatchItems
			rewards := classes[0]*sidecars.rewards[0] + classes[1]*sidecars.rewards[1] + classes[2]*sidecars.rewards[2]
			commonBytes += rlpListSizeChecked(batches*sidecars.certificate) + rlpListSizeChecked(evmSyntheticRefContent(n)) + rlpListSizeChecked(rewards)
			certificates += batches
			total += n
			accesses += classes[0]*3 + classes[1]*20 + classes[2]*40
			gas += classes[0]*params.TxGas + classes[1]*150_000 + classes[2]*250_000
			signed += classes[0]*114 + classes[1]*300 + classes[2]*400
			logs += classes[1]*1715 + classes[2]*956
		}
		if total != 500_000 || accesses != 13_300_000 || gas != 87_100_000_000 || signed != 156_400_000 || logs != 496_250_000 || certificates != 979 {
			t.Fatal("four one-lane proposals changed the assumed 20/30/50 per-second demand")
		}
		if accesses <= 4*baseline.MaxAccessesPerBlock || logs <= 4*baseline.MaxLogBytesPerBlock {
			t.Fatal("unchanged access/log limits must still reject the assumed 500k per-second demand")
		}
		// Measure only small encoded framing, using an actual BLS QC. This is
		// neither full-size execution nor a CPU, disk, network or RSS benchmark.
		_, secrets, public, keyHash := makeFHSCommitProofValidator(t)
		header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), ParentHash: common.Hash{1}, KeyHash: keyHash,
			TxHash: types.EmptyRootHash, ReceiptHash: types.EmptyRootHash, UncleHash: types.EmptyUncleHash}
		header.SetFHSSlot(401)
		sample := types.NewBlockWithHeader(header)
		_, qc := makeFHSCommitProofQC(t, sample, 7, "slot-cost", common.Hash{}, secrets, public)
		qcBytes, err := hotstuff.EncodeSignedState(qc)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := EncodeFHSCommitProof(singleFHSCommitProof(qc))
		if err != nil {
			t.Fatal(err)
		}
		headerBytes, err := rlp.EncodeToBytes(header)
		if err != nil {
			t.Fatal(err)
		}
		const headerUncleAllowance = uint64(64 * 1024)
		fixedReserve := headerUncleAllowance + params.FairHotstuffFinalityProofReserveBytes
		if 4*fixedReserve != 4_456_512 || len(proof) > params.FairHotstuffFinalityProofReserveBytes {
			t.Fatal("per-block fixed body reservation changed")
		}
		t.Logf("ASSUMED four-slot second: one fast100000 and slow133334/133333/133333, totalTx=%d accessDemand=%d currentAccessCapacityPerSecond=%d retainedLogDemandB=%d currentLogCapacityPerSecondB=%d gas=%d signedB=%d packedCertificates=%d commonSidecarB=%d fixedBodyReservePerBlockB=%d perSecondB=%d (slot Extra already within header allowance); no per-block limit or 2GiB lease increase", total, accesses, 4*baseline.MaxAccessesPerBlock, logs, 4*baseline.MaxLogBytesPerBlock, gas, signed, certificates, commonBytes, fixedReserve, 4*fixedReserve)
		t.Logf("small signed encoding sample only: headerB=%d unsignedEmptyBodyB=%d proposalRefB=%d QCB=%d singleQCFinalityB=%d; at four such samples per second headerB=%d QCB=%d finalityB=%d. QC, embedded proof and body are overlapping representations, not a summed wire/RSS budget; transport/storage/CPU costs remain unmeasured", len(headerBytes), len(sample.EncodeToBytes()), len(qc.State), len(qcBytes), len(proof), 4*len(headerBytes), 4*len(qcBytes), 4*len(proof))
	})
	t.Log("The opt-in research profile and slot clock permit bounded experiments; occupancy and four-slot budgets remain assumptions. Header.Time and EVM forks retain Unix seconds; the checked-in genesis now enables the research profile. Cadence eligibility and encoding arithmetic prove no sustained TPS.")
}

func testEVMSyntheticMixedBlobAndLanes(t *testing.T, config *params.ChainConfig, block *types.Block, sidecars evmSyntheticSidecarSize) {
	t.Helper()
	if params.MaxBlobsPerTransaction(config, block.Time()) != params.BlobTxMaxBlobs || params.BlobTxMaxBlobs != 6 {
		t.Fatal("Osaka per-transaction blob cap must remain distinct from the 288-blob block cap")
	}
	for _, tx := range block.Transactions() {
		if ClassifyTxLane(tx) != TxLaneFast {
			t.Fatal("the existing 20-transaction execution fixture changed its all-fast classification")
		}
	}
	for _, sample := range []struct {
		name  string
		gas   uint64
		data  []byte
		lane  TxLane
		class TxResourceClass
	}{{"transfer", params.TxGas, nil, TxLaneFast, TxClassNative}, {"erc20_selector", 80_000, []byte{0xa9, 0x05, 0x9c, 0xbb}, TxLaneFast, TxClassERC20}, {"dex_selector", 150_000, []byte{0x38, 0xed, 0x17, 0x39}, TxLaneSlow, TxClassDex}, {"generic_250k_call", 250_000, make([]byte, 32), TxLaneFast, TxClassSmallCall}, {"generic_350k_call", 350_000, make([]byte, 32), TxLaneSlow, TxClassHeavy}} {
		tx := types.NewTransaction(0, common.Address{1}, new(big.Int), sample.gas, big.NewInt(params.FixedTransferGasPricePerGas), sample.data)
		if ClassifyTxLane(tx) != sample.lane || ClassifyTxResource(tx) != sample.class {
			t.Fatalf("actual classifier sample %s differs", sample.name)
		}
	}
	t.Log("actual execution fixture: all 20 transactions fast; DEX/perpetual fixture names describe storage shapes, not lane classification or deployed contract measurements. ERC20 fraction and real selectors/gas limits are unspecified.")
	// One proposal contains one lane. Slot shares below are explicit service
	// assumptions, not a consequence of the existing adaptive scheduler.
	for _, share := range []struct{ fastPercent, fastSlots uint64 }{{20, 1}, {70, 3}, {100, 4}} {
		fastRate, slowRate := 500_000*share.fastPercent/100, 500_000*(100-share.fastPercent)/100
		fastPerBlock := (fastRate + share.fastSlots - 1) / share.fastSlots
		slowSlots, slowPerBlock := 4-share.fastSlots, uint64(0)
		if slowSlots != 0 {
			slowPerBlock = (slowRate + slowSlots - 1) / slowSlots
		}
		t.Logf("hypothetical 250ms lane service: fastSharePercent=%d assumed fast/slowSlotsPerSecond=%d/%d required fast/slowTxPerBlock=%d/%d; aggregate125k occupancy cannot be reused independently for both lanes", share.fastPercent, share.fastSlots, slowSlots, fastPerBlock, slowPerBlock)
	}
	// If only the transfer 20%% is fast, one fast and three slow slots need
	// 133334 slow transactions per block. Reweight resource assumptions by the
	// slow 30:50 DEX/perpetual mixture before comparing with the candidate.
	const slowPerBlock = uint64(133_334)
	slowAccesses := (slowPerBlock*325 + 9) / 10
	slowLogs := (slowPerBlock*9925 + 7) / 8
	if slowAccesses > 5_242_880 || slowLogs > 160*(1<<20) {
		t.Fatal("assumed candidate lane access/log envelope unexpectedly changed")
	}
	t.Logf("assumed20%% fast: slow-slot requirement=%d slowAccesses=%d slowRetainedLogB=%d; count/access/log checks alone omit receipts, bytes, graph, and actual service measurements", slowPerBlock, slowAccesses, slowLogs)
	// Measure one bounded sidecar, then scale its encoded size arithmetically.
	oneBlob := types.NewBlobTxSidecar(types.BlobSidecarVersion1, []types.Blob{make([]byte, params.BlobTxBlobBytes)}, make([]types.KZGCommitment, 1), make([]types.KZGProof, types.BlobCellProofsPerBlob))
	encodedBlob, err := rlp.EncodeToBytes(oneBlob)
	if err != nil {
		t.Fatal(err)
	}
	maximumBlobs := params.MaxBlobGasPerBlock(config.ActiveBlobConfig(block.Time())) / params.BlobTxBlobGasPerBlob
	osakaSidecarEnvelope := rlpListSizeChecked(maximumBlobs * uint64(len(encodedBlob)))
	candidate := *params.FHS250msResearchEVMParallelConfig()
	local := *config
	local.NativeParallel = &candidate
	local.SetModernForkConfig(config.ModernForkConfig())
	defer local.SetModernForkConfig(nil)
	for _, lane := range []struct {
		name                               string
		count, accesses, gas, signed, logs uint64
		tx                                 *types.Transaction
	}{{"fast_transfer_only", 100_000, 300_000, 100_000 * params.TxGas, 100_000 * 114, 0, block.Transactions()[0]}, {"slow_assumed_30_to_50", slowPerBlock, slowAccesses, slowPerBlock * 212_500, (slowPerBlock*3625 + 9) / 10, slowLogs, block.Transactions()[5]}} {
		h, w := evmRuntimeRetainedMemoryWeight(&local, int(lane.count)), evmRuntimeTransactionMemoryWeight(&local, block.Header(), lane.tx)
		batches := (lane.count + types.MaxCommonTxAdmissionBatchItems - 1) / types.MaxCommonTxAdmissionBatchItems
		// All measured declared-gas reward entries are 92 B; taking their
		// maximum also covers any class-dependent width within this sample.
		rewardContent := lane.count * max(sidecars.rewards[0], max(sidecars.rewards[1], sidecars.rewards[2]))
		commonBytes := rlpListSizeChecked(batches*sidecars.certificate) + rlpListSizeChecked(evmSyntheticRefContent(lane.count)) + rlpListSizeChecked(rewardContent)
		bodyContent := rlpListSizeChecked(lane.signed+4*lane.count) + commonBytes + 64*1024 + params.FairHotstuffFinalityProofReserveBytes + 1
		body, withBlob := rlpListSizeChecked(bodyContent), rlpListSizeChecked(bodyContent-1+osakaSidecarEnvelope)
		receiptContent := lane.count * sidecars.receipts[0]
		if lane.name == "slow_assumed_30_to_50" {
			receiptContent = (lane.count*(3*sidecars.receipts[1]+5*sidecars.receipts[2]) + 7) / 8
		}
		receipts := rlpListSizeChecked(receiptContent)
		fragmentedCertificates := rlpListSizeChecked(lane.count * sidecars.certificate)
		if lane.count > candidate.MaxTransactionsPerBlock || lane.accesses > candidate.MaxAccessesPerBlock || lane.gas > candidate.MaxComputePerBlock || lane.logs > candidate.MaxLogBytesPerBlock || receipts > candidate.MaxReceiptBytesPerBlock || body > candidate.MaxBlockBytes || withBlob > candidate.MaxBlockBytes || rewardContent > candidate.MaxBlockBytes/4 || fragmentedCertificates <= candidate.MaxBlockBytes || h+w >= nativeExecutionMemoryBudget {
			t.Fatalf("assumed per-lane candidate resource bound changed: %s", lane.name)
		}
		if lane.gas <= candidate.MaxCriticalPathCompute || lane.count <= candidate.MaxDependencyDepth {
			t.Fatalf("one serial conflict chain should exceed both graph caps: %s", lane.name)
		}
		minimumChains := max((lane.gas+candidate.MaxCriticalPathCompute-1)/candidate.MaxCriticalPathCompute, (lane.count+candidate.MaxDependencyDepth-1)/candidate.MaxDependencyDepth)
		t.Logf("contrasting assumed graph per-lane=%s: one serial chain gas=%d exceeds criticalPathCap=%d and depth=%d exceeds depthCap=%d; partition into independent equal-work chains requires at least%d chains by arithmetic. This lower requirement is insufficient without actual state/nonce dependencies; total lane gas is not a measured critical path", lane.name, lane.gas, candidate.MaxCriticalPathCompute, lane.count, candidate.MaxDependencyDepth, minimumChains)
		t.Logf("hypothetical candidate per-lane=%s count=%d access=%d gas=%d signedPayloadB=%d retainedLogB=%d sampledReceiptListB=%d commonSidecarB=%d rewardPayloadB=%d bodyEnvelopeB=%d maximumOsakaSidecarEnvelopeB=%d bodyWithBlobComponentsB=%d bodyHeadroomWithBlobB=%d fragmentedCertificateListB=%d H=%d representativeW=%d HplusW=%d; favorable packed certificates and representative one-log receipt shapes assumed; H uses conservative1024 accesses/tx", lane.name, lane.count, lane.accesses, lane.gas, lane.signed, lane.logs, receipts, commonBytes, rewardContent, body, osakaSidecarEnvelope, withBlob, candidate.MaxBlockBytes-withBlob, fragmentedCertificates, h, w, h+w)
	}
	t.Log("per-lane blob addition is component sensitivity: assigning blob transactions to a lane, replacement of modeled transactions and additional signed blob metadata are unspecified assumptions; this does not prove a complete valid block. State graph, actual receipt widths, lane service and copy lifetime remain unmeasured.")
	t.Log("legacy cadence: fast eligible after70ms; slow1s,250ms at512 pending,100ms at2048,70ms at8192. The distributed250ms profile instead uses bounded backlog preference and aging; neither policy guarantees the modeled useful lane allocation.")
	for _, fork := range []struct {
		name    string
		version byte
		limits  *params.BlobConfig
	}{{"cancun", types.BlobSidecarVersion0, config.ModernForkConfig().BlobSchedule.Cancun}, {"prague", types.BlobSidecarVersion0, config.ModernForkConfig().BlobSchedule.Prague}, {"osaka", types.BlobSidecarVersion1, config.ModernForkConfig().BlobSchedule.Osaka}} {
		proofs := 1
		if fork.version == types.BlobSidecarVersion1 {
			proofs = types.BlobCellProofsPerBlob
		}
		sidecar := types.NewBlobTxSidecar(fork.version, []types.Blob{make([]byte, params.BlobTxBlobBytes)}, make([]types.KZGCommitment, 1), make([]types.KZGProof, proofs))
		if err := sidecar.ValidateShape(); err != nil {
			t.Fatal(err)
		}
		encoded, err := rlp.EncodeToBytes(sidecar)
		if err != nil {
			t.Fatal(err)
		}
		maximum := params.MaxBlobGasPerBlock(fork.limits) / params.BlobTxBlobGasPerBlob
		raw := params.BlobTxBlobBytes + 48 + uint64(proofs)*48
		if maximum != uint64(fork.limits.Max) || maximum != 288 || maximum*raw > 160*(1<<20)/4 {
			t.Fatalf("actual root genesis fork blob ceiling changed: %s", fork.name)
		}
		for _, copies := range []uint64{1, 4, 16} {
			t.Logf("blob sensitivity fork=%s maximumBlobs=%d blobGasCap=%d proofsPerBlob=%d rawBPerBlob=%d measuredOneBlobSidecarRLPB=%d rawAtMaxB=%d assumedCopies=%d copyBytes=%d separateSidecarListEnvelopeB=%d; Osaka caps6 blobs/tx independently; defensive copies and encoded body are outside H+W, copy count/RSS unmeasured; model mix does not specify blob incidence", fork.name, maximum, params.MaxBlobGasPerBlock(fork.limits), proofs, raw, len(encoded), maximum*raw, copies, copies*maximum*raw, rlpListSizeChecked(maximum*uint64(len(encoded))))
		}
	}
}

// Every large workload here is a count or encoded-component arithmetic. Only
// classifier examples, receipt shapes and one blob are materialized.
func testEVMResearchActualLaneBudgets(t *testing.T, source *params.ChainConfig, genesisGasLimit uint64, block *types.Block, sizes evmSyntheticSidecarSize) {
	config := *source
	config.NativeParallel = params.FHS250msResearchEVMParallelConfig()
	config.FairHotstuffSlotMillis = params.FairHotstuffSlotDurationMillis
	config.SetModernForkConfig(source.ModernForkConfig())
	defer config.SetModernForkConfig(nil)
	if err := config.CheckConfigForkOrder(); err != nil || !config.FairHotstuffSlotEnabled() || !config.IsOsaka(block.Number(), block.Time()) {
		t.Fatalf("active whole-chain research profile: %v", err)
	}
	limits := config.NativeParallel
	work := params.FairHotstuffEVMWorkLimitsForConfig(&config)
	makeTx := func(gas uint64, data []byte) *types.Transaction {
		return types.NewTransaction(0, common.Address{1}, new(big.Int), gas, big.NewInt(params.FixedTransferGasPricePerGas), data)
	}
	native := makeTx(params.TxGas, nil)
	dex := makeTx(150_000, []byte{0x38, 0xed, 0x17, 0x39})
	genericPerp := makeTx(250_000, make([]byte, 32))
	slowPerp := makeTx(250_000, []byte{0xac, 0x96, 0x50, 0xd8})
	erc20 := makeTx(80_000, []byte{0xa9, 0x05, 0x9c, 0xbb})
	if ClassifyTxResource(native) != TxClassNative || ClassifyTxLane(native) != TxLaneFast ||
		ClassifyTxResource(dex) != TxClassDex || ClassifyTxLane(dex) != TxLaneSlow ||
		ClassifyTxResource(genericPerp) != TxClassSmallCall || ClassifyTxLane(genericPerp) != TxLaneFast ||
		ClassifyTxResource(slowPerp) != TxClassDex || ClassifyTxLane(slowPerp) != TxLaneSlow ||
		ClassifyTxResource(erc20) != TxClassERC20 || ClassifyTxLane(erc20) != TxLaneFast {
		t.Fatal("research lane arithmetic must follow the actual signed-field classifier")
	}
	ceil := func(n, d uint64) uint64 { return (n + d - 1) / d }
	// The selector stops at an opposite-lane nonce prerequisite, retaining one
	// lane per proposal. The starting count needs three fast opportunities by
	// count plus two slow by DEX logs. N=175k is the exact two-fast-slot count
	// threshold for this construction; actual sender prefixes can reduce service.
	const startingN = uint64(150_000)
	slowDEXCapacity := limits.MaxLogBytesPerBlock / 1715
	if ceil(350_000, startingN)+ceil(150_000, slowDEXCapacity) != 5 || limits.MaxTransactionsPerBlock != 175_000 || ceil(350_000, limits.MaxTransactionsPerBlock)+ceil(150_000, slowDEXCapacity) != 4 {
		t.Fatal("lane-disjoint opportunity/count correction changed")
	}
	if (limits.MaxTransactionsPerBlock-1)*2 >= 350_000 {
		t.Fatal("research count correction is not minimal for two lane-disjoint fast opportunities")
	}
	oneBlob := types.NewBlobTxSidecar(types.BlobSidecarVersion1, []types.Blob{make([]byte, params.BlobTxBlobBytes)}, make([]types.KZGCommitment, 1), make([]types.KZGProof, types.BlobCellProofsPerBlob))
	encodedBlob, err := rlp.EncodeToBytes(oneBlob)
	if err != nil {
		t.Fatal(err)
	}
	blobCount := params.MaxBlobGasPerBlock(config.ActiveBlobConfig(block.Time())) / params.BlobTxBlobGasPerBlob
	blobEnvelope := rlpListSizeChecked(blobCount * uint64(len(encodedBlob)))
	rawBlobs := blobCount * (params.BlobTxBlobBytes + 48 + 48*types.BlobCellProofsPerBlob)
	maxTx := makeTx(params.MaxTxGas, nil)
	worstWeight := evmRuntimeTransactionMemoryWeight(&config, block.Header(), maxTx) + limits.MaxTransactionBytes - uint64(maxTx.Size())
	// Repeated hot storage can violate the original path cap with only 17
	// maximum-gas observations, far below aggregate count/gas/depth ceilings.
	hotResource := evmMVCCResource{kind: evmMVCCStorageResource, address: common.Address{7}, slot: common.Hash{1}}
	hot := evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{hotResource: {}}}
	pathMeter := newEVMRuntimeDependencyMeter(&config)
	var pathErr error
	for index := uint64(0); index <= limits.MaxCriticalPathCompute/params.MaxTxGas; index++ {
		if pathErr = pathMeter.Add(int(index), common.BigToAddress(new(big.Int).SetUint64(index+1)), hot, params.MaxTxGas); pathErr != nil {
			break
		}
	}
	var pathLimit *EVMRuntimeWorkLimitError
	if !errors.As(pathErr, &pathLimit) || pathLimit.Dimension != "critical path compute" || pathLimit.Observed != limits.MaxCriticalPathCompute+params.MaxTxGas {
		t.Fatalf("hot-state original critical-path failure: %v", pathErr)
	}
	depthConfig, depthLimits := config, *limits
	depthLimits.MaxDependencyDepth = 1 // Isolate depth while original path/gas still fit.
	depthConfig.NativeParallel = &depthLimits
	depthMeter := newEVMRuntimeDependencyMeter(&depthConfig)
	if err := depthMeter.Add(0, common.Address{1}, hot, params.TxGas); err != nil {
		t.Fatal(err)
	}
	depthErr := depthMeter.Add(1, common.Address{2}, hot, params.TxGas)
	var depthLimit *EVMRuntimeWorkLimitError
	if !errors.As(depthErr, &depthLimit) || depthLimit.Dimension != "dependency depth" || depthLimit.Observed != 2 {
		t.Fatalf("independent hot-state depth failure: %v", depthErr)
	}
	for _, scenario := range []struct {
		name   string
		perp   *types.Transaction
		counts [4][3]uint64
		lanes  [4]TxLane
	}{
		{"generic_perp_fast_two_fast_two_slow", genericPerp, [4][3]uint64{{50_000, 0, 125_000}, {0, 75_000, 0}, {50_000, 0, 125_000}, {0, 75_000, 0}}, [4]TxLane{TxLaneFast, TxLaneSlow, TxLaneFast, TxLaneSlow}},
		{"recognized_multicall_perp_slow_one_fast_three_slow", slowPerp, [4][3]uint64{{100_000, 0, 0}, {0, 50_000, 83_334}, {0, 50_000, 83_333}, {0, 50_000, 83_333}}, [4]TxLane{TxLaneFast, TxLaneSlow, TxLaneSlow, TxLaneSlow}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var totals [3]uint64
			var totalGas, totalLogs, totalReceipts, totalBody, totalCertificates uint64
			for slot, counts := range scenario.counts {
				var n, accesses, gas, signed, logs, receiptContent, rewards uint64
				for class, tx := range []*types.Transaction{native, dex, scenario.perp} {
					count := counts[class]
					if count != 0 && ClassifyTxLane(tx) != scenario.lanes[slot] {
						t.Fatalf("slot %d class %d cannot enter this lane", slot, class)
					}
					totals[class] += count
					n += count
					accesses += count * [3]uint64{3, 20, 40}[class]
					gas += count * [3]uint64{params.TxGas, 150_000, 250_000}[class]
					signed += count * [3]uint64{114, 300, 400}[class]
					logs += count * [3]uint64{0, 1715, 956}[class]
					receiptContent += count * sizes.receipts[class]
					rewards += count * sizes.rewards[class]
				}
				batches := ceil(n, types.MaxCommonTxAdmissionBatchItems)
				admissions := rlpListSizeChecked(batches*sizes.certificate) + rlpListSizeChecked(evmSyntheticRefContent(n))
				commonBytes := admissions + rlpListSizeChecked(rewards)
				bodyContent := rlpListSizeChecked(signed+4*n) + commonBytes + 64*1024 + params.FairHotstuffFinalityProofReserveBytes + 1
				body, withBlob := rlpListSizeChecked(bodyContent), rlpListSizeChecked(bodyContent-1+blobEnvelope)
				receipts := rlpListSizeChecked(receiptContent)
				if n > work.Transactions || accesses > limits.MaxAccessesPerBlock || gas > limits.MaxComputePerBlock || gas > genesisGasLimit || logs > limits.MaxLogBytesPerBlock || receipts > limits.MaxReceiptBytesPerBlock || withBlob > limits.MaxBlockBytes || rewards > work.CommonTxRewardPayloadBytes || batches > work.CommonTxAdmissionBatches || admissions > work.CommonTxAdmissionPayloadBytes {
					t.Fatalf("actual-lane scalar budget fails slot=%d N=%d accesses=%d gas=%d logs=%d receipts=%d bodyWithBlob=%d rewards=%d", slot, n, accesses, gas, logs, receipts, withBlob, rewards)
				}
				fragmented := rlpListSizeChecked(n * sizes.certificate)
				if fragmented <= limits.MaxBlockBytes || ceil(gas, limits.MaxCriticalPathCompute) <= 1 || ceil(n, limits.MaxDependencyDepth) <= 1 {
					t.Fatal("fragmented certificates and one hot-state chain must remain explicit failures")
				}
				h := evmRuntimeRetainedMemoryWeight(&config, int(n))
				if h+worstWeight >= nativeExecutionMemoryBudget {
					t.Fatalf("maximum allowed Osaka transaction cannot make progress: H=%d Wmax=%d", h, worstWeight)
				}
				maximumBatch := min(uint64(evmOptimisticMicroBatch), (nativeExecutionMemoryBudget-h)/worstWeight) * worstWeight
				for _, copies := range []uint64{1, 4, 16} {
					t.Logf("combined component sensitivity slot=%d HplusMaximumBatchB=%d encodedBodyWithBlobB=%d rawBlobCopies=%d rawBlobCopyB=%d componentSumB=%d; body/sidecar copies are outside the scheduler lease and may overlap physically; no measured copy lifetime, heap or RSS bound", slot, h+maximumBatch, withBlob, copies, copies*rawBlobs, h+maximumBatch+withBlob+copies*rawBlobs)
				}
				totalGas, totalLogs, totalReceipts, totalBody, totalCertificates = totalGas+gas, totalLogs+logs, totalReceipts+receipts, totalBody+body, totalCertificates+batches
				t.Logf("conditional 250ms slot=%d lane=%d counts=%v N=%d/%d accesses=%d/%d gas=%d logs=%d/%d receiptListB=%d/%d signedPayloadB=%d admissionB=%d rewardPayloadB=%d/%d bodyB=%d bodyWithMaximumBlobComponentsB=%d/%d packedCertificates=%d fragmentedCertificateB=%d H=%d Wmax=%d HplusWmax=%d minimumIndependentChainLowerBound=%d; exact one-log receipt samples, favorable admission co-selection, header allowance and unchanged per-transaction limits", slot, scenario.lanes[slot], counts, n, limits.MaxTransactionsPerBlock, accesses, limits.MaxAccessesPerBlock, gas, logs, limits.MaxLogBytesPerBlock, receipts, limits.MaxReceiptBytesPerBlock, signed, admissions, rewards, work.CommonTxRewardPayloadBytes, body, withBlob, limits.MaxBlockBytes, batches, fragmented, h, worstWeight, h+worstWeight, max(ceil(gas, limits.MaxCriticalPathCompute), ceil(n, limits.MaxDependencyDepth)))
			}
			if totals != [3]uint64{100_000, 150_000, 250_000} || totalGas != 87_100_000_000 || totalLogs != 496_250_000 {
				t.Fatal("four one-lane slots changed the 20/30/50 scalar target")
			}
			t.Logf("500k/s arithmetic budget: classCounts=%v slots=4 averageTxPerSlot=125000 gasPerSecond=%d retainedLogsPerSecondB=%d sampledReceiptListsPerSecondB=%d bodyPerSecondB=%d packedCertificates=%d; slot allocation is an existence assumption, not guaranteed service or measured throughput", totals, totalGas, totalLogs, totalReceipts, totalBody, totalCertificates)
		})
	}
	if 175_000*40 <= limits.MaxAccessesPerBlock || 150_000*1715 <= limits.MaxLogBytesPerBlock || 50_000*5+125_000*40 <= limits.MaxAccessesPerBlock || 175_000*params.MaxFHSCommonTxRewardBytesPerReward <= work.CommonTxRewardPayloadBytes {
		t.Fatal("class and reward-width sensitivities must independently exceed finite aggregate caps")
	}
	if 50_000*3+400_000*40 <= 3*limits.MaxAccessesPerBlock || 4*slowDEXCapacity >= 500_000 {
		t.Fatal("heavier lane/class shares unexpectedly meet the reference rate")
	}
	// Replacing perps by DEX within the narrow 1:3 slow slot holds count
	// constant but consumes an extra 759 retained bytes for every replacement.
	const narrowLogs = uint64(50_000*1715 + 83_334*956)
	narrowSlack := limits.MaxLogBytesPerBlock - narrowLogs
	firstFailingReplacement := narrowSlack/(1715-956) + 1
	if narrowSlack != 2_354_856 || firstFailingReplacement != 3103 || narrowLogs+firstFailingReplacement*(1715-956) <= limits.MaxLogBytesPerBlock {
		t.Fatal("slow-slot class sensitivity changed")
	}
	t.Logf("explicit failures: original path-cap hot-state=%v; isolated depth=%v; recognized-slow-perp slot log slackB=%d, replacing%d perps with DEX exceeds logs by%dB; five-access ERC20 assumption in generic fast slot exceeds access cap by%d despite fast classification", pathErr, depthErr, narrowSlack, firstFailingReplacement, narrowLogs+firstFailingReplacement*(1715-956)-limits.MaxLogBytesPerBlock, 50_000*5+125_000*40-limits.MaxAccessesPerBlock)
	t.Logf("class/lane-share sensitivity: assumed10/10/80 with generic perps fast requires fast accesses=%d >threeFastSlotsAccesses=%d plus at least one DEX slow slot; pure assumedDEX has log-only upper bound%d/s at four slots. These show the reference mix is not a universal500k/s envelope", 50_000*3+400_000*40, 3*limits.MaxAccessesPerBlock, 4*slowDEXCapacity)
	t.Logf("time-envelope change only: unchanged per-block gas=%d gives nominal four-slot gas/s=%d versus one-slot gas/s=%d; root blob ceiling=%d gives nominal maxBlobs/s=%d versus%d, independently6/tx; replay512blocks spans nominal128s versus512s with no missed slots. These per-second and elapsed-time effects follow cadence, not measured sustainable execution", limits.MaxComputePerBlock, 4*limits.MaxComputePerBlock, limits.MaxComputePerBlock, blobCount, 4*blobCount, blobCount)
	t.Log("Sensitivity: all-perp175k fast block exceeds accesses; one150k DEX slow block exceeds retained logs; maximum256B rewards at175k exceed independent B/4. Ordinary ERC20 ratio, selectors, accesses, gas, log topics and real receipt distributions are unspecified; a fast ERC20 classification does not inherit transfer resource assumptions. Fair lane opportunities do not guarantee the explicit2:2 or1:3 successful service allocation, useful work completion, or250ms wall-clock execution. Critical-path/depth chain lower bounds require a real state/nonce graph; one hot shared-state chain fails even when aggregates fit.")
}

// evmSyntheticMixedCode performs two read/modify/write storage operations and
// emits a log. The optional child adds a second contract/frame. These bytecode
// fixtures represent resource shapes, without modeling real market semantics.
func evmSyntheticMixedCode(child *common.Address, memoryBytes, logBytes uint16) []byte {
	var code []byte
	for offset := byte(0); offset < 2; offset++ {
		code = append(code, 0x60, 0, 0x35, 0x60, offset, 0x01, 0x80, 0x54, 0x60, 1, 0x01, 0x90, 0x55)
	}
	code = append(code, 0x60, 1, 0x61, byte((memoryBytes-1)>>8), byte(memoryBytes-1), 0x53)
	if child != nil {
		// Forward the slot key in one calldata word while parent memory is live.
		code = append(code, 0x60, 0, 0x35, 0x60, 0, 0x52)
		code = append(code, 0x60, 0, 0x60, 0, 0x60, 32, 0x60, 0, 0x60, 0, 0x73)
		code = append(code, child[:]...)
		code = append(code, 0x5a, 0xf1, 0x50)
	}
	return append(code, 0x60, 1, 0x60, 2, 0x61, byte(logBytes>>8), byte(logBytes), 0x60, 0, 0xa2, 0x00)
}

func evmSyntheticMixedFixture(t testing.TB, count int, hot bool) (*params.ChainConfig, *state.StateDB, *types.Block) {
	t.Helper()
	// At most 40 senders, three tiny code images, 160 storage writes and 40
	// short receipts keep the fixture comfortably below its 128 MiB estimate.
	// Even 40 simultaneous 24 KiB interpreter memories total less than 1 MiB.
	// The much larger conservative scheduler reservations allocate no buffers.
	if count <= 0 || count > 40 || count%10 != 0 {
		t.Fatal("synthetic fixture must contain 10, 20, 30, or 40 transactions")
	}
	config := evmMVCTestConfig()
	config.EIP150Block = big.NewInt(0)
	base, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	dex, perp, child := common.HexToAddress("0xd001"), common.HexToAddress("0xd002"), common.HexToAddress("0xd003")
	base.SetCode(dex, evmSyntheticMixedCode(nil, 4096, 128))
	base.SetCode(perp, evmSyntheticMixedCode(&child, 8192, 128))
	base.SetCode(child, evmSyntheticMixedCode(nil, 16384, 256))
	for _, address := range []common.Address{dex, perp, child} {
		base.SetNonce(address, 1)
	}
	txs := make(types.Transactions, count)
	var gasLimit uint64
	for index := range txs {
		key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", index+1))
		if err != nil {
			t.Fatal(err)
		}
		base.SetBalance(crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
		to := common.BigToAddress(big.NewInt(int64(0xe000 + index)))
		gas, data := uint64(params.TxGas), []byte(nil)
		value := big.NewInt(1)
		class := index % 10
		if class >= 2 {
			value = new(big.Int)
			to, gas = dex, 150_000
			if class >= 5 {
				to, gas = perp, 250_000
			}
			slot := uint64(index * 4)
			if hot {
				slot = 0
			}
			data = evmMVCCStorageCallData(slot, 1)[:32]
		}
		unsigned := types.NewTransaction(0, to, value, gas, big.NewInt(params.FixedTransferGasPricePerGas), data)
		txs[index], err = types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
		gasLimit += gas
	}
	base.Finalise(true)
	header := &types.Header{Number: big.NewInt(1), Time: 1, Difficulty: big.NewInt(1), GasLimit: gasLimit, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
	return config, base, types.NewBlockWithHeader(header).WithBody(txs, nil)
}

func TestEVMSyntheticMixedMatchesSerialAndMemoryPlan(t *testing.T) {
	testEVMSyntheticMixedMatchesSerialAndMemoryPlan(t, false)
}

func TestEVMResearchProfileMixedMatchesSerialAndMemoryPlan(t *testing.T) {
	testEVMSyntheticMixedMatchesSerialAndMemoryPlan(t, true)
}

func testEVMSyntheticMixedMatchesSerialAndMemoryPlan(t *testing.T, research bool) {
	originalSlots := parallelValidationSlots
	defer func() { parallelValidationSlots = originalSlots }()
	for _, hot := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared_storage_%t", hot), func(t *testing.T) {
			config, base, block := evmSyntheticMixedFixture(t, 20, hot)
			if research {
				fixtureConfig := config
				encoded, err := os.ReadFile("../genesis.json")
				var genesis Genesis
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(encoded, &genesis); err != nil {
					t.Fatal(err)
				}
				config = genesis.Config
				config.ChainID = fixtureConfig.ChainID // Keep the bounded fixture's actual signatures.
				config.NativeParallel = params.FHS250msResearchEVMParallelConfig()
				config.FairHotstuffSlotMillis = params.FairHotstuffSlotDurationMillis
				t.Cleanup(func() { config.SetModernForkConfig(nil); fixtureConfig.SetModernForkConfig(nil) })
				if err := config.CheckConfigForkOrder(); err != nil || !config.FairHotstuffSlotEnabled() || !config.IsOsaka(block.Number(), block.Time()) || config.GetMaxCodeSize(block.Number()) != 128*1024 {
					t.Fatalf("research differential requires active valid slot/Osaka/128KiB profile: %v", err)
				}
				header := block.Header()
				header.SetFHSSlot(4) // Slot four starts at Unix second one.
				block = types.NewBlockWithHeader(header).WithBody(block.Transactions(), nil)
			}
			engine := colossusX.NewFaker()
			defer engine.Close()
			chain := &BlockChain{chainConfig: config, engine: engine}
			processor := NewStateProcessor(config, chain, engine)
			header, txs := block.Header(), block.Transactions()
			serial := base.Copy()
			pool := new(GasPool).AddGas(block.GasLimit())
			var used, signedBytes, bodyItems, accesses, retainedLogs, receiptContent, maximumDepth, criticalPath uint64
			var receipts types.Receipts
			weights := make([]uint64, len(txs))
			accessSets := make([]evmMVCCAccessSet, len(txs))
			senders := make([]common.Address, len(txs))
			dependency := newEVMRuntimeDependencyMeter(config)
			for index, tx := range txs {
				receipt, access, err := executeRecordedEVMSerial(config, chain, block, serial, pool, &used, tx, index, vm.Config{})
				if err != nil || receipt == nil || receipt.Status != types.ReceiptStatusSuccessful {
					t.Fatalf("serial mixed transaction %d: receipt=%v err=%v", index, receipt, err)
				}
				receipts = append(receipts, receipt)
				meter := &evmRuntimeAccessMeter{maxPerTransaction: ^uint64(0), maxPerBlock: ^uint64(0)}
				if err := meter.Add(index, access); err != nil {
					t.Fatal(err)
				}
				accesses += meter.total
				measured, err := measureExecutionOutput(receipt)
				if err != nil {
					t.Fatal(err)
				}
				retainedLogs += measured.logRetained
				receiptContent += measured.receiptEntry
				signed, err := tx.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				signedBytes += uint64(len(signed))
				body, err := rlp.EncodeToBytes(tx)
				if err != nil {
					t.Fatal(err)
				}
				bodyItems += uint64(len(body))
				weights[index] = evmRuntimeTransactionMemoryWeight(config, header, tx)
				sender, err := types.Sender(types.LatestSignerForChainID(config.ChainID), tx)
				if err != nil {
					t.Fatal(err)
				}
				if err := dependency.Add(index, sender, access, receipt.GasUsed); err != nil {
					t.Fatal(err)
				}
				accessSets[index], senders[index] = access, sender
				path := dependency.frontiers.accounts[sender]
				if path.depth > maximumDepth {
					maximumDepth = path.depth
				}
				if path.finish > criticalPath {
					criticalPath = path.finish
				}
			}
			if (!hot && maximumDepth != 1) || (hot && maximumDepth <= 1) {
				t.Fatalf("unexpected mixed storage graph: hot=%t maximumDepth=%d", hot, maximumDepth)
			}
			encodedReceipts, err := rlp.EncodeToBytes(receipts)
			if err != nil || rlpListSizeChecked(receiptContent) != uint64(len(encodedReceipts)) {
				t.Fatalf("canonical receipt-list accounting: bytes=%d error=%v", len(encodedReceipts), err)
			}
			for _, count := range []uint64{125_000, 500_000} {
				t.Logf("measured-fixture receipt scaling sensitivity: sampleTx=%d projectedTx=%d receiptListB=%d; repeated fixture entry sizes only, excludes cumulative-gas integer/list growth and unknown real-contract receipts, not a deployment capacity guarantee", len(txs), count, rlpListSizeChecked(receiptContent*count/uint64(len(txs))))
			}
			retained := evmRuntimeRetainedMemoryWeight(config, len(txs))
			var maxWeight uint64
			for _, weight := range weights {
				if weight > maxWeight {
					maxWeight = weight
				}
			}
			// Alternate local window capacities exercise the real scheduler helper.
			// The actual executor below keeps its configured 2 GiB lease.
			for _, capacity := range []uint64{maxWeight, 2 * maxWeight, nativeExecutionMemoryBudget - retained} {
				for start := 0; start < len(weights); {
					end, batch := evmOptimisticMemoryBatchEndWithin(start, weights, capacity)
					if end <= start || batch > capacity || end-start > evmOptimisticMicroBatch || retained+batch > nativeExecutionMemoryBudget {
						t.Fatalf("invalid mixed window start=%d end=%d batch=%d capacity=%d retained=%d", start, end, batch, capacity, retained)
					}
					start = end
				}
			}
			if end, _ := evmOptimisticMemoryBatchEndWithin(0, []uint64{maxWeight}, maxWeight-1); end != 0 {
				t.Fatal("overweight mixed transaction was scheduled")
			}
			// Observe aggregate live interpreter memory across both call frames.
			trace := &evmReservationMemoryTrace{live: make(map[int]uint64)}
			traced := base.Copy()
			var tracedGas uint64
			_, _, err = executeRecordedEVMSerial(config, chain, block, traced, new(GasPool).AddGas(block.GasLimit()), &tracedGas, txs[5], 5, vm.Config{Debug: true, Tracer: trace})
			if err != nil || trace.depth < 2 || trace.peak <= 16384 || trace.peak > 128*1024 {
				t.Fatalf("nested mixed memory trace depth=%d liveB=%d error=%v", trace.depth, trace.peak, err)
			}
			root := serial.IntermediateRoot(true)
			for _, workers := range []int{1, 2, 4} {
				parallelValidationSlots = make(chan struct{}, workers)
				parallel := base.Copy()
				parallelPool := new(GasPool).AddGas(block.GasLimit())
				var parallelUsed uint64
				var parallelReceipts types.Receipts
				err := processor.processEVMOptimistic(block, parallel, parallelPool, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
					parallelReceipts = append(parallelReceipts, receipt)
					return nil
				})
				if err != nil || parallel.IntermediateRoot(true) != root || parallelUsed != used || parallelPool.Gas() != pool.Gas() || !reflect.DeepEqual(parallelReceipts, receipts) || types.DeriveSha(parallelReceipts, new(trie.Trie)) != types.DeriveSha(receipts, new(trie.Trie)) {
					t.Fatalf("mixed workers=%d serial mismatch gas=%d/%d error=%v", workers, parallelUsed, used, err)
				}
			}
			// Explicit boundary failure must be a deterministic admission dimension.
			limited := *config
			localLimits := *config.NativeParallel
			limited.NativeParallel = &localLimits
			localLimits.MaxAccessesPerBlock = accesses - 1
			limitedAccess := newEVMRuntimeAccessMeter(&limited)
			var accessErr error
			for index, access := range accessSets {
				if accessErr = limitedAccess.Add(index, access); accessErr != nil {
					break
				}
			}
			var accessLimit *EVMRuntimeWorkLimitError
			if !errors.As(accessErr, &accessLimit) || accessLimit.Dimension != "block runtime accesses" || accessLimit.Observed != accesses {
				t.Fatalf("mixed access boundary rejection=%v", accessErr)
			}
			localLimits.MaxDependencyDepth = 1
			limitedDependency := newEVMRuntimeDependencyMeter(&limited)
			var dependencyErr error
			for index, access := range accessSets {
				if dependencyErr = limitedDependency.Add(index, senders[index], access, receipts[index].GasUsed); dependencyErr != nil {
					break
				}
			}
			var dependencyLimit *EVMRuntimeWorkLimitError
			if hot && (!errors.As(dependencyErr, &dependencyLimit) || dependencyLimit.Dimension != "dependency depth") || !hot && dependencyErr != nil {
				t.Fatalf("mixed dependency boundary hot=%t rejection=%v", hot, dependencyErr)
			}
			output := newBlockExecutionOutputMeter(config)
			for index, receipt := range receipts {
				if err := output.Add(index, receipt); err != nil {
					t.Fatal(err)
				}
			}
			localLimits.MaxLogBytesPerBlock = retainedLogs - 1
			limitedLogs := newBlockExecutionOutputMeter(&limited)
			var logErr error
			for index, receipt := range receipts {
				if logErr = limitedLogs.Add(index, receipt); logErr != nil {
					break
				}
			}
			if logErr == nil {
				t.Fatal("one-byte-short retained log limit accepted mixed logs")
			}
			localLimits.MaxLogBytesPerBlock = config.NativeParallel.MaxLogBytesPerBlock
			localLimits.MaxReceiptBytesPerBlock = uint64(len(encodedReceipts)) - 1
			limitedOutput := newBlockExecutionOutputMeter(&limited)
			var outputErr error
			for index, receipt := range receipts {
				if outputErr = limitedOutput.Add(index, receipt); outputErr != nil {
					break
				}
			}
			if outputErr == nil {
				t.Fatal("one-byte-short canonical receipt limit accepted mixed receipts")
			}
			t.Logf("measured synthetic fixture: tx=%d gas=%d accesses=%d signedB=%d canonicalTxItemsB=%d retainedLogB=%d receiptListB=%d retainedReserveB=%d maxTxReserveB=%d nestedLiveMemoryB=%d frameDepth=%d dependencyDepth=%d criticalPathGas=%d; explicit access rejection=%v; dependency rejection=%v; log rejection=%v; receipt rejection=%v", len(txs), used, accesses, signedBytes, bodyItems, retainedLogs, len(encodedReceipts), retained, maxWeight, trace.peak, trace.depth, maximumDepth, criticalPath, accessErr, dependencyErr, logErr, outputErr)
		})
	}
}

// This benchmark measures local planning over bounded, real signed fixtures;
// reservation bytes and allocations are not hardware throughput or RSS claims.
func BenchmarkEVMSyntheticMixedReservation(b *testing.B) {
	for _, count := range []int{20, 40} {
		b.Run(fmt.Sprintf("tx%d", count), func(b *testing.B) {
			config, _, block := evmSyntheticMixedFixture(b, count, false)
			header, txs := block.Header(), block.Transactions()
			for _, tx := range txs {
				tx.Size()
			}
			retained := evmRuntimeRetainedMemoryWeight(config, count)
			weights := make([]uint64, count)
			b.ReportAllocs()
			b.ResetTimer()
			var lease uint64
			for iteration := 0; iteration < b.N; iteration++ {
				for index, tx := range txs {
					weights[index] = evmRuntimeTransactionMemoryWeight(config, header, tx)
				}
				for start := 0; start < count; {
					end, reserved := evmOptimisticMemoryBatchEndWithin(start, weights, nativeExecutionMemoryBudget-retained)
					if end <= start {
						b.Fatal("mixed fixture reservation cannot advance")
					}
					if retained+reserved > lease {
						lease = retained + reserved
					}
					start = end
				}
			}
			b.ReportMetric(float64(lease), "leaseB")
			b.ReportMetric(float64(count), "tx/plan")
		})
	}
}

func evmMVCCStorageCallData(slot, value uint64) []byte {
	data := make([]byte, 64)
	new(big.Int).SetUint64(slot).FillBytes(data[:32])
	new(big.Int).SetUint64(value).FillBytes(data[32:])
	return data
}

func evmMVCCTestBlock(t *testing.T, config *params.ChainConfig, base *state.StateDB, sameSender bool, count int) (*types.Block, types.Transactions) {
	t.Helper()
	contract := common.HexToAddress("0x8000000000000000000000000000000000000080")
	// CALLDATALOAD(32), CALLDATALOAD(0), SSTORE, STOP. Different calldata
	// keys exercise slot-granular conflict detection inside one contract.
	base.SetCode(contract, []byte{0x60, 0x20, 0x35, 0x60, 0x00, 0x35, 0x55, 0x00})
	base.SetNonce(contract, 1)

	// Use concrete ECDSA keys below. The intentionally small helper keeps the
	// transaction construction identical for independent and nonce-chain cases.
	var senderKey = func() *ecdsa.PrivateKey {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}()

	txs := make(types.Transactions, count)
	signer := types.LatestSignerForChainID(config.ChainID)
	for index := range txs {
		key := senderKey
		nonce := uint64(index)
		if !sameSender {
			key = func() *ecdsa.PrivateKey {
				generated, err := crypto.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				return generated
			}()
			nonce = 0
		}
		from := crypto.PubkeyToAddress(key.PublicKey)
		base.SetBalance(from, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
		unsigned := types.NewTx(&types.DynamicFeeTx{
			ChainID:   config.ChainID,
			Nonce:     nonce,
			GasTipCap: big.NewInt(2),
			GasFeeCap: new(big.Int).Add(
				big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2),
			),
			Gas:   100_000,
			To:    &contract,
			Value: new(big.Int),
			Data:  evmMVCCStorageCallData(uint64(index+1), uint64(index+100)),
		})
		signed, err := types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		txs[index] = signed
	}
	base.Finalise(true)
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc1"),
		Coinbase:   common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   uint64(count) * 100_000,
		Time:       1,
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
	}
	return types.NewBlockWithHeader(header).WithBody(txs, nil), txs
}

func compareEVMOptimisticWithSerial(t *testing.T, sameSender bool, count int) {
	t.Helper()
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	block, txs := evmMVCCTestBlock(t, config, base, sameSender, count)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)

	parallelState := base.Copy()
	parallelGas := new(GasPool).AddGas(block.GasLimit())
	var parallelUsed uint64
	parallelReceipts := make(types.Receipts, 0, len(txs))
	err := processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		parallelReceipts = append(parallelReceipts, receipt)
		return nil
	})
	if err != nil {
		t.Fatalf("optimistic execution: %v", err)
	}

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(block.GasLimit())
	var serialUsed uint64
	serialReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		serialState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, block.Header(), tx, &serialUsed, vm.Config{})
		if err != nil {
			t.Fatalf("serial transaction %d: %v", index, err)
		}
		serialReceipts = append(serialReceipts, receipt)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelUsed != serialUsed || parallelGas.Gas() != serialGas.Gas() || !reflect.DeepEqual(parallelReceipts, serialReceipts) {
		t.Fatalf("optimistic/serial mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t",
			parallelRoot, serialRoot, parallelUsed, serialUsed, parallelGas.Gas(), serialGas.Gas(), reflect.DeepEqual(parallelReceipts, serialReceipts))
	}
}

func TestEVMOptimisticMVCCMatchesSerialForIndependentContractSlots(t *testing.T) {
	compareEVMOptimisticWithSerial(t, false, 16)
}

func TestEVMOptimisticMVCCReexecutesNonceDependencies(t *testing.T) {
	// Transactions after index zero initially observe the old sender nonce and
	// fail speculatively. The sender write from the preceding canonical result
	// makes those failures stale, so each is re-executed and must match serial.
	compareEVMOptimisticWithSerial(t, true, 16)
}

func TestEVMOptimisticMVCCMatchesSerialAcrossMemoryWindows(t *testing.T) {
	compareEVMOptimisticWithSerial(t, false, 130)
}

func TestEVMOptimisticMVCCMatchesSerialForEnvelopeTypesZeroThroughFour(t *testing.T) {
	config := evmMVCTestConfig()
	base := newModernTestState(t)
	signer := types.LatestSignerForChainID(config.ChainID)
	txs := make(types.Transactions, 0, 5)
	gasLimit := uint64(0)
	for txType := uint8(types.LegacyTxType); txType <= types.SetCodeTxType; txType++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		sender := crypto.PubkeyToAddress(key.PublicKey)
		base.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
		to := common.BigToAddress(new(big.Int).SetUint64(uint64(0x9000) + uint64(txType)))
		gas := uint64(params.TxGas)
		var unsigned *types.Transaction
		switch txType {
		case types.LegacyTxType:
			unsigned = types.NewTransaction(0, to, big.NewInt(int64(txType+1)), gas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
		case types.AccessListTxType:
			unsigned = types.NewTx(&types.AccessListTx{
				ChainID: config.ChainID, GasPrice: big.NewInt(params.FixedTransferGasPricePerGas), Gas: gas,
				To: &to, Value: big.NewInt(int64(txType + 1)),
			})
		case types.DynamicFeeTxType:
			unsigned = types.NewTx(&types.DynamicFeeTx{
				ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)), Gas: gas,
				To: &to, Value: big.NewInt(int64(txType + 1)),
			})
		case types.BlobTxType:
			var blobHash common.Hash
			blobHash[0] = types.BlobCommitmentVersionKZG
			blobHash[len(blobHash)-1] = 1
			unsigned = types.NewTx(&types.BlobTx{
				ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)), Gas: gas,
				To: to, Value: big.NewInt(int64(txType + 1)), BlobFeeCap: big.NewInt(2), BlobHashes: []common.Hash{blobHash},
			})
		case types.SetCodeTxType:
			gas = 100_000
			authorityKey, err := crypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{
				ChainID: config.ChainID,
				Address: common.HexToAddress("0x7702000000000000000000000000000000000001"),
			})
			if err != nil {
				t.Fatal(err)
			}
			unsigned = types.NewTx(&types.SetCodeTx{
				ChainID: config.ChainID, GasTipCap: big.NewInt(2), GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)), Gas: gas,
				To: to, Value: big.NewInt(int64(txType + 1)), AuthList: []types.SetCodeAuthorization{authorization},
			})
		}
		signed, err := types.SignTx(unsigned, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, signed)
		gasLimit += gas
	}
	base.Finalise(true)
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc5"), Coinbase: common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: gasLimit, Time: 1,
		BaseFee: big.NewInt(params.FixedBaseFeePerGas), BlobGasUsed: params.BlobTxBlobGasPerBlob,
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)

	parallelState := base.Copy()
	parallelGas := new(GasPool).AddGas(block.GasLimit())
	var parallelUsed uint64
	parallelReceipts := make(types.Receipts, 0, len(txs))
	if err := processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		parallelReceipts = append(parallelReceipts, receipt)
		return nil
	}); err != nil {
		t.Fatalf("optimistic mixed-envelope execution: %v", err)
	}

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(block.GasLimit())
	var serialUsed uint64
	serialReceipts := make(types.Receipts, 0, len(txs))
	for index, tx := range txs {
		serialState.Prepare(tx.Hash(), block.Hash(), index)
		receipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, header, tx, &serialUsed, vm.Config{})
		if err != nil {
			t.Fatalf("serial mixed-envelope transaction %d/type %d: %v", index, tx.Type(), err)
		}
		serialReceipts = append(serialReceipts, receipt)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelUsed != serialUsed || parallelGas.Gas() != serialGas.Gas() || !reflect.DeepEqual(parallelReceipts, serialReceipts) {
		t.Fatalf("mixed-envelope optimistic/serial mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t",
			parallelRoot, serialRoot, parallelUsed, serialUsed, parallelGas.Gas(), serialGas.Gas(), reflect.DeepEqual(parallelReceipts, serialReceipts))
	}
	for index, receipt := range parallelReceipts {
		if receipt.Type != uint8(index) {
			t.Fatalf("receipt %d type = %d, want %d", index, receipt.Type, index)
		}
	}
}

func TestEVMOptimisticMVCCDiscardsRevertedAccountWrites(t *testing.T) {
	config := evmMVCTestConfig()
	database := state.NewDatabase(rawdb.NewMemoryDatabase())
	initial, err := state.New(common.Hash{}, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyAccount := common.HexToAddress("0x7000000000000000000000000000000000000007")
	contract := common.HexToAddress("0x8000000000000000000000000000000000000008")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	initial.CreateAccount(emptyAccount)
	initial.SetCode(contract, revertedStaticCallCode(emptyAccount))
	initial.SetNonce(contract, 1)
	initial.SetBalance(sender, new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
	root, err := initial.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	base, err := state.New(root, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !base.Exist(emptyAccount) || !base.Empty(emptyAccount) {
		t.Fatal("test fixture did not retain the committed empty account")
	}

	unsigned := types.NewTx(&types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     0,
		GasTipCap: big.NewInt(2),
		GasFeeCap: new(big.Int).Add(big.NewInt(params.FixedBaseFeePerGas), big.NewInt(2)),
		Gas:       100_000,
		To:        &contract,
		Value:     new(big.Int),
	})
	tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(config.ChainID), key)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{
		ParentHash: common.HexToHash("0xabc2"),
		Coinbase:   common.HexToAddress("0x9000000000000000000000000000000000000009"),
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   tx.Gas(),
		Time:       1,
		BaseFee:    big.NewInt(params.FixedBaseFeePerGas),
	}
	block := types.NewBlockWithHeader(header).WithBody(types.Transactions{tx}, nil)
	engine := colossusX.NewFaker()
	defer engine.Close()
	chain := &BlockChain{chainConfig: config, engine: engine}
	processor := NewStateProcessor(config, chain, engine)

	parallelState := base.Copy()
	parallelGas := new(GasPool).AddGas(block.GasLimit())
	var parallelUsed uint64
	var parallelReceipt *types.Receipt
	err = processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
		parallelReceipt = receipt
		return nil
	})
	if err != nil {
		t.Fatalf("optimistic execution: %v", err)
	}

	serialState := base.Copy()
	serialGas := new(GasPool).AddGas(block.GasLimit())
	var serialUsed uint64
	serialState.Prepare(tx.Hash(), block.Hash(), 0)
	serialReceipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, header, tx, &serialUsed, vm.Config{})
	if err != nil {
		t.Fatalf("serial execution: %v", err)
	}
	parallelRoot := parallelState.IntermediateRoot(true)
	serialRoot := serialState.IntermediateRoot(true)
	if parallelRoot != serialRoot || parallelState.Exist(emptyAccount) != serialState.Exist(emptyAccount) || !reflect.DeepEqual(parallelReceipt, serialReceipt) {
		t.Fatalf("reverted write changed optimistic state: root=%s/%s emptyExists=%t/%t receiptsEqual=%t",
			parallelRoot, serialRoot, parallelState.Exist(emptyAccount), serialState.Exist(emptyAccount), reflect.DeepEqual(parallelReceipt, serialReceipt))
	}
}

func revertedStaticCallCode(target common.Address) []byte {
	// STATICCALL(target), discard its success flag, then REVERT the outer call.
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73}
	code = append(code, target[:]...)
	return append(code, 0x61, 0xff, 0xff, 0xfa, 0x50, 0x60, 0x00, 0x60, 0x00, 0xfd)
}

func TestEVMMVCCRecorderRevertRestoresWritesButRetainsObservedWork(t *testing.T) {
	statedb := newModernTestState(t)
	persistent := common.HexToAddress("0x11")
	reverted := common.HexToAddress("0x12")
	readOnly := common.HexToAddress("0x13")
	overLimit := common.HexToAddress("0x14")
	recorder := newEVMMVCCRecorder(statedb)
	recorder.setAccessLimit(3)

	recorder.SetNonce(persistent, 1)
	snapshot := recorder.Snapshot()
	recorder.SetNonce(reverted, 1)
	recorder.GetBalance(readOnly)
	recorder.RevertToSnapshot(snapshot)

	account := func(address common.Address) evmMVCCResource {
		return evmMVCCResource{kind: evmMVCCAccountResource, address: address}
	}
	if _, exists := recorder.writes[account(persistent)]; !exists {
		t.Fatal("write made before the snapshot was discarded")
	}
	if _, exists := recorder.writes[account(reverted)]; exists {
		t.Fatal("reverted write remained publishable")
	}
	if _, exists := recorder.reads[account(reverted)]; !exists {
		t.Fatal("reverted write did not retain a conservative dependency")
	}
	if _, exists := recorder.reads[account(readOnly)]; !exists {
		t.Fatal("reverted execution read was discarded")
	}
	if got := len(recorder.seen); got != 3 {
		t.Fatalf("observed work after revert = %d, want 3", got)
	}
	if statedb.Exist(reverted) {
		t.Fatal("underlying StateDB write was not reverted")
	}
	recorder.GetNonce(overLimit)
	if !errors.Is(recorder.Error(), ErrEVMRuntimeAccessLimitExceeded) {
		t.Fatalf("access error = %v, want %v", recorder.Error(), ErrEVMRuntimeAccessLimitExceeded)
	}
}

func TestEVMMVCCRecorderClassifiesZeroBalanceTouches(t *testing.T) {
	statedb := newModernTestState(t)
	nonEmpty := common.HexToAddress("0x15")
	empty := common.HexToAddress("0x16")
	missing := common.HexToAddress("0x17")
	statedb.SetNonce(nonEmpty, 1)
	statedb.CreateAccount(empty)
	recorder := newEVMMVCCRecorder(statedb)
	recorder.AddBalance(nonEmpty, new(big.Int))
	recorder.AddBalance(empty, new(big.Int))
	recorder.AddBalance(missing, new(big.Int))
	recorder.SubBalance(common.HexToAddress("0x18"), new(big.Int))

	resource := func(address common.Address) evmMVCCResource {
		return evmMVCCResource{kind: evmMVCCAccountResource, address: address}
	}
	if _, write := recorder.writes[resource(nonEmpty)]; write {
		t.Fatal("zero balance add made a non-empty contract a whole-account writer")
	}
	if _, read := recorder.reads[resource(nonEmpty)]; !read {
		t.Fatal("zero balance add did not observe the non-empty account")
	}
	if _, write := recorder.writes[resource(empty)]; !write {
		t.Fatal("EIP-161 empty-account touch was not recorded as a write")
	}
	if _, write := recorder.writes[resource(missing)]; write {
		t.Fatal("ephemeral zero touch of a missing account was recorded as persistent")
	}
	if got := len(recorder.seen); got != 3 {
		t.Fatalf("zero balance access count = %d, want 3", got)
	}
}

func TestEVMRuntimeDependencyMeterBoundsCanonicalChains(t *testing.T) {
	config := evmMVCTestConfig()
	config.NativeParallel.MaxComputePerTransaction = 100
	config.NativeParallel.MaxComputePerBlock = 1_000
	config.NativeParallel.MaxCriticalPathCompute = 1_000
	config.NativeParallel.MaxDependencyDepth = 2
	contract := common.HexToAddress("0x21")
	slot := common.HexToHash("0x01")
	storage := evmMVCCResource{kind: evmMVCCStorageResource, address: contract, slot: slot}
	write := evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{storage: {}}}

	meter := newEVMRuntimeDependencyMeter(config)
	if err := meter.Add(0, common.HexToAddress("0x31"), write, 10); err != nil {
		t.Fatal(err)
	}
	if err := meter.Add(1, common.HexToAddress("0x32"), write, 10); err != nil {
		t.Fatal(err)
	}
	err := meter.Add(2, common.HexToAddress("0x33"), write, 10)
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &limitError) || limitError.TransactionIndex != 2 || limitError.Dimension != "dependency depth" || limitError.Observed != 3 {
		t.Fatalf("depth error = %#v, want transaction 2 depth 3", err)
	}

	// A reverted write is represented as a read: it depends on the prior writer
	// but does not become a new writer frontier for the following transaction.
	meter = newEVMRuntimeDependencyMeter(config)
	if err := meter.Add(0, common.HexToAddress("0x41"), write, 10); err != nil {
		t.Fatal(err)
	}
	revertedWrite := evmMVCCAccessSet{reads: map[evmMVCCResource]struct{}{storage: {}}}
	if err := meter.Add(1, common.HexToAddress("0x42"), revertedWrite, 10); err != nil {
		t.Fatal(err)
	}
	if err := meter.Add(2, common.HexToAddress("0x43"), revertedWrite, 10); err != nil {
		t.Fatalf("reverted write extended the writer chain: %v", err)
	}

	// Disjoint resources remain at depth one, while the explicit sender frontier
	// serializes same-sender nonce/fee updates even if a recorder were incomplete.
	config.NativeParallel.MaxCriticalPathCompute = 10
	meter = newEVMRuntimeDependencyMeter(config)
	otherSlot := evmMVCCResource{kind: evmMVCCStorageResource, address: contract, slot: common.HexToHash("0x02")}
	if err := meter.Add(0, common.HexToAddress("0x51"), write, 10); err != nil {
		t.Fatal(err)
	}
	if err := meter.Add(1, common.HexToAddress("0x52"), evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{otherSlot: {}}}, 10); err != nil {
		t.Fatalf("disjoint slot inherited a critical path: %v", err)
	}
	meter = newEVMRuntimeDependencyMeter(config)
	sender := common.HexToAddress("0x53")
	if err := meter.Add(0, sender, evmMVCCAccessSet{}, 10); err != nil {
		t.Fatal(err)
	}
	err = meter.Add(1, sender, evmMVCCAccessSet{}, 10)
	if !errors.As(err, &limitError) || limitError.Dimension != "critical path compute" || limitError.Observed != 20 {
		t.Fatalf("sender critical-path error = %#v, want compute 20", err)
	}
}

func TestEVMRuntimeMetersRejectArithmeticOverflow(t *testing.T) {
	config := evmMVCTestConfig()
	config.NativeParallel.MaxComputePerTransaction = ^uint64(0)
	config.NativeParallel.MaxComputePerBlock = ^uint64(0)
	config.NativeParallel.MaxCriticalPathCompute = ^uint64(0)
	config.NativeParallel.MaxDependencyDepth = ^uint64(0)
	sender := common.HexToAddress("0x61")

	blockMeter := newEVMRuntimeDependencyMeter(config)
	blockMeter.totalCompute = ^uint64(0) - 5
	err := blockMeter.Add(4, sender, evmMVCCAccessSet{}, 10)
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &limitError) || limitError.Dimension != "block compute" || limitError.Observed != ^uint64(0) {
		t.Fatalf("block compute overflow error = %#v", err)
	}

	pathMeter := newEVMRuntimeDependencyMeter(config)
	pathMeter.frontiers.accounts[sender] = evmRuntimePath{depth: 1, finish: ^uint64(0) - 5}
	err = pathMeter.Add(5, sender, evmMVCCAccessSet{}, 10)
	if !errors.As(err, &limitError) || limitError.Dimension != "critical path compute" || limitError.Observed != ^uint64(0) {
		t.Fatalf("critical path overflow error = %#v", err)
	}

	accessMeter := &evmRuntimeAccessMeter{maxPerTransaction: ^uint64(0), maxPerBlock: ^uint64(0), total: ^uint64(0) - 1}
	first := evmMVCCResource{kind: evmMVCCAccountResource, address: common.HexToAddress("0x62")}
	second := evmMVCCResource{kind: evmMVCCAccountResource, address: common.HexToAddress("0x63")}
	err = accessMeter.Add(6, evmMVCCAccessSet{reads: map[evmMVCCResource]struct{}{first: {}, second: {}}})
	if !errors.As(err, &limitError) || limitError.Dimension != "block runtime accesses" || limitError.Observed != ^uint64(0) {
		t.Fatalf("block access overflow error = %#v", err)
	}
}

func TestEVMOptimisticMVCCChargesCanonicalDependencyOnce(t *testing.T) {
	run := func(limit uint64) error {
		config := evmMVCTestConfig()
		config.NativeParallel.MaxDependencyDepth = limit
		base := newModernTestState(t)
		block, _ := evmMVCCTestBlock(t, config, base, true, 16)
		engine := colossusX.NewFaker()
		defer engine.Close()
		chain := &BlockChain{chainConfig: config, engine: engine}
		processor := NewStateProcessor(config, chain, engine)
		statedb := base.Copy()
		gasPool := new(GasPool).AddGas(block.GasLimit())
		var usedGas uint64
		return processor.processEVMOptimistic(block, statedb, gasPool, &usedGas, vm.Config{}, func(int, *types.Transaction, *types.Receipt) error { return nil })
	}
	if err := run(16); err != nil {
		t.Fatalf("exact canonical dependency boundary rejected: %v", err)
	}
	err := run(15)
	var executionError *EVMTransactionExecutionError
	var limitError *EVMRuntimeWorkLimitError
	if !errors.As(err, &executionError) || !errors.As(err, &limitError) {
		t.Fatalf("dependency limit did not retain typed causes: %v", err)
	}
	if executionError.TransactionIndex != 15 || limitError.TransactionIndex != 15 || limitError.Dimension != "dependency depth" || limitError.Observed != 16 {
		t.Fatalf("dependency limit error = %#v / %#v, want transaction 15 depth 16", executionError, limitError)
	}
}

func TestEVMRuntimeMemorySchedulingUsesNestedGasBound(t *testing.T) {
	configured := uint64(64 * 1024 * 1024)
	logical := evmGasBoundedLogicalMemory(params.MaxTxGas, configured, true)
	// A single-frame inversion is about 3 MiB, but nested calls can keep many
	// separately metered memories live. The scheduler must not use that unsafe
	// single-frame estimate for its process-wide reservation.
	if logical <= 3*1024*1024 {
		t.Fatalf("nested logical memory bound = %d, want more than single-frame 3 MiB", logical)
	}
	if logical > configured {
		t.Fatalf("nested logical memory bound = %d, exceeds configured limit %d", logical, configured)
	}
	if preEIP150 := evmGasBoundedLogicalMemory(params.MaxTxGas, configured, false); preEIP150 < logical || preEIP150 > configured {
		t.Fatalf("pre-EIP-150 memory bound = %d, want range [%d,%d]", preEIP150, logical, configured)
	}
	if got := evmGasBoundedLogicalMemory(0, configured, true); got != 0 {
		t.Fatalf("zero-gas memory bound = %d, want 0", got)
	}
}

func TestEVMRuntimeAggregateMemoryGasHandlesQuadraticRounding(t *testing.T) {
	// Balancing 46 words as 23+23 costs 140 gas, whereas 15+31 costs 139.
	// Rounding each quadratic term down invalidates discrete convexity.
	if got := evmMinimumAggregateMemoryGas(46, 2); got > 139 {
		t.Fatalf("aggregate lower bound = %d, exceeds feasible 139 gas", got)
	}
	const maximumWords, maximumFrames = 160, 5
	minimum := make([][]uint64, maximumFrames+1)
	minimum[0] = make([]uint64, maximumWords+1)
	for words := 1; words <= maximumWords; words++ {
		minimum[0][words] = ^uint64(0) / 2
	}
	for frames := 1; frames <= maximumFrames; frames++ {
		minimum[frames] = make([]uint64, maximumWords+1)
		for words := 0; words <= maximumWords; words++ {
			best := ^uint64(0) / 2
			for last := 0; last <= words; last++ {
				lastWords := uint64(last)
				// Exact single-frame schedule from vm.memoryGasCost.
				cost := minimum[frames-1][words-last] + lastWords*params.MemoryGas + lastWords*lastWords/params.QuadCoeffDiv
				if cost < best {
					best = cost
				}
			}
			minimum[frames][words] = best
			if lower := evmMinimumAggregateMemoryGas(uint64(words), uint64(frames)); lower > best {
				t.Fatalf("words=%d frames=%d lower=%d exceeds exhaustive minimum=%d", words, frames, lower, best)
			}
		}
	}
	for _, frames := range []uint64{1, 2, 8, 128, params.CallCreateDepth + 1} {
		var previous uint64
		for words := uint64(0); words <= 4096; words++ {
			lower := evmMinimumAggregateMemoryGas(words, frames)
			if lower < previous {
				t.Fatalf("nonmonotone lower bound at words=%d frames=%d: %d < %d", words, frames, lower, previous)
			}
			previous = lower
		}
	}
}

func TestEVMRuntimeMemoryGasBoundCoversFeasibleFrameAllocations(t *testing.T) {
	const limit = uint64(params.NativeParallelHardMaxMemory)
	for _, eip150 := range []bool{false, true} {
		for seed := uint64(1); seed <= 256; seed++ {
			var totalWords, expansionGas uint64
			for frame := uint64(0); frame < 8; frame++ {
				words := (seed*7919 + frame*3571) % 4096
				totalWords += words
				expansionGas += words*params.MemoryGas + words*words/params.QuadCoeffDiv
			}
			// This extra gas is enough for more than eight warm calls and their
			// EIP-150 forwarding loss; the expansion budget is deliberately loose.
			gas := expansionGas + 100_000
			if frames := evmMaximumLiveMemoryFrames(gas, eip150); frames < 8 {
				t.Fatalf("fixture has only %d possible frames", frames)
			}
			if bound := evmGasBoundedLogicalMemory(gas, limit, eip150); bound < totalWords*32 {
				t.Fatalf("seed=%d EIP150=%t bound=%d below feasible memory=%d", seed, eip150, bound, totalWords*32)
			}
		}
	}
}

type evmReservationMemoryTrace struct {
	live  map[int]uint64
	peak  uint64
	depth int
}

func (trace *evmReservationMemoryTrace) CaptureStart(common.Address, common.Address, bool, []byte, uint64, *big.Int) error {
	return nil
}

func (trace *evmReservationMemoryTrace) CaptureEnd([]byte, uint64, time.Duration, error) error {
	return nil
}

func (trace *evmReservationMemoryTrace) CaptureFault(*vm.EVM, uint64, vm.OpCode, uint64, uint64, *vm.Memory, *vm.Stack, *vm.ReturnStack, *vm.Contract, int, error) error {
	return nil
}

func (trace *evmReservationMemoryTrace) CaptureState(_ *vm.EVM, _ uint64, _ vm.OpCode, _, _ uint64, memory *vm.Memory, _ *vm.Stack, _ *vm.ReturnStack, _ []byte, _ *vm.Contract, depth int, _ error) error {
	for previous := range trace.live {
		if previous > depth {
			delete(trace.live, previous)
		}
	}
	trace.live[depth] = uint64(memory.Len())
	var total uint64
	for _, bytes := range trace.live {
		total += bytes
	}
	if total > trace.peak {
		trace.peak = total
	}
	if depth > trace.depth {
		trace.depth = depth
	}
	return nil
}

func TestEVMRuntimeMemoryReservationMatchesNestedSerialAcrossForksAndWorkers(t *testing.T) {
	originalSlots := parallelValidationSlots
	defer func() { parallelValidationSlots = originalSlots }()
	for _, fork := range []string{"istanbul", "berlin", "shanghai", "prague", "osaka"} {
		for _, value := range []byte{0, 1} {
			for _, memoryLimit := range []uint64{128 * 1024, 64 * 1024 * 1024} {
				t.Run(fmt.Sprintf("%s/value%d/memory%d", fork, value, memoryLimit), func(t *testing.T) {
					config := modernTestConfig(fork != "istanbul", fork != "istanbul" && fork != "berlin", fork != "istanbul" && fork != "berlin")
					if fork == "prague" || fork == "osaka" {
						config = modernExecutionTestConfig(true, fork == "osaka")
					}
					config.EIP150Block = big.NewInt(0)
					config.NativeParallel = params.SolanaScaleEVMParallelConfig()
					config.NativeParallel.MaxMemoryBytesPerTransaction = memoryLimit
					base := newModernTestState(t)
					contract := common.HexToAddress("0x8000000000000000000000000000000000000080")
					// Keep 4096 bytes live in each recursive frame, emit a log, then
					// CALL self with all available gas. Value calls exercise stipends.
					code := []byte{0x60, 1, 0x61, 0x0f, 0xff, 0x53, 0x60, 32, 0x60, 0, 0xa0}
					for index := 0; index < 4; index++ {
						code = append(code, 0x60, 0)
					}
					code = append(code, 0x60, value, 0x30, 0x5a, 0xf1, 0x50, 0x00)
					base.SetCode(contract, code)
					base.SetNonce(contract, 1)
					base.SetBalance(contract, big.NewInt(1_000_000))
					const count, gas = 4, uint64(200_000)
					txs := make(types.Transactions, count)
					for index := range txs {
						key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", index+1))
						if err != nil {
							t.Fatal(err)
						}
						base.SetBalance(crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil))
						tx := types.NewTransaction(0, contract, new(big.Int), gas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
						txs[index], err = types.SignTx(tx, types.LatestSignerForChainID(config.ChainID), key)
						if err != nil {
							t.Fatal(err)
						}
					}
					base.Finalise(true)
					header := &types.Header{Number: big.NewInt(1), Time: 1, Difficulty: big.NewInt(1), GasLimit: count * gas, BaseFee: big.NewInt(params.FixedBaseFeePerGas)}
					block := types.NewBlockWithHeader(header).WithBody(txs, nil)
					engine := colossusX.NewFaker()
					defer engine.Close()
					chain := &BlockChain{chainConfig: config, engine: engine}
					processor := NewStateProcessor(config, chain, engine)
					serial := base.Copy()
					serialPool := new(GasPool).AddGas(block.GasLimit())
					var serialGas uint64
					var serialReceipts types.Receipts
					for index, tx := range txs {
						serial.Prepare(tx.Hash(), block.Hash(), index)
						receipt, err := ApplyTransaction(config, chain, nil, serialPool, serial, header, tx, &serialGas, vm.Config{})
						if err != nil || receipt.Status != types.ReceiptStatusSuccessful || len(receipt.Logs) == 0 {
							t.Fatalf("serial transaction %d failed: receipt=%v error=%v", index, receipt, err)
						}
						serialReceipts = append(serialReceipts, receipt)
					}
					serialRoot := serial.IntermediateRoot(true)
					trace := &evmReservationMemoryTrace{live: make(map[int]uint64)}
					traced := base.Copy()
					traced.Prepare(txs[0].Hash(), block.Hash(), 0)
					var tracedGas uint64
					if _, err := ApplyTransaction(config, chain, nil, new(GasPool).AddGas(gas), traced, header, txs[0], &tracedGas, vm.Config{Debug: true, Tracer: trace}); err != nil {
						t.Fatal(err)
					}
					upperGas := evmRuntimeExecutionGasUpperBound(txs[0])
					logical := evmGasBoundedLogicalMemory(upperGas, memoryLimit, true)
					if trace.depth < 2 || trace.peak <= 4096 || trace.peak > logical || uint64(trace.depth) > evmMaximumLiveMemoryFrames(upperGas, true) {
						t.Fatalf("trace depth=%d peak=%d exceeds frame/memory bound=%d/%d", trace.depth, trace.peak, evmMaximumLiveMemoryFrames(upperGas, true), logical)
					}
					for _, workers := range []int{1, 2, 4} {
						parallelValidationSlots = make(chan struct{}, workers)
						parallel := base.Copy()
						pool := new(GasPool).AddGas(block.GasLimit())
						var used uint64
						var receipts types.Receipts
						err := processor.processEVMOptimistic(block, parallel, pool, &used, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
							receipts = append(receipts, receipt)
							return nil
						})
						if err != nil {
							t.Fatalf("workers=%d: %v", workers, err)
						}
						if root := parallel.IntermediateRoot(true); root != serialRoot || used != serialGas || pool.Gas() != serialPool.Gas() || !reflect.DeepEqual(receipts, serialReceipts) || types.DeriveSha(receipts, new(trie.Trie)) != types.DeriveSha(serialReceipts, new(trie.Trie)) {
							t.Fatalf("workers=%d serial mismatch root=%s/%s gas=%d/%d receipts=%t", workers, root, serialRoot, used, serialGas, reflect.DeepEqual(receipts, serialReceipts))
						}
					}
				})
			}
		}
	}
}

func TestEVMRuntimeExecutionGasBoundRetainsIntrinsicExtrasAcrossForks(t *testing.T) {
	to := common.HexToAddress("0x81")
	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{{1}, {2}}}}
	data := []byte{0, 1, 2, 0}
	fixtures := []*types.Transaction{
		types.NewTransaction(0, to, new(big.Int), 0, big.NewInt(1), nil),
		types.NewTransaction(0, to, new(big.Int), params.TxGas-1, big.NewInt(1), nil),
		types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil),
		types.NewTransaction(0, to, new(big.Int), 100_000, big.NewInt(1), data),
		types.NewContractCreation(0, new(big.Int), params.TxGasContractCreation, big.NewInt(1), nil),
		types.NewContractCreation(0, new(big.Int), 100_000, big.NewInt(1), data),
		types.NewContractCreation(0, new(big.Int), 100_000, big.NewInt(1), make([]byte, 32)),
		types.NewContractCreation(0, new(big.Int), 100_000, big.NewInt(1), make([]byte, 33)),
		types.NewContractCreation(0, new(big.Int), params.MaxTxGas, big.NewInt(1), make([]byte, params.MaxInitCodeSize)),
		types.NewContractCreation(0, new(big.Int), params.MaxTxGas, big.NewInt(1), make([]byte, params.MaxInitCodeSize+1)),
		types.NewTransaction(0, to, new(big.Int), ^uint64(0), big.NewInt(1), data),
		types.NewTx(&types.AccessListTx{ChainID: big.NewInt(1), To: &to, Gas: 100_000, GasPrice: big.NewInt(1), AccessList: accessList, Data: data}),
		types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), To: &to, Gas: 100_000, GasFeeCap: big.NewInt(1), AccessList: accessList, Data: data}),
		types.NewTx(&types.BlobTx{ChainID: big.NewInt(1), To: to, Gas: 100_000, GasFeeCap: big.NewInt(1), AccessList: accessList, Data: data}),
		types.NewTx(&types.SetCodeTx{ChainID: big.NewInt(1), To: to, Gas: 200_000, GasFeeCap: big.NewInt(1), AuthList: make([]types.SetCodeAuthorization, 4)}),
	}
	for _, config := range []*params.ChainConfig{
		{ChainID: big.NewInt(1)},
		modernTestConfig(false, false, false),
		modernTestConfig(true, false, false),
		modernTestConfig(true, true, true),
		modernExecutionTestConfig(true, false),
		modernExecutionTestConfig(true, true),
	} {
		rules := config.CypheriumRules(big.NewInt(1), 1)
		for index, tx := range fixtures {
			base := params.TxGas
			if tx.To() == nil {
				base = params.TxGasContractCreation
			}
			bound := evmRuntimeExecutionGasUpperBound(tx)
			if tx.Gas() <= base {
				if bound != 0 {
					t.Fatalf("fixture=%d gas=%d bound=%d, want zero", index, tx.Gas(), bound)
				}
				continue
			}
			intrinsic, err := IntrinsicGasWithRulesAndAuthorizations(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), tx.To() == nil, rules)
			if err != nil {
				if rules.IsShanghai && errors.Is(err, ErrMaxInitCodeSizeExceeded) {
					continue // This shape is rejected before entering the EVM.
				}
				t.Fatal(err)
			}
			if bound != tx.Gas()-base || intrinsic > tx.Gas() || bound < tx.Gas()-intrinsic {
				t.Fatalf("fixture=%d bound=%d gas=%d intrinsic=%d base=%d", index, bound, tx.Gas(), intrinsic, base)
			}
			if authGas := tx.SetCodeAuthorizationCount() * params.CallNewAccountGas; authGas > bound-(tx.Gas()-intrinsic) {
				t.Fatalf("fixture=%d authorization gas %d was removed from code-load reserve", index, authGas)
			}
		}
	}
	floorTx := types.NewTransaction(0, to, new(big.Int), 200_000, big.NewInt(1), bytes.Repeat([]byte{1}, 4096))
	floor, err := FloorDataGas(floorTx.Data())
	if err != nil {
		t.Fatal(err)
	}
	if bound := evmRuntimeExecutionGasUpperBound(floorTx); bound <= floorTx.Gas()-floor {
		t.Fatalf("Prague floor incorrectly reduced execution-gas upper bound: %d", bound)
	}
}

func TestEVMRuntimeMemoryReservationPreservesNonGasReserves(t *testing.T) {
	config := evmMVCTestConfig()
	config.EIP150Block = big.NewInt(0)
	header := &types.Header{Number: big.NewInt(1)}
	to := common.HexToAddress("0x81")
	tx := types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil)
	limits := config.NativeParallel
	want := nativeBranchBaseMemoryReserve +
		limits.MaxOutputBytesPerTransaction*nativeOutputPhysicalFactor + limits.MaxLogBytesPerTransaction + uint64(tx.Size()) +
		limits.MaxAccessesPerTransaction*(nativeBranchAccountMemoryReserve+nativeBranchStorageMemoryReserve) +
		evmRuntimeCodeLoadBase*uint64(config.GetMaxCodeSize(header.Number))
	if got := evmRuntimeTransactionMemoryWeight(config, header, tx); got != want {
		t.Fatalf("fixed reserves changed: got=%d want=%d", got, want)
	}
	call := types.NewTransaction(0, to, new(big.Int), 41_000, big.NewInt(1), nil)
	berlin := evmRuntimeTransactionMemoryWeight(config, header, call)
	preBerlin := *config
	preBerlin.SetModernForkConfig(new(params.ModernForkConfig))
	frontier := evmRuntimeTransactionMemoryWeight(&preBerlin, header, call)
	if frontier <= berlin {
		t.Fatalf("pre-Berlin cheap code loads not reserved: pre=%d Berlin=%d", frontier, berlin)
	}
	if weight := evmRuntimeTransactionMemoryWeight(nil, header, tx); weight != nativeExecutionMemoryBudget {
		t.Fatalf("missing context reservation=%d, want full budget", weight)
	}
	if got := evmGasBoundedLogicalMemory(params.MaxTxGas, params.NativeParallelHardMaxMemory+1, true); got != params.NativeParallelHardMaxMemory+1 {
		t.Fatalf("invalid configured limit did not fail conservatively: %d", got)
	}
}

// BenchmarkEVMRuntimeMemoryPlanning measures deterministic local reservation
// planning. It does not execute a chain or estimate transaction throughput.
func BenchmarkEVMRuntimeMemoryPlanning(b *testing.B) {
	config := evmMVCTestConfig()
	config.EIP150Block = big.NewInt(0)
	header := &types.Header{Number: big.NewInt(1), Time: 1}
	to := common.HexToAddress("0x81")
	for _, fixture := range []struct {
		name string
		tx   *types.Transaction
	}{
		{"transfer", types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil)},
		{"contract_call", types.NewTransaction(0, to, new(big.Int), 100_000, big.NewInt(1), nil)},
		{"calldata", types.NewTransaction(0, to, new(big.Int), 100_000, big.NewInt(1), bytes.Repeat([]byte{1}, 4096))},
		{"create", types.NewContractCreation(0, new(big.Int), 100_000, big.NewInt(1), make([]byte, 32))},
		{"maximum_gas", types.NewTransaction(0, to, new(big.Int), params.MaxTxGas, big.NewInt(1), nil)},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			const count = 256
			// Populate the immutable transaction's size cache before measuring.
			fixture.tx.Size()
			retained := evmRuntimeRetainedMemoryWeight(config, count)
			capacity := nativeExecutionMemoryBudget - retained
			weight := evmRuntimeTransactionMemoryWeight(config, header, fixture.tx)
			probe := make([]uint64, count)
			for index := range probe {
				probe[index] = weight
			}
			end, reserved := evmOptimisticMemoryBatchEndWithin(0, probe, capacity)
			windows, boundaryVisits := 0, 0
			for start := 0; start < count; windows++ {
				next, _ := evmOptimisticMemoryBatchEndWithin(start, probe, capacity)
				if next <= start {
					b.Fatalf("reservation does not fit: weight=%d capacity=%d", weight, capacity)
				}
				if next < count && next-start < evmOptimisticMicroBatch {
					boundaryVisits++
				}
				start = next
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				weights := make([]uint64, count)
				for index := range weights {
					weights[index] = evmRuntimeTransactionMemoryWeight(config, header, fixture.tx)
				}
				for pass := 0; pass < 2; pass++ {
					for start := 0; start < count; {
						start, _ = evmOptimisticMemoryBatchEndWithin(start, weights, capacity)
					}
				}
			}
			b.ReportMetric(float64(weight), "reserveB/tx")
			b.ReportMetric(float64(retained+reserved), "leaseB")
			b.ReportMetric(float64(end), "windowTx")
			b.ReportMetric(float64(windows), "windows/plan")
			b.ReportMetric(count, "weights/plan")
			b.ReportMetric(float64(2*(count+boundaryVisits)), "batchVisits/plan")
		})
	}
}

func BenchmarkEVMRuntimeMemoryPlanningHeader(b *testing.B) {
	config := evmMVCTestConfig()
	header := &types.Header{Number: big.NewInt(1), Time: 1}
	header.SignInfo.FHSFinalityProof = make([]byte, 1024*1024)
	block := types.NewBlockWithHeader(header)
	to := common.HexToAddress("0x81")
	tx := types.NewTransaction(0, to, new(big.Int), params.TxGas, big.NewInt(1), nil)
	tx.Size()
	for _, shared := range []bool{false, true} {
		b.Run(fmt.Sprintf("shared_header_%t", shared), func(b *testing.B) {
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				var planningHeader *types.Header
				if shared {
					planningHeader = block.Header()
				}
				for index := 0; index < 32; index++ {
					if !shared {
						planningHeader = block.Header()
					}
					if evmRuntimeTransactionMemoryWeight(config, planningHeader, tx) == 0 {
						b.Fatal("missing transaction reserve")
					}
				}
			}
		})
	}
}

func TestEVMRuntimeMemoryBatchesStayWithinProcessLease(t *testing.T) {
	config := evmMVCTestConfig()
	header := &types.Header{Number: big.NewInt(1)}
	makeTx := func(gas uint64) *types.Transaction {
		to := common.HexToAddress("0x81")
		return types.NewTransaction(0, to, new(big.Int), gas, big.NewInt(1), nil)
	}
	lowWeight := evmRuntimeTransactionMemoryWeight(config, header, makeTx(params.TxGas))
	highWeight := evmRuntimeTransactionMemoryWeight(config, header, makeTx(params.MaxTxGas))
	if lowWeight == 0 || lowWeight >= highWeight || highWeight > nativeExecutionMemoryBudget {
		t.Fatalf("unexpected EVM weights low=%d high=%d budget=%d", lowWeight, highWeight, nativeExecutionMemoryBudget)
	}
	weights := make([]uint64, evmOptimisticMicroBatch+3)
	for index := range weights {
		if index%2 == 0 {
			weights[index] = highWeight
		} else {
			weights[index] = lowWeight
		}
	}
	for start := 0; start < len(weights); {
		end, reserved := evmOptimisticMemoryBatchEnd(start, weights)
		if end <= start {
			t.Fatalf("memory scheduler did not advance at %d", start)
		}
		if end-start > evmOptimisticMicroBatch || reserved == 0 || reserved > nativeExecutionMemoryBudget {
			t.Fatalf("invalid memory batch [%d,%d) reserve=%d", start, end, reserved)
		}
		var exact uint64
		for _, weight := range weights[start:end] {
			exact += weight
		}
		if exact != reserved {
			t.Fatalf("memory batch [%d,%d) reserve=%d, exact=%d", start, end, reserved, exact)
		}
		start = end
	}

	end, reserved := evmOptimisticMemoryBatchEnd(0, []uint64{nativeExecutionMemoryBudget, 1})
	if end != 1 || reserved != nativeExecutionMemoryBudget {
		t.Fatalf("full-budget transaction batch = [%d] reserve=%d", end, reserved)
	}
}

func TestEVMRuntimeMemoryLeaseReservesPlanningAndResults(t *testing.T) {
	limits := params.SolanaScaleEVMParallelConfig()
	config := &params.ChainConfig{
		NativeParallel: limits,
		EIP150Block:    big.NewInt(0),
		MaxCodeSizeConfig: []params.MaxCodeConfigStruct{{
			Block: big.NewInt(0),
			Size:  128,
		}},
	}
	retained := evmRuntimeRetainedMemoryWeight(config, int(limits.MaxTransactionsPerBlock))
	if retained == 0 || retained >= nativeExecutionMemoryBudget {
		t.Fatalf("retained EVM reserve = %d, budget %d", retained, nativeExecutionMemoryBudget)
	}
	capacity := nativeExecutionMemoryBudget - retained
	to := common.HexToAddress("0x81")
	maxGasTx := types.NewTransaction(0, to, new(big.Int), params.MaxTxGas, big.NewInt(1), nil)
	weight := evmRuntimeTransactionMemoryWeight(config, &types.Header{Number: big.NewInt(1)}, maxGasTx)
	if weight == 0 || weight > capacity {
		t.Fatalf("maximum-gas transaction weight %d does not fit residual batch capacity %d", weight, capacity)
	}
	end, batch := evmOptimisticMemoryBatchEndWithin(0, []uint64{weight, weight}, capacity)
	if end == 0 || batch > capacity || retained+batch > nativeExecutionMemoryBudget {
		t.Fatalf("retained=%d batch=%d end=%d exceeds budget=%d", retained, batch, end, nativeExecutionMemoryBudget)
	}
	if end, batch := evmOptimisticMemoryBatchEndWithin(0, []uint64{capacity + 1}, capacity); end != 0 || batch != 0 {
		t.Fatalf("overweight transaction was scheduled: end=%d batch=%d capacity=%d", end, batch, capacity)
	}
}

func TestEVMTransactionErrorClassifierPreservesInfrastructureAbort(t *testing.T) {
	stateFailure := errors.New("state trie read failed")
	infrastructure := markEVMExecutionInfrastructure(stateFailure)
	classified := evmTransactionExecutionError(7, fmt.Errorf("execute: %w", infrastructure))
	var transactionError *EVMTransactionExecutionError
	var infrastructureError *EVMExecutionInfrastructureError
	if errors.As(classified, &transactionError) {
		t.Fatalf("infrastructure failure was classified as droppable transaction: %v", classified)
	}
	if !errors.As(classified, &infrastructureError) || !errors.Is(classified, stateFailure) {
		t.Fatalf("infrastructure cause was not preserved: %v", classified)
	}

	candidate := evmTransactionExecutionError(7, errors.New("nonce too low"))
	if !errors.As(candidate, &transactionError) || transactionError.TransactionIndex != 7 {
		t.Fatalf("candidate error was not indexed: %v", candidate)
	}
}

func TestEVMMVCCStorageConflictsRemainSlotGranular(t *testing.T) {
	address := common.HexToAddress("0x1234")
	first := evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{
		{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x01")}: {},
	}}
	index := newEVMMVCCWriteIndex()
	index.add(first)
	independent := evmMVCCAccessSet{
		reads: map[evmMVCCResource]struct{}{
			{kind: evmMVCCAccountResource, address: address}:                                 {},
			{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x02")}: {},
		},
		writes: map[evmMVCCResource]struct{}{
			{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x02")}: {},
		},
	}
	if index.conflicts(independent) {
		t.Fatal("independent storage slots were serialized")
	}
	dependent := evmMVCCAccessSet{reads: map[evmMVCCResource]struct{}{
		{kind: evmMVCCStorageResource, address: address, slot: common.HexToHash("0x01")}: {},
	}}
	if !index.conflicts(dependent) {
		t.Fatal("same-slot dependency was not detected")
	}
}

func TestEVMMVCCTransientConflictsRemainTransactionLocal(t *testing.T) {
	address := common.HexToAddress("0x1234")
	slot := common.HexToHash("0x01")
	temporary := evmMVCCResource{kind: evmMVCCTemporaryStorageResource, address: address, slot: slot}
	for _, kind := range []evmMVCCResourceKind{0, evmMVCCAccountResource, evmMVCCStorageResource, evmMVCCStorageWildcardResource, evmMVCCTemporaryStorageResource} {
		t.Run(fmt.Sprintf("priorKind%d", kind), func(t *testing.T) {
			index := newEVMMVCCWriteIndex()
			if kind != 0 {
				index.add(evmMVCCAccessSet{writes: map[evmMVCCResource]struct{}{
					{kind: kind, address: address, slot: slot}: {},
				}})
			}
			if index.conflictsRead(temporary) || index.conflictsWrite(temporary) {
				t.Fatal("transaction-local transient storage required serial replay")
			}
			persistent := evmMVCCResource{kind: evmMVCCStorageResource, address: address, slot: slot}
			wantPersistentConflict := kind != 0 && kind != evmMVCCTemporaryStorageResource
			if index.conflictsRead(persistent) != wantPersistentConflict || index.conflictsWrite(persistent) != wantPersistentConflict {
				t.Fatal("transient exclusion changed persistent storage validation")
			}
			unknown := evmMVCCResource{kind: 255, address: address, slot: slot}
			if !index.conflictsRead(unknown) || !index.conflictsWrite(unknown) {
				t.Fatal("unknown resources lost conservative validation")
			}
		})
	}
}

func TestEVMMVCCTransientRecorderRetainsAccessAccounting(t *testing.T) {
	statedb := newModernTestState(t)
	address := common.HexToAddress("0x1234")
	first, second, third, fourth := common.HexToHash("0x01"), common.HexToHash("0x02"), common.HexToHash("0x03"), common.HexToHash("0x04")
	value := common.HexToHash("0x99")
	statedb.Prepare(common.HexToHash("0xa1"), common.Hash{}, 0)
	recorder := newEVMMVCCRecorder(statedb)
	recorder.setAccessLimit(3)
	recorder.SetTransientState(address, first, value)
	snapshot := recorder.Snapshot()
	recorder.SetTransientState(address, first, second)
	recorder.SetTransientState(address, second, value)
	recorder.GetTransientState(address, third)
	recorder.RevertToSnapshot(snapshot)
	if got := recorder.GetTransientState(address, first); got != value {
		t.Fatalf("reverted transient overwrite = %s, want %s", got, value)
	}
	if got := recorder.GetTransientState(address, second); got != (common.Hash{}) {
		t.Fatalf("reverted transient write survived: %s", got)
	}
	if got := len(recorder.seen); got != 3 {
		t.Fatalf("transient runtime accesses after revert = %d, want 3", got)
	}
	meter := &evmRuntimeAccessMeter{maxPerTransaction: 3, maxPerBlock: 3}
	if err := meter.Add(0, recorder.accessSet()); err != nil {
		t.Fatal(err)
	}
	if meter.total != 3 {
		t.Fatalf("canonical transient access charge = %d, want 3", meter.total)
	}
	if err := meter.Add(1, recorder.accessSet()); !errors.Is(err, ErrEVMRuntimeAccessLimitExceeded) {
		t.Fatalf("block transient access limit error = %v", err)
	}
	recorder.SetTransientState(address, fourth, value)
	if !errors.Is(recorder.Error(), ErrEVMRuntimeAccessLimitExceeded) {
		t.Fatalf("transaction transient access limit error = %v", recorder.Error())
	}
	if got := statedb.GetTransientState(address, fourth); got != (common.Hash{}) {
		t.Fatalf("over-limit transient write executed: %s", got)
	}
	statedb.Prepare(common.HexToHash("0xa2"), common.Hash{}, 1)
	if got := statedb.GetTransientState(address, first); got != (common.Hash{}) {
		t.Fatalf("transient value survived the transaction boundary: %s", got)
	}
}

func evmMVCCTransientCode(child common.Address, delegate, childRevert, outerRevert, persistent bool) ([]byte, []byte) {
	// Preserve the transaction's initial TLOAD(0) in memory, then write the
	// calldata value to the same transient key in every transaction.
	code := common.FromHex("0x60005c60005260203560005d")
	if persistent {
		// A persistent read/modify/write of slot zero must still force replay.
		code = append(code, common.FromHex("0x60005460010160005d")...)
	}
	var childCode []byte
	if child != (common.Address{}) {
		// The child logs its own initial value and its TSTORE(0, 99).
		childCode = common.FromHex("0x60005c600052606360005d60005c60205260406000a0")
		if childRevert {
			childCode = append(childCode, common.FromHex("0x60006000fd")...)
		} else {
			childCode = append(childCode, byte(vm.STOP))
		}
		// Empty input/output, zero CALL value, child address, gas, CALL or
		// DELEGATECALL. Save the success flag as the parent's third log word.
		code = append(code, common.FromHex("0x6000600060006000")...)
		if !delegate {
			code = append(code, 0x60, 0x00)
		}
		code = append(code, byte(vm.PUSH20))
		code = append(code, child[:]...)
		code = append(code, 0x61, 0xff, 0xff)
		if delegate {
			code = append(code, byte(vm.DELEGATECALL))
		} else {
			code = append(code, byte(vm.CALL))
		}
	} else {
		code = append(code, 0x60, 0x01)
	}
	code = append(code, common.FromHex("0x60405260005c60205260005c")...)
	if persistent {
		code = append(code, 0x60, 0x00)
	} else {
		// Independent persistent slots make the transient result observable in
		// the final root without introducing a cross-transaction dependency.
		code = append(code, 0x60, 0x00, byte(vm.CALLDATALOAD))
	}
	code = append(code, common.FromHex("0x5560606000a0")...)
	if outerRevert {
		code = append(code, common.FromHex("0x60006000fd")...)
	} else {
		code = append(code, byte(vm.STOP))
	}
	return code, childCode
}

func TestEVMOptimisticMVCCTransientMatchesSerial(t *testing.T) {
	contract := common.HexToAddress("0x8000000000000000000000000000000000000080")
	childAddress := common.HexToAddress("0x7000000000000000000000000000000000000070")
	cases := []struct {
		name        string
		nested      bool
		delegate    bool
		childRevert bool
		outerRevert bool
		persistent  bool
	}{
		{name: "direct"},
		{name: "call", nested: true},
		{name: "delegatecall", nested: true, delegate: true},
		{name: "callRevert", nested: true, childRevert: true},
		{name: "delegatecallRevert", nested: true, delegate: true, childRevert: true},
		{name: "outerRevert", outerRevert: true},
		{name: "persistentCollision", persistent: true},
	}
	// These tests are sequential. Change the shared scheduler's actual capacity
	// and restore it before any parallel tests can resume.
	originalSlots := parallelValidationSlots
	defer func() { parallelValidationSlots = originalSlots }()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			config := evmMVCTestConfig()
			base := newModernTestState(t)
			block, txs := evmMVCCTestBlock(t, config, base, false, 4)
			var child common.Address
			if test.nested {
				child = childAddress
			}
			code, childCode := evmMVCCTransientCode(child, test.delegate, test.childRevert, test.outerRevert, test.persistent)
			base.SetCode(contract, code)
			if test.nested {
				base.SetCode(child, childCode)
				base.SetNonce(child, 1)
			}
			base.Finalise(true)
			engine := colossusX.NewFaker()
			defer engine.Close()
			chain := &BlockChain{chainConfig: config, engine: engine}
			processor := NewStateProcessor(config, chain, engine)

			serialState := base.Copy()
			serialGas := new(GasPool).AddGas(block.GasLimit())
			var serialUsed uint64
			serialReceipts := make(types.Receipts, 0, len(txs))
			for index, tx := range txs {
				serialState.Prepare(tx.Hash(), block.Hash(), index)
				receipt, err := ApplyTransaction(config, chain, nil, serialGas, serialState, block.Header(), tx, &serialUsed, vm.Config{})
				if err != nil {
					t.Fatalf("serial transaction %d: %v", index, err)
				}
				serialReceipts = append(serialReceipts, receipt)
				if test.outerRevert {
					if receipt.Status != types.ReceiptStatusFailed || len(receipt.Logs) != 0 {
						t.Fatalf("outer revert receipt %d: status=%d logs=%d", index, receipt.Status, len(receipt.Logs))
					}
					continue
				}
				wantValue := uint64(index + 100)
				if test.delegate && !test.childRevert {
					wantValue = 99
				}
				if test.persistent {
					wantValue = uint64(index + 1)
				}
				wantLogs := 1
				if test.nested && !test.childRevert {
					wantLogs++
				}
				if receipt.Status != types.ReceiptStatusSuccessful || len(receipt.Logs) != wantLogs {
					t.Fatalf("receipt %d: status=%d logs=%d, want success and %d logs", index, receipt.Status, len(receipt.Logs), wantLogs)
				}
				parentLog := receipt.Logs[len(receipt.Logs)-1]
				wantData := make([]byte, 96)
				new(big.Int).SetUint64(wantValue).FillBytes(wantData[32:64])
				if !test.childRevert {
					wantData[95] = 1
				}
				if parentLog.Address != contract || !reflect.DeepEqual(parentLog.Data, wantData) {
					t.Fatalf("parent log %d = %x, want %x at %s", index, parentLog.Data, wantData, contract)
				}
				if wantLogs == 2 {
					wantChildData := make([]byte, 64)
					wantAddress := child
					if test.delegate {
						new(big.Int).SetUint64(uint64(index + 100)).FillBytes(wantChildData[:32])
						wantAddress = contract
					}
					wantChildData[63] = 99
					if receipt.Logs[0].Address != wantAddress || !reflect.DeepEqual(receipt.Logs[0].Data, wantChildData) {
						t.Fatalf("child log %d = %x at %s, want %x at %s", index, receipt.Logs[0].Data, receipt.Logs[0].Address, wantChildData, wantAddress)
					}
				}
				storageSlot := uint64(index + 1)
				if test.persistent {
					storageSlot = 0
				}
				if got := serialState.GetState(contract, common.BigToHash(new(big.Int).SetUint64(storageSlot))); got != common.BigToHash(new(big.Int).SetUint64(wantValue)) {
					t.Fatalf("persistent transient result %d = %s, want %d", index, got, wantValue)
				}
			}
			serialRoot := serialState.IntermediateRoot(true)
			for _, workers := range []int{1, 2, 4} {
				t.Run(fmt.Sprintf("workers%d", workers), func(t *testing.T) {
					parallelValidationSlots = make(chan struct{}, workers)
					parallelState := base.Copy()
					parallelGas := new(GasPool).AddGas(block.GasLimit())
					var parallelUsed uint64
					var parallelReceipts types.Receipts
					err := processor.processEVMOptimistic(block, parallelState, parallelGas, &parallelUsed, vm.Config{}, func(_ int, _ *types.Transaction, receipt *types.Receipt) error {
						parallelReceipts = append(parallelReceipts, receipt)
						return nil
					})
					if err != nil {
						t.Fatalf("optimistic execution: %v", err)
					}
					parallelRoot := parallelState.IntermediateRoot(true)
					if parallelRoot != serialRoot || parallelUsed != serialUsed || parallelGas.Gas() != serialGas.Gas() || !reflect.DeepEqual(parallelReceipts, serialReceipts) {
						t.Fatalf("transient optimistic/serial mismatch: root=%s/%s gas=%d/%d remaining=%d/%d receiptsEqual=%t", parallelRoot.Hex(), serialRoot.Hex(), parallelUsed, serialUsed, parallelGas.Gas(), serialGas.Gas(), reflect.DeepEqual(parallelReceipts, serialReceipts))
					}
				})
			}

			// There is no replay counter in the executor. Check its exact replay
			// predicate using real speculative access sets from one snapshot.
			snapshotState := base.Copy()
			snapshot, err := snapshotState.PrepareRuntimeMVCCSnapshot(true)
			if err != nil {
				t.Fatal(err)
			}
			priorWrites := newEVMMVCCWriteIndex()
			for index, tx := range txs {
				branch, err := snapshot.Branch()
				if err != nil {
					t.Fatal(err)
				}
				result := executeEVMMVCCTransaction(config, chain, block, branch, tx, index, vm.Config{})
				if result.err != nil {
					t.Fatal(result.err)
				}
				wantReplay := test.persistent && index > 0
				if got := priorWrites.conflicts(result.access); got != wantReplay {
					t.Fatalf("transaction %d requires serial replay = %t, want %t", index, got, wantReplay)
				}
				priorWrites.add(result.access)
			}
		})
	}
}
