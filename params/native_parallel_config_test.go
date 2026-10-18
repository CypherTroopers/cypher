package params

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
)

func TestSolanaScaleNativeParallelConfigValid(t *testing.T) {
	config := SolanaScaleEVMParallelConfig()
	if config.RequireNativeTransactions {
		t.Fatal("standard high-capacity profile must accept only Ethereum transaction types 0 through 4")
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("profile is invalid: %v", err)
	}
	if config.MaxTransactionsPerBlock <= MaxTxCountPerBlock {
		t.Fatalf("native transaction ceiling %d did not exceed legacy %d", config.MaxTransactionsPerBlock, MaxTxCountPerBlock)
	}
	if config.MaxTransactionsPerBlock < EVMParallelIngressBurstTransactions {
		t.Fatalf("EVM transaction ceiling %d cannot retain %d TPS for %d seconds", config.MaxTransactionsPerBlock, EVMParallelIngressTargetTPS, EVMParallelIngressBurstSeconds)
	}
	if config.MaxBlockBytes <= MaxBlockSize {
		t.Fatalf("native block ceiling %d did not exceed legacy %d", config.MaxBlockBytes, MaxBlockSize)
	}
	wantDepth := config.MaxCriticalPathCompute / TxGas
	if config.MaxDependencyDepth != wantDepth {
		t.Fatalf("dependency depth %d did not match minimum-gas critical-path ceiling %d", config.MaxDependencyDepth, wantDepth)
	}
	legacyName := SolanaScaleNativeParallelConfig()
	if *legacyName != *config {
		t.Fatalf("internal compatibility helper diverged from EVM profile: got %+v want %+v", legacyName, config)
	}
}

func testFHS250msResearchConfig(t *testing.T) *ChainConfig {
	t.Helper()
	config := testFairHotstuffConfig()
	config.FairHotstuffSlotMillis = FairHotstuffSlotDurationMillis
	config.FixedCommittee = true
	config.MaxCodeSize = 128
	config.NativeParallel = FHS250msResearchEVMParallelConfig()
	zero := uint64(0)
	config.SetModernForkConfig(&ModernForkConfig{
		BerlinBlock: bigInt(0), LondonBlock: bigInt(0),
		ShanghaiTime: &zero, CancunTime: &zero, PragueTime: &zero, OsakaTime: &zero,
		BlobSchedule: &BlobScheduleConfig{
			Cancun: &BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 213662528},
			Prague: &BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 160246912},
			Osaka:  &BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 160246912},
		},
	})
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	return config
}

func TestFHS250msResearchEVMParallelConfigLimits(t *testing.T) {
	baseline := *SolanaScaleEVMParallelConfig()
	want := baseline
	want.MaxTransactionsPerBlock = 175_000
	want.MaxBlockBytes = 160 * 1024 * 1024
	want.MaxAccessesPerBlock = 5 * 1024 * 1024
	want.MaxLogBytesPerBlock = 160 * 1024 * 1024
	want.MaxReceiptBytesPerBlock = 192 * 1024 * 1024
	profile := FHS250msResearchEVMParallelConfig()
	if *profile != want {
		t.Fatalf("research profile changed a preserved per-transaction, compute, path, depth or replay bound: got %+v want %+v", profile, want)
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("research limits are invalid: %v", err)
	}
	if NativeParallelExecutionMemoryBudget != 2<<30 {
		t.Fatal("research profile increased the execution lease")
	}
	// Validation accounts for retained planning and results. The executor tests
	// separately check the largest transaction reserve and actual microbatches.
	hold := profile.MaxAccessesPerBlock*NativePlanningMemoryPerAccess +
		profile.MaxTransactionsPerBlock*(NativePlanningMemoryPerTransaction+NativeReceiptMemoryReservePerTransaction) +
		profile.MaxLogBytesPerBlock
	if hold != 1_286_405_120 || hold >= NativeParallelExecutionMemoryBudget {
		t.Fatalf("research retained reservation = %d", hold)
	}
	profile.MaxTransactionsPerBlock = 1
	if *FHS250msResearchEVMParallelConfig() != want || *SolanaScaleEVMParallelConfig() != baseline || *SolanaScaleNativeParallelConfig() != baseline {
		t.Fatal("research helper mutated another profile or its defaults")
	}
}

func TestFHS250msResearchRequiresWholeConfigValidation(t *testing.T) {
	config := testFHS250msResearchConfig(t)
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatalf("complete research genesis config is invalid: %v", err)
	}
	if !config.FairHotstuffSlotEnabled() || !config.FixedCommittee {
		t.Fatal("research fixture omitted the explicit slot or fixed-committee opt-in")
	}
	for _, test := range []struct {
		name   string
		mutate func(*ChainConfig)
		want   string
	}{
		{"consensus", func(c *ChainConfig) { c.FairHotstuff = false }, "requires Fair HotStuff"},
		{"slot", func(c *ChainConfig) { c.FairHotstuffSlotMillis = 125 }, "must be 0 or 250"},
		{"seed", func(c *ChainConfig) { c.FairHotstuffSeed = common.Hash{} }, "fairHotstuffSeed"},
		{"committee", func(c *ChainConfig) { c.GenCommittee = nil }, "committee size"},
		{"forks", func(c *ChainConfig) { c.SetModernForkConfig(nil) }, "active at genesis"},
	} {
		t.Run(test.name, func(t *testing.T) {
			incomplete := testFHS250msResearchConfig(t)
			test.mutate(incomplete)
			if err := incomplete.NativeParallel.Validate(); err != nil {
				t.Fatalf("fixture changed the execution profile: %v", err)
			}
			if err := incomplete.CheckConfigForkOrder(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("incomplete whole config error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFHS250msResearchJSONAndGenesisCommitment(t *testing.T) {
	config := testFHS250msResearchConfig(t)
	want, err := FairHotstuffGenesisCommitment(config)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["fairHotstuffSlotMillis"]) != "250" || string(fields["fixedCommittee"]) != "true" || fields["evmParallel"] == nil {
		t.Fatalf("research genesis opt-ins missing from JSON: %s", encoded)
	}
	for _, retired := range []string{"nativeParallel", "requireNativeTransactions", "researchProfile"} {
		if strings.Contains(string(encoded), `"`+retired+`"`) {
			t.Fatalf("research config introduced an implicit or retired profile field %q", retired)
		}
	}
	var decoded ChainConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { decoded.SetModernForkConfig(nil) })
	if err := decoded.CheckConfigForkOrder(); err != nil {
		t.Fatalf("JSON round trip invalidated complete config: %v", err)
	}
	if decoded.NativeParallel == nil || *decoded.NativeParallel != *config.NativeParallel || !decoded.FairHotstuffSlotEnabled() || !decoded.FixedCommittee {
		t.Fatal("research profile did not survive JSON round trip")
	}
	if got, err := FairHotstuffGenesisCommitment(&decoded); err != nil || got != want {
		t.Fatalf("round trip genesis commitment = %s, error %v, want %s", got, err, want)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ChainConfig)
	}{
		{"slot", func(c *ChainConfig) { c.FairHotstuffSlotMillis = 0 }},
		{"default profile", func(c *ChainConfig) { c.NativeParallel = SolanaScaleEVMParallelConfig() }},
		{"transactions", func(c *ChainConfig) { c.NativeParallel.MaxTransactionsPerBlock++ }},
		{"body bytes", func(c *ChainConfig) { c.NativeParallel.MaxBlockBytes++ }},
		{"accesses", func(c *ChainConfig) { c.NativeParallel.MaxAccessesPerBlock++ }},
		{"logs", func(c *ChainConfig) { c.NativeParallel.MaxLogBytesPerBlock++ }},
		{"receipts", func(c *ChainConfig) { c.NativeParallel.MaxReceiptBytesPerBlock++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := testFHS250msResearchConfig(t)
			test.mutate(changed)
			if err := changed.CheckConfigForkOrder(); err != nil {
				t.Fatalf("commitment mutation should remain a valid genesis choice: %v", err)
			}
			if got, err := FairHotstuffGenesisCommitment(changed); err != nil || got == want {
				t.Fatalf("research choice was not committed: hash %s error %v", got, err)
			}
		})
	}
}

func TestFHS250msResearchWorkAndBlobBoundaries(t *testing.T) {
	config := testFHS250msResearchConfig(t)
	profile := config.NativeParallel
	limits := FairHotstuffEVMWorkLimitsForConfig(config)
	if limits.Transactions != profile.MaxTransactionsPerBlock || limits.DeclaredGas != profile.MaxComputePerBlock ||
		limits.TransactionsPerSender != profile.MaxDependencyDepth || limits.CommonTxAdmissionBatches != profile.MaxTransactionsPerBlock ||
		limits.CommonTxAdmissionRefs != profile.MaxTransactionsPerBlock || limits.CommonTxRewards != profile.MaxTransactionsPerBlock ||
		limits.CommonTxAdmissionBytesPerBatch != 64*1024 || limits.CommonTxAdmissionPayloadBytes != profile.MaxBlockBytes ||
		limits.CommonTxRewardPayloadBytes != profile.MaxBlockBytes/4 {
		t.Fatalf("research work envelope = %+v", limits)
	}
	for _, limit := range []uint64{limits.Transactions, limits.DeclaredGas, limits.TransactionsPerSender, limits.CommonTxAdmissionBatches,
		limits.CommonTxAdmissionRefs, limits.CommonTxRewards, limits.CommonTxAdmissionPayloadBytes, limits.CommonTxRewardPayloadBytes} {
		if got, ok := AddFHSWork(limit-1, 1, limit); !ok || got != limit {
			t.Fatalf("work bound %d was not inclusive: %d, %t", limit, got, ok)
		}
		if got, ok := AddFHSWork(limit, 1, limit); ok || got != limit {
			t.Fatalf("work bound %d accepted one extra unit: %d, %t", limit, got, ok)
		}
	}
	// Count and reward bytes are independent bounds: a block cannot use the
	// count ceiling to exceed the finite envelope with maximum-sized entries.
	if _, ok := AddFHSWork(0, profile.MaxTransactionsPerBlock*limits.CommonTxRewardBytesPerEntry, limits.CommonTxRewardPayloadBytes); ok {
		t.Fatal("maximum-sized reward entries bypassed the aggregate byte ceiling")
	}
	allowance := profile.MaxBlockBytes / 4
	perBlob := uint64(BlobTxBlobBytes + 48 + 48*128)
	maxBlobs := allowance / perBlob
	config.ModernForkConfig().BlobSchedule.Osaka.Max = int(maxBlobs)
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatalf("exact Osaka defensive-copy boundary rejected: %v", err)
	}
	config.ModernForkConfig().BlobSchedule.Osaka.Max++
	if err := config.CheckConfigForkOrder(); err == nil || !strings.Contains(err.Error(), "memory allowance") {
		t.Fatalf("Osaka boundary plus one error = %v", err)
	}
}

func TestParallelConfigRejectsCombinedExecutorMemoryOverflow(t *testing.T) {
	config := SolanaScaleEVMParallelConfig()
	config.MaxAccessesPerBlock = 10 * 1024 * 1024
	if err := config.Validate(); err == nil {
		t.Fatal("configuration whose planning and retained results exceed the shared execution budget was accepted")
	}
}

func TestNativeParallelConfigJSONRoundTrip(t *testing.T) {
	want := &ChainConfig{NativeParallel: SolanaScaleNativeParallelConfig()}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(encoded), `"evmParallel"`) {
		t.Fatalf("public chain config omitted evmParallel: %s", encoded)
	}
	if strings.Contains(string(encoded), `"nativeParallel"`) || strings.Contains(string(encoded), `"requireNativeTransactions"`) {
		t.Fatalf("public chain config exposed retired NativeTx schema: %s", encoded)
	}
	var got ChainConfig
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.NativeParallel == nil || *got.NativeParallel != *want.NativeParallel {
		t.Fatalf("round trip mismatch: got %+v want %+v", got.NativeParallel, want.NativeParallel)
	}
}

func TestChainConfigRejectsRetiredNativeTransactionSchema(t *testing.T) {
	tests := []string{
		`{"nativeParallel":null}`,
		`{"NativeParallel":null}`,
		`{"evmParallel":{"version":2}}`,
		`{"evmParallel":{"requireNativeTransactions":false}}`,
		`{"evmParallel":{"requireNativeTransactions":true}}`,
		`{"evmParallel":{"RequireNativeTransactions":null}}`,
	}
	for _, input := range tests {
		var config ChainConfig
		if err := json.Unmarshal([]byte(input), &config); err == nil {
			t.Fatalf("retired NativeTx schema was accepted: %s", input)
		}
	}
}

func TestChainConfigRejectsProgrammaticNativeTransactionMode(t *testing.T) {
	parallel := SolanaScaleNativeParallelConfig()
	parallel.RequireNativeTransactions = true
	config := &ChainConfig{NativeParallel: parallel}
	if err := config.CheckConfigForkOrder(); err == nil || !strings.Contains(err.Error(), "types 0 through 4") {
		t.Fatalf("programmatic NativeTx mode was not rejected: %v", err)
	}
	if _, err := json.Marshal(config); err == nil || !strings.Contains(err.Error(), "types 0 through 4") {
		t.Fatalf("programmatic NativeTx mode was silently serialized: %v", err)
	}
}

func TestNativeParallelConfigRejectsUnsafeRelationships(t *testing.T) {
	tests := []func(*NativeParallelConfig){
		func(c *NativeParallelConfig) { c.MaxBlockBytes = 0 },
		func(c *NativeParallelConfig) { c.MaxBlockBytes = FairHotstuffFinalityProofReserveBytes },
		func(c *NativeParallelConfig) { c.MaxTransactionBytes = c.MaxBlockBytes + 1 },
		func(c *NativeParallelConfig) { c.MaxAccessesPerTransaction = c.MaxAccessesPerBlock + 1 },
		func(c *NativeParallelConfig) { c.MaxComputePerTransaction = c.MaxComputePerBlock + 1 },
		func(c *NativeParallelConfig) { c.MaxCriticalPathCompute = c.MaxComputePerBlock + 1 },
		func(c *NativeParallelConfig) { c.MaxDependencyDepth = c.MaxTransactionsPerBlock + 1 },
		func(c *NativeParallelConfig) { c.MaxDependencyDepth = c.MaxCriticalPathCompute/TxGas + 1 },
	}
	for index, mutate := range tests {
		config := SolanaScaleNativeParallelConfig()
		mutate(config)
		if err := config.Validate(); err == nil {
			t.Fatalf("case %d accepted invalid config", index)
		}
	}
}

func TestNativeParallelConfigAllowsEVMOnlyMode(t *testing.T) {
	config := SolanaScaleNativeParallelConfig()
	config.RequireNativeTransactions = false
	if err := config.Validate(); err != nil {
		t.Fatalf("EVM-only native-capacity profile is invalid: %v", err)
	}
}

func TestRetiredNativeModeCannotUseSignedWireByteBound(t *testing.T) {
	config := SolanaScaleNativeParallelConfig()
	config.MaxAccessesPerBlock = 16 * 1024 * 1024
	config.RequireNativeTransactions = true
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "types 0 through 4") {
		t.Fatalf("retired NativeTx mode was not rejected: %v", err)
	}
	// Standard EVM bytecode can discover many runtime resources from a compact
	// transaction. Its full configured frontier must therefore fit memory.
	config.RequireNativeTransactions = false
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "dependency planning memory") {
		t.Fatalf("EVM runtime access frontier was not rejected: %v", err)
	}
}

func TestNativeParallelEffectiveConsensusLimits(t *testing.T) {
	native := SolanaScaleNativeParallelConfig()
	config := &ChainConfig{NativeParallel: native}
	limits := FairHotstuffWorkLimitsForConfig(config)
	if limits.Transactions != native.MaxTransactionsPerBlock || limits.DeclaredGas != native.MaxComputePerBlock {
		t.Fatalf("native work limits = %+v", limits)
	}
	if limits.CommonTxAdmissionBatches != native.MaxTransactionsPerBlock {
		t.Fatalf("native admission batch limit = %d, want fragmented worst case %d", limits.CommonTxAdmissionBatches, native.MaxTransactionsPerBlock)
	}
	if limits.CommonTxAdmissionPayloadBytes != native.MaxBlockBytes {
		t.Fatalf("native admission payload limit = %d, want block envelope %d", limits.CommonTxAdmissionPayloadBytes, native.MaxBlockBytes)
	}
	if got := config.EffectiveMaxBlockBytes(); got != native.MaxBlockBytes {
		t.Fatalf("block bytes = %d, want %d", got, native.MaxBlockBytes)
	}
	if got := config.EffectiveMaxTransactionBytes(); got != native.MaxTransactionBytes {
		t.Fatalf("transaction bytes = %d, want %d", got, native.MaxTransactionBytes)
	}
}

func TestNativeParallelEVMWorkLimits(t *testing.T) {
	native := SolanaScaleNativeParallelConfig()
	native.RequireNativeTransactions = false
	config := &ChainConfig{NativeParallel: native}
	limits := FairHotstuffEVMWorkLimitsForConfig(config)
	if limits.Transactions != native.MaxTransactionsPerBlock || limits.DeclaredGas != native.MaxComputePerBlock {
		t.Fatalf("EVM aggregate limits = %+v", limits)
	}
	wantSerialTransactions := native.MaxCriticalPathCompute / TxGas
	if limits.TransactionsPerSender != wantSerialTransactions {
		t.Fatalf("EVM per-sender limit = %d, want %d", limits.TransactionsPerSender, wantSerialTransactions)
	}
	wantAuthorizations := native.MaxTransactionsPerBlock * MaxFHSSetCodeAuthorizationsPerTransaction
	if limits.SetCodeAuthorizationsPerTx != MaxFHSSetCodeAuthorizationsPerTransaction || limits.SetCodeAuthorizations != wantAuthorizations {
		t.Fatalf("EVM authorization limits = %d/%d", limits.SetCodeAuthorizationsPerTx, limits.SetCodeAuthorizations)
	}
	if limits.AccessListAddressesPerTx != native.MaxAccessesPerTransaction || limits.AccessListAddresses != native.MaxAccessesPerBlock ||
		limits.AccessListStorageKeysPerTx != native.MaxAccessesPerTransaction || limits.AccessListStorageKeys != native.MaxAccessesPerBlock {
		t.Fatalf("EVM access-list limits = %+v", limits)
	}
	wantSignatureOperations := native.MaxTransactionsPerBlock + wantAuthorizations + native.MaxTransactionsPerBlock
	if limits.SignatureOperations != wantSignatureOperations {
		t.Fatalf("EVM signature-operation limit = %d, want %d", limits.SignatureOperations, wantSignatureOperations)
	}
	if limits.CommonTxAdmissionBatches != native.MaxTransactionsPerBlock || limits.CommonTxAdmissionPayloadBytes != native.MaxBlockBytes {
		t.Fatalf("EVM admission limits = %+v", limits)
	}
}

func TestEVMParallelBlobScheduleFitsDefensiveCopyBudget(t *testing.T) {
	config := &ChainConfig{NativeParallel: SolanaScaleNativeParallelConfig()}
	config.SetModernForkConfig(&ModernForkConfig{BlobSchedule: &BlobScheduleConfig{
		Cancun: &BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 213662528},
		Prague: &BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 160246912},
		Osaka:  &BlobConfig{Target: 192, Max: 288, BaseFeeUpdateFraction: 160246912},
	}})
	defer config.SetModernForkConfig(nil)
	if err := config.validateEVMParallelBlobMemory(); err != nil {
		t.Fatalf("high-capacity blob schedule rejected: %v", err)
	}
	config.ModernForkConfig().BlobSchedule.Osaka.Max = int(NativeParallelExecutionMemoryBudget/16/BlobTxBlobBytes) + 1
	if err := config.validateEVMParallelBlobMemory(); err == nil || !strings.Contains(err.Error(), "memory allowance") {
		t.Fatalf("unsafe blob schedule error = %v", err)
	}
}

func TestNativeReplayRegistryUsesPayerShards(t *testing.T) {
	left := common.Address{0x11, 0x01}
	right := common.Address{0x22, 0x01}
	leftAddress := NativeReplayRegistryAddressForPayer(left)
	rightAddress := NativeReplayRegistryAddressForPayer(right)
	if leftAddress == rightAddress {
		t.Fatal("different payer prefixes selected the same replay shard")
	}
	if leftAddress[len(leftAddress)-1] != left[0] || rightAddress[len(rightAddress)-1] != right[0] {
		t.Fatal("replay shard does not preserve the full prefix byte")
	}
	if !IsNativeReplayRegistryAddress(leftAddress) || !IsNativeReplayRegistryAddress(NativeReplayRegistryAddress) {
		t.Fatal("replay registry range was not recognized")
	}
	outside := leftAddress
	outside[0] = 0xfe
	if IsNativeReplayRegistryAddress(outside) {
		t.Fatal("ordinary high address was classified as replay registry")
	}
	if leftAddress[17] != 0xff || leftAddress[18] != 0xff {
		t.Fatalf("payer replay shard is outside the fixed sequence bucket: %s", leftAddress)
	}
}
