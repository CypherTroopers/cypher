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
