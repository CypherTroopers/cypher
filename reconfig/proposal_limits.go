package reconfig

import (
	"time"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// proposalBodyLimitForConfig is the maximum canonical encoded block and
// manifest size accepted by Fair HotStuff. The legacy constants remain the
// default for networks which have not committed NativeParallel at genesis.
func proposalBodyLimitForConfig(config *params.ChainConfig) int {
	limit := uint64(proposalBodySidecarMaxBytes)
	if config != nil && config.NativeParallelEnabled() {
		limit = config.EffectiveMaxBlockBytes()
	}
	return boundedUint64ToInt(limit)
}

// proposalRepairPayloadLimitForConfig deliberately does not grow every repair
// message to MaxBlockBytes. A large block is repaired in bounded batches; only
// the largest configured single transaction must fit in one batch.
func proposalRepairPayloadLimitForConfig(config *params.ChainConfig) int {
	limit := uint64(proposalBodySidecarMaxBytes)
	if config != nil && config.NativeParallelEnabled() {
		transactionLimit := config.EffectiveMaxTransactionBytes()
		const framingAllowance = uint64(proposalRepairResponseReserve + commonHashWireBytes)
		if transactionLimit <= ^uint64(0)-framingAllowance && transactionLimit+framingAllowance > limit {
			limit = transactionLimit + framingAllowance
		}
		if blockLimit := config.EffectiveMaxBlockBytes(); limit > blockLimit {
			limit = blockLimit
		}
	}
	return boundedUint64ToInt(limit)
}

// proposalBodyCacheLimitForConfig budgets a hot working set of three maximum-
// sized bodies. Certificates and execution artifacts outlive this evictable
// cache, so its capacity does not bound an uncommitted certified suffix.
// Small/legacy blocks retain their historical 64 MiB budget.
func proposalBodyCacheLimitForConfig(config *params.ChainConfig) int {
	limit := proposalBodyCacheMaxBytes
	perBody := saturatingAddInt(proposalBodyLimitForConfig(config), proposalBodyControlMaxBytes+types.MaxFHSFinalityProofSize+4096)
	if candidate := saturatingMulInt(perBody, 3); candidate > limit {
		limit = candidate
	}
	return limit
}

func proposalPeerQueueBulkLimitForConfig(config *params.ChainConfig) int {
	limit := proposalBodyLimitForConfig(config)
	if repair := proposalRepairPayloadLimitForConfig(config); repair > limit {
		limit = repair
	}
	return saturatingAddInt(limit, proposalBodyControlMaxBytes+types.MaxFHSFinalityProofSize+4096)
}

func boundedUint64ToInt(value uint64) int {
	maxInt := int(^uint(0) >> 1)
	if value > uint64(maxInt) {
		return maxInt
	}
	return int(value)
}

func saturatingAddInt(left, right int) int {
	maxInt := int(^uint(0) >> 1)
	if left < 0 || right < 0 || left > maxInt-right {
		return maxInt
	}
	return left + right
}

func saturatingMulInt(value, factor int) int {
	maxInt := int(^uint(0) >> 1)
	if value < 0 || factor < 0 || (factor != 0 && value > maxInt/factor) {
		return maxInt
	}
	return value * factor
}

func fitsIntBudget(current, additional, limit int) bool {
	return current >= 0 && additional >= 0 && limit >= 0 && current <= limit && additional <= limit-current
}

const (
	commonHashWireBytes            = 32
	proposalBodyCacheTTL           = 2 * time.Minute
	proposalBodyWaitBaseTimeout    = 2 * time.Second
	proposalBodyWaitMaxTimeout     = 30 * time.Second
	proposalBodyWaitBytesPerSecond = 2 * 1024 * 1024
	proposalBodyRequestAfter       = 250 * time.Millisecond
	proposalBodyRequestInterval    = 250 * time.Millisecond
	proposalBodyControlMaxBytes    = 512 * 1024
	proposalBodySidecarMaxBytes    = int(params.MaxBlockSize)
	proposalRepairMaxHashes        = 1024
	proposalRepairResponseReserve  = 64 * 1024
	// Native proposals may contain hundreds of thousands of transactions. Keep
	// each authenticated repair message bounded, but pipeline a bounded number of
	// disjoint windows per request interval instead of serialising all windows.
	proposalRepairNativeRequestBurst = 16
	// Leave a bounded response/assembly window after the last distinct repair
	// batch is scheduled; the batch schedule itself is accounted for separately.
	proposalRepairNetworkMargin                 = 2 * time.Second
	proposalBodyCacheMaxEntries                 = 64
	proposalBodyCacheMaxBytes                   = 8 * proposalBodySidecarMaxBytes
	proposalAssemblyBytesPerTransaction         = 112
	proposalAssemblyBytesPerRepairedTransaction = 160
)

// proposalBodyCacheTTLForConfig keeps uncertified native proposal data through
// at least two complete pacemaker intervals. A proposal body can still be the
// only repair source while its current view validates, and the native deadline
// includes size-derived body transfer, repair and execution leases. Legacy
// networks retain their historical two-minute cache lifetime.
func proposalBodyCacheTTLForConfig(config *params.ChainConfig) time.Duration {
	ttl := proposalBodyCacheTTL
	if config == nil || !config.NativeParallelEnabled() {
		return ttl
	}
	paceMaker := paceMakerTimeoutForConfig(config)
	minimum := addDurationSaturating(paceMaker, paceMaker)
	if minimum > ttl {
		return minimum
	}
	return ttl
}

func proposalAssemblyBaseWeight(payloadBytes, transactions int) int {
	return saturatingAddInt(payloadBytes, saturatingMulInt(transactions, proposalAssemblyBytesPerTransaction))
}

func proposalAssemblyTransactionWeight(tx *types.Transaction) int {
	if tx == nil {
		return 0
	}
	return saturatingAddInt(int(tx.Size()), proposalAssemblyBytesPerRepairedTransaction)
}

func proposalManifestBlobSidecarWeight(sidecars []*types.BlobTxSidecar) int {
	weight := 0
	for _, sidecar := range sidecars {
		if sidecar == nil {
			continue
		}
		weight = saturatingAddInt(weight, 128)
		for _, blob := range sidecar.Blobs {
			weight = saturatingAddInt(weight, len(blob))
		}
		weight = saturatingAddInt(weight, saturatingMulInt(len(sidecar.Commitments)+len(sidecar.Proofs), 48))
	}
	return weight
}

func proposalRepairRequestBurstForConfig(config *params.ChainConfig) uint64 {
	if config != nil && config.NativeParallelEnabled() {
		return proposalRepairNativeRequestBurst
	}
	return 1
}

func proposalBodyWaitTimeoutForConfig(config *params.ChainConfig, bodySize uint64) time.Duration {
	timeout := proposalBodyWaitBaseTimeout
	if config != nil && config.NativeParallelEnabled() {
		if limit := uint64(proposalBodyLimitForConfig(config)); bodySize > limit {
			bodySize = limit
		}
	}
	if bodySize > 0 {
		transfer := time.Duration(bodySize) * time.Second / proposalBodyWaitBytesPerSecond
		timeout += transfer
	}
	maxTimeout := proposalBodyWaitMaxTimeout
	if config != nil && config.NativeParallelEnabled() {
		configuredTransfer := time.Duration(config.EffectiveMaxBlockBytes()) * time.Second / proposalBodyWaitBytesPerSecond
		if configuredTransfer > time.Duration(^uint64(0)>>1)-proposalBodyWaitBaseTimeout {
			maxTimeout = time.Duration(^uint64(0) >> 1)
		} else if candidate := proposalBodyWaitBaseTimeout + configuredTransfer; candidate > maxTimeout {
			maxTimeout = candidate
		}
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

func proposalRepairWaitTimeoutForConfig(config *params.ChainConfig, missingCount int) time.Duration {
	recoveryBytes := uint64(0)
	if config != nil && config.NativeParallelEnabled() {
		recoveryBytes = config.EffectiveMaxBlockBytes()
	}
	return proposalRepairWaitTimeoutForPayload(config, missingCount, recoveryBytes)
}

// proposalRepairWaitTimeoutForPayload covers both the request-window schedule
// and the bytes which may need to be recovered. The count schedule alone is not
// sufficient: a single 1024-hash request can yield only one maximum-size
// transaction because repair responses are deliberately capped near 1 MiB.
func proposalRepairWaitTimeoutForPayload(config *params.ChainConfig, missingCount int, recoveryBytes uint64) time.Duration {
	if missingCount <= 0 {
		return 0
	}
	count := uint64(missingCount)
	if limit := params.FairHotstuffWorkLimitsForConfig(config).Transactions; count > limit {
		count = limit
	}
	if count == 0 {
		return 0
	}
	batchSize := uint64(proposalRepairMaxHashes)
	batches := (count + batchSize - 1) / batchSize
	burst := proposalRepairRequestBurstForConfig(config)
	rounds := (batches + burst - 1) / burst
	timeout := proposalBodyRequestAfter + time.Duration(rounds-1)*proposalBodyRequestInterval + proposalRepairNetworkMargin
	maxTimeout := proposalBodyWaitMaxTimeout
	if config != nil && config.NativeParallelEnabled() {
		maxBatches := (config.NativeParallel.MaxTransactionsPerBlock + batchSize - 1) / batchSize
		if maxBatches > 0 {
			maxRounds := (maxBatches + burst - 1) / burst
			configured := proposalBodyRequestAfter + time.Duration(maxRounds-1)*proposalBodyRequestInterval + proposalRepairNetworkMargin
			if configured > maxTimeout {
				maxTimeout = configured
			}
		}
		transferTimeout := proposalBodyWaitTimeoutForConfig(config, recoveryBytes)
		if transferTimeout > timeout {
			timeout = transferTimeout
		}
		configuredTransfer := proposalBodyWaitTimeoutForConfig(config, config.EffectiveMaxBlockBytes())
		if configuredTransfer > maxTimeout {
			maxTimeout = configuredTransfer
		}
	}
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}
