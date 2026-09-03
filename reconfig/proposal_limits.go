package reconfig

import "github.com/cypherium/cypher/params"

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

// proposalBodyCacheLimitForConfig retains room for the two-chain certified
// suffix plus the next maximum-sized proposal without multiplying a 256 MiB
// genesis limit by the legacy eight-body factor. Small/legacy blocks retain
// their historical 64 MiB budget.
func proposalBodyCacheLimitForConfig(config *params.ChainConfig) int {
	limit := proposalBodyCacheMaxBytes
	perBody := saturatingAddInt(proposalBodyLimitForConfig(config), proposalBodyControlMaxBytes+4096)
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
	return saturatingAddInt(limit, 1024*1024)
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

const commonHashWireBytes = 32
