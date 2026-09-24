package engine

import "github.com/cypherium/cypher/dex/instrumentation"

// ProcessMetrics distinguish DEX execution from bounded CLX settlement work.
// Counts describe this process only and do not assert that cryptography or
// settlement verification consumed no resources.
type ProcessMetrics = instrumentation.ExecutionStats

func Metrics() ProcessMetrics {
	return instrumentation.Execution()
}
