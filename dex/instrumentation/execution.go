// Package instrumentation exposes process-local counters without importing the
// DEX engine, consensus, storage or any background worker.
package instrumentation

import "sync/atomic"

type ExecutionStats struct{ Instances, Actions, InboxImports uint64 }

var instances, actions, inboxImports atomic.Uint64

func EngineCreated()  { instances.Add(1) }
func ActionExecuted() { actions.Add(1) }
func InboxImported()  { inboxImports.Add(1) }
func Execution() ExecutionStats {
	return ExecutionStats{instances.Load(), actions.Load(), inboxImports.Load()}
}
