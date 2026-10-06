package tracers

import "github.com/cypherium/cypher/core/vm"

// SetBlockscoutContext also initializes the DB wrapper for transactions that
// execute no opcodes (EOA transfers and direct precompile calls).
func (jst *Tracer) SetBlockscoutContext(db vm.StateDB, blockNumber, gas, gasUsed uint64) {
	jst.dbWrapper.db = db
	jst.ctx["block"] = blockNumber
	jst.ctx["gas"] = gas
	jst.ctx["gasUsed"] = gasUsed
	jst.inited = true
}

// Close releases the JS heap on failed execution as well as successful traces.
// Calls must be serialized with tracer execution; this is not a concurrent API.
func (jst *Tracer) Close() {
	if jst.vm != nil {
		jst.vm.DestroyHeap()
		jst.vm.Destroy()
		jst.vm = nil
	}
}
