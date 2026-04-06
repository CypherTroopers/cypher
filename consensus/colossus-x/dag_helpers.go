package miner

import cx "colossusx/colossusx"

func NewDAGWithAllocation(spec Spec, alloc managedAllocation, ownership bool) (*DAG, error) {
	return cx.NewDAGWithAllocation(spec, alloc, ownership)
}

func NewDAGWithStrategy(spec Spec, strategy MemoryStrategy) (*DAG, error) {
	if strategy == nil {
		strategy = GoHeapMemory{}
	}
	return cx.NewDAGWithAllocator(spec, strategy)
}

func NewDAG(spec Spec) (*DAG, error) { return NewDAGWithStrategy(spec, GoHeapMemory{}) }

func GenerateDAG(dag *DAG, epochSeed []byte, workers int) error {
	return cx.PopulateDAG(dag, epochSeed, workers)
}
