package core

import (
	"errors"
	"fmt"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
)

// ErrEVMLogLimitExceeded is a genesis-configured consensus resource failure
// for standard Ethereum envelopes. It is sticky across nested calls and is
// checked after EVM execution, so contract code cannot catch it as an ordinary
// CALL failure.
var ErrEVMLogLimitExceeded = errors.New("EVM transaction log limit exceeded")

// evmResourceGuard bounds logs before StateDB retains them. Ethereum gas still
// prices LOG opcodes normally; this independent genesis limit prevents an
// extremely large block gas limit from becoming an unbounded heap allowance.
type evmResourceGuard struct {
	vm.StateDB
	logLimit       uint64
	logContentSize uint64
	logMemorySize  uint64
	err            error
}

func newEVMResourceGuard(statedb vm.StateDB, logLimit uint64) *evmResourceGuard {
	return &evmResourceGuard{StateDB: statedb, logLimit: logLimit}
}

func (g *evmResourceGuard) AddLog(entry *types.Log) {
	if g == nil || g.StateDB == nil || g.err != nil {
		return
	}
	encodedSize, ok := nativeLogRLPSize(entry)
	if !ok || encodedSize > ^uint64(0)-g.logContentSize {
		g.err = fmt.Errorf("%w: invalid or overflowing log encoding", ErrEVMLogLimitExceeded)
		return
	}
	nextContentSize := g.logContentSize + encodedSize
	encodedListSize := rlpListSizeChecked(nextContentSize)
	if encodedListSize == 0 || encodedListSize > g.logLimit {
		g.err = fmt.Errorf("%w: encoded bytes=%d limit=%d", ErrEVMLogLimitExceeded, encodedListSize, g.logLimit)
		return
	}
	if encodedSize > ^uint64(0)-nativeLogObjectMemoryReserve {
		g.err = fmt.Errorf("%w: overflowing retained-memory charge", ErrEVMLogLimitExceeded)
		return
	}
	entryMemorySize := encodedSize + nativeLogObjectMemoryReserve
	if entryMemorySize > ^uint64(0)-g.logMemorySize {
		g.err = fmt.Errorf("%w: overflowing aggregate retained-memory charge", ErrEVMLogLimitExceeded)
		return
	}
	nextMemorySize := g.logMemorySize + entryMemorySize
	if nextMemorySize > g.logLimit {
		g.err = fmt.Errorf("%w: retained bytes=%d limit=%d", ErrEVMLogLimitExceeded, nextMemorySize, g.logLimit)
		return
	}
	g.logContentSize = nextContentSize
	g.logMemorySize = nextMemorySize
	g.StateDB.AddLog(entry)
}

func (g *evmResourceGuard) Error() error {
	if g == nil {
		return nil
	}
	return g.err
}
