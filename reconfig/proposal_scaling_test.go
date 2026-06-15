package reconfig

import (
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
)

func TestHighBacklogProposalIsChunked(t *testing.T) {
	if got := blockMaxTxCount(types.FastTx_Block); got != 16384 {
		t.Fatalf("fast proposal tx limit = %d, want 16384", got)
	}
	if got := blockMaxTxCount(types.SlowTx_Block); got != 16384 {
		t.Fatalf("slow proposal tx limit = %d, want 16384", got)
	}
	if got := blockProposalLimit(types.FastTx_Block, 250000); got != 16384 {
		t.Fatalf("high-backlog per-account limit = %d, want 16384", got)
	}
	const submitted = 250000
	blocks := (submitted + int(fastBlockMaxTxCount) - 1) / int(fastBlockMaxTxCount)
	if blocks != 16 {
		t.Fatalf("%d transactions require %d proposal chunks, want 16", submitted, blocks)
	}
}

func TestProposalBodyWaitTimeoutScalesWithBody(t *testing.T) {
	if got := proposalBodyWaitTimeout(0); got != 2*time.Second {
		t.Fatalf("empty body timeout = %s, want 2s", got)
	}
	if got := proposalBodyWaitTimeout(16 * 1024 * 1024); got != 10*time.Second {
		t.Fatalf("16MiB body timeout = %s, want 10s", got)
	}
	if got := proposalBodyWaitTimeout(256 * 1024 * 1024); got != 30*time.Second {
		t.Fatalf("large body timeout = %s, want 30s cap", got)
	}
}
