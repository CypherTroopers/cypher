package ethapi

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rpc"
)

type evidenceBackend struct {
	Backend
	config *params.ChainConfig
	block  *types.Block
	err    error
	reads  int
}

type inboxEvidenceBackend struct {
	Backend
	config *params.ChainConfig
	state  *state.StateDB
	header *types.Header
	err    error
	reads  int
	ref    rpc.BlockNumberOrHash
}

func (b *inboxEvidenceBackend) ChainConfig() *params.ChainConfig { return b.config }
func (b *inboxEvidenceBackend) StateAndHeaderByNumberOrHash(_ context.Context, ref rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	b.reads++
	b.ref = ref
	return b.state, b.header, b.err
}

func TestNativeInboxRPCExplicitCanonicalBoundsAndMissingData(t *testing.T) {
	ctx := context.Background()
	// These errors must precede any backend lookup, including integer overflow.
	for _, tc := range []struct {
		hash         common.Hash
		start, count hexutil.Uint64
	}{
		{common.Hash{}, 0, 1}, {common.Hash{1}, 0, 0}, {common.Hash{1}, 0, protocol.MaxDepositsPerCheckpoint + 1},
		{common.Hash{1}, ^hexutil.Uint64(0), 1}, {common.Hash{1}, hexutil.Uint64(protocol.MaxInboxEntries), 1},
	} {
		if out, err := (&PublicBlockChainAPI{}).GetDEXInboxEntries(ctx, tc.hash, tc.start, tc.count); err == nil || out != nil {
			t.Fatal("unbounded/implicit inbox lookup")
		}
	}
	b := &inboxEvidenceBackend{}
	api := &PublicBlockChainAPI{b: b}
	if out, err := api.GetDEXInboxEntries(ctx, common.Hash{1}, 0, 1); err == nil || out != nil || b.reads != 0 {
		t.Fatal("non-devnet read")
	}
	b.config = &params.ChainConfig{FairHotstuff: true, DEXDevnet: &params.DEXDevnetConfig{Version: 3, ActivationBlock: 2, Custody: params.DEXSettlementAddress}}
	b.header = &types.Header{Number: big.NewInt(2)}
	db := rawdb.NewMemoryDatabase()
	var err error
	b.state, err = state.New(types.EmptyRootHash, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := b.state.IntermediateRoot(false)
	for _, name := range []string{"missing-entry", "wrong-header", "inactive", "database-error"} {
		t.Run(name, func(t *testing.T) {
			hash := b.header.Hash()
			savedHeader := b.header
			switch name {
			case "wrong-header":
				hash = common.Hash{99}
			case "inactive":
				b.header = &types.Header{Number: big.NewInt(1)}
				hash = b.header.Hash()
			case "database-error":
				b.err = errors.New("injected database read failure")
			}
			out, err := api.GetDEXInboxEntries(ctx, hash, 0, 1)
			if err == nil || out != nil {
				t.Fatal("missing/noncanonical data became entries")
			}
			if got, ok := b.ref.Hash(); !ok || got != hash || !b.ref.RequireCanonical {
				t.Fatal("lookup did not bind explicit canonical hash")
			}
			if b.state.IntermediateRoot(false) != before {
				t.Fatal("read-only inbox changed state")
			}
			b.header = savedHeader
			b.err = nil
		})
	}
}

func (b *evidenceBackend) ChainConfig() *params.ChainConfig { return b.config }
func (b *evidenceBackend) BlockByNumber(context.Context, rpc.BlockNumber) (*types.Block, error) {
	b.reads++
	return b.block, b.err
}

func TestCLXFinalityWitnessRPCUnavailableIsNotFinality(t *testing.T) {
	ctx := context.Background()
	// Invalid selectors must fail before touching a backend or a mutable head.
	for _, n := range []rpc.BlockNumber{rpc.PendingBlockNumber, rpc.LatestBlockNumber, 0} {
		if got, err := (&PublicBlockChainAPI{}).GetCLXFinalityWitness(ctx, n); err == nil || got != nil {
			t.Fatalf("selector %d returned evidence", n)
		}
	}
	b := &evidenceBackend{}
	api := &PublicBlockChainAPI{b: b}
	if got, err := api.GetCLXFinalityWitness(ctx, 1); err == nil || got != nil || b.reads != 0 {
		t.Fatal("non-devnet configuration read source data")
	}
	b.config = &params.ChainConfig{ChainID: big.NewInt(1337), FairHotstuff: true, DEXDevnet: &params.DEXDevnetConfig{Version: 3}}
	for _, tc := range []struct {
		name  string
		block *types.Block
		err   error
	}{
		{"absent", nil, nil},
		{"storage-error", nil, errors.New("injected source database error")},
		{"wrong-height", types.NewBlockWithHeader(&types.Header{Number: big.NewInt(2)}), nil},
		{"no-finality", types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b.block, b.err = tc.block, tc.err
			if got, err := api.GetCLXFinalityWitness(ctx, 1); err == nil || got != nil {
				t.Fatal("unavailable/unfinalized source became evidence")
			}
		})
	}
}
