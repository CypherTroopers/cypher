package ethapi

import (
	"context"
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/rpc"
)

// CLXFinalityWitness transports evidence, not an RPC assertion of finality.
// The recipient must authenticate it from its own trusted source anchor.
type CLXFinalityWitness struct {
	Header      hexutil.Bytes `json:"header"`
	ProposalRef hexutil.Bytes `json:"proposalRef"`
}

// GetDEXInboxEntries transports bounded native entry preimages at one explicit
// canonical block. Each returned entry still requires its exact MPT inclusion
// proof and authenticated source finality before a DEX may credit it.
func (s *PublicBlockChainAPI) GetDEXInboxEntries(ctx context.Context, blockHash common.Hash, start, count hexutil.Uint64) ([]hexutil.Bytes, error) {
	if blockHash == (common.Hash{}) || count == 0 || uint64(count) > protocol.MaxDepositsPerCheckpoint || uint64(start) > protocol.MaxInboxEntries || uint64(count) > protocol.MaxInboxEntries-uint64(start) {
		return nil, errors.New("native inbox explicit block/range bound")
	}
	config := s.b.ChainConfig()
	if config == nil || !config.FairHotstuff || config.DEXDevnet == nil {
		return nil, errors.New("isolated native inbox unavailable")
	}
	st, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithHash(blockHash, true))
	if err != nil {
		return nil, err
	}
	if st == nil || header == nil || header.Hash() != blockHash || !config.DEXDevnetActive(header.Number) {
		return nil, errors.New("canonical native inbox data unavailable")
	}
	entries := make([]hexutil.Bytes, 0, int(count))
	for i := uint64(0); i < uint64(count); i++ {
		entry, err := settlement.ReadNativeEntry(st, config.DEXDevnet.Custody, uint64(start)+i)
		if err != nil {
			return nil, err
		}
		raw, err := entry.Encode()
		if err != nil {
			return nil, err
		}
		entries = append(entries, raw)
	}
	if err := st.Error(); err != nil {
		return nil, err
	}
	return entries, nil
}

// GetCLXFinalityWitness returns one bounded historical witness. In particular,
// latest/pending and caller-provided headers cannot choose a new trust root.
func (s *PublicBlockChainAPI) GetCLXFinalityWitness(ctx context.Context, number rpc.BlockNumber) (*CLXFinalityWitness, error) {
	if number <= 0 {
		return nil, errors.New("explicit positive source block number required")
	}
	config := s.b.ChainConfig()
	if config == nil || !config.FairHotstuff || config.DEXDevnet == nil || config.ChainID == nil || !config.ChainID.IsUint64() {
		return nil, errors.New("isolated CLX evidence service unavailable")
	}
	block, err := s.b.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil || block.NumberU64() != uint64(number) {
		return nil, errors.New("historical source data unavailable")
	}
	witness, err := clxevidence.BuildHeaderWitness(config.ChainID.Uint64(), block)
	if err != nil {
		return nil, err
	}
	return &CLXFinalityWitness{Header: witness.Header, ProposalRef: witness.ProposalRef}, nil
}
