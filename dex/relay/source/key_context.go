package source

import (
	"context"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

// AnchorContextAt returns a fully authenticated historical anchor and owned
// preimages for that anchor's key context. The context comes only from retained,
// verified source history; it is not the input context of a range ending here.
// In particular, a range crossing a key renewal has different input and target
// contexts. AnchorAt also verifies the target's custody/count MPT information.
func (c *Client) AnchorContextAt(ctx context.Context, height uint64, hash protocol.Hash) (clxevidence.Anchor, clxevidence.KeyContext, error) {
	anchor, err := c.AnchorAt(ctx, height, hash)
	if err != nil {
		return clxevidence.Anchor{}, clxevidence.KeyContext{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(); err != nil {
		return clxevidence.Anchor{}, clxevidence.KeyContext{}, err
	}
	// Source segments are immutable after verification, even if Advance appended
	// more between these reads. Recheck lifecycle/durability before using them.
	k, err := c.keyContext(ctx, anchor, nil)
	if err != nil {
		return clxevidence.Anchor{}, clxevidence.KeyContext{}, err
	}
	return anchor, k.Clone(), nil
}

// keyContext retrieves only hash preimages of a caller-authenticated base.
// Neither current RPC committee labels nor key-block RPC hash labels are trusted.
func (c *Client) keyContext(ctx context.Context, base clxevidence.Anchor, headers []clxevidence.HeaderWitness) (clxevidence.KeyContext, error) {
	needed := base.Version == 2
	for _, w := range headers {
		var h types.Header
		if err := rlp.DecodeBytes(w.Header, &h); err != nil {
			return clxevidence.KeyContext{}, err
		}
		needed = needed || h.BlockType == types.Key_Block
	}
	if !needed {
		return clxevidence.KeyContext{}, nil
	}
	if base.Version == 2 {
		for _, segment := range c.segments {
			if base.Height <= segment.Base.Height || base.Height > segment.Target.Height {
				continue
			}
			count := base.Height - segment.Base.Height
			_, derived, k, err := c.verifier.VerifyHeaderContext(segment.Base, segment.Evidence.KeyContext(), segment.Evidence.Headers[:count])
			if err != nil {
				return clxevidence.KeyContext{}, err
			}
			if derived.Height != base.Height || derived.BlockHash != base.BlockHash || derived.StateRoot != base.StateRoot || derived.SourceKeyHash != base.SourceKeyHash || derived.SourceCommittee != base.SourceCommittee || derived.ActivationEnd != base.ActivationEnd || derived.ActivationRoot != base.ActivationRoot {
				return clxevidence.KeyContext{}, ErrAuthentication
			}
			// The independently verified local chain supplies only the preimage. The
			// caller's actual base is still checked again by VerifyRolling below.
			return k, nil
		}
		return clxevidence.KeyContext{}, errors.New("authenticated CLX key context not retained by source")
	}
	var response struct {
		Number     uint64           `json:"keyBlockNumber"`
		Difficulty *hexutil.Big     `json:"difficulty"`
		ParentHash common.Hash      `json:"parentHash"`
		Nonce      types.BlockNonce `json:"nonce"`
		Mix        common.Hash      `json:"mixDigest"`
		Time       uint64           `json:"timestamp"`
		Committee  common.Hash      `json:"committeeHash"`
		Type       uint8            `json:"blockType"`
		TNumber    uint64           `json:"TxBlockNumber"`
	}
	if err := c.rpc(ctx, "eth_getKeyBlockByHash", []interface{}{common.Hash(base.SourceKeyHash).Hex()}, &response); err != nil {
		return clxevidence.KeyContext{}, err
	}
	if response.Difficulty == nil {
		return clxevidence.KeyContext{}, ErrAuthentication
	}
	header := &types.KeyBlockHeader{Number: new(big.Int).SetUint64(response.Number), Difficulty: new(big.Int).Set((*big.Int)(response.Difficulty)), ParentHash: response.ParentHash, Nonce: response.Nonce, MixDigest: response.Mix, Time: response.Time, CommitteeHash: response.Committee, BlockType: response.Type, T_Number: response.TNumber}
	if protocol.Hash(header.Hash()) != base.SourceKeyHash || protocol.Hash(header.CommitteeHash) != base.SourceCommittee {
		return clxevidence.KeyContext{}, ErrAuthentication
	}
	raw, err := rlp.EncodeToBytes(header)
	if err != nil {
		return clxevidence.KeyContext{}, err
	}
	if _, err = clxevidence.DecodeKeyHeader(raw); err != nil {
		return clxevidence.KeyContext{}, err
	}
	return clxevidence.KeyContext{KeyHeader: raw, Order: []uint8{0, 1, 2, 3, 4, 5, 6}}, nil
}
