package core

import (
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

// fhsPrevRandaoKeyReader is the minimum authenticated key-chain view needed to
// bind an execution block's PREVRANDAO to its signing epoch. Implementations
// must expose the canonical block at a height as well as hash lookup so a
// stored side-branch key block cannot become an execution randomness source.
type fhsPrevRandaoKeyReader interface {
	GetBlockByHash(common.Hash) *types.KeyBlock
	GetBlockByNumber(uint64) *types.KeyBlock
}

// validateFHSPrevRandao prevents a Fair HotStuff proposer from choosing
// opcode 0x44 independently of the authenticated key chain.
//
// Ordinary transaction blocks use the MixDigest of the canonical key block
// named by Header.KeyHash. A key-block carrier uses the new key block embedded
// in Header.KeyInfo; that transition is authenticated separately by the key
// candidate and HotStuff checks, but the outer execution header must commit to
// the exact same MixDigest. Before Shanghai opcode 0x44 retains DIFFICULTY
// semantics, so this rule activates together with PREVRANDAO.
func validateFHSPrevRandao(config *params.ChainConfig, block *types.Block, keys fhsPrevRandaoKeyReader) error {
	if config == nil || !config.FairHotstuff || block == nil || block.NumberU64() == 0 {
		return nil
	}
	header := block.Header()
	if header == nil || header.Number == nil || !config.IsShanghai(header.Number, header.Time) {
		return nil
	}
	if block.BlockType() == types.Key_Block {
		keyBlock := types.DecodeToKeyBlock(block.KeyInfo())
		if keyBlock == nil {
			return fmt.Errorf("Fair HotStuff PREVRANDAO key carrier has invalid embedded key block")
		}
		if block.KeyHash() != keyBlock.ParentHash() {
			return fmt.Errorf("Fair HotStuff PREVRANDAO key carrier parent mismatch: header=%s keyParent=%s", block.KeyHash(), keyBlock.ParentHash())
		}
		if block.MixDigest() != keyBlock.MixDigest() {
			return fmt.Errorf("Fair HotStuff PREVRANDAO key carrier mismatch: header=%s keyBlock=%s", block.MixDigest(), keyBlock.MixDigest())
		}
		return nil
	}
	if keys == nil {
		return fmt.Errorf("Fair HotStuff PREVRANDAO key chain is unavailable")
	}
	keyHash := block.KeyHash()
	if keyHash == (common.Hash{}) {
		return fmt.Errorf("Fair HotStuff PREVRANDAO block has an empty key hash")
	}
	keyBlock := keys.GetBlockByHash(keyHash)
	if keyBlock == nil {
		return fmt.Errorf("Fair HotStuff PREVRANDAO key block is unknown: %s", keyHash)
	}
	canonical := keys.GetBlockByNumber(keyBlock.NumberU64())
	if canonical == nil || canonical.Hash() != keyBlock.Hash() {
		return fmt.Errorf("Fair HotStuff PREVRANDAO key block is not canonical: %s", keyHash)
	}
	if block.MixDigest() != keyBlock.MixDigest() {
		return fmt.Errorf("Fair HotStuff PREVRANDAO mismatch for key block %s: header=%s keyBlock=%s", keyHash, block.MixDigest(), keyBlock.MixDigest())
	}
	return nil
}
