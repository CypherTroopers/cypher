// Copyright 2026 The cypher Authors
// This file is part of the cypher library.

package core

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

// These committees are exact historical mainnet records. They are needed at
// transaction-block boundaries where the deployed network changed committee
// out of band, without a key block whose normal transition reproduces the
// effective committee. The first entry repairs a committee which old clients
// computed incorrectly and therefore never persisted.
//
//go:embed checkpoints/131145.rlp.b64
var historicalCommittee131145 string

//go:embed checkpoints/131881.rlp.b64
var historicalCommittee131881 string

//go:embed checkpoints/178145.rlp.b64
var historicalCommittee178145 string

//go:embed checkpoints/313785.rlp.b64
var historicalCommittee313785 string

type historicalCommitteeCheckpoint struct {
	activationTx  uint64
	keyBlock      uint64
	keyHash       common.Hash
	headerHash    common.Hash
	committeeHash common.Hash
	memberCount   int
	encodedSize   int
	encodedSHA256 string
	encodedBase64 string
}

var historicalCommitteeCheckpoints = []historicalCommitteeCheckpoint{
	{
		activationTx:  139979,
		keyBlock:      131145,
		keyHash:       common.HexToHash("0x512f303ae81723aa45b85a511b50f19be0bae3a4efa41264d7548acf075863a0"),
		headerHash:    common.HexToHash("0xf690afcb52ec3c163496c383fff4f026acc2a34119fc576e3c02d134859cdd81"),
		committeeHash: common.HexToHash("0xf690afcb52ec3c163496c383fff4f026acc2a34119fc576e3c02d134859cdd81"),
		memberCount:   21,
		encodedSize:   4095,
		encodedSHA256: "a62f2a578e6c3e88892569b2b19386fff15c382c7b7df6306a31959a5faab150",
		encodedBase64: historicalCommittee131145,
	},
	{
		activationTx:  140715,
		keyBlock:      131881,
		keyHash:       common.HexToHash("0x8fbb23151b173f62a0e8e03a62095e9eb18b3de6ae600b09f156f31bcc291bc4"),
		headerHash:    common.HexToHash("0x3520cf6bc110e95245604f953807b74867cf812b3495ba943d6ea821107b2df9"),
		committeeHash: common.HexToHash("0x3fd8b15974d37cad78a92130fdde3bdefa97b24cd40351080e8ada0908b4ec39"),
		memberCount:   21,
		encodedSize:   4059,
		encodedSHA256: "d36348384275474e3e48b05a3fb9f5d881b59d9f7b947388c6316d455ffdb24b",
		encodedBase64: historicalCommittee131881,
	},
	{
		activationTx:  189869,
		keyBlock:      178145,
		keyHash:       common.HexToHash("0x91ea88c7dffa04495584f4b3e26c56e848cd5b42cc54436294608c9e9fb4988b"),
		headerHash:    common.HexToHash("0xc449458d56b035fdbade5bdcb6ae6284f6ae9dffc39bb9adaeb63d83cf429610"),
		committeeHash: common.HexToHash("0xae3279ba03964d15dc297bd804f5314019e00edc6a913c7d95f187c42f0e5adc"),
		memberCount:   20,
		encodedSize:   3884,
		encodedSHA256: "3beba05af1f43cc2e5911554956e30fd8e39ff56f40c415536c1b0b70e963e68",
		encodedBase64: historicalCommittee178145,
	},
	{
		activationTx:  328362,
		keyBlock:      313785,
		keyHash:       common.HexToHash("0x22db2ac21b1e06ffc528e9eef25c41044910e0a41aede915feff07243f2998cc"),
		headerHash:    common.HexToHash("0x03f666371e91bc779c80d9eef04bafa1e66544657def8ee1212e7fc67e40fd61"),
		committeeHash: common.HexToHash("0x9d8c5597615ae5e802ffe16d1c891da2ce7b10a93ab9db6ce6e40e59dca8cc5b"),
		memberCount:   21,
		encodedSize:   4081,
		encodedSHA256: "78c4ac3a49726c0aa485864057be0ee07d380e6b4ec20c8885870d55a510195c",
		encodedBase64: historicalCommittee313785,
	},
}

type resolvedHistoricalCommittee struct {
	checkpoint *historicalCommitteeCheckpoint
	committee  *bftview.Committee
	encoded    []byte
}

func historicalCommitteeCheckpointFor(txNumber uint64, keyHash common.Hash) *historicalCommitteeCheckpoint {
	for i := range historicalCommitteeCheckpoints {
		checkpoint := &historicalCommitteeCheckpoints[i]
		if txNumber >= checkpoint.activationTx && keyHash == checkpoint.keyHash {
			return checkpoint
		}
	}
	return nil
}

func decodeHistoricalCommittee(checkpoint *historicalCommitteeCheckpoint) ([]byte, *bftview.Committee, error) {
	encoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(checkpoint.encodedBase64))
	if err != nil {
		return nil, nil, fmt.Errorf("decode checkpoint %d: %w", checkpoint.keyBlock, err)
	}
	if len(encoded) != checkpoint.encodedSize {
		return nil, nil, fmt.Errorf("checkpoint %d size mismatch: have %d, want %d", checkpoint.keyBlock, len(encoded), checkpoint.encodedSize)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if digest != checkpoint.encodedSHA256 {
		return nil, nil, fmt.Errorf("checkpoint %d SHA-256 mismatch: have %s, want %s", checkpoint.keyBlock, digest, checkpoint.encodedSHA256)
	}
	committee := new(bftview.Committee)
	if err := rlp.DecodeBytes(encoded, committee); err != nil {
		return nil, nil, fmt.Errorf("decode checkpoint %d RLP: %w", checkpoint.keyBlock, err)
	}
	if len(committee.List) != checkpoint.memberCount {
		return nil, nil, fmt.Errorf("checkpoint %d member count mismatch: have %d, want %d", checkpoint.keyBlock, len(committee.List), checkpoint.memberCount)
	}
	for i, member := range committee.List {
		if member == nil {
			return nil, nil, fmt.Errorf("checkpoint %d has nil member %d", checkpoint.keyBlock, i)
		}
	}
	if hash := committee.RlpHash(); hash != checkpoint.committeeHash {
		return nil, nil, fmt.Errorf("checkpoint %d committee hash mismatch: have %s, want %s", checkpoint.keyBlock, hash.Hex(), checkpoint.committeeHash.Hex())
	}
	roundTrip, err := rlp.EncodeToBytes(committee)
	if err != nil {
		return nil, nil, fmt.Errorf("encode checkpoint %d RLP: %w", checkpoint.keyBlock, err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		return nil, nil, fmt.Errorf("checkpoint %d RLP is not canonical", checkpoint.keyBlock)
	}
	return encoded, committee, nil
}

func (v *BlockValidator) resolveHistoricalCommittee(block *types.Block) (*resolvedHistoricalCommittee, error) {
	if !params.IsCypheriumMainnet(v.config, v.bc.Genesis().Hash()) {
		return nil, nil
	}
	checkpoint := historicalCommitteeCheckpointFor(block.NumberU64(), block.KeyHash())
	if checkpoint == nil {
		return nil, nil
	}
	if block.NumberU64() == 0 || v.bc.GetCanonicalHash(block.NumberU64()-1) != block.ParentHash() {
		return nil, nil
	}
	keyBlock := v.bc.keyBlockChain.GetBlockByNumber(checkpoint.keyBlock)
	if keyBlock == nil {
		return nil, fmt.Errorf("historical committee key block %d is missing", checkpoint.keyBlock)
	}
	if keyBlock.Hash() != checkpoint.keyHash {
		return nil, fmt.Errorf("historical committee key block %d hash mismatch: have %s, want %s", checkpoint.keyBlock, keyBlock.Hash().Hex(), checkpoint.keyHash.Hex())
	}
	if keyBlock.CommitteeHash() != checkpoint.headerHash {
		return nil, fmt.Errorf("historical committee key block %d header hash mismatch: have %s, want %s", checkpoint.keyBlock, keyBlock.CommitteeHash().Hex(), checkpoint.headerHash.Hex())
	}

	encoded, committee, err := decodeHistoricalCommittee(checkpoint)
	if err != nil {
		return nil, err
	}
	committeeKey := rawdb.CommitteeKey(checkpoint.keyBlock, checkpoint.keyHash)
	hasExisting, err := v.bc.db.Has(committeeKey)
	if err != nil {
		return nil, fmt.Errorf("check historical committee %d: %w", checkpoint.keyBlock, err)
	}
	var existing []byte
	if hasExisting {
		existing, err = v.bc.db.Get(committeeKey)
		if err != nil {
			return nil, fmt.Errorf("read historical committee %d: %w", checkpoint.keyBlock, err)
		}
	}
	if len(existing) > 0 && !bytes.Equal(existing, encoded) {
		previous := new(bftview.Committee)
		if err := rlp.DecodeBytes(existing, previous); err != nil {
			return nil, fmt.Errorf("decode existing committee %d: %w", checkpoint.keyBlock, err)
		}
		previousHash := previous.RlpHash()
		if previousHash != checkpoint.headerHash && previousHash != checkpoint.committeeHash {
			return nil, fmt.Errorf("unexpected existing committee %d hash: have %s", checkpoint.keyBlock, previousHash.Hex())
		}
	}
	return &resolvedHistoricalCommittee{
		checkpoint: checkpoint,
		committee:  committee,
		encoded:    encoded,
	}, nil
}

func installHistoricalCommittee(resolved *resolvedHistoricalCommittee) error {
	if resolved == nil {
		return nil
	}
	checkpoint := resolved.checkpoint
	changed, err := bftview.EnsureCommitteeRLP(checkpoint.keyBlock, checkpoint.keyHash, resolved.encoded)
	if err != nil {
		return fmt.Errorf("install historical committee %d: %w", checkpoint.keyBlock, err)
	}
	if !changed {
		return nil
	}
	log.Warn("Applied historical committee checkpoint",
		"tx", checkpoint.activationTx,
		"keyblock", checkpoint.keyBlock,
		"keyhash", checkpoint.keyHash,
		"committee", checkpoint.committeeHash)
	return nil
}
