package types

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	cx "colossusx/colossusx"
	"golang.org/x/crypto/sha3"
)

type Hash [32]byte

type BlockHeader struct {
	Version          uint32    `json:"version"`
	AlgorithmVersion uint32    `json:"algorithm_version"`
	Height           uint64    `json:"height"`
	ParentHash       Hash      `json:"parent_hash"`
	Timestamp        int64     `json:"timestamp"`
	Target           cx.Target `json:"target"`
	Nonce            uint64    `json:"nonce"`
	EpochSeed        Hash      `json:"epoch_seed"`
	DAGSizeBytes     uint64    `json:"dag_size_bytes"` // resolved DAG size for this block height
	DAGMerkleRoot    Hash      `json:"dag_merkle_root"`
	TxRoot           Hash      `json:"tx_root"`
	StateRoot        Hash      `json:"state_root"`
}

type Block struct {
	Header                   BlockHeader                  `json:"header"`
	Transactions             []string                     `json:"transactions,omitempty"`
	ColossusXSolution        *cx.ColossusXSolution        `json:"colossusx_solution,omitempty"`
	ColossusXSolutionCompact *cx.ColossusXSolutionCompact `json:"colossusx_solution_compact,omitempty"`
}

type GenesisConfig struct {
	ChainID   string    `json:"chain_id"`
	Message   string    `json:"message,omitempty"`
	Timestamp int64     `json:"timestamp"`
	Bits      cx.Target `json:"target"`
	Spec      cx.Spec   `json:"spec"`
	ExtraData string    `json:"extra_data,omitempty"`
}

type ChainConfig struct {
	NetworkID string  `json:"network_id"`
	Spec      cx.Spec `json:"spec"`
}

type PeerStatus struct {
	PeerID      string `json:"peer_id"`
	BestHash    Hash   `json:"best_hash"`
	BestHeight  uint64 `json:"best_height"`
	TotalWork   string `json:"total_work"`
	ConnectedAt int64  `json:"connected_at"`
}

type MiningTemplate struct {
	Parent    Hash        `json:"parent"`
	Height    uint64      `json:"height"`
	Target    cx.Target   `json:"target"`
	EpochSeed Hash        `json:"epoch_seed"`
	CreatedAt time.Time   `json:"created_at"`
	Header    BlockHeader `json:"header"`
}

func (h Hash) String() string               { return hex.EncodeToString(h[:]) }
func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(h.String()) }
func (h *Hash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(decoded) != len(h) {
		return fmt.Errorf("expected %d bytes, got %d", len(h), len(decoded))
	}
	copy(h[:], decoded)
	return nil
}
func (h BlockHeader) EncodeForMining() []byte {
	buf := make([]byte, 0, 4+4+8+32+8+32+32+8+32+32+32)
	buf = binary.BigEndian.AppendUint32(buf, h.Version)
	buf = binary.BigEndian.AppendUint32(buf, h.AlgorithmVersion)
	buf = binary.BigEndian.AppendUint64(buf, h.Height)
	buf = append(buf, h.ParentHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(h.Timestamp))
	buf = append(buf, h.Target[:]...)
	buf = append(buf, h.EpochSeed[:]...)
	buf = binary.BigEndian.AppendUint64(buf, h.DAGSizeBytes)
	buf = append(buf, h.DAGMerkleRoot[:]...)
	buf = append(buf, h.TxRoot[:]...)
	buf = append(buf, h.StateRoot[:]...)
	return buf
}
func (h BlockHeader) Encode() []byte {
	buf := h.EncodeForMining()
	buf = binary.BigEndian.AppendUint64(buf, h.Nonce)
	return buf
}
func (h BlockHeader) HeaderHash() Hash { return sha256.Sum256(h.Encode()) }
func (b Block) BlockHash() Hash        { return b.Header.HeaderHash() }
func NewGenesisBlock(cfg GenesisConfig) Block {
	var txRoot Hash
	var stateRoot Hash
	txRoot = sha256.Sum256([]byte(cfg.Message))
	stateRoot = sha256.Sum256([]byte(cfg.ExtraData))
	resolved := cfg.Spec.ResolvedForHeight(0)
	return Block{Header: BlockHeader{Version: 1, AlgorithmVersion: resolved.AlgorithmVersion, Height: 0, ParentHash: Hash{}, Timestamp: cfg.Timestamp, Target: cfg.Bits, Nonce: 0, EpochSeed: EpochSeedForHeight(resolved, 0), DAGSizeBytes: resolved.DAGSizeBytes, DAGMerkleRoot: Hash{}, TxRoot: txRoot, StateRoot: stateRoot}}
}
func EpochSeedForHeight(spec cx.Spec, height uint64) Hash {
	var seedMaterial [40]byte
	epoch := uint64(0)
	if spec.EpochBlocks != 0 {
		epoch = height / spec.EpochBlocks
	}
	binary.BigEndian.PutUint64(seedMaterial[:8], epoch)
	copy(seedMaterial[8:], spec.GenesisHash[:])
	return sha3.Sum256(seedMaterial[:])
}
