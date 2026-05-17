package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
)

// PoWResult is the compact, UDP-friendly representation of a mined candidate
// seal. It carries the work template identifiers and the PoW output only; a
// validator reconstructs the Candidate locally and performs full verification.
type PoWResult struct {
	ParentHash common.Hash
	Number     uint64
	TNumber    uint64
	Time       uint64

	IP       []byte
	Port     uint64
	PubKey   string
	Coinbase string

	Nonce     BlockNonce
	MixDigest common.Hash
}

// NewPoWResultFromCandidate extracts the mined PoW result and the minimal work
// template metadata required by validators to reconstruct and verify it.
func NewPoWResultFromCandidate(candidate *Candidate) *PoWResult {
	if candidate == nil || candidate.KeyCandidate == nil {
		return nil
	}
	result := &PoWResult{
		ParentHash: candidate.KeyCandidate.ParentHash,
		Number:     candidate.KeyCandidate.Number.Uint64(),
		TNumber:    candidate.KeyCandidate.T_Number,
		Time:       candidate.KeyCandidate.Time,
		Port:       uint64(candidate.Port),
		PubKey:     candidate.PubKey,
		Coinbase:   candidate.Coinbase,
		Nonce:      candidate.KeyCandidate.Nonce,
		MixDigest:  candidate.KeyCandidate.MixDigest,
	}
	result.IP = make([]byte, len(candidate.IP))
	copy(result.IP, candidate.IP)
	return result
}

// ToCandidate reconstructs a Candidate from the PoW result. The difficulty is
// intentionally left empty because validators recompute it from their local
// chain state before verification.
func (r *PoWResult) ToCandidate() *Candidate {
	if r == nil {
		return nil
	}
	candidate := NewCandidate(r.ParentHash, big.NewInt(0), r.Number, r.TNumber, nil, r.IP, r.PubKey, r.Coinbase, int(r.Port))
	candidate.KeyCandidate.Time = r.Time
	candidate.KeyCandidate.Nonce = r.Nonce
	candidate.KeyCandidate.MixDigest = r.MixDigest
	return candidate
}
