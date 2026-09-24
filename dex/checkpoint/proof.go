// Package checkpoint authenticates devnet DEX checkpoints without executing DEX
// actions. The genesis-gated native CLX settlement handler uses these bounded
// committee proofs. They are not validity proofs or authorization for real funds.
package checkpoint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const (
	MaxProofBytes  = 16 * 1024
	MaxDescendants = 8
	MaxRefBytes    = 2048
)

// Epoch is a trusted registry snapshot, installed by CLX authorization rather
// than by the proof submitter. Its fields cannot be mutated after construction.
type Epoch struct {
	domain     protocol.Domain
	first, end uint64
	keys       []*bls.PublicKey
	leaders    []string
}

func NewEpoch(domain protocol.Domain, first, end uint64, nodes []*common.Cnode) (*Epoch, error) {
	if !domain.Valid() || first == 0 || end <= first || len(nodes) != 7 {
		return nil, errors.New("invalid devnet epoch registration")
	}
	committee := &bftview.Committee{List: make([]*common.Cnode, 7)}
	e := &Epoch{domain: domain, first: first, end: end}
	seenKeys, seenIDs := make(map[string]bool), make(map[string]bool)
	for i, n := range nodes {
		if n == nil || len(n.Public) != 128 || len(n.Address) == 0 || len(n.Address) > 128 {
			return nil, errors.New("invalid registered member")
		}
		copyNode := *n
		committee.List[i] = &copyNode
		key := new(bls.PublicKey)
		if err := key.DeserializeHexStr(n.Public); err != nil {
			return nil, errors.New("invalid registered key")
		}
		encoded := key.Serialize()
		id := bftview.GetNodeID(n.Address, n.Public)
		if len(id) > 128 || bytes.Equal(encoded, make([]byte, len(encoded))) || seenKeys[string(encoded)] || seenIDs[id] {
			return nil, errors.New("duplicate or invalid registry identity")
		}
		seenKeys[string(encoded)], seenIDs[id] = true, true
		e.keys = append(e.keys, key)
		e.leaders = append(e.leaders, id)
	}
	if protocol.Hash(committee.RlpHash()) != domain.Committee {
		return nil, errors.New("committee commitment mismatch")
	}
	return e, nil
}

func (e *Epoch) Domain() protocol.Domain { return e.domain }

// Bounds returns the immutable CLX-authorized half-open sequence range.
func (e *Epoch) Bounds() (uint64, uint64) { return e.first, e.end }

// RegistryCommitment additionally binds endpoints/leader IDs and activation
// boundaries, which the legacy committee commitment alone does not include.
func (e *Epoch) RegistryCommitment() protocol.Hash {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, e.domain)
	_ = binary.Write(&b, binary.BigEndian, e.first)
	_ = binary.Write(&b, binary.BigEndian, e.end)
	for i, key := range e.keys {
		b.Write(key.Serialize())
		_ = binary.Write(&b, binary.BigEndian, uint16(len(e.leaders[i])))
		b.WriteString(e.leaders[i])
	}
	return protocol.Digest("common-dex/registry/v1", b.Bytes())
}

// Proof contains the target's own QC and authenticated descendant QCs. A target
// alone is never finality. The final parent/child views must be consecutive.
type Proof struct {
	Target      *hotstuff.SignedState
	Descendants []*hotstuff.SignedState
	// Version is populated by decoding. Zero requests the legacy encoder unless
	// History is present; schema 6 callers use EncodeProofV2 explicitly.
	Version uint16
	History *HistoryWitness
}

// HistoryWitness authenticates the target's exact semantic QC identity in the
// finalized anchor's ancestor commitment. Descendants then holds anchor/child.
type HistoryWitness struct {
	Count      uint64
	ActionRoot protocol.Hash
	Siblings   []protocol.Hash
}
type envelope struct {
	Version uint16
	QCs     [][]byte
}
type envelopeV2 struct {
	Version uint16
	QCs     [][]byte
	History []HistoryWitness // exactly zero (direct) or one (ancestry)
}

func proofShape(p Proof) error {
	if p.Target == nil || len(p.Descendants) < 1 || len(p.Descendants) > MaxDescendants {
		return errors.New("finality requires target and bounded descendants")
	}
	if p.History != nil && (len(p.Descendants) != 2 || p.History.Count == 0 || p.History.Count > protocol.MaxHistoryCount || p.History.ActionRoot == (protocol.Hash{}) || len(p.History.Siblings) != protocol.HistoryDepth) {
		return errors.New("finality history witness bounds")
	}
	for _, qc := range append([]*hotstuff.SignedState{p.Target}, p.Descendants...) {
		if qc == nil || len(qc.State) == 0 || len(qc.State) > MaxRefBytes || len(qc.Sign) == 0 || len(qc.Sign) > 128 || len(qc.LeaderID) == 0 || len(qc.LeaderID) > 128 {
			return errors.New("oversized or incomplete QC")
		}
		if err := hotstuff.ValidateCanonicalSignerMask(qc.Mask, 7, 5); err != nil {
			return err
		}
	}
	return nil
}

func EncodeProof(p Proof) ([]byte, error) {
	if p.Version == 2 || p.History != nil {
		return EncodeProofV2(p)
	}
	if p.Version != 0 && p.Version != 1 {
		return nil, errors.New("unsupported finality proof version")
	}
	if err := proofShape(p); err != nil {
		return nil, err
	}
	e := envelope{Version: 1}
	for _, qc := range append([]*hotstuff.SignedState{p.Target}, p.Descendants...) {
		data, err := hotstuff.EncodeSignedState(qc)
		if err != nil {
			return nil, err
		}
		e.QCs = append(e.QCs, data)
	}
	data, err := rlp.EncodeToBytes(e)
	if len(data) > MaxProofBytes {
		return nil, errors.New("proof byte limit exceeded")
	}
	return data, err
}

func EncodeProofV2(p Proof) ([]byte, error) {
	if p.Version != 0 && p.Version != 2 {
		return nil, errors.New("unsupported finality proof version")
	}
	if err := proofShape(p); err != nil {
		return nil, err
	}
	e := envelopeV2{Version: 2}
	for _, qc := range append([]*hotstuff.SignedState{p.Target}, p.Descendants...) {
		data, err := hotstuff.EncodeSignedState(qc)
		if err != nil {
			return nil, err
		}
		e.QCs = append(e.QCs, data)
	}
	if p.History != nil {
		e.History = []HistoryWitness{*p.History}
	}
	data, err := rlp.EncodeToBytes(e)
	if len(data) > MaxProofBytes {
		return nil, errors.New("proof byte limit exceeded")
	}
	return data, err
}

func DecodeProof(data []byte) (Proof, error) {
	var p Proof
	if len(data) == 0 || len(data) > MaxProofBytes {
		return p, errors.New("proof byte limit exceeded")
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(data, &fields); err != nil {
		return p, err
	}
	if len(fields) < 2 || len(fields) > 3 || rlp.DecodeBytes(fields[0], &p.Version) != nil {
		return p, errors.New("proof envelope fields invalid")
	}
	var qcs [][]byte
	switch p.Version {
	case 1:
		var e envelope
		if len(fields) != 2 || rlp.DecodeBytes(data, &e) != nil {
			return p, errors.New("proof version 1 framing")
		}
		qcs = e.QCs
	case 2:
		var e envelopeV2
		if len(fields) != 3 || rlp.DecodeBytes(data, &e) != nil || len(e.History) > 1 {
			return p, errors.New("proof version 2 framing")
		}
		qcs = e.QCs
		if len(e.History) == 1 {
			p.History = &e.History[0]
		}
	default:
		return p, errors.New("proof version invalid")
	}
	if len(qcs) < 2 || len(qcs) > MaxDescendants+1 {
		return p, errors.New("proof version or count invalid")
	}
	for i, data := range qcs {
		if len(data) > MaxRefBytes+512 {
			return Proof{}, errors.New("QC byte limit exceeded")
		}
		qc, err := hotstuff.DecodeSignedState(data)
		if err != nil {
			return Proof{}, err
		}
		if i == 0 {
			p.Target = qc
		} else {
			p.Descendants = append(p.Descendants, qc)
		}
	}
	if err := proofShape(p); err != nil {
		return Proof{}, err
	}
	return p, nil
}

// VerifyStats makes the bounded verification cost visible; it counts signature
// checks only and does not imply computation or availability verification.
type VerifyStats struct{ SignatureChecks int }

func (e *Epoch) Verify(c protocol.Checkpoint, encoded []byte) (VerifyStats, error) {
	var stats VerifyStats
	if e == nil || c.Domain() != e.domain || c.Sequence < e.first || c.Sequence >= e.end {
		return stats, errors.New("unauthorized epoch boundary")
	}
	hash, err := c.Hash()
	if err != nil {
		return stats, err
	}
	p, err := DecodeProof(encoded)
	if err != nil {
		return stats, err
	}
	if (c.DataSchema == 6) != (p.Version == 2) {
		return stats, errors.New("checkpoint schema/finality proof version mismatch")
	}
	if p.Version == 2 && (c.Sequence != c.FirstBlock || c.Sequence != c.LastBlock) {
		return stats, errors.New("history checkpoint must cover exactly its sequence")
	}
	qcs := append([]*hotstuff.SignedState{p.Target}, p.Descendants...)
	refs := make([]*types.HotstuffProposalRef, len(qcs))
	for i, qc := range qcs {
		ref, err := types.DecodeHotstuffProposalRef(qc.State)
		if err != nil {
			return stats, err
		}
		if ref.ChainID != e.domain.ChainID || ref.KeyHash != common.Hash(e.domain.EpochKey()) ||
			ref.ViewNumber != qc.Number || ref.ViewID != qc.ViewID || ref.LeaderID != qc.LeaderID ||
			ref.LeaderID != e.leaders[(ref.ViewNumber-1)%7] {
			return stats, errors.New("QC domain, epoch or leader mismatch")
		}
		if p.Version == 2 && (ref.Number < e.first || ref.Number >= e.end || ref.Number > protocol.MaxHistoryCount+1) {
			return stats, errors.New("history QC outside registered epoch/height")
		}
		if ref.Time != ref.Number || ref.BodySize > 1024*1024 || ref.TxHash != (common.Hash{}) ||
			ref.ReceiptHash != (common.Hash{}) || ref.CommonTxAdmissionRoot != (common.Hash{}) ||
			ref.CommonTxRewardRoot != (common.Hash{}) || ref.BlockType != 0 || ref.GasLimit != 0 || ref.GasUsed != 0 {
			return stats, errors.New("noncanonical DEX proposal metadata")
		}
		refs[i] = ref
		if i == 0 {
			if ref.BlockHash != common.Hash(hash) || ref.StateRoot != common.Hash(c.PostRoot) || ref.Number != c.LastBlock || ref.BodyHash != common.Hash(c.DataRoot) {
				return stats, errors.New("QC does not commit checkpoint")
			}
			continue
		}
		if p.History != nil && i == 1 {
			if ref.Number <= refs[0].Number || ref.Number-1 != p.History.Count || ref.ViewNumber <= refs[0].ViewNumber {
				return stats, errors.New("finality history anchor range")
			}
			id, err := hotstuff.SignedStateID(p.Target)
			if err != nil {
				return stats, err
			}
			root, err := protocol.HistoryProofRoot(protocol.Hash(id.Hash()), refs[0].Number-1, p.History.Count, p.History.Siblings)
			if err != nil {
				return stats, err
			}
			dataRoot, err := protocol.HistoryDataRoot(p.History.ActionRoot, root, p.History.Count)
			if err != nil || common.Hash(dataRoot) != ref.BodyHash {
				return stats, errors.New("finality history commitment mismatch")
			}
			continue
		}
		parent := refs[i-1]
		id, err := hotstuff.SignedStateID(qcs[i-1])
		if err != nil {
			return stats, err
		}
		if ref.ParentHash != parent.BlockHash || ref.Number <= parent.Number || ref.Number-parent.Number != 1 ||
			ref.ParentQCID != id.Hash() || ref.ViewNumber <= parent.ViewNumber ||
			(i == len(qcs)-1 && ref.ViewNumber-parent.ViewNumber != 1) {
			return stats, errors.New("invalid FHS 2-chain finality edge")
		}
	}
	// All bounds, metadata and edges have been checked before any cryptography.
	for i, qc := range qcs {
		stats.SignatureChecks++
		if !hotstuff.VerifyFHSSignatureWithContext(qc.Sign, qc.Mask, qc.State, e.keys, 5, e.domain.ChainID, hotstuff.MsgVotePrepare, qc.ViewID, qc.LeaderID) {
			return stats, fmt.Errorf("invalid QC signature %d", i)
		}
	}
	return stats, nil
}
