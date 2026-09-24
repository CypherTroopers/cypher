// Package clxevidence authenticates bounded native inbox evidence offline. Its
// committee snapshots come from trusted CLX genesis/history, never from a proof.
package clxevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const (
	MaxEvidenceBytes  = 4 * 1024 * 1024
	MaxAncestryBlocks = 64
	MaxBlockBytes     = 1024 * 1024
	MaxFinalityBytes  = 16 * 1024
	MaxDescendants    = 8
	MaxRefBytes       = 2048
)

type CommitteeEpoch struct {
	First, End uint64
	KeyHash    common.Hash
	Members    []*common.Cnode
}
type Config struct {
	ChainID     uint64
	Genesis     *types.Header
	ChainConfig *params.ChainConfig
	Seed        common.Hash
	DEXID       protocol.Hash
	Custody     common.Address
	Epochs      []CommitteeEpoch
}
type epoch struct {
	first, end             uint64
	keyHash, committeeHash common.Hash
	keys                   []*bls.PublicKey
	leaders                []string
}
type Verifier struct {
	chainID        uint64
	genesis        *types.Header
	seed           common.Hash
	dex            protocol.Hash
	custody        common.Address
	epochs         []epoch
	renewalEnabled bool
	members        []*common.Cnode
	qcEpoch        func(*types.HotstuffProposalRef, *hotstuff.SignedState) *epoch
}

func New(c Config) (*Verifier, error) {
	if c.Genesis == nil || c.Genesis.Number == nil || c.Genesis.Number.Sign() != 0 || c.ChainID == 0 || c.Seed == (common.Hash{}) || c.DEXID == (protocol.Hash{}) || c.Custody == (common.Address{}) || len(c.Epochs) == 0 || len(c.Epochs) > 64 || c.ChainConfig == nil || !c.ChainConfig.FairHotstuff || c.ChainConfig.ChainID == nil || !c.ChainConfig.ChainID.IsUint64() || c.ChainConfig.ChainID.Uint64() != c.ChainID || c.ChainConfig.FairHotstuffSeed != c.Seed {
		return nil, errors.New("invalid trusted CLX evidence configuration")
	}
	commit, err := params.FairHotstuffGenesisCommitment(c.ChainConfig)
	if err != nil || commit != c.Genesis.MixDigest {
		return nil, errors.New("CLX genesis does not authenticate supplied chain configuration")
	}
	if err = c.Genesis.SanityCheck(); err != nil {
		return nil, err
	}
	indices := make([]int, 0, len(c.ChainConfig.GenCommittee))
	for index := range c.ChainConfig.GenCommittee {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	if len(indices) != 7 || len(c.Epochs[0].Members) != 7 {
		return nil, errors.New("evidence fixture requires seven genesis members")
	}
	for i, index := range indices {
		if c.Epochs[0].Members[i] == nil || *c.Epochs[0].Members[i] != c.ChainConfig.GenCommittee[index] {
			return nil, errors.New("first committee differs from authenticated genesis")
		}
	}
	v := &Verifier{chainID: c.ChainID, genesis: types.CopyHeader(c.Genesis), seed: c.Seed, dex: c.DEXID, custody: c.Custody}
	v.renewalEnabled = c.ChainConfig.FixedCommittee && c.ChainConfig.DEXDevnet.RollingAnchors()
	for _, m := range c.Epochs[0].Members {
		n := *m
		v.members = append(v.members, &n)
	}
	seenEpoch := map[common.Hash]bool{}
	for i, registered := range c.Epochs {
		if registered.First == 0 || registered.End <= registered.First || registered.KeyHash == (common.Hash{}) || seenEpoch[registered.KeyHash] || len(registered.Members) != 7 || (i == 0 && registered.First != 1) || (i > 0 && registered.First != c.Epochs[i-1].End) {
			return nil, errors.New("invalid historical committee interval")
		}
		seenEpoch[registered.KeyHash] = true
		e := epoch{first: registered.First, end: registered.End, keyHash: registered.KeyHash}
		committee := &bftview.Committee{List: make([]*common.Cnode, 7)}
		seenKeys, seenLeaders := map[string]bool{}, map[string]bool{}
		for j, m := range registered.Members {
			if m == nil || len(m.Public) != 128 || len(m.Address) == 0 || len(m.Address) > 128 {
				return nil, errors.New("invalid CLX registered member")
			}
			key := new(bls.PublicKey)
			if err := key.DeserializeHexStr(m.Public); err != nil {
				return nil, err
			}
			encoded := key.Serialize()
			leader := bftview.GetNodeID(m.Address, m.Public)
			if len(leader) == 0 || len(leader) > 128 || bytes.Equal(encoded, make([]byte, len(encoded))) || seenKeys[string(encoded)] || seenLeaders[leader] {
				return nil, errors.New("duplicate/zero CLX registry identity")
			}
			seenKeys[string(encoded)], seenLeaders[leader] = true, true
			n := *m
			committee.List[j] = &n
			e.keys = append(e.keys, key)
			e.leaders = append(e.leaders, leader)
		}
		e.committeeHash = committee.RlpHash()
		v.epochs = append(v.epochs, e)
	}
	return v, nil
}
func (v *Verifier) epoch(number uint64, key common.Hash) (*epoch, error) {
	for i := range v.epochs {
		e := &v.epochs[i]
		if number >= e.first && number < e.end && key == e.keyHash {
			return e, nil
		}
	}
	return nil, errors.New("CLX proof uses unauthorized historical key/height")
}

// LeaderIndex exactly matches reconfig/fhs_context.go's genesis-seeded PRF.
func LeaderIndex(seed common.Hash, chainID, view uint64, committee common.Hash) (uint, error) {
	if seed == (common.Hash{}) || chainID == 0 || view == 0 || committee == (common.Hash{}) {
		return 0, errors.New("invalid CLX leader context")
	}
	n := uint64(7)
	cutoff := -n % n
	for counter := uint64(0); counter < 64; counter++ {
		h := sha256.New()
		h.Write([]byte("cypher-fhs-leader-v2"))
		h.Write(seed[:])
		var b [8]byte
		for _, x := range []uint64{chainID, view} {
			binary.BigEndian.PutUint64(b[:], x)
			h.Write(b[:])
		}
		h.Write(committee[:])
		binary.BigEndian.PutUint64(b[:], counter)
		h.Write(b[:])
		candidate := binary.BigEndian.Uint64(h.Sum(nil)[:8])
		if candidate >= cutoff {
			return uint(candidate % n), nil
		}
	}
	return 0, errors.New("CLX leader rejection-sampling budget exhausted")
}

type finalityEnvelope struct {
	Version uint32
	QCs     [][]byte
}
type checkedBlock struct {
	block  *types.Block
	ref    *types.HotstuffProposalRef
	target *hotstuff.SignedState
	desc   []*hotstuff.SignedState
}

func (v *Verifier) qcShape(q *hotstuff.SignedState) (*types.HotstuffProposalRef, *epoch, error) {
	if q == nil || len(q.State) == 0 || len(q.State) > MaxRefBytes || len(q.Sign) == 0 || len(q.Sign) > 128 || len(q.LeaderID) == 0 || len(q.LeaderID) > 128 {
		return nil, nil, errors.New("CLX QC byte bound")
	}
	r, err := types.DecodeHotstuffProposalRef(q.State)
	if err != nil {
		return nil, nil, err
	}
	if r.ChainID != v.chainID || r.ViewNumber == math.MaxUint64 || r.ViewNumber != q.Number || r.ViewID != q.ViewID || r.LeaderID != q.LeaderID {
		return nil, nil, errors.New("CLX QC context mismatch")
	}
	var e *epoch
	if v.qcEpoch != nil {
		if !v.renewalEnabled || len(v.epochs) != 1 {
			return nil, nil, errors.New("CLX key context disabled")
		}
		e = v.qcEpoch(r, q)
		if e == nil {
			return nil, nil, errors.New("CLX proof uses unauthorized key activation context")
		}
	} else {
		e, err = v.epoch(r.Number, r.KeyHash)
		if err != nil {
			return nil, nil, err
		}
	}

	leader, err := LeaderIndex(v.seed, v.chainID, r.ViewNumber, e.committeeHash)
	if err != nil || r.LeaderID != e.leaders[leader] {
		return nil, nil, errors.New("CLX QC leader mismatch")
	}
	if err = hotstuff.ValidateCanonicalSignerMask(q.Mask, len(e.keys), hotstuff.CalcThreshold(len(e.keys))); err != nil {
		return nil, nil, err
	}
	return r, e, nil
}
func (v *Verifier) prepareBlock(raw []byte) (checkedBlock, error) {
	var out checkedBlock
	if len(raw) == 0 || len(raw) > MaxBlockBytes {
		return out, errors.New("CLX block byte bound")
	}
	var b types.Block
	if err := rlp.DecodeBytes(raw, &b); err != nil {
		return out, err
	}
	if b.Header0() == nil || b.Header0().Number == nil || !b.Header0().Number.IsUint64() || b.Header0().Number.Sign() == 0 {
		return out, errors.New("invalid CLX block height")
	}
	if !bytes.Equal(raw, b.EncodeToBytes()) {
		return out, errors.New("noncanonical CLX block encoding")
	}
	if err := b.SanityCheck(); err != nil {
		return out, err
	}
	si := b.SignInfo()
	if len(si.FHSFinalityProof) == 0 || len(si.FHSFinalityProof) > MaxFinalityBytes || len(si.Signature) == 0 || len(si.Signature) > 128 || len(si.LeaderID) > 128 {
		return out, errors.New("CLX target lacks bounded QC/finality")
	}
	ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(v.chainID, si.ViewNumber, si.ViewID, si.LeaderID, &b, si.ExtraHash, si.ParentQCID)
	if err != nil {
		return out, err
	}
	q := &hotstuff.SignedState{State: ref.EncodeToBytes(), Sign: common.CopyBytes(si.Signature), Mask: common.CopyBytes(si.Exceptions), ViewID: si.ViewID, LeaderID: si.LeaderID, Number: si.ViewNumber}
	if _, _, err = v.qcShape(q); err != nil {
		return out, err
	}
	var envelope finalityEnvelope
	if err = rlp.DecodeBytes(si.FHSFinalityProof, &envelope); err != nil {
		return out, err
	}
	if envelope.Version != 2 || len(envelope.QCs) < 1 || len(envelope.QCs) > MaxDescendants {
		return out, errors.New("CLX descendant proof count/version")
	}
	parentRef, parentQC := ref, q
	for i, encoded := range envelope.QCs {
		if len(encoded) > MaxRefBytes+512 {
			return out, errors.New("CLX descendant QC bound")
		}
		child, err := hotstuff.DecodeSignedState(encoded)
		if err != nil {
			return out, err
		}
		cr, _, err := v.qcShape(child)
		if err != nil {
			return out, err
		}
		pid, err := hotstuff.SignedStateID(parentQC)
		if err != nil {
			return out, err
		}
		if parentRef.Number == math.MaxUint64 || cr.ParentHash != parentRef.BlockHash || cr.Number != parentRef.Number+1 || cr.ViewNumber <= parentRef.ViewNumber || cr.ParentQCID != pid.Hash() {
			return out, errors.New("CLX descendant does not bind exact parent QC")
		}
		if i == len(envelope.QCs)-1 && cr.ViewNumber-parentRef.ViewNumber != 1 {
			return out, errors.New("CLX terminal finality edge requires consecutive views")
		}
		out.desc = append(out.desc, child)
		parentRef, parentQC = cr, child
	}
	out.block, out.ref, out.target = &b, ref, q
	return out, nil
}
func (v *Verifier) verifyQC(q *hotstuff.SignedState) error {
	_, e, err := v.qcShape(q)
	if err != nil {
		return err
	}
	if !hotstuff.VerifyFHSSignatureWithContext(q.Sign, q.Mask, q.State, e.keys, hotstuff.CalcThreshold(len(e.keys)), v.chainID, hotstuff.MsgVotePrepare, q.ViewID, q.LeaderID) {
		return errors.New("invalid actual CLX FHS signature")
	}
	return nil
}
func (v *Verifier) verifyBlocks(raw [][]byte) (*types.Header, error) {
	if len(raw) == 0 || len(raw) > MaxAncestryBlocks {
		return nil, errors.New("CLX ancestry count bound")
	}
	blocks := make([]checkedBlock, len(raw))
	parent := v.genesis.Hash()
	for i, b := range raw {
		checked, err := v.prepareBlock(b)
		if err != nil {
			return nil, fmt.Errorf("CLX block %d: %w", i+1, err)
		}
		if checked.block.NumberU64() != uint64(i+1) || checked.block.ParentHash() != parent {
			return nil, errors.New("orphan/noncontiguous CLX ancestry")
		}
		blocks[i] = checked
		parent = checked.block.Hash()
	}
	// All ancestry and finality shapes are bounded before signature operations.
	for _, b := range blocks {
		if err := v.verifyQC(b.target); err != nil {
			return nil, err
		}
		for _, q := range b.desc {
			if err := v.verifyQC(q); err != nil {
				return nil, err
			}
		}
	}
	return blocks[len(blocks)-1].block.Header(), nil
}
