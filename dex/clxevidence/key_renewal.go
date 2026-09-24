package clxevidence

import (
	"bytes"
	"fmt"
	"math"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const MaxKeyHeaderBytes = 512
const MaxKeyCarrierBytes = 2048

// KeyContext contains hash preimages, never a new trust root. The caller's
// authenticated Anchor commits both the active header and boundary QC IDs.
type KeyContext struct {
	KeyHeader         []byte
	Boundary          []protocol.Hash
	Order             []uint8
	PreviousKeyHeader []byte
	PreviousOrder     []uint8
}

func (k KeyContext) Clone() KeyContext {
	return KeyContext{KeyHeader: bytes.Clone(k.KeyHeader), Boundary: append([]protocol.Hash(nil), k.Boundary...), Order: bytes.Clone(k.Order), PreviousKeyHeader: bytes.Clone(k.PreviousKeyHeader), PreviousOrder: bytes.Clone(k.PreviousOrder)}
}
func (e RollingEvidence) KeyContext() KeyContext {
	return (KeyContext{KeyHeader: e.KeyHeader, Boundary: e.Boundary, Order: e.Order, PreviousKeyHeader: e.PreviousKeyHeader, PreviousOrder: e.PreviousOrder}).Clone()
}
func (e *RollingEvidence) SetKeyContext(k KeyContext) {
	k = k.Clone()
	e.KeyHeader, e.Boundary, e.Order, e.PreviousKeyHeader, e.PreviousOrder = k.KeyHeader, k.Boundary, k.Order, k.PreviousKeyHeader, k.PreviousOrder
}
func identityOrder() []uint8 { return []uint8{0, 1, 2, 3, 4, 5, 6} }
func (v *Verifier) orderedEpoch(header *types.KeyBlockHeader, order []uint8) (*epoch, error) {
	if len(order) == 0 {
		order = identityOrder()
	}
	if len(order) != 7 {
		return nil, ErrRollingMalformed
	}
	e := epoch{first: v.epochs[0].first, end: v.epochs[0].end, keyHash: header.Hash()}
	seen := uint8(0)
	committee := &bftview.Committee{}
	for _, index := range order {
		if index >= 7 || seen&(1<<index) != 0 {
			return nil, ErrRollingMalformed
		}
		seen |= 1 << index
		e.keys = append(e.keys, v.epochs[0].keys[index])
		e.leaders = append(e.leaders, v.epochs[0].leaders[index])
		member := *v.members[index]
		committee.List = append(committee.List, &member)
	}
	e.committeeHash = committee.RlpHash()
	if e.committeeHash != header.CommitteeHash {
		return nil, ErrRollingBase
	}
	return &e, nil
}
func (v *Verifier) contextEpochs(base Anchor, k KeyContext) (*types.KeyBlockHeader, *epoch, *epoch, error) {
	header, err := v.checkKeyContext(base, k)
	if err != nil {
		return nil, nil, nil, err
	}
	current, err := v.orderedEpoch(header, k.Order)
	if err != nil {
		return nil, nil, nil, err
	}
	previous := &v.epochs[0]
	if len(k.Order) > 0 {
		if base.ActivationEnd == 0 {
			if len(k.PreviousKeyHeader) > 0 || len(k.PreviousOrder) > 0 {
				return nil, nil, nil, ErrRollingBase
			}
		} else {
			old, err := DecodeKeyHeader(k.PreviousKeyHeader)
			if err != nil || old.Hash() != header.ParentHash {
				return nil, nil, nil, ErrRollingBase
			}
			if len(k.PreviousOrder) != 7 {
				return nil, nil, nil, ErrRollingBase
			}
			previous, err = v.orderedEpoch(old, k.PreviousOrder)
			if err != nil {
				return nil, nil, nil, err
			}
		}
	} else if len(k.PreviousKeyHeader) > 0 || len(k.PreviousOrder) > 0 {
		return nil, nil, nil, ErrRollingBase
	}
	return header, current, previous, nil
}

func (r *VerifiedRange) KeyContext() KeyContext {
	if r == nil {
		return KeyContext{}
	}
	return r.keyContext.Clone()
}
func BoundaryCommitment(ids []protocol.Hash) (protocol.Hash, error) {
	if len(ids) == 0 || len(ids) > MaxDescendants {
		return protocol.Hash{}, ErrRollingMalformed
	}
	raw := []byte{byte(len(ids))}
	seen := map[protocol.Hash]bool{}
	for _, id := range ids {
		if id == (protocol.Hash{}) || seen[id] {
			return protocol.Hash{}, ErrRollingMalformed
		}
		seen[id] = true
		raw = append(raw, id[:]...)
	}
	return protocol.Digest("common-dex/clx-key-boundary/v1", raw), nil
}
func DecodeKeyHeader(raw []byte) (*types.KeyBlockHeader, error) {
	if len(raw) == 0 || len(raw) > MaxKeyHeaderBytes {
		return nil, ErrRollingMalformed
	}
	var h types.KeyBlockHeader
	if err := rlp.DecodeBytes(raw, &h); err != nil {
		return nil, ErrRollingMalformed
	}
	canonical, err := rlp.EncodeToBytes(&h)
	if err != nil || !bytes.Equal(raw, canonical) || h.Number == nil || !h.Number.IsUint64() || h.Difficulty == nil || h.Difficulty.Sign() < 0 || h.Difficulty.BitLen() > 256 {
		return nil, ErrRollingMalformed
	}
	return &h, nil
}
func (v *Verifier) checkKeyContext(base Anchor, k KeyContext) (*types.KeyBlockHeader, error) {
	if !v.renewalEnabled {
		return nil, ErrRollingBase
	}
	h, err := DecodeKeyHeader(k.KeyHeader)
	if err != nil {
		return nil, err
	}
	if protocol.Hash(h.Hash()) != base.SourceKeyHash || protocol.Hash(h.CommitteeHash) != base.SourceCommittee {
		return nil, ErrRollingBase
	}
	if base.ActivationRoot == (protocol.Hash{}) {
		if len(k.Boundary) != 0 {
			return nil, ErrRollingBase
		}
	} else {
		root, err := BoundaryCommitment(k.Boundary)
		if err != nil || root != base.ActivationRoot {
			return nil, ErrRollingBase
		}
	}
	return h, nil
}

// VerifyHeaderContext authenticates only the short contiguous interval after
// trusted base. It does not authenticate custody MPT data or inbox count.
// Legacy v1 with empty context follows the unchanged static-key verifier.
func (v *Verifier) VerifyHeaderContext(base Anchor, k KeyContext, headers []HeaderWitness) (*types.Header, Anchor, KeyContext, error) {
	fail := func(err error) (*types.Header, Anchor, KeyContext, error) { return nil, Anchor{}, KeyContext{}, err }
	if err := v.checkBase(base); err != nil {
		return fail(err)
	}
	if len(headers) > MaxAncestryBlocks {
		return fail(ErrRollingMalformed)
	}
	if len(k.KeyHeader) == 0 {
		if base.Version != 1 || len(k.Boundary) > 0 || len(k.Order) > 0 || len(k.PreviousKeyHeader) > 0 || len(k.PreviousOrder) > 0 {
			return fail(ErrRollingBase)
		}
		h, err := v.VerifyHeaderWitnesses(base, headers)
		if err != nil {
			return fail(err)
		}
		target := base
		if len(headers) > 0 {
			target.Height = h.Number.Uint64()
			target.BlockHash = protocol.Hash(h.Hash())
			target.StateRoot = protocol.Hash(h.Root)
		}
		// A legacy payload may authenticate a carrier but cannot silently retain a
		// stale source-key anchor; require its parent-header preimage at that edge.
		for _, w := range headers {
			var header types.Header
			if err := rlp.DecodeBytes(w.Header, &header); err != nil {
				return fail(err)
			}
			if header.BlockType == types.Key_Block {
				return fail(fmt.Errorf("%w: key carrier context required", ErrRollingBase))
			}
		}
		return h, target, KeyContext{}, nil
	}
	parentKey, currentEpoch, previousEpoch, err := v.contextEpochs(base, k)
	if err != nil {
		return fail(err)
	}
	k = k.Clone()
	target := base
	auth := *v
	auth.qcEpoch = func(r *types.HotstuffProposalRef, q *hotstuff.SignedState) *epoch {
		if r.Number < v.epochs[0].first || r.Number >= v.epochs[0].end {
			return nil
		}
		if protocol.Hash(r.KeyHash) == target.SourceKeyHash {
			if target.ActivationEnd == 0 || r.Number > target.ActivationEnd {
				return currentEpoch
			}
			return nil
		}
		if target.ActivationEnd == 0 || r.Number > target.ActivationEnd {
			return nil
		}
		// v3's old fixed-order interpretation remains exact-ID bound. v4 also
		// authenticates the previous header and its ordered signature registry.
		if len(k.Order) > 0 && r.KeyHash != previousEpoch.keyHash {
			return nil
		}
		id, err := hotstuff.SignedStateID(q)
		if err != nil {
			return nil
		}
		for _, allowed := range k.Boundary {
			if protocol.Hash(id.Hash()) == allowed {
				return previousEpoch
			}
		}
		return nil
	}

	var last *types.Header
	for _, w := range headers {
		checked, err := auth.prepareHeader(w)
		if err != nil {
			return fail(err)
		}
		h := checked.header
		if target.Height == math.MaxUint64 || h.Number.Uint64() != target.Height+1 || h.ParentHash != common.Hash(target.BlockHash) {
			return fail(ErrRollingBase)
		}
		if err = auth.authenticateHeaders([]checkedHeader{checked}); err != nil {
			return fail(err)
		}
		if h.BlockType == types.Key_Block {
			if target.ActivationEnd != 0 {
				return fail(fmt.Errorf("%w: overlapping key activation", ErrRollingAuthentication))
			}
			next, nextOrder, err := v.verifyRenewal(parentKey, k.Order, checked)
			if err != nil {
				return fail(err)
			}
			if len(k.Order) == 0 && !bytes.Equal(nextOrder, identityOrder()) {
				return fail(fmt.Errorf("%w: v3 ordered committee changed", ErrRollingAuthentication))
			}
			ids := make([]protocol.Hash, 0, len(checked.desc))
			end := uint64(0)
			for _, q := range checked.desc {
				r, err := types.DecodeHotstuffProposalRef(q.State)
				if err != nil || r.KeyHash != parentKey.Hash() {
					return fail(ErrRollingAuthentication)
				}
				id, err := hotstuff.SignedStateID(q)
				if err != nil {
					return fail(err)
				}
				ids = append(ids, protocol.Hash(id.Hash()))
				end = r.Number
			}
			root, err := BoundaryCommitment(ids)
			if err != nil {
				return fail(err)
			}
			target.Version = 2
			target.SourceKeyHash = protocol.Hash(next.Hash())
			target.SourceCommittee = protocol.Hash(next.CommitteeHash)
			target.ActivationEnd = end
			target.ActivationRoot = root
			if len(k.Order) > 0 {
				k.PreviousKeyHeader = bytes.Clone(k.KeyHeader)
				k.PreviousOrder = bytes.Clone(k.Order)
				k.Order = nextOrder
			}
			previousEpoch = currentEpoch
			currentEpoch, err = v.orderedEpoch(next, k.Order)
			if err != nil {
				return fail(err)
			}
			k.KeyHeader, err = rlp.EncodeToBytes(next)
			if err != nil {
				return fail(err)
			}
			k.Boundary = ids
			parentKey = next
		} else if len(h.KeyInfo) != 0 {
			return fail(ErrRollingAuthentication)
		}
		target.Height = h.Number.Uint64()
		target.BlockHash = protocol.Hash(h.Hash())
		target.StateRoot = protocol.Hash(h.Root)
		if target.ActivationEnd != 0 && target.Height >= target.ActivationEnd {
			target.ActivationEnd = 0
			target.ActivationRoot = protocol.Hash{}
			k.Boundary = nil
			k.PreviousKeyHeader = nil
			k.PreviousOrder = nil
		}
		if err = target.Validate(); err != nil {
			return fail(err)
		}
		last = types.CopyHeader(h)
	}
	if len(headers) == 0 && base.Height == 0 {
		last = types.CopyHeader(v.genesis)
	}
	return last, target, k.Clone(), nil
}
func (v *Verifier) verifyRenewal(parent *types.KeyBlockHeader, order []uint8, h checkedHeader) (*types.KeyBlockHeader, []uint8, error) {
	if len(h.header.KeyInfo) == 0 || len(h.header.KeyInfo) > MaxKeyCarrierBytes {
		return nil, nil, ErrRollingMalformed
	}
	fields, err := splitBounded(h.header.KeyInfo, 7)
	if err != nil || len(fields) != 7 {
		return nil, nil, ErrRollingMalformed
	}
	if _, err = DecodeKeyHeader(fields[0]); err != nil {
		return nil, nil, err
	}
	var block types.KeyBlock
	if err := rlp.DecodeBytes(h.header.KeyInfo, &block); err != nil {
		return nil, nil, ErrRollingMalformed
	}
	encoded, err := rlp.EncodeToBytes(&block)
	if err != nil || !bytes.Equal(encoded, h.header.KeyInfo) {
		return nil, nil, ErrRollingMalformed
	}
	next := block.Header()
	raw, err := rlp.EncodeToBytes(next)
	if err != nil {
		return nil, nil, err
	}
	if _, err = DecodeKeyHeader(raw); err != nil {
		return nil, nil, err
	}
	ref, err := types.DecodeHotstuffProposalRef(h.target.State)
	if err != nil {
		return nil, nil, err
	}
	if ref.KeyHash != parent.Hash() || next.ParentHash != parent.Hash() || parent.Number.Uint64() == math.MaxUint64 || next.Number.Uint64() != parent.Number.Uint64()+1 || ref.Number == 0 || next.T_Number != ref.Number-1 {
		return nil, nil, fmt.Errorf("%w: key parent/number/committee", ErrRollingAuthentication)
	}
	if (next.BlockType != types.TimeReconfig && next.BlockType != types.PaceReconfig) || block.OutPubKey() != "" || block.OutAddress(0) != "" || next.Nonce != (types.BlockNonce{}) || next.MixDigest != (common.Hash{}) || next.Difficulty.Cmp(parent.Difficulty) != 0 {
		return nil, nil, fmt.Errorf("%w: unsupported key generation/candidate", ErrRollingAuthentication)
	}
	interval := uint64(params.KeyBlockMinInterval / time.Second)
	if parent.Time > math.MaxUint64-interval || ((parent.Number.Sign() != 0 || parent.Time != 0) && next.Time != parent.Time+interval) || next.Time < parent.Time+interval {
		return nil, nil, fmt.Errorf("%w: key cadence", ErrRollingAuthentication)
	}
	leader, err := LeaderIndex(v.seed, v.chainID, ref.ViewNumber, parent.CommitteeHash)
	if err != nil {
		return nil, nil, err
	}
	if len(order) == 0 {
		order = identityOrder()
	}
	committee := &bftview.Committee{}
	for _, index := range order {
		member := *v.members[index]
		committee.List = append(committee.List, &member)
	}
	committee.Add(nil, int(leader), "")
	if committee.RlpHash() != next.CommitteeHash || block.LeaderPubKey() != committee.Leader().Public || block.LeaderAddress() != committee.Leader().CoinBase || block.InPubKey() != committee.In().Public || block.InAddress() != committee.In().CoinBase {
		return nil, nil, fmt.Errorf("%w: changed ordered committee", ErrRollingAuthentication)
	}
	nextOrder := make([]uint8, 7)
	for i, m := range committee.List {
		found := false
		for index, registered := range v.members {
			if *m == *registered {
				nextOrder[i] = uint8(index)
				found = true
				break
			}
		}
		if !found {
			return nil, nil, ErrRollingAuthentication
		}
	}
	// An absent order denotes the immutable v3 fixed-order wire interpretation.
	// Do not silently reinterpret an old v3 payload as the permutation extension.
	return types.CopyKeyBlockHeader(next), nextOrder, nil
}

// payloadEpochs performs only immutable signature-registry selection at ingress.
// Its key preimages are untrusted and confer no continuity/custody capability.
// VerifyRolling later authenticates every key activation from parent state.
func (v *Verifier) payloadEpochs(e RollingEvidence) (func(*types.HotstuffProposalRef, *hotstuff.SignedState) *epoch, error) {
	if len(e.Order) == 0 {
		return func(*types.HotstuffProposalRef, *hotstuff.SignedState) *epoch { return &v.epochs[0] }, nil
	}
	headers := map[common.Hash]*types.KeyBlockHeader{}
	orders := map[common.Hash][]uint8{}
	epochs := map[common.Hash]*epoch{}
	add := func(raw []byte, order []uint8) error {
		h, err := DecodeKeyHeader(raw)
		if err != nil {
			return err
		}
		ep, err := v.orderedEpoch(h, order)
		if err != nil {
			return err
		}
		headers[h.Hash()] = h
		orders[h.Hash()] = bytes.Clone(order)
		epochs[h.Hash()] = ep
		return nil
	}
	if err := add(e.KeyHeader, e.Order); err != nil {
		return nil, err
	}
	if len(e.PreviousKeyHeader) > 0 {
		if err := add(e.PreviousKeyHeader, e.PreviousOrder); err != nil {
			return nil, err
		}
	}
	for _, w := range e.Headers {
		var h types.Header
		if err := rlp.DecodeBytes(w.Header, &h); err != nil {
			return nil, err
		}
		if h.BlockType != types.Key_Block {
			continue
		}
		ref, err := types.DecodeHotstuffProposalRef(w.ProposalRef)
		if err != nil {
			return nil, err
		}
		parent := headers[ref.KeyHash]
		if parent == nil {
			return nil, ErrRollingBase
		}
		q := &hotstuff.SignedState{State: w.ProposalRef, Sign: h.SignInfo.Signature, Mask: h.SignInfo.Exceptions, ViewID: h.SignInfo.ViewID, LeaderID: h.SignInfo.LeaderID, Number: h.SignInfo.ViewNumber}
		next, order, err := v.verifyRenewal(parent, orders[ref.KeyHash], checkedHeader{header: &h, target: q})
		if err != nil {
			return nil, err
		}
		raw, err := rlp.EncodeToBytes(next)
		if err != nil {
			return nil, err
		}
		if err = add(raw, order); err != nil {
			return nil, err
		}
	}
	return func(ref *types.HotstuffProposalRef, _ *hotstuff.SignedState) *epoch { return epochs[ref.KeyHash] }, nil
}
