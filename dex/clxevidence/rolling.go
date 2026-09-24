package clxevidence

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const AnchorSize = 246
const AnchorV2Size = 286
const MaxHeaderWitnessBytes = 20 * 1024

var (
	ErrRollingMalformed      = errors.New("malformed rolling CLX evidence")
	ErrRollingBase           = errors.New("rolling CLX trusted base mismatch")
	ErrRollingAuthentication = errors.New("rolling CLX authentication failed")
	ErrRollingUnavailable    = errors.New("rolling CLX historical data unavailable")
)

// Anchor is a canonical state record, not a capability. A verifier's base must
// come from authenticated parent state, never from a request-supplied record.
type Anchor struct {
	Version                                              uint16
	ChainID                                              uint64
	Genesis, DEXID                                       protocol.Hash
	Custody                                              [20]byte
	Height                                               uint64
	BlockHash, StateRoot, SourceKeyHash, SourceCommittee protocol.Hash
	SourceEpoch, InboxCount                              uint64
	ActivationEnd                                        uint64        `json:",omitempty"`
	ActivationRoot                                       protocol.Hash `json:"-"`
}

func (a Anchor) Validate() error {
	if (a.Version != 1 && a.Version != 2) || a.ChainID == 0 || a.Genesis == (protocol.Hash{}) || a.DEXID == (protocol.Hash{}) || a.Custody == ([20]byte{}) || a.BlockHash == (protocol.Hash{}) || a.StateRoot == (protocol.Hash{}) || a.SourceKeyHash == (protocol.Hash{}) || a.SourceCommittee == (protocol.Hash{}) || a.SourceEpoch != 1 || a.InboxCount > protocol.MaxInboxEntries || (a.Height == 0 && (a.BlockHash != a.Genesis || a.InboxCount != 0)) {
		return fmt.Errorf("%w: anchor fields", ErrRollingMalformed)
	}
	if a.Version == 1 && (a.ActivationEnd != 0 || a.ActivationRoot != (protocol.Hash{})) {
		return ErrRollingMalformed
	}
	if (a.ActivationRoot == (protocol.Hash{})) != (a.ActivationEnd == 0) || (a.ActivationEnd != 0 && (a.ActivationEnd <= a.Height || a.ActivationEnd-a.Height > MaxDescendants)) {
		return ErrRollingMalformed
	}
	return nil
}

// Explicit version-aware JSON preserves legacy FinancialState5 JSON/root bytes.
func (a Anchor) MarshalJSON() ([]byte, error) {
	type alias Anchor
	if a.Version == 1 {
		return json.Marshal(alias(a))
	}
	return json.Marshal(struct {
		alias
		ActivationRoot protocol.Hash
	}{alias(a), a.ActivationRoot})
}
func (a *Anchor) UnmarshalJSON(raw []byte) error {
	type alias Anchor
	var w struct {
		alias
		ActivationRoot protocol.Hash
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&w); err != nil {
		return err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return ErrRollingMalformed
	}
	if w.Version == 1 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		if _, ok := fields["ActivationRoot"]; ok {
			return ErrRollingMalformed
		}
		if _, ok := fields["ActivationEnd"]; ok {
			return ErrRollingMalformed
		}
	}
	*a = Anchor(w.alias)
	a.ActivationRoot = w.ActivationRoot
	return nil
}
func (a Anchor) Encode() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	size := AnchorSize
	if a.Version == 2 {
		size = AnchorV2Size
	}
	b := make([]byte, size)
	off := 0
	put := func(v []byte) { copy(b[off:], v); off += len(v) }
	u64 := func(v uint64) { binary.BigEndian.PutUint64(b[off:], v); off += 8 }
	binary.BigEndian.PutUint16(b, a.Version)
	off = 2
	u64(a.ChainID)
	put(a.Genesis[:])
	put(a.DEXID[:])
	put(a.Custody[:])
	u64(a.Height)
	put(a.BlockHash[:])
	put(a.StateRoot[:])
	put(a.SourceKeyHash[:])
	put(a.SourceCommittee[:])
	u64(a.SourceEpoch)
	u64(a.InboxCount)
	if a.Version == 2 {
		u64(a.ActivationEnd)
		put(a.ActivationRoot[:])
	}
	return b, nil
}
func DecodeAnchor(raw []byte) (Anchor, error) {
	var a Anchor
	if len(raw) < 2 || (binary.BigEndian.Uint16(raw) == 1 && len(raw) != AnchorSize) || (binary.BigEndian.Uint16(raw) == 2 && len(raw) != AnchorV2Size) || (binary.BigEndian.Uint16(raw) != 1 && binary.BigEndian.Uint16(raw) != 2) {
		return a, fmt.Errorf("%w: anchor length", ErrRollingMalformed)
	}
	off := 2
	get := func(v []byte) { copy(v, raw[off:]); off += len(v) }
	u64 := func() uint64 { x := binary.BigEndian.Uint64(raw[off:]); off += 8; return x }
	a.Version = binary.BigEndian.Uint16(raw)
	a.ChainID = u64()
	get(a.Genesis[:])
	get(a.DEXID[:])
	get(a.Custody[:])
	a.Height = u64()
	get(a.BlockHash[:])
	get(a.StateRoot[:])
	get(a.SourceKeyHash[:])
	get(a.SourceCommittee[:])
	a.SourceEpoch = u64()
	a.InboxCount = u64()
	if a.Version == 2 {
		a.ActivationEnd = u64()
		get(a.ActivationRoot[:])
	}
	if err := a.Validate(); err != nil {
		return Anchor{}, err
	}
	return a, nil
}
func (a Anchor) ID() (protocol.Hash, error) {
	b, err := a.Encode()
	if err != nil {
		return protocol.Hash{}, err
	}
	domain := "common-dex/clx-anchor/v1"
	if a.Version == 2 {
		domain = "common-dex/clx-anchor/v2"
	}
	return protocol.Digest(domain, b), nil
}

// BootstrapAnchor uses the immutable genesis and source registry already
// authenticated by New. Rolling v2 supports only the static epoch1 experiment.
func (v *Verifier) BootstrapAnchor() (Anchor, error) {
	if v == nil || v.genesis == nil || len(v.epochs) != 1 || v.epochs[0].first != 1 {
		return Anchor{}, fmt.Errorf("%w: static source epoch required", ErrRollingBase)
	}
	a := Anchor{Version: 1, ChainID: v.chainID, Genesis: protocol.Hash(v.genesis.Hash()), DEXID: v.dex, Custody: [20]byte(v.custody), BlockHash: protocol.Hash(v.genesis.Hash()), StateRoot: protocol.Hash(v.genesis.Root), SourceKeyHash: protocol.Hash(v.epochs[0].keyHash), SourceCommittee: protocol.Hash(v.epochs[0].committeeHash), SourceEpoch: 1}
	return a, a.Validate()
}
func (v *Verifier) checkBase(base Anchor) error {
	g, err := v.BootstrapAnchor()
	if err != nil {
		return err
	}
	if err := base.Validate(); err != nil {
		return err
	}
	if base.ChainID != g.ChainID || base.Genesis != g.Genesis || base.DEXID != g.DEXID || base.Custody != g.Custody || (base.Version == 1 && base.SourceKeyHash != g.SourceKeyHash) || (base.Version == 1 && base.SourceCommittee != g.SourceCommittee) || base.SourceEpoch != g.SourceEpoch {
		return ErrRollingBase
	}
	if base.Version == 2 && !v.renewalEnabled {
		return ErrRollingBase
	}
	if base.Height == 0 && base != g {
		return ErrRollingBase
	}
	if base.Height > 0 && (base.Height < v.epochs[0].first || base.Height >= v.epochs[0].end) {
		return ErrRollingBase
	}
	return nil
}

type HeaderWitness struct{ Header, ProposalRef []byte }
type RollingEvidence struct {
	Base                     protocol.Hash
	Headers                  []HeaderWitness
	AccountProof, CountProof [][]byte
	Entries                  []EntryProof
	KeyHeader                []byte
	Boundary                 []protocol.Hash
	Order                    []uint8
	PreviousKeyHeader        []byte
	PreviousOrder            []uint8
}
type rollingEnvelope struct {
	Version                  uint16
	Base                     protocol.Hash
	Headers                  []HeaderWitness
	AccountProof, CountProof [][]byte
	Entries                  []evidenceEntry
}

type rollingEnvelopeV3 struct {
	Version                  uint16
	Base                     protocol.Hash
	Headers                  []HeaderWitness
	AccountProof, CountProof [][]byte
	Entries                  []evidenceEntry
	KeyHeader                []byte
	Boundary                 []protocol.Hash
}

type rollingEnvelopeV4 struct {
	Version                  uint16
	Base                     protocol.Hash
	Headers                  []HeaderWitness
	AccountProof, CountProof [][]byte
	Entries                  []evidenceEntry
	KeyHeader                []byte
	Boundary                 []protocol.Hash
	Order                    []uint8
	PreviousKeyHeader        []byte
	PreviousOrder            []uint8
}

func rollingShape(e RollingEvidence) error {
	if len(e.PreviousKeyHeader) > MaxKeyHeaderBytes || (len(e.Order) != 0 && len(e.Order) != 7) || (len(e.PreviousOrder) != 0 && len(e.PreviousOrder) != 7) || (len(e.Order) == 0 && (len(e.PreviousOrder) != 0 || len(e.PreviousKeyHeader) != 0)) || (len(e.Order) != 0 && len(e.KeyHeader) == 0) || len(e.KeyHeader) > MaxKeyHeaderBytes || len(e.Boundary) > MaxDescendants || (len(e.KeyHeader) == 0 && len(e.Boundary) != 0) || e.Base == (protocol.Hash{}) || len(e.Headers) > MaxAncestryBlocks || len(e.Entries) > protocol.MaxDepositsPerCheckpoint {
		return fmt.Errorf("%w: collection bound", ErrRollingMalformed)
	}
	n := len(e.KeyHeader) + len(e.PreviousKeyHeader) + len(e.Order) + len(e.PreviousOrder) + 32*len(e.Boundary)
	for _, w := range e.Headers {
		if len(w.Header) == 0 || len(w.ProposalRef) == 0 || len(w.ProposalRef) > MaxRefBytes || len(w.Header)+len(w.ProposalRef) > MaxHeaderWitnessBytes {
			return fmt.Errorf("%w: witness bytes", ErrRollingMalformed)
		}
		n += len(w.Header) + len(w.ProposalRef)
	}
	paths := [][][]byte{e.AccountProof}
	if len(e.CountProof) > 0 {
		paths = append(paths, e.CountProof)
	}
	for _, p := range e.Entries {
		if err := p.Entry.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrRollingMalformed, err)
		}
		n += protocol.InboxEntrySize
		paths = append(paths, p.Proof)
	}
	for _, p := range paths {
		size, err := proofShape(p)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRollingMalformed, err)
		}
		n += size
		if n > MaxEvidenceBytes {
			return fmt.Errorf("%w: total byte bound", ErrRollingMalformed)
		}
	}
	return nil
}
func EncodeRollingEvidence(e RollingEvidence) ([]byte, error) {
	if err := rollingShape(e); err != nil {
		return nil, err
	}
	w := rollingEnvelope{Version: 2, Base: e.Base, Headers: e.Headers, AccountProof: e.AccountProof, CountProof: e.CountProof}
	for _, p := range e.Entries {
		b, err := p.Entry.Encode()
		if err != nil {
			return nil, err
		}
		w.Entries = append(w.Entries, evidenceEntry{b, p.Proof})
	}
	var raw []byte
	var err error
	if len(e.Order) > 0 {
		raw, err = rlp.EncodeToBytes(rollingEnvelopeV4{4, w.Base, w.Headers, w.AccountProof, w.CountProof, w.Entries, e.KeyHeader, e.Boundary, e.Order, e.PreviousKeyHeader, e.PreviousOrder})
	} else if len(e.KeyHeader) > 0 {
		raw, err = rlp.EncodeToBytes(rollingEnvelopeV3{3, w.Base, w.Headers, w.AccountProof, w.CountProof, w.Entries, e.KeyHeader, e.Boundary})
	} else {
		raw, err = rlp.EncodeToBytes(w)
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxEvidenceBytes {
		return nil, fmt.Errorf("%w: encoded byte bound", ErrRollingMalformed)
	}
	return raw, nil
}

// splitBounded checks nested RLP collection counts without allocating decoded
// object arrays. Crypto and big allocations happen only after these limits.
func splitBounded(raw []byte, limit int) ([][]byte, error) {
	list, tail, err := rlp.SplitList(raw)
	if err != nil || len(tail) != 0 {
		return nil, fmt.Errorf("%w: RLP list", ErrRollingMalformed)
	}
	out := make([][]byte, 0)
	for len(list) > 0 {
		if len(out) == limit {
			return nil, fmt.Errorf("%w: RLP collection count", ErrRollingMalformed)
		}
		_, _, rest, err := rlp.Split(list)
		if err != nil {
			return nil, err
		}
		out = append(out, list[:len(list)-len(rest)])
		list = rest
	}
	return out, nil
}
func boundedProofRLP(raw []byte) error {
	values, err := splitBounded(raw, MaxProofNodes)
	if err != nil {
		return err
	}
	for _, value := range values {
		b, tail, err := rlp.SplitString(value)
		if err != nil || len(tail) != 0 || len(b) == 0 || len(b) > MaxProofNodeBytes {
			return fmt.Errorf("%w: RLP proof node", ErrRollingMalformed)
		}
	}
	return nil
}
func DecodeRollingEvidence(raw []byte) (RollingEvidence, error) {
	var e RollingEvidence
	if len(raw) == 0 || len(raw) > MaxEvidenceBytes {
		return e, fmt.Errorf("%w: encoded bytes", ErrRollingMalformed)
	}
	fields, err := splitBounded(raw, 11)
	if err != nil || (len(fields) != 6 && len(fields) != 8 && len(fields) != 11) {
		return e, fmt.Errorf("%w: envelope fields", ErrRollingMalformed)
	}
	witnesses, err := splitBounded(fields[2], MaxAncestryBlocks)
	if err != nil {
		return e, err
	}
	for _, w := range witnesses {
		parts, err := splitBounded(w, 2)
		if err != nil || len(parts) != 2 {
			return e, fmt.Errorf("%w: header fields", ErrRollingMalformed)
		}
		n := 0
		for i, p := range parts {
			b, _, err := rlp.SplitString(p)
			if err != nil || len(b) == 0 || (i == 1 && len(b) > MaxRefBytes) {
				return e, fmt.Errorf("%w: header bytes", ErrRollingMalformed)
			}
			n += len(b)
		}
		if n > MaxHeaderWitnessBytes {
			return e, fmt.Errorf("%w: witness bound", ErrRollingMalformed)
		}
	}
	if err = boundedProofRLP(fields[3]); err != nil {
		return e, err
	}
	if err = boundedProofRLP(fields[4]); err != nil {
		return e, err
	}
	entries, err := splitBounded(fields[5], protocol.MaxDepositsPerCheckpoint)
	if err != nil {
		return e, err
	}
	for _, entry := range entries {
		parts, err := splitBounded(entry, 2)
		if err != nil || len(parts) != 2 {
			return e, fmt.Errorf("%w: entry fields", ErrRollingMalformed)
		}
		b, _, err := rlp.SplitString(parts[0])
		if err != nil || len(b) != protocol.InboxEntrySize {
			return e, fmt.Errorf("%w: entry bytes", ErrRollingMalformed)
		}
		if err = boundedProofRLP(parts[1]); err != nil {
			return e, err
		}
	}
	var w rollingEnvelope
	if len(fields) >= 8 {
		key, tail, err := rlp.SplitString(fields[6])
		if err != nil || len(tail) != 0 || len(key) == 0 || len(key) > MaxKeyHeaderBytes {
			return e, ErrRollingMalformed
		}
		ids, err := splitBounded(fields[7], MaxDescendants)
		if err != nil {
			return e, err
		}
		for _, id := range ids {
			b, tail, err := rlp.SplitString(id)
			if err != nil || len(tail) != 0 || len(b) != 32 {
				return e, ErrRollingMalformed
			}
		}
		if len(fields) == 11 {
			for i, max := range []int{7, MaxKeyHeaderBytes, 7} {
				b, tail, err := rlp.SplitString(fields[8+i])
				if err != nil || len(tail) != 0 || len(b) > max {
					return e, ErrRollingMalformed
				}
			}
			var x rollingEnvelopeV4
			if err = rlp.DecodeBytes(raw, &x); err != nil || x.Version != 4 {
				return e, ErrRollingMalformed
			}
			w = rollingEnvelope{2, x.Base, x.Headers, x.AccountProof, x.CountProof, x.Entries}
			e.KeyHeader = x.KeyHeader
			e.Boundary = x.Boundary
			e.Order = x.Order
			e.PreviousKeyHeader = x.PreviousKeyHeader
			e.PreviousOrder = x.PreviousOrder
		} else {
			var x rollingEnvelopeV3
			if err = rlp.DecodeBytes(raw, &x); err != nil || x.Version != 3 {
				return e, ErrRollingMalformed
			}
			w = rollingEnvelope{2, x.Base, x.Headers, x.AccountProof, x.CountProof, x.Entries}
			e.KeyHeader = x.KeyHeader
			e.Boundary = x.Boundary
		}
	} else {
		if err = rlp.DecodeBytes(raw, &w); err != nil || w.Version != 2 {
			return e, ErrRollingMalformed
		}
	}
	e.Base, e.Headers, e.AccountProof, e.CountProof = w.Base, w.Headers, w.AccountProof, w.CountProof
	for _, p := range w.Entries {
		entry, err := protocol.DecodeInboxEntry(p.Entry)
		if err != nil {
			return RollingEvidence{}, fmt.Errorf("%w: %v", ErrRollingMalformed, err)
		}
		e.Entries = append(e.Entries, EntryProof{entry, p.Proof})
	}
	encoded, err := EncodeRollingEvidence(e)
	if err != nil {
		return RollingEvidence{}, err
	}
	if !bytes.Equal(encoded, raw) {
		return RollingEvidence{}, fmt.Errorf("%w: noncanonical RLP", ErrRollingMalformed)
	}
	return e, nil
}

// BuildHeaderWitness is an untrusted transport builder. It derives the exact
// signed ref from the full source block, then transmits only header+ref.
func BuildHeaderWitness(chainID uint64, b *types.Block) (HeaderWitness, error) {
	if b == nil || b.Header0() == nil {
		return HeaderWitness{}, ErrRollingUnavailable
	}
	if err := b.SanityCheck(); err != nil {
		return HeaderWitness{}, err
	}
	si := b.SignInfo()
	if len(si.FHSFinalityProof) == 0 || len(si.Signature) == 0 {
		return HeaderWitness{}, fmt.Errorf("%w: block is not finalized", ErrRollingUnavailable)
	}
	if len(si.FHSFinalityProof) > MaxFinalityBytes || len(si.Signature) > 128 || len(si.LeaderID) > 128 || b.Size() > MaxBlockBytes {
		return HeaderWitness{}, fmt.Errorf("%w: source block/QC/finality bound", ErrRollingMalformed)
	}
	ref, err := types.NewHotstuffProposalRefFromUnsignedBlockWithCommitments(chainID, si.ViewNumber, si.ViewID, si.LeaderID, b, si.ExtraHash, si.ParentQCID)
	if err != nil {
		return HeaderWitness{}, err
	}
	h, err := rlp.EncodeToBytes(b.Header())
	if err != nil {
		return HeaderWitness{}, err
	}
	w := HeaderWitness{h, ref.EncodeToBytes()}
	if len(w.Header)+len(w.ProposalRef) > MaxHeaderWitnessBytes || len(w.ProposalRef) > MaxRefBytes {
		return HeaderWitness{}, fmt.Errorf("%w: witness byte bound", ErrRollingMalformed)
	}
	return w, nil
}

type checkedHeader struct {
	header *types.Header
	target *hotstuff.SignedState
	desc   []*hotstuff.SignedState
}

func (v *Verifier) prepareHeader(w HeaderWitness) (checkedHeader, error) {
	var out checkedHeader
	if len(w.Header) == 0 || len(w.ProposalRef) == 0 || len(w.ProposalRef) > MaxRefBytes || len(w.Header)+len(w.ProposalRef) > MaxHeaderWitnessBytes {
		return out, ErrRollingMalformed
	}
	var h types.Header
	if err := rlp.DecodeBytes(w.Header, &h); err != nil {
		return out, fmt.Errorf("%w: header RLP", ErrRollingMalformed)
	}
	canonical, err := rlp.EncodeToBytes(&h)
	if err != nil || !bytes.Equal(canonical, w.Header) || h.Number == nil || !h.Number.IsUint64() || h.Number.Sign() == 0 {
		return out, fmt.Errorf("%w: header canonicality/height", ErrRollingMalformed)
	}
	if err = h.SanityCheck(); err != nil {
		return out, fmt.Errorf("%w: %v", ErrRollingMalformed, err)
	}
	r, err := types.DecodeHotstuffProposalRef(w.ProposalRef)
	if err != nil || !bytes.Equal(r.EncodeToBytes(), w.ProposalRef) || r.BodySize > MaxBlockBytes {
		return out, fmt.Errorf("%w: proposal ref", ErrRollingMalformed)
	}
	si := h.SignInfo
	if r.ChainID != v.chainID || r.Number != h.Number.Uint64() || r.BlockHash != h.Hash() || r.ParentHash != h.ParentHash || r.StateRoot != h.Root || r.TxHash != h.TxHash || r.ReceiptHash != h.ReceiptHash || r.CommonTxAdmissionRoot != h.CommonTxAdmissionRoot || r.CommonTxRewardRoot != h.CommonTxRewardRoot || r.BlockType != h.BlockType || r.KeyHash != h.KeyHash || r.Time != h.Time || r.GasLimit != h.GasLimit || r.GasUsed != h.GasUsed || r.ViewNumber != si.ViewNumber || r.ViewID != si.ViewID || r.LeaderID != si.LeaderID || r.ExtraHash != si.ExtraHash || r.ParentQCID != si.ParentQCID {
		return out, fmt.Errorf("%w: header/ref/SignInfo mismatch", ErrRollingAuthentication)
	}
	if len(si.FHSFinalityProof) == 0 || len(si.FHSFinalityProof) > MaxFinalityBytes {
		return out, fmt.Errorf("%w: finality bytes", ErrRollingMalformed)
	}
	q := &hotstuff.SignedState{State: bytes.Clone(w.ProposalRef), Sign: bytes.Clone(si.Signature), Mask: bytes.Clone(si.Exceptions), ViewID: si.ViewID, LeaderID: si.LeaderID, Number: si.ViewNumber}
	if _, _, err = v.qcShape(q); err != nil {
		return out, fmt.Errorf("%w: %v", ErrRollingAuthentication, err)
	}
	var proof finalityEnvelope
	if err = rlp.DecodeBytes(si.FHSFinalityProof, &proof); err != nil || proof.Version != 2 || len(proof.QCs) == 0 || len(proof.QCs) > MaxDescendants {
		return out, fmt.Errorf("%w: finality shape", ErrRollingMalformed)
	}
	parent, pc := r, q
	for i, raw := range proof.QCs {
		if len(raw) > MaxRefBytes+512 {
			return out, fmt.Errorf("%w: descendant bytes", ErrRollingMalformed)
		}
		child, err := hotstuff.DecodeSignedState(raw)
		if err != nil {
			return out, fmt.Errorf("%w: descendant codec", ErrRollingMalformed)
		}
		cr, _, err := v.qcShape(child)
		if err != nil {
			return out, fmt.Errorf("%w: %v", ErrRollingAuthentication, err)
		}
		if cr.BodySize > MaxBlockBytes {
			return out, fmt.Errorf("%w: descendant body size", ErrRollingMalformed)
		}
		id, err := hotstuff.SignedStateID(pc)
		if err != nil {
			return out, err
		}
		if parent.Number == math.MaxUint64 || cr.Number != parent.Number+1 || cr.ParentHash != parent.BlockHash || cr.ViewNumber <= parent.ViewNumber || cr.ParentQCID != id.Hash() || (i == len(proof.QCs)-1 && cr.ViewNumber-parent.ViewNumber != 1) {
			return out, fmt.Errorf("%w: descendant parent/finality edge", ErrRollingAuthentication)
		}
		out.desc = append(out.desc, child)
		parent, pc = cr, child
	}
	out.header, out.target = &h, q
	return out, nil
}
func (v *Verifier) checkHeaders(headers []HeaderWitness) ([]checkedHeader, error) {
	if v == nil || len(headers) > MaxAncestryBlocks {
		return nil, ErrRollingMalformed
	}
	checked := make([]checkedHeader, len(headers))
	for i, w := range headers {
		h, err := v.prepareHeader(w)
		if err != nil {
			return nil, err
		}
		if i > 0 && (checked[i-1].header.Number.Uint64() == math.MaxUint64 || h.header.Number.Uint64() != checked[i-1].header.Number.Uint64()+1 || h.header.ParentHash != checked[i-1].header.Hash()) {
			return nil, fmt.Errorf("%w: noncontiguous headers", ErrRollingAuthentication)
		}
		checked[i] = h
	}
	return checked, nil
}
func (v *Verifier) authenticateHeaders(checked []checkedHeader) error {
	for _, h := range checked {
		if err := v.verifyQC(h.target); err != nil {
			return fmt.Errorf("%w: %v", ErrRollingAuthentication, err)
		}
		for _, q := range h.desc {
			if err := v.verifyQC(q); err != nil {
				return fmt.Errorf("%w: %v", ErrRollingAuthentication, err)
			}
		}
	}
	return nil
}

// VerifyHeaderWitnesses proves finality/continuity after a caller-authenticated
// base. It does not authenticate custody storage or inbox count. Zero witnesses
// return nil for a non-genesis base: an Anchor cannot recreate a complete Header.
func (v *Verifier) VerifyHeaderWitnesses(base Anchor, headers []HeaderWitness) (*types.Header, error) {
	if base.Version == 2 && len(headers) > 0 {
		return nil, fmt.Errorf("%w: version2 key context required", ErrRollingBase)
	}
	if err := v.checkBase(base); err != nil {
		return nil, err
	}
	checked, err := v.checkHeaders(headers)
	if err != nil {
		return nil, err
	}
	if len(checked) == 0 {
		if base.Height == 0 {
			return types.CopyHeader(v.genesis), nil
		}
		return nil, nil
	}
	if base.Height == math.MaxUint64 || checked[0].header.Number.Uint64() != base.Height+1 || checked[0].header.ParentHash != common.Hash(base.BlockHash) {
		return nil, ErrRollingBase
	}
	if err = v.authenticateHeaders(checked); err != nil {
		return nil, err
	}
	return types.CopyHeader(checked[len(checked)-1].header), nil
}
func (v *Verifier) rollingEntries(start uint64, entries []EntryProof) error {
	if start > protocol.MaxInboxEntries || uint64(len(entries)) > protocol.MaxInboxEntries-start {
		return fmt.Errorf("%w: inbox range", ErrRollingMalformed)
	}
	for i, p := range entries {
		e := p.Entry
		if e.Index != start+uint64(i) || e.ChainID != v.chainID || e.Genesis != protocol.Hash(v.genesis.Hash()) || e.DEXID != v.dex || e.Custody != [20]byte(v.custody) {
			return fmt.Errorf("%w: entry domain/cursor", ErrRollingAuthentication)
		}
	}
	return nil
}

// VerifyRolling advances only a trusted parent anchor. It returns neither a
// credit capability nor a new anchor on any error. Header() may be nil for an
// authenticated same-anchor range; use the returned Anchor's height/hash/root.
func (v *Verifier) VerifyRolling(base Anchor, start uint64, e RollingEvidence) (*VerifiedRange, Anchor, error) {
	if err := v.checkBase(base); err != nil {
		return nil, Anchor{}, err
	}
	if err := rollingShape(e); err != nil {
		return nil, Anchor{}, err
	}
	id, err := base.ID()
	if err != nil || e.Base != id {
		return nil, Anchor{}, ErrRollingBase
	}
	if err = v.rollingEntries(start, e.Entries); err != nil {
		return nil, Anchor{}, err
	}
	header, target, keyContext, err := v.VerifyHeaderContext(base, e.KeyContext(), e.Headers)
	if err != nil {
		return nil, Anchor{}, err
	}
	verified, err := v.verifyRangeAtRoot(header, common.Hash(target.StateRoot), start, RangeEvidence{AccountProof: e.AccountProof, CountProof: e.CountProof, Entries: e.Entries})
	if err != nil {
		return nil, Anchor{}, fmt.Errorf("%w: %v", ErrRollingAuthentication, err)
	}
	if verified.count < base.InboxCount || (len(e.Headers) == 0 && verified.count != base.InboxCount) {
		return nil, Anchor{}, fmt.Errorf("%w: inbox count regression/conflict", ErrRollingAuthentication)
	}
	target.InboxCount = verified.count
	if err = target.Validate(); err != nil {
		return nil, Anchor{}, err
	}
	owned := target
	verified.anchor = &owned
	verified.keyContext = keyContext.Clone()
	return verified, target, nil
}

// VerifyRollingPayload is partial ingress authentication, not continuity or
// credit authorization. Nonempty witnesses authenticate their signatures and
// target MPT paths without trusting the supplied Base identifier. Zero-header
// payloads receive shape checks only; execution must call VerifyRolling using
// its authenticated parent anchor. No VerifiedRange capability is returned.
func (v *Verifier) VerifyRollingPayload(e RollingEvidence) error {
	if v == nil {
		return ErrRollingMalformed
	}
	if _, err := v.BootstrapAnchor(); err != nil {
		return err
	}
	if err := rollingShape(e); err != nil {
		return err
	}
	start := uint64(0)
	if len(e.Entries) > 0 {
		start = e.Entries[0].Entry.Index
	}
	if err := v.rollingEntries(start, e.Entries); err != nil {
		return err
	}
	if len(e.Headers) == 0 {
		return nil
	}
	auth := v
	if len(e.KeyHeader) > 0 {
		if !v.renewalEnabled {
			return ErrRollingBase
		}
		copy := *v
		selector, err := v.payloadEpochs(e)
		if err != nil {
			return err
		}
		copy.qcEpoch = selector
		auth = &copy
	}
	checked, err := auth.checkHeaders(e.Headers)
	if err != nil {
		return err
	}
	if err = auth.authenticateHeaders(checked); err != nil {
		return err
	}
	h := checked[len(checked)-1].header
	_, err = v.verifyRangeAtRoot(h, h.Root, start, RangeEvidence{AccountProof: e.AccountProof, CountProof: e.CountProof, Entries: e.Entries})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRollingAuthentication, err)
	}
	return nil
}

// BuildRollingEvidence only obtains/copies transport data; it confers no trust.
func BuildRollingEvidence(base protocol.Hash, headers []HeaderWitness, source ProofSource, entries []protocol.InboxEntry, custody ...common.Address) (RollingEvidence, error) {
	var e RollingEvidence
	if source == nil || len(custody) > 1 || len(entries) > protocol.MaxDepositsPerCheckpoint || len(headers) > MaxAncestryBlocks {
		return e, ErrRollingMalformed
	}
	var address common.Address
	if len(entries) > 0 {
		address = common.Address(entries[0].Custody)
	}
	if len(custody) == 1 {
		if address != (common.Address{}) && address != custody[0] {
			return e, ErrRollingMalformed
		}
		address = custody[0]
	}
	if address == (common.Address{}) {
		return e, ErrRollingMalformed
	}
	e.Base = base
	for _, w := range headers {
		e.Headers = append(e.Headers, HeaderWitness{bytes.Clone(w.Header), bytes.Clone(w.ProposalRef)})
	}
	var err error
	e.AccountProof, err = source.GetProof(address)
	if err != nil {
		return RollingEvidence{}, fmt.Errorf("%w: %v", ErrRollingUnavailable, err)
	}
	e.AccountProof = copyNodes(e.AccountProof)
	e.CountProof, err = source.GetStorageProof(address, common.Hash(protocol.InboxCountStorageKey()))
	if err != nil {
		return RollingEvidence{}, fmt.Errorf("%w: %v", ErrRollingUnavailable, err)
	}
	e.CountProof = copyNodes(e.CountProof)
	for _, entry := range entries {
		p, err := source.GetStorageProof(address, common.Hash(protocol.InboxEntryStorageKey(entry.Index)))
		if err != nil {
			return RollingEvidence{}, fmt.Errorf("%w: %v", ErrRollingUnavailable, err)
		}
		e.Entries = append(e.Entries, EntryProof{entry, copyNodes(p)})
	}
	if err = rollingShape(e); err != nil {
		return RollingEvidence{}, err
	}
	return e, nil
}
