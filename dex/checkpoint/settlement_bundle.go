package checkpoint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/dex/protocol"
)

const (
	MaxSettlementBundleBytes = 128 * 1024
	MaxBundleClaims          = 128
	MaxBundlePathDepth       = 7
)

type ClaimPath struct {
	Claim        protocol.Claim
	Index, Count uint32
	Siblings     []protocol.Hash
}

// SettlementBundle contains a complete checkpoint's claim sets, not arbitrary
// individually included leaves. Its bytes are untrusted until Verify succeeds.
type SettlementBundle struct {
	Checkpoint, Proof, Finance []byte
	Withdrawals, Rewards       []ClaimPath
}

type VerifiedSettlementBundle struct{ bundle SettlementBundle }

func (v *VerifiedSettlementBundle) Checkpoint() protocol.Checkpoint {
	c, _ := protocol.DecodeCheckpoint(v.bundle.Checkpoint)
	return c
}
func (v *VerifiedSettlementBundle) Finance() protocol.FinanceSummary {
	f, _ := protocol.DecodeFinanceSummary(v.bundle.Finance)
	return f
}
func (v *VerifiedSettlementBundle) Proof() []byte            { return bytes.Clone(v.bundle.Proof) }
func (v *VerifiedSettlementBundle) Withdrawals() []ClaimPath { return copyPaths(v.bundle.Withdrawals) }
func (v *VerifiedSettlementBundle) Rewards() []ClaimPath     { return copyPaths(v.bundle.Rewards) }
func copyPaths(paths []ClaimPath) []ClaimPath {
	result := append([]ClaimPath(nil), paths...)
	for i := range result {
		result[i].Siblings = append([]protocol.Hash(nil), result[i].Siblings...)
	}
	return result
}

func bundleShape(b SettlementBundle) error {
	if len(b.Checkpoint) != protocol.CheckpointSize || len(b.Finance) != protocol.FinanceSummarySize || len(b.Proof) == 0 || len(b.Proof) > MaxProofBytes || len(b.Withdrawals)+len(b.Rewards) > MaxBundleClaims {
		return errors.New("settlement bundle bounds")
	}
	for _, paths := range [][]ClaimPath{b.Withdrawals, b.Rewards} {
		for _, p := range paths {
			if len(p.Siblings) > MaxBundlePathDepth {
				return errors.New("settlement claim path bounds")
			}
		}
	}
	return nil
}

func bundleBindings(b SettlementBundle) (protocol.Checkpoint, protocol.FinanceSummary, error) {
	var c protocol.Checkpoint
	var f protocol.FinanceSummary
	if err := bundleShape(b); err != nil {
		return c, f, err
	}
	c, err := protocol.DecodeCheckpoint(b.Checkpoint)
	if err != nil {
		return c, f, err
	}
	f, err = protocol.DecodeFinanceSummary(b.Finance)
	if err != nil {
		return c, f, err
	}
	h, err := f.Hash()
	reward := new(big.Int).Add(f.RewardFromFees.Big(), f.RewardFromSupport.Big())
	if err != nil || c.DataSchema < 2 || c.Domain() != f.Domain || c.Sequence != f.Sequence || h != c.FundingRef || f.WithdrawalTotal != c.WithdrawalTotal || f.RewardPeriod != c.RewardPeriod || reward.BitLen() > 128 || reward.Cmp(c.RewardTotal.Big()) != 0 {
		return c, f, errors.New("settlement finance binding")
	}
	for i, paths := range [][]ClaimPath{b.Withdrawals, b.Rewards} {
		root, total, kind, period := c.WithdrawalRoot, c.WithdrawalTotal, protocol.Withdrawal, uint64(0)
		if i == 1 {
			root, total, kind, period = c.RewardRoot, c.RewardTotal, protocol.Reward, c.RewardPeriod
		}
		sum := new(big.Int)
		leaves := make([]protocol.Hash, len(paths))
		for index, p := range paths {
			claim := p.Claim
			if claim.Domain != c.Domain() || claim.Sequence != c.Sequence || claim.Kind != kind || claim.Period != period || p.Index != uint32(index) || p.Count != uint32(len(paths)) || (index > 0 && bytes.Compare(paths[index-1].Claim.ID[:], claim.ID[:]) >= 0) || !claim.Amount.Valid() {
				return c, f, errors.New("settlement claim identity/order/count")
			}
			leaf, err := claim.Hash()
			if err != nil {
				return c, f, err
			}
			if err := protocol.VerifyCountedInclusion(root, leaf, p.Index, p.Count, p.Siblings); err != nil {
				return c, f, err
			}
			leaves[index] = leaf
			sum.Add(sum, claim.Amount.Big())
			if sum.BitLen() > 128 {
				return c, f, errors.New("settlement claim sum overflow")
			}
		}
		fullRoot, _, err := protocol.BuildCountedTree(leaves)
		if err != nil || fullRoot != root || sum.Cmp(total.Big()) != 0 {
			return c, f, errors.New("settlement incomplete claim set or total")
		}
	}
	return c, f, nil
}

func EncodeSettlementBundle(b SettlementBundle) ([]byte, error) {
	if _, _, err := bundleBindings(b); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("CDXB")
	_ = binary.Write(&out, binary.BigEndian, uint16(1))
	out.Write(b.Checkpoint)
	out.Write(b.Finance)
	_ = binary.Write(&out, binary.BigEndian, uint32(len(b.Proof)))
	out.Write(b.Proof)
	_ = binary.Write(&out, binary.BigEndian, uint16(len(b.Withdrawals)))
	_ = binary.Write(&out, binary.BigEndian, uint16(len(b.Rewards)))
	for _, paths := range [][]ClaimPath{b.Withdrawals, b.Rewards} {
		for _, p := range paths {
			raw, _ := p.Claim.Encode()
			out.Write(raw)
			_ = binary.Write(&out, binary.BigEndian, p.Index)
			_ = binary.Write(&out, binary.BigEndian, p.Count)
			out.WriteByte(byte(len(p.Siblings)))
			for _, h := range p.Siblings {
				out.Write(h[:])
			}
		}
	}
	if out.Len() > MaxSettlementBundleBytes {
		return nil, errors.New("settlement bundle byte bound")
	}
	return out.Bytes(), nil
}

func DecodeSettlementBundle(raw []byte) (SettlementBundle, error) {
	var b SettlementBundle
	const fixed = 6 + protocol.CheckpointSize + protocol.FinanceSummarySize
	if len(raw) < fixed+9 || len(raw) > MaxSettlementBundleBytes || !bytes.Equal(raw[:6], []byte{'C', 'D', 'X', 'B', 0, 1}) {
		return b, errors.New("settlement bundle framing")
	}
	b.Checkpoint = bytes.Clone(raw[6 : 6+protocol.CheckpointSize])
	b.Finance = bytes.Clone(raw[6+protocol.CheckpointSize : fixed])
	n := uint64(binary.BigEndian.Uint32(raw[fixed : fixed+4]))
	if n == 0 || n > MaxProofBytes || n > uint64(len(raw)-fixed-8) {
		return SettlementBundle{}, errors.New("settlement proof bound")
	}
	off := fixed + 4 + int(n)
	b.Proof = bytes.Clone(raw[fixed+4 : off])
	counts := []uint16{binary.BigEndian.Uint16(raw[off : off+2]), binary.BigEndian.Uint16(raw[off+2 : off+4])}
	off += 4
	if uint32(counts[0])+uint32(counts[1]) > MaxBundleClaims {
		return SettlementBundle{}, errors.New("settlement claim count")
	}
	sets := []*[]ClaimPath{&b.Withdrawals, &b.Rewards}
	for i, count := range counts {
		for j := uint16(0); j < count; j++ {
			const size = protocol.ClaimSize + 9
			if len(raw)-off < size {
				return SettlementBundle{}, errors.New("truncated settlement claim")
			}
			claim, err := protocol.DecodeClaim(raw[off : off+protocol.ClaimSize])
			if err != nil {
				return SettlementBundle{}, err
			}
			off += protocol.ClaimSize
			p := ClaimPath{Claim: claim, Index: binary.BigEndian.Uint32(raw[off : off+4]), Count: binary.BigEndian.Uint32(raw[off+4 : off+8])}
			depth := int(raw[off+8])
			off += 9
			if depth > MaxBundlePathDepth || len(raw)-off < depth*32 {
				return SettlementBundle{}, errors.New("settlement path byte bound")
			}
			p.Siblings = make([]protocol.Hash, depth)
			for k := range p.Siblings {
				copy(p.Siblings[k][:], raw[off:off+32])
				off += 32
			}
			*sets[i] = append(*sets[i], p)
		}
	}
	if off != len(raw) {
		return SettlementBundle{}, errors.New("trailing settlement bytes")
	}
	if _, _, err := bundleBindings(b); err != nil {
		return SettlementBundle{}, err
	}
	return b, nil
}

func VerifySettlementBundle(epoch *Epoch, b SettlementBundle) (*VerifiedSettlementBundle, error) {
	c, _, err := bundleBindings(b)
	if err != nil {
		return nil, err
	}
	if epoch == nil {
		return nil, errors.New("registered settlement epoch required")
	}
	if _, err = epoch.Verify(c, b.Proof); err != nil {
		return nil, err
	}
	return &VerifiedSettlementBundle{SettlementBundle{bytes.Clone(b.Checkpoint), bytes.Clone(b.Proof), bytes.Clone(b.Finance), copyPaths(b.Withdrawals), copyPaths(b.Rewards)}}, nil
}

// BuildSettlementBundle derives paths from the complete finalized claim sets.
// Verification with a registered Epoch remains mandatory for every consumer.
func BuildSettlementBundle(c protocol.Checkpoint, proof []byte, f protocol.FinanceSummary, withdrawals, rewards []protocol.Claim) (SettlementBundle, error) {
	b := SettlementBundle{Proof: bytes.Clone(proof)}
	var err error
	b.Checkpoint, err = c.Encode()
	if err != nil {
		return b, err
	}
	b.Finance, err = f.Encode()
	if err != nil {
		return b, err
	}
	if len(withdrawals)+len(rewards) > MaxBundleClaims {
		return b, errors.New("settlement claim count")
	}
	sets := []*[]ClaimPath{&b.Withdrawals, &b.Rewards}
	for i, original := range [][]protocol.Claim{withdrawals, rewards} {
		claims := append([]protocol.Claim(nil), original...)
		sort.Slice(claims, func(i, j int) bool { return bytes.Compare(claims[i].ID[:], claims[j].ID[:]) < 0 })
		leaves := make([]protocol.Hash, len(claims))
		for j, c := range claims {
			leaves[j], err = c.Hash()
			if err != nil {
				return b, err
			}
		}
		_, paths, e := protocol.BuildCountedTree(leaves)
		if e != nil {
			return b, e
		}
		for j, c := range claims {
			*sets[i] = append(*sets[i], ClaimPath{c, uint32(j), uint32(len(claims)), paths[j]})
		}
	}
	_, _, err = bundleBindings(b)
	return b, err
}
