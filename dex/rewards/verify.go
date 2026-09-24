package rewards

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type Registry struct {
	domain                protocol.Domain
	keys                  [7]*bls.PublicKey
	addresses             [7]string
	recipients            [7][20]byte
	epoch                 *checkpoint.Epoch
	nativeRecipientsBound bool
}

// NativeRecipientsBound checks the immutable genesis committee CoinBase binding.
// Legacy fixtures may still register separate recipients.
func (r *Registry) NativeRecipientsBound() bool { return r != nil && r.nativeRecipientsBound }
func (r *Registry) Domain() protocol.Domain     { return r.domain }

// Commitment additionally binds the authenticated reward-address registry and
// exact ordered voter endpoints, which the legacy committee hash alone omits.
func (r *Registry) Commitment() protocol.Hash {
	return registryCommitment(r.domain, r.epoch.RegistryCommitment(), r.recipients)
}

func registryCommitment(domain protocol.Domain, epoch protocol.Hash, recipients [7][20]byte) protocol.Hash {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, domain)
	b.Write(epoch[:])
	for _, recipient := range recipients {
		b.Write(recipient[:])
	}
	return protocol.Digest("common-dex/participation-registry/v1", b.Bytes())
}

func NewRegistry(domain protocol.Domain, members []*common.Cnode, recipients [][20]byte) (*Registry, error) {
	if len(recipients) != 7 {
		return nil, errors.New("seven reward recipients required")
	}
	epoch, err := checkpoint.NewEpoch(domain, 1, math.MaxUint64, members)
	if err != nil {
		return nil, err
	}
	r := &Registry{domain: domain, epoch: epoch, nativeRecipientsBound: true}
	for i, m := range members {
		if recipients[i] == ([20]byte{}) {
			return nil, errors.New("empty reward recipient")
		}
		key := new(bls.PublicKey)
		if err := key.DeserializeHexStr(m.Public); err != nil {
			return nil, err
		}
		r.keys[i], r.addresses[i], r.recipients[i] = key, m.Address, recipients[i]
		if !common.IsHexAddress(m.CoinBase) || common.HexToAddress(m.CoinBase) != common.Address(recipients[i]) {
			r.nativeRecipientsBound = false
		}
	}
	return r, nil
}

func (r *Registry) ref(data []byte) (*types.HotstuffProposalRef, error) {
	if len(data) == 0 || len(data) > checkpoint.MaxRefBytes {
		return nil, errors.New("participation proposal bound")
	}
	ref, err := types.DecodeHotstuffProposalRef(data)
	if err != nil {
		return nil, err
	}
	if ref.ChainID != r.domain.ChainID || ref.KeyHash != common.Hash(r.domain.EpochKey()) || ref.Number == 0 || ref.Number > math.MaxUint64-GraceBlocks || ref.ViewNumber == 0 || ref.LeaderID != r.addresses[(ref.ViewNumber-1)%7] {
		return nil, errors.New("participation proposal domain/view mismatch")
	}
	return ref, nil
}

func (r *Registry) verifyVote(data []byte, vote *hotstuff.HotstuffMessage) (Duty, error) {
	var duty Duty
	ref, err := r.ref(data)
	if err != nil {
		return duty, err
	}
	if vote == nil || vote.Code != hotstuff.MsgVotePrepare || vote.Number != ref.ViewNumber || vote.ViewId != ref.ViewID || len(vote.PubKey) != 64 || len(vote.DataC) != 32 || len(vote.Id) > 128 || len(vote.AuthSig) > 128 || len(vote.DataA)+len(vote.DataB)+len(vote.DataD)+len(vote.DataE)+len(vote.DataF)+len(vote.DataG) != 0 {
		return duty, errors.New("invalid bounded participation prepare vote")
	}
	participant := -1
	for i, key := range r.keys {
		if vote.Id == r.addresses[i] && bytes.Equal(vote.PubKey, key.Serialize()) {
			participant = i
			break
		}
	}
	if participant < 0 {
		return duty, errors.New("unregistered participation voter")
	}
	if !hotstuff.VerifyFHSSignatureWithContext(vote.DataC, []byte{1 << uint(participant)}, data, r.keys[:], 1, r.domain.ChainID, hotstuff.MsgVotePrepare, ref.ViewID, ref.LeaderID) {
		return duty, errors.New("invalid participation prepare signature")
	}
	duty = Duty{Version: 1, Domain: r.domain, Period: (ref.Number-1)/PeriodBlocks + 1, Height: ref.Number, View: ref.ViewNumber, ProposalID: protocol.Hash(ref.ProposalID()), Participant: uint8(participant), Recipient: r.recipients[participant]}
	return duty, duty.Validate()
}

func (r *Registry) VerifyReceipt(receipt Receipt) error {
	if _, err := receipt.Encode(); err != nil {
		return err
	}
	d := receipt.Duty
	if d.Domain != r.domain || d.Recipient != r.recipients[d.Participant] {
		return errors.New("participation receipt registry mismatch")
	}
	digest, err := receiptDigest(d, receipt.Collector, r.keys[receipt.Collector].Serialize())
	if err != nil {
		return err
	}
	var signature bls.Sign
	if err := signature.Deserialize(receipt.Signature[:]); err != nil {
		return err
	}
	if !signature.VerifyHash(r.keys[receipt.Collector], digest[:]) {
		return errors.New("invalid collector receipt signature")
	}
	return nil
}

func (r *Registry) VerifyCertificate(c Certificate) error {
	if _, err := c.Encode(); err != nil {
		return err
	}
	if c.Duty.Domain != r.domain || c.Duty.Recipient != r.recipients[c.Duty.Participant] {
		return errors.New("participation certificate registry mismatch")
	}
	for _, s := range c.Signatures {
		if err := r.VerifyReceipt(Receipt{c.Duty, s.Collector, s.Signature}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) Certificate(receipts []Receipt) (Certificate, error) {
	if len(receipts) < 5 || len(receipts) > 7 {
		return Certificate{}, errors.New("collector receipt count bound")
	}
	c := Certificate{Duty: receipts[0].Duty}
	seen := make(map[uint8]bool)
	for _, receipt := range receipts {
		if receipt.Duty != c.Duty || seen[receipt.Collector] {
			return Certificate{}, errors.New("mixed or duplicate collector receipt")
		}
		if err := r.VerifyReceipt(receipt); err != nil {
			return Certificate{}, err
		}
		seen[receipt.Collector] = true
		c.Signatures = append(c.Signatures, CollectorSignature{receipt.Collector, receipt.Signature})
	}
	sort.Slice(c.Signatures, func(i, j int) bool { return c.Signatures[i].Collector < c.Signatures[j].Collector })
	return c, nil
}

type FinalizedBlock struct {
	Checkpoint protocol.Checkpoint
	Proof      []byte
}
type canonicalDuty struct {
	proposal protocol.Hash
	view     uint64
}

func (r *Registry) compute(period uint64, blocks []FinalizedBlock, certificates []Certificate) (Points, map[uint64]canonicalDuty, error) {
	points := Points{Domain: r.domain, Period: period}
	for i := range points.Entries {
		points.Entries[i] = Point{Participant: uint8(i), Recipient: r.recipients[i]}
	}
	if period == 0 || period > (math.MaxUint64-GraceBlocks)/PeriodBlocks || len(blocks) != int(PeriodBlocks)+1 || len(certificates) > MaxPeriodCertificates {
		return Points{}, nil, errors.New("period/finality/certificate bounds")
	}
	first, last := (period-1)*PeriodBlocks+1, period*PeriodBlocks
	for i, b := range blocks {
		want := first + uint64(i)
		if i == int(PeriodBlocks) {
			want = last + GraceBlocks
		}
		if b.Checkpoint.Domain() != r.domain || b.Checkpoint.FirstBlock != want || b.Checkpoint.LastBlock != want || len(b.Proof) == 0 || len(b.Proof) > checkpoint.MaxProofBytes {
			return Points{}, nil, errors.New("period close requires exact authenticated block/grace witnesses")
		}
	}
	for _, cert := range certificates {
		if _, err := cert.Encode(); err != nil {
			return Points{}, nil, err
		}
		if cert.Duty.Domain != r.domain || cert.Duty.Period != period {
			return Points{}, nil, errors.New("foreign participation period")
		}
	}
	canonical := make(map[uint64]canonicalDuty, PeriodBlocks)
	for i, b := range blocks {
		if _, err := r.epoch.Verify(b.Checkpoint, b.Proof); err != nil {
			return Points{}, nil, err
		}
		if i > 0 && i < int(PeriodBlocks) {
			previous := blocks[i-1].Checkpoint
			hash, err := previous.Hash()
			if err != nil {
				return Points{}, nil, err
			}
			if b.Checkpoint.Previous != hash || b.Checkpoint.PreRoot != previous.PostRoot {
				return Points{}, nil, errors.New("period witnesses do not connect")
			}
		}
		if i < int(PeriodBlocks) {
			proof, err := checkpoint.DecodeProof(b.Proof)
			if err != nil {
				return Points{}, nil, err
			}
			ref, err := r.ref(proof.Target.State)
			if err != nil {
				return Points{}, nil, err
			}
			canonical[ref.Number] = canonicalDuty{protocol.Hash(ref.ProposalID()), ref.ViewNumber}
		}
	}
	seen := make(map[[2]uint64]bool, MaxPeriodCertificates)
	for _, cert := range certificates {
		if err := r.VerifyCertificate(cert); err != nil {
			return Points{}, nil, err
		}
		target, ok := canonical[cert.Duty.Height]
		if !ok || target.proposal != cert.Duty.ProposalID || target.view != cert.Duty.View {
			return Points{}, nil, errors.New("participation certificate does not match finalized duty")
		}
		slot := [2]uint64{cert.Duty.Height, uint64(cert.Duty.Participant)}
		if !seen[slot] {
			seen[slot] = true
			points.Entries[cert.Duty.Participant].Points++
		}
	}
	return points, canonical, nil
}

// ComputePoints authenticates actual finality and collector signatures; it does
// not enforce certificate inclusion or persist a period close. Consensus close
// actions use CheckCommittedClose against the authenticated parent state.
func (r *Registry) ComputePoints(period uint64, blocks []FinalizedBlock, certificates []Certificate) (Points, error) {
	p, _, err := r.compute(period, blocks, certificates)
	return p, err
}
