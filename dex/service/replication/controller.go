package replication

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

type Config struct {
	Index     uint8
	Peers     []transport.Peer
	Registry  *rewards.Registry
	Collector *rewards.Collector
	Heights   []uint64
	// Continuous selects the authenticated generation-v4 every-height policy.
	// It must not be combined with the finite legacy ReceiptHeights fixture.
	Continuous bool
	MaxHeight  uint64
}
type Controller struct {
	config                   Config
	app                      *consensus.Application
	send                     func(string, uint8, []byte) error
	heights                  map[uint64]bool
	receipts                 map[string]map[uint8]rewards.Receipt
	known                    map[string]uint64
	ticks, peer, certificate uint64
	retirementScan           uint64
	// These cursors are scheduling hints, never authenticated state. Start each
	// peer at our finalized prefix: a certified height alone can hide a missing
	// same-height sibling QC needed by the peer's selected descendant.
	repairAfter   [7]uint64
	repairStarted [7]bool
	Errors        uint64
}

func New(c Config) (*Controller, error) {
	if c.Index >= 7 || len(c.Peers) != 7 || c.Registry == nil || c.Collector == nil || len(c.Heights) > 128 || (c.Continuous && (len(c.Heights) != 0 || c.MaxHeight < 2 || c.MaxHeight > consensus.MaxOperatingHeight)) {
		return nil, errors.New("replication configuration")
	}
	n := &Controller{config: c, heights: map[uint64]bool{}, receipts: map[string]map[uint8]rewards.Receipt{}, known: map[string]uint64{}}
	n.retirementScan = c.Collector.Retirement().Height
	for i, h := range c.Heights {
		if h == 0 || h > 128 || (i > 0 && h <= c.Heights[i-1]) {
			return nil, errors.New("replication receipt height fixture")
		}
		n.heights[h] = true
	}
	certs, err := c.Collector.Certificates(0)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		h, _ := cert.Duty.Hash()
		n.known[fmt.Sprintf("%x", h)] = cert.Duty.Period
	}
	c.Peers = append([]transport.Peer(nil), c.Peers...)
	n.config = c
	return n, nil
}

func (n *Controller) eligible(height uint64) bool {
	if !n.config.Continuous {
		return n.heights[height]
	}
	return height != 0 && height <= n.config.MaxHeight && (height-1)/rewards.PeriodBlocks+1 > n.config.Collector.Retirement().Period
}
func (n *Controller) Bind(a *consensus.Application, send func(string, uint8, []byte) error) error {
	if a == nil || send == nil || n.app != nil {
		return errors.New("replication actor binding")
	}
	n.app, n.send = a, send
	return nil
}
func (n *Controller) broadcast(raw []byte) error {
	var errs []error
	for i, p := range n.config.Peers {
		if i != int(n.config.Index) {
			if e := n.send(p.ID, transport.KindExtension, raw); e != nil {
				errs = append(errs, e)
			}
		}
	}
	return errors.Join(errs...)
}
func (n *Controller) Observe(ref []byte, vote *hotstuff.HotstuffMessage) error {
	decoded, err := types.DecodeHotstuffProposalRef(ref)
	if err != nil {
		return err
	}
	if !n.eligible(decoded.Number) {
		return nil
	}
	raw, err := rlp.EncodeToBytes(vote)
	if err != nil {
		return err
	}
	payload, err := encodeVote(ref, raw)
	if err != nil {
		return err
	}
	// Receipt unavailability must not suppress the ordinary prepared FHS vote.
	if err = n.Receive(n.config.Index, payload); err != nil {
		n.Errors++
	}
	if err = n.broadcast(payload); err != nil {
		n.Errors++
	}
	return nil
}
func (n *Controller) Receive(peer uint8, raw []byte) error {
	if n.app == nil || n.send == nil {
		return transport.ErrBusy
	}
	if peer >= 7 {
		return errors.New("unregistered replication peer")
	}
	kind, b, err := decode(raw)
	if err != nil {
		return err
	}
	switch kind {
	case voteKind:
		ref, encoded, err := decodeVote(b)
		if err != nil {
			return err
		}
		var vote hotstuff.HotstuffMessage
		if err = rlp.DecodeBytes(encoded, &vote); err != nil {
			return err
		}
		key, e := hex.DecodeString(n.config.Peers[peer].BLSPublic)
		if e != nil || vote.Code != hotstuff.MsgVotePrepare || vote.Id != n.config.Peers[peer].ID || !bytes.Equal(vote.PubKey, key) {
			return errors.New("replication vote TLS identity")
		}
		decoded, err := types.DecodeHotstuffProposalRef(ref)
		if err != nil {
			return err
		}
		if !n.eligible(decoded.Number) {
			return errors.New("receipt outside configured devnet duties")
		}
		receipt, err := n.config.Collector.Issue(ref, &vote)
		if errors.Is(err, rewards.ErrUnvalidatedTarget) {
			return transport.ErrBusy
		}
		if err != nil {
			n.Errors++
			return err
		}
		if err = n.addReceipt(receipt); err != nil {
			return err
		}
		b, err = receipt.Encode()
		if err != nil {
			return err
		}
		payload, _ := encode(receiptKind, b)
		return n.broadcast(payload)
	case receiptKind:
		receipt, err := rewards.DecodeReceipt(b)
		if err != nil {
			return err
		}
		return n.addReceipt(receipt)
	case certificateKind:
		cert, err := rewards.DecodeCertificate(b)
		if err != nil {
			return err
		}
		return n.remember(cert)
	case requestKind:
		if len(b) != 8 {
			return errors.New("repair request length")
		}
		after := binary.BigEndian.Uint64(b)
		if after >= n.app.CertifiedHeight() {
			return nil
		}
		// Follow one authenticated selected chain, not independently sorted
		// records at each height. In particular an older-view sibling can be the
		// exact ParentQCID selected by the next block.
		record, err := n.app.SelectedCertifiedData(after + 1)
		if err != nil {
			return err
		}
		payload, err := encode(recordKind, record)
		if err != nil {
			return consensus.ErrUnavailable
		}
		return n.send(n.config.Peers[peer].ID, transport.KindExtension, payload)
	case recordKind:
		if err = n.app.ImportProposalData(b); err != nil {
			if errors.Is(err, consensus.ErrUnavailable) {
				// A peer may switch its unfinalized branch after a request. Do
				// not guess its parent or accept the child: repair from the
				// finalized prefix while the reliable transport retains it.
				n.repairAfter[peer] = n.app.FinalizedHeight()
				n.repairStarted[peer] = true
				if sendErr := n.sendRepair(peer); sendErr != nil {
					return sendErr
				}
				return transport.ErrBusy
			}
			return err
		}
		var accepted struct{ Checkpoint struct{ Sequence uint64 } }
		// ImportProposalData has already checked the full canonical record,
		// signatures, parent state, execution and finality. Read only its height.
		if err = json.Unmarshal(b, &accepted); err != nil {
			return err
		}
		n.repairAfter[peer] = accepted.Checkpoint.Sequence
		n.repairStarted[peer] = true
		return n.sendRepair(peer)
	default:
		return errors.New("replication kind")
	}
}

func (n *Controller) sendRepair(peer uint8) error {
	finalized := n.app.FinalizedHeight()
	if !n.repairStarted[peer] || n.repairAfter[peer] < finalized {
		n.repairAfter[peer] = finalized
		n.repairStarted[peer] = true
	}
	return n.send(n.config.Peers[peer].ID, transport.KindExtension, request(n.repairAfter[peer]))
}
func (n *Controller) addReceipt(r rewards.Receipt) error {
	if !n.eligible(r.Duty.Height) {
		return errors.New("receipt outside configured duties")
	}
	if err := n.config.Registry.VerifyReceipt(r); err != nil {
		return err
	}
	h, _ := r.Duty.Hash()
	key := fmt.Sprintf("%x", h)
	if n.known[key] != 0 {
		return nil
	}
	set := n.receipts[key]
	if set == nil {
		if len(n.receipts) >= 128*7 {
			return errors.New("receipt accumulator bound")
		}
		set = map[uint8]rewards.Receipt{}
		n.receipts[key] = set
	}
	set[r.Collector] = r
	if len(set) < 5 {
		return nil
	}
	var rs []rewards.Receipt
	for _, receipt := range set {
		rs = append(rs, receipt)
	}
	cert, err := n.config.Registry.Certificate(rs)
	if err != nil {
		return err
	}
	if err = n.remember(cert); err != nil {
		return err
	}
	b, _ := cert.Encode()
	raw, _ := encode(certificateKind, b)
	return n.broadcast(raw)
}
func (n *Controller) remember(cert rewards.Certificate) error {
	if !n.eligible(cert.Duty.Height) {
		return errors.New("certificate outside configured duties")
	}
	if err := n.config.Registry.VerifyCertificate(cert); err != nil {
		return err
	}
	h, _ := cert.Duty.Hash()
	key := fmt.Sprintf("%x", h)
	if n.known[key] != 0 {
		return nil
	}
	if err := n.config.Collector.RememberCertificate(cert); err != nil {
		return err
	}
	n.known[key] = cert.Duty.Period
	delete(n.receipts, key)
	return nil
}

// Tick is called on the actor every10ms. It bounds repair work independently of
// balances and does not create a funding/oracle clock or a participation point.
func (n *Controller) Tick(a *consensus.Application) error {
	if n.app != a || n.send == nil {
		return errors.New("replication actor mismatch")
	}
	n.ticks++
	if n.ticks%50 != 0 {
		return nil
	}
	if n.config.Continuous {
		if err := n.retire(); err != nil {
			return err
		}
	}
	peer := n.peer % 7
	n.peer++
	if peer == uint64(n.config.Index) {
		peer = n.peer % 7
		n.peer++
	}
	if err := n.sendRepair(uint8(peer)); err != nil {
		return err
	}
	certs, err := n.config.Collector.Certificates(0)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return nil
	}
	// Six remote peers must all see each retained certificate. Advancing the
	// certificate and peer modulo seven together would repeatedly pair each
	// certificate with only one peer after a restart.
	cert := certs[(n.certificate/6)%uint64(len(certs))]
	n.certificate++
	b, _ := cert.Encode()
	raw, _ := encode(certificateKind, b)
	return n.send(n.config.Peers[peer].ID, transport.KindExtension, raw)
}

// Retirement is bounded background retention work over already authenticated
// finalized checkpoints. Missing archive data does not authorize a jump.
func (n *Controller) retire() error {
	for work := 0; work < 32 && n.retirementScan < n.app.FinalizedHeight(); work++ {
		h := n.retirementScan + 1
		cp, proof, err := n.app.FinalizedCheckpoint(h)
		if err != nil {
			return err
		}
		if cp.RewardPeriod != 0 {
			if err := n.config.Collector.RetireFinalized(rewards.FinalizedBlock{Checkpoint: cp, Proof: proof}); err != nil {
				return err
			}
		}
		n.retirementScan = h
	}
	closed := n.config.Collector.Retirement().Period
	for key, period := range n.known {
		if period <= closed {
			delete(n.known, key)
		}
	}
	for key, set := range n.receipts {
		for _, receipt := range set {
			if receipt.Duty.Period <= closed {
				delete(n.receipts, key)
			}
			break
		}
	}
	return nil
}
