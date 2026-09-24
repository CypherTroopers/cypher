package rewards

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"

	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

var (
	ErrDeadline           = errors.New("participation receipt deadline closed")
	ErrUnvalidatedTarget  = errors.New("collector has not durably validated this target")
	ErrPeriodClosed       = errors.New("participation period already closed")
	ErrOmittedCertificate = errors.New("reward close omits a locally acknowledged participation certificate")
	ErrPersistence        = errors.New("participation WAL unavailable or uncertain")
)

const MaxWALRecords = 2048

type collectorDisk struct {
	Version       uint16
	Domain        protocol.Domain
	RegistryHash  protocol.Hash
	Index         uint8
	ClosedThrough uint64
	LastVote      *hotstuff.PersistedVote
	// BeforeVote fsync precedes the FHS WAL fsync. Keep the prior exact vote
	// as a recovery pin until another successful consensus step supersedes it.
	RecoveryVote *hotstuff.PersistedVote `json:",omitempty"`
	Targets      map[string][]byte
	Issued       map[string]Receipt
	Certificates map[string][]byte
	Closed       map[string]protocol.Hash
	Retired      *RetiredFrontier `json:",omitempty"`
}

type Collector struct {
	mu       sync.Mutex
	registry *Registry
	index    uint8
	secret   *bls.SecretKey
	wal      *collectorWAL
	disk     collectorDisk
	persist  func(collectorDisk) error
	failure  error
	closed   bool
	// Startup supplies the real FHS WAL watermark. After a pre-FHS-fsync
	// crash, LastVote can be a collector-only attempt; it must not replace
	// this recovery pin on the first new attempt after restart.
	restoredVote    *hotstuff.PersistedVote
	restoredPending bool
}

func OpenCollector(dir string, registry *Registry, index uint8, secret *bls.SecretKey) (*Collector, error) {
	if registry == nil || index >= 7 || secret == nil || !secret.GetPublicKey().IsEqual(registry.keys[index]) {
		return nil, errors.New("collector key not registered")
	}
	clone := new(bls.SecretKey)
	if err := clone.Deserialize(secret.Serialize()); err != nil {
		return nil, err
	}
	wal, err := openCollectorWAL(dir)
	if err != nil {
		return nil, err
	}
	c := &Collector{registry: registry, index: index, secret: clone, wal: wal, persist: wal.save}
	c.disk, err = wal.load(registry.domain, registry.Commitment(), index)
	if err == nil {
		err = c.validateDisk()
	}
	if err == nil {
		err = c.recoverRetirementTail()
	}
	if err == nil {
		err = wal.cleanupRetirementTemporary()
	}
	if err == nil {
		err = wal.save(c.disk)
	}
	if err != nil {
		wal.close()
		return nil, err
	}
	return c, nil
}

func (c *Collector) validateDisk() error {
	d := c.disk
	if d.Version != 1 || d.Domain != c.registry.domain || d.RegistryHash != c.registry.Commitment() || d.Index != c.index || d.Targets == nil || d.Issued == nil || d.Certificates == nil || d.Closed == nil || recordCount(d) > MaxWALRecords {
		return errors.New("invalid collector WAL identity or bounds")
	}
	if d.LastVote != nil {
		ref, err := c.registry.ref(d.LastVote.ProposalRef)
		if err != nil {
			return err
		}
		if ref.ProposalID() != d.LastVote.ProposalID || hotstuff.StateDigest(d.LastVote.ProposalRef) != d.LastVote.ProposalRefHash || ref.ViewNumber != d.LastVote.ViewNumber || ref.ViewID != d.LastVote.ViewID || ref.LeaderID != d.LastVote.LeaderID || d.ClosedThrough < ref.Number-1 || !bytes.Equal(d.Targets[d.LastVote.ProposalID.Hex()], d.LastVote.ProposalRef) {
			return errors.New("inconsistent collector vote watermark")
		}
	}
	if d.RecoveryVote != nil {
		v := d.RecoveryVote
		ref, err := c.registry.ref(v.ProposalRef)
		if err != nil || d.LastVote == nil || v.ViewNumber >= d.LastVote.ViewNumber || ref.ProposalID() != v.ProposalID || hotstuff.StateDigest(v.ProposalRef) != v.ProposalRefHash || ref.ViewNumber != v.ViewNumber || ref.ViewID != v.ViewID || ref.LeaderID != v.LeaderID || d.ClosedThrough < ref.Number-1 || !bytes.Equal(d.Targets[v.ProposalID.Hex()], v.ProposalRef) {
			return errors.New("inconsistent collector recovery vote pin")
		}
	}
	for key, data := range d.Targets {
		ref, err := c.registry.ref(data)
		if err != nil {
			return err
		}
		if key != ref.ProposalID().Hex() {
			return errors.New("collector target key mismatch")
		}
	}
	for key, receipt := range d.Issued {
		hash, err := receipt.Duty.Hash()
		if err != nil {
			return err
		}
		if key != hex.EncodeToString(hash[:]) || receipt.Collector != c.index {
			return errors.New("collector receipt key mismatch")
		}
		if err := c.registry.VerifyReceipt(receipt); err != nil {
			return err
		}
		target, ok := d.Targets[fmt.Sprintf("0x%x", receipt.Duty.ProposalID)]
		if !ok {
			return errors.New("issued receipt lost validated target")
		}
		ref, err := c.registry.ref(target)
		if err != nil || ref.Number != receipt.Duty.Height || ref.ViewNumber != receipt.Duty.View {
			return errors.New("issued receipt target metadata mismatch")
		}
	}
	for key, data := range d.Certificates {
		cert, err := DecodeCertificate(data)
		if err != nil {
			return err
		}
		hash, _ := cert.Duty.Hash()
		if key != hex.EncodeToString(hash[:]) {
			return errors.New("stored certificate key mismatch")
		}
		if err := c.registry.VerifyCertificate(cert); err != nil {
			return err
		}
	}
	for period, root := range d.Closed {
		n, err := strconv.ParseUint(period, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != period || root == (protocol.Hash{}) {
			return errors.New("invalid closed participation period")
		}
	}
	if d.Retired != nil {
		if err := c.validateRetirement(); err != nil {
			return err
		}
	}
	return nil
}

func recordCount(d collectorDisk) int {
	return len(d.Targets) + len(d.Issued) + len(d.Certificates) + len(d.Closed)
}
func cloneDisk(d collectorDisk) collectorDisk {
	n := d
	if d.Retired != nil {
		r := *d.Retired
		n.Retired = &r
	}
	n.LastVote = hotstuff.ClonePersistedVote(d.LastVote)
	n.RecoveryVote = hotstuff.ClonePersistedVote(d.RecoveryVote)
	n.Targets = make(map[string][]byte, len(d.Targets))
	for k, v := range d.Targets {
		n.Targets[k] = bytes.Clone(v)
	}
	n.Issued = make(map[string]Receipt, len(d.Issued))
	for k, v := range d.Issued {
		n.Issued[k] = v
	}
	n.Certificates = make(map[string][]byte, len(d.Certificates))
	for k, v := range d.Certificates {
		n.Certificates[k] = bytes.Clone(v)
	}
	n.Closed = make(map[string]protocol.Hash, len(d.Closed))
	for k, v := range d.Closed {
		n.Closed[k] = v
	}
	return n
}

func (c *Collector) check() error {
	if c.closed {
		return errors.New("collector closed")
	}
	if c.failure != nil {
		return c.failure
	}
	return nil
}
func (c *Collector) commit(next collectorDisk) error {
	if recordCount(next) > MaxWALRecords {
		return errors.New("collector WAL record capacity exhausted")
	}
	if err := c.persist(next); err != nil {
		c.failure = fmt.Errorf("%w: %w", ErrPersistence, err)
		return c.failure
	}
	c.disk = next
	return nil
}

// CheckFHSWatermark is called at application startup with the authenticated
// restored FHS safety watermark. A new/missing collector WAL may not be silently
// attached to a signer which has already voted. The collector can conservatively
// be ahead after a crash between its fsync and the FHS fsync.
func (c *Collector) CheckFHSWatermark(v *hotstuff.PersistedVote) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return err
	}
	if v == nil {
		c.restoredVote, c.restoredPending = nil, true
		return nil
	}
	ref, err := c.registry.ref(v.ProposalRef)
	if err != nil {
		return err
	}
	if ref.ViewNumber != v.ViewNumber || ref.ViewID != v.ViewID || ref.LeaderID != v.LeaderID || ref.ProposalID() != v.ProposalID || hotstuff.StateDigest(v.ProposalRef) != v.ProposalRefHash {
		return errors.New("invalid restored FHS vote metadata")
	}
	if c.disk.LastVote == nil || c.disk.LastVote.ViewNumber < v.ViewNumber || c.disk.ClosedThrough < ref.Number-1 || !bytes.Equal(c.disk.Targets[ref.ProposalID().Hex()], v.ProposalRef) {
		return errors.New("collector WAL does not cover restored FHS vote")
	}
	c.restoredVote, c.restoredPending = hotstuff.ClonePersistedVote(v), true
	return nil
}

// BeforeVote belongs only at the consensus validated-proposal/pre-signature
// boundary. A caller-asserted height is never accepted in place of this object.
func (c *Collector) BeforeVote(v *hotstuff.PersistedVote) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return err
	}
	if v == nil {
		return errors.New("nil participation vote context")
	}
	ref, err := c.registry.ref(v.ProposalRef)
	if err != nil {
		return err
	}
	if ref.ViewNumber != v.ViewNumber || ref.ViewID != v.ViewID || ref.LeaderID != v.LeaderID || ref.ProposalID() != v.ProposalID || hotstuff.StateDigest(v.ProposalRef) != v.ProposalRefHash || v.ViewNumber == math.MaxUint64 {
		return errors.New("participation vote context mismatch")
	}
	if old := c.disk.LastVote; old != nil {
		if v.ViewNumber < old.ViewNumber {
			return errors.New("stale participation vote context")
		}
		if v.ViewNumber == old.ViewNumber {
			if !bytes.Equal(v.ProposalRef, old.ProposalRef) {
				return errors.New("conflicting participation vote context")
			}
			// Exact retry is also a successful pre-signature step. A later
			// callback in this process implies this vote reached the FHS WAL,
			// otherwise its persist failure must have halted consensus.
			c.restoredVote, c.restoredPending = nil, false
			return nil
		}
	}
	next := cloneDisk(c.disk)
	next.RecoveryVote = hotstuff.ClonePersistedVote(next.LastVote)
	if c.restoredPending {
		next.RecoveryVote = hotstuff.ClonePersistedVote(c.restoredVote)
	}
	next.LastVote = hotstuff.ClonePersistedVote(v)
	next.Targets[ref.ProposalID().Hex()] = bytes.Clone(v.ProposalRef)
	if next.Retired != nil {
		for key, raw := range next.Targets {
			old, err := c.registry.ref(raw)
			if err != nil {
				return err
			}
			if (old.Number-1)/PeriodBlocks+1 <= next.Retired.Period && !collectorVotePinned(next, raw) {
				delete(next.Targets, key)
			}
		}
	}
	if ref.Number-1 > next.ClosedThrough {
		next.ClosedThrough = ref.Number - 1
	}
	if err := c.commit(next); err != nil {
		return err
	}
	// A later BeforeVote in this process can only follow a successfully
	// persisted FHS vote: FHS WAL failure halts the application. A restart
	// calls CheckFHSWatermark again before any signing and reestablishes the
	// actual durable pin, including repeated crashes at the same boundary.
	c.restoredVote, c.restoredPending = nil, false
	return nil
}

func (c *Collector) Issue(ref []byte, vote *hotstuff.HotstuffMessage) (Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return Receipt{}, err
	}
	duty, err := c.registry.verifyVote(ref, vote)
	if err != nil {
		return Receipt{}, err
	}
	if c.disk.Retired != nil && duty.Period <= c.disk.Retired.Period {
		return Receipt{}, ErrPeriodClosed
	}
	if !bytes.Equal(c.disk.Targets[fmt.Sprintf("0x%x", duty.ProposalID)], ref) {
		return Receipt{}, ErrUnvalidatedTarget
	}
	hash, _ := duty.Hash()
	key := hex.EncodeToString(hash[:])
	if old, ok := c.disk.Issued[key]; ok {
		return old, nil
	}
	if _, ok := c.disk.Closed[strconv.FormatUint(duty.Period, 10)]; ok {
		return Receipt{}, ErrPeriodClosed
	}
	if duty.Height <= c.disk.ClosedThrough {
		return Receipt{}, ErrDeadline
	}
	digest, err := receiptDigest(duty, c.index, c.registry.keys[c.index].Serialize())
	if err != nil {
		return Receipt{}, err
	}
	signature := c.secret.SignHash(digest[:]).Serialize()
	if len(signature) != 32 {
		return Receipt{}, errors.New("unsupported participation BLS signature codec")
	}
	receipt := Receipt{Duty: duty, Collector: c.index}
	copy(receipt.Signature[:], signature)
	next := cloneDisk(c.disk)
	next.Issued[key] = receipt
	if err := c.commit(next); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// RememberCertificate acknowledges a complete quorum certificate. A single
// collector receipt alone cannot establish that other collectors know its set.
func (c *Collector) RememberCertificate(cert Certificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return err
	}
	if err := c.registry.VerifyCertificate(cert); err != nil {
		return err
	}
	if c.disk.Retired != nil && cert.Duty.Period <= c.disk.Retired.Period {
		return ErrPeriodClosed
	}
	hash, _ := cert.Duty.Hash()
	key := hex.EncodeToString(hash[:])
	if _, ok := c.disk.Certificates[key]; ok {
		return nil
	}
	if _, ok := c.disk.Closed[strconv.FormatUint(cert.Duty.Period, 10)]; ok {
		return ErrPeriodClosed
	}
	encoded, err := cert.Encode()
	if err != nil {
		return err
	}
	next := cloneDisk(c.disk)
	next.Certificates[key] = encoded
	return c.commit(next)
}

// Close records a local diagnostic inclusion decision. It is not a consensus
// validity gate: collectors may have different asynchronously delivered sets.
// Financial execution uses CheckCommittedClose against the agreed parent state.
func (c *Collector) Close(period uint64, blocks []FinalizedBlock, certificates []Certificate) (Points, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return Points{}, err
	}
	return c.closeLocked(period, blocks, certificates, true)
}

// CheckClose is a nonmutating local inclusion diagnostic, never an input to
// deterministic execution, replay, or a finalized-state callback.
func (c *Collector) CheckClose(period uint64, blocks []FinalizedBlock, certificates []Certificate) (Points, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return Points{}, err
	}
	return c.closeLocked(period, blocks, certificates, false)
}

func (c *Collector) closeLocked(period uint64, blocks []FinalizedBlock, certificates []Certificate, persist bool) (Points, error) {
	if c.disk.Retired != nil && period <= c.disk.Retired.Period {
		return Points{}, ErrPeriodClosed
	}
	points, canonical, err := c.registry.compute(period, blocks, certificates)
	if err != nil {
		return Points{}, err
	}
	root, err := points.Root()
	if err != nil {
		return Points{}, err
	}
	periodKey := strconv.FormatUint(period, 10)
	if old, ok := c.disk.Closed[periodKey]; ok {
		if old != root {
			return Points{}, ErrPeriodClosed
		}
		return points, nil
	}
	included := make(map[string]bool, len(certificates))
	for _, cert := range certificates {
		hash, _ := cert.Duty.Hash()
		included[hex.EncodeToString(hash[:])] = true
	}
	for key, data := range c.disk.Certificates {
		cert, err := DecodeCertificate(data)
		if err != nil {
			return Points{}, err
		}
		if cert.Duty.Period != period {
			continue
		}
		target, ok := canonical[cert.Duty.Height]
		if ok && target.proposal == cert.Duty.ProposalID && target.view == cert.Duty.View && !included[key] {
			return Points{}, ErrOmittedCertificate
		}
	}
	if !persist {
		return points, nil
	}
	next := cloneDisk(c.disk)
	next.Closed[periodKey] = root
	if err := c.commit(next); err != nil {
		return Points{}, err
	}
	return points, nil
}

func (c *Collector) Shutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.wal.close()
}
func (c *Collector) ClosedThrough() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disk.ClosedThrough
}
