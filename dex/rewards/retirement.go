package rewards

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cypherium/cypher/dex/protocol"
)

const MaxRetiredPeriods = 1024
const MaxRetirementBytes = 128 * 1024 * 1024
const retirementTemporary = "RETIRE.next"

type RetiredFrontier struct {
	Period, Height uint64
	Root           protocol.Hash
	Bytes          uint64
}

// The archive preserves even locally known certificates absent from the
// committed close. Retirement is retention, not a decision to award/delete them.
type retiredPeriod struct {
	Version      uint16
	RegistryHash protocol.Hash
	Index        uint8
	Previous     protocol.Hash
	Finalized    FinalizedBlock
	Targets      map[string][]byte
	Issued       map[string]Receipt
	Certificates map[string][]byte
	Closed       map[string]protocol.Hash
}

func collectorVotePinned(d collectorDisk, raw []byte) bool {
	return d.LastVote != nil && bytes.Equal(raw, d.LastVote.ProposalRef) || d.RecoveryVote != nil && bytes.Equal(raw, d.RecoveryVote.ProposalRef)
}

func retirementPath(dir string, period uint64) string {
	return filepath.Join(dir, fmt.Sprintf("period-%08d.json", period))
}

// Finish the single fully published archive tail before exposing the collector
// to any new network input. Otherwise a delayed certificate could change the
// old hot set between an interrupted archive publication and its retry. The
// archive is not a replacement trust root: the authoritative WAL must exist,
// and RetireFinalized rechecks its exact hot set, committee finality and linkage.
func (c *Collector) recoverRetirementTail() error {
	period := uint64(1)
	var previous protocol.Hash
	if c.disk.Retired != nil {
		period += c.disk.Retired.Period
		previous = c.disk.Retired.Root
	}
	if period > MaxRetiredPeriods {
		return nil
	}
	if _, err := os.Lstat(retirementPath(c.wal.dir, period)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	state, err := os.Lstat(filepath.Join(c.wal.dir, "state.json"))
	if err != nil || !state.Mode().IsRegular() {
		return errors.New("orphan archive cannot replace missing canonical collector WAL")
	}
	p, _, _, err := readRetired(c.wal.dir, period)
	if err != nil {
		return err
	}
	if err = c.verifyRetired(p, period, previous); err != nil {
		return err
	}
	return c.RetireFinalized(p.Finalized)
}

// The one staging inode is never referenced by the canonical active WAL. Its
// removal is allowed only after that WAL and all referenced archives validate.
// A published hard link remains intact if a crash left this staging name too.
func (w *collectorWAL) cleanupRetirementTemporary() error {
	path := filepath.Join(w.dir, retirementTemporary)
	f, err := collectorOpenNoFollow(path, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	f.Close()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCollectorWALBytes {
		return errors.New("invalid collector retirement temporary")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open(w.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func encodeRetired(p retiredPeriod) ([]byte, protocol.Hash, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, protocol.Hash{}, err
	}
	h := protocol.Digest("common-dex/retired-participation/v1", b)
	b, err = json.Marshal(collectorEnvelope{b, h})
	if len(b) > maxCollectorWALBytes {
		return nil, protocol.Hash{}, errors.New("retired participation byte bound")
	}
	return b, h, err
}

func readRetired(dir string, period uint64) (retiredPeriod, protocol.Hash, uint64, error) {
	var p retiredPeriod
	f, err := collectorOpenNoFollow(retirementPath(dir, period), os.O_RDONLY, 0)
	if err != nil {
		return p, protocol.Hash{}, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCollectorWALBytes {
		return p, protocol.Hash{}, 0, errors.New("retired participation file bound")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCollectorWALBytes+1))
	if err != nil || len(b) > maxCollectorWALBytes {
		return p, protocol.Hash{}, 0, errors.New("retired participation read bound")
	}
	var e collectorEnvelope
	if err = strictCollectorJSON(b, &e); err != nil {
		return p, protocol.Hash{}, 0, err
	}
	if err = strictCollectorJSON(e.Payload, &p); err != nil {
		return p, protocol.Hash{}, 0, err
	}
	canonical, hash, err := encodeRetired(p)
	if err != nil || !bytes.Equal(canonical, b) || hash != e.Checksum {
		return p, protocol.Hash{}, 0, errors.New("retired participation canonical checksum")
	}
	return p, hash, uint64(len(b)), nil
}

func (c *Collector) verifyRetired(p retiredPeriod, period uint64, previous protocol.Hash) error {
	cp := p.Finalized.Checkpoint
	if p.Version != 1 || p.RegistryHash != c.registry.Commitment() || p.Index != c.index || p.Previous != previous || cp.Domain() != c.registry.domain || cp.RewardPeriod != period || period == 0 || period > MaxRetiredPeriods || cp.Sequence < period*PeriodBlocks+GraceBlocks || p.Targets == nil || p.Issued == nil || p.Certificates == nil || p.Closed == nil || len(p.Targets)+len(p.Issued)+len(p.Certificates)+len(p.Closed) > MaxWALRecords {
		return errors.New("retired participation identity/frontier")
	}
	if _, err := c.registry.epoch.Verify(cp, p.Finalized.Proof); err != nil {
		return err
	}
	for key, raw := range p.Targets {
		ref, err := c.registry.ref(raw)
		if err != nil || ref.ProposalID().Hex() != key || (ref.Number-1)/PeriodBlocks+1 > period {
			return errors.New("retired participation target")
		}
	}
	for key, r := range p.Issued {
		h, err := r.Duty.Hash()
		if err != nil || fmt.Sprintf("%x", h) != key || r.Collector != c.index || r.Duty.Period > period || c.registry.VerifyReceipt(r) != nil {
			return errors.New("retired participation receipt")
		}
		ref, err := c.registry.ref(p.Targets[fmt.Sprintf("0x%x", r.Duty.ProposalID)])
		if err != nil || ref.Number != r.Duty.Height || ref.ViewNumber != r.Duty.View {
			return errors.New("retired receipt target missing")
		}
	}
	for key, raw := range p.Certificates {
		cert, err := DecodeCertificate(raw)
		if err != nil {
			return err
		}
		h, err := cert.Duty.Hash()
		if err != nil || fmt.Sprintf("%x", h) != key || cert.Duty.Period > period || c.registry.VerifyCertificate(cert) != nil {
			return errors.New("retired participation certificate")
		}
	}
	for key, root := range p.Closed {
		n, err := strconv.ParseUint(key, 10, 64)
		if err != nil || n == 0 || n > period || strconv.FormatUint(n, 10) != key || root == (protocol.Hash{}) {
			return errors.New("retired local close marker")
		}
	}
	return nil
}

func (c *Collector) validateRetirement() error {
	f := c.disk.Retired
	if f.Period == 0 || f.Period > MaxRetiredPeriods || f.Height < f.Period*PeriodBlocks+GraceBlocks || f.Root == (protocol.Hash{}) || f.Bytes == 0 || f.Bytes > MaxRetirementBytes {
		return errors.New("collector retired frontier bound")
	}
	var previous protocol.Hash
	var total, height uint64
	for period := uint64(1); period <= f.Period; period++ {
		p, hash, size, err := readRetired(c.wal.dir, period)
		if err != nil {
			return fmt.Errorf("retirement archive unavailable: %w", err)
		}
		total += size
		if total > MaxRetirementBytes || p.Finalized.Checkpoint.Sequence <= height {
			return errors.New("collector retired archive budget/order")
		}
		if err := c.verifyRetired(p, period, previous); err != nil {
			return err
		}
		previous, height = hash, p.Finalized.Checkpoint.Sequence
	}
	if previous != f.Root || total != f.Bytes || height != f.Height {
		return errors.New("collector retired frontier mismatch")
	}
	for _, raw := range c.disk.Targets {
		ref, err := c.registry.ref(raw)
		if err != nil {
			return err
		}
		if (ref.Number-1)/PeriodBlocks+1 <= f.Period && !collectorVotePinned(c.disk, raw) {
			return errors.New("retired target reintroduced into hot state")
		}
	}
	for _, r := range c.disk.Issued {
		if r.Duty.Period <= f.Period {
			return errors.New("retired receipt reintroduced")
		}
	}
	for _, raw := range c.disk.Certificates {
		r, err := DecodeCertificate(raw)
		if err != nil || r.Duty.Period <= f.Period {
			return errors.New("retired certificate reintroduced")
		}
	}
	for key := range c.disk.Closed {
		period, _ := strconv.ParseUint(key, 10, 64)
		if period <= f.Period {
			return errors.New("retired local close reintroduced")
		}
	}
	return nil
}

// RetireFinalized is a local storage operation authorized by a verified DEX
// descendant-finality proof. It never changes the financial state or pays a
// reward. An unsigned height, caller-selected validator set or local Close is
// insufficient to reclaim evidence.
func (c *Collector) RetireFinalized(block FinalizedBlock) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return err
	}
	cp := block.Checkpoint
	period := cp.RewardPeriod
	if period == 0 || period > MaxRetiredPeriods || cp.Domain() != c.registry.domain || cp.Sequence < period*PeriodBlocks+GraceBlocks {
		return errors.New("retirement finalized period bound")
	}
	if _, err := c.registry.epoch.Verify(cp, block.Proof); err != nil {
		return err
	}
	frontier := RetiredFrontier{}
	if c.disk.Retired != nil {
		frontier = *c.disk.Retired
	}
	if period <= frontier.Period {
		old, _, _, err := readRetired(c.wal.dir, period)
		if err != nil {
			return err
		}
		a, _ := old.Finalized.Checkpoint.Hash()
		b, _ := cp.Hash()
		if a != b {
			return errors.New("retired finalized period conflict")
		}
		return nil
	}
	if period != frontier.Period+1 || cp.Sequence <= frontier.Height {
		return errors.New("retirement nonsequential period")
	}
	p := retiredPeriod{Version: 1, RegistryHash: c.registry.Commitment(), Index: c.index, Previous: frontier.Root, Finalized: block, Targets: map[string][]byte{}, Issued: map[string]Receipt{}, Certificates: map[string][]byte{}, Closed: map[string]protocol.Hash{}}
	next := cloneDisk(c.disk)
	for key, raw := range c.disk.Targets {
		ref, err := c.registry.ref(raw)
		if err != nil {
			return err
		}
		if (ref.Number-1)/PeriodBlocks+1 <= period {
			p.Targets[key] = bytes.Clone(raw)
			if !collectorVotePinned(c.disk, raw) {
				delete(next.Targets, key)
			}
		}
	}
	for key, r := range c.disk.Issued {
		if r.Duty.Period <= period {
			p.Issued[key] = r
			delete(next.Issued, key)
		}
	}
	for key, raw := range c.disk.Certificates {
		cert, err := DecodeCertificate(raw)
		if err != nil {
			return err
		}
		if cert.Duty.Period <= period {
			p.Certificates[key] = bytes.Clone(raw)
			delete(next.Certificates, key)
		}
	}
	for key, root := range c.disk.Closed {
		n, _ := strconv.ParseUint(key, 10, 64)
		if n <= period {
			p.Closed[key] = root
			delete(next.Closed, key)
		}
	}
	if err := c.verifyRetired(p, period, frontier.Root); err != nil {
		return err
	}
	raw, hash, err := encodeRetired(p)
	if err != nil {
		return err
	}
	if uint64(len(raw)) > MaxRetirementBytes-frontier.Bytes {
		return errors.New("collector retirement archive budget exhausted")
	}
	path := retirementPath(c.wal.dir, period)
	_, err = os.Lstat(path)
	if err == nil {
		old, oldHash, _, readErr := readRetired(c.wal.dir, period)
		oldRaw, _, _ := encodeRetired(old)
		if readErr != nil || oldHash != hash || !bytes.Equal(oldRaw, raw) {
			return errors.New("collector orphan retirement conflict")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		f, err := collectorOpenNoFollow(filepath.Join(c.wal.dir, retirementTemporary), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			c.failure = fmt.Errorf("%w: retirement archive write: %v", ErrPersistence, errors.Join(err, closeErr))
			return c.failure
		}
		// Link publishes a completely fsynced inode without overwriting an
		// existing archive. An interrupted temporary file is never canonical.
		if err := os.Link(f.Name(), path); err != nil {
			return err
		}
	}
	dir, err := os.Open(c.wal.dir)
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	if err != nil {
		c.failure = fmt.Errorf("%w: retirement directory: %v", ErrPersistence, err)
		return c.failure
	}
	next.Retired = &RetiredFrontier{period, cp.Sequence, hash, frontier.Bytes + uint64(len(raw))}
	return c.commit(next)
}

func (c *Collector) Retirement() RetiredFrontier {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disk.Retired == nil {
		return RetiredFrontier{}
	}
	return *c.disk.Retired
}

type StorageStatus struct {
	Retired                                                        RetiredFrontier
	HotTargets, HotReceipts, HotCertificates, HotLocalCloses       int
	MaxHotRecords, MaxWALBytes, MaxArchivePeriods, MaxArchiveBytes int
}

func (c *Collector) StorageStatus() StorageStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := StorageStatus{HotTargets: len(c.disk.Targets), HotReceipts: len(c.disk.Issued), HotCertificates: len(c.disk.Certificates), HotLocalCloses: len(c.disk.Closed), MaxHotRecords: MaxWALRecords, MaxWALBytes: maxCollectorWALBytes, MaxArchivePeriods: MaxRetiredPeriods, MaxArchiveBytes: MaxRetirementBytes}
	if c.disk.Retired != nil {
		s.Retired = *c.disk.Retired
	}
	return s
}
