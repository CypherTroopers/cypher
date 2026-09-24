package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// SnapshotValidator is optional for legacy execution but required by financial
// schema 5. Consensus still streams and reexecutes the archive from genesis;
// this check also validates financial canonical encoding and state invariants.
type SnapshotValidator interface {
	ValidateSnapshot(raw []byte, height uint64, root protocol.Hash) error
}

type StorageStatus struct {
	Generation   uint64 `json:"generation"`
	BaseHeight   uint64 `json:"base_height"`
	HotRecords   int    `json:"hot_records"`
	ArchiveBytes uint64 `json:"archive_bytes"`
	BudgetBytes  uint64 `json:"budget_bytes"`
	Blocked      bool   `json:"blocked"`
}

func (a *Application) StorageStatus() StorageStatus {
	return StorageStatus{a.disk.Generation, a.disk.BaseHeight, len(a.disk.Records), a.disk.ArchiveBytes, a.config.ArchiveBudgetBytes, a.storageBlocked}
}

func archiveTip(state diskState) (protocol.Hash, error) {
	if state.BaseHeight == 0 {
		if state.ArchiveTip != "" || state.ArchiveBytes != 0 || state.Generation != 0 {
			return protocol.Hash{}, errors.New("nonempty genesis archive metadata")
		}
		return protocol.Hash{}, nil
	}
	b, err := hex.DecodeString(state.ArchiveTip)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != state.ArchiveTip {
		return protocol.Hash{}, errors.New("invalid archive tip")
	}
	var h protocol.Hash
	copy(h[:], b)
	return h, nil
}

func (a *Application) verifyArchivedFinality(e archiveEntry) error {
	if e.Domain != a.config.Domain || e.Record == nil || e.Record.QC == nil || e.Record.Checkpoint.Sequence != e.Height || !bytes.Equal(e.Record.Ref, e.Record.QC.State) {
		return errors.New("foreign archive domain/record")
	}
	ref, err := types.DecodeHotstuffProposalRef(e.Record.Ref)
	if err != nil {
		return err
	}
	if ref.ProposalID().Hex() != e.Finalized.Key {
		return errors.New("archive record key mismatch")
	}
	h, err := e.Record.Checkpoint.Hash()
	if err != nil || common.Hash(h).Hex() != e.Finalized.Hash {
		return errors.New("archive checkpoint hash mismatch")
	}
	if err = a.verifyQC(e.Record.QC); err != nil {
		return err
	}
	_, err = a.epoch.Verify(e.Record.Checkpoint, e.Finalized.Proof)
	return err
}

// Authenticate the entire durable prefix with one predecessor and one current
// record in memory. Checksums alone never skip execution or finality checking.
func (a *Application) recoverArchive() error {
	if a.disk.Version != StorageGenerationVersion || a.disk.BaseHeight > a.config.MaxHeight || a.disk.Generation > a.disk.BaseHeight {
		return errors.New("invalid generation WAL bounds")
	}
	want, err := archiveTip(a.disk)
	if err != nil {
		return err
	}
	probe := *a
	probe.archiveReplay = true
	probe.disk = diskState{Records: make(map[string]*Record)}
	var prior protocol.Hash
	var total uint64
	var last *Record
	var parent *hotstuff.SignedState
	for height := uint64(1); height <= a.disk.BaseHeight; height++ {
		e, h, n, err := a.wal.readArchive(height)
		if err != nil {
			return fmt.Errorf("archive %d unavailable/corrupt: %w", height, err)
		}
		if e.Previous != prior {
			return errors.New("archive hash chain gap")
		}
		if err = probe.verifyArchivedFinality(e); err != nil {
			return err
		}
		if err = probe.validateRecord(e.Record, parent); err != nil {
			return fmt.Errorf("archive %d execution: %w", height, err)
		}
		if validator, ok := a.config.Execution.(SnapshotValidator); ok {
			if err = validator.ValidateSnapshot(e.Record.State, height, e.Record.Checkpoint.PostRoot); err != nil {
				return err
			}
		}
		probe.disk.Records = map[string]*Record{e.Finalized.Key: e.Record}
		last, parent = e.Record, e.Record.QC
		prior = h
		a.archiveDigests[height] = h
		total += n
		if total > a.config.ArchiveBudgetBytes-archiveWorkReserve {
			return ErrStorageCapacity
		}
	}
	if prior != want || total != a.disk.ArchiveBytes {
		return errors.New("archive tip/byte sum mismatch")
	}
	actual, err := a.wal.archiveDiskBytes()
	if err != nil {
		return err
	}
	if actual > a.config.ArchiveBudgetBytes-archiveWorkReserve {
		return ErrStorageCapacity
	}
	if last != nil {
		ref, _ := types.DecodeHotstuffProposalRef(last.Ref)
		key := ref.ProposalID().Hex()
		old := a.disk.Records[key]
		if old == nil || old.Checkpoint != last.Checkpoint || !bytes.Equal(old.Ref, last.Ref) || !bytes.Equal(old.State, last.State) || !bytes.Equal(old.Actions, last.Actions) || !sameHistory(old.History, last.History) || !hotstuff.SignedStateSemanticEqual(old.QC, last.QC) {
			return errors.New("hot cut state differs from authenticated archive")
		}
	}
	return nil
}

// Read one <=2MiB entry against the fixed-size digest index established by
// complete authenticated cold replay. A persisted/cache-provided index is never
// accepted as a trust root. Missing history remains an explicit failure.
func (a *Application) archived(height uint64) (*Record, finalizedRecord, error) {
	if !a.config.StorageGenerations || a.archiveReplay || height == 0 || height > a.disk.BaseHeight {
		return nil, finalizedRecord{}, ErrUnavailable
	}
	e, h, _, err := a.wal.readArchive(height)
	if err != nil {
		return nil, finalizedRecord{}, err
	}
	if err = a.verifyArchivedFinality(e); err != nil {
		return nil, finalizedRecord{}, err
	}
	if a.archiveDigests[height] == (protocol.Hash{}) || h != a.archiveDigests[height] {
		return nil, finalizedRecord{}, errors.New("archive read differs from authenticated digest")
	}
	return e.Record, e.Finalized, nil
}

func (a *Application) finalizedRecordAt(height uint64) (*Record, finalizedRecord, error) {
	if height == 0 || height > a.FinalizedHeight() {
		return nil, finalizedRecord{}, ErrUnavailable
	}
	if height <= a.disk.BaseHeight {
		return a.archived(height)
	}
	f := a.disk.Finalized[height-a.disk.BaseHeight-1]
	r := a.disk.Records[f.Key]
	if r == nil {
		return nil, f, ErrUnavailable
	}
	return r, f, nil
}

func (a *Application) lookupRecord(ref *types.HotstuffProposalRef) *Record {
	if ref == nil {
		return nil
	}
	if r := a.disk.Records[ref.ProposalID().Hex()]; r != nil {
		return r
	}
	if a.archiveReplay {
		return nil
	}
	r, _, err := a.archived(ref.Number)
	if err != nil || !bytes.Equal(r.Ref, ref.EncodeToBytes()) {
		return nil
	}
	return r
}

// reuseOrWriteArchive never replaces a durable entry. Recovery may learn a
// semantically identical QC with a different valid signer subset. Authenticate
// both finality proofs and the identical executed prefix before reusing the
// existing immutable bytes and their original digest chain.
func (a *Application) reuseOrWriteArchive(e archiveEntry) (protocol.Hash, uint64, error) {
	if err := a.verifyArchivedFinality(e); err != nil {
		return protocol.Hash{}, 0, err
	}
	old, digest, size, err := a.wal.readArchive(e.Height)
	if errors.Is(err, os.ErrNotExist) {
		return a.wal.writeArchive(e, a.config.ArchiveBudgetBytes)
	}
	if err != nil {
		return protocol.Hash{}, 0, err
	}
	if err = a.verifyArchivedFinality(old); err != nil {
		return protocol.Hash{}, 0, err
	}
	if old.Version != e.Version || old.Domain != e.Domain || old.Height != e.Height || old.Previous != e.Previous ||
		old.Finalized.Key != e.Finalized.Key || old.Finalized.Hash != e.Finalized.Hash ||
		old.Record.Checkpoint != e.Record.Checkpoint || old.Record.Action != e.Record.Action ||
		!bytes.Equal(old.Record.Ref, e.Record.Ref) || !bytes.Equal(old.Record.Actions, e.Record.Actions) ||
		!bytes.Equal(old.Record.State, e.Record.State) || !sameHistory(old.Record.History, e.Record.History) || !hotstuff.SignedStateSemanticEqual(old.Record.QC, e.Record.QC) {
		return protocol.Hash{}, 0, errors.New("archive tail conflicts with authenticated executed prefix")
	}
	return digest, size, nil
}

func (a *Application) rotateStorage() error {
	interval := StorageGenerationInterval
	if a.wal.rotationInterval != 0 {
		interval = a.wal.rotationInterval
	}
	if interval > StorageGenerationInterval {
		return errors.New("invalid private storage interval")
	}
	if !a.config.StorageGenerations {
		return nil
	}
	available := a.FinalizedHeight() - a.disk.BaseHeight
	if available < interval {
		// A byte-heavy current generation can exhaust the hot WAL before its
		// usual 64-finalized-block cut. Reuse the same authenticated archive
		// transaction early, without changing the WAL cap or omitting safety,
		// financial state, actions, certificates, or pinned branch ancestors.
		// With no new finality there is nothing safe to archive: retain the
		// existing bounded refusal instead of pruning unfinalized obligations.
		if available == 0 {
			return nil
		}
		payload, err := json.Marshal(a.disk)
		if err != nil {
			return err
		}
		if len(payload) < maxWALBytes*3/4 {
			return nil
		}
		interval = available
	}
	cut := a.disk.BaseHeight + interval
	prior, err := archiveTip(a.disk)
	if err != nil {
		return err
	}
	bytesWritten := a.disk.ArchiveBytes
	// Every entry contains authenticated finalized state before any old hot
	// record is removed. Partially completed immutable prefixes are reusable.
	for height := a.disk.BaseHeight + 1; height <= cut; height++ {
		r, f, err := a.finalizedRecordAt(height)
		if err != nil {
			return err
		}
		e := archiveEntry{StorageGenerationVersion, a.config.Domain, height, prior, r, f}
		h, n, err := a.reuseOrWriteArchive(e)
		if err != nil {
			return err
		}
		prior = h
		a.archiveDigests[height] = h
		bytesWritten += n
	}
	if a.wal.generationFault != nil {
		if err = a.wal.generationFault("archive-durable"); err != nil {
			return err
		}
	}
	pins := make(map[string]bool)
	pin := func(raw []byte) {
		if ref, e := types.DecodeHotstuffProposalRef(raw); e == nil {
			pins[ref.ProposalID().Hex()] = true
		}
	}
	if v := a.disk.Safety.LastVote; v != nil {
		pin(v.ProposalRef)
	}
	for _, q := range []*hotstuff.SignedState{a.disk.Safety.HighestQC, a.disk.Outbox, a.selected} {
		if q != nil {
			pin(q.State)
		}
	}
	for _, b := range a.builds {
		if b.ParentQC != nil {
			pin(b.ParentQC.State)
		}
	}
	kept := make(map[string]*Record)
	var pending []*Record
	for key, r := range a.disk.Records {
		if r.Checkpoint.Sequence >= cut || pins[key] {
			kept[key] = r
			pending = append(pending, r)
		}
	}
	// An old own vote may be on a branch that was never finalized. Keep its
	// authenticated noncanonical parent chain, not just the last vote record.
	// Canonical parents are available from the immutable prefix being cut.
	for len(pending) > 0 {
		r := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		ref, err := types.DecodeHotstuffProposalRef(r.Ref)
		if err != nil {
			return err
		}
		q, err := a.parentQC(ref)
		if err != nil {
			return err
		}
		if q == nil {
			continue
		}
		parent := a.recordForQC(q)
		if parent == nil {
			return ErrUnavailable
		}
		p, err := types.DecodeHotstuffProposalRef(parent.Ref)
		if err != nil {
			return err
		}
		key := p.ProposalID().Hex()
		if kept[key] != nil {
			continue
		}
		if p.Number <= cut {
			canonical, _, err := a.finalizedRecordAt(p.Number)
			if err == nil && bytes.Equal(canonical.Ref, parent.Ref) && hotstuff.SignedStateSemanticEqual(canonical.QC, q) {
				continue
			}
		}
		if a.disk.Records[key] == nil || len(kept) >= MaxRecords {
			return ErrStorageCapacity
		}
		kept[key] = parent
		pending = append(pending, parent)
	}
	if len(kept) >= MaxRecords {
		return ErrStorageCapacity
	}
	a.disk.Records = kept
	a.disk.Finalized = append([]finalizedRecord(nil), a.disk.Finalized[interval:]...)
	a.disk.BaseHeight = cut
	a.disk.Generation++
	a.disk.ArchiveTip = hex.EncodeToString(prior[:])
	a.disk.ArchiveBytes = bytesWritten
	a.storageBlocked = false
	return nil
}

// MaintainStorage retries bounded retention after an operator resolves local
// capacity. It never clears obligations or changes the consensus state.
func (a *Application) MaintainStorage() error {
	if err := a.check(); err != nil {
		return err
	}
	if err := a.persist(); err != nil {
		return err
	}
	if a.storageBlocked {
		return ErrStorageCapacity
	}
	return nil
}
