package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

const maxWALBytes = 2 * 1024 * 1024

const devnetMarker = "COMMON_DEX_ISOLATED_DEVNET_V1\n"

type finalizedRecord struct {
	Key   string
	Hash  string
	Proof []byte
}
type diskState struct {
	Version         uint16
	Domain          protocol.Domain
	VotePublic      string
	ExecutionID     string
	ExecutionSchema uint16
	GenesisState    []byte
	GenesisRoot     protocol.Hash
	SnapshotOrigin  string `json:",omitempty"`
	Safety          *hotstuff.FHSSafetyState
	Records         map[string]*Record
	Finalized       []finalizedRecord
	Outbox          *hotstuff.SignedState
	Generation      uint64 `json:",omitempty"`
	BaseHeight      uint64 `json:",omitempty"`
	ArchiveTip      string `json:",omitempty"`
	ArchiveBytes    uint64 `json:",omitempty"`
}
type walEnvelope struct {
	Payload  json.RawMessage
	Checksum protocol.Hash
}
type walStore struct {
	dir                 string
	lock                *os.File
	recoveryVerified    bool
	canonicalPresent    bool
	cleanupPending      bool
	afterTemporaryChunk func() error // private partial-write crash-test boundary
	generational        bool
	generation          uint64
	currentPresent      bool
	generationFault     func(string) error // private crash-boundary tests only
	rotationInterval    uint64             // private small-threshold component tests; production zero means 64
}

func openWAL(dir string) (*walStore, error) {
	if err := checkWALPlatform(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	created := os.IsNotExist(err)
	if created {
		// Create only the final private directory; its parent must already exist.
		// This avoids treating an existing operational directory as a devnet.
		if err = os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("DEX WAL path is not a private directory")
	}
	markerPath := filepath.Join(dir, "DEVNET")
	if created {
		marker, err := openNoFollow(markerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		if _, err = marker.WriteString(devnetMarker); err != nil {
			marker.Close()
			return nil, err
		}
		if err = marker.Sync(); err != nil {
			marker.Close()
			return nil, err
		}
		if err = marker.Close(); err != nil {
			return nil, err
		}
		for _, path := range []string{dir, filepath.Dir(dir)} {
			d, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			err = d.Sync()
			d.Close()
			if err != nil {
				return nil, err
			}
		}
	} else {
		marker, err := openNoFollow(markerPath, os.O_RDONLY, 0)
		if err != nil {
			return nil, errors.New("existing directory is not a marked DEX devnet")
		}
		b, err := io.ReadAll(io.LimitReader(marker, int64(len(devnetMarker)+1)))
		marker.Close()
		if err != nil || string(b) != devnetMarker {
			return nil, errors.New("invalid DEX devnet marker")
		}
	}
	f, err := openNoFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockExclusive(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("DEX WAL already in use: %w", err)
	}
	return &walStore{dir: dir, lock: f, cleanupPending: true}, nil
}
func (w *walStore) close() error { return w.lock.Close() }
func decodeStrict(data []byte, out interface{}) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing DEX WAL data")
	}
	return nil
}
func (w *walStore) load(domain protocol.Domain, votePublic string) (diskState, error) {
	var state diskState
	name := "state.json"
	generation, present, err := w.loadCurrent()
	if err != nil {
		return state, err
	}
	if !present {
		artifacts, e := w.generationArtifacts()
		if e != nil {
			return state, e
		}
		if artifacts {
			return state, errors.New("generation artifacts exist without CURRENT; fresh-voter fallback forbidden")
		}
	}
	if !w.generational && present {
		return state, errors.New("v4 WAL requires storage generation configuration")
	}
	if w.generational {
		if _, e := os.Lstat(filepath.Join(w.dir, "state.json")); !os.IsNotExist(e) {
			return state, errors.New("legacy WAL cannot open as generation storage")
		}
		if !present {
			if _, e := os.Lstat(filepath.Join(w.dir, generationStateName(0))); !os.IsNotExist(e) {
				return state, errors.New("generation WAL exists without CURRENT")
			}
			state = diskState{Version: StorageGenerationVersion, Domain: domain, VotePublic: votePublic, Safety: hotstuff.NewFHSSafetyState(), Records: make(map[string]*Record)}
			return state, nil
		}
		w.generation, w.currentPresent = generation, true
		name = generationStateName(generation)
	}
	f, err := openNoFollow(filepath.Join(w.dir, name), os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		if present {
			return state, errors.New("CURRENT names a missing WAL; rollback forbidden")
		}
		return diskState{Version: 1, Domain: domain, VotePublic: votePublic, Safety: hotstuff.NewFHSSafetyState(), Records: make(map[string]*Record)}, nil
	}
	if err != nil {
		return state, err
	}
	w.canonicalPresent = true
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxWALBytes+1))
	if err != nil {
		return state, err
	}
	if len(b) > maxWALBytes {
		return state, errors.New("DEX WAL exceeds bound")
	}
	var envelope walEnvelope
	if err = decodeStrict(b, &envelope); err != nil {
		return state, err
	}
	if state, err = decodeWALPayload(envelope); err != nil {
		return state, err
	}
	if w.generational {
		// decodeWALPayload already checks the version-specific payload and
		// checksum before expansion. Preserve the exact v4/v5 outer envelope;
		// do not re-encode expanded v5 records as a legacy v4 representation.
		canonical, e := json.Marshal(envelope)
		if e != nil || !bytes.Equal(canonical, b) {
			return state, errors.New("noncanonical generation WAL")
		}
		info, e := f.Stat()
		if e != nil || info.Mode() != 0600 || !ownedWALTemporary(info) {
			return state, errors.New("unsafe generation WAL")
		}
	}
	if w.generational && (state.Version != StorageGenerationVersion || state.Generation != generation || state.BaseHeight > MaxOperatingHeight) || !w.generational && state.Version == StorageGenerationVersion {
		return state, errors.New("generation configuration mismatch")
	}
	if !replayVersion(state.Version, state.ExecutionSchema) || state.Domain != domain || state.VotePublic != votePublic || state.Safety == nil || state.Records == nil || len(state.Records) > MaxRecords || len(state.Finalized) > MaxRecords {
		return state, errors.New("foreign/incompatible DEX WAL")
	}
	base := hotstuff.NewFHSSafetyState()
	if state.Safety.Version != base.Version || state.Safety.Domain != base.Domain {
		return state, errors.New("foreign FHS WAL schema")
	}
	return state, nil
}
func (w *walStore) save(state diskState) error {
	var payload []byte
	var err error
	version := state.Version
	if state.Version == StorageGenerationVersion {
		payload, err = generationWALPayload(state)
		version = generationDictionaryVersion
	} else if state.ExecutionSchema == RollingExecutionSchema {
		state.Version = 2
		state.Records, err = compactRecords(state.Records, state.Finalized)
		if err != nil {
			return err
		}
		packed, err := packDictionary(state)
		if err != nil {
			return err
		}
		payload, err = json.Marshal(packed)
		if err != nil {
			return err
		}
		version = 3
	} else {
		payload, err = json.Marshal(state)
	}
	if err != nil {
		return err
	}
	b, err := json.Marshal(walEnvelope{Payload: payload, Checksum: protocol.Digest(walDigestDomain(version), payload)})
	if err != nil {
		return err
	}
	if len(b) > maxWALBytes {
		return errors.New("DEX WAL byte budget exhausted")
	}
	f, err := openNoFollow(filepath.Join(w.dir, walPendingName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	// The private hook allows an actual SIGKILL after an incomplete generation.
	// Normal execution writes the same bytes without exposing a configurable
	// process hook, signer callback or alternate recovery source.
	if w.afterTemporaryChunk != nil {
		middle := len(b) / 2
		if _, err = f.Write(b[:middle]); err == nil {
			err = w.afterTemporaryChunk()
		}
		if err == nil {
			_, err = f.Write(b[middle:])
		}
	} else {
		_, err = f.Write(b)
	}
	if err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	target := "state.json"
	if state.Version == StorageGenerationVersion {
		target = generationStateName(state.Generation)
	}
	if err = os.Rename(name, filepath.Join(w.dir, target)); err != nil {
		return err
	}
	d, err := os.Open(w.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return err
	}
	if state.Version == StorageGenerationVersion && (!w.currentPresent || w.generation != state.Generation) {
		if w.generationFault != nil {
			if err = w.generationFault("hot-durable"); err != nil {
				return err
			}
		}
		old := w.generation
		if err = w.publishCurrent(state.Generation); err != nil {
			return err
		}
		wasPresent := w.currentPresent
		w.generation, w.currentPresent = state.Generation, true
		if w.generationFault != nil {
			if err = w.generationFault("current-durable"); err != nil {
				return err
			}
		}
		if wasPresent && old != state.Generation {
			if err = os.Remove(filepath.Join(w.dir, generationStateName(old))); err != nil {
				return err
			}
			if err = d.Sync(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *Application) persist() error {
	if err := a.check(); err != nil {
		return err
	}
	// Open reaches its first persist only after canonical recovery and its own
	// RestoreVote/finalized-execution callbacks. Never clean debris while a
	// canonical state or external safety record is still unauthenticated.
	if a.wal.cleanupPending {
		if !a.wal.recoveryVerified {
			return errors.New("DEX WAL cleanup before authenticated recovery")
		}
		if err := a.wal.cleanupTemporary(); err != nil {
			a.fatal = fmt.Errorf("DEX WAL temporary recovery failed; signing disabled: %w", err)
			return a.fatal
		}
		a.wal.cleanupPending = false
	}
	if err := a.rotateStorage(); err != nil {
		if errors.Is(err, ErrStorageCapacity) {
			a.storageBlocked = true
		} else {
			a.fatal = fmt.Errorf("DEX archive persistence failed; signing disabled: %w", err)
			return a.fatal
		}
	}
	if err := a.wal.save(a.disk); err != nil {
		a.fatal = fmt.Errorf("DEX persistence failed; signing disabled: %w", err)
		return a.fatal
	}
	return nil
}
func (a *Application) recordForQC(q *hotstuff.SignedState) *Record {
	if q == nil {
		return nil
	}
	r, err := types.DecodeHotstuffProposalRef(q.State)
	if err != nil {
		return nil
	}
	return a.lookupRecord(r)
}
func (a *Application) parentQC(ref *types.HotstuffProposalRef) (*hotstuff.SignedState, error) {
	if ref.Number == 1 {
		if ref.ParentHash != a.genesisHash() || ref.ParentQCID != (common.Hash{}) {
			return nil, errors.New("invalid DEX genesis parent")
		}
		return nil, nil
	}
	for _, r := range a.disk.Records {
		if r.QC == nil {
			continue
		}
		id, err := hotstuff.SignedStateID(r.QC)
		if err != nil {
			return nil, err
		}
		if id.Hash() == ref.ParentQCID {
			return r.QC, nil
		}
	}
	if a.config.StorageGenerations && !a.archiveReplay && ref.Number > 1 && ref.Number-1 <= a.disk.BaseHeight {
		r, _, err := a.archived(ref.Number - 1)
		if err != nil {
			return nil, err
		}
		if r.QC != nil {
			id, err := hotstuff.SignedStateID(r.QC)
			if err == nil && id.Hash() == ref.ParentQCID {
				return r.QC, nil
			}
		}
	}
	return nil, ErrUnavailable
}
func (a *Application) recover() error {
	if a.config.StorageGenerations {
		if err := a.recoverArchive(); err != nil {
			return err
		}
	}
	if err := compactLayout(a.disk.Version, a.disk.Records, a.disk.Finalized); err != nil {
		return err
	}
	if a.disk.SnapshotOrigin != "" {
		decoded, err := hex.DecodeString(a.disk.SnapshotOrigin)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != a.disk.SnapshotOrigin || len(a.disk.Finalized) == 0 {
			return errors.New("invalid local bootstrap provenance")
		}
	}
	records := make([]*Record, 0, len(a.disk.Records))
	for key, r := range a.disk.Records {
		if r == nil || len(r.Ref) == 0 || len(r.Ref) > checkpoint.MaxRefBytes {
			return errors.New("nil DEX record")
		}
		ref, err := types.DecodeHotstuffProposalRef(r.Ref)
		if err != nil {
			return err
		}
		if key != ref.ProposalID().Hex() {
			return errors.New("DEX record key mismatch")
		}
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Checkpoint.LastBlock < records[j].Checkpoint.LastBlock })
	for _, r := range records {
		ref, _ := types.DecodeHotstuffProposalRef(r.Ref)
		parent, err := a.parentQC(ref)
		if err != nil {
			return err
		}
		compareState := a.disk.Version != 2 || r.State != nil
		if err = a.validateRecordState(r, parent, compareState); err != nil {
			return err
		}
		if a.disk.Version == 2 {
			if err = replayStateBudget(a.disk.Records); err != nil {
				return err
			}
		}
		if r.QC != nil {
			if !bytes.Equal(r.Ref, r.QC.State) {
				return errors.New("DEX record QC mismatch")
			}
			if err = a.verifyQC(r.QC); err != nil {
				return err
			}
		}
	}
	if q := a.disk.Safety.HighestQC; q != nil {
		if err := a.verifyQC(q); err != nil {
			return err
		}
		if r := a.recordForQC(q); r == nil || r.QC == nil {
			return ErrUnavailable
		}
	}
	for i, f := range a.disk.Finalized {
		r := a.disk.Records[f.Key]
		if r == nil || r.Checkpoint.Sequence != a.disk.BaseHeight+uint64(i+1) {
			return errors.New("DEX finality record gap")
		}
		hash, err := r.Checkpoint.Hash()
		if err != nil || f.Hash != common.Hash(hash).Hex() {
			return errors.New("DEX finalized hash mismatch")
		}
		if _, err = a.epoch.Verify(r.Checkpoint, f.Proof); err != nil {
			return err
		}
		if i > 0 && r.Checkpoint.Previous != protocol.Hash(common.HexToHash(a.disk.Finalized[i-1].Hash)) {
			return errors.New("DEX finalized branch mismatch")
		}
		if i == 0 && a.disk.BaseHeight > 0 {
			_, base, err := a.finalizedRecordAt(a.disk.BaseHeight)
			if err != nil || r.Checkpoint.Previous != protocol.Hash(common.HexToHash(base.Hash)) {
				return errors.New("hot finality does not extend archived cut")
			}
		}
	}
	if v := a.disk.Safety.LastVote; v != nil {
		r, err := types.DecodeHotstuffProposalRef(v.ProposalRef)
		if err != nil {
			return err
		}
		if r.ViewNumber != v.ViewNumber || r.ViewID != v.ViewID || r.LeaderID != v.LeaderID || r.ProposalID() != v.ProposalID || hotstuff.StateDigest(v.ProposalRef) != v.ProposalRefHash || a.disk.Records[r.ProposalID().Hex()] == nil {
			return errors.New("invalid durable DEX vote")
		}
	}
	if t := a.disk.Safety.HighestTC; t != nil {
		if err := timeoutShape(t); err != nil {
			return err
		}
		if err := a.validTimeout(&t.Statement); err != nil {
			return err
		}
		if err := hotstuff.VerifyTimeoutCertificate(t, a.keys, 5); err != nil {
			return err
		}
		if a.disk.Safety.LastTimeoutView != t.Statement.TimedOutView {
			return errors.New("timeout watermark mismatch")
		}
	} else if a.disk.Safety.LastTimeoutView != 0 {
		return errors.New("missing durable TC")
	}
	if s := a.disk.Safety.LastTimeoutVote; s != nil {
		if err := a.validTimeout(s); err != nil {
			return err
		}
		if s.TimedOutView < a.CurrentN() {
			return errors.New("stale durable timeout")
		}
	}
	if q := a.disk.Outbox; q != nil {
		if q.LeaderID != a.Self() {
			return errors.New("foreign DEX outbox")
		}
		if err := a.verifyQC(q); err != nil {
			return err
		}
		if a.recordForQC(q) == nil {
			return ErrUnavailable
		}
	}
	a.wal.recoveryVerified = true
	return nil
}
