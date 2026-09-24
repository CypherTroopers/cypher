package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

const MaxSnapshotBytes = maxWALBytes

type replaySnapshot struct {
	Version         uint16
	Domain          protocol.Domain
	Records         map[string]*Record
	Finalized       []finalizedRecord
	ExecutionID     string
	ExecutionSchema uint16
	GenesisState    []byte
	GenesisRoot     protocol.Hash
}

// ExportSnapshot returns authenticated replay content, never local votes, secret
// keys or timeout watermarks. Possessing a data hash alone cannot produce this.
func (a *Application) ExportSnapshot() ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if a.config.StorageGenerations {
		return nil, errors.New("generation snapshot requires authenticated archive transfer; single-file export unavailable")
	}
	s := replaySnapshot{Version: 1, Domain: a.config.Domain, Records: make(map[string]*Record), Finalized: a.disk.Finalized}
	s.ExecutionID, s.ExecutionSchema = a.disk.ExecutionID, a.disk.ExecutionSchema
	s.GenesisState, s.GenesisRoot = a.disk.GenesisState, a.disk.GenesisRoot
	for k, r := range a.disk.Records {
		if r.QC != nil {
			s.Records[k] = r
		}
	}
	if s.ExecutionSchema == RollingExecutionSchema {
		s.Version = 2
		var err error
		s.Records, err = compactRecords(s.Records, s.Finalized)
		if err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(b) > maxWALBytes {
		return nil, errors.New("snapshot exceeds DEX byte bound")
	}
	return b, nil
}

// ExportSnapshotAt deliberately serves only the actual finalized tip. The
// certified descendants required to prove that tip remain in the replay data.
func (a *Application) ExportSnapshotAt(height uint64) ([]byte, error) {
	if height == 0 || height != a.FinalizedHeight() {
		return nil, errors.New("snapshot height is not the current finalized tip")
	}
	return a.ExportSnapshot()
}

func snapshotOrigin(data []byte) string {
	h := protocol.Digest("common-dex/bootstrap-snapshot/v1", data)
	return hex.EncodeToString(h[:])
}

// BootstrapSnapshot is idempotent only for the exact locally recorded import.
// It never replaces or rewinds an existing voter's records or own safety state.
func (a *Application) BootstrapSnapshot(data []byte) error {
	if err := a.check(); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxSnapshotBytes {
		return errors.New("snapshot byte bound")
	}
	if a.disk.SnapshotOrigin != "" {
		if a.disk.SnapshotOrigin != snapshotOrigin(data) {
			return errors.New("different bootstrap snapshot origin")
		}
		return nil
	}
	var candidate replaySnapshot
	if err := decodeStrict(data, &candidate); err != nil || len(candidate.Finalized) == 0 {
		return errors.New("bootstrap requires an actual finalized snapshot")
	}
	return a.ImportSnapshot(data)
}

// ImportSnapshot is only for a new, empty syncing instance. Every body is
// reexecuted and every supplied QC/finality proof checked before state is saved.
// A voter must never replace its durable safety watermarks with a peer snapshot.
func (a *Application) ImportSnapshot(data []byte) error {
	if err := a.check(); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxWALBytes {
		return errors.New("snapshot byte bound")
	}
	if a.config.StorageGenerations {
		return errors.New("legacy snapshot cannot bootstrap generation storage")
	}
	if a.started || len(a.disk.Records) != 0 || a.disk.Safety.LastVote != nil || a.disk.Safety.HighestQC != nil || a.disk.Safety.HighestTC != nil || a.disk.Safety.LastTimeoutVote != nil {
		return errors.New("snapshot cannot replace an existing voter WAL")
	}
	var s replaySnapshot
	if err := decodeStrict(data, &s); err != nil {
		return err
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("noncanonical snapshot encoding")
	}
	if s.Version == StorageGenerationVersion || !replayVersion(s.Version, s.ExecutionSchema) || s.Domain != a.config.Domain || s.Records == nil || len(s.Records) > MaxRecords || len(s.Finalized) > MaxRecords {
		return errors.New("foreign/oversized snapshot")
	}
	if s.ExecutionID != a.disk.ExecutionID || s.ExecutionSchema != a.disk.ExecutionSchema || s.GenesisRoot != a.disk.GenesisRoot || !bytes.Equal(s.GenesisState, a.disk.GenesisState) {
		return errors.New("foreign snapshot execution configuration")
	}
	next := diskState{Version: s.Version, Domain: s.Domain, VotePublic: a.disk.VotePublic, Safety: hotstuff.NewFHSSafetyState(), Records: s.Records, Finalized: s.Finalized}
	next.SnapshotOrigin = snapshotOrigin(data)
	next.ExecutionID, next.ExecutionSchema = a.disk.ExecutionID, a.disk.ExecutionSchema
	next.GenesisState, next.GenesisRoot = append([]byte(nil), a.disk.GenesisState...), a.disk.GenesisRoot
	for _, r := range s.Records {
		if r == nil || r.QC == nil {
			return errors.New("uncertified snapshot record")
		}
		if next.Safety.HighestQC == nil || r.QC.Number > next.Safety.HighestQC.Number {
			next.Safety.HighestQC = hotstuff.CloneSignedState(r.QC)
		} else if r.QC.Number == next.Safety.HighestQC.Number && !hotstuff.SignedStateSemanticEqual(r.QC, next.Safety.HighestQC) {
			return errors.New("conflicting snapshot highest QC")
		}
	}
	old := a.disk
	a.disk = next
	if err := a.recover(); err != nil {
		a.disk = old
		return err
	}
	a.selected = hotstuff.CloneSignedState(a.disk.Safety.HighestQC)
	if err := a.persist(); err != nil {
		return err
	}
	return a.reconcileFinalizedExecution()
}

// ProposalData retrieves a complete record by the authenticated proposal ID.
// Absence remains an explicit unavailable error rather than a successful hash ACK.
func (a *Application) ProposalData(id string) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	r := a.disk.Records[id]
	if r == nil {
		return nil, ErrUnavailable
	}
	return json.Marshal(r)
}

func (a *Application) extendsFinalized(q *hotstuff.SignedState) error {
	if a.FinalizedHeight() == 0 {
		return nil
	}
	if q == nil {
		return errors.New("proposal parent precedes finalized state")
	}
	for count := 0; count < MaxRecords; count++ {
		r := a.recordForQC(q)
		if r == nil {
			return ErrUnavailable
		}
		if r.Checkpoint.LastBlock < a.FinalizedHeight() {
			return errors.New("proposal precedes finalized state")
		}
		if r.Checkpoint.LastBlock == a.FinalizedHeight() {
			ref, err := types.DecodeHotstuffProposalRef(r.Ref)
			if err != nil {
				return err
			}
			_, f, err := a.finalizedRecordAt(a.FinalizedHeight())
			if err != nil {
				return err
			}
			if ref.BlockHash.Hex() != f.Hash {
				return errors.New("proposal conflicts with finalized branch")
			}
			return nil
		}
		ref, err := types.DecodeHotstuffProposalRef(r.Ref)
		if err != nil {
			return err
		}
		q, err = a.parentQC(ref)
		if err != nil {
			return err
		}
	}
	return errors.New("DEX ancestry bound exceeded")
}
