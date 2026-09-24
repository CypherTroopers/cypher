package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

const maxCertifiedPlanningRecords = 128

// Certified planning is disposable scheduling data, never a completion proof
// or trust root. No raw financial state or action is executed/imported here.
// The QC authenticates the checkpoint's post-state commitment, and independently
// verified CLX history authenticates every planned inbox boundary.
type certifiedPlanningRecord struct {
	Checkpoint protocol.Checkpoint
	QC         *hotstuff.SignedState
	Ref        []byte
}

func (n *Network) readCertifiedPlanning(ctx context.Context, height uint64) (certifiedPlanningRecord, error) {
	var result certifiedPlanningRecord
	var response struct{ Record json.RawMessage }
	if err := n.json(ctx, http.MethodGet, n.cfg.DEXURL+"/v1/certified?height="+strconv.FormatUint(height, 10)+"&selected=true", nil, &response, 256*1024); err != nil {
		return result, err
	}
	if len(response.Record) == 0 || len(response.Record) > 128*1024 {
		return result, errors.New("certified planning record byte bound")
	}
	if err := json.Unmarshal(response.Record, &result); err != nil {
		return result, err
	}
	if result.QC == nil || !bytes.Equal(result.Ref, result.QC.State) || result.Checkpoint.Sequence != height || height > n.cfg.MaxHeight || result.Checkpoint.DataSchema != n.expectedCheckpointSchema() {
		return result, errors.New("certified planning record binding")
	}
	if _, err := n.epoch.VerifyCertified(result.Checkpoint, result.QC); err != nil {
		return result, err
	}
	return result, nil
}

func (n *Network) planningGenesisHash() (common.Hash, error) {
	id := map[uint16]string{4: "BTC-CLX-native-finance-v5", 5: "BTC-CLX-native-finance-v6", 6: "BTC-CLX-native-finance-v6-history-v1"}[n.expectedCheckpointSchema()]
	if id == "" {
		return common.Hash{}, errors.New("certified planning execution schema unsupported")
	}
	key := n.cfg.Relay.Domain.EpochKey()
	b := append([]byte(nil), key[:]...)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(id)))
	b = append(b, size[:]...)
	b = append(b, id...)
	b = append(b, n.genesisRoot[:]...)
	return common.Hash(protocol.Digest("common-dex/execution-genesis/v1", b)), nil
}

func (n *Network) finalizedPlanningParent() (certifiedPlanningRecord, error) {
	if n.bundleCount() == 0 {
		return certifiedPlanningRecord{}, nil
	}
	bundle, _, err := n.bundleAt(n.bundleCount())
	if err != nil {
		return certifiedPlanningRecord{}, err
	}
	proof, err := checkpoint.DecodeProof(bundle.Proof())
	if err != nil {
		return certifiedPlanningRecord{}, err
	}
	return certifiedPlanningRecord{Checkpoint: bundle.Checkpoint(), QC: proof.Target, Ref: proof.Target.State}, nil
}

func (n *Network) planningLink(parent, child certifiedPlanningRecord) error {
	cp := child.Checkpoint
	pre, previous, cursor, sourceHeight := n.genesisRoot, protocol.Hash{}, uint64(0), uint64(0)
	parentHash, err := n.planningGenesisHash()
	if err != nil {
		return err
	}
	var parentQCID common.Hash
	if parent.QC != nil {
		pre, cursor, sourceHeight = parent.Checkpoint.PostRoot, parent.Checkpoint.InboxEnd, parent.Checkpoint.CLXHeight
		previous, _ = parent.Checkpoint.Hash()
		parentHash = common.Hash(previous)
		id, err := hotstuff.SignedStateID(parent.QC)
		if err != nil {
			return err
		}
		parentQCID = id.Hash()
	}
	ref, err := types.DecodeHotstuffProposalRef(child.Ref)
	if err != nil {
		return err
	}
	if cp.Sequence != parent.Checkpoint.Sequence+1 || cp.PreRoot != pre || cp.Previous != previous || cp.InboxStart != cursor || cp.CLXHeight < sourceHeight || ref.ParentHash != parentHash || ref.ParentQCID != parentQCID || parent.QC != nil && child.QC.Number <= parent.QC.Number {
		return errors.New("certified planning parent/root/cursor continuity")
	}
	return nil
}

func (n *Network) refreshCertifiedPlanning(ctx context.Context) (err error) {
	if !n.cfg.CertifiedInboxPlanning {
		return nil
	}
	defer func() {
		if err != nil && !errors.Is(err, errCertifiedPlanningCatchup) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, source.ErrUnavailable) {
			// A changed branch is rediscovered from the authenticated finalized
			// prefix on a later tick; never bless the RPC's claimed new head.
			n.certifiedPlanning = nil
		}
		// A request deadline or source outage does not invalidate the fully
		// authenticated prefix already stored here. Keep it for the next bounded
		// tick (which rechecks its tip), but still return the error and plan no
		// action from an incomplete prefix.
	}()
	var status struct{ Certified, Finalized uint64 }
	if err = n.json(ctx, http.MethodGet, n.cfg.DEXURL+"/v1/status", nil, &status, 65536); err != nil {
		return err
	}
	if status.Certified > n.cfg.MaxHeight || status.Finalized > n.cfg.MaxHeight {
		return errors.New("certified planning discovery bound")
	}
	parent, err := n.finalizedPlanningParent()
	if err != nil {
		return err
	}
	baseHeight := parent.Checkpoint.Sequence
	if status.Certified <= baseHeight {
		n.certifiedPlanning = nil
		return nil
	}
	if status.Certified-baseHeight > maxCertifiedPlanningRecords {
		return ErrCapacity
	}
	kept := n.certifiedPlanning[:0]
	for _, record := range n.certifiedPlanning {
		if record.Checkpoint.Sequence == baseHeight && (!hotstuff.SignedStateSemanticEqual(record.QC, parent.QC) || record.Checkpoint != parent.Checkpoint) {
			return errors.New("certified planning conflicts with finalized prefix")
		}
		if record.Checkpoint.Sequence > baseHeight {
			if record.Checkpoint.Sequence > status.Certified || n.planningLink(parent, record) != nil {
				return errors.New("certified planning cached branch changed")
			}
			kept = append(kept, record)
			parent = record
		}
	}
	n.certifiedPlanning = kept
	work := 0
	if len(kept) > 0 {
		// Verify that the endpoint still serves the same selected certified
		// tip before extending a non-final branch from disposable cache.
		current, e := n.readCertifiedPlanning(ctx, parent.Checkpoint.Sequence)
		if e != nil {
			return e
		}
		work++
		if current.Checkpoint != parent.Checkpoint || !hotstuff.SignedStateSemanticEqual(current.QC, parent.QC) {
			return errors.New("certified planning tip changed")
		}
	}
	for parent.Checkpoint.Sequence < status.Certified && work < 8 {
		record, e := n.readCertifiedPlanning(ctx, parent.Checkpoint.Sequence+1)
		if e != nil {
			return e
		}
		work++
		if err = n.planningLink(parent, record); err != nil {
			return err
		}
		anchor, e := n.Source.AnchorAt(ctx, record.Checkpoint.CLXHeight, record.Checkpoint.CLXHash)
		if e != nil {
			return e
		}
		if record.Checkpoint.InboxEnd > anchor.InboxCount {
			return errors.New("certified planning cursor exceeds authenticated source")
		}
		var entries []protocol.InboxEntry
		if count := record.Checkpoint.InboxEnd - record.Checkpoint.InboxStart; count > 0 {
			entries, e = n.Source.Entries(ctx, anchor, record.Checkpoint.InboxStart, count)
			if e != nil {
				return e
			}
		}
		root, e := protocol.InboxEntriesRoot(entries)
		if e != nil || root != record.Checkpoint.InboxRoot {
			return errors.New("certified planning inbox commitment differs from source")
		}
		n.certifiedPlanning = append(n.certifiedPlanning, record)
		parent = record
	}
	// Do not plan on an intermediate prefix while the actual selected parent
	// is still unavailable. Subsequent ticks continue bounded authentication.
	if parent.Checkpoint.Sequence < status.Certified {
		return errCertifiedPlanningCatchup
	}
	return nil
}

var errCertifiedPlanningCatchup = errors.New("certified planning bounded catch-up pending")

func (n *Network) inboxPlanningBase(ctx context.Context) (clxevidence.Anchor, uint64, error) {
	base, err := n.verifier.BootstrapAnchor()
	if err != nil {
		return base, 0, err
	}
	var cp protocol.Checkpoint
	if len(n.certifiedPlanning) > 0 && n.cfg.CertifiedInboxPlanning {
		cp = n.certifiedPlanning[len(n.certifiedPlanning)-1].Checkpoint
	} else if n.bundleCount() > 0 {
		cp, err = n.bundleCP(n.bundleCount())
		if err != nil {
			return base, 0, err
		}
	}
	if cp.Sequence == 0 {
		return base, 0, nil
	}
	if cp.Sequence >= n.cfg.MaxHeight {
		return base, 0, ErrCapacity
	}
	base, err = n.Source.AnchorAt(ctx, cp.CLXHeight, cp.CLXHash)
	if err == nil && cp.InboxEnd > base.InboxCount {
		err = errors.New("certified planning cursor outside source inbox")
	}
	return base, cp.InboxEnd, err
}
