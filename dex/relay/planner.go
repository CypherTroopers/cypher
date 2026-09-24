package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/dex/settlement"
)

func enqueuePlanned(r *Relay, j Job) error {
	for _, record := range r.Status() {
		if record.Job.ID != j.ID {
			continue
		}
		if record.Phase == "complete" || record.Attempt.GasLimit != 0 {
			return nil
		}
		if bytes.Equal(record.Job.Payload, j.Payload) && bytes.Equal(record.Job.Authorization, j.Authorization) {
			return nil
		}
		return r.ReplaceUnsent(j)
	}
	return r.Enqueue(j)
}

// Discover performs bounded discovery per tick. Failed source reads do not
// mutate a trusted root or stop independent already-authorized relay work.
func (n *Network) Discover(ctx context.Context, r *Relay) error {
	_, sourceErr := n.Source.Advance(ctx)
	dexErr := n.refreshDEX(ctx)
	at := n.Source.Current()
	p := proofObservation{}
	words, err := n.slots(ctx, at, []common.Hash{settlement.CheckpointSequenceStorageKey(), settlement.RollingMetadataStorageKey()}, &p)
	if err != nil {
		return errors.Join(sourceErr, dexErr, err)
	}
	accepted, err := wordUint(words[0])
	if err != nil {
		return err
	}
	if accepted > n.cfg.MaxHeight {
		return errors.New("authenticated checkpoint sequence exceeds relay operating budget")
	}
	meta, err := metaWord(words[1])
	if err != nil {
		return err
	}
	n.clxSequence, n.clxSequenceVerified = accepted, true
	var errs []error
	if n.archive != nil {
		if e := n.planContinuousBundles(ctx, r, at, meta, accepted); e != nil {
			errs = append(errs, e)
		}
	} else {
		for i, b := range n.bundles {
			cp := b.Checkpoint()
			if cp.Sequence > accepted+8 {
				break
			}
			hash, _ := cp.Hash()
			if cp.Sequence > accepted {
				if cp.Sequence == accepted+1 {
					if e := n.planAnchor(ctx, r, at, meta, cp.CLXHeight, cp.CLXHash); e != nil {
						errs = append(errs, e)
					}
				}
				call, e := protocol.EncodeNativeCheckpoint(cp, b.Finance(), b.Proof(), nil)
				if e != nil {
					return e
				}
				job := Job{Version: 1, Lane: Checkpoint, ID: BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Checkpoint, hash), Payload: call, Authorization: bytes.Clone(n.bundleBytes[i])}
				if e = enqueuePlanned(r, job); e != nil {
					errs = append(errs, e)
				}
			}
			for _, path := range append(b.Withdrawals(), b.Rewards()...) {
				deferClaim := false
				for _, who := range n.cfg.DeferredRecipients {
					deferClaim = deferClaim || who == common.Address(path.Claim.Recipient)
				}
				if deferClaim {
					continue
				}
				leaf, _ := path.Claim.Hash()
				call, e := protocol.EncodeNativeClaim(path.Claim, path.Index, path.Count, path.Siblings)
				if e != nil {
					return e
				}
				job := Job{Version: 1, Lane: Claim, ID: BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Claim, leaf), Payload: call, Authorization: bytes.Clone(n.bundleBytes[i]), Owner: common.Address(path.Claim.Owner)}
				if e = enqueuePlanned(r, job); e != nil {
					errs = append(errs, e)
				}
			}
		}
	}
	if n.cfg.AutoInbox {
		if e := n.planInbox(ctx, r, at); e != nil {
			errs = append(errs, e)
		}
	}
	return errors.Join(append(errs, sourceErr, dexErr)...)
}

// The independent checkpoint lane advances up to eight records per tick while
// a round-robin claim cursor revisits all authenticated old rights. Deferred or
// paid claims remain in the archive; local scanning state is not a nullifier.
func (n *Network) planContinuousBundles(ctx context.Context, r *Relay, at clxevidence.Anchor, meta settlement.RollingStatus, accepted uint64) error {
	var errs []error
	for h := accepted + 1; h <= n.bundleCount() && h <= accepted+8; h++ {
		b, raw, err := n.bundleAt(h)
		if err != nil {
			return err
		}
		cp := b.Checkpoint()
		if h == accepted+1 {
			if e := n.planAnchor(ctx, r, at, meta, cp.CLXHeight, cp.CLXHash); e != nil {
				errs = append(errs, e)
			}
		}
		hash, _ := cp.Hash()
		call, e := protocol.EncodeNativeCheckpoint(cp, b.Finance(), b.Proof(), nil)
		if e != nil {
			return e
		}
		job := Job{Version: 1, Lane: Checkpoint, ID: BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Checkpoint, hash), Payload: call, Authorization: raw}
		if e = enqueuePlanned(r, job); e != nil {
			errs = append(errs, e)
		}
	}
	end := accepted
	if end > n.bundleCount() {
		end = n.bundleCount()
	}
	if end == 0 {
		return errors.Join(errs...)
	}
	if n.claimSequence == 0 || n.claimSequence > end {
		n.claimSequence, n.claimOffset = 1, 0
	}
	scanned, work := 0, 0
	for scanned < 8 && work < 8 {
		b, raw, err := n.bundleAt(n.claimSequence)
		if err != nil {
			return err
		}
		paths := append(b.Withdrawals(), b.Rewards()...)
		for n.claimOffset < len(paths) && work < 8 {
			path := paths[n.claimOffset]
			n.claimOffset++
			work++
			deferClaim := false
			for _, who := range n.cfg.DeferredRecipients {
				deferClaim = deferClaim || who == common.Address(path.Claim.Recipient)
			}
			if deferClaim {
				continue
			}
			leaf, _ := path.Claim.Hash()
			call, e := protocol.EncodeNativeClaim(path.Claim, path.Index, path.Count, path.Siblings)
			if e != nil {
				return e
			}
			job := Job{Version: 1, Lane: Claim, ID: BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Claim, leaf), Payload: call, Authorization: bytes.Clone(raw), Owner: common.Address(path.Claim.Owner)}
			if e = enqueuePlanned(r, job); e != nil {
				errs = append(errs, e)
			}
		}
		if n.claimOffset < len(paths) {
			break
		}
		n.claimOffset = 0
		n.claimSequence++
		scanned++
		if n.claimSequence > end {
			n.claimSequence = 1
			break
		}
	}
	return errors.Join(errs...)
}

func (n *Network) anchorJob(e clxevidence.RollingEvidence, continuation []clxevidence.HeaderWitness, target clxevidence.Anchor) (Job, error) {
	call, err := settlement.EncodeNativeAnchorUpdate(e, continuation)
	if err != nil {
		return Job{}, err
	}
	auth, err := target.Encode()
	if err != nil {
		return Job{}, err
	}
	id, _ := target.ID()
	return Job{Version: 1, Lane: Anchor, ID: BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Anchor, id), Payload: call, Authorization: auth}, nil
}

func (n *Network) planAnchor(ctx context.Context, r *Relay, at clxevidence.Anchor, meta settlement.RollingStatus, height uint64, hash protocol.Hash) error {
	p := proofObservation{}
	existing, found, err := n.storedAnchor(ctx, at, height, &p)
	if err != nil {
		return err
	}
	if found && existing.BlockHash != hash {
		return errors.New("finalized DEX source conflicts with CLX retained anchor")
	}
	if found && height <= meta.ConfirmedThrough {
		return nil
	}
	if meta.Records >= settlement.MaxNativeAnchors {
		return ErrCapacity
	}
	if !found && height < meta.TipHeight {
		return n.planHistorical(ctx, r, at, height, hash)
	}
	base, foundBase, err := n.storedAnchor(ctx, at, meta.TipHeight, &p)
	if err != nil || !foundBase {
		return errors.New("rolling tip unavailable")
	}
	targetHeight := height
	if found {
		targetHeight = base.Height + 32
	}
	if targetHeight > base.Height+32 {
		targetHeight = base.Height + 32
	}
	if targetHeight > at.Height {
		targetHeight = at.Height
	}
	if targetHeight <= base.Height {
		return errors.New("source must advance before anchor confirmation")
	}
	for targetHeight > base.Height {
		e, target, err := n.Source.BuildRange(ctx, base, targetHeight, 0, nil)
		if err != nil {
			return err
		}
		if targetHeight == height && target.BlockHash != hash {
			return errors.New("DEX source reference differs from authenticated CLX chain")
		}
		job, err := n.anchorJob(e, nil, target)
		if err == nil {
			return enqueuePlanned(r, job)
		}
		if targetHeight == base.Height+1 {
			return err
		}
		targetHeight = base.Height + (targetHeight-base.Height)/2
	}
	return errors.New("anchor byte budget unavailable")
}

// Adjacent retained targets have gaps of at most64 source heights. Probe only
// that fixed interval with batches of at most32 MPT slots, never a chain scan.
func (n *Network) planHistorical(ctx context.Context, r *Relay, at clxevidence.Anchor, height uint64, hash protocol.Hash) error {
	lo := uint64(0)
	if height > 64 {
		lo = height - 64
	}
	hi := height + 64
	if hi < height {
		return ErrInvalidJob
	}
	if hi > at.Height {
		hi = at.Height
	}
	baseHeight, descHeight := uint64(0), uint64(0)
	for first := lo; first <= hi; {
		var keys []common.Hash
		var heights []uint64
		for first <= hi && len(keys) < 32 {
			h := first
			first++
			if h == 0 || h == height {
				continue
			}
			slots, _ := settlement.RollingAnchorStorageKeys(h)
			keys = append(keys, slots[8])
			heights = append(heights, h)
		}
		if len(keys) == 0 {
			break
		}
		p := proofObservation{}
		words, err := n.slots(ctx, at, keys, &p)
		if err != nil {
			return err
		}
		for i, w := range words {
			h := heights[i]
			if w == (common.Hash{}) {
				continue
			}
			if h < height && h > baseHeight {
				baseHeight = h
			}
			if h > height && (descHeight == 0 || h < descHeight) {
				descHeight = h
			}
		}
	}
	if descHeight == 0 || descHeight-baseHeight > 64 {
		return errors.New("bounded historical anchor endpoints unavailable")
	}
	p := proofObservation{}
	base, found, err := n.storedAnchor(ctx, at, baseHeight, &p)
	if err != nil || !found {
		return errors.New("historical base unavailable")
	}
	e, target, err := n.historicalRange(ctx, base, height)
	if err != nil {
		return err
	}
	if target.BlockHash != hash {
		return errors.New("historical fork reference")
	}
	after, _, err := n.historicalRange(ctx, target, descHeight)
	if err != nil {
		return err
	}
	if len(e.KeyHeader) == 0 && len(after.KeyHeader) > 0 {
		e.SetKeyContext(after.KeyContext())
		_, checked, err := n.verifier.VerifyRolling(base, 0, e)
		if err != nil || checked != target {
			return errors.New("historical key context continuity mismatch")
		}
	}
	job, err := n.anchorJob(e, after.Headers, target)
	if err != nil {
		return err
	}
	return enqueuePlanned(r, job)
}

// historicalRange composes bounded source requests without increasing either
// the source's32-header request bound or G1's64-header complete proof bound.
func (n *Network) historicalRange(ctx context.Context, base clxevidence.Anchor, targetHeight uint64) (clxevidence.RollingEvidence, clxevidence.Anchor, error) {
	var combined clxevidence.RollingEvidence
	if targetHeight <= base.Height || targetHeight-base.Height > clxevidence.MaxAncestryBlocks {
		return combined, clxevidence.Anchor{}, ErrInvalidJob
	}
	original := base
	var headers []clxevidence.HeaderWitness
	var context clxevidence.KeyContext
	for base.Height < targetHeight {
		next := targetHeight
		if next-base.Height > source.MaxSegmentHeaders {
			next = base.Height + source.MaxSegmentHeaders
		}
		segment, target, err := n.Source.BuildRange(ctx, base, next, 0, nil)
		if err != nil {
			return combined, clxevidence.Anchor{}, err
		}
		if len(context.KeyHeader) == 0 && len(segment.KeyHeader) > 0 {
			context = segment.KeyContext()
		}
		headers = append(headers, segment.Headers...)
		combined, base = segment, target
	}
	combined.Base, _ = original.ID()
	combined.Headers = headers
	combined.SetKeyContext(context)
	_, target, err := n.verifier.VerifyRolling(original, 0, combined)
	return combined, target, err
}

func (n *Network) planInbox(ctx context.Context, r *Relay, at clxevidence.Anchor) error {
	// A stale hint never survives failed discovery as a claim of readiness.
	r.prioritizeInbox(protocol.Hash{})
	if err := n.refreshCertifiedPlanning(ctx); err != nil {
		return err
	}
	base, cursor, err := n.inboxPlanningBase(ctx)
	if err != nil {
		return err
	}
	// Keep every submitted intent until finalized completion. A certified
	// predecessor may nevertheless authorize planning the next bounded source
	// segment, otherwise waiting for its child finality creates a circular wait.
	for _, record := range r.Status() {
		if record.Job.Lane == Inbox && record.Phase != "complete" && record.Phase != "quarantined" {
			if !n.cfg.CertifiedInboxPlanning || len(n.certifiedPlanning) == 0 {
				return nil
			}
			target, e := clxevidence.DecodeAnchor(record.Job.Authorization)
			if e != nil {
				return e
			}
			if target.Height > base.Height || target.Height == base.Height && target.BlockHash != base.BlockHash {
				// The previously planned next range is still outstanding. Rebuild
				// its scheduling eligibility from the authenticated parent/proof,
				// not its queued/submitted label or a local claimed cursor.
				proof, e := clxevidence.DecodeRollingEvidence(record.Job.Payload[4:])
				if e != nil {
					return e
				}
				baseID, _ := base.ID()
				if proof.Base == baseID {
					_, checked, e := n.verifier.VerifyRolling(base, cursor, proof)
					if e != nil || checked != target {
						return errors.Join(ErrInvalidJob, e)
					}
					r.prioritizeInbox(record.Job.ID)
				}
				return nil
			}
			proof, e := clxevidence.DecodeRollingEvidence(record.Job.Payload[4:])
			if e != nil {
				return e
			}
			if len(proof.Entries) > 0 && cursor < proof.Entries[len(proof.Entries)-1].Entry.Index+1 {
				return nil
			}
		}
	}
	if at.InboxCount <= cursor {
		return nil
	}
	targetHeight := at.Height
	if targetHeight > base.Height+32 {
		targetHeight = base.Height + 32
	}
	for targetHeight >= base.Height {
		e, target, err := n.Source.BuildRange(ctx, base, targetHeight, cursor, nil)
		if err != nil {
			return err
		}
		count := target.InboxCount - cursor
		if count > protocol.MaxDepositsPerCheckpoint {
			count = protocol.MaxDepositsPerCheckpoint
		}
		var entries []protocol.InboxEntry
		if count > 0 {
			entries, err = n.Source.Entries(ctx, target, cursor, count)
			if err != nil {
				return err
			}
			e, target, err = n.Source.BuildRange(ctx, base, targetHeight, cursor, entries)
			if err != nil {
				return err
			}
		}
		raw, err := clxevidence.EncodeRollingEvidence(e)
		if err != nil {
			return err
		}
		if len(raw)+4 <= protocol.MaxNativeCallBytes {
			root, _ := protocol.InboxEntriesRoot(entries)
			key := inboxKey(cursor, cursor+count, root)
			if count == 0 {
				key, _ = target.ID()
			}
			auth, _ := target.Encode()
			job := Job{Version: 1, Lane: Inbox, ID: BusinessID(n.cfg.Relay.Domain, n.cfg.Relay.Custody, Inbox, key), Payload: append([]byte("CDXA"), raw...), Authorization: auth}
			if err := enqueuePlanned(r, job); err != nil {
				return err
			}
			r.prioritizeInbox(job.ID)
			return nil
		}
		if targetHeight <= base.Height+1 {
			return fmt.Errorf("inbox evidence exceeds existing action budget")
		}
		targetHeight = base.Height + (targetHeight-base.Height)/2
	}
	return errors.New("inbox data unavailable")
}
