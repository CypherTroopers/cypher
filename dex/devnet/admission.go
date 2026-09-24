package devnet

import (
	"bytes"
	"errors"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/rewards"
)

// AuthenticateAction performs bounded immutable authentication before durable
// network admission. Nonce, cursor, oracle age, margin and economic execution
// remain checks against the actual parent state before voting.
func (e *Execution) AuthenticateAction(raw []byte) error {
	if e == nil || e.Market == nil || len(raw) == 0 || len(raw) > consensus.MaxActionBytes {
		return errors.New("financial ingress bound/config")
	}
	if bytes.HasPrefix(raw, []byte("CDXA")) {
		if !e.rolling() || e.Native.Verifier == nil {
			return errors.New("rolling inbox unavailable")
		}
		proof, err := clxevidence.DecodeRollingEvidence(raw[4:])
		if err != nil {
			return err
		}
		// Immutable authentication only. Trusted base and cursor are checked
		// against the actual proposal parent by Execute, never a local cache.
		return e.Native.Verifier.VerifyRollingPayload(proof)
	}
	if bytes.HasPrefix(raw, []byte("CDXI")) {
		if e.Native == nil || e.Native.Verifier == nil || e.rolling() {
			return errors.New("native inbox unavailable")
		}
		proof, err := clxevidence.DecodeRangeEvidence(raw[4:])
		if err != nil {
			return err
		}
		start := uint64(0)
		if len(proof.Entries) > 0 {
			start = proof.Entries[0].Entry.Index
		}
		_, err = e.Native.Verifier.VerifyRange(start, proof)
		return err
	}
	var signed []byte
	var pkg *rewards.ClosePackage
	var batch *rewards.CommitBatch
	var err error
	if bytes.HasPrefix(raw, []byte("CDXP")) {
		signed, batch, err = decodeCommitAction(raw)
	} else {
		signed, pkg, err = decodeAction(raw)
	}
	if err != nil {
		return err
	}
	a, err := engine.Decode(signed)
	if err != nil {
		return err
	}
	if a.Epoch != e.Market.Domain().EpochKey() {
		return errors.New("financial ingress domain")
	}
	if e.Native != nil && a.Kind == engine.Credit {
		return errors.New("native credit requires finalized inbox evidence")
	}
	if (a.Kind == engine.RewardClose) != (pkg != nil || batch != nil) {
		return errors.New("financial ingress reward binding")
	}
	if batch != nil {
		if e.Registry == nil {
			return errors.New("reward registry unavailable")
		}
		for _, cert := range batch.Certificates {
			if err := e.Registry.VerifyCertificate(cert); err != nil {
				return err
			}
		}
	}
	if a.Kind == engine.Noop || a.Kind == engine.Oracle || a.Kind == engine.Funding || a.Kind == engine.RewardClose {
		if a.Owner != e.Market.Oracle() {
			return errors.New("financial oracle authorization")
		}
	}
	if pkg != nil {
		if e.Registry == nil {
			return errors.New("reward registry unavailable")
		}
		_, err = e.Registry.ComputePoints(pkg.Period, pkg.Blocks, pkg.Certificates)
		return err
	}
	return nil
}
