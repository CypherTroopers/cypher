package devnet

import (
	"errors"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
)

func (e *Execution) rolling() bool    { return e.Native != nil && e.Native.Rolling }
func (e *Execution) continuous() bool { return e.rolling() && e.Native.Continuous }

// ValidateSnapshot validates state invariants and the supplied authenticated
// checkpoint root. It does not authenticate checkpoint finality on its own.
func (e *Execution) ValidateSnapshot(raw []byte, height uint64, root protocol.Hash) error {
	f, s, err := e.Decode(raw)
	if err != nil {
		return err
	}
	if s.Height != height {
		return errors.New("financial snapshot height")
	}
	want, err := e.parentRoot(raw, f, s)
	if err != nil || want != root {
		return errors.New("financial snapshot root")
	}
	return nil
}

// This checks the identity of an anchor restored from authenticated DEX state.
// It does not authenticate a client-supplied record as a new trust root.
func (e *Execution) validateRollingAnchor(a clxevidence.Anchor) error {
	if !e.rolling() || e.Native.Verifier == nil {
		return errors.New("rolling verifier unavailable")
	}
	if _, err := a.Encode(); err != nil {
		return err
	}
	b, err := e.Native.Verifier.BootstrapAnchor()
	if err != nil {
		return err
	}
	// Version 2's current key/order were derived by VerifyRolling and committed
	// in the DEX parent root. Execute checks that parent root before using them;
	// a new action still needs the bounded key-header/order/finality evidence.
	// Applying the old static-key condition here would reject a valid state as
	// soon as its first authenticated renewal was executed.
	if a.ChainID != b.ChainID || a.Genesis != b.Genesis || a.DEXID != b.DEXID || a.Custody != b.Custody || (a.Version == 1 && (a.SourceKeyHash != b.SourceKeyHash || a.SourceCommittee != b.SourceCommittee)) || a.SourceEpoch != b.SourceEpoch || a.InboxCount > protocol.MaxInboxEntries || (a.Height == 0 && a != b) {
		return errors.New("rolling anchor domain/history mismatch")
	}
	return nil
}

// EncodeRollingInboxAction keeps the legacy CDXI/v1 meaning unchanged.
func EncodeRollingInboxAction(evidence clxevidence.RollingEvidence) ([]byte, error) {
	raw, err := clxevidence.EncodeRollingEvidence(evidence)
	if err != nil {
		return nil, err
	}
	if len(raw)+4 > consensus.MaxActionBytes {
		return nil, errors.New("rolling inbox action byte bound")
	}
	return append([]byte("CDXA"), raw...), nil
}
