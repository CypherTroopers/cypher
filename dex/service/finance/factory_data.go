package finance

import (
	"errors"

	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
)

// FinalizedSettlement is invoked on the Application's serialized actor. It
// exports retained finalized data; it never triggers financial execution.
func FinalizedSettlement(a *consensus.Application, execution *devnet.Execution, epoch *checkpoint.Epoch, height uint64) ([]byte, error) {
	if a == nil || execution == nil {
		return nil, errors.New("financial provider unavailable")
	}
	cp, proof, err := a.FinalizedCheckpoint(height)
	if err != nil {
		return nil, err
	}
	raw, err := a.FinalizedState(height)
	if err != nil {
		return nil, err
	}
	state, _, err := execution.Decode(raw)
	if err != nil {
		return nil, err
	}
	root, err := state.Root()
	if err != nil || root != cp.PostRoot || state.Finance == nil {
		return nil, errors.New("finalized financial state mismatch")
	}
	bundle, err := checkpoint.BuildSettlementBundle(cp, proof, *state.Finance, state.Withdrawals, state.Rewards)
	if err != nil {
		return nil, err
	}
	if _, err = checkpoint.VerifySettlementBundle(epoch, bundle); err != nil {
		return nil, err
	}
	return checkpoint.EncodeSettlementBundle(bundle)
}
