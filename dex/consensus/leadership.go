package consensus

import "errors"

// Leadership is an owned observation of this actor's authenticated FHS view.
// It is a submission scheduling hint, never CLX settlement authorization. A
// partitioned node may observe an older view; all submissions still need normal
// CLX proof validation, nonce handling and business-level idempotence.
type Leadership struct {
	View        uint64
	LeaderIndex uint8
	LeaderID    string
	SelfIndex   uint8
	Active      bool
}

// Leadership must run on the same actor as Handle/Advance. It neither examines
// an RPC's claimed leader nor installs a new consensus view.
func (a *Application) Leadership() (Leadership, error) {
	if err := a.check(); err != nil {
		return Leadership{}, err
	}
	if !a.started {
		return Leadership{}, errors.New("DEX leadership unavailable before consensus start")
	}
	_, leader, view := a.CurrentState()
	index := (view - 1) % uint64(len(a.committee.List))
	return Leadership{View: view, LeaderIndex: uint8(index), LeaderID: leader, SelfIndex: uint8(a.config.Index), Active: leader == a.Self()}, nil
}
