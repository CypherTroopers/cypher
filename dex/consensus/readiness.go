package consensus

import "github.com/cypherium/cypher/core/types"

// ProposalWorkParent returns owned state and the next execution context for the
// highest authenticated QC. Local ingress readiness may inspect this snapshot;
// its result never participates in proposal validation or state execution.
func (a *Application) ProposalWorkParent() ([]byte, ExecutionContext, error) {
	if err := a.check(); err != nil {
		return nil, ExecutionContext{}, err
	}
	q := a.disk.Safety.HighestQC
	h, _, _, err := a.parent(q)
	if err != nil {
		return nil, ExecutionContext{}, err
	}
	state, root, err := a.executionParent(q)
	if err != nil {
		return nil, ExecutionContext{}, err
	}
	return state, a.executionContext(h+1, root), nil
}

// HasUncertifiedVote preserves timeout progress for an already persisted vote
// whose proposal has not yet been certified, including after a cold restart.
func (a *Application) HasUncertifiedVote() bool {
	v := a.disk.Safety.LastVote
	if v == nil {
		return false
	}
	q := a.disk.Safety.HighestQC
	if q == nil {
		return true
	}
	r, err := types.DecodeHotstuffProposalRef(v.ProposalRef)
	if err != nil {
		return true // uncertain local safety state must not look idle
	}
	return v.ViewNumber > q.Number || r.Number > a.CertifiedHeight()
}
