package finance

import (
	"bytes"
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// timeoutPolicy only schedules local timeout votes. It neither consumes ingress
// nor changes execution validity. One cache entry bounds the retained state;
// economic checks run only when the certified parent or durable queue changes.
func (p *Pool) timeoutPolicy() func(*consensus.Application) (bool, error) {
	var cached bool
	var parentKey common.Hash
	var revision uint64
	var ready bool
	return func(a *consensus.Application) (bool, error) {
		if err := p.check(); err != nil {
			return false, err
		}
		if a.HasUncertifiedVote() {
			return true, nil
		}
		pending, err := a.PendingFHSTimeoutVote()
		if err != nil {
			return false, err
		}
		if pending != nil && pending.TimedOutView >= a.CurrentN() {
			return true, nil
		}
		key := common.Hash{}
		if q := a.HighestCertified(); q != nil {
			key = hotstuff.StateDigest(q.State)
		}
		if cached && key == parentKey && revision == p.revision {
			return ready, nil
		}
		parent, ctx, err := a.ProposalWorkParent()
		if err != nil {
			return false, err
		}
		ready, err = p.readyAgainst(parent, ctx)
		if err != nil {
			return false, err
		}
		cached, parentKey, revision = true, key, p.revision
		return ready, nil
	}
}

func (p *Pool) readyAgainst(parent []byte, ctx consensus.ExecutionContext) (bool, error) {
	if err := p.check(); err != nil {
		return false, err
	}
	f, state, err := p.execution.Decode(parent)
	if err != nil {
		return false, err
	}
	root, err := f.Root()
	if state.Height == 0 {
		_, root, err = p.execution.Genesis()
	}
	if err != nil || ctx.ParentRoot != root || ctx.Height != state.Height+1 || ctx.Domain != p.execution.Market.Domain() {
		return false, errors.New("financial readiness parent execution context")
	}
	// At most the already bounded 64 ingress entries are inspected. A cached
	// certified action remains in the pool until finality, but its consumed nonce
	// or inbox cursor must not keep an otherwise idle view timing out.
	for _, item := range p.disk.Pending {
		if _, err := p.execution.Execute(bytes.Clone(parent), bytes.Clone(item.Raw), ctx); err == nil {
			return true, nil
		}
	}
	return false, nil
}
