package relay

import (
	"context"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
)

// ErrNotLeader means no new signature or submission is authorized locally.
// It is a scheduling result, never a consensus validity decision.
var ErrNotLeader = errors.New("DEX submission waiting for local leadership")

// Leadership is a snapshot obtained from the DEX consensus actor. Active must
// require registration and synchronization as well as ownership of View. Done,
// when supplied, closes on loss of this view and cancels an in-flight operation.
// An already delivered CLX transaction cannot be recalled by losing leadership.
type Leadership struct {
	View   uint64
	Active bool
	Done   <-chan struct{}
}

type LeadershipCheck func(context.Context) (Leadership, error)

// LeaderRelay reuses the ordinary authenticated relay journal inside a DEX
// participant. Every member owns its payer keys, nonces and directory. Successors
// reconstruct business jobs from finalized bundles and authenticated CLX state;
// they never import a predecessor's signing keys or reserved nonce.
type LeaderRelay struct {
	journal *Relay
	check   LeadershipCheck
}

type leadershipKey struct{}
type leadershipToken struct {
	owner *LeaderRelay
	view  uint64
	done  <-chan struct{}
}

func OpenLeader(dir string, c Config, b Backend, s Signer, check LeadershipCheck) (*LeaderRelay, error) {
	if b == nil || s == nil || check == nil {
		return nil, errors.New("leader submission backend, signer and leadership check required")
	}
	l := &LeaderRelay{check: check}
	r, err := Open(dir, c, &leaderBackend{owner: l, backend: b}, &leaderSigner{owner: l, signer: s})
	if err != nil {
		return nil, err
	}
	l.journal = r
	return l, nil
}

// Journal exposes read/discovery/enqueue operations to the existing planner.
// Calling Journal().Step directly cannot authorize signing or broadcasting:
// only LeaderRelay.Step supplies a fresh, privately typed leadership token.
func (l *LeaderRelay) Journal() *Relay                     { return l.journal }
func (l *LeaderRelay) Close() error                        { return l.journal.Close() }
func (l *LeaderRelay) Status() []Record                    { return l.journal.Status() }
func (l *LeaderRelay) Enqueue(j Job) error                 { return l.journal.Enqueue(j) }
func (l *LeaderRelay) Reconcile(ctx context.Context) error { return l.journal.Reconcile(ctx) }

// PendingWork reports semantic work still outstanding in this local journal.
// Discover and Reconcile must continue on standby nodes: RPC ACKs and persisted
// completion labels alone cannot remove pending work after a cold restart.
// A signed nonce awaiting consumption after authenticated business completion is
// retained but does not by itself ask FHS to produce another leader view.
func (l *LeaderRelay) PendingWork() bool {
	r := l.journal
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.state.Records {
		if record.Phase == "quarantined" || record.Phase == "nonce_conflict" {
			continue
		}
		if (record.Phase == "complete" || record.Phase == "completed_pending_nonce") && r.validated[record.Job.ID] {
			continue
		}
		return true
	}
	return false
}

func (l *LeaderRelay) Step(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	at, err := l.check(ctx)
	if err != nil {
		return err
	}
	if !at.Active || channelClosed(at.Done) {
		return ErrNotLeader
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = context.WithValue(ctx, leadershipKey{}, leadershipToken{owner: l, view: at.View, done: at.Done})
	if at.Done != nil {
		go func() {
			select {
			case <-at.Done:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return l.journal.Step(ctx)
}

func channelClosed(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (l *LeaderRelay) authorize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	token, ok := ctx.Value(leadershipKey{}).(leadershipToken)
	if !ok || token.owner != l || channelClosed(token.done) {
		return ErrNotLeader
	}
	at, err := l.check(ctx)
	if err != nil {
		return err
	}
	if !at.Active || at.View != token.view || channelClosed(at.Done) {
		return ErrNotLeader
	}
	return nil
}

type leaderBackend struct {
	owner   *LeaderRelay
	backend Backend
}

func (b *leaderBackend) Observe(ctx context.Context, job Job, attempt Attempt) (observation, error) {
	return b.backend.Observe(ctx, job, attempt)
}
func (b *leaderBackend) SendRawTransaction(ctx context.Context, raw []byte) (common.Hash, error) {
	if err := b.owner.authorize(ctx); err != nil {
		return common.Hash{}, err
	}
	return b.backend.SendRawTransaction(ctx, raw)
}
func (b *leaderBackend) SendDEX(ctx context.Context, raw []byte) (protocol.Hash, error) {
	if err := b.owner.authorize(ctx); err != nil {
		return protocol.Hash{}, err
	}
	return b.backend.SendDEX(ctx, raw)
}

type leaderSigner struct {
	owner  *LeaderRelay
	signer Signer
}

func (s *leaderSigner) Sign(ctx context.Context, payer common.Address, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if err := s.owner.authorize(ctx); err != nil {
		return nil, err
	}
	signed, err := s.signer.Sign(ctx, payer, tx, chainID)
	if err != nil {
		return nil, err
	}
	if err := s.owner.authorize(ctx); err != nil {
		return nil, err
	}
	return signed, nil
}
