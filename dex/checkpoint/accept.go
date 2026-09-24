package checkpoint

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cypherium/cypher/dex/protocol"
)

const (
	MaxAcceptedCheckpoints      = 4096
	MaxRegisteredEpochs         = 64
	MaxFinalizedAnchors         = 4096
	MaxCheckpointBlocks         = uint64(1024)
	DataAvailabilityNotVerified = "not_verified"
)

var (
	ErrCheckpointConflict   = errors.New("different checkpoint already accepted at sequence")
	ErrCheckpointConnection = errors.New("checkpoint does not extend accepted state")
	ErrUnauthorizedEpoch    = errors.New("checkpoint epoch not authorized at sequence")
	ErrUnfinalizedAnchor    = errors.New("checkpoint does not reference authenticated finalized CLX anchor")
	ErrNoFundsMode          = errors.New("financial checkpoints are disabled in B-stage no-funds mode")
	ErrHistoryCapacity      = errors.New("checkpoint history capacity exhausted")
)

// FinalizedAnchor must come from authenticated CLX state, never a submitter's
// assertion or an HTTP lookup while executing the acceptance state transition.
type FinalizedAnchor struct {
	Height uint64
	Hash   protocol.Hash
}

type AcceptedState struct {
	Sequence    uint64
	Hash        protocol.Hash
	Root        protocol.Hash
	LastBlock   uint64
	InboxCursor uint64
	Epoch       uint64
	CLX         FinalizedAnchor
}

type Acceptance struct {
	Sequence         uint64
	Hash             protocol.Hash
	Replay           bool
	DataAvailability string
	Verification     VerifyStats
}

// Acceptor authenticates no-funds checkpoints against an immutable trusted
// registry and finalized-anchor snapshot. It is not wired to CLX execution.
type Acceptor struct {
	mu      sync.Mutex
	domain  protocol.Domain
	epochs  []*Epoch
	anchors map[uint64]protocol.Hash
	limit   int
	state   AcceptedState
	history map[uint64]protocol.Hash
}

func NewAcceptor(genesisRoot protocol.Hash, epochs []*Epoch, anchors []FinalizedAnchor, maxCheckpoints int) (*Acceptor, error) {
	if genesisRoot == (protocol.Hash{}) || len(epochs) == 0 || len(epochs) > MaxRegisteredEpochs || len(anchors) == 0 || len(anchors) > MaxFinalizedAnchors || maxCheckpoints < 1 || maxCheckpoints > MaxAcceptedCheckpoints {
		return nil, errors.New("invalid no-funds acceptance initialization")
	}
	a := &Acceptor{limit: maxCheckpoints, anchors: make(map[uint64]protocol.Hash, len(anchors)), history: make(map[uint64]protocol.Hash)}
	for index, epoch := range epochs {
		if epoch == nil {
			return nil, errors.New("nil registered epoch")
		}
		if index == 0 {
			if epoch.first != 1 {
				return nil, errors.New("initial epoch must start at sequence 1")
			}
			a.domain = epoch.domain
		} else {
			previous := epochs[index-1]
			if epoch.first != previous.end || previous.domain.Epoch == ^uint64(0) || epoch.domain.Epoch != previous.domain.Epoch+1 || !sameChainDEX(epoch.domain, a.domain) {
				return nil, errors.New("registered epochs must have contiguous authorized boundaries")
			}
		}
		a.epochs = append(a.epochs, epoch)
	}
	for _, anchor := range anchors {
		if anchor.Hash == (protocol.Hash{}) {
			return nil, errors.New("empty finalized anchor hash")
		}
		if _, exists := a.anchors[anchor.Height]; exists {
			return nil, errors.New("duplicate finalized anchor height")
		}
		a.anchors[anchor.Height] = anchor.Hash
	}
	a.state.Root = genesisRoot
	return a, nil
}

func sameChainDEX(left, right protocol.Domain) bool {
	return left.Version == right.Version && left.ChainID == right.ChainID && left.Genesis == right.Genesis && left.DEXID == right.DEXID
}

func (a *Acceptor) State() AcceptedState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

func (a *Acceptor) Accept(c protocol.Checkpoint, proof []byte) (Acceptance, error) {
	result := Acceptance{Sequence: c.Sequence, DataAvailability: DataAvailabilityNotVerified}
	hash, err := c.Hash()
	if err != nil {
		return result, err
	}
	result.Hash = hash
	a.mu.Lock()
	defer a.mu.Unlock()
	if !sameChainDEX(c.Domain(), a.domain) {
		return result, ErrCheckpointConnection
	}
	if accepted, exists := a.history[c.Sequence]; exists {
		if accepted != hash {
			return result, ErrCheckpointConflict
		}
		result.Replay = true
		return result, nil
	}
	if len(a.history) >= a.limit {
		return result, ErrHistoryCapacity
	}
	if a.state.Sequence == ^uint64(0) || c.Sequence != a.state.Sequence+1 || c.Previous != a.state.Hash || c.PreRoot != a.state.Root || a.state.LastBlock == ^uint64(0) || c.FirstBlock != a.state.LastBlock+1 || c.LastBlock-c.FirstBlock >= MaxCheckpointBlocks {
		return result, ErrCheckpointConnection
	}
	if c.DataSchema != 1 || c.InboxStart != a.state.InboxCursor || c.InboxEnd != a.state.InboxCursor || c.InboxRoot != (protocol.Hash{}) || c.WithdrawalRoot != (protocol.Hash{}) || c.WithdrawalTotal != (protocol.Amount{}) || c.RewardPeriod != 0 || c.RewardRoot != (protocol.Hash{}) || c.RewardTotal != (protocol.Amount{}) || c.FundingRef != (protocol.Hash{}) {
		return result, ErrNoFundsMode
	}
	anchor, exists := a.anchors[c.CLXHeight]
	if !exists || anchor != c.CLXHash || c.CLXHeight < a.state.CLX.Height {
		return result, ErrUnfinalizedAnchor
	}
	var authorized *Epoch
	for _, epoch := range a.epochs {
		if c.Sequence >= epoch.first && c.Sequence < epoch.end {
			authorized = epoch
			break
		}
	}
	if authorized == nil || c.Domain() != authorized.domain {
		return result, ErrUnauthorizedEpoch
	}
	result.Verification, err = authorized.Verify(c, proof)
	if err != nil {
		return result, fmt.Errorf("checkpoint finality: %w", err)
	}
	a.state = AcceptedState{Sequence: c.Sequence, Hash: hash, Root: c.PostRoot, LastBlock: c.LastBlock, InboxCursor: c.InboxEnd, Epoch: c.Epoch, CLX: FinalizedAnchor{c.CLXHeight, c.CLXHash}}
	a.history[c.Sequence] = hash
	return result, nil
}
