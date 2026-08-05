package reconfig

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func TestCheckViewNumbers(t *testing.T) {
	tests := []struct {
		name                               string
		viewKey, viewTx, localKey, localTx uint64
		want                               error
	}{
		{name: "equal", viewKey: 4, viewTx: 10, localKey: 4, localTx: 10},
		{name: "old key", viewKey: 3, viewTx: 10, localKey: 4, localTx: 10, want: hotstuff.ErrOldState},
		{name: "future key", viewKey: 5, viewTx: 10, localKey: 4, localTx: 10, want: hotstuff.ErrFutureState},
		{name: "old transaction block", viewKey: 4, viewTx: 9, localKey: 4, localTx: 10, want: hotstuff.ErrOldState},
		{name: "one transaction block ahead", viewKey: 4, viewTx: 11, localKey: 4, localTx: 10, want: hotstuff.ErrFutureState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := checkViewNumbers(test.viewKey, test.viewTx, test.localKey, test.localTx); got != test.want {
				t.Fatalf("checkViewNumbers() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCheckViewRejectsMalformedStateBeforeStoppedState(t *testing.T) {
	err := new(Service).CheckView([]byte{0xff})
	if err == nil {
		t.Fatal("expected malformed view error")
	}
	if errors.Is(err, types.ErrNotRunning) {
		t.Fatalf("malformed view was retained as a stopped-state error: %v", err)
	}
}

func TestOnProposeRejectsMalformedBlockWithoutPanic(t *testing.T) {
	service := new(Service)
	atomic.StoreInt32(&service.runningState, 1)
	if err := service.OnPropose([]byte{0xff}, nil, nil); err == nil {
		t.Fatal("expected malformed proposal error")
	}
}

func TestConsensusReadyExcludesStartupReplay(t *testing.T) {
	service := new(Service)
	atomic.StoreInt32(&service.runningState, 1)
	atomic.StoreInt32(&service.startingState, 1)
	if service.consensusReady() {
		t.Fatal("service became consensus-ready during pending-message replay")
	}
	atomic.StoreInt32(&service.startingState, 0)
	if !service.consensusReady() {
		t.Fatal("service did not become consensus-ready after replay")
	}
}

func TestPendingTargetIsNextBlock(t *testing.T) {
	if got := pendingTarget(41); got != 42 {
		t.Fatalf("pendingTarget(41) = %d, want 42", got)
	}
}

func TestRunConsensusStartReplaysBeforeConsensus(t *testing.T) {
	var events []string
	err := runConsensusStart(consensusStartHooks{
		startTransport: func() { events = append(events, "transport-start") },
		stopTransport:  func() { events = append(events, "transport-stop") },
		setRunning: func(running bool) {
			if running {
				events = append(events, "running")
			} else {
				events = append(events, "stopped")
			}
		},
		replayPending: func() error {
			events = append(events, "replay")
			return nil
		},
		startConsensus: func() { events = append(events, "consensus") },
	})
	if err != nil {
		t.Fatalf("runConsensusStart returned error: %v", err)
	}
	want := []string{"transport-start", "running", "replay", "consensus"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRunConsensusStartRollsBackReplayFailure(t *testing.T) {
	replayErr := errors.New("pending message still needs its parent")
	var events []string
	err := runConsensusStart(consensusStartHooks{
		startTransport: func() { events = append(events, "transport-start") },
		stopTransport:  func() { events = append(events, "transport-stop") },
		setRunning: func(running bool) {
			if running {
				events = append(events, "running")
			} else {
				events = append(events, "stopped")
			}
		},
		replayPending: func() error {
			events = append(events, "replay")
			return replayErr
		},
		startConsensus: func() { events = append(events, "consensus") },
	})
	if !errors.Is(err, replayErr) {
		t.Fatalf("runConsensusStart error = %v, want %v", err, replayErr)
	}
	want := []string{"transport-start", "running", "replay", "stopped", "transport-stop"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRecoverableBlockValidationError(t *testing.T) {
	recoverable := []error{
		consensus.ErrUnknownAncestor,
		consensus.ErrPrunedAncestor,
		consensus.ErrFutureBlock,
		types.ErrUnknownAncestor,
		types.ErrPrunedAncestor,
		types.ErrFutureBlock,
		fmt.Errorf("wrapped: %w", consensus.ErrUnknownAncestor),
	}
	for _, err := range recoverable {
		if !isRecoverableBlockValidationError(err) {
			t.Fatalf("error %v was not classified as recoverable", err)
		}
	}
	if isRecoverableBlockValidationError(errors.New("invalid transaction root")) {
		t.Fatal("permanent validation error was classified as recoverable")
	}
}
