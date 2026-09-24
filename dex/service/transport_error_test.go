package service

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cypherium/cypher/dex/transport"
)

func TestTemporaryTransportDoesNotHideJoinedFailure(t *testing.T) {
	busy := errors.Join(transport.ErrBusy, transport.ErrCapacity)
	if !temporaryTransport(busy) || !temporaryTransport(fmt.Errorf("peer: %w", busy)) {
		t.Fatal("pure bounded peer backpressure not classified")
	}
	for _, err := range []error{nil, transport.ErrCapacity, errors.Join(busy, errors.New("disk failure")), errors.Join(errors.New("authentication failure"), busy)} {
		if temporaryTransport(err) {
			t.Fatal("non-transient error was hidden", err)
		}
	}
}
