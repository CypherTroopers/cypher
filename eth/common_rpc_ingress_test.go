package eth

import (
	"errors"
	"testing"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
)

type commonRPCLocalTxPoolStub struct {
	err   error
	calls int
}

func (s *commonRPCLocalTxPoolStub) AddLocal(*types.Transaction) error {
	s.calls++
	return s.err
}

func TestAcceptCommonRPCTransactionLocallyIsIdempotent(t *testing.T) {
	tx := new(types.Transaction)
	pool := &commonRPCLocalTxPoolStub{err: core.ErrAlreadyKnown}
	if err := acceptCommonRPCTransactionLocally(pool, tx); err != nil {
		t.Fatalf("already-known transaction was rejected: %v", err)
	}
	if pool.calls != 1 {
		t.Fatalf("AddLocal calls = %d, want 1", pool.calls)
	}
}

func TestAcceptCommonRPCTransactionLocallyReturnsValidationFailure(t *testing.T) {
	want := errors.New("validation failed")
	pool := &commonRPCLocalTxPoolStub{err: want}
	if err := acceptCommonRPCTransactionLocally(pool, new(types.Transaction)); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
