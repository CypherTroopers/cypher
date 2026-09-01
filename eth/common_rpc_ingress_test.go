package eth

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb/memorydb"
)

type commonRPCTxQUICTransportStub struct {
	enqueueErr    error
	enqueueCalls  int
	enqueueCtxErr error
}

func (s *commonRPCTxQUICTransportStub) enqueueVerifiedLocalTxsWithAdmissions(ctx context.Context, _ []*types.Transaction, _ []core.CommonRPCAdmissionResult, _ *accounts.Manager) error {
	s.enqueueCalls++
	s.enqueueCtxErr = ctx.Err()
	return s.enqueueErr
}

func TestForwardCommonRPCTransactionUsesNodeDurabilityContext(t *testing.T) {
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := new(commonRPCTxQUICTransportStub)
	tx := types.NewTransaction(1, [20]byte{1}, nil, 21000, nil, nil)

	err := forwardCommonRPCTransaction(
		requestCtx,
		transport,
		[]*types.Transaction{tx},
		nil,
		nil,
		time.Second,
	)
	if err != nil {
		t.Fatalf("durable forward failed: %v", err)
	}
	if transport.enqueueCalls != 1 {
		t.Fatalf("enqueue calls = %d, want 1", transport.enqueueCalls)
	}
	if transport.enqueueCtxErr != nil {
		t.Fatalf("request cancellation leaked into node delivery context: %v", transport.enqueueCtxErr)
	}
}

func TestForwardCommonRPCTransactionReportsQueueFailure(t *testing.T) {
	want := errors.New("queue stopped")
	transport := &commonRPCTxQUICTransportStub{enqueueErr: want}
	tx := types.NewTransaction(1, [20]byte{2}, nil, 21000, nil, nil)

	err := forwardCommonRPCTransaction(
		context.Background(),
		transport,
		[]*types.Transaction{tx},
		nil,
		nil,
		time.Second,
	)
	if !errors.Is(err, want) {
		t.Fatalf("queue error = %v, want %v", err, want)
	}
	if transport.enqueueCalls != 1 {
		t.Fatalf("enqueue calls = %d, want 1", transport.enqueueCalls)
	}
}

type commonRPCAdmissionPoolStub struct {
	mu     sync.Mutex
	calls  int
	decide func(int, *types.Transaction) error
	stored map[common.Hash]*types.Transaction
}

func (p *commonRPCAdmissionPoolStub) AddLocalsAsync(txs []*types.Transaction) []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	results := make([]error, len(txs))
	if p.stored == nil {
		p.stored = make(map[common.Hash]*types.Transaction)
	}
	for i, tx := range txs {
		p.calls++
		if p.decide != nil {
			results[i] = p.decide(p.calls, tx)
		}
		if results[i] == nil || errors.Is(results[i], core.ErrAlreadyKnown) {
			p.stored[tx.Hash()] = tx
		}
	}
	return results
}

func (p *commonRPCAdmissionPoolStub) Get(hash common.Hash) *types.Transaction {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stored[hash]
}

func setupCommonRPCAdmissionIngressTest(t *testing.T) (common.Address, *big.Int, common.Hash) {
	t.Helper()
	core.SetCommonRPCAdmissionDatabase(memorydb.New())
	t.Cleanup(func() { core.SetCommonRPCAdmissionDatabase(nil) })
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	core.SetCommonRPCAdmissionSigner(func(batch *types.CommonTxAdmissionBatch) error {
		signature, err := crypto.Sign(types.CommonTxAdmissionSigningHash(batch).Bytes(), key)
		if err == nil {
			batch.Signature = signature
		}
		return err
	})
	return crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1), common.HexToHash("0x1234")
}

func recordAndAddCommonRPCTestTx(
	pool commonRPCAdmissionTxPool,
	tx *types.Transaction,
	miner common.Address,
	chainID *big.Int,
	genesis common.Hash,
	timestamp uint64,
) (core.CommonRPCAdmissionResult, error) {
	release := lockCommonRPCSubmissionHashes([]common.Hash{tx.Hash()})
	defer release()
	admissions, err := core.SignAndRecordCommonRPCAdmissions([]common.Hash{tx.Hash()}, miner, chainID, genesis, 1, timestamp)
	if err != nil {
		return core.CommonRPCAdmissionResult{}, err
	}
	results := make([]error, 1)
	_, _, _, cleanupErr := addCommonRPCAdmittedTransactions(pool, types.Transactions{tx}, admissions, []int{0}, results)
	if cleanupErr != nil {
		return admissions[0], cleanupErr
	}
	return admissions[0], results[0]
}

func TestCommonRPCRejectedUniqueSameNonceTransactionsDoNotRetainAdmissions(t *testing.T) {
	miner, chainID, genesis := setupCommonRPCAdmissionIngressTest(t)
	pool := &commonRPCAdmissionPoolStub{decide: func(call int, _ *types.Transaction) error {
		if call == 1 {
			return nil
		}
		return core.ErrReplaceUnderpriced
	}}
	const attempts = 256
	var accepted common.Hash
	for i := 0; i < attempts; i++ {
		to := common.Address{byte(i), byte(i >> 8), 1}
		tx := types.NewTransaction(0, to, big.NewInt(int64(i+1)), 21000, big.NewInt(1), nil)
		admission, err := recordAndAddCommonRPCTestTx(pool, tx, miner, chainID, genesis, uint64(time.Now().Unix()))
		if i == 0 {
			if err != nil {
				t.Fatalf("first transaction was not accepted: %v", err)
			}
			accepted = tx.Hash()
			if !admission.Inserted {
				t.Fatal("first admission was not marked inserted")
			}
			continue
		}
		if !errors.Is(err, core.ErrReplaceUnderpriced) {
			t.Fatalf("attempt %d error=%v, want replacement underpriced", i, err)
		}
		if core.HasCommonRPCAdmission(tx.Hash()) {
			t.Fatalf("attempt %d retained an orphan admission", i)
		}
	}
	if !core.HasCommonRPCAdmission(accepted) || pool.Get(accepted) == nil {
		t.Fatal("accepted transaction lost its admission or pool entry")
	}
}

func TestCommonRPCSameHashConcurrentAcceptRejectNeverLeavesNakedPoolTx(t *testing.T) {
	miner, chainID, genesis := setupCommonRPCAdmissionIngressTest(t)
	tx := types.NewTransaction(0, common.Address{9}, big.NewInt(1), 21000, big.NewInt(1), nil)
	pool := &commonRPCAdmissionPoolStub{decide: func(call int, _ *types.Transaction) error {
		if call == 1 {
			return core.ErrReplaceUnderpriced
		}
		return nil
	}}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(timestamp uint64) {
			defer wg.Done()
			<-start
			_, err := recordAndAddCommonRPCTestTx(pool, tx, miner, chainID, genesis, timestamp)
			errs <- err
		}(uint64(time.Now().Unix()) + uint64(i))
	}
	close(start)
	wg.Wait()
	close(errs)
	accepted, rejected := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, core.ErrReplaceUnderpriced):
			rejected++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("accepted/rejected=%d/%d, want 1/1", accepted, rejected)
	}
	if pool.Get(tx.Hash()) == nil || !core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("successful same-hash submission was left naked")
	}
}

func TestCommonRPCSubmissionHashLeasesSerializeOnlyOverlaps(t *testing.T) {
	firstHash := common.Hash{1}
	otherHash := common.Hash{2}
	releaseFirst := lockCommonRPCSubmissionHashes([]common.Hash{firstHash})
	overlap := make(chan struct{})
	overlapRelease := make(chan struct{})
	go func() {
		release := lockCommonRPCSubmissionHashes([]common.Hash{firstHash})
		close(overlap)
		<-overlapRelease
		release()
	}()
	select {
	case <-overlap:
		t.Fatal("same-hash lease did not block")
	case <-time.After(25 * time.Millisecond):
	}
	disjoint := make(chan struct{})
	go func() {
		release := lockCommonRPCSubmissionHashes([]common.Hash{otherHash})
		release()
		close(disjoint)
	}()
	select {
	case <-disjoint:
	case <-time.After(time.Second):
		t.Fatal("disjoint hash was serialized")
	}
	releaseFirst()
	select {
	case <-overlap:
	case <-time.After(time.Second):
		t.Fatal("same-hash waiter did not resume")
	}
	close(overlapRelease)

	deadline := time.Now().Add(time.Second)
	for {
		commonRPCSubmissionLeases.Lock()
		remaining := len(commonRPCSubmissionLeases.entries)
		commonRPCSubmissionLeases.Unlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("submission lease registry retained %d entries", remaining)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCommonRPCAdmissionPoolAlignmentMismatchFailsBeforeMutation(t *testing.T) {
	pool := new(commonRPCAdmissionPoolStub)
	tx := types.NewTransaction(0, common.Address{3}, big.NewInt(1), 21000, big.NewInt(1), nil)
	results := make([]error, 1)
	forwardTxs, _, _, err := addCommonRPCAdmittedTransactions(pool, types.Transactions{tx}, nil, []int{0}, results)
	if err == nil || results[0] == nil {
		t.Fatalf("alignment mismatch err=%v result=%v", err, results[0])
	}
	if len(forwardTxs) != 0 {
		t.Fatalf("alignment mismatch forwarded %d transactions", len(forwardTxs))
	}
	pool.mu.Lock()
	calls := pool.calls
	pool.mu.Unlock()
	if calls != 0 {
		t.Fatalf("alignment mismatch mutated TxPool %d times", calls)
	}
}

func TestCommonRPCAlreadyKnownAndOutboxFailureRetainAdmission(t *testing.T) {
	miner, chainID, genesis := setupCommonRPCAdmissionIngressTest(t)
	tx := types.NewTransaction(0, common.Address{8}, big.NewInt(1), 21000, big.NewInt(1), nil)
	pool := &commonRPCAdmissionPoolStub{decide: func(_ int, _ *types.Transaction) error { return core.ErrAlreadyKnown }}
	admission, err := recordAndAddCommonRPCTestTx(pool, tx, miner, chainID, genesis, uint64(time.Now().Unix()))
	if !errors.Is(err, core.ErrAlreadyKnown) {
		// The helper normalizes ErrAlreadyKnown into a forwarded success.
		if err != nil {
			t.Fatalf("already-known admission failed: %v", err)
		}
	}
	if !admission.Inserted || !core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("already-known handling removed admission")
	}
	transport := &commonRPCTxQUICTransportStub{enqueueErr: errors.New("outbox unavailable")}
	if err := forwardCommonRPCTransaction(context.Background(), transport, []*types.Transaction{tx}, []core.CommonRPCAdmissionResult{admission}, nil, time.Second); err == nil {
		t.Fatal("expected outbox failure")
	}
	if !core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("outbox failure removed admission")
	}
}
