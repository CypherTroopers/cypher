package eth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type checkpointFaultTxQUICDB struct {
	ethdb.KeyValueStore
	mode    atomic.Int32
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type checkpointFaultTxQUICBatch struct {
	ethdb.Batch
	db            *checkpointFaultTxQUICDB
	hasManifest   bool
	hasCheckpoint bool
}

func (db *checkpointFaultTxQUICDB) NewBatch() ethdb.Batch {
	return &checkpointFaultTxQUICBatch{Batch: db.KeyValueStore.NewBatch(), db: db}
}

func (batch *checkpointFaultTxQUICBatch) Put(key, value []byte) error {
	if bytes.Equal(key, txIngressWALManifestKey) {
		batch.hasManifest = true
	}
	if bytes.HasPrefix(key, txIngressWALGenerationPrefix) {
		batch.hasCheckpoint = true
	}
	return batch.Batch.Put(key, value)
}

func (batch *checkpointFaultTxQUICBatch) WriteSync() error {
	syncBatch, ok := batch.Batch.(ethdb.SyncBatch)
	if !ok {
		return errors.New("underlying checkpoint test DB has no synchronous batch")
	}
	mode := batch.db.mode.Load()
	if batch.hasManifest && (mode == 1 || mode == 5) {
		return errors.New("simulated crash before WAL manifest switch")
	}
	if batch.hasManifest && mode == 3 {
		batch.db.once.Do(func() { close(batch.db.started) })
		<-batch.db.release
	}
	if batch.hasCheckpoint && !batch.hasManifest && (mode == 4 || mode == 5 || mode == 6) {
		batch.db.once.Do(func() { close(batch.db.started) })
		<-batch.db.release
	}
	if err := syncBatch.WriteSync(); err != nil {
		return err
	}
	if batch.hasManifest && (mode == 2 || mode == 6) {
		return errors.New("simulated crash after WAL manifest switch")
	}
	return nil
}

func testIngressWALEvent(index byte) (common.Hash, common.Hash, []byte) {
	return common.Hash{index, 1}, common.Hash{index, 2}, []byte{index, 3, 4, 5}
}

func TestTxIngressWALGroupCommitAndIdempotentReplay(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitInterval = 50 * time.Millisecond
	config.IngressCommitMaxRequests = 16
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wal.Stop)
	db.syncWrites.Store(0)

	const count = 12
	sequences := make([]uint64, count)
	errs := make([]error, count)
	var wg sync.WaitGroup
	ready := make(chan struct{})
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-ready
			batchID, eventID, payload := testIngressWALEvent(byte(index + 1))
			sequences[index], errs[index] = wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, payload)
		}(index)
	}
	close(ready)
	wg.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}
	seen := make(map[uint64]bool, count)
	for _, sequence := range sequences {
		seen[sequence] = true
	}
	for sequence := uint64(1); sequence <= count; sequence++ {
		if !seen[sequence] {
			t.Fatalf("missing committed sequence %d: %v", sequence, sequences)
		}
	}
	if writes := db.syncWrites.Load(); writes >= count {
		t.Fatalf("WAL did not group fsyncs: writes=%d records=%d", writes, count)
	}

	batchID, eventID, payload := testIngressWALEvent(1)
	writesBefore := db.syncWrites.Load()
	sequence, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != sequences[0] {
		t.Fatalf("idempotent append sequence=%d want=%d", sequence, sequences[0])
	}
	if writes := db.syncWrites.Load(); writes != writesBefore {
		t.Fatalf("idempotent append performed another fsync: before=%d after=%d", writesBefore, writes)
	}

	var replayed []uint64
	if err := wal.Replay(func(frame *txIngressWALFrame) error {
		replayed = append(replayed, frame.Sequence)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(replayed) != count {
		t.Fatalf("replayed %d records, want %d", len(replayed), count)
	}
}

func TestTxIngressWALRejectsSameGroupEventIDCollision(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitInterval = 50 * time.Millisecond
	config.IngressCommitMaxRequests = 2
	db := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()

	batchID, eventID, payload := testIngressWALEvent(1)
	start := make(chan struct{})
	results := make(chan error, 2)
	appendPayload := func(value []byte) {
		<-start
		_, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, value)
		results <- err
	}
	go appendPayload(payload)
	go appendPayload(append(append([]byte(nil), payload...), 9))
	close(start)

	var successes, collisions int
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case strings.Contains(err.Error(), "EventID collision"):
			collisions++
		default:
			t.Fatalf("unexpected append result: %v", err)
		}
	}
	if successes != 1 || collisions != 1 {
		t.Fatalf("same-group collision results: successes=%d collisions=%d", successes, collisions)
	}
}

func TestTxIngressWALRepairsOnlyTornTerminalRecord(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := byte(1); index <= 2; index++ {
		batchID, eventID, payload := testIngressWALEvent(index)
		if _, err := wal.Append(context.Background(), txIngressWALInboundReceived, batchID, eventID, payload); err != nil {
			t.Fatal(err)
		}
	}
	wal.Stop()
	if err := db.Put(txIngressWALRecordKey(2), []byte{0xc4, 0x01}); err != nil {
		t.Fatal(err)
	}

	restarted := newTxIngressWAL(db, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatalf("terminal tear was not repaired: %v", err)
	}
	defer restarted.Stop()
	var sequences []uint64
	if err := restarted.Replay(func(frame *txIngressWALFrame) error {
		sequences = append(sequences, frame.Sequence)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sequences) != "[1]" {
		t.Fatalf("replayed sequences %v, want [1]", sequences)
	}
	if has, err := db.Has(txIngressWALRecordKey(2)); err != nil || has {
		t.Fatalf("torn terminal record remains: has=%t err=%v", has, err)
	}
}

func TestTxIngressWALRejectsInteriorCorruption(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := byte(1); index <= 3; index++ {
		batchID, eventID, payload := testIngressWALEvent(index)
		if _, err := wal.Append(context.Background(), txIngressWALInboundOutcome, batchID, eventID, payload); err != nil {
			t.Fatal(err)
		}
	}
	wal.Stop()
	if err := db.Put(txIngressWALRecordKey(2), []byte{0xc1}); err != nil {
		t.Fatal(err)
	}
	restarted := newTxIngressWAL(db, config)
	if err := restarted.Start(context.Background()); err == nil {
		restarted.Stop()
		t.Fatal("interior WAL corruption was silently truncated")
	}
}

func TestTxIngressWALAppliesBoundedQueueBackpressure(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitMaxRequests = 1
	db := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	db.block.Store(true)

	appendAsync := func(index byte) <-chan error {
		done := make(chan error, 1)
		go func() {
			batchID, eventID, payload := testIngressWALEvent(index)
			_, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, payload)
			done <- err
		}()
		return done
	}
	results := []<-chan error{appendAsync(1)}
	select {
	case <-db.started:
	case <-time.After(time.Second):
		t.Fatal("WAL fsync did not block")
	}
	for index := byte(2); index <= byte(cap(wal.appendCh)+1); index++ {
		results = append(results, appendAsync(index))
	}
	deadline := time.Now().Add(time.Second)
	for len(wal.appendCh) != cap(wal.appendCh) {
		if time.Now().After(deadline) {
			t.Fatalf("WAL queue did not fill: len=%d cap=%d", len(wal.appendCh), cap(wal.appendCh))
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	batchID, eventID, payload := testIngressWALEvent(99)
	_, err := wal.Append(ctx, txIngressWALOutboxEnqueued, batchID, eventID, payload)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full WAL queue error=%v, want deadline exceeded", err)
	}
	close(db.release)
	for index, result := range results {
		if err := <-result; err != nil {
			t.Fatalf("queued append %d: %v", index, err)
		}
	}
	wal.Stop()
}

func TestTxIngressWALStopRejectsLateAppendWithoutQueueing(t *testing.T) {
	config := testTxQUICConfig()
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wal.Stop()

	// A closed lifetime and a buffered send are simultaneously selectable in
	// Append's enqueue select. Exercise enough late callers that the old
	// ungated implementation deterministically leaves work behind after the
	// commit loop's final drain.
	for index := 0; index < cap(wal.appendCh)*4; index++ {
		batchID := crypto.Keccak256Hash([]byte("late WAL batch"), []byte{byte(index), byte(index >> 8)})
		eventID := crypto.Keccak256Hash([]byte("late WAL event"), []byte{byte(index), byte(index >> 8)})
		if _, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, []byte{1}); err == nil {
			t.Fatalf("late append %d succeeded after Stop", index)
		}
	}
	if queued := len(wal.appendCh); queued != 0 {
		t.Fatalf("%d late appends crossed admission after the final drain", queued)
	}
}

func TestTxIngressWALConcurrentStopsWaitForSameCompletion(t *testing.T) {
	config := testTxQUICConfig()
	db := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
	}
	wal := newTxIngressWAL(db, config)
	// Keep the initial append below the automatic checkpoint threshold, then
	// make the same state require a checkpoint before explicitly waking the
	// tracked compaction worker.
	wal.maxRecords = 3
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	batchID, eventID, payload := testIngressWALEvent(91)
	if _, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, payload); err != nil {
		t.Fatal(err)
	}
	wal.mu.Lock()
	wal.maxRecords = 1
	wal.mu.Unlock()
	db.block.Store(true)
	wal.requestCompaction()
	select {
	case <-db.started:
	case <-time.After(time.Second):
		close(db.release)
		wal.Stop()
		t.Fatal("tracked WAL compaction did not reach the blocking fsync")
	}

	firstStopped := make(chan struct{})
	go func() {
		wal.Stop()
		close(firstStopped)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		wal.mu.Lock()
		stopping := wal.stopped
		wal.mu.Unlock()
		if stopping {
			break
		}
		if time.Now().After(deadline) {
			close(db.release)
			<-firstStopped
			t.Fatal("first Stop did not begin shutdown")
		}
		time.Sleep(time.Millisecond)
	}

	secondStopped := make(chan struct{})
	go func() {
		wal.Stop()
		close(secondStopped)
	}()
	select {
	case <-secondStopped:
		close(db.release)
		<-firstStopped
		t.Fatal("concurrent Stop returned before the shared shutdown completed")
	case <-time.After(25 * time.Millisecond):
	}
	close(db.release)
	for index, stopped := range []<-chan struct{}{firstStopped, secondStopped} {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatalf("Stop caller %d did not observe shared completion", index)
		}
	}
}

func TestTxIngressWALCancellationTerminatesCommitAndCapacityWaiters(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitMaxRequests = 1
	db := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
	}
	wal := newTxIngressWAL(db, config)
	parent, cancel := context.WithCancel(context.Background())
	if err := wal.Start(parent); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		cancel()
		if !released {
			close(db.release)
		}
		wal.Stop()
	}()
	db.block.Store(true)

	appendAsync := func(index byte) <-chan error {
		done := make(chan error, 1)
		go func() {
			batchID, eventID, payload := testIngressWALEvent(index)
			_, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, payload)
			done <- err
		}()
		return done
	}
	commitWaiter := appendAsync(101)
	select {
	case <-db.started:
	case <-time.After(time.Second):
		t.Fatal("WAL commit did not reach the blocking fsync")
	}
	queued := make([]<-chan error, 0, cap(wal.appendCh))
	for index := 0; index < cap(wal.appendCh); index++ {
		queued = append(queued, appendAsync(byte(102+index)))
	}
	deadline := time.Now().Add(time.Second)
	for len(wal.appendCh) != cap(wal.appendCh) {
		if time.Now().After(deadline) {
			t.Fatalf("WAL append queue did not fill: len=%d cap=%d", len(wal.appendCh), cap(wal.appendCh))
		}
		time.Sleep(time.Millisecond)
	}
	capacityWaiter := appendAsync(120)
	select {
	case err := <-capacityWaiter:
		t.Fatalf("capacity waiter returned before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	cancel()
	for name, result := range map[string]<-chan error{
		"commit": commitWaiter, "capacity": capacityWaiter,
	} {
		select {
		case err := <-result:
			if err == nil {
				t.Fatalf("%s waiter succeeded after WAL lifetime cancellation", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s waiter did not terminate after WAL lifetime cancellation", name)
		}
	}
	for index, result := range queued {
		select {
		case err := <-result:
			if err == nil {
				t.Fatalf("queued waiter %d succeeded after WAL lifetime cancellation", index)
			}
		case <-time.After(time.Second):
			t.Fatalf("queued waiter %d did not terminate after WAL lifetime cancellation", index)
		}
	}
	close(db.release)
	released = true
}

func TestTxIngressWALDefaultCapacityCoversStandardBurstPartitioning(t *testing.T) {
	const transactionsPerRecord = 8 // 512 unique senders / 64 bounded partitions
	burstTransactions := int64(params.EVMParallelIngressBurstTransactions)
	burstRecords := (burstTransactions + transactionsPerRecord - 1) / transactionsPerRecord
	placementBytes := burstRecords * txOutboxPlacementReserveBytes
	minimumOutboxBytes := placementBytes + txQUICMaxBridgeQueueBytes
	if defaultTxOutboxMaxBytes < minimumOutboxBytes {
		t.Fatalf("default outbox bytes %d cannot retain %d partitioned records: placement=%d payload=%d minimum=%d",
			defaultTxOutboxMaxBytes, burstRecords, placementBytes, txQUICMaxBridgeQueueBytes, minimumOutboxBytes)
	}
	if txQUICMaxOutboxBytes < defaultTxOutboxMaxBytes {
		t.Fatalf("hard outbox byte limit %d is below default %d", txQUICMaxOutboxBytes, defaultTxOutboxMaxBytes)
	}
	if int64(defaultTxOutboxMaxRecords) < burstRecords {
		t.Fatalf("default outbox record limit %d is below partitioned burst %d", defaultTxOutboxMaxRecords, burstRecords)
	}
	// A live local batch may retain its intent, outcome and canonical outbox
	// projection until finality. The WAL shares the byte setting but has its own
	// record accounting, so check both derived dimensions explicitly.
	if int64(defaultTxOutboxMaxRecords) < burstRecords*3 {
		t.Fatalf("default WAL record limit %d cannot retain three lifecycle records for %d batches", defaultTxOutboxMaxRecords, burstRecords)
	}
	wal := newTxIngressWAL(memorydb.New(), TxQUICConfig{})
	if wal.maxBytes != defaultTxOutboxMaxBytes || wal.maxRecords != defaultTxOutboxMaxRecords {
		t.Fatalf("zero-config WAL capacity = %d/%d, want %d/%d",
			wal.maxBytes, wal.maxRecords, defaultTxOutboxMaxBytes, defaultTxOutboxMaxRecords)
	}
	if txQUICMaxBridgeQueueBytes != 1<<30 || DefaultConfig.TxQUIC.BridgeQueueMaxBytes > txQUICMaxBridgeQueueBytes {
		t.Fatalf("bridge memory bound changed with disk capacity: default=%d hard=%d",
			DefaultConfig.TxQUIC.BridgeQueueMaxBytes, txQUICMaxBridgeQueueBytes)
	}
}

func TestTxIngressWALRejectsRecordBeyondHardCapacity(t *testing.T) {
	config := testTxQUICConfig()
	wal := newTxIngressWAL(memorydb.New(), config)
	wal.maxBytes = 1
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()
	batchID, eventID, payload := testIngressWALEvent(121)
	if _, err := wal.Append(context.Background(), txIngressWALOutboxEnqueued, batchID, eventID, payload); err == nil || !strings.Contains(err.Error(), "capacity exceeded") {
		t.Fatalf("over-capacity WAL append error = %v", err)
	}
	wal.mu.Lock()
	sequence, records, bytes := wal.sequence, wal.records, wal.bytes
	wal.mu.Unlock()
	if sequence != 0 || records != 0 || bytes != 0 {
		t.Fatalf("rejected WAL record changed accounting: sequence=%d records=%d bytes=%d", sequence, records, bytes)
	}
}

func TestTxOutboxRetryReleasesGlobalLockBeforeWALFsync(t *testing.T) {
	config := testTxQUICConfig()
	walDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outbox := NewTxOutbox(memorydb.New(), config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-walDB.release:
		default:
			close(walDB.release)
		}
		outbox.Stop()
		wal.Stop()
	}()

	batchIDs := make([]common.Hash, 0, 2)
	for seed := uint64(1); len(batchIDs) < 2; seed++ {
		payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(seed, 32))
		batchID, err := outbox.StoreSync(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(batchIDs) == 0 || txOutboxLifecycleStripe(batchIDs[0]) != txOutboxLifecycleStripe(batchID) {
			batchIDs = append(batchIDs, batchID)
		}
	}

	walDB.block.Store(true)
	results := make(chan error, 2)
	go func() {
		_, err := outbox.updateRetry(batchIDs[0], errors.New("first delivery failed"))
		results <- err
	}()
	select {
	case <-walDB.started:
	case <-time.After(time.Second):
		t.Fatal("first retry did not reach the blocked WAL fsync")
	}
	go func() {
		_, err := outbox.updateRetry(batchIDs[1], errors.New("second delivery failed"))
		results <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(wal.appendCh) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("second retry was serialized behind the first WAL fsync by the global outbox lock")
		}
		time.Sleep(time.Millisecond)
	}
	close(walDB.release)
	for range batchIDs {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTxOutboxNonceStreamsReleaseGlobalLockBeforeWALFsync(t *testing.T) {
	config := testTxQUICConfig()
	walDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outbox := NewTxOutbox(memorydb.New(), config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-walDB.release:
		default:
			close(walDB.release)
		}
		outbox.Stop()
		wal.Stop()
	}()

	senders := make([]common.Address, 0, 2)
	epochs := make([]common.Hash, 0, 2)
	for index := uint64(1); len(senders) < 2; index++ {
		sender := common.BigToAddress(new(big.Int).SetUint64(index))
		epoch := txQUICSenderEpoch(config.ChainID, config.GenesisHash, sender)
		stripeID := crypto.Keccak256Hash(txOutboxNonceKey(sender, epoch))
		if len(senders) == 0 || txOutboxLifecycleStripe(crypto.Keccak256Hash(txOutboxNonceKey(senders[0], epochs[0]))) != txOutboxLifecycleStripe(stripeID) {
			senders = append(senders, sender)
			epochs = append(epochs, epoch)
		}
	}

	walDB.block.Store(true)
	results := make(chan error, 2)
	go func() {
		_, err := outbox.NextNonce(senders[0], epochs[0])
		results <- err
	}()
	select {
	case <-walDB.started:
	case <-time.After(time.Second):
		t.Fatal("first nonce stream did not reach the blocked WAL fsync")
	}
	go func() {
		_, err := outbox.NextNonce(senders[1], epochs[1])
		results <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(wal.appendCh) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("second nonce stream was serialized behind the first WAL fsync by the global outbox lock")
		}
		time.Sleep(time.Millisecond)
	}
	close(walDB.release)
	for range senders {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTxOutboxRetryUsesWALGroupCommitAcrossBatchIDs(t *testing.T) {
	config := testTxQUICConfig()
	config.IngressCommitInterval = 50 * time.Millisecond
	config.IngressCommitMaxRequests = 16
	walDB := &countingTxQUICDB{KeyValueStore: memorydb.New()}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outbox := NewTxOutbox(memorydb.New(), config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	defer func() {
		outbox.Stop()
		wal.Stop()
	}()

	batchIDs := make([]common.Hash, 0, 2)
	for seed := uint64(100); len(batchIDs) < 2; seed++ {
		payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(seed, 32))
		batchID, err := outbox.StoreSync(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(batchIDs) == 0 || txOutboxLifecycleStripe(batchIDs[0]) != txOutboxLifecycleStripe(batchID) {
			batchIDs = append(batchIDs, batchID)
		}
	}
	walDB.syncWrites.Store(0)

	start := make(chan struct{})
	results := make(chan error, len(batchIDs))
	for index, batchID := range batchIDs {
		go func(index int, batchID common.Hash) {
			<-start
			_, err := outbox.updateRetry(batchID, fmt.Errorf("delivery %d failed", index))
			results <- err
		}(index, batchID)
	}
	close(start)
	for range batchIDs {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if writes := walDB.syncWrites.Load(); writes != 1 {
		t.Fatalf("independent retry mutations used %d WAL fsync groups, want 1", writes)
	}
}

func TestTxOutboxPlacementReleasesGlobalLockBeforeWALFsync(t *testing.T) {
	config := testTxQUICConfig()
	walDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outbox := NewTxOutbox(memorydb.New(), config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-walDB.release:
		default:
			close(walDB.release)
		}
		outbox.Stop()
		wal.Stop()
	}()

	payloads := make([][]byte, 0, 2)
	batchIDs := make([]common.Hash, 0, 2)
	for seed := uint64(200); len(batchIDs) < 2; seed++ {
		payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(seed, 32))
		batchID, err := outbox.StoreSync(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(batchIDs) == 0 || txOutboxLifecycleStripe(batchIDs[0]) != txOutboxLifecycleStripe(batchID) {
			payloads = append(payloads, payload)
			batchIDs = append(batchIDs, batchID)
		}
	}
	states := []txOutboxPlacementState{
		testTxOutboxPlacementState(t, 4, 16200),
		testTxOutboxPlacementState(t, 4, 16300),
	}
	for index := range states {
		for completed := 0; completed < txQUICReceiptQuorum(len(states[index].Endpoints)); completed++ {
			txQUICBitmapSet(states[index].CompletedBitmap, completed)
		}
	}
	aggregates := []txQUICAck{
		testTxOutboxPromotionAggregate(t, config, payloads[0], states[0]),
		testTxOutboxPromotionAggregate(t, config, payloads[1], states[1]),
	}

	walDB.block.Store(true)
	results := make(chan error, 2)
	go func() {
		results <- outbox.promotePlacementSync(batchIDs[0], states[0], aggregates[0])
	}()
	select {
	case <-walDB.started:
	case <-time.After(time.Second):
		t.Fatal("first placement did not reach the blocked WAL fsync")
	}
	go func() {
		results <- outbox.promotePlacementSync(batchIDs[1], states[1], aggregates[1])
	}()
	deadline := time.Now().Add(time.Second)
	for len(wal.appendCh) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("second placement was serialized behind the first WAL fsync by the global outbox lock")
		}
		time.Sleep(time.Millisecond)
	}
	close(walDB.release)
	for range batchIDs {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTxOutboxDeleteReleasesGlobalLockBeforeWALFsync(t *testing.T) {
	config := testTxQUICConfig()
	walDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	projectionDB := memorydb.New()
	outbox := NewTxOutbox(projectionDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-walDB.release:
		default:
			close(walDB.release)
		}
		outbox.Stop()
		wal.Stop()
	}()

	records := make([]TxOutboxRecord, 0, 2)
	for seed := uint64(300); len(records) < 2; seed++ {
		payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(seed, 32))
		batchID, err := outbox.StoreSync(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) == 0 || txOutboxLifecycleStripe(records[0].BatchID) != txOutboxLifecycleStripe(batchID) {
			records = append(records, testTxOutboxStoredRecord(t, projectionDB, batchID))
		}
	}

	walDB.block.Store(true)
	results := make(chan error, 2)
	go func() { results <- outbox.deleteRecord(&records[0]) }()
	select {
	case <-walDB.started:
	case <-time.After(time.Second):
		t.Fatal("first delete did not reach the blocked WAL fsync")
	}
	go func() { results <- outbox.deleteRecord(&records[1]) }()
	deadline := time.Now().Add(time.Second)
	for len(wal.appendCh) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("second delete was serialized behind the first WAL fsync by the global outbox lock")
		}
		time.Sleep(time.Millisecond)
	}
	close(walDB.release)
	for range records {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if pending, charged := outbox.Pending(); pending != 0 || charged != 0 {
		t.Fatalf("concurrent deletes left outbox accounting at %d records/%d bytes", pending, charged)
	}
}

func TestTxOutboxVisibilityWaitsForUnifiedWALFsync(t *testing.T) {
	config := testTxQUICConfig()
	walDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outboxDB := memorydb.New()
	outbox := NewTxOutbox(outboxDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(1, 32))
	batchID := txOutboxBatchID(payload)
	walDB.block.Store(true)
	stored := make(chan error, 1)
	go func() {
		_, err := outbox.StoreSync(context.Background(), payload)
		stored <- err
	}()
	select {
	case <-walDB.started:
	case <-time.After(time.Second):
		t.Fatal("unified WAL fsync did not start")
	}
	if has, err := outboxDB.Has(txOutboxRecordKey(batchID)); err != nil || has {
		t.Fatalf("outbox became visible before WAL fsync: has=%t err=%v", has, err)
	}
	close(walDB.release)
	select {
	case err := <-stored:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("outbox store did not resume after WAL fsync")
	}
	if has, err := outboxDB.Has(txOutboxRecordKey(batchID)); err != nil || !has {
		t.Fatalf("outbox was not materialized after WAL fsync: has=%t err=%v", has, err)
	}
	outbox.Stop()
	wal.Stop()
}

func TestTxOutboxCapacityAdmissionPrecedesReplayOwnership(t *testing.T) {
	for _, test := range []struct {
		name         string
		localOutcome bool
	}{
		{name: "outbox enqueue"},
		{name: "local RPC outcome", localOutcome: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testTxQUICConfig()
			config.OutboxMaxRecords = 1
			payloadA := testTxQUICBatchPayload(t, config, testTxQUICTransaction(525, 8))
			payloadB := testTxQUICBatchPayload(t, config, testTxQUICTransaction(526, 8))
			capacityA, err := txOutboxRecordCapacityBytes(payloadA)
			if err != nil {
				t.Fatal(err)
			}
			capacityB, err := txOutboxRecordCapacityBytes(payloadB)
			if err != nil {
				t.Fatal(err)
			}
			config.OutboxMaxBytes = capacityA
			if capacityB > config.OutboxMaxBytes {
				config.OutboxMaxBytes = capacityB
			}

			walDB := memorydb.New()
			wal := newTxIngressWAL(walDB, config)
			// The focused projection capacity is one record. Keep enough raw WAL
			// headroom for the intent+outcome lifecycle being exercised.
			wal.maxRecords = 64
			wal.maxBytes = config.OutboxMaxBytes * 64
			if err := wal.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			projectionDB := memorydb.New()
			outbox := NewTxOutbox(projectionDB, config)
			outbox.wal = wal
			if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
				<-ctx.Done()
				return ctx.Err()
			}, nil); err != nil {
				t.Fatal(err)
			}

			store := func(ctx context.Context, payload []byte) error {
				if !test.localOutcome {
					_, err := outbox.StoreSync(ctx, payload)
					return err
				}
				intent, _, err := decodeTxQUICBatch(payload)
				if err != nil {
					return err
				}
				intentID, err := wal.appendLocalIntent(ctx, intent)
				if err != nil {
					return err
				}
				accepted := make([]byte, txQUICBitmapBytes(len(intent.Items)))
				for index := range intent.Items {
					txQUICBitmapSet(accepted, index)
				}
				_, err = outbox.storeLocalOutcomeVerifiedSync(ctx, payload, func(durableCtx context.Context) error {
					return wal.appendLocalOutcome(durableCtx, intent.BatchID, intentID, len(intent.Items), accepted)
				})
				return err
			}
			if err := store(context.Background(), payloadA); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			err = store(ctx, payloadB)
			cancel()
			if err == nil || !strings.Contains(err.Error(), "capacity wait") {
				t.Fatalf("second ownership crossed full capacity: %v", err)
			}

			outcomeB := false
			batchB, _, err := decodeTxQUICBatch(payloadB)
			if err != nil {
				t.Fatal(err)
			}
			if err := wal.Replay(func(frame *txIngressWALFrame) error {
				if frame.BatchID == batchB.BatchID && (frame.Kind == txIngressWALOutboxEnqueued || frame.Kind == txIngressWALLocalOutcome) {
					outcomeB = true
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if outcomeB {
				t.Fatal("capacity-rejected batch became replay-owned before projection admission")
			}
			outbox.Stop()
			wal.Stop() // crash/restart after the rejected ownership attempt

			restartedWAL := newTxIngressWAL(walDB, config)
			restartedWAL.maxRecords = 64
			restartedWAL.maxBytes = config.OutboxMaxBytes * 64
			if err := restartedWAL.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer restartedWAL.Stop()
			restartedProjection := memorydb.New()
			restartedOutbox := NewTxOutbox(restartedProjection, config)
			if err := ensureTxQUICDatabaseIdentity(restartedProjection, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}); err != nil {
				t.Fatal(err)
			}
			q := &TxQUICIngress{config: config, ctx: context.Background(), wal: restartedWAL, outbox: restartedOutbox}
			if err := q.replayWALOutboxProjection(); err != nil {
				t.Fatal(err)
			}
			if err := restartedOutbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
				<-ctx.Done()
				return ctx.Err()
			}, nil); err != nil {
				t.Fatalf("capacity-bounded WAL projection could not restart: %v", err)
			}
			defer restartedOutbox.Stop()
			if records, _ := restartedOutbox.Pending(); records != 1 {
				t.Fatalf("restart materialized %d active records, want 1", records)
			}
		})
	}
}

func TestTxIngressWALExistingResidualReplacementPreservesPlacementOnRestart(t *testing.T) {
	config := testTxQUICConfig()
	walDB := memorydb.New()
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	projectionDB := memorydb.New()
	outbox := NewTxOutbox(projectionDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}

	batch := testTxQUICBatch(t, config, testTxQUICTransaction(527, 0), testTxQUICTransaction(528, 0))
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := outbox.StoreSync(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	residualBatch, residualPayload := testTxOutboxResidual(t, batch, 1)
	if _, err := outbox.StoreSync(context.Background(), residualPayload); err != nil {
		t.Fatal(err)
	}
	placement := testTxOutboxPlacementState(t, 4, 20100)
	quorum := txQUICReceiptQuorum(len(placement.Endpoints))
	for index := 0; index < quorum; index++ {
		txQUICBitmapSet(placement.CompletedBitmap, index)
	}
	placement.NextEndpoint = uint32(quorum)
	if err := outbox.promotePlacementSync(residualBatch.BatchID, placement, testTxOutboxPromotionAggregate(t, config, residualPayload, placement)); err != nil {
		t.Fatal(err)
	}
	wantRetry, err := outbox.updateRetry(residualBatch.BatchID, errors.New("preserved residual retry"))
	if err != nil {
		t.Fatal(err)
	}
	oldRecord := testTxOutboxStoredRecord(t, projectionDB, oldID)
	residual, oldDeleted, err := outbox.compactAcknowledgedRecord(&oldRecord, testTxOutboxPartialAck(t, config, batch, []int{0}, []int{1}))
	if err != nil {
		t.Fatal(err)
	}
	if residual == nil || residual.BatchID != residualBatch.BatchID || !oldDeleted {
		t.Fatalf("existing residual replacement = %#v deleted=%t", residual, oldDeleted)
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	outbox.Stop()
	wal.Stop()

	restartedWAL := newTxIngressWAL(walDB, config)
	if err := restartedWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restartedWAL.Stop()
	restartedDB := memorydb.New()
	restartedOutbox := NewTxOutbox(restartedDB, config)
	if err := ensureTxQUICDatabaseIdentity(restartedDB, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}); err != nil {
		t.Fatal(err)
	}
	q := &TxQUICIngress{config: config, ctx: context.Background(), wal: restartedWAL, outbox: restartedOutbox}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	restored := testTxOutboxStoredRecord(t, restartedDB, residualBatch.BatchID)
	wantPlacement := placement
	wantPlacement.QuorumEstablished = true
	wantPlacementRLP, err := rlp.EncodeToBytes(&wantPlacement)
	if err != nil {
		t.Fatal(err)
	}
	gotPlacementRLP, err := rlp.EncodeToBytes(&restored.Placement)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlacementRLP, wantPlacementRLP) {
		t.Fatalf("restart rolled existing residual placement back: got %#v want %#v", restored.Placement, wantPlacement)
	}
	gotRetry, err := restartedOutbox.readRetry(residualBatch.BatchID)
	if err != nil || gotRetry != wantRetry {
		t.Fatalf("restart residual retry = %#v err=%v, want %#v", gotRetry, err, wantRetry)
	}
}

func TestTxIngressWALDuplicateLocalOutcomePreservesActiveProjectionOnRestart(t *testing.T) {
	config := testTxQUICConfig()
	walDB := memorydb.New()
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	projectionDB := memorydb.New()
	outbox := NewTxOutbox(projectionDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		wal.Stop()
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(529, 0))
	intent, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make([]byte, txQUICBitmapBytes(len(intent.Items)))
	for index := range intent.Items {
		txQUICBitmapSet(accepted, index)
	}
	storeLocal := func() error {
		intentID, err := wal.appendLocalIntent(context.Background(), intent)
		if err != nil {
			return err
		}
		_, err = outbox.storeLocalOutcomeVerifiedSync(context.Background(), payload, func(durableCtx context.Context) error {
			return wal.appendLocalOutcome(durableCtx, intent.BatchID, intentID, len(intent.Items), accepted)
		})
		return err
	}
	if err := storeLocal(); err != nil {
		t.Fatal(err)
	}
	placement := testTxOutboxPlacementState(t, 4, 20200)
	quorum := txQUICReceiptQuorum(len(placement.Endpoints))
	for index := 0; index < quorum; index++ {
		txQUICBitmapSet(placement.CompletedBitmap, index)
	}
	placement.NextEndpoint = uint32(quorum)
	if err := outbox.promotePlacementSync(intent.BatchID, placement, testTxOutboxPromotionAggregate(t, config, payload, placement)); err != nil {
		t.Fatal(err)
	}
	wantRetry, err := outbox.updateRetry(intent.BatchID, errors.New("preserved duplicate retry"))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeLocal(); err != nil {
		t.Fatal(err)
	}
	wantPlacement := placement
	wantPlacement.QuorumEstablished = true
	wantPlacementRLP, err := rlp.EncodeToBytes(&wantPlacement)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise replay of the uncompacted duplicate outcomes independently of
	// canonical compaction's final full-state checkpoint.
	directDB := memorydb.New()
	directOutbox := NewTxOutbox(directDB, config)
	if err := ensureTxQUICDatabaseIdentity(directDB, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}); err != nil {
		t.Fatal(err)
	}
	direct := &TxQUICIngress{config: config, ctx: context.Background(), wal: wal, outbox: directOutbox}
	if err := direct.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	directRecord := testTxOutboxStoredRecord(t, directDB, intent.BatchID)
	directPlacementRLP, err := rlp.EncodeToBytes(&directRecord.Placement)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(directPlacementRLP, wantPlacementRLP) {
		t.Fatalf("uncompacted duplicate local outcome rolled active placement back: got %#v want %#v", directRecord.Placement, wantPlacement)
	}
	directRetry, err := directOutbox.readRetry(intent.BatchID)
	if err != nil || directRetry != wantRetry {
		t.Fatalf("uncompacted duplicate local outcome retry = %#v err=%v, want %#v", directRetry, err, wantRetry)
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	outbox.Stop()
	wal.Stop()

	restartedWAL := newTxIngressWAL(walDB, config)
	if err := restartedWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restartedWAL.Stop()
	restartedDB := memorydb.New()
	restartedOutbox := NewTxOutbox(restartedDB, config)
	if err := ensureTxQUICDatabaseIdentity(restartedDB, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}); err != nil {
		t.Fatal(err)
	}
	q := &TxQUICIngress{config: config, ctx: context.Background(), wal: restartedWAL, outbox: restartedOutbox}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	restored := testTxOutboxStoredRecord(t, restartedDB, intent.BatchID)
	gotPlacementRLP, err := rlp.EncodeToBytes(&restored.Placement)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPlacementRLP, wantPlacementRLP) {
		t.Fatalf("duplicate local outcome rolled active placement back: got %#v want %#v", restored.Placement, wantPlacement)
	}
	gotRetry, err := restartedOutbox.readRetry(intent.BatchID)
	if err != nil || gotRetry != wantRetry {
		t.Fatalf("duplicate local outcome retry = %#v err=%v, want %#v", gotRetry, err, wantRetry)
	}
}

func TestTxIngressWALRebuildsOutboxProjectionIdempotently(t *testing.T) {
	config := testTxQUICConfig()
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()
	outboxDB := memorydb.New()
	outbox := NewTxOutbox(outboxDB, config)
	q := &TxQUICIngress{config: config, wal: wal, outbox: outbox}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(3, 64))
	record := TxOutboxRecord{BatchID: txOutboxBatchID(payload), Payload: payload, CreatedAt: uint64(time.Now().UnixNano())}
	retry := txOutboxRetryState{Attempts: 2, NextRetry: uint64(time.Now().Add(time.Second).UnixNano()), LastError: "retry"}
	if err := wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, record, txOutboxRetryState{}); err != nil {
		t.Fatal(err)
	}
	if err := wal.appendOutbox(context.Background(), txIngressWALOutboxState, record, retry); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		if err := q.replayWALOutboxProjection(); err != nil {
			t.Fatalf("projection pass %d: %v", pass, err)
		}
	}
	raw, err := outboxDB.Get(txOutboxRecordKey(record.BatchID))
	if err != nil {
		t.Fatal(err)
	}
	var restored TxOutboxRecord
	if err := rlp.DecodeBytes(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.BatchID != record.BatchID || string(restored.Payload) != string(record.Payload) {
		t.Fatal("replayed outbox record changed")
	}
	restoredRetry, err := outbox.readRetry(record.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if restoredRetry != retry {
		t.Fatalf("replayed retry=%#v want=%#v", restoredRetry, retry)
	}
}

func appendCheckpointTestOutbox(t *testing.T, wal *txIngressWAL, config TxQUICConfig, nonce uint64) TxOutboxRecord {
	t.Helper()
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(nonce, 16))
	record := TxOutboxRecord{BatchID: txOutboxBatchID(payload), Payload: payload, CreatedAt: uint64(time.Now().UnixNano())}
	if err := wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, record, txOutboxRetryState{}); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestTxIngressWALCheckpointCrashBeforeAndAfterManifestSwitch(t *testing.T) {
	for _, test := range []struct {
		name           string
		mode           int32
		wantGeneration uint64
	}{
		{name: "before switch", mode: 1, wantGeneration: 0},
		{name: "after switch", mode: 2, wantGeneration: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testTxQUICConfig()
			db := &checkpointFaultTxQUICDB{KeyValueStore: memorydb.New()}
			wal := newTxIngressWAL(db, config)
			if err := wal.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			record := appendCheckpointTestOutbox(t, wal, config, 100+uint64(test.mode))
			db.mode.Store(test.mode)
			if err := wal.Compact(); err == nil {
				t.Fatal("faulted checkpoint unexpectedly succeeded")
			}
			wal.Stop()
			db.mode.Store(0)

			restarted := newTxIngressWAL(db, config)
			if err := restarted.Start(context.Background()); err != nil {
				t.Fatalf("restart after checkpoint crash: %v", err)
			}
			defer restarted.Stop()
			if restarted.generation != test.wantGeneration {
				t.Fatalf("active generation=%d want=%d", restarted.generation, test.wantGeneration)
			}
			var replayed []common.Hash
			if err := restarted.Replay(func(frame *txIngressWALFrame) error {
				if frame.Kind == txIngressWALOutboxEnqueued {
					replayed = append(replayed, frame.BatchID)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(replayed) != 1 || replayed[0] != record.BatchID {
				t.Fatalf("checkpoint crash replay=%v want=%s", replayed, record.BatchID)
			}
			// Reuse the next generation immediately. In the before-switch case it
			// contains the orphan written by the simulated crash; durable cleanup
			// must prevent stale records beyond the new canonical tail.
			if err := restarted.Compact(); err != nil {
				t.Fatalf("reuse generation after checkpoint crash: %v", err)
			}
			replayed = nil
			if err := restarted.Replay(func(frame *txIngressWALFrame) error {
				if frame.Kind == txIngressWALOutboxEnqueued {
					replayed = append(replayed, frame.BatchID)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(replayed) != 1 || replayed[0] != record.BatchID {
				t.Fatalf("reused checkpoint generation replay=%v want=%s", replayed, record.BatchID)
			}
		})
	}
}

func TestTxIngressWALCheckpointSerializesConcurrentAppendAndRestarts(t *testing.T) {
	config := testTxQUICConfig()
	db := &checkpointFaultTxQUICDB{
		KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
	}
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := appendCheckpointTestOutbox(t, wal, config, 201)
	db.mode.Store(3)
	compacted := make(chan error, 1)
	go func() { compacted <- wal.Compact() }()
	select {
	case <-db.started:
	case <-time.After(time.Second):
		t.Fatal("checkpoint did not reach atomic manifest switch")
	}
	secondPayload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(202, 16))
	second := TxOutboxRecord{BatchID: txOutboxBatchID(secondPayload), Payload: secondPayload, CreatedAt: uint64(time.Now().UnixNano())}
	appended := make(chan error, 1)
	go func() {
		appended <- wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, second, txOutboxRetryState{})
	}()
	select {
	case <-appended:
		close(db.release)
		t.Fatal("append crossed an in-progress checkpoint")
	case <-time.After(20 * time.Millisecond):
	}
	close(db.release)
	if err := <-compacted; err != nil {
		t.Fatal(err)
	}
	if err := <-appended; err != nil {
		t.Fatal(err)
	}
	wal.Stop()
	db.mode.Store(0)

	restarted := newTxIngressWAL(db, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	seen := make(map[common.Hash]bool)
	if err := restarted.Replay(func(frame *txIngressWALFrame) error {
		if frame.Kind == txIngressWALOutboxEnqueued {
			seen[frame.BatchID] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !seen[first.BatchID] || !seen[second.BatchID] || len(seen) != 2 {
		t.Fatalf("checkpoint/concurrent append replay=%v", seen)
	}
}

func TestTxIngressWALBulkCheckpointAllowsConcurrentAppendAndExactRestart(t *testing.T) {
	config := testTxQUICConfig()
	db := &checkpointFaultTxQUICDB{
		KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
	}
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := appendCheckpointTestOutbox(t, wal, config, 211)
	db.mode.Store(4)
	compacted := make(chan error, 1)
	go func() { compacted <- wal.Compact() }()
	select {
	case <-db.started:
	case <-time.After(time.Second):
		t.Fatal("checkpoint did not reach a bulk target-generation fsync")
	}

	secondPayload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(212, 16))
	second := TxOutboxRecord{BatchID: txOutboxBatchID(secondPayload), Payload: secondPayload, CreatedAt: uint64(time.Now().UnixNano())}
	appended := make(chan error, 1)
	go func() {
		appended <- wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, second, txOutboxRetryState{})
	}()
	select {
	case err := <-appended:
		if err != nil {
			close(db.release)
			t.Fatalf("append during bulk checkpoint: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(db.release)
		t.Fatal("append was stalled by bulk checkpoint construction")
	}
	close(db.release)
	if err := <-compacted; err != nil {
		t.Fatal(err)
	}
	wal.Stop()
	db.mode.Store(0)

	restarted := newTxIngressWAL(db, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	seen := make(map[common.Hash]int)
	if err := restarted.Replay(func(frame *txIngressWALFrame) error {
		if frame.Kind == txIngressWALOutboxEnqueued {
			seen[frame.BatchID]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen[first.BatchID] != 1 || seen[second.BatchID] != 1 || len(seen) != 2 {
		t.Fatalf("bulk checkpoint restart replay=%v", seen)
	}
}

func TestTxIngressWALConcurrentAppendCheckpointCrashReplaysExactly(t *testing.T) {
	for _, test := range []struct {
		name           string
		mode           int32
		wantGeneration uint64
	}{
		{name: "before manifest switch", mode: 5, wantGeneration: 0},
		{name: "after manifest switch", mode: 6, wantGeneration: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testTxQUICConfig()
			db := &checkpointFaultTxQUICDB{
				KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
			}
			wal := newTxIngressWAL(db, config)
			if err := wal.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			first := appendCheckpointTestOutbox(t, wal, config, 220+uint64(test.mode))
			db.mode.Store(test.mode)
			compacted := make(chan error, 1)
			go func() { compacted <- wal.Compact() }()
			select {
			case <-db.started:
			case <-time.After(time.Second):
				t.Fatal("checkpoint did not reach a bulk target-generation fsync")
			}

			secondPayload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(230+uint64(test.mode), 16))
			second := TxOutboxRecord{BatchID: txOutboxBatchID(secondPayload), Payload: secondPayload, CreatedAt: uint64(time.Now().UnixNano())}
			appended := make(chan error, 1)
			go func() {
				appended <- wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, second, txOutboxRetryState{})
			}()
			select {
			case err := <-appended:
				if err != nil {
					close(db.release)
					t.Fatal(err)
				}
			case <-time.After(250 * time.Millisecond):
				close(db.release)
				t.Fatal("append was stalled by bulk checkpoint construction")
			}
			close(db.release)
			if err := <-compacted; err == nil {
				t.Fatal("faulted checkpoint unexpectedly succeeded")
			}
			wal.Stop()
			db.mode.Store(0)

			restarted := newTxIngressWAL(db, config)
			if err := restarted.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer restarted.Stop()
			if restarted.generation != test.wantGeneration {
				t.Fatalf("active generation=%d want=%d", restarted.generation, test.wantGeneration)
			}
			seen := make(map[common.Hash]int)
			if err := restarted.Replay(func(frame *txIngressWALFrame) error {
				if frame.Kind == txIngressWALOutboxEnqueued {
					seen[frame.BatchID]++
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if seen[first.BatchID] != 1 || seen[second.BatchID] != 1 || len(seen) != 2 {
				t.Fatalf("checkpoint crash restart replay=%v", seen)
			}
		})
	}
}

func TestTxIngressWALOnlineCheckpointRecoversCapacity(t *testing.T) {
	config := testTxQUICConfig()
	config.OutboxMaxRecords = 4
	config.OutboxMaxBytes = 16 << 20
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()
	for nonce := uint64(300); nonce < 320; nonce++ {
		record := appendCheckpointTestOutbox(t, wal, config, nonce)
		mutationID, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
		if err != nil {
			t.Fatalf("lifecycle %d exhausted append-only capacity: %v", nonce, err)
		}
		if err := wal.appendOutboxApplied(context.Background(), record.BatchID, mutationID); err != nil {
			t.Fatalf("lifecycle %d could not confirm its projection: %v", nonce, err)
		}
	}
	wal.mu.Lock()
	generation, records := wal.generation, wal.records
	wal.mu.Unlock()
	if generation == 0 {
		t.Fatal("online capacity pressure never checkpointed the WAL")
	}
	if records > config.OutboxMaxRecords {
		t.Fatalf("checkpoint did not recover capacity: records=%d limit=%d", records, config.OutboxMaxRecords)
	}
}

func TestTxIngressWALCheckpointKeepsOnlyUnappliedInbound(t *testing.T) {
	config := testTxQUICConfig()
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()
	sender := common.HexToAddress("0x9876000000000000000000000000000000000001")
	pending := testTxQUICPacket(t, config, sender, 41, testTxQUICTransaction(401, 8))
	applied := testTxQUICPacket(t, config, sender, 42, testTxQUICTransaction(402, 8))
	if err := wal.appendInboundReceived(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if err := wal.appendInboundReceived(context.Background(), applied); err != nil {
		t.Fatal(err)
	}
	ack := testTxQUICAck(t, applied, []int{0}, nil, nil)
	if err := wal.appendInboundOutcome(context.Background(), applied, ack); err != nil {
		t.Fatal(err)
	}
	if err := wal.appendInboundApplied(context.Background(), applied); err != nil {
		t.Fatal(err)
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	var frames []*txIngressWALFrame
	if err := wal.Replay(func(frame *txIngressWALFrame) error {
		frames = append(frames, frame)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].Kind != txIngressWALInboundReceived || frames[0].BatchID != pending.BatchID {
		t.Fatalf("canonical inbound frames=%+v", frames)
	}
}

func TestTxIngressWALCheckpointRetainsUnappliedOutboxMutationCrashWindow(t *testing.T) {
	for _, test := range []struct {
		name        string
		replacement bool
	}{
		{name: "delete"},
		{name: "replacement", replacement: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testTxQUICConfig()
			walDB := memorydb.New()
			projectionDB := memorydb.New()
			wal := newTxIngressWAL(walDB, config)
			if err := wal.Start(context.Background()); err != nil {
				t.Fatal(err)
			}

			oldPayload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(500, 16))
			oldRecord := TxOutboxRecord{
				BatchID: txOutboxBatchID(oldPayload), Payload: oldPayload, CreatedAt: uint64(time.Now().UnixNano()),
			}
			encodedOld, err := rlp.EncodeToBytes(&oldRecord)
			if err != nil {
				t.Fatal(err)
			}
			if err := projectionDB.Put(txOutboxRecordKey(oldRecord.BatchID), encodedOld); err != nil {
				t.Fatal(err)
			}
			staleRetry := txOutboxRetryState{Attempts: 3, NextRetry: 77, LastError: "stale"}
			encodedRetry, err := rlp.EncodeToBytes(&staleRetry)
			if err != nil {
				t.Fatal(err)
			}
			if err := projectionDB.Put(txOutboxRetryKey(oldRecord.BatchID), encodedRetry); err != nil {
				t.Fatal(err)
			}

			mutationRecord := oldRecord
			kind := txIngressWALOutboxDeleted
			supersedes := common.Hash{}
			if test.replacement {
				residualPayload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(501, 16))
				mutationRecord = TxOutboxRecord{
					BatchID: txOutboxBatchID(residualPayload), Payload: residualPayload, CreatedAt: oldRecord.CreatedAt,
				}
				kind = txIngressWALOutboxState
				supersedes = oldRecord.BatchID
			}
			mutationID, err := wal.appendOutboxProjectionTracked(context.Background(), kind, mutationRecord, txOutboxRetryState{}, supersedes)
			if err != nil {
				t.Fatal(err)
			}
			// Exact crash window: the mutation is durable and another append has
			// checkpointed it, but the mutable projection has not been written.
			if err := wal.Compact(); err != nil {
				t.Fatal(err)
			}
			var retained bool
			if err := wal.Replay(func(frame *txIngressWALFrame) error {
				if frame.EventID == mutationID {
					retained = true
				}
				if frame.Kind == txIngressWALOutboxApplied {
					t.Fatal("projection was marked applied before its DB write")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !retained {
				t.Fatal("checkpoint discarded an unapplied destructive outbox mutation")
			}
			wal.Stop()

			restarted := newTxIngressWAL(walDB, config)
			if err := restarted.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer restarted.Stop()
			q := &TxQUICIngress{
				config: config, ctx: context.Background(), wal: restarted,
				outbox: NewTxOutbox(projectionDB, config),
			}
			if err := q.replayWALOutboxProjection(); err != nil {
				t.Fatal(err)
			}
			if has, err := projectionDB.Has(txOutboxRecordKey(oldRecord.BatchID)); err != nil || has {
				t.Fatalf("stale superseded record survived replay: has=%t err=%v", has, err)
			}
			if has, err := projectionDB.Has(txOutboxRetryKey(oldRecord.BatchID)); err != nil || has {
				t.Fatalf("stale superseded retry survived replay: has=%t err=%v", has, err)
			}
			if test.replacement {
				raw, err := projectionDB.Get(txOutboxRecordKey(mutationRecord.BatchID))
				if err != nil {
					t.Fatal(err)
				}
				var restored TxOutboxRecord
				if err := rlp.DecodeBytes(raw, &restored); err != nil {
					t.Fatal(err)
				}
				if restored.BatchID != mutationRecord.BatchID || !bytes.Equal(restored.Payload, mutationRecord.Payload) {
					t.Fatal("replacement projection was not rebuilt from the retained WAL mutation")
				}
			}
			var applied bool
			if err := restarted.Replay(func(frame *txIngressWALFrame) error {
				if frame.Kind == txIngressWALOutboxApplied {
					var payload txIngressWALOutboxAppliedPayload
					if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
						return err
					}
					applied = applied || payload.MutationID == mutationID
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !applied {
				t.Fatal("replay did not durably acknowledge the applied projection")
			}
		})
	}
}

func TestTxIngressWALReenqueueAfterAppliedDeleteSurvivesRestart(t *testing.T) {
	config := testTxQUICConfig()
	walDB := memorydb.New()
	projectionDB := memorydb.New()
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(550, 16))
	record := TxOutboxRecord{
		BatchID: txOutboxBatchID(payload), Payload: payload, CreatedAt: uint64(time.Now().UnixNano()),
	}
	firstEnqueueID, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxEnqueued, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := rlp.EncodeToBytes(&record)
	if err != nil {
		t.Fatal(err)
	}
	if err := projectionDB.Put(txOutboxRecordKey(record.BatchID), encoded); err != nil {
		t.Fatal(err)
	}
	deleteID, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	deleteBatch := projectionDB.NewBatch()
	if err := deleteBatch.Delete(txOutboxRecordKey(record.BatchID)); err != nil {
		t.Fatal(err)
	}
	if err := writeTxIngressWALSync(deleteBatch, "test delete outbox projection"); err != nil {
		t.Fatal(err)
	}
	if err := wal.appendOutboxApplied(context.Background(), record.BatchID, deleteID); err != nil {
		t.Fatal(err)
	}
	secondEnqueueID, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxEnqueued, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if secondEnqueueID == firstEnqueueID {
		t.Fatal("post-delete enqueue reused the completed lifecycle EventID")
	}
	if err := projectionDB.Put(txOutboxRecordKey(record.BatchID), encoded); err != nil {
		t.Fatal(err)
	}
	wal.Stop() // no compaction: the prior enqueue/delete/applied prefix remains

	restarted := newTxIngressWAL(walDB, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	q := &TxQUICIngress{
		config: config, ctx: context.Background(), wal: restarted,
		outbox: NewTxOutbox(projectionDB, config),
	}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	raw, err := projectionDB.Get(txOutboxRecordKey(record.BatchID))
	if err != nil {
		t.Fatalf("post-delete re-enqueue was lost on restart: %v", err)
	}
	var restored TxOutboxRecord
	if err := rlp.DecodeBytes(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.BatchID != record.BatchID || !bytes.Equal(restored.Payload, record.Payload) {
		t.Fatal("post-delete re-enqueue replayed a different record")
	}
}

func TestTxIngressWALLocalIntentReenqueueUsesNewLifecycle(t *testing.T) {
	config := testTxQUICConfig()
	walDB := memorydb.New()
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(555, 16))
	intent, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make([]byte, txQUICBitmapBytes(len(intent.Items)))
	for index := range intent.Items {
		txQUICBitmapSet(accepted, index)
	}
	firstIntentID, err := wal.appendLocalIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.appendLocalOutcome(context.Background(), intent.BatchID, firstIntentID, len(intent.Items), accepted); err != nil {
		t.Fatal(err)
	}
	record := TxOutboxRecord{BatchID: intent.BatchID, Payload: payload, CreatedAt: txOutboxStableCreatedAt(intent.Certificate)}
	deleteID, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.appendOutboxApplied(context.Background(), record.BatchID, deleteID); err != nil {
		t.Fatal(err)
	}
	secondIntentID, err := wal.appendLocalIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if secondIntentID == firstIntentID {
		t.Fatal("post-ACK local intent reused the prior lifecycle EventID")
	}
	if err := wal.appendLocalOutcome(context.Background(), intent.BatchID, secondIntentID, len(intent.Items), accepted); err != nil {
		t.Fatal(err)
	}
	wal.Stop() // retain both lifecycles in one generation

	restarted := newTxIngressWAL(walDB, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	projectionDB := memorydb.New()
	q := &TxQUICIngress{config: config, ctx: context.Background(), wal: restarted, outbox: NewTxOutbox(projectionDB, config)}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	raw, err := projectionDB.Get(txOutboxRecordKey(intent.BatchID))
	if err != nil {
		t.Fatalf("second local lifecycle was lost on restart: %v", err)
	}
	var restored TxOutboxRecord
	if err := rlp.DecodeBytes(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.BatchID != intent.BatchID || !bytes.Equal(restored.Payload, payload) {
		t.Fatal("second local lifecycle replayed a different outbox record")
	}
}

func TestTxIngressWALRetainsAcceptedLocalTxUntilFinality(t *testing.T) {
	config := testTxQUICConfig()
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()

	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(777, 32))
	intent, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make([]byte, txQUICBitmapBytes(len(intent.Items)))
	for index := range intent.Items {
		txQUICBitmapSet(accepted, index)
	}
	intentID, err := wal.appendLocalIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.appendLocalOutcome(context.Background(), intent.BatchID, intentID, len(intent.Items), accepted); err != nil {
		t.Fatal(err)
	}
	acceptedBatch, acceptedPayload, err := txIngressWALAcceptedBatch(intent, accepted)
	if err != nil {
		t.Fatal(err)
	}
	record := TxOutboxRecord{
		BatchID: acceptedBatch.BatchID, Payload: acceptedPayload,
		CreatedAt: txOutboxStableCreatedAt(acceptedBatch.Certificate),
	}
	deleteID, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.appendOutboxApplied(context.Background(), record.BatchID, deleteID); err != nil {
		t.Fatal(err)
	}

	countLocalLifecycle := func() int {
		t.Helper()
		count := 0
		if err := wal.Replay(func(frame *txIngressWALFrame) error {
			if frame.Kind == txIngressWALLocalIntent || frame.Kind == txIngressWALLocalOutcome {
				count++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	if got := countLocalLifecycle(); got != 2 {
		t.Fatalf("pending accepted local lifecycle events = %d, want 2", got)
	}
	projectionDB := memorydb.New()
	q := &TxQUICIngress{
		config: config, ctx: context.Background(), wal: wal,
		outbox: NewTxOutbox(projectionDB, config),
	}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	if has, err := projectionDB.Has(txOutboxRecordKey(acceptedBatch.BatchID)); err != nil || has {
		t.Fatalf("completed accepted batch was re-enqueued after compaction: has=%t err=%v", has, err)
	}

	finalizedHash := intent.Items[0].Tx.Hash()
	wal.setTransactionLookups(func(hash common.Hash) bool { return hash == finalizedHash }, nil)
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	if got := countLocalLifecycle(); got != 0 {
		t.Fatalf("finalized local lifecycle events = %d, want 0", got)
	}
}

func TestTxOutboxSerializesDeleteAndReenqueueWALProjectionOrder(t *testing.T) {
	config := testTxQUICConfig()
	walDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
	}
	projectionDB := memorydb.New()
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outbox := NewTxOutbox(projectionDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(560, 16))
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	record := TxOutboxRecord{
		BatchID: batch.BatchID, Payload: payload, CreatedAt: txOutboxStableCreatedAt(batch.Certificate),
	}
	if _, err := outbox.StoreSync(context.Background(), payload); err != nil {
		t.Fatal(err)
	}

	walDB.block.Store(true)
	deleted := make(chan error, 1)
	go func() { deleted <- outbox.deleteRecord(&record) }()
	select {
	case <-walDB.started:
	case <-time.After(time.Second):
		t.Fatal("delete did not reach its WAL durability boundary")
	}
	reenqueued := make(chan error, 1)
	go func() {
		_, err := outbox.StoreSync(context.Background(), payload)
		reenqueued <- err
	}()
	select {
	case err := <-reenqueued:
		close(walDB.release)
		t.Fatalf("re-enqueue crossed an in-progress delete lifecycle: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(walDB.release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if err := <-reenqueued; err != nil {
		t.Fatal(err)
	}
	walDB.block.Store(false)
	outbox.Stop()
	wal.Stop()

	restarted := newTxIngressWAL(walDB, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	q := &TxQUICIngress{
		config: config, ctx: context.Background(), wal: restarted,
		outbox: NewTxOutbox(projectionDB, config),
	}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	if has, err := projectionDB.Has(txOutboxRecordKey(record.BatchID)); err != nil || !has {
		t.Fatalf("serialized post-delete re-enqueue was lost: has=%t err=%v", has, err)
	}
}

func TestTxOutboxTimeoutTransfersLifecycleUntilProjectionCommit(t *testing.T) {
	config := testTxQUICConfig()
	walDB := memorydb.New()
	projectionDB := &blockingSyncTxQUICDB{
		KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{}),
	}
	wal := newTxIngressWAL(walDB, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	outbox := NewTxOutbox(projectionDB, config)
	outbox.wal = wal
	if err := outbox.Start(context.Background(), func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(565, 16))
	batch, _, err := decodeTxQUICBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	record := TxOutboxRecord{
		BatchID: batch.BatchID, Payload: payload, CreatedAt: txOutboxStableCreatedAt(batch.Certificate),
	}
	if _, err := outbox.StoreSync(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	if err := outbox.deleteRecord(&record); err != nil {
		t.Fatal(err)
	}

	projectionDB.block.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	reenqueueResult := make(chan error, 1)
	go func() {
		_, err := outbox.StoreSync(ctx, payload)
		reenqueueResult <- err
	}()
	select {
	case <-projectionDB.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("re-enqueue did not reach the blocked projection fsync")
	}
	if err := <-reenqueueResult; !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatalf("re-enqueue timeout=%v, want deadline exceeded", err)
	}
	cancel()

	deleted := make(chan error, 1)
	go func() { deleted <- outbox.deleteRecord(&record) }()
	select {
	case err := <-deleted:
		close(projectionDB.release)
		t.Fatalf("delete overtook the background-owned projection commit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(projectionDB.release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	projectionDB.block.Store(false)
	outbox.Stop()
	wal.Stop()

	restarted := newTxIngressWAL(walDB, config)
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	q := &TxQUICIngress{
		config: config, ctx: context.Background(), wal: restarted,
		outbox: NewTxOutbox(projectionDB, config),
	}
	if err := q.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	if has, err := projectionDB.Has(txOutboxRecordKey(record.BatchID)); err != nil || has {
		t.Fatalf("timed-out enqueue resurrected after its serialized delete: has=%t err=%v", has, err)
	}
}

func TestTxIngressWALRoleTransitionKeepsDedicatedAuthority(t *testing.T) {
	for _, test := range []struct {
		name              string
		firstReceiver     bool
		restartedReceiver bool
	}{
		{name: "bridge-only to dual-role", restartedReceiver: true},
		{name: "dual-role to bridge-only", firstReceiver: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testTxQUICConfig()
			config.BridgeEnabled = true
			config.Enabled = test.firstReceiver
			walDB := memorydb.New()
			first := NewTxQUICIngress(config, nil)
			first.SetIngressWALDatabase(walDB)
			first.SetDurableOutbox(NewTxOutbox(memorydb.New(), config), nil)
			if test.firstReceiver {
				first.SetDurableIngress(NewTxQUICIngressStore(memorydb.New(), config))
			}
			if first.wal == nil || first.wal.db != walDB {
				t.Fatal("first role replaced the dedicated WAL database")
			}
			if err := first.wal.Start(first.ctx); err != nil {
				t.Fatal(err)
			}
			payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(580, 16))
			record := TxOutboxRecord{
				BatchID: txOutboxBatchID(payload), Payload: payload, CreatedAt: uint64(time.Now().UnixNano()),
			}
			if err := first.wal.appendOutbox(context.Background(), txIngressWALOutboxEnqueued, record, txOutboxRetryState{}); err != nil {
				t.Fatal(err)
			}
			first.wal.Stop()
			first.cancel()

			restartedConfig := config
			restartedConfig.Enabled = test.restartedReceiver
			restartedProjection := memorydb.New()
			restarted := NewTxQUICIngress(restartedConfig, nil)
			restarted.SetIngressWALDatabase(walDB)
			restarted.SetDurableOutbox(NewTxOutbox(restartedProjection, restartedConfig), nil)
			if test.restartedReceiver {
				restarted.SetDurableIngress(NewTxQUICIngressStore(memorydb.New(), restartedConfig))
			}
			if restarted.wal == nil || restarted.wal.db != walDB {
				t.Fatal("restarted role replaced the dedicated WAL database")
			}
			if err := restarted.wal.Start(restarted.ctx); err != nil {
				t.Fatal(err)
			}
			if err := restarted.replayWALOutboxProjection(); err != nil {
				t.Fatal(err)
			}
			if has, err := restartedProjection.Has(txOutboxRecordKey(record.BatchID)); err != nil || !has {
				t.Fatalf("role transition lost WAL-owned outbox work: has=%t err=%v", has, err)
			}
			restarted.wal.Stop()
			restarted.cancel()
		})
	}
}

func TestTxIngressWALAppliedMarkerCoversEquivalentMutationRetries(t *testing.T) {
	config := testTxQUICConfig()
	wal := newTxIngressWAL(memorydb.New(), config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer wal.Stop()
	payload := testTxQUICBatchPayload(t, config, testTxQUICTransaction(575, 16))
	record := TxOutboxRecord{
		BatchID: txOutboxBatchID(payload), Payload: payload, CreatedAt: uint64(time.Now().UnixNano()),
	}
	first, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := wal.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("retried destructive mutations did not receive distinct operation identities")
	}
	// The caller may have timed out after the first commit and only materialized
	// the projection for its retry. That one durable projection applies both
	// identical mutations, so its marker must retire both pending records.
	if err := wal.appendOutboxApplied(context.Background(), record.BatchID, second); err != nil {
		t.Fatal(err)
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	if err := wal.Replay(func(frame *txIngressWALFrame) error {
		if frame.EventID == first || frame.EventID == second || frame.Kind == txIngressWALOutboxApplied {
			t.Fatalf("equivalent applied mutation leaked through checkpoint: kind=%d event=%s", frame.Kind, frame.EventID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTxIngressWALLocalIntentCrashBeforePoolReplaysExactlyOnce(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.FairHotstuff = true
	chainID := new(big.Int).SetUint64(config.ChainID)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	unsigned := types.NewTransaction(0, common.HexToAddress("0x1000000000000000000000000000000000000001"), big.NewInt(1), 21_000, big.NewInt(params.GWei), nil)
	tx, err := types.SignTx(unsigned, types.NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testTxQUICCertificate(t, config, tx)
	admissions := []core.CommonRPCAdmissionResult{{Batch: certificate, Item: 0, Updated: true, Inserted: true}}
	admissionDB := memorydb.New()
	core.SetCommonRPCAdmissionDatabase(admissionDB)
	t.Cleanup(func() { core.SetCommonRPCAdmissionDatabase(nil) })
	if core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("sign-only local intent admission was visible before WAL replay")
	}

	walDB := memorydb.New()
	outboxDB := memorydb.New()
	firstWAL := newTxIngressWAL(walDB, config)
	if err := firstWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := NewTxQUICIngress(config, nil)
	first.wal = firstWAL
	first.outbox = NewTxOutbox(outboxDB, config)
	intentSet, err := first.persistVerifiedLocalTxsIntent(context.Background(), []*types.Transaction{tx}, admissions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(intentSet.batches) != 1 {
		t.Fatalf("persisted %d intents, want 1", len(intentSet.batches))
	}
	intentID := intentSet.batches[0].BatchID
	firstWAL.Stop() // crash boundary: no pool mutation and no outcome record
	first.cancel()
	// Clear process-local admission caches exactly as a process restart would.
	// The empty admission DB is not an authority; replay must rebuild it from the
	// certificate owned by the WAL intent.
	core.SetCommonRPCAdmissionDatabase(admissionDB)
	if core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("local intent mutated admission DB before replay")
	}
	if has, err := outboxDB.Has(txOutboxRecordKey(intentID)); err != nil || has {
		t.Fatalf("intent became deliverable before pool outcome: has=%t err=%v", has, err)
	}

	stateDB, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	stateDB.SetBalance(sender, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = chainID
	head := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), GasLimit: 30_000_000, BaseFee: big.NewInt(1), Time: uint64(time.Now().Unix())})
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.Journal = ""
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{block: head, state: stateDB})
	defer pool.Stop()

	restartedWAL := newTxIngressWAL(walDB, config)
	if err := restartedWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted := NewTxQUICIngress(config, pool)
	restarted.wal = restartedWAL
	restarted.outbox = NewTxOutbox(outboxDB, config)
	restarted.outbox.wal = restartedWAL
	if err := ensureTxQUICDatabaseIdentity(outboxDB, txOutboxIdentityKey, txQUICDatabaseIdentity{ChainID: config.ChainID, GenesisHash: config.GenesisHash}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.outbox.Start(restarted.ctx, func(ctx context.Context, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}, nil); err != nil {
		t.Fatal(err)
	}
	restarted.startBridgeWorkers()
	restarted.bridgeAcceptMu.Lock()
	restarted.bridgeAccepting = true
	restarted.bridgeAcceptMu.Unlock()
	if err := restarted.replayWALLocalIntents(); err != nil {
		t.Fatal(err)
	}
	if !core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("local intent replay did not rebuild the admission index")
	}
	if pool.Get(tx.Hash()) == nil {
		t.Fatal("crash-owned local intent was not restored to the pool")
	}
	if has, err := outboxDB.Has(txOutboxRecordKey(intentID)); err != nil || !has {
		t.Fatalf("accepted replay was not materialized in outbox: has=%t err=%v", has, err)
	}
	restartedWAL.mu.Lock()
	sequence := restartedWAL.sequence
	restartedWAL.mu.Unlock()
	if err := restarted.replayWALLocalIntents(); err != nil {
		t.Fatal(err)
	}
	restartedWAL.mu.Lock()
	sequenceAfter := restartedWAL.sequence
	restartedWAL.mu.Unlock()
	if sequenceAfter != sequence {
		t.Fatalf("idempotent replay appended records: before=%d after=%d", sequence, sequenceAfter)
	}

	restarted.cancel()
	restarted.bridgeAcceptMu.Lock()
	restarted.bridgeAccepting = false
	restarted.bridgeAcceptMu.Unlock()
	restarted.outbox.Stop()
	restarted.wg.Wait()
	restartedWAL.Stop()
}

func TestTxIngressWALCompletedLocalDeliveryRestoresPendingPoolOnly(t *testing.T) {
	config := testTxQUICConfig()
	config.BridgeEnabled = true
	config.FairHotstuff = true
	chainID := new(big.Int).SetUint64(config.ChainID)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	unsigned := types.NewTransaction(0, common.HexToAddress("0x1000000000000000000000000000000000000001"), big.NewInt(1), 21_000, big.NewInt(params.GWei), nil)
	tx, err := types.SignTx(unsigned, types.NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testTxQUICCertificate(t, config, tx)
	admissionDB := memorydb.New()
	core.SetCommonRPCAdmissionDatabase(admissionDB)
	t.Cleanup(func() { core.SetCommonRPCAdmissionDatabase(nil) })

	walDB := memorydb.New()
	firstWAL := newTxIngressWAL(walDB, config)
	if err := firstWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	item, err := newTxQUICItem(0, tx)
	if err != nil {
		t.Fatal(err)
	}
	intent, _, err := newTxQUICBatch(config.ChainID, config.GenesisHash, certificate, []*txQUICItem{item})
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := firstWAL.appendLocalIntent(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make([]byte, txQUICBitmapBytes(len(intent.Items)))
	txQUICBitmapSet(accepted, 0)
	if err := firstWAL.appendLocalOutcome(context.Background(), intent.BatchID, intentID, len(intent.Items), accepted); err != nil {
		t.Fatal(err)
	}
	acceptedBatch, acceptedPayload, err := txIngressWALAcceptedBatch(intent, accepted)
	if err != nil {
		t.Fatal(err)
	}
	record := TxOutboxRecord{
		BatchID: acceptedBatch.BatchID, Payload: acceptedPayload,
		CreatedAt: txOutboxStableCreatedAt(acceptedBatch.Certificate),
	}
	deleteID, err := firstWAL.appendOutboxProjectionTracked(context.Background(), txIngressWALOutboxDeleted, record, txOutboxRetryState{}, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if err := firstWAL.appendOutboxApplied(context.Background(), record.BatchID, deleteID); err != nil {
		t.Fatal(err)
	}
	if err := firstWAL.Compact(); err != nil {
		t.Fatal(err)
	}
	firstWAL.Stop()

	stateDB, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	stateDB.SetBalance(sender, new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether)))
	chainConfig := *params.TestChainConfig
	chainConfig.ChainID = chainID
	head := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), GasLimit: 30_000_000, BaseFee: big.NewInt(1), Time: uint64(time.Now().Unix())})
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.Journal = ""
	pool := core.NewTxPool(poolConfig, &chainConfig, &testTxQUICPoolChain{block: head, state: stateDB})
	defer pool.Stop()

	outboxDB := memorydb.New()
	restartedWAL := newTxIngressWAL(walDB, config)
	if err := restartedWAL.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restartedWAL.Stop()
	restarted := NewTxQUICIngress(config, pool)
	defer restarted.cancel()
	restarted.wal = restartedWAL
	restarted.outbox = NewTxOutbox(outboxDB, config)
	if err := restarted.replayWALOutboxProjection(); err != nil {
		t.Fatal(err)
	}
	if has, err := outboxDB.Has(txOutboxRecordKey(acceptedBatch.BatchID)); err != nil || has {
		t.Fatalf("completed delivery reappeared in outbox: has=%t err=%v", has, err)
	}
	if err := restarted.replayWALLocalIntents(); err != nil {
		t.Fatal(err)
	}
	if !core.HasCommonRPCAdmission(tx.Hash()) {
		t.Fatal("completed local lifecycle did not restore admission evidence")
	}
	if pool.Get(tx.Hash()) == nil {
		t.Fatal("completed but unfinalized local transaction was not restored to the pool")
	}
}
