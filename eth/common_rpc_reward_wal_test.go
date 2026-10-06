package eth

import (
	"context"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/ethdb/memorydb"
)

func TestCommonRPCLocalIntentTimeoutKeepsOwnershipUntilFsync(t *testing.T) {
	config := testTxQUICConfig()
	db := &blockingSyncTxQUICDB{KeyValueStore: memorydb.New(), started: make(chan struct{}), release: make(chan struct{})}
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			close(db.release)
		}
		wal.Stop()
	}()
	tx := testTxQUICTransaction(0, 0)
	batch := testTxQUICBatch(t, config, tx)
	db.block.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := wal.appendLocalIntent(ctx, batch); done <- err }()
	select {
	case <-db.started:
	case <-time.After(time.Second):
		t.Fatal("fsync did not start")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("local lease could be released before durable proof publication: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(db.release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	previous, found, err := wal.localRPCAdmission(batch.Certificate.Miner, tx.Hash())
	if err != nil || !found || previous.Batch.AdmissionID != batch.Certificate.AdmissionID {
		t.Fatalf("durable retry lost original proof: found=%v err=%v", found, err)
	}
}

func TestCommonRPCLocalRetryIndexCheckpointRestartAndSignerIsolation(t *testing.T) {
	config := testTxQUICConfig()
	db := memorydb.New()
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	tx := testTxQUICTransaction(0, 0)
	batch := testTxQUICBatch(t, config, tx)
	if _, err := wal.appendLocalIntent(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	wal.Stop()
	restored := newTxIngressWAL(db, config)
	if err := restored.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restored.Stop()
	previous, found, err := restored.localRPCAdmission(batch.Certificate.Miner, tx.Hash())
	if err != nil || !found || previous.Batch.AdmissionID != batch.Certificate.AdmissionID {
		t.Fatalf("checkpoint/restart lost retry: found=%v err=%v", found, err)
	}
	if _, found, err := restored.localRPCAdmission(common.Address{99}, tx.Hash()); err != nil || found {
		t.Fatalf("another signer inherited local proof: found=%v err=%v", found, err)
	}
	previous.Batch.Signature[0] ^= 1
	again, _, _ := restored.localRPCAdmission(batch.Certificate.Miner, tx.Hash())
	if again.Batch.Signature[0] != batch.Certificate.Signature[0] {
		t.Fatal("retry caller mutated WAL proof")
	}
}
