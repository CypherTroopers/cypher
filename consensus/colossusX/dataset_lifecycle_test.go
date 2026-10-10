package colossusX

import (
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cypherium/cypher/core/types"
)

func newLifecycleTestEngine(t *testing.T, lock bool, diskLimit int) *colossusX {
	t.Helper()
	engine := New(Config{
		PowMode: ModeTest, CachesInMem: 1, DatasetsInMem: 1,
		DatasetDir: t.TempDir(), DatasetsOnDisk: diskLimit, DatasetsLockMmap: lock,
	})
	engine.SetThreads(1)
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Errorf("close engine: %v", err)
		}
	})
	return engine
}

func lifecycleCandidate(number uint64) *types.Candidate {
	return &types.Candidate{KeyCandidate: &types.KeyBlockHeader{
		Number: new(big.Int).SetUint64(number), Difficulty: new(big.Int).Set(maxUint256),
	}}
}

func lifecycleDatasetPath(engine *colossusX, epoch uint64) string {
	endian := ""
	if !isLittleEndian() {
		endian = ".be"
	}
	return datasetPath(engine.config.DatasetDir, seedHash(epoch*epochLength+1), endian)
}

func skipUnavailableLifecycleLock(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.ENOTSUP) {
		t.Skipf("OS cannot lock the 32 KiB test DAG: %v", err)
	}
}

func waitLifecycleCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("mining lifecycle did not reach the expected state")
		}
	}
}

func assertLifecycleDatasetReleased(t *testing.T, d *dataset) {
	t.Helper()
	if d.mmap != nil || d.dump != nil || d.dataset != nil || d.locked {
		t.Fatalf("retained DAG resources: mmap=%t fd=%t data=%t locked=%t", d.mmap != nil, d.dump != nil, d.dataset != nil, d.locked)
	}
}

func TestMiningStopReleasesAndRestartRemapsDataset(t *testing.T) {
	for _, test := range []struct {
		name  string
		lock  bool
		limit int
	}{{"disk_limit_zero", false, 0}, {"disk_limit_one", false, 1}, {"locked", true, 1}} {
		t.Run(test.name, func(t *testing.T) {
			engine := newLifecycleTestEngine(t, test.lock, test.limit)
			d, err := engine.dataset(0)
			if test.lock {
				skipUnavailableLifecycleLock(t, err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.mmap == nil || len(d.dataset)*4 != 32*1024 || d.locked != test.lock {
				t.Fatal("initial DAG is not the expected small mapped dataset")
			}
			file := d.dump
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			cache := engine.cache(0)
			// Join the already-registered preparation before stopping. This forces
			// both disk retention branches to run, rather than canceling the future
			// job before it can prune the current epoch's restart artifact.
			engine.miningWG.Wait()
			if _, err := os.Stat(lifecycleDatasetPath(engine, 1)); err != nil {
				t.Fatalf("future DAG was not prepared: %v", err)
			}
			future := engine.datasets.futureItem.(*dataset)
			if err := future.prepareOnDisk(engine.config.DatasetDir, test.limit, true); err != nil {
				t.Fatal(err)
			}
			if err := engine.StopMining(); err != nil {
				t.Fatal(err)
			}
			assertLifecycleDatasetReleased(t, d)
			if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("DAG file descriptor still open: %v", err)
			}
			if _, err := engine.dataset(0); !errors.Is(err, ErrMiningStopped) {
				t.Fatalf("stopped engine admitted DAG work: %v", err)
			}
			if err := engine.StartMining(); err != nil {
				t.Fatal(err)
			}
			if len(engine.miningDatasets) != 0 || engine.datasets.cache.Len() != 0 {
				t.Fatal("StartMining eagerly mapped a dataset")
			}
			remapped, err := engine.dataset(0)
			if err != nil {
				t.Fatal(err)
			}
			if remapped == d || remapped.mmap == nil || remapped.locked != test.lock {
				t.Fatal("restart reused a released sync.Once dataset")
			}
			after, err := remapped.dump.Stat()
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("restart regenerated rather than remapped the retained disk DAG: %v", err)
			}
			if engine.cache(0) != cache {
				t.Fatal("mining stop discarded the independent verification cache")
			}
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
			assertLifecycleDatasetReleased(t, remapped)
			if err := engine.StartMining(); !errors.Is(err, ErrEngineClosed) {
				t.Fatalf("closed engine reopened mining: %v", err)
			}
			if _, err := engine.SealCandidate(lifecycleCandidate(0), nil); !errors.Is(err, ErrEngineClosed) {
				t.Fatalf("closed engine admitted sealing: %v", err)
			}
		})
	}
}

func TestMiningStopJoinsConcurrentSealsAndThreadUpdates(t *testing.T) {
	engine := newLifecycleTestEngine(t, false, 2)
	const seals = 3
	done := make(chan error, seals)
	for i := 0; i < seals; i++ {
		go func() {
			sealed, err := engine.SealCandidate(lifecycleCandidate(0), nil)
			if sealed != nil {
				err = errors.New("unexpected seal at maximal test difficulty")
			}
			done <- err
		}()
	}
	var d *dataset
	waitLifecycleCondition(t, func() bool {
		engine.miningMu.Lock()
		defer engine.miningMu.Unlock()
		for candidate, users := range engine.miningDatasets {
			if users == seals {
				d = candidate
				return true
			}
		}
		return false
	})
	waitLifecycleCondition(t, func() bool {
		engine.lock.Lock()
		defer engine.lock.Unlock()
		return engine.rand != nil
	})
	engine.SetThreads(2)
	if err := engine.StopMining(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < seals; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("StopMining returned before a sealing call completed")
		}
	}
	assertLifecycleDatasetReleased(t, d)
	if len(engine.miningDatasets) != 0 {
		t.Fatal("stop retained mapped dataset references")
	}
}

func TestDatasetEvictionKeepsActiveLeaseThenReleases(t *testing.T) {
	engine := newLifecycleTestEngine(t, false, 8)
	cancel, done, err := engine.beginMining()
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	d0, release0, err := engine.acquireDataset(0, cancel, nil)
	if err != nil {
		t.Fatal(err)
	}
	d1, release1, err := engine.acquireDataset(epochLength, cancel, nil)
	if err != nil {
		release0()
		t.Fatal(err)
	}
	if d0.mmap == nil {
		t.Fatal("LRU eviction unmapped an actively leased DAG")
	}
	release0()
	assertLifecycleDatasetReleased(t, d0)
	if d1.mmap == nil {
		t.Fatal("eviction release also discarded the retained current DAG")
	}
	release1()
	engine.miningMu.Lock()
	defer engine.miningMu.Unlock()
	if len(engine.miningDatasets) > 1 {
		t.Fatalf("idle evicted DAG remained in the lifecycle registry: %d", len(engine.miningDatasets))
	}
}

func TestMiningStopWaitsForFuturePreparationAndSerializesRestart(t *testing.T) {
	engine := newLifecycleTestEngine(t, false, 1)
	started, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	engine.datasets = newlru("dataset", 1, func(epoch uint64) interface{} {
		d := newDataset(epoch).(*dataset)
		if epoch == 1 {
			d.prepareHook = func() {
				close(started)
				<-release
			}
		}
		return d
	})
	if _, err := engine.dataset(0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("future preparation was not launched")
	}
	stopped, restarted := make(chan error, 1), make(chan error, 1)
	go func() { stopped <- engine.StopMining() }()
	waitLifecycleCondition(t, func() bool {
		engine.miningMu.Lock()
		defer engine.miningMu.Unlock()
		return engine.miningStopped
	})
	go func() { restarted <- engine.StartMining() }()
	select {
	case <-stopped:
		t.Fatal("stop did not wait for the active preparation")
	case <-restarted:
		t.Fatal("restart raced the unfinished stop")
	default:
	}
	unblock.Do(func() { close(release) })
	for _, result := range []<-chan error{stopped, restarted} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stop/restart did not finish after preparation was released")
		}
	}
	if _, err := os.Stat(lifecycleDatasetPath(engine, 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled future preparation created an artifact after stop: %v", err)
	}
}

func TestMiningStopWaitsForActiveDatasetInitialization(t *testing.T) {
	engine := newLifecycleTestEngine(t, false, 1)
	started, resume := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(resume) })
	var current *dataset
	engine.datasets = newlru("dataset", 1, func(epoch uint64) interface{} {
		d := newDataset(epoch).(*dataset)
		if epoch == 0 {
			current = d
			d.generateHook = func() {
				close(started)
				<-resume
			}
		}
		return d
	})
	sealed := make(chan error, 1)
	go func() {
		candidate, err := engine.SealCandidate(lifecycleCandidate(0), nil)
		if candidate != nil {
			err = errors.New("stopped initialization launched nonce work")
		}
		sealed <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("active dataset initialization did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- engine.StopMining() }()
	waitLifecycleCondition(t, func() bool {
		engine.miningMu.Lock()
		defer engine.miningMu.Unlock()
		return engine.miningStopped
	})
	select {
	case <-stopped:
		t.Fatal("stop returned while current dataset generation was still active")
	default:
	}
	unblock.Do(func() { close(resume) })
	for _, result := range []<-chan error{sealed, stopped} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stop did not complete after active generation finished")
		}
	}
	assertLifecycleDatasetReleased(t, current)
	if engine.rand != nil {
		t.Fatal("nonce workers were initialized after mining cancellation")
	}
}

func TestCancelledSealDoesNotGenerateDataset(t *testing.T) {
	engine := newLifecycleTestEngine(t, false, 1)
	stop := make(chan struct{})
	close(stop)
	if sealed, err := engine.SealCandidate(lifecycleCandidate(0), stop); sealed != nil || err != nil {
		t.Fatalf("cancelled seal: candidate=%v err=%v", sealed, err)
	}
	entries, err := os.ReadDir(engine.config.DatasetDir)
	if err != nil || len(entries) != 0 || len(engine.miningDatasets) != 0 {
		t.Fatalf("already-cancelled work initialized DAG resources: files=%d err=%v", len(entries), err)
	}
}

func TestMiningRestartRetriesFailedDatasetInitialization(t *testing.T) {
	engine := newLifecycleTestEngine(t, true, 1)
	path := filepath.Join(t.TempDir(), "dataset-dir")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	engine.config.DatasetDir = path
	if _, err := engine.dataset(0); err == nil {
		t.Fatal("mapped initialization unexpectedly succeeded through a regular file")
	}
	if err := engine.StopMining(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := engine.StartMining(); err != nil {
		t.Fatal(err)
	}
	d, err := engine.dataset(0)
	skipUnavailableLifecycleLock(t, err)
	if err != nil || d.genErr != nil || !d.locked {
		t.Fatalf("restart retained the previous initialization failure: %v", err)
	}
}

func TestDatasetGenerationFailureRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	// Adding the dump header overflows the signed truncate length to a negative
	// value, so failure happens before mapping or generating any real DAG.
	generated := false
	dump, mapping, _, err := memoryMapAndGenerate(filepath.Join(dir, "dag"), uint64(math.MaxInt64), func([]uint32) { generated = true })
	if err == nil || generated || dump != nil || mapping != nil {
		t.Fatalf("failed truncate reached generation: generated=%t fd=%t mapped=%t err=%v", generated, dump != nil, mapping != nil, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed generation retained temporary disk files: count=%d err=%v", len(entries), err)
	}
}
