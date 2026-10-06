package state

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
)

func parallelRootFixture(t *testing.T) *StateDB {
	t.Helper()
	statedb, err := New(common.Hash{}, NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	for accountIndex := uint64(0); accountIndex < 96; accountIndex++ {
		var address common.Address
		binary.BigEndian.PutUint64(address[len(address)-8:], accountIndex+1)
		statedb.CreateAccount(address)
		statedb.SetNonce(address, accountIndex+1)
		for slotIndex := uint64(0); slotIndex < 8; slotIndex++ {
			var slot, value common.Hash
			binary.BigEndian.PutUint64(slot[len(slot)-8:], slotIndex+1)
			binary.BigEndian.PutUint64(value[len(value)-8:], (accountIndex+1)*1000+slotIndex)
			statedb.SetState(address, slot, value)
		}
	}
	return statedb
}

func TestIntermediateRootWorkerCountIsConsensusInvariant(t *testing.T) {
	base := parallelRootFixture(t)
	want := base.Copy().intermediateRootWithWorkers(true, 1)
	for _, workers := range []int{2, 8, 64} {
		if got := base.Copy().intermediateRootWithWorkers(true, workers); got != want {
			t.Fatalf("workers=%d root=%s, serial=%s", workers, got, want)
		}
	}
}

func TestIntermediateRootParallelCopiesAreRaceSafe(t *testing.T) {
	base := parallelRootFixture(t)
	want := base.Copy().intermediateRootWithWorkers(true, 1)
	const copies = 8
	roots := make([]common.Hash, copies)
	var group sync.WaitGroup
	group.Add(copies)
	for index := 0; index < copies; index++ {
		go func(index int) {
			defer group.Done()
			roots[index] = base.Copy().intermediateRootWithWorkers(true, 8)
		}(index)
	}
	group.Wait()
	for index, root := range roots {
		if root != want {
			t.Fatalf("copy=%d root=%s, want=%s", index, root, want)
		}
	}
}

func TestIntermediateRootParallelizesSingleHotStorageTrie(t *testing.T) {
	base, err := New(common.Hash{}, NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	address := common.HexToAddress("0x7777")
	base.CreateAccount(address)
	base.SetNonce(address, 1)
	for index := uint64(0); index < 4096; index++ {
		var slot, value common.Hash
		binary.BigEndian.PutUint64(slot[len(slot)-8:], index)
		binary.BigEndian.PutUint64(value[len(value)-8:], index+1)
		base.SetState(address, slot, value)
	}
	want := base.Copy().intermediateRootWithWorkers(true, 1)
	if got := base.Copy().intermediateRootWithWorkers(true, 64); got != want {
		t.Fatalf("hot storage root=%s, serial=%s", got, want)
	}
}

func TestCommitParallelStorageTriesMatchesCalculatedRoot(t *testing.T) {
	base := parallelRootFixture(t)
	want := base.Copy().intermediateRootWithWorkers(true, 1)
	got, err := base.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("committed root=%s, calculated root=%s", got, want)
	}
}

func TestCommitParallelStorageTriesRaceSafe(t *testing.T) {
	want := parallelRootFixture(t).Copy().intermediateRootWithWorkers(true, 1)
	const copies = 4
	roots := make([]common.Hash, copies)
	errs := make([]error, copies)
	states := make([]*StateDB, copies)
	for index := range states {
		states[index] = parallelRootFixture(t)
	}
	var group sync.WaitGroup
	group.Add(copies)
	for index := 0; index < copies; index++ {
		go func(index int) {
			defer group.Done()
			roots[index], errs[index] = states[index].Commit(true)
		}(index)
	}
	group.Wait()
	for index := range roots {
		if errs[index] != nil {
			t.Fatalf("copy=%d commit failed: %v", index, errs[index])
		}
		if roots[index] != want {
			t.Fatalf("copy=%d root=%s, want=%s", index, roots[index], want)
		}
	}
}
