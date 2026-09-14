package state

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
)

func newNativeMVCCForkState(t *testing.T) *StateDB {
	t.Helper()
	statedb, err := New(common.Hash{}, NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return statedb
}

func TestRuntimeMVCCSnapshotLoadsOnlyObservedStorageSlots(t *testing.T) {
	base := newNativeMVCCForkState(t)
	address := common.Address{0x08}
	base.CreateAccount(address)
	base.SetNonce(address, 1)
	const slots = 4096
	for index := 0; index < slots; index++ {
		slot := common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
		base.SetState(address, slot, common.BigToHash(new(big.Int).SetUint64(uint64(index+101))))
	}

	snapshot, err := base.PrepareRuntimeMVCCSnapshot(true)
	if err != nil {
		t.Fatal(err)
	}
	seed := snapshot.accounts[address]
	if seed == nil {
		t.Fatal("runtime snapshot lost the account seed")
	}
	if len(seed.originStorage) != 0 {
		t.Fatalf("snapshot seed retained %d published origin slots, want 0", len(seed.originStorage))
	}

	branch, err := snapshot.Branch()
	if err != nil {
		t.Fatal(err)
	}
	wantedSlot := common.BigToHash(big.NewInt(2048))
	wantedValue := common.BigToHash(big.NewInt(2148))
	if got := branch.GetState(address, wantedSlot); got != wantedValue {
		t.Fatalf("branch slot = %s, want %s", got, wantedValue)
	}
	object := branch.stateObjects[address]
	if object == nil {
		t.Fatal("runtime branch did not detach the observed account")
	}
	if len(object.pendingStorage) != 0 || len(object.dirtyStorage) != 0 || len(object.originStorage) != 1 {
		t.Fatalf("branch storage maps pending/dirty/origin=%d/%d/%d, want 0/0/1", len(object.pendingStorage), len(object.dirtyStorage), len(object.originStorage))
	}

	changedSlot := common.BigToHash(big.NewInt(4097))
	changedValue := common.BigToHash(big.NewInt(9999))
	branch.SetState(address, changedSlot, changedValue)
	if got := base.GetState(address, changedSlot); got != (common.Hash{}) {
		t.Fatalf("runtime branch storage aliased canonical state: %s", got)
	}
	branch.ReleaseRuntimeMVCCSnapshot()
}

func TestRuntimeMVCCSnapshotBuildsSparseBranchesConcurrently(t *testing.T) {
	base := newNativeMVCCForkState(t)
	address := common.Address{0x09}
	code := []byte{0x60, 0x00, 0x56}
	base.CreateAccount(address)
	base.SetNonce(address, 1)
	base.SetCode(address, code)
	const (
		slots    = 4096
		branches = 32
	)
	for index := 0; index < slots; index++ {
		slot := common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
		base.SetState(address, slot, common.BigToHash(new(big.Int).SetUint64(uint64(index+101))))
	}
	snapshot, err := base.PrepareRuntimeMVCCSnapshot(true)
	if err != nil {
		t.Fatal(err)
	}
	seed := snapshot.accounts[address]
	if seed == nil {
		t.Fatal("runtime snapshot lost the hot account seed")
	}
	if len(seed.originStorage) != 0 {
		t.Fatalf("runtime snapshot retained %d cumulative origin slots", len(seed.originStorage))
	}

	var group sync.WaitGroup
	errorsByBranch := make([]error, branches)
	group.Add(branches)
	for index := 0; index < branches; index++ {
		go func(index int) {
			defer group.Done()
			branch, err := snapshot.Branch()
			if err != nil {
				errorsByBranch[index] = err
				return
			}
			defer branch.ReleaseRuntimeMVCCSnapshot()
			slot := common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
			want := common.BigToHash(new(big.Int).SetUint64(uint64(index + 101)))
			if got := branch.GetState(address, slot); got != want {
				err = errors.New("branch read the wrong lazy storage value")
			} else if got := branch.GetCode(address); !bytes.Equal(got, code) {
				err = errors.New("branch lost uncommitted contract code")
			} else if object := branch.stateObjects[address]; object == nil || len(object.originStorage) != 1 || len(object.pendingStorage) != 0 || len(object.dirtyStorage) != 0 {
				err = errors.New("branch did not retain exactly one observed storage slot")
			}
			errorsByBranch[index] = err
		}(index)
	}
	group.Wait()
	for index, err := range errorsByBranch {
		if err != nil {
			t.Fatalf("branch %d: %v", index, err)
		}
	}
}

func TestRuntimeMVCCSnapshotSharesImmutableCodeAndDetachesOnWrite(t *testing.T) {
	base := newNativeMVCCForkState(t)
	address := common.Address{0x19}
	original := []byte{0x60, 0x00, 0x56}
	replacement := []byte{0x60, 0x01, 0x56}
	base.SetCode(address, original)
	base.SetNonce(address, 1)
	snapshot, err := base.PrepareRuntimeMVCCSnapshot(true)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := snapshot.Branch()
	if err != nil {
		t.Fatal(err)
	}
	defer branch.ReleaseRuntimeMVCCSnapshot()

	seedCode := snapshot.accounts[address].code
	branchCode := branch.GetCode(address)
	if len(seedCode) == 0 || len(branchCode) == 0 || &seedCode[0] != &branchCode[0] {
		t.Fatal("runtime branch copied an immutable snapshot code image")
	}
	branch.SetCode(address, replacement)
	if got := branch.GetCode(address); !bytes.Equal(got, replacement) {
		t.Fatalf("branch replacement code = %x, want %x", got, replacement)
	}
	if got := base.GetCode(address); !bytes.Equal(got, original) {
		t.Fatalf("branch SetCode mutated canonical shared code = %x", got)
	}
}

func TestRuntimeMVCCSnapshotSurfacesTouchedSeedError(t *testing.T) {
	base := newNativeMVCCForkState(t)
	address := common.Address{0x0a}
	base.CreateAccount(address)
	base.SetNonce(address, 1)
	base.IntermediateRoot(true)
	seedError := errors.New("missing runtime storage trie node")
	base.getStateObject(address).dbErr = seedError

	snapshot, err := base.PrepareRuntimeMVCCSnapshot(true)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := snapshot.Branch()
	if err != nil {
		t.Fatal(err)
	}
	defer branch.ReleaseRuntimeMVCCSnapshot()
	branch.GetNonce(address)
	if err := branch.RuntimeMVCCError(address); err == nil || !strings.Contains(err.Error(), seedError.Error()) {
		t.Fatalf("runtime MVCC error = %v, want %q", err, seedError)
	}
}

func TestPruneRuntimeMVCCOriginsDropsReadsAndPreservesPendingWrites(t *testing.T) {
	base := newNativeMVCCForkState(t)
	address := common.Address{0x0b}
	revertedAddress := common.Address{0x0c}
	readOnly := common.Hash{0x01}
	written := common.Hash{0x02}
	reverted := common.Hash{0x03}
	oldRead := common.Hash{0x11}
	oldWrite := common.Hash{0x12}
	oldReverted := common.Hash{0x13}
	newWrite := common.Hash{0x22}
	base.CreateAccount(address)
	base.SetNonce(address, 1)
	base.SetState(address, readOnly, oldRead)
	base.SetState(address, written, oldWrite)
	base.CreateAccount(revertedAddress)
	base.SetNonce(revertedAddress, 1)
	base.SetState(revertedAddress, reverted, oldReverted)
	base.IntermediateRoot(true)

	if got := base.GetState(address, readOnly); got != oldRead {
		t.Fatalf("read-only slot = %s, want %s", got, oldRead)
	}
	snapshot := base.Snapshot()
	base.SetState(revertedAddress, reverted, common.Hash{0x23})
	base.RevertToSnapshot(snapshot)
	base.SetState(address, written, newWrite)
	if err := base.PruneRuntimeMVCCOrigins(map[common.Address][]common.Hash{address: {readOnly}}); err == nil {
		t.Fatal("origin pruning accepted an open transaction journal")
	}
	base.Finalise(true)
	if err := base.PruneRuntimeMVCCOrigins(map[common.Address][]common.Hash{
		address:         {readOnly, written},
		revertedAddress: {reverted},
	}); err != nil {
		t.Fatal(err)
	}
	object := base.getStateObject(address)
	if _, cached := object.originStorage[readOnly]; cached {
		t.Fatal("read-only origin survived pruning")
	}
	revertedObject := base.getStateObject(revertedAddress)
	if _, cached := revertedObject.originStorage[reverted]; cached {
		t.Fatal("reverted origin survived pruning")
	}
	if _, dirty := revertedObject.dirtyStorage[reverted]; dirty {
		t.Fatal("reverted no-op dirty value survived pruning")
	}
	if got, cached := object.originStorage[written]; !cached || got != oldWrite {
		t.Fatalf("pending write origin = %s/%t, want %s/true", got, cached, oldWrite)
	}
	if got := object.pendingStorage[written]; got != newWrite {
		t.Fatalf("pending write = %s, want %s", got, newWrite)
	}

	base.IntermediateRoot(true)
	if len(object.originStorage) != 0 {
		t.Fatalf("published write retained %d origin slots", len(object.originStorage))
	}
	if got := base.GetState(address, readOnly); got != oldRead {
		t.Fatalf("pruned read-only slot reloaded %s, want %s", got, oldRead)
	}
	if got := base.GetState(address, written); got != newWrite {
		t.Fatalf("published write reloaded %s, want %s", got, newWrite)
	}
	if got := base.GetState(revertedAddress, reverted); got != oldReverted {
		t.Fatalf("reverted slot reloaded %s, want %s", got, oldReverted)
	}
}

func TestNativeBlockHashViewFollowsStateCopies(t *testing.T) {
	base := newNativeMVCCForkState(t)
	want := common.HexToHash("0x1234")
	input := map[uint64]common.Hash{7: want}
	base.SetNativeBlockHashes(input)
	input[7] = common.HexToHash("0xffff")

	if !base.NativeBlockHashesPrepared() || base.NativeBlockHash(7) != want {
		t.Fatalf("base BLOCKHASH view = %s, want %s", base.NativeBlockHash(7), want)
	}
	snapshot, err := base.PrepareRuntimeMVCCSnapshot(false)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := snapshot.Branch()
	if err != nil {
		t.Fatal(err)
	}
	for name, copied := range map[string]*StateDB{
		"full":    base.Copy(),
		"runtime": branch,
	} {
		if !copied.NativeBlockHashesPrepared() {
			t.Fatalf("%s copy lost prepared BLOCKHASH marker", name)
		}
		if got := copied.NativeBlockHash(7); got != want {
			t.Fatalf("%s copy BLOCKHASH = %s, want %s", name, got, want)
		}
		if got := copied.NativeBlockHash(8); got != (common.Hash{}) {
			t.Fatalf("%s copy out-of-window BLOCKHASH = %s, want zero", name, got)
		}
	}
}
