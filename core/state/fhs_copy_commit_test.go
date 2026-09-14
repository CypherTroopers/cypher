package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/ethdb"
)

// fhsCopyCommitDatabase counts successful physical trie-node batch writes.
// State execution, trie hashing, batch replay and persistence use the real
// implementations. Account preimages/code metadata have longer keys and are
// deliberately excluded from this archive-node write-amplification check.
type fhsCopyCommitDatabase struct {
	ethdb.Database
	mu           sync.Mutex
	nodePuts     int
	nodeBytes    int
	trieHasError error
}

type fhsCopyCommitBatch struct {
	ethdb.Batch
	database  *fhsCopyCommitDatabase
	nodePuts  int
	nodeBytes int
}

func (db *fhsCopyCommitDatabase) Has(key []byte) (bool, error) {
	db.mu.Lock()
	err := db.trieHasError
	db.mu.Unlock()
	if len(key) == common.HashLength && err != nil {
		// Deliberately combine a truthy result with an error: durability must
		// require a successful lookup, never just the boolean result.
		return true, err
	}
	return db.Database.Has(key)
}

func (db *fhsCopyCommitDatabase) NewBatch() ethdb.Batch {
	return &fhsCopyCommitBatch{Batch: db.Database.NewBatch(), database: db}
}

func (batch *fhsCopyCommitBatch) Put(key, value []byte) error {
	if err := batch.Batch.Put(key, value); err != nil {
		return err
	}
	if len(key) == common.HashLength {
		batch.nodePuts++
		batch.nodeBytes += len(key) + len(value)
	}
	return nil
}

func (batch *fhsCopyCommitBatch) Write() error {
	if err := batch.Batch.Write(); err != nil {
		return err
	}
	batch.database.mu.Lock()
	batch.database.nodePuts += batch.nodePuts
	batch.database.nodeBytes += batch.nodeBytes
	batch.database.mu.Unlock()
	return nil
}

func (batch *fhsCopyCommitBatch) Reset() {
	batch.Batch.Reset()
	batch.nodePuts, batch.nodeBytes = 0, 0
}

func (db *fhsCopyCommitDatabase) counts() (int, int) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.nodePuts, db.nodeBytes
}

func fhsCopyCommitAddress(index uint64) common.Address {
	var address common.Address
	binary.BigEndian.PutUint64(address[len(address)-8:], index+1)
	return address
}

func fhsCopyCommitFixture(t *testing.T) (*StateDB, *fhsCopyCommitDatabase, common.Hash) {
	t.Helper()
	disk := &fhsCopyCommitDatabase{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { _ = disk.Close() })
	parent, err := New(common.Hash{}, NewDatabase(disk), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A transaction-rich parent followed by an empty carrier reproduces the
	// speculative pipeline without EVM timing, mining, sockets or a live chain.
	for index := uint64(0); index < 4096; index++ {
		address := fhsCopyCommitAddress(index)
		parent.SetBalance(address, new(big.Int).SetUint64(index+1))
		parent.SetNonce(address, index+1)
	}
	return parent, disk, parent.IntermediateRoot(true)
}

func fhsCopyCommitPersist(t *testing.T, state *StateDB) common.Hash {
	t.Helper()
	root, err := state.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Database().TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	return root
}

func fhsCopyCommitCheckAccounts(t *testing.T, disk ethdb.Database, root common.Hash, changed bool) {
	t.Helper()
	// Reopen through a fresh trie database to prove physical persistence rather
	// than relying on either speculative branch's live objects or trie cache.
	stored, err := New(root, NewDatabase(disk), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := uint64(0); index < 4096; index++ {
		address := fhsCopyCommitAddress(index)
		want := index + 1
		if changed && index == 2048 {
			want += 7
		}
		if got := stored.GetBalance(address); got.Cmp(new(big.Int).SetUint64(want)) != 0 {
			t.Fatalf("account %d balance=%s want=%d", index, got, want)
		}
		if got := stored.GetNonce(address); got != index+1 {
			t.Fatalf("account %d nonce=%d want=%d", index, got, index+1)
		}
	}
	if err := stored.Error(); err != nil {
		t.Fatal(err)
	}
}

func TestFHSSpeculativeEmptyChildDoesNotRewritePersistedParentTrie(t *testing.T) {
	parent, disk, want := fhsCopyCommitFixture(t)
	// FHS verifies the child before its parent reaches canonical archive
	// persistence. Copy therefore inherits the parent's still-dirty trie.
	child := parent.Copy()
	if got := fhsCopyCommitPersist(t, parent); got != want {
		t.Fatalf("parent root=%s want=%s", got, want)
	}
	parentNodes, parentBytes := disk.counts()
	if parentNodes < 4096 {
		t.Fatalf("fixture did not persist the populated parent trie: %d nodes", parentNodes)
	}
	if got := fhsCopyCommitPersist(t, child); got != want {
		t.Fatalf("empty child changed root=%s want=%s", got, want)
	}
	totalNodes, totalBytes := disk.counts()
	fhsCopyCommitCheckAccounts(t, disk, want, false)
	t.Logf("parent: %d trie nodes / %d bytes; empty child: %d trie nodes / %d bytes",
		parentNodes, parentBytes, totalNodes-parentNodes, totalBytes-parentBytes)
	if rewritten := totalNodes - parentNodes; rewritten != 0 {
		t.Fatalf("empty speculative child rewrote %d already-persisted trie nodes (%d bytes), want no trie writes for unchanged root",
			rewritten, totalBytes-parentBytes)
	}
}

func TestFHSSpeculativeChangedChildPersistsOnlyItsChangedTriePath(t *testing.T) {
	parent, disk, parentRoot := fhsCopyCommitFixture(t)
	child := parent.Copy()
	child.AddBalance(fhsCopyCommitAddress(2048), big.NewInt(7))
	wantChild := child.IntermediateRoot(true)
	if wantChild == parentRoot {
		t.Fatal("one changed account did not change the child root")
	}
	if got := fhsCopyCommitPersist(t, parent); got != parentRoot {
		t.Fatal("child mutation changed its parent state")
	}
	parentNodes, _ := disk.counts()
	if got := fhsCopyCommitPersist(t, child); got != wantChild {
		t.Fatalf("child root=%s want=%s", got, wantChild)
	}
	totalNodes, _ := disk.counts()
	fhsCopyCommitCheckAccounts(t, disk, parentRoot, false)
	fhsCopyCommitCheckAccounts(t, disk, wantChild, true)
	// A secure account key has 64 nibbles. One account update can affect at
	// most its root-to-leaf path, independently of the parent's 4096 accounts.
	if nodes := totalNodes - parentNodes; nodes <= 0 || nodes > 65 {
		t.Fatalf("one-account child persisted %d trie nodes, want only its changed path (1..65)", nodes)
	}
}

func TestFHSSpeculativeCopyCanPersistBeforeItsParent(t *testing.T) {
	parent, disk, want := fhsCopyCommitFixture(t)
	child := parent.Copy()
	if got := fhsCopyCommitPersist(t, child); got != want {
		t.Fatalf("child root=%s want=%s", got, want)
	}
	if nodes, _ := disk.counts(); nodes < 4096 {
		t.Fatalf("child discarded its unpersisted inherited state: wrote %d nodes", nodes)
	}
	fhsCopyCommitCheckAccounts(t, disk, want, false)
	if got := parent.IntermediateRoot(true); got != want {
		t.Fatalf("persisting child changed parent root=%s want=%s", got, want)
	}
}

func fhsCopyCommitContractFixture(t *testing.T, cache int) (*StateDB, *fhsCopyCommitDatabase, common.Address, common.Hash) {
	t.Helper()
	disk := &fhsCopyCommitDatabase{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { _ = disk.Close() })
	parent, err := New(common.Hash{}, NewDatabaseWithCache(disk, cache, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := uint64(0); index < 128; index++ {
		address := fhsCopyCommitAddress(index)
		parent.SetBalance(address, new(big.Int).SetUint64(index+1))
		parent.SetNonce(address, index+1)
	}
	contract := common.HexToAddress("0xdeadbeef")
	parent.SetBalance(contract, big.NewInt(17))
	parent.SetNonce(contract, 3)
	parent.SetCode(contract, []byte{0x60, 0x00, 0x35, 0x60, 0x20, 0x35, 0x55, 0x00})
	for index := uint64(0); index < 64; index++ {
		parent.SetState(contract, common.BigToHash(new(big.Int).SetUint64(index)), common.BigToHash(new(big.Int).SetUint64(index+1)))
	}
	return parent, disk, contract, parent.IntermediateRoot(true)
}

func fhsCopyCommitCheckContract(t *testing.T, disk ethdb.Database, root common.Hash, contract common.Address, changed bool) {
	t.Helper()
	stored, err := New(root, NewDatabase(disk), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := uint64(0); index < 128; index++ {
		address := fhsCopyCommitAddress(index)
		if stored.GetNonce(address) != index+1 || stored.GetBalance(address).Cmp(new(big.Int).SetUint64(index+1)) != 0 {
			t.Fatalf("contract child changed unrelated EOA %d", index)
		}
	}
	code := []byte{0x60, 0x00, 0x35, 0x60, 0x20, 0x35, 0x55, 0x00}
	balance, nonce := int64(17), uint64(3)
	if changed {
		code = []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x00}
		balance, nonce = 24, 4
	}
	if got := stored.GetCode(contract); !bytes.Equal(got, code) {
		t.Fatalf("persisted contract code=%x want=%x", got, code)
	}
	if stored.GetBalance(contract).Cmp(big.NewInt(balance)) != 0 || stored.GetNonce(contract) != nonce {
		t.Fatal("persisted contract balance/nonce mismatch")
	}
	for index := uint64(0); index < 64; index++ {
		want := index + 1
		if changed && index == 7 {
			want = 999
		}
		key := common.BigToHash(new(big.Int).SetUint64(index))
		if got := stored.GetState(contract, key); got != common.BigToHash(new(big.Int).SetUint64(want)) {
			t.Fatalf("storage slot %d=%s want=%d", index, got, want)
		}
	}
	if err := stored.Error(); err != nil {
		t.Fatal(err)
	}
}

func TestFHSSpeculativeContractCopyPersistenceModes(t *testing.T) {
	for _, cache := range []int{0, 16} {
		for _, parentMode := range []string{"persisted", "memory", "dereferenced"} {
			for _, changed := range []bool{false, true} {
				t.Run(fmt.Sprintf("cache_%d/%s/changed_%t", cache, parentMode, changed), func(t *testing.T) {
					parent, disk, contract, parentRoot := fhsCopyCommitContractFixture(t, cache)
					child := parent.Copy()
					if changed {
						child.AddBalance(contract, big.NewInt(7))
						child.SetNonce(contract, 4)
						child.SetCode(contract, []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x00})
						child.SetState(contract, common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(999)))
					}
					childRoot := child.IntermediateRoot(true)
					if (childRoot != parentRoot) != changed {
						t.Fatal("child root changed inconsistently with its mutations")
					}
					gotParent, err := parent.Commit(true)
					if err != nil || gotParent != parentRoot {
						t.Fatalf("commit parent to trie memory: root=%s error=%v", gotParent, err)
					}
					triedb := parent.Database().TrieDB()
					if parentMode == "persisted" {
						if err := triedb.Commit(parentRoot, false, nil); err != nil {
							t.Fatal(err)
						}
					} else {
						// Full-node mode pins a canonical root without archive flush.
						triedb.Reference(parentRoot, common.Hash{})
						if nodes, _ := disk.counts(); nodes != 0 {
							t.Fatalf("memory-only parent unexpectedly persisted %d trie nodes", nodes)
						}
						if parentMode == "dereferenced" {
							triedb.Dereference(parentRoot)
						}
					}
					before, _ := disk.counts()
					gotChild, err := child.Commit(true)
					if err != nil || gotChild != childRoot {
						t.Fatalf("commit child to trie memory: root=%s error=%v", gotChild, err)
					}
					if parentMode == "memory" {
						triedb.Reference(childRoot, common.Hash{})
						triedb.Dereference(parentRoot)
					}
					if err := triedb.Commit(childRoot, false, nil); err != nil {
						t.Fatal(err)
					}
					after, _ := disk.counts()
					fhsCopyCommitCheckContract(t, disk, childRoot, contract, changed)
					if parentMode == "persisted" {
						fhsCopyCommitCheckContract(t, disk, parentRoot, contract, false)
						if !changed && after != before {
							t.Fatalf("empty contract child rewrote %d persisted trie nodes", after-before)
						}
						// One account path and one storage-key path: at most 65
						// nodes each, independent of the inherited account count.
						if changed && (after-before <= 0 || after-before > 130) {
							t.Fatalf("changed contract persisted %d nodes, want only two changed paths", after-before)
						}
					} else if after-before < 128 {
						t.Fatalf("memory-only ancestry lost its physical persistence: %d trie nodes", after-before)
					}
				})
			}
		}
	}
}

func TestFHSSpeculativeCopyFailsClosedOnPersistenceLookupError(t *testing.T) {
	parent, disk, want := fhsCopyCommitFixture(t)
	child := parent.Copy()
	lookupErr := errors.New("injected trie persistence lookup failure")
	disk.mu.Lock()
	disk.trieHasError = lookupErr
	disk.mu.Unlock()
	if root, err := child.Commit(true); !errors.Is(err, lookupErr) {
		t.Fatalf("persistence lookup error was treated as durable state: root=%s error=%v", root, err)
	}
	if nodes, _ := disk.counts(); nodes != 0 {
		t.Fatalf("failed persistence lookup silently wrote %d trie nodes", nodes)
	}
	// A failed child must not damage the independently owned parent. Recover
	// the database and commit that parent, then read every account from disk.
	disk.mu.Lock()
	disk.trieHasError = nil
	disk.mu.Unlock()
	if got := fhsCopyCommitPersist(t, parent); got != want {
		t.Fatalf("child lookup failure changed parent root=%s want=%s", got, want)
	}
	fhsCopyCommitCheckAccounts(t, disk, want, false)
}
