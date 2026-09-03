// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state/snapshot"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/metrics"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

type revision struct {
	id                       int
	journalIndex             int
	nativeBlockHashes        map[uint64]common.Hash
	nativeReplayTransactions map[common.Hash]struct{}
	nativeMVCCVersion        uint64
}

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type proofList [][]byte

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

// StateDB structs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
// * Contracts
// * Accounts
type StateDB struct {
	db   Database
	trie Trie

	snaps         *snapshot.Tree
	snap          snapshot.Snapshot
	snapDestructs map[common.Hash]struct{}
	snapAccounts  map[common.Hash][]byte
	snapStorage   map[common.Hash]map[common.Hash][]byte

	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateObjects        map[common.Address]*stateObject
	stateObjectsPending map[common.Address]struct{} // State objects finalized but not yet written to the trie
	stateObjectsDirty   map[common.Address]struct{} // State objects modified in the current execution

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund uint64

	thash, bhash common.Hash
	txIndex      int
	logs         map[common.Hash][]*types.Log
	logSize      uint

	preimages map[common.Hash][]byte

	transientStorage transientStorage
	createdContracts map[common.Address]struct{}
	accessList       *accessListState

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal        *journal
	validRevisions []revision
	nextRevisionId int

	// parallelRootMu protects process-local metrics and the outer snapshot
	// storage map while independent account storage tries are hashed in
	// parallel. It is never held across trie hashing.
	parallelRootMu sync.Mutex

	// nativeStorageWrites is enabled only on transaction-local CopyDeclared
	// branches. It records slots actually written by execution so the native
	// MVCC merge never expands every signed write declaration into an artificial
	// state mutation. Values are read from the finalized branch at capture time.
	nativeStorageWrites map[common.Address]map[common.Hash]struct{}

	// nativeMVCCVersion identifies the immutable block-local base from which a
	// declared transaction branch was created. Native DAG deltas may only merge
	// into the exact same version; the base advances once per published
	// microbatch. This is process-local concurrency metadata, never trie state.
	nativeMVCCVersion uint64

	// nativeBlockHashes is a proposal-local, immutable BLOCKHASH view populated
	// from the state-rooted EIP-2935 history before native execution starts. It
	// is deliberately process-local (and therefore excluded from the trie/root),
	// but Copy and CopyDeclared retain the same immutable view so every DAG
	// branch observes the certified parent ancestry even when that parent is not
	// present in the node's canonical header database yet. A nil map means the
	// view has not been prepared; a non-nil empty map is valid for genesis.
	nativeBlockHashes map[uint64]common.Hash

	// nativeReplayTransactions is the immutable set of NativeTxV1 hashes whose
	// signed payer sequence was validated and consumed by the block prepass.
	// The map is process-local execution metadata, not trie state; the replay
	// base/bitmap values themselves live in reserved state storage. Copies and
	// MVCC branches share this map read-only while executing one block.
	nativeReplayTransactions map[common.Hash]struct{}

	// runtimeMVCCAccounts is a read-only seed table owned by one immutable
	// RuntimeMVCCSnapshot. It contains canonical objects whose code/storage trie
	// changes are not committed to the backing database yet. A standard-EVM
	// branch deep-copies only a seed it actually touches, avoiding both stale DB
	// reads and O(all block writes) memory per speculative transaction.
	runtimeMVCCAccounts map[common.Address]*stateObject

	// Measurements gathered during execution for debugging purposes
	AccountReads         time.Duration
	AccountHashes        time.Duration
	AccountUpdates       time.Duration
	AccountCommits       time.Duration
	StorageReads         time.Duration
	StorageHashes        time.Duration
	StorageUpdates       time.Duration
	StorageCommits       time.Duration
	SnapshotAccountReads time.Duration
	SnapshotStorageReads time.Duration
	SnapshotCommits      time.Duration
}

// New creates a new state from a given trie.
func New(root common.Hash, db Database, snaps *snapshot.Tree) (*StateDB, error) {
	tr, err := db.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	sdb := &StateDB{
		db:                  db,
		trie:                tr,
		snaps:               snaps,
		stateObjects:        make(map[common.Address]*stateObject),
		stateObjectsPending: make(map[common.Address]struct{}),
		stateObjectsDirty:   make(map[common.Address]struct{}),
		logs:                make(map[common.Hash][]*types.Log),
		preimages:           make(map[common.Hash][]byte),
		transientStorage:    newTransientStorage(),
		createdContracts:    make(map[common.Address]struct{}),
		accessList:          newAccessListState(),
		journal:             newJournal(),
	}
	if sdb.snaps != nil {
		if sdb.snap = sdb.snaps.Snapshot(root); sdb.snap != nil {
			sdb.snapDestructs = make(map[common.Hash]struct{})
			sdb.snapAccounts = make(map[common.Hash][]byte)
			sdb.snapStorage = make(map[common.Hash]map[common.Hash][]byte)
		}
	}
	return sdb, nil
}

// setError remembers the first non-nil error it is called with.
func (s *StateDB) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

func (s *StateDB) Error() error {
	return s.dbErr
}

// RuntimeMVCCError surfaces database errors memoized by the StateDB or by the
// exact account objects touched by a standard-EVM execution branch. The EVM
// StateDB interface cannot return read errors directly, so optimistic execution
// must check this before publishing a speculative delta. Supplying addresses
// keeps serial conflict fallback proportional to that transaction's observed
// working set; an empty list checks every materialized object in a sparse branch.
func (s *StateDB) RuntimeMVCCError(addresses ...common.Address) error {
	if s == nil {
		return errors.New("cannot inspect runtime MVCC error on nil state")
	}
	if s.dbErr != nil {
		return s.dbErr
	}
	if len(addresses) == 0 {
		addresses = make([]common.Address, 0, len(s.stateObjects))
		for address := range s.stateObjects {
			addresses = append(addresses, address)
		}
	} else {
		unique := make(map[common.Address]struct{}, len(addresses))
		filtered := make([]common.Address, 0, len(addresses))
		for _, address := range addresses {
			if _, duplicate := unique[address]; duplicate {
				continue
			}
			unique[address] = struct{}{}
			filtered = append(filtered, address)
		}
		addresses = filtered
	}
	sort.Slice(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) < 0 })
	for _, address := range addresses {
		if object := s.stateObjects[address]; object != nil && object.dbErr != nil {
			return fmt.Errorf("runtime MVCC account %s: %w", address, object.dbErr)
		}
	}
	return nil
}

// PruneRuntimeMVCCOrigins releases exact storage values cached by a serial EVM
// execution after its transaction boundary. Slots still dirty or pending are
// retained because updateTrieWithWorkers needs their original values to detect
// no-op writes before publication. The boundary check prevents callers from
// dropping values that an open EVM snapshot could still revert or reuse.
func (s *StateDB) PruneRuntimeMVCCOrigins(slots map[common.Address][]common.Hash) error {
	if s == nil {
		return errors.New("cannot prune runtime MVCC origins on nil state")
	}
	if s.journal == nil || s.journal.length() != 0 || len(s.validRevisions) != 0 {
		return errors.New("runtime MVCC origins may only be pruned at a finalized transaction boundary")
	}
	for address, keys := range slots {
		object := s.stateObjects[address]
		if object == nil {
			continue
		}
		for _, key := range keys {
			if _, pending := object.pendingStorage[key]; pending {
				continue
			}
			if dirty, exists := object.dirtyStorage[key]; exists {
				origin, loaded := object.originStorage[key]
				if !loaded || dirty != origin {
					continue
				}
				// StateDB journal reversion restores the old value in dirtyStorage.
				// If the account has no surviving journal dirties, Finalise does not
				// visit it. At a closed transaction boundary this exact no-op is safe
				// to discard together with its cached origin.
				delete(object.dirtyStorage, key)
			}
			delete(object.originStorage, key)
		}
	}
	return nil
}

// Reset clears out all ephemeral state objects from the state db, but keeps
// the underlying state trie to avoid reloading data for the next operations.
func (s *StateDB) Reset(root common.Hash) error {
	tr, err := s.db.OpenTrie(root)
	if err != nil {
		return err
	}
	s.trie = tr
	s.stateObjects = make(map[common.Address]*stateObject)
	s.stateObjectsPending = make(map[common.Address]struct{})
	s.stateObjectsDirty = make(map[common.Address]struct{})
	s.thash = common.Hash{}
	s.bhash = common.Hash{}
	s.txIndex = 0
	s.logs = make(map[common.Hash][]*types.Log)
	s.logSize = 0
	s.preimages = make(map[common.Hash][]byte)
	s.transientStorage = newTransientStorage()
	s.createdContracts = make(map[common.Address]struct{})
	s.accessList = newAccessListState()
	s.nativeMVCCVersion = 0
	s.nativeBlockHashes = nil
	s.nativeReplayTransactions = nil
	s.clearJournalAndRefund()

	if s.snaps != nil {
		s.snapAccounts, s.snapDestructs, s.snapStorage = nil, nil, nil
		if s.snap = s.snaps.Snapshot(root); s.snap != nil {
			s.snapDestructs = make(map[common.Hash]struct{})
			s.snapAccounts = make(map[common.Hash][]byte)
			s.snapStorage = make(map[common.Hash]map[common.Hash][]byte)
		}
	}
	return nil
}

func (s *StateDB) AddLog(log *types.Log) {
	s.journal.append(addLogChange{txhash: s.thash})

	log.TxHash = s.thash
	log.BlockHash = s.bhash
	log.TxIndex = uint(s.txIndex)
	log.Index = s.logSize
	s.logs[s.thash] = append(s.logs[s.thash], log)
	s.logSize++
}

func (s *StateDB) GetLogs(hash common.Hash) []*types.Log {
	return s.logs[hash]
}

func (s *StateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range s.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (s *StateDB) AddPreimage(hash common.Hash, preimage []byte) {
	if _, ok := s.preimages[hash]; !ok {
		s.journal.append(addPreimageChange{hash: hash})
		pi := make([]byte, len(preimage))
		copy(pi, preimage)
		s.preimages[hash] = pi
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (s *StateDB) Preimages() map[common.Hash][]byte {
	return s.preimages
}

// AddRefund adds gas to the refund counter
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	s.refund += gas
}

// SubRefund removes gas from the refund counter.
// This method will panic if the refund counter goes below zero
func (s *StateDB) SubRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	if gas > s.refund {
		panic(fmt.Sprintf("Refund counter below zero (gas: %d > refund: %d)", gas, s.refund))
	}
	s.refund -= gas
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (s *StateDB) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (s *StateDB) Empty(addr common.Address) bool {
	so := s.getStateObject(addr)
	return so == nil || so.empty()
}

// GetBalance retrieves the balance from the given address or 0 if object not found
func (s *StateDB) GetBalance(addr common.Address) *big.Int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0
}

func (s *StateDB) GetNonce(addr common.Address) uint64 {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

// TxIndex returns the current transaction index set by Prepare.
func (s *StateDB) TxIndex() int {
	return s.txIndex
}

// BlockHash returns the current block hash set by Prepare.
func (s *StateDB) BlockHash() common.Hash {
	return s.bhash
}

func (s *StateDB) GetCode(addr common.Address) []byte {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code(s.db)
	}
	return nil
}

func (s *StateDB) GetCodeSize(addr common.Address) int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.CodeSize(s.db)
	}
	return 0
}

func (s *StateDB) GetCodeHash(addr common.Address) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}

// GetStorageRoot retrieves an account's storage root. A missing account has no
// root; an existing account with empty storage has the canonical empty trie
// root. CREATE collision checks need to distinguish both from non-empty
// storage (EIP-7610).
func (s *StateDB) GetStorageRoot(addr common.Address) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return stateObject.data.Root
}

// GetState retrieves a value from the given account's storage trie.
func (s *StateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(s.db, hash)
	}
	return common.Hash{}
}

// SetNativeBlockHashes publishes a proposal-local immutable BLOCKHASH view.
// The input is cloned so callers cannot mutate a view concurrently with native
// DAG workers. Subsequent StateDB copies may safely share the cloned map.
func (s *StateDB) SetNativeBlockHashes(hashes map[uint64]common.Hash) {
	if s == nil {
		return
	}
	view := make(map[uint64]common.Hash, len(hashes))
	for number, hash := range hashes {
		view[number] = hash
	}
	if !equalNativeBlockHashViews(s.nativeBlockHashes, view) {
		// A different ancestry view marks a new proposal/block execution. An
		// exact transaction batch from the preceding block must be checked
		// against its now-consumed state instead of being mistaken for an
		// idempotent retry of the current block prepass.
		s.nativeReplayTransactions = nil
	}
	s.nativeBlockHashes = view
}

func equalNativeBlockHashViews(left, right map[uint64]common.Hash) bool {
	if left == nil || right == nil || len(left) != len(right) {
		return false
	}
	for number, hash := range left {
		if right[number] != hash {
			return false
		}
	}
	return true
}

// NativeBlockHashesPrepared reports whether the proposal-local BLOCKHASH view
// has been installed. It distinguishes an unprepared StateDB from the valid
// empty view used while executing genesis.
func (s *StateDB) NativeBlockHashesPrepared() bool {
	return s != nil && s.nativeBlockHashes != nil
}

// NativeBlockHash resolves one hash from the immutable proposal-local view.
// Numbers outside the EVM's retained window return the zero hash.
func (s *StateDB) NativeBlockHash(number uint64) common.Hash {
	if s == nil {
		return common.Hash{}
	}
	return s.nativeBlockHashes[number]
}

// SetNativeReplayTransactions publishes the immutable set validated by the
// block-level replay prepass. The input is copied before publication so native
// DAG workers can query it concurrently without synchronization.
func (s *StateDB) SetNativeReplayTransactions(hashes []common.Hash) {
	if s == nil {
		return
	}
	prepared := make(map[common.Hash]struct{}, len(hashes))
	for _, hash := range hashes {
		prepared[hash] = struct{}{}
	}
	s.nativeReplayTransactions = prepared
}

// NativeReplayTransactionPrepared reports whether the exact transaction was
// consumed by the current block prepass. A nil map is deliberately distinct
// from an empty prepared block.
func (s *StateDB) NativeReplayTransactionPrepared(hash common.Hash) bool {
	if s == nil || s.nativeReplayTransactions == nil {
		return false
	}
	_, prepared := s.nativeReplayTransactions[hash]
	return prepared
}

// NativeReplayTransactionsPrepared reports whether hashes are exactly the
// batch already consumed on this StateDB. It makes retrying the same immutable
// proposal idempotent without permitting a partially overlapping or extended
// batch to bypass canonical sequence validation.
func (s *StateDB) NativeReplayTransactionsPrepared(hashes []common.Hash) bool {
	if s == nil || s.nativeReplayTransactions == nil || len(s.nativeReplayTransactions) != len(hashes) {
		return false
	}
	for _, hash := range hashes {
		if _, prepared := s.nativeReplayTransactions[hash]; !prepared {
			return false
		}
	}
	return true
}

// GetProof returns the MerkleProof for a given Account
func (s *StateDB) GetProof(a common.Address) ([][]byte, error) {
	var proof proofList
	err := s.trie.Prove(crypto.Keccak256(a.Bytes()), 0, &proof)
	return [][]byte(proof), err
}

// GetStorageProof returns the StorageProof for given key
func (s *StateDB) GetStorageProof(a common.Address, key common.Hash) ([][]byte, error) {
	var proof proofList
	trie := s.StorageTrie(a)
	if trie == nil {
		return proof, errors.New("storage trie for requested address does not exist")
	}
	err := trie.Prove(crypto.Keccak256(key.Bytes()), 0, &proof)
	return [][]byte(proof), err
}

// GetCommittedState retrieves a value from the given account's committed storage trie.
func (s *StateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetCommittedState(s.db, hash)
	}
	return common.Hash{}
}

// Database retrieves the low level database supporting the lower level trie ops.
func (s *StateDB) Database() Database {
	return s.db
}

// StorageTrie returns the storage trie of an account.
// The return value is a copy and is nil for non-existent accounts.
func (s *StateDB) StorageTrie(addr common.Address) Trie {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return nil
	}
	cpy := stateObject.deepCopy(s)
	cpy.updateTrie(s.db)
	return cpy.getTrie(s.db)
}

func (s *StateDB) HasSuicided(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (s *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount)
	}
}

func (s *StateDB) SetBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount)
	}
}

func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

func (s *StateDB) SetCode(addr common.Address, code []byte) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (s *StateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if changed := stateObject.SetState(s.db, key, value); changed && s.nativeStorageWrites != nil {
			if s.nativeStorageWrites[addr] == nil {
				s.nativeStorageWrites[addr] = make(map[common.Hash]struct{})
			}
			s.nativeStorageWrites[addr][key] = struct{}{}
		}
	}
}

// NativeProtocolStorageMutation is one state-rooted system metadata update.
// Before comes from an immutable prevalidation view; ApplyNativeProtocolStorageBatch
// verifies any already-cached value against it and seeds uncached origins so
// publishing does not repeat hundreds of thousands of trie reads serially.
type NativeProtocolStorageMutation struct {
	Key    common.Hash
	Before common.Hash
	After  common.Hash
}

// NativeProtocolState reads one system metadata slot and surfaces both account
// trie and storage trie errors immediately. The ordinary VM StateDB interface
// memoizes storage errors until commit because its GetState method cannot
// return an error; consensus prevalidation must fail before publishing.
func (s *StateDB) NativeProtocolState(addr common.Address, key common.Hash) (common.Hash, error) {
	if s == nil {
		return common.Hash{}, errors.New("cannot read native protocol storage from nil state")
	}
	object := s.getStateObject(addr)
	if s.dbErr != nil {
		return common.Hash{}, s.dbErr
	}
	if object == nil {
		return common.Hash{}, nil
	}
	value := object.GetState(s.db, key)
	if object.dbErr != nil {
		return common.Hash{}, object.dbErr
	}
	return value, nil
}

// ApplyNativeProtocolStorageBatch publishes validated system storage changes
// into one reserved account. The caller must ensure no state mutation occurs
// between creation of the immutable read views and this call. Updates retain
// normal StateDB journaling/revert semantics.
func (s *StateDB) ApplyNativeProtocolStorageBatch(addr common.Address, nonce uint64, mutations []NativeProtocolStorageMutation) error {
	if s == nil {
		return errors.New("cannot publish native protocol storage into nil state")
	}
	object := s.getStateObject(addr)
	if object == nil {
		for _, mutation := range mutations {
			if mutation.Before != (common.Hash{}) {
				return fmt.Errorf("native protocol account %s is absent with non-zero prior storage %s", addr, mutation.Key)
			}
		}
		s.CreateAccount(addr)
		s.SetNonce(addr, nonce)
		object = s.getStateObject(addr)
	} else if object.Nonce() != nonce {
		return fmt.Errorf("native protocol account %s has nonce %d, want %d", addr, object.Nonce(), nonce)
	}
	if object == nil {
		return fmt.Errorf("native protocol account %s could not be created", addr)
	}
	if object.dbErr != nil {
		return object.dbErr
	}
	if object.fakeStorage != nil {
		return fmt.Errorf("native protocol account %s uses debug-only fake storage", addr)
	}
	for index, mutation := range mutations {
		if mutation.Before == mutation.After {
			continue
		}
		if current, ok := object.dirtyStorage[mutation.Key]; ok {
			if current != mutation.Before {
				return fmt.Errorf("native protocol mutation %d for %s/%s has stale dirty value %s, want %s", index, addr, mutation.Key, current, mutation.Before)
			}
		} else if current, ok := object.pendingStorage[mutation.Key]; ok {
			if current != mutation.Before {
				return fmt.Errorf("native protocol mutation %d for %s/%s has stale pending value %s, want %s", index, addr, mutation.Key, current, mutation.Before)
			}
		} else if current, ok := object.originStorage[mutation.Key]; ok {
			if current != mutation.Before {
				return fmt.Errorf("native protocol mutation %d for %s/%s has stale cached value %s, want %s", index, addr, mutation.Key, current, mutation.Before)
			}
		} else {
			object.originStorage[mutation.Key] = mutation.Before
		}
		if !object.SetState(s.db, mutation.Key, mutation.After) {
			return fmt.Errorf("native protocol mutation %d for %s/%s did not change validated state", index, addr, mutation.Key)
		}
	}
	if s.dbErr != nil {
		return s.dbErr
	}
	return nil
}

// SetStorage replaces the entire storage for the specified account with given
// storage. This function should only be used for debugging.
func (s *StateDB) SetStorage(addr common.Address, storage map[common.Hash]common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetStorage(storage)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (s *StateDB) Suicide(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return false
	}
	s.journal.append(suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)

	return true
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
func (s *StateDB) updateStateObject(obj *stateObject) {
	// Track the amount of time wasted on updating the account from the trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	// Encode the account and update the account trie
	addr := obj.Address()

	data, err := rlp.EncodeToBytes(obj)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
	}
	if err = s.trie.TryUpdate(addr[:], data); err != nil {
		s.setError(fmt.Errorf("updateStateObject (%x) error: %v", addr[:], err))
	}

	// If state snapshotting is active, cache the data til commit. Note, this
	// update mechanism is not symmetric to the deletion, because whereas it is
	// enough to track account updates at commit time, deletions need tracking
	// at transaction boundary level to ensure we capture state clearing.
	if s.snap != nil {
		s.snapAccounts[obj.addrHash] = snapshot.SlimAccountRLP(obj.data.Nonce, obj.data.Balance, obj.data.Root, obj.data.CodeHash)
	}
}

// deleteStateObject removes the given object from the state trie.
func (s *StateDB) deleteStateObject(obj *stateObject) {
	// Track the amount of time wasted on deleting the account from the trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	// Delete the account from the trie
	addr := obj.Address()
	if err := s.trie.TryDelete(addr[:]); err != nil {
		s.setError(fmt.Errorf("deleteStateObject (%x) error: %v", addr[:], err))
	}
}

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context. If you need
// to differentiate between non-existent/just-deleted, use getDeletedStateObject.
func (s *StateDB) getStateObject(addr common.Address) *stateObject {
	if obj := s.getDeletedStateObject(addr); obj != nil && !obj.deleted {
		return obj
	}
	return nil
}

// getDeletedStateObject is similar to getStateObject, but instead of returning
// nil for a deleted state object, it returns the actual object with the deleted
// flag set. This is needed by the state journal to revert to the correct s-
// destructed object instead of wiping all knowledge about the state object.
func (s *StateDB) getDeletedStateObject(addr common.Address) *stateObject {
	// Prefer live objects if any is available
	if obj := s.stateObjects[addr]; obj != nil {
		return obj
	}
	// Runtime MVCC snapshots publish pending account/storage changes into the
	// copied trie, but newly created code and uncommitted storage trie nodes may
	// not exist in the backing database yet. Seed those objects from the frozen
	// canonical version and immediately detach them before any branch mutation.
	if seed, ok := s.runtimeMVCCAccounts[addr]; ok && seed != nil {
		obj := seed.deepCopyRuntimeMVCC(s)
		s.setStateObject(obj)
		return obj
	}
	// If no live objects are available, attempt to use snapshots
	var (
		data *Account
		err  error
	)
	if s.snap != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.SnapshotAccountReads += time.Since(start) }(time.Now())
		}
		var acc *snapshot.Account
		if acc, err = s.snap.Account(crypto.Keccak256Hash(addr.Bytes())); err == nil {
			if acc == nil {
				return nil
			}
			data = &Account{
				Nonce:    acc.Nonce,
				Balance:  acc.Balance,
				CodeHash: acc.CodeHash,
				Root:     common.BytesToHash(acc.Root),
			}
			if len(data.CodeHash) == 0 {
				data.CodeHash = emptyCodeHash
			}
			if data.Root == (common.Hash{}) {
				data.Root = emptyRoot
			}
		}
	}
	// If snapshot unavailable or reading from it failed, load from the database
	if s.snap == nil || err != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.AccountReads += time.Since(start) }(time.Now())
		}
		enc, err := s.trie.TryGet(addr.Bytes())
		if err != nil {
			s.setError(fmt.Errorf("getDeleteStateObject (%x) error: %v", addr.Bytes(), err))
			return nil
		}
		if len(enc) == 0 {
			return nil
		}
		data = new(Account)
		if err := rlp.DecodeBytes(enc, data); err != nil {
			log.Error("Failed to decode state object", "addr", addr, "err", err)
			return nil
		}
	}
	// Insert into the live set
	obj := newObject(s, addr, *data)
	s.setStateObject(obj)
	return obj
}

func (s *StateDB) setStateObject(object *stateObject) {
	s.stateObjects[object.Address()] = object
}

// GetOrNewStateObject retrieves a state object or create a new state object if nil.
func (s *StateDB) GetOrNewStateObject(addr common.Address) *stateObject {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		stateObject, _ = s.createObject(addr)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (s *StateDB) createObject(addr common.Address) (newobj, prev *stateObject) {
	prev = s.getDeletedStateObject(addr) // Note, prev might have been deleted, we need that!

	var prevdestruct bool
	if s.snap != nil && prev != nil {
		_, prevdestruct = s.snapDestructs[prev.addrHash]
		if !prevdestruct {
			s.snapDestructs[prev.addrHash] = struct{}{}
		}
	}
	newobj = newObject(s, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		s.journal.append(createObjectChange{account: &addr})
	} else {
		s.journal.append(resetObjectChange{prev: prev, prevdestruct: prevdestruct})
	}
	s.setStateObject(newobj)
	if prev != nil && !prev.deleted {
		return newobj, prev
	}
	return newobj, nil
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//  1. sends funds to sha(account ++ (nonce + 1))
//  2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (s *StateDB) CreateAccount(addr common.Address) {
	newObj, prev := s.createObject(addr)
	if prev != nil {
		newObj.setBalance(prev.data.Balance)
	}
}

func (s *StateDB) CreateContract(addr common.Address) {
	_, prev := s.createdContracts[addr]
	s.journal.append(createContractChange{account: &addr, prev: prev})
	s.createdContracts[addr] = struct{}{}
}

func (s *StateDB) CreatedContract(addr common.Address) bool {
	_, ok := s.createdContracts[addr]
	return ok
}

func (db *StateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) error {
	so := db.getStateObject(addr)
	if so == nil {
		return nil
	}
	it := trie.NewIterator(so.getTrie(db.db).NodeIterator(nil))

	for it.Next() {
		key := common.BytesToHash(db.trie.GetKey(it.Key))
		if value, dirty := so.dirtyStorage[key]; dirty {
			if !cb(key, value) {
				return nil
			}
			continue
		}

		if len(it.Value) > 0 {
			_, content, _, err := rlp.Split(it.Value)
			if err != nil {
				return err
			}
			if !cb(key, common.BytesToHash(content)) {
				return nil
			}
		}
	}
	return nil
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (s *StateDB) Copy() *StateDB {
	// Copy all the basic fields, initialize the memory ones
	state := &StateDB{
		db:                       s.db,
		trie:                     s.db.CopyTrie(s.trie),
		stateObjects:             make(map[common.Address]*stateObject, len(s.journal.dirties)),
		stateObjectsPending:      make(map[common.Address]struct{}, len(s.stateObjectsPending)),
		stateObjectsDirty:        make(map[common.Address]struct{}, len(s.journal.dirties)),
		refund:                   s.refund,
		logs:                     make(map[common.Hash][]*types.Log, len(s.logs)),
		logSize:                  s.logSize,
		preimages:                make(map[common.Hash][]byte, len(s.preimages)),
		transientStorage:         newTransientStorage(),
		createdContracts:         make(map[common.Address]struct{}, len(s.createdContracts)),
		accessList:               s.accessList.copy(),
		journal:                  newJournal(),
		nativeBlockHashes:        s.nativeBlockHashes,
		nativeReplayTransactions: s.nativeReplayTransactions,
		nativeMVCCVersion:        s.nativeMVCCVersion,
	}
	// Copy the dirty states, logs, and preimages
	for addr := range s.journal.dirties {
		// As documented [here](https://github.com/cypherium/cypher/pull/16485#issuecomment-380438527),
		// and in the Finalise-method, there is a case where an object is in the journal but not
		// in the stateObjects: OOG after touch on ripeMD prior to Byzantium. Thus, we need to check for
		// nil
		if object, exist := s.stateObjects[addr]; exist {
			// Even though the original object is dirty, we are not copying the journal,
			// so we need to make sure that anyside effect the journal would have caused
			// during a commit (or similar op) is already applied to the copy.
			state.stateObjects[addr] = object.deepCopy(state)

			state.stateObjectsDirty[addr] = struct{}{}   // Mark the copy dirty to force internal (code/state) commits
			state.stateObjectsPending[addr] = struct{}{} // Mark the copy pending to force external (account) commits
		}
	}
	// Above, we don't copy the actual journal. This means that if the copy is copied, the
	// loop above will be a no-op, since the copy's journal is empty.
	// Thus, here we iterate over stateObjects, to enable copies of copies
	for addr := range s.stateObjectsPending {
		if _, exist := state.stateObjects[addr]; !exist {
			state.stateObjects[addr] = s.stateObjects[addr].deepCopy(state)
		}
		state.stateObjectsPending[addr] = struct{}{}
	}
	for addr := range s.stateObjectsDirty {
		if _, exist := state.stateObjects[addr]; !exist {
			state.stateObjects[addr] = s.stateObjects[addr].deepCopy(state)
		}
		state.stateObjectsDirty[addr] = struct{}{}
	}
	for hash, logs := range s.logs {
		cpy := make([]*types.Log, len(logs))
		for i, l := range logs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		state.logs[hash] = cpy
	}
	for hash, preimage := range s.preimages {
		state.preimages[hash] = preimage
	}
	for addr, slots := range s.transientStorage {
		state.transientStorage[addr] = make(map[common.Hash]common.Hash, len(slots))
		for key, value := range slots {
			state.transientStorage[addr][key] = value
		}
	}
	for addr := range s.createdContracts {
		state.createdContracts[addr] = struct{}{}
	}
	return state
}

// CopyDeclared creates a transaction-local copy containing only the account
// objects named by a signed native access manifest. The account trie itself is
// copied as an immutable fallback, while live/pending objects are copied on
// write at account granularity. Callers must build these forks before starting
// parallel execution; getDeletedStateObject may populate the base read cache.
//
// This is the production block-local MVCC fork used by the native DAG executor.
// Unlike Copy, its cost is proportional to one transaction's declared account
// footprint instead of every account touched earlier in the block. An object
// tombstone is copied too, preventing an account deleted in the current base
// version from being resurrected through the older trie snapshot.
func (s *StateDB) CopyDeclared(addresses []common.Address, declaredSlots ...map[common.Address][]common.Hash) *StateDB {
	if s == nil {
		return nil
	}
	state := &StateDB{
		db:                       s.db,
		trie:                     s.db.CopyTrie(s.trie),
		stateObjects:             make(map[common.Address]*stateObject, len(addresses)),
		stateObjectsPending:      make(map[common.Address]struct{}),
		stateObjectsDirty:        make(map[common.Address]struct{}),
		logs:                     make(map[common.Hash][]*types.Log),
		preimages:                make(map[common.Hash][]byte),
		transientStorage:         newTransientStorage(),
		createdContracts:         make(map[common.Address]struct{}),
		accessList:               newAccessListState(),
		journal:                  newJournal(),
		dbErr:                    s.dbErr,
		nativeStorageWrites:      make(map[common.Address]map[common.Hash]struct{}),
		nativeBlockHashes:        s.nativeBlockHashes,
		nativeReplayTransactions: s.nativeReplayTransactions,
		nativeMVCCVersion:        s.nativeMVCCVersion,
	}
	seen := make(map[common.Address]struct{}, len(addresses))
	var slotsByAddress map[common.Address][]common.Hash
	if len(declaredSlots) > 0 {
		slotsByAddress = declaredSlots[0]
	}
	for _, address := range addresses {
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		if object := s.getDeletedStateObject(address); object != nil {
			seeded := make(map[common.Hash]common.Hash, len(slotsByAddress[address]))
			for _, slot := range slotsByAddress[address] {
				seeded[slot] = s.GetState(address, slot)
			}
			state.stateObjects[address] = object.deepCopyDeclared(state, seeded)
		}
	}
	return state
}

// NativeMVCCVersion returns the block-local version represented by this state
// or declared branch.
func (s *StateDB) NativeMVCCVersion() uint64 {
	if s == nil {
		return 0
	}
	return s.nativeMVCCVersion
}

// AdvanceNativeMVCCVersion publishes one completed microbatch. It deliberately
// advances only after Finalise, making the next snapshot observe all prior
// writes and preventing stale speculative deltas from being merged.
func (s *StateDB) AdvanceNativeMVCCVersion() error {
	if s == nil {
		return errors.New("cannot advance a nil native MVCC state")
	}
	if s.nativeMVCCVersion == ^uint64(0) {
		return errors.New("native MVCC version overflow")
	}
	s.nativeMVCCVersion++
	return nil
}

type nativeDeclaredSeed struct {
	object *stateObject
	slots  map[common.Hash]common.Hash
}

// NativeDeclaredSnapshot is an immutable, prefetched StateDB version shared by
// every transaction branch in one DAG microbatch. Construction performs all
// lazy account/storage reads serially once; Branch is then read-only and safe
// to call concurrently.
type NativeDeclaredSnapshot struct {
	db                       Database
	trie                     Trie
	dbErr                    error
	nativeBlockHashes        map[uint64]common.Hash
	nativeReplayTransactions map[common.Hash]struct{}
	version                  uint64
	accounts                 map[common.Address]nativeDeclaredSeed
}

// RuntimeMVCCSnapshot is an immutable block-local state version used by the
// standard-EVM optimistic executor. Unlike NativeDeclaredSnapshot it does not
// require a signed access manifest: each branch starts with an empty object
// cache over an independent copy of the already-updated account trie and
// records the resources it actually observes while executing.
//
// The snapshot must be prepared before workers start. PrepareRuntimeMVCCSnapshot
// first publishes all pending objects into the in-memory trie, then borrows the
// canonical object table for the read-only worker phase. Branches detach that
// table before canonical merging resumes, avoiding an O(all block accounts)
// map copy at every fixed-size microbatch.
type RuntimeMVCCSnapshot struct {
	db                       Database
	trie                     Trie
	dbErr                    error
	nativeBlockHashes        map[uint64]common.Hash
	nativeReplayTransactions map[common.Hash]struct{}
	version                  uint64
	accounts                 map[common.Address]*stateObject
}

// PrepareRuntimeMVCCSnapshot freezes the current canonical state into an
// immutable trie view. IntermediateRoot is a process-local publication step;
// it does not commit a block or alter consensus state, and its deterministic
// root is computed from the same finalized transaction boundary as the serial
// executor.
func (s *StateDB) PrepareRuntimeMVCCSnapshot(deleteEmptyObjects bool) (*RuntimeMVCCSnapshot, error) {
	if s == nil {
		return nil, errors.New("cannot snapshot a nil runtime MVCC state")
	}
	s.IntermediateRoot(deleteEmptyObjects)
	if s.dbErr != nil {
		return nil, s.dbErr
	}
	return &RuntimeMVCCSnapshot{
		db:                       s.db,
		trie:                     s.db.CopyTrie(s.trie),
		dbErr:                    s.dbErr,
		nativeBlockHashes:        s.nativeBlockHashes,
		nativeReplayTransactions: s.nativeReplayTransactions,
		version:                  s.nativeMVCCVersion,
		accounts:                 s.stateObjects,
	}, nil
}

// ReleaseRuntimeMVCCSnapshot drops a branch's borrowed read-only seed table.
// The optimistic executor calls this before it resumes canonical StateDB
// mutation. Objects already touched by the branch were deep-copied into its
// private stateObjects map and remain available for delta capture.
func (s *StateDB) ReleaseRuntimeMVCCSnapshot() {
	if s != nil {
		s.runtimeMVCCAccounts = nil
	}
}

// Branch creates an isolated standard-EVM transaction view. Branches share
// only immutable snapshot metadata; their tries, object caches, journals,
// transient storage, logs and preimages are independent and may be mutated by
// separate workers concurrently.
func (snapshot *RuntimeMVCCSnapshot) Branch() (*StateDB, error) {
	if snapshot == nil || snapshot.db == nil || snapshot.trie == nil {
		return nil, errors.New("runtime MVCC snapshot is unavailable")
	}
	return &StateDB{
		db:                       snapshot.db,
		trie:                     snapshot.db.CopyTrie(snapshot.trie),
		stateObjects:             make(map[common.Address]*stateObject),
		stateObjectsPending:      make(map[common.Address]struct{}),
		stateObjectsDirty:        make(map[common.Address]struct{}),
		logs:                     make(map[common.Hash][]*types.Log),
		preimages:                make(map[common.Hash][]byte),
		transientStorage:         newTransientStorage(),
		createdContracts:         make(map[common.Address]struct{}),
		accessList:               newAccessListState(),
		journal:                  newJournal(),
		dbErr:                    snapshot.dbErr,
		nativeBlockHashes:        snapshot.nativeBlockHashes,
		nativeReplayTransactions: snapshot.nativeReplayTransactions,
		nativeMVCCVersion:        snapshot.version,
		runtimeMVCCAccounts:      snapshot.accounts,
	}, nil
}

// PrepareNativeDeclaredSnapshot prefetches the union of exact declared
// resources for a microbatch. Missing accounts are recorded explicitly so a
// concurrent branch never falls back to the mutable base StateDB cache.
func (s *StateDB) PrepareNativeDeclaredSnapshot(addresses []common.Address, slots map[common.Address][]common.Hash) (*NativeDeclaredSnapshot, error) {
	if s == nil {
		return nil, errors.New("cannot snapshot a nil native MVCC state")
	}
	snapshot := &NativeDeclaredSnapshot{
		db:                       s.db,
		trie:                     s.db.CopyTrie(s.trie),
		dbErr:                    s.dbErr,
		nativeBlockHashes:        s.nativeBlockHashes,
		nativeReplayTransactions: s.nativeReplayTransactions,
		version:                  s.nativeMVCCVersion,
		accounts:                 make(map[common.Address]nativeDeclaredSeed, len(addresses)),
	}
	template := &StateDB{db: s.db, trie: s.db.CopyTrie(s.trie), journal: newJournal()}
	for _, address := range addresses {
		if _, prepared := snapshot.accounts[address]; prepared {
			continue
		}
		object := s.getDeletedStateObject(address)
		seed := nativeDeclaredSeed{slots: make(map[common.Hash]common.Hash, len(slots[address]))}
		if object != nil && !object.deleted {
			for _, slot := range slots[address] {
				seed.slots[slot] = object.GetState(s.db, slot)
			}
		}
		if object != nil && object.dbErr != nil {
			return nil, fmt.Errorf("prefetch native MVCC account %s: %w", address, object.dbErr)
		}
		if object != nil {
			// Detach account metadata/code/trie handles from the mutable base.
			// Branch creation can now proceed concurrently even if a caller
			// retains the snapshot beyond the immediate execution phase.
			seed.object = object.deepCopyDeclared(template, seed.slots)
		}
		snapshot.accounts[address] = seed
	}
	if s.dbErr != nil {
		return nil, s.dbErr
	}
	return snapshot, nil
}

// Branch creates one transaction-local COW view from a prepared version. It
// performs no reads or writes against the base StateDB and is safe for parallel
// branch construction.
func (snapshot *NativeDeclaredSnapshot) Branch(addresses []common.Address, slots map[common.Address][]common.Hash) (*StateDB, error) {
	if snapshot == nil || snapshot.db == nil || snapshot.trie == nil {
		return nil, errors.New("native MVCC snapshot is unavailable")
	}
	state := &StateDB{
		db:                       snapshot.db,
		trie:                     snapshot.db.CopyTrie(snapshot.trie),
		stateObjects:             make(map[common.Address]*stateObject, len(addresses)),
		stateObjectsPending:      make(map[common.Address]struct{}),
		stateObjectsDirty:        make(map[common.Address]struct{}),
		logs:                     make(map[common.Hash][]*types.Log),
		preimages:                make(map[common.Hash][]byte),
		transientStorage:         newTransientStorage(),
		createdContracts:         make(map[common.Address]struct{}),
		accessList:               newAccessListState(),
		journal:                  newJournal(),
		dbErr:                    snapshot.dbErr,
		nativeStorageWrites:      make(map[common.Address]map[common.Hash]struct{}),
		nativeBlockHashes:        snapshot.nativeBlockHashes,
		nativeReplayTransactions: snapshot.nativeReplayTransactions,
		nativeMVCCVersion:        snapshot.version,
	}
	seen := make(map[common.Address]struct{}, len(addresses))
	for _, address := range addresses {
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		seed, prepared := snapshot.accounts[address]
		if !prepared {
			return nil, fmt.Errorf("native MVCC account %s was not prefetched", address)
		}
		if seed.object == nil {
			continue
		}
		values := make(map[common.Hash]common.Hash, len(slots[address]))
		for _, slot := range slots[address] {
			value, prepared := seed.slots[slot]
			if !prepared && !seed.object.deleted {
				return nil, fmt.Errorf("native MVCC storage %s/%s was not prefetched", address, slot)
			}
			values[slot] = value
		}
		state.stateObjects[address] = seed.object.deepCopyDeclared(state, values)
	}
	return state, nil
}

// NativeAccountChanged reports whether the current transaction-local branch
// finalized a persistent change for address. It is meaningful only on a
// CopyDeclared branch after transaction execution.
func (s *StateDB) NativeAccountChanged(address common.Address) bool {
	if s == nil || s.nativeStorageWrites == nil {
		return false
	}
	_, changed := s.stateObjectsDirty[address]
	return changed
}

// NativeStorageChanged reports whether execution actually attempted a value
// change for one slot. A reverted write may conservatively return true; capture
// then reads the final branch value and merge is a no-op, preserving serial
// semantics without letting unused manifest declarations amplify work.
func (s *StateDB) NativeStorageChanged(address common.Address, slot common.Hash) bool {
	if s == nil || s.nativeStorageWrites == nil {
		return false
	}
	_, changed := s.nativeStorageWrites[address][slot]
	return changed
}

// Snapshot returns an identifier for the current revision of the state.
func (s *StateDB) Snapshot() int {
	id := s.nextRevisionId
	s.nextRevisionId++
	s.validRevisions = append(s.validRevisions, revision{
		id:                       id,
		journalIndex:             s.journal.length(),
		nativeBlockHashes:        s.nativeBlockHashes,
		nativeReplayTransactions: s.nativeReplayTransactions,
		nativeMVCCVersion:        s.nativeMVCCVersion,
	})
	return id
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (s *StateDB) RevertToSnapshot(revid int) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(s.validRevisions), func(i int) bool {
		return s.validRevisions[i].id >= revid
	})
	if idx == len(s.validRevisions) || s.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	revision := s.validRevisions[idx]

	// Replay the journal to undo changes and remove invalidated snapshots
	s.journal.revert(s, revision.journalIndex)
	s.nativeBlockHashes = revision.nativeBlockHashes
	s.nativeReplayTransactions = revision.nativeReplayTransactions
	s.nativeMVCCVersion = revision.nativeMVCCVersion
	s.validRevisions = s.validRevisions[:idx]
}

// GetRefund returns the current value of the refund counter.
func (s *StateDB) GetRefund() uint64 {
	return s.refund
}

// Finalise finalises the state by removing the s destructed objects and clears
// the journal as well as the refunds. Finalise, however, will not push any updates
// into the tries just yet. Only IntermediateRoot or Commit will do that.
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	for addr := range s.journal.dirties {
		obj, exist := s.stateObjects[addr]
		if !exist {
			// ripeMD is 'touched' at block 1714175, in tx 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2
			// That tx goes out of gas, and although the notion of 'touched' does not exist there, the
			// touch-event will still be recorded in the journal. Since ripeMD is a special snowflake,
			// it will persist in the journal even though the journal is reverted. In this special circumstance,
			// it may exist in `s.journal.dirties` but not in `s.stateObjects`.
			// Thus, we can safely ignore it here
			continue
		}
		if obj.suicided || (deleteEmptyObjects && obj.empty()) {
			obj.deleted = true

			// If state snapshotting is active, also mark the destruction there.
			// Note, we can't do this only at the end of a block because multiple
			// transactions within the same block might self destruct and then
			// ressurrect an account; but the snapshotter needs both events.
			if s.snap != nil {
				s.snapDestructs[obj.addrHash] = struct{}{} // We need to maintain account deletions explicitly (will remain set indefinitely)
				delete(s.snapAccounts, obj.addrHash)       // Clear out any previously updated account data (may be recreated via a ressurrect)
				delete(s.snapStorage, obj.addrHash)        // Clear out any previously updated storage data (may be recreated via a ressurrect)
			}
		} else {
			obj.finalise()
		}
		s.stateObjectsPending[addr] = struct{}{}
		s.stateObjectsDirty[addr] = struct{}{}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	s.clearJournalAndRefund()
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	workers := runtime.GOMAXPROCS(0)
	if workers > 64 {
		workers = 64
	}
	return s.intermediateRootWithWorkers(deleteEmptyObjects, workers)
}

// intermediateRootWithWorkers computes independent account storage roots and
// account RLPs in bounded worker pools, then atomically updates independent
// first-nibble account-trie subtrees. Worker count is a local choice and cannot
// affect consensus output.
func (s *StateDB) intermediateRootWithWorkers(deleteEmptyObjects bool, workers int) common.Hash {
	// Finalise all the dirty storage states and write them into the tries
	s.Finalise(deleteEmptyObjects)

	addresses := make([]common.Address, 0, len(s.stateObjectsPending))
	for addr := range s.stateObjectsPending {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return bytes.Compare(addresses[i][:], addresses[j][:]) < 0 })
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	// Split one process-local worker budget between account-level jobs and the
	// storage batches inside hot accounts. Without this split, a single contract
	// remains serial; naively giving every account its own full pool oversubscribes
	// validators by O(accounts*GOMAXPROCS).
	storageAccounts := 0
	for _, addr := range addresses {
		if obj := s.stateObjects[addr]; obj != nil && !obj.deleted && len(obj.pendingStorage) > 1 {
			storageAccounts++
		}
	}
	outerWorkers := workers
	storageWorkers := 1
	if storageAccounts > 0 && workers > 1 {
		outerWorkers = workers / 2
		if outerWorkers < 1 {
			outerWorkers = 1
		}
		if outerWorkers > len(addresses) {
			outerWorkers = len(addresses)
		}
		innerBudget := workers - outerWorkers
		if innerBudget > 0 {
			storageWorkers = innerBudget / storageAccounts
			if storageWorkers < 1 {
				storageWorkers = 1
			}
		}
	}
	if outerWorkers > len(addresses) {
		outerWorkers = len(addresses)
	}
	updateRoot := func(addr common.Address) {
		if obj := s.stateObjects[addr]; obj != nil && !obj.deleted {
			innerWorkers := 1
			if len(obj.pendingStorage) > 1 {
				innerWorkers = storageWorkers
			}
			obj.updateRootWithWorkers(s.db, innerWorkers)
		}
	}
	if outerWorkers <= 1 {
		for _, addr := range addresses {
			updateRoot(addr)
		}
	} else {
		jobs := make(chan common.Address, outerWorkers)
		var group sync.WaitGroup
		group.Add(outerWorkers)
		for worker := 0; worker < outerWorkers; worker++ {
			go func() {
				defer group.Done()
				for addr := range jobs {
					updateRoot(addr)
				}
			}()
		}
		for _, addr := range addresses {
			jobs <- addr
		}
		close(jobs)
		group.Wait()
	}
	s.updateAccountTrieBatch(addresses, workers)
	if len(s.stateObjectsPending) > 0 {
		s.stateObjectsPending = make(map[common.Address]struct{})
	}
	// Track the amount of time wasted on hashing the account trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountHashes += time.Since(start) }(time.Now())
	}
	return s.trie.Hash()
}

// updateAccountTrieBatch prepares consensus account encodings in parallel and
// applies them through SecureTrie's deterministic first-nibble batch API. The
// mutation list remains address-sorted for reproducible diagnostics and
// duplicate-free state-object semantics.
func (s *StateDB) updateAccountTrieBatch(addresses []common.Address, workers int) {
	objects := make([]*stateObject, 0, len(addresses))
	for _, address := range addresses {
		if obj := s.stateObjects[address]; obj != nil {
			objects = append(objects, obj)
		}
	}
	if len(objects) == 0 {
		return
	}
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	if workers > len(objects) {
		workers = len(objects)
	}
	mutations := make([]trie.BatchMutation, len(objects))
	encodeErrors := make([]error, len(objects))
	slimAccounts := make([][]byte, len(objects))
	prepare := func(index int) {
		obj := objects[index]
		key := make([]byte, len(obj.address))
		copy(key, obj.address[:])
		if obj.deleted {
			mutations[index] = trie.BatchMutation{Key: key, Delete: true}
			return
		}
		encoded, err := rlp.EncodeToBytes(obj)
		if err != nil {
			encodeErrors[index] = err
			return
		}
		mutations[index] = trie.BatchMutation{Key: key, Value: encoded}
		if s.snap != nil {
			slimAccounts[index] = snapshot.SlimAccountRLP(obj.data.Nonce, obj.data.Balance, obj.data.Root, obj.data.CodeHash)
		}
	}
	if workers <= 1 {
		for index := range objects {
			prepare(index)
		}
	} else {
		jobs := make(chan int, workers)
		var group sync.WaitGroup
		group.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func() {
				defer group.Done()
				for index := range jobs {
					prepare(index)
				}
			}()
		}
		for index := range objects {
			jobs <- index
		}
		close(jobs)
		group.Wait()
	}
	for index, err := range encodeErrors {
		if err != nil {
			panic(fmt.Errorf("can't encode object at %x: %v", objects[index].address[:], err))
		}
	}
	if err := s.trie.TryUpdateBatch(mutations, workers); err != nil {
		s.setError(fmt.Errorf("update account trie batch: %v", err))
	}
	if s.snap != nil {
		for index, obj := range objects {
			if !obj.deleted {
				s.snapAccounts[obj.addrHash] = slimAccounts[index]
			}
		}
	}
}

// Prepare sets the current transaction hash and index and block hash which is
// used when the EVM emits new state logs.
func (s *StateDB) Prepare(thash, bhash common.Hash, ti int) {
	s.transientStorage = newTransientStorage()
	s.createdContracts = make(map[common.Address]struct{})
	s.thash = thash
	s.bhash = bhash
	s.txIndex = ti
}

func (s *StateDB) SetTransientState(addr common.Address, key, value common.Hash) {
	prev := s.GetTransientState(addr, key)
	if prev == value {
		return
	}
	s.journal.append(transientStorageChange{account: &addr, key: key, prevalue: prev})
	s.setTransientState(addr, key, value)
}

func (s *StateDB) setTransientState(addr common.Address, key, value common.Hash) {
	s.transientStorage.Set(addr, key, value)
}

func (s *StateDB) GetTransientState(addr common.Address, key common.Hash) common.Hash {
	return s.transientStorage.Get(addr, key)
}

func (s *StateDB) clearJournalAndRefund() {
	if len(s.journal.entries) > 0 {
		s.journal = newJournal()
		s.refund = 0
	}
	s.validRevisions = s.validRevisions[:0] // Snapshots can be created without journal entires
}

// Commit writes the state to the underlying in-memory trie database.
func (s *StateDB) Commit(deleteEmptyObjects bool) (common.Hash, error) {
	if s.dbErr != nil {
		return common.Hash{}, fmt.Errorf("commit aborted due to earlier error: %v", s.dbErr)
	}
	// Finalize any pending changes and merge everything into the tries
	s.IntermediateRoot(deleteEmptyObjects)

	// Commit objects to the trie, measuring the elapsed time
	codeWriter := s.db.TrieDB().DiskDB().NewBatch()
	dirtyAddresses := make([]common.Address, 0, len(s.stateObjectsDirty))
	for addr := range s.stateObjectsDirty {
		dirtyAddresses = append(dirtyAddresses, addr)
	}
	sort.Slice(dirtyAddresses, func(i, j int) bool { return bytes.Compare(dirtyAddresses[i][:], dirtyAddresses[j][:]) < 0 })
	dirtyObjects := make([]*stateObject, 0, len(dirtyAddresses))
	committedAddresses := make([]common.Address, 0, len(dirtyAddresses))
	for _, addr := range dirtyAddresses {
		if obj := s.stateObjects[addr]; obj != nil && !obj.deleted {
			// Write any contract code associated with the state object
			if obj.code != nil && obj.dirtyCode {
				rawdb.WriteCode(codeWriter, common.BytesToHash(obj.CodeHash()), obj.code)
				obj.dirtyCode = false
			}
			dirtyObjects = append(dirtyObjects, obj)
			committedAddresses = append(committedAddresses, addr)
		}
	}
	// Storage tries are independent after IntermediateRoot has finalized every
	// mutation. Trie.Database serializes its node-cache insertions internally,
	// while hashing/collapsing each account trie can proceed in parallel. Errors
	// are consumed in sorted account order so worker timing is never observable.
	commitErrors := make([]error, len(dirtyObjects))
	workers := runtime.GOMAXPROCS(0)
	if workers > 64 {
		workers = 64
	}
	if workers > len(dirtyObjects) {
		workers = len(dirtyObjects)
	}
	commitStorage := func(index int) {
		commitErrors[index] = dirtyObjects[index].CommitTrie(s.db)
	}
	if workers <= 1 {
		for index := range dirtyObjects {
			commitStorage(index)
		}
	} else {
		jobs := make(chan int, workers)
		var group sync.WaitGroup
		group.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func() {
				defer group.Done()
				for index := range jobs {
					commitStorage(index)
				}
			}()
		}
		for index := range dirtyObjects {
			jobs <- index
		}
		close(jobs)
		group.Wait()
	}
	for index, err := range commitErrors {
		if err != nil {
			return common.Hash{}, fmt.Errorf("commit storage trie for %s: %w", committedAddresses[index], err)
		}
	}
	if len(s.stateObjectsDirty) > 0 {
		s.stateObjectsDirty = make(map[common.Address]struct{})
	}
	if codeWriter.ValueSize() > 0 {
		if err := codeWriter.Write(); err != nil {
			log.Crit("Failed to commit dirty codes", "error", err)
		}
	}
	// Write the account trie changes, measuing the amount of wasted time
	var start time.Time
	if metrics.EnabledExpensive {
		start = time.Now()
	}
	// The onleaf func is called _serially_, so we can reuse the same account
	// for unmarshalling every time.
	var account Account
	root, err := s.trie.Commit(func(leaf []byte, parent common.Hash) error {
		if err := rlp.DecodeBytes(leaf, &account); err != nil {
			return nil
		}
		if account.Root != emptyRoot {
			s.db.TrieDB().Reference(account.Root, parent)
		}
		return nil
	})
	if metrics.EnabledExpensive {
		s.AccountCommits += time.Since(start)
	}
	// If snapshotting is enabled, update the snapshot tree with this new version
	if s.snap != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.SnapshotCommits += time.Since(start) }(time.Now())
		}
		// Only update if there's a state transition (skip empty Clique blocks)
		if parent := s.snap.Root(); parent != root {
			if err := s.snaps.Update(root, parent, s.snapDestructs, s.snapAccounts, s.snapStorage); err != nil {
				log.Warn("Failed to update snapshot tree", "from", parent, "to", root, "err", err)
			}
			if err := s.snaps.Cap(root, 127); err != nil { // Persistent layer is 128th, the last available trie
				log.Warn("Failed to cap snapshot tree", "root", root, "layers", 127, "err", err)
			}
		}
		s.snap, s.snapDestructs, s.snapAccounts, s.snapStorage = nil, nil, nil, nil
	}
	return root, err
}
