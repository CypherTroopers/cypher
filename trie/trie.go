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

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
)

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// emptyState is the known hash of an empty state trie entry.
	emptyState = crypto.Keccak256Hash(nil)
)

// LeafCallback is a callback type invoked when a trie operation reaches a leaf
// node. It's used by state sync and commit to allow handling external references
// between account and storage tries.
type LeafCallback func(leaf []byte, parent common.Hash) error

// Trie is a Merkle Patricia Trie.
// The zero value is an empty trie with no database.
// Use New to create a trie that sits on top of a database.
//
// Trie is not safe for concurrent use.
type Trie struct {
	db   *Database
	root node
	// Keep track of the number leafs which have been inserted since the last
	// hashing operation. This number will not directly map to the number of
	// actually unhashed nodes
	unhashed int
}

// BatchMutation describes one atomic trie mutation. A mutation deletes the key
// when Delete is set or Value is empty, matching TryDelete and TryUpdate.
// Otherwise it associates Key with Value. Callers must not modify Key or Value
// while TryUpdateBatch is running.
type BatchMutation struct {
	Key    []byte
	Value  []byte
	Delete bool
}

type hexBatchMutation struct {
	key    []byte
	value  []byte
	delete bool
}

// newFlag returns the cache flag value for a newly created node.
func (t *Trie) newFlag() nodeFlag {
	return nodeFlag{dirty: true}
}

// New creates a trie with an existing root node from db.
//
// If root is the zero hash or the sha3 hash of an empty string, the
// trie is initially empty and does not require a database. Otherwise,
// New will panic if db is nil and returns a MissingNodeError if root does
// not exist in the database. Accessing the trie loads nodes from db on demand.
func New(root common.Hash, db *Database) (*Trie, error) {
	if db == nil {
		panic("trie.New called without a database")
	}
	trie := &Trie{
		db: db,
	}
	if root != (common.Hash{}) && root != emptyRoot {
		rootnode, err := trie.resolveHash(root[:], nil)
		if err != nil {
			return nil, err
		}
		trie.root = rootnode
	}
	return trie, nil
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
func (t *Trie) NodeIterator(start []byte) NodeIterator {
	return newNodeIterator(t, start)
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
func (t *Trie) Get(key []byte) []byte {
	res, err := t.TryGet(key)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return res
}

// TryGet returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryGet(key []byte) ([]byte, error) {
	key = keybytesToHex(key)
	value, newroot, didResolve, err := t.tryGet(t.root, key, 0)
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}

func (t *Trie) tryGet(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.tryGet(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.tryGet(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveHash(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.tryGet(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
func (t *Trie) Update(key, value []byte) {
	if err := t.TryUpdate(key, value); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// TryUpdate associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryUpdate(key, value []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

// TryUpdateBatch atomically applies mutations to the trie. Mutations whose
// keys have different first nibbles are applied to independent subtries by a
// bounded worker pool. The resulting root uses the same short/full-node
// canonicalisation rules as serial TryUpdate/TryDelete calls.
//
// If any subtrie cannot be resolved, the original trie is left unchanged.
// Mutations for the same key retain their input order.
func (t *Trie) TryUpdateBatch(mutations []BatchMutation, workers int) error {
	if len(mutations) == 0 {
		return nil
	}
	hexMutations := make([]hexBatchMutation, len(mutations))
	for i, mutation := range mutations {
		hexMutations[i] = hexBatchMutation{
			key:    keybytesToHex(mutation.Key),
			value:  mutation.Value,
			delete: mutation.Delete || len(mutation.Value) == 0,
		}
	}
	return t.tryUpdateHexBatch(hexMutations, workers)
}

// TryUpdateKeyValueBatch adapts already encoded key/value leaves to the atomic
// batch mutation API. It exists as a dependency-neutral optional capability for
// consensus list hashing: core/types cannot import trie without creating an
// import cycle through rawdb.
func (t *Trie) TryUpdateKeyValueBatch(keys, values [][]byte, workers int) error {
	if len(keys) != len(values) {
		return fmt.Errorf("trie batch key/value count mismatch: %d != %d", len(keys), len(values))
	}
	mutations := make([]BatchMutation, len(keys))
	for index := range keys {
		mutations[index] = BatchMutation{Key: keys[index], Value: values[index]}
	}
	return t.TryUpdateBatch(mutations, workers)
}

// tryUpdateHexBatch partitions the trie at the first nibble. A Merkle Patricia
// trie has at most 17 root branches (16 nibbles and the terminator), so this
// bounds both the number of goroutines and the merge cost independent of batch
// size.
func (t *Trie) tryUpdateHexBatch(mutations []hexBatchMutation, workers int) error {
	// Adaptively descend through common prefixes until enough independent COW
	// subtries exist. Fixed one/two-nibble sharding is not adversarially robust:
	// account owners can offline-grind secure keys into one chosen prefix.
	if workers > 1 && len(mutations) > 1 {
		return t.tryUpdateHexBatchAdaptive(mutations, workers)
	}
	branches, err := t.splitRootBranches()
	if err != nil {
		return err
	}
	groups := make([][]hexBatchMutation, len(branches))
	for _, mutation := range mutations {
		if len(mutation.key) == 0 || int(mutation.key[0]) >= len(groups) {
			return fmt.Errorf("invalid hex trie key %x", mutation.key)
		}
		index := int(mutation.key[0])
		groups[index] = append(groups[index], mutation)
	}
	type batchJob struct {
		index int
		group []hexBatchMutation
	}
	jobs := make([]batchJob, 0, len(groups))
	for index, group := range groups {
		if len(group) != 0 {
			jobs = append(jobs, batchJob{index: index, group: group})
		}
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	errs := make([]error, len(branches))
	apply := func(job batchJob) {
		root := branches[job.index]
		prefix := []byte{byte(job.index)}
		for _, mutation := range job.group {
			var (
				dirty bool
				next  node
				err   error
			)
			if mutation.delete {
				dirty, next, err = t.delete(root, prefix, mutation.key[1:])
			} else {
				dirty, next, err = t.insert(root, prefix, mutation.key[1:], valueNode(mutation.value))
			}
			if err != nil {
				errs[job.index] = err
				return
			}
			if dirty {
				root = next
			}
		}
		branches[job.index] = root
	}
	if workers <= 1 {
		for _, job := range jobs {
			apply(job)
		}
	} else {
		queue := make(chan batchJob, len(jobs))
		var group sync.WaitGroup
		group.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer group.Done()
				for job := range queue {
					apply(job)
				}
			}()
		}
		for _, job := range jobs {
			queue <- job
		}
		close(queue)
		group.Wait()
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	root, err := t.joinRootBranches(branches)
	if err != nil {
		return err
	}
	t.root = root
	t.unhashed += len(mutations)
	return nil
}

type adaptiveBatchPartition struct {
	prefix    []byte
	root      node
	mutations []hexBatchMutation
	split     bool
	branches  [17]node
	children  [17]*adaptiveBatchPartition
	result    node
	err       error
}

// tryUpdateHexBatchAdaptive recursively partitions hot secure-key prefixes.
// Unique keys eventually diverge even if an adversary grinds several leading
// nibbles; exact duplicate keys remain in one ordered leaf, preserving serial
// last-write semantics. Every mutation job is copy-on-write and t.root is only
// replaced after all jobs and deterministic bottom-up joins succeed.
func (t *Trie) tryUpdateHexBatchAdaptive(mutations []hexBatchMutation, workers int) error {
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	if workers > len(mutations) {
		workers = len(mutations)
	}
	// Aim for at least two leaves per worker while avoiding tiny jobs on very
	// large blocks. Prefix skew is handled recursively rather than assumed away.
	target := (len(mutations) + workers*2 - 1) / (workers * 2)
	if target < 8 {
		target = 8
	}
	leaves := make([]*adaptiveBatchPartition, 0, workers*2)
	var build func(root node, prefix []byte, group []hexBatchMutation) (*adaptiveBatchPartition, error)
	build = func(root node, prefix []byte, group []hexBatchMutation) (*adaptiveBatchPartition, error) {
		partition := &adaptiveBatchPartition{prefix: prefix, root: root, mutations: group}
		if len(group) <= target {
			leaves = append(leaves, partition)
			return partition, nil
		}
		depth := len(prefix)
		var groups [17][]hexBatchMutation
		canSplit := false
		terminal := false
		for _, mutation := range group {
			if depth >= len(mutation.key) {
				// Only exact duplicate keys reach this point. They must retain input
				// order in one leaf because no independent subtree remains.
				terminal = true
				break
			}
			nibble := mutation.key[depth]
			if nibble > 16 {
				return nil, fmt.Errorf("invalid hex trie key %x", mutation.key)
			}
			groups[nibble] = append(groups[nibble], mutation)
			canSplit = true
		}
		if terminal || !canSplit {
			leaves = append(leaves, partition)
			return partition, nil
		}
		branches, err := t.splitNodeBranches(root, prefix)
		if err != nil {
			return nil, err
		}
		partition.split = true
		partition.branches = branches
		for nibble := 0; nibble < len(groups); nibble++ {
			if len(groups[nibble]) == 0 {
				continue
			}
			childPrefix := make([]byte, len(prefix)+1)
			copy(childPrefix, prefix)
			childPrefix[len(prefix)] = byte(nibble)
			child, err := build(branches[nibble], childPrefix, groups[nibble])
			if err != nil {
				return nil, err
			}
			partition.children[nibble] = child
		}
		return partition, nil
	}
	rootPartition, err := build(t.root, nil, mutations)
	if err != nil {
		return err
	}
	apply := func(partition *adaptiveBatchPartition) {
		root := partition.root
		depth := len(partition.prefix)
		for _, mutation := range partition.mutations {
			var (
				dirty bool
				next  node
				err   error
			)
			if mutation.delete {
				dirty, next, err = t.delete(root, partition.prefix, mutation.key[depth:])
			} else {
				dirty, next, err = t.insert(root, partition.prefix, mutation.key[depth:], valueNode(mutation.value))
			}
			if err != nil {
				partition.err = err
				return
			}
			if dirty {
				root = next
			}
		}
		partition.result = root
	}
	if workers <= 1 || len(leaves) <= 1 {
		for _, leaf := range leaves {
			apply(leaf)
		}
	} else {
		if workers > len(leaves) {
			workers = len(leaves)
		}
		queue := make(chan *adaptiveBatchPartition, len(leaves))
		var group sync.WaitGroup
		group.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func() {
				defer group.Done()
				for leaf := range queue {
					apply(leaf)
				}
			}()
		}
		for _, leaf := range leaves {
			queue <- leaf
		}
		close(queue)
		group.Wait()
	}
	for _, leaf := range leaves {
		if leaf.err != nil {
			return leaf.err
		}
	}
	var join func(*adaptiveBatchPartition) (node, error)
	join = func(partition *adaptiveBatchPartition) (node, error) {
		if !partition.split {
			return partition.result, nil
		}
		branches := partition.branches
		for nibble, child := range partition.children {
			if child == nil {
				continue
			}
			result, err := join(child)
			if err != nil {
				return nil, err
			}
			branches[nibble] = result
		}
		return t.joinNodeBranches(branches, partition.prefix)
	}
	root, err := join(rootPartition)
	if err != nil {
		return err
	}
	t.root = root
	t.unhashed += len(mutations)
	return nil
}

// tryUpdateHexBatchTwoLevels applies mutations to up to 256 independent
// two-nibble subtries. All exposed roots are resolved before workers start and
// every job uses copy-on-write insert/delete, so an error leaves t.root
// unchanged. Joins run in deterministic nibble order and perform the same
// single-child compression as serial mutation.
func (t *Trie) tryUpdateHexBatchTwoLevels(mutations []hexBatchMutation, workers int) error {
	rootBranches, err := t.splitRootBranches()
	if err != nil {
		return err
	}
	type secondPartition struct {
		active   bool
		branches [17]node
	}
	var partitions [16]secondPartition
	groups := make([][]hexBatchMutation, 17*17)
	for _, mutation := range mutations {
		if len(mutation.key) == 0 || mutation.key[0] > 16 {
			return fmt.Errorf("invalid hex trie key %x", mutation.key)
		}
		first := int(mutation.key[0])
		if first == 16 {
			groups[16*17+16] = append(groups[16*17+16], mutation)
			continue
		}
		if len(mutation.key) < 2 || mutation.key[1] > 16 {
			return fmt.Errorf("invalid second-level hex trie key %x", mutation.key)
		}
		groups[first*17+int(mutation.key[1])] = append(groups[first*17+int(mutation.key[1])], mutation)
	}
	for first := 0; first < 16; first++ {
		hasMutations := false
		for second := 0; second < 17; second++ {
			if len(groups[first*17+second]) != 0 {
				hasMutations = true
				break
			}
		}
		if !hasMutations {
			continue
		}
		branches, err := t.splitNodeBranches(rootBranches[first], []byte{byte(first)})
		if err != nil {
			return err
		}
		partitions[first] = secondPartition{active: true, branches: branches}
	}
	type batchJob struct {
		first, second int
		depth         int
		group         []hexBatchMutation
		root          node
		result        node
		err           error
	}
	jobs := make([]batchJob, 0, 16*16+1)
	for first := 0; first < 16; first++ {
		if !partitions[first].active {
			continue
		}
		for second := 0; second < 17; second++ {
			group := groups[first*17+second]
			if len(group) == 0 {
				continue
			}
			jobs = append(jobs, batchJob{
				first: first, second: second, depth: 2, group: group,
				root: partitions[first].branches[second],
			})
		}
	}
	if group := groups[16*17+16]; len(group) != 0 {
		jobs = append(jobs, batchJob{first: 16, second: 16, depth: 1, group: group, root: rootBranches[16]})
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	apply := func(job *batchJob) {
		root := job.root
		prefix := make([]byte, job.depth)
		prefix[0] = byte(job.first)
		if job.depth == 2 {
			prefix[1] = byte(job.second)
		}
		for _, mutation := range job.group {
			var (
				dirty bool
				next  node
				err   error
			)
			if mutation.delete {
				dirty, next, err = t.delete(root, prefix, mutation.key[job.depth:])
			} else {
				dirty, next, err = t.insert(root, prefix, mutation.key[job.depth:], valueNode(mutation.value))
			}
			if err != nil {
				job.err = err
				return
			}
			if dirty {
				root = next
			}
		}
		job.result = root
	}
	if workers <= 1 {
		for index := range jobs {
			apply(&jobs[index])
		}
	} else {
		queue := make(chan int, len(jobs))
		var group sync.WaitGroup
		group.Add(workers)
		for index := 0; index < workers; index++ {
			go func() {
				defer group.Done()
				for jobIndex := range queue {
					apply(&jobs[jobIndex])
				}
			}()
		}
		for index := range jobs {
			queue <- index
		}
		close(queue)
		group.Wait()
	}
	for index := range jobs {
		if jobs[index].err != nil {
			return jobs[index].err
		}
		if jobs[index].depth == 1 {
			rootBranches[16] = jobs[index].result
		} else {
			partitions[jobs[index].first].branches[jobs[index].second] = jobs[index].result
		}
	}
	for first := 0; first < 16; first++ {
		if !partitions[first].active {
			continue
		}
		joined, err := t.joinNodeBranches(partitions[first].branches, []byte{byte(first)})
		if err != nil {
			return err
		}
		rootBranches[first] = joined
	}
	root, err := t.joinRootBranches(rootBranches)
	if err != nil {
		return err
	}
	t.root = root
	t.unhashed += len(mutations)
	return nil
}

// splitRootBranches removes the first nibble from the current root and returns
// its 17 possible branches. Newly exposed short nodes are marked dirty because
// their compact key changed; their consensus encoding is otherwise unchanged.
func (t *Trie) splitRootBranches() ([17]node, error) {
	return t.splitNodeBranches(t.root, nil)
}

func (t *Trie) splitNodeBranches(root node, prefix []byte) ([17]node, error) {
	var branches [17]node
	if hashed, ok := root.(hashNode); ok {
		resolved, err := t.resolveHash(hashed, prefix)
		if err != nil {
			return branches, err
		}
		root = resolved
	}
	switch root := root.(type) {
	case nil:
		return branches, nil
	case *fullNode:
		copy(branches[:], root.Children[:])
		return branches, nil
	case *shortNode:
		if len(root.Key) == 0 || int(root.Key[0]) >= len(branches) {
			return branches, fmt.Errorf("invalid short trie root key %x", root.Key)
		}
		if len(root.Key) == 1 {
			branches[root.Key[0]] = root.Val
		} else {
			branches[root.Key[0]] = &shortNode{Key: root.Key[1:], Val: root.Val, flags: t.newFlag()}
		}
		return branches, nil
	case valueNode:
		// A public Trie key always includes the terminator and therefore
		// normally represents this as shortNode{16, value}. Accepting a bare
		// value node here keeps the batch operation robust for internal tries.
		branches[16] = root
		return branches, nil
	default:
		return branches, fmt.Errorf("invalid trie root type %T", root)
	}
}

// joinRootBranches performs the same single-child collapse as delete. This is
// the only serial merge point after the independent first-nibble updates.
func (t *Trie) joinRootBranches(branches [17]node) (node, error) {
	return t.joinNodeBranches(branches, nil)
}

func (t *Trie) joinNodeBranches(branches [17]node, prefix []byte) (node, error) {
	count, position := 0, -1
	for index, child := range branches {
		if child != nil {
			count++
			position = index
		}
	}
	switch count {
	case 0:
		return nil, nil
	case 1:
		child := branches[position]
		if position != 16 {
			resolved, err := t.resolve(child, append(prefix, byte(position)))
			if err != nil {
				return nil, err
			}
			if short, ok := resolved.(*shortNode); ok {
				return &shortNode{Key: concat([]byte{byte(position)}, short.Key...), Val: short.Val, flags: t.newFlag()}, nil
			}
		}
		return &shortNode{Key: []byte{byte(position)}, Val: child, flags: t.newFlag()}, nil
	default:
		return &fullNode{Children: branches, flags: t.newFlag()}, nil
	}
}

func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			return true, branch, nil
		}
		// Otherwise, replace it with a short node leading up to the branch.
		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		return true, &shortNode{key, value, t.newFlag()}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveHash(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// Delete removes any existing value for key from the trie.
func (t *Trie) Delete(key []byte) {
	if err := t.TryDelete(key); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// TryDelete removes any existing value for key from the trie.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryDelete(key []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}
		if matchlen == len(key) {
			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			return true, &shortNode{concat(n.Key, child.Key...), child.Val, t.newFlag()}, nil
		default:
			return true, &shortNode{n.Key, child, t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn

		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				cnode, err := t.resolve(n.Children[pos], prefix)
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{k, cnode.Val, t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			return true, &shortNode{[]byte{byte(pos)}, n.Children[pos], t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveHash(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if n, ok := n.(hashNode); ok {
		return t.resolveHash(n, prefix)
	}
	return n, nil
}

func (t *Trie) resolveHash(n hashNode, prefix []byte) (node, error) {
	hash := common.BytesToHash(n)
	if node := t.db.node(hash); node != nil {
		return node, nil
	}
	return nil, &MissingNodeError{NodeHash: hash, Path: prefix}
}

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *Trie) Hash() common.Hash {
	hash, cached, _ := t.hashRoot(nil)
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// Commit writes all nodes to the trie's memory database, tracking the internal
// and external (for account tries) references.
func (t *Trie) Commit(onleaf LeafCallback) (root common.Hash, err error) {
	if t.db == nil {
		panic("commit called on trie with nil database")
	}
	if t.root == nil {
		return emptyRoot, nil
	}
	rootHash := t.Hash()
	h := newCommitter()
	defer returnCommitterToPool(h)
	// Do a quick check if we really need to commit, before we spin
	// up goroutines. This can happen e.g. if we load a trie for reading storage
	// values, but don't write to it.
	if !h.commitNeeded(t.root) {
		return rootHash, nil
	}
	var wg sync.WaitGroup
	if onleaf != nil {
		h.onleaf = onleaf
		h.leafCh = make(chan *leaf, leafChanSize)
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.commitLoop(t.db)
		}()
	}
	var newRoot hashNode
	newRoot, err = h.Commit(t.root, t.db)
	if onleaf != nil {
		// The leafch is created in newCommitter if there was an onleaf callback
		// provided. The commitLoop only _reads_ from it, and the commit
		// operation was the sole writer. Therefore, it's safe to close this
		// channel here.
		close(h.leafCh)
		wg.Wait()
	}
	if err != nil {
		return common.Hash{}, err
	}
	t.root = newRoot
	return rootHash, nil
}

// hashRoot calculates the root hash of the given trie
func (t *Trie) hashRoot(db *Database) (node, node, error) {
	if t.root == nil {
		return hashNode(emptyRoot.Bytes()), nil, nil
	}
	// If the number of changes is below 100, we let one thread handle it
	h := newHasher(t.unhashed >= 100)
	defer returnHasherToPool(h)
	hashed, cached := h.hash(t.root, true)
	t.unhashed = 0
	return hashed, cached, nil
}

// Reset drops the referenced root node and cleans all internal state.
func (t *Trie) Reset() {
	t.root = nil
	t.unhashed = 0
}
