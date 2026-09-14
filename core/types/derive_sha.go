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

package types

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rlp"
)

const (
	// Small lists are faster through the allocation-light serial path. Above this
	// boundary, leaf encoding is large enough to amortize the mutation table and
	// bounded worker startup used by the trie batch path.
	deriveShaParallelThreshold = 128
	deriveShaMaxWorkers        = 64
	deriveShaEncodeChunk       = 32
)

// DerivableList is the interface which can derive the hash.
type DerivableList interface {
	Len() int
	GetRlp(i int) []byte
}

// Hasher is the tool used to calculate the hash of derivable list.
type Hasher interface {
	Reset()
	Update([]byte, []byte)
	Hash() common.Hash
}

func DeriveSha(list DerivableList, hasher Hasher) common.Hash {
	workers := runtime.GOMAXPROCS(0)
	if workers > deriveShaMaxWorkers {
		workers = deriveShaMaxWorkers
	}
	return deriveShaWithWorkers(list, hasher, workers)
}

// DeriveShaFromEncoded derives a consensus list root from leaf values that the
// caller has already encoded. Native block validation uses this to share the
// potentially large receipt encodings between its byte-envelope check and the
// receipt trie instead of serializing every receipt twice.
//
// The caller retains ownership of values and must not mutate them until this
// function returns.
func DeriveShaFromEncoded(values [][]byte, hasher Hasher) common.Hash {
	workers := runtime.GOMAXPROCS(0)
	if workers > deriveShaMaxWorkers {
		workers = deriveShaMaxWorkers
	}
	if workers > len(values) {
		workers = len(values)
	}
	hasher.Reset()
	batch, parallel := hasher.(deriveShaBatchHasher)
	if len(values) < deriveShaParallelThreshold || workers <= 1 || !parallel {
		return deriveShaEncodedSerial(values, hasher)
	}
	keys := encodeDeriveShaKeys(len(values), workers)
	if err := batch.TryUpdateKeyValueBatch(keys, values, workers); err != nil {
		hasher.Reset()
		for index := range keys {
			hasher.Update(keys[index], values[index])
		}
	}
	return hasher.Hash()
}

// deriveShaBatchHasher is deliberately optional so existing Hasher
// implementations and the public DerivableList contract remain unchanged.
// The consensus trie implements this without making types depend on trie.
type deriveShaBatchHasher interface {
	TryUpdateKeyValueBatch(keys, values [][]byte, workers int) error
}

func deriveShaWithWorkers(list DerivableList, hasher Hasher, workers int) common.Hash {
	hasher.Reset()
	if list.Len() < deriveShaParallelThreshold || workers <= 1 || !parallelDeriveShaList(list) {
		return deriveShaSerial(list, hasher)
	}
	batch, ok := hasher.(deriveShaBatchHasher)
	if !ok {
		return deriveShaSerial(list, hasher)
	}
	if workers > deriveShaMaxWorkers {
		workers = deriveShaMaxWorkers
	}
	if workers > list.Len() {
		workers = list.Len()
	}
	keys, values := encodeDeriveShaLeaves(list, workers)
	if err := batch.TryUpdateKeyValueBatch(keys, values, workers); err != nil {
		// TryUpdateBatch is atomic, so resetting and replaying the already encoded
		// leaves preserves the historical best-effort Hasher contract without a
		// second MarshalBinary pass.
		hasher.Reset()
		for index := range keys {
			hasher.Update(keys[index], values[index])
		}
	}
	return hasher.Hash()
}

// Only the two consensus list implementations are known to permit concurrent
// GetRlp calls. Custom DerivableList implementations retain serial behavior.
func parallelDeriveShaList(list DerivableList) bool {
	switch list.(type) {
	case Transactions, *Transactions, Receipts, *Receipts:
		return true
	default:
		return false
	}
}

func deriveShaSerial(list DerivableList, hasher Hasher) common.Hash {
	keybuf := new(bytes.Buffer)
	for i := 0; i < list.Len(); i++ {
		keybuf.Reset()
		rlp.Encode(keybuf, uint(i))
		hasher.Update(keybuf.Bytes(), list.GetRlp(i))
	}
	return hasher.Hash()
}

func deriveShaEncodedSerial(values [][]byte, hasher Hasher) common.Hash {
	keybuf := new(bytes.Buffer)
	for index, value := range values {
		keybuf.Reset()
		rlp.Encode(keybuf, uint(index))
		hasher.Update(keybuf.Bytes(), value)
	}
	return hasher.Hash()
}

func encodeDeriveShaKeys(count, workers int) [][]byte {
	keys := make([][]byte, count)
	var next atomic.Uint64
	encode := func() {
		for {
			start := int(next.Add(deriveShaEncodeChunk) - deriveShaEncodeChunk)
			if start >= len(keys) {
				return
			}
			end := start + deriveShaEncodeChunk
			if end > len(keys) {
				end = len(keys)
			}
			for index := start; index < end; index++ {
				key, err := rlp.EncodeToBytes(uint(index))
				if err != nil {
					panic(err)
				}
				keys[index] = key
			}
		}
	}
	var group sync.WaitGroup
	group.Add(workers - 1)
	for worker := 1; worker < workers; worker++ {
		go func() {
			defer group.Done()
			encode()
		}()
	}
	encode()
	group.Wait()
	return keys
}

// encodeDeriveShaLeaves encodes every trie key and value exactly once. Work
// is claimed in small atomic chunks so differently sized transactions cannot
// pin one static worker shard while worker creation remains strictly bounded.
func encodeDeriveShaLeaves(list DerivableList, workers int) ([][]byte, [][]byte) {
	keys := make([][]byte, list.Len())
	values := make([][]byte, list.Len())
	var next atomic.Uint64
	encode := func() {
		for {
			start := int(next.Add(deriveShaEncodeChunk) - deriveShaEncodeChunk)
			if start >= len(keys) {
				return
			}
			end := start + deriveShaEncodeChunk
			if end > len(keys) {
				end = len(keys)
			}
			for index := start; index < end; index++ {
				key, err := rlp.EncodeToBytes(uint(index))
				if err != nil {
					// Encoding a Go unsigned integer cannot fail. Keep the same
					// fail-fast behavior as a malformed consensus leaf encoder.
					panic(err)
				}
				keys[index] = key
				values[index] = list.GetRlp(index)
			}
		}
	}

	var group sync.WaitGroup
	group.Add(workers - 1)
	for worker := 1; worker < workers; worker++ {
		go func() {
			defer group.Done()
			encode()
		}()
	}
	encode()
	group.Wait()
	return keys, values
}
