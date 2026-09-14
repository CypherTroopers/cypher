// Copyright 2017 The go-ethereum Authors
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

package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
)

// errNoActiveJournal is returned if a transaction is attempted to be inserted
// into the journal, but no such file is currently open.
var errNoActiveJournal = errors.New("no active journal")
var errJournalQueueFull = errors.New("transaction journal queue is full")

const (
	txJournalBatchSize             = 512
	txJournalBatchBytes            = 16 * 1024 * 1024
	txJournalFlushInterval         = 2 * time.Millisecond
	txJournalMaxQueuedTransactions = 1_048_576
)

// devNull is a WriteCloser that just discards anything written into it. Its
// goal is to allow the transaction journal to write into a fake journal when
// loading transactions on startup without printing warnings due to no file
// being read for write.
type devNull struct{}

func (*devNull) Write(p []byte) (n int, err error) { return len(p), nil }
func (*devNull) Close() error                      { return nil }

// txJournal is a rotating log of transactions with the aim of storing locally
// created transactions to allow non-executed ones to survive node restarts.
type txJournal struct {
	path   string         // Filesystem path to store the transactions at
	writer io.WriteCloser // Output stream to write new transactions into
}

type txJournalCommandKind uint8

const (
	txJournalAppend txJournalCommandKind = iota
	txJournalRotate
)

type txJournalCommand struct {
	kind txJournalCommandKind
	txs  types.Transactions
	all  map[common.Address]types.Transactions
	done chan struct{}
}

// txJournalWriter owns all live journal I/O. TxPool mutations enqueue pointer
// batches in a non-blocking command queue while holding pool.mu. Rotations use
// that same queue, so an append can never be truncated behind its snapshot.
type txJournalWriter struct {
	journal *txJournal

	queueMu   sync.Mutex
	queue     []txJournalCommand
	queued    int
	maxQueued int
	notify    chan struct{}
	closed    bool
	wg        sync.WaitGroup

	errMu sync.Mutex
	err   error
}

func newTxJournalWriter(journal *txJournal) *txJournalWriter {
	w := &txJournalWriter{
		journal:   journal,
		notify:    make(chan struct{}, 1),
		maxQueued: txJournalMaxQueuedTransactions,
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

func (w *txJournalWriter) enqueue(txs types.Transactions, wait bool) (<-chan struct{}, error) {
	if w == nil || len(txs) == 0 {
		return nil, nil
	}
	batch := append(types.Transactions(nil), txs...)
	command := txJournalCommand{kind: txJournalAppend, txs: batch}
	if wait {
		command.done = make(chan struct{})
	}
	if err := w.send(command); err != nil {
		return nil, err
	}
	return command.done, nil
}

func (w *txJournalWriter) rotate(all map[common.Address]types.Transactions) error {
	if w == nil {
		return nil
	}
	return w.send(txJournalCommand{kind: txJournalRotate, all: all})
}

func (w *txJournalWriter) send(command txJournalCommand) error {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	if w.closed {
		return errNoActiveJournal
	}
	commandTransactions := len(command.txs)
	if command.kind == txJournalRotate {
		for _, txs := range command.all {
			commandTransactions += len(txs)
		}
	}
	// Keep journal I/O off pool.mu without allowing a disk stall to turn the
	// pointer queue into an unbounded memory sink. The outbox is the durable
	// common-ingress boundary; this queue remains a bounded secondary copy.
	maxQueued := w.maxQueued
	if maxQueued <= 0 {
		maxQueued = txJournalMaxQueuedTransactions
	}
	if commandTransactions > maxQueued-w.queued {
		return errJournalQueueFull
	}
	const maxCoalescedJournalTransactions = 16 * 1024
	if command.kind == txJournalAppend && command.done == nil && len(w.queue) > 0 {
		last := &w.queue[len(w.queue)-1]
		if last.kind == txJournalAppend && last.done == nil && len(last.txs)+len(command.txs) <= maxCoalescedJournalTransactions {
			last.txs = append(last.txs, command.txs...)
			w.queued += commandTransactions
			w.signal()
			return nil
		}
	}
	w.queue = append(w.queue, command)
	w.queued += commandTransactions
	w.signal()
	return nil
}

func (w *txJournalWriter) close() error {
	if w == nil {
		return nil
	}
	w.queueMu.Lock()
	if !w.closed {
		w.closed = true
	}
	w.queueMu.Unlock()
	w.signal()
	w.wg.Wait()
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.err
}

func (w *txJournalWriter) recordError(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.errMu.Unlock()
}

func (w *txJournalWriter) loop() {
	defer w.wg.Done()
	ticker := time.NewTicker(txJournalFlushInterval)
	defer ticker.Stop()

	pending := make(types.Transactions, 0, txJournalBatchSize)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		err := w.journal.insertBatch(pending)
		if err != nil {
			w.recordError(err)
			log.Warn("Failed to journal local transaction batch", "transactions", len(pending), "err", err)
		}
		for i := range pending {
			pending[i] = nil
		}
		pending = pending[:0]
		return err
	}
	appendAsync := func(txs types.Transactions) {
		for len(txs) > 0 {
			available := txJournalBatchSize - len(pending)
			if available > len(txs) {
				available = len(txs)
			}
			pending = append(pending, txs[:available]...)
			txs = txs[available:]
			if len(pending) == txJournalBatchSize {
				flush()
			}
		}
	}
	writeCommand := func(command txJournalCommand) {
		switch command.kind {
		case txJournalAppend:
			if command.done == nil {
				appendAsync(command.txs)
				return
			}
			// Preserve AddLocal/AddLocals' historical journal-before-return
			// behavior. Async/outbox-backed additions still group for 2ms.
			flush()
			for len(command.txs) > 0 {
				count := txJournalBatchSize
				if count > len(command.txs) {
					count = len(command.txs)
				}
				if err := w.journal.insertBatch(command.txs[:count]); err != nil {
					w.recordError(err)
					log.Warn("Failed to journal local transaction batch", "transactions", count, "err", err)
				}
				command.txs = command.txs[count:]
			}
			close(command.done)
		case txJournalRotate:
			flush()
			if err := w.journal.rotate(command.all); err != nil {
				w.recordError(err)
				log.Warn("Failed to rotate local tx journal", "err", err)
			}
		}
	}
	drain := func() (closed bool) {
		w.queueMu.Lock()
		commands := w.queue
		w.queue = nil
		w.queued = 0
		closed = w.closed
		w.queueMu.Unlock()
		for _, command := range commands {
			writeCommand(command)
		}
		return closed
	}
	for {
		select {
		case <-w.notify:
			if drain() {
				flush()
				if err := w.journal.close(); err != nil {
					w.recordError(err)
				}
				return
			}
		case <-ticker.C:
			drain()
			flush()
		}
	}
}

func (w *txJournalWriter) signal() {
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// newTxJournal creates a new transaction journal to
func newTxJournal(path string) *txJournal {
	return &txJournal{
		path: path,
	}
}

// load parses a transaction journal dump from disk, loading its contents into
// the specified pool.
func (journal *txJournal) load(add func([]*types.Transaction) []error) error {
	// Skip the parsing if the journal file doesn't exist at all
	if _, err := os.Stat(journal.path); os.IsNotExist(err) {
		return nil
	}
	// Open the journal for loading any past transactions
	input, err := os.Open(journal.path)
	if err != nil {
		return err
	}
	defer input.Close()

	// Temporarily discard any journal additions (don't double add on load)
	journal.writer = new(devNull)
	defer func() { journal.writer = nil }()

	// Inject all transactions from the journal into the pool
	stream := rlp.NewStream(input, 0)
	total, dropped := 0, 0

	// Create a method to load a limited batch of transactions and bump the
	// appropriate progress counters. Then use this method to load all the
	// journaled transactions in small-ish batches.
	loadBatch := func(txs types.Transactions) {
		for _, err := range add(txs) {
			if err != nil {
				log.Debug("Failed to add journaled transaction", "err", err)
				dropped++
			}
		}
	}
	var (
		failure    error
		batch      types.Transactions
		batchBytes int
	)
	for {
		// Journal records contain the pooled EIP-2718 envelope as an RLP byte
		// string. This is significant for type-3 transactions: their execution
		// encoding deliberately omits the blobs, commitments, and proofs needed
		// to re-admit the transaction after restart.
		payload, decodeErr := stream.Bytes()
		if decodeErr != nil {
			if decodeErr != io.EOF {
				failure = decodeErr
			}
			if batch.Len() > 0 {
				loadBatch(batch)
			}
			break
		}
		tx := new(types.Transaction)
		if decodeErr = tx.UnmarshalBinary(payload); decodeErr != nil {
			failure = decodeErr
			if batch.Len() > 0 {
				loadBatch(batch)
			}
			break
		}
		// New transaction parsed, queue up for later, import if threshold is reached
		total++

		batch = append(batch, tx)
		batchBytes += len(payload)
		if batch.Len() >= txJournalBatchSize || batchBytes >= txJournalBatchBytes {
			loadBatch(batch)
			batch = batch[:0]
			batchBytes = 0
		}
	}
	log.Info("Loaded local transaction journal", "transactions", total, "dropped", dropped)

	return failure
}

// insert adds the specified transaction to the local disk journal.
func (journal *txJournal) insert(tx *types.Transaction) error {
	return journal.insertBatch(types.Transactions{tx})
}

// insertBatch writes pooled transaction envelopes to the live append-only
// journal. Writes are byte-bounded so a full batch of large type-3 sidecars
// cannot require hundreds of MiB of transient contiguous memory.
func (journal *txJournal) insertBatch(txs types.Transactions) error {
	if journal.writer == nil {
		return errNoActiveJournal
	}
	return writeJournalTransactions(journal.writer, txs)
}

func writeJournalTransactions(writer io.Writer, txs types.Transactions) error {
	var encoded bytes.Buffer
	writeEncoded := func() error {
		payload := encoded.Bytes()
		for len(payload) > 0 {
			n, err := writer.Write(payload)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			payload = payload[n:]
		}
		encoded.Reset()
		return nil
	}
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		pooled, err := tx.MarshalPooledBinary()
		if err != nil {
			return err
		}
		record, err := rlp.EncodeToBytes(pooled)
		if err != nil {
			return err
		}
		if encoded.Len() > 0 && encoded.Len()+len(record) > txJournalBatchBytes {
			if err := writeEncoded(); err != nil {
				return err
			}
		}
		if len(record) > txJournalBatchBytes {
			for len(record) > 0 {
				n, err := writer.Write(record)
				if err != nil {
					return err
				}
				if n == 0 {
					return io.ErrShortWrite
				}
				record = record[n:]
			}
			continue
		}
		_, _ = encoded.Write(record)
	}
	return writeEncoded()
}

// rotate regenerates the transaction journal based on the current contents of
// the transaction pool.
func (journal *txJournal) rotate(all map[common.Address]types.Transactions) error {
	// Close the current journal (if any is open)
	if journal.writer != nil {
		if err := journal.writer.Close(); err != nil {
			return err
		}
		journal.writer = nil
	}
	// Generate a new journal with the contents of the current pool
	replacement, err := os.OpenFile(journal.path+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	journaled := 0
	for _, txs := range all {
		if err = writeJournalTransactions(replacement, txs); err != nil {
			replacement.Close()
			return err
		}
		journaled += len(txs)
	}
	replacement.Close()

	// Replace the live journal with the newly generated one
	if err = os.Rename(journal.path+".new", journal.path); err != nil {
		return err
	}
	sink, err := os.OpenFile(journal.path, os.O_WRONLY|os.O_APPEND, 0755)
	if err != nil {
		return err
	}
	journal.writer = sink
	log.Info("Regenerated local transaction journal", "transactions", journaled, "accounts", len(all))

	return nil
}

// close flushes the transaction journal contents to disk and closes the file.
func (journal *txJournal) close() error {
	var err error

	if journal.writer != nil {
		err = journal.writer.Close()
		journal.writer = nil
	}
	return err
}
