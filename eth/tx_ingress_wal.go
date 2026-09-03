package eth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/rlp"
)

// txIngressWAL is the single durability boundary for transaction ingress. The
// older ingress/outbox databases are retained as rebuildable materialized
// indexes; an RPC success, pool publication, or network ACK must never depend
// on an index write that is not preceded by one of these fsynced records.
//
// Records are immutable and chained. Only the small tail pointer is replaced.
// Event indexes make retries idempotent without rewriting prior records.
const txIngressWALVersion uint16 = 1

type txIngressWALEventKind uint8

const (
	txIngressWALInboundReceived txIngressWALEventKind = iota + 1
	txIngressWALInboundOutcome
	txIngressWALLocalIntent
	txIngressWALLocalOutcome
	txIngressWALOutboxEnqueued
	txIngressWALOutboxState
	txIngressWALOutboxDeleted
	txIngressWALOutboxNonce
	txIngressWALInboundApplied
	txIngressWALOutboxApplied
)

var (
	txIngressWALIdentityKey      = []byte("cypher-ingress-wal/identity")
	txIngressWALManifestKey      = []byte("cypher-ingress-wal/manifest")
	txIngressWALTailKey          = []byte("cypher-ingress-wal/tail")
	txIngressWALRecordPrefix     = []byte("cypher-ingress-wal/record/")
	txIngressWALEventPrefix      = []byte("cypher-ingress-wal/event/")
	txIngressWALGenerationPrefix = []byte("cypher-ingress-wal/generation/")
)

type txIngressWALIdentity struct {
	Version     uint16
	ChainID     uint64
	GenesisHash common.Hash
}

type txIngressWALTail struct {
	Sequence uint64
	Digest   common.Hash
}

type txIngressWALManifest struct {
	Version    uint16
	Generation uint64
}

type txIngressWALFrame struct {
	Version  uint16
	Sequence uint64
	Previous common.Hash
	Kind     txIngressWALEventKind
	BatchID  common.Hash
	EventID  common.Hash
	Payload  []byte
	Checksum common.Hash
}

type txIngressWALFrameCommitment struct {
	Version  uint16
	Sequence uint64
	Previous common.Hash
	Kind     txIngressWALEventKind
	BatchID  common.Hash
	EventID  common.Hash
	Payload  []byte
}

type txIngressWALAppendRequest struct {
	kind    txIngressWALEventKind
	batchID common.Hash
	eventID common.Hash
	payload []byte
	bytes   int64
	result  chan txIngressWALAppendResult
}

type txIngressWALAppendResult struct {
	sequence uint64
	err      error
}

type txIngressWAL struct {
	db       ethdb.KeyValueStore
	identity txIngressWALIdentity

	lookupMu    sync.RWMutex
	finalizedTx func(common.Hash) bool
	obsoleteTxs func(types.Transactions) []bool

	maxRecords     int
	maxBytes       int64
	interval       time.Duration
	maxGroup       int
	maxGroupBytes  int64
	appendCh       chan *txIngressWALAppendRequest
	compactCh      chan struct{}
	compactMu      sync.Mutex
	operationMu    sync.Mutex
	operationSeed  common.Hash
	operationNonce uint64
	admissionMu    sync.Mutex
	appendClosed   bool
	appendDone     <-chan struct{}
	appenders      int
	appendersDone  chan struct{}
	stopStarted    bool
	stopDone       chan struct{}

	mu                  sync.Mutex
	started             bool
	stopped             bool
	poison              error
	generation          uint64
	sequence            uint64
	digest              common.Hash
	records             int
	bytes               int64
	sinceCompactRecords int
	sinceCompactBytes   int64
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
}

func (w *txIngressWAL) setTransactionLookups(finalized func(common.Hash) bool, obsolete func(types.Transactions) []bool) {
	if w == nil {
		return
	}
	w.lookupMu.Lock()
	w.finalizedTx = finalized
	w.obsoleteTxs = obsolete
	w.lookupMu.Unlock()
}

// recoverableLocalItems identifies accepted local transactions which must stay
// in the unified WAL until FHS finality (or a canonically consumed nonce) makes
// replay unnecessary. Callback failures are treated conservatively as pending.
func (w *txIngressWAL) recoverableLocalItems(items []*txQUICItem) []bool {
	recoverable := make([]bool, len(items))
	txs := make(types.Transactions, len(items))
	for index, item := range items {
		if item != nil && item.Tx != nil {
			txs[index] = item.Tx
			recoverable[index] = true
		}
	}
	w.lookupMu.RLock()
	finalized, obsolete := w.finalizedTx, w.obsoleteTxs
	w.lookupMu.RUnlock()
	obsoleteResults := []bool(nil)
	if obsolete != nil {
		if resolved := obsolete(txs); len(resolved) == len(txs) {
			obsoleteResults = resolved
		}
	}
	for index, tx := range txs {
		if tx == nil {
			continue
		}
		if finalized != nil && finalized(tx.Hash()) {
			recoverable[index] = false
			continue
		}
		if obsoleteResults != nil && obsoleteResults[index] {
			recoverable[index] = false
		}
	}
	return recoverable
}

func newTxIngressWAL(db ethdb.KeyValueStore, config TxQUICConfig) *txIngressWAL {
	applyTxQUICDefaults(&config)
	maxRecords := config.OutboxMaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultTxOutboxMaxRecords
	}
	maxBytes := config.OutboxMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultTxOutboxMaxBytes
	}
	queue := minPositiveInt(config.IngressCommitMaxRequests, txQUICMaxCommitRequests) * 4
	return &txIngressWAL{
		db:         db,
		identity:   txIngressWALIdentity{Version: txIngressWALVersion, ChainID: config.ChainID, GenesisHash: config.GenesisHash},
		maxRecords: maxRecords, maxBytes: maxBytes,
		interval: config.IngressCommitInterval, maxGroup: config.IngressCommitMaxRequests, maxGroupBytes: config.IngressCommitMaxBytes,
		appendCh:     make(chan *txIngressWALAppendRequest, queue),
		compactCh:    make(chan struct{}, 1),
		appendClosed: true,
		stopDone:     make(chan struct{}),
	}
}

func txIngressWALRecordKey(sequence uint64) []byte {
	return txIngressWALRecordKeyForGeneration(0, sequence)
}

func txIngressWALGenerationBase(generation uint64) []byte {
	key := make([]byte, len(txIngressWALGenerationPrefix)+8+1)
	copy(key, txIngressWALGenerationPrefix)
	binary.BigEndian.PutUint64(key[len(txIngressWALGenerationPrefix):], generation)
	key[len(key)-1] = '/'
	return key
}

func txIngressWALRecordPrefixForGeneration(generation uint64) []byte {
	if generation == 0 {
		return txIngressWALRecordPrefix
	}
	return append(txIngressWALGenerationBase(generation), []byte("record/")...)
}

func txIngressWALEventPrefixForGeneration(generation uint64) []byte {
	if generation == 0 {
		return txIngressWALEventPrefix
	}
	return append(txIngressWALGenerationBase(generation), []byte("event/")...)
}

func txIngressWALTailKeyForGeneration(generation uint64) []byte {
	if generation == 0 {
		return txIngressWALTailKey
	}
	return append(txIngressWALGenerationBase(generation), []byte("tail")...)
}

func txIngressWALRecordKeyForGeneration(generation, sequence uint64) []byte {
	prefix := txIngressWALRecordPrefixForGeneration(generation)
	key := make([]byte, len(prefix)+8)
	copy(key, prefix)
	binary.BigEndian.PutUint64(key[len(prefix):], sequence)
	return key
}

func txIngressWALEventKey(eventID common.Hash) []byte {
	return txIngressWALEventKeyForGeneration(0, eventID)

}

func txIngressWALEventKeyForGeneration(generation uint64, eventID common.Hash) []byte {
	prefix := txIngressWALEventPrefixForGeneration(generation)
	key := make([]byte, len(prefix)+common.HashLength)
	copy(key, prefix)
	copy(key[len(prefix):], eventID[:])
	return key
}

func txIngressWALFrameDigest(frame *txIngressWALFrame) (common.Hash, error) {
	if frame == nil {
		return common.Hash{}, errors.New("nil ingress WAL frame")
	}
	encoded, err := rlp.EncodeToBytes(&txIngressWALFrameCommitment{
		Version: frame.Version, Sequence: frame.Sequence, Previous: frame.Previous,
		Kind: frame.Kind, BatchID: frame.BatchID, EventID: frame.EventID, Payload: frame.Payload,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

func encodeTxIngressWALFrame(frame *txIngressWALFrame) ([]byte, error) {
	digest, err := txIngressWALFrameDigest(frame)
	if err != nil {
		return nil, err
	}
	frame.Checksum = digest
	return rlp.EncodeToBytes(frame)
}

func decodeTxIngressWALFrame(generation uint64, key, encoded []byte, expectedSequence uint64, previous common.Hash) (*txIngressWALFrame, error) {
	prefix := txIngressWALRecordPrefixForGeneration(generation)
	if len(key) != len(prefix)+8 || !bytes.HasPrefix(key, prefix) {
		return nil, fmt.Errorf("invalid ingress WAL record key")
	}
	keySequence := binary.BigEndian.Uint64(key[len(prefix):])
	var frame txIngressWALFrame
	if err := rlp.DecodeBytes(encoded, &frame); err != nil {
		return nil, fmt.Errorf("decode ingress WAL record %d: %w", keySequence, err)
	}
	if frame.Version != txIngressWALVersion || frame.Sequence != keySequence || frame.Sequence != expectedSequence ||
		frame.Previous != previous || frame.Kind < txIngressWALInboundReceived || frame.Kind > txIngressWALOutboxApplied ||
		frame.BatchID == (common.Hash{}) || frame.EventID == (common.Hash{}) || len(frame.Payload) == 0 {
		return nil, fmt.Errorf("invalid ingress WAL record %d", keySequence)
	}
	digest, err := txIngressWALFrameDigest(&frame)
	if err != nil {
		return nil, err
	}
	if digest != frame.Checksum {
		return nil, fmt.Errorf("ingress WAL checksum mismatch at record %d", keySequence)
	}
	return &frame, nil
}

func (w *txIngressWAL) Start(parent context.Context) error {
	if w == nil || w.db == nil {
		return errors.New("ingress WAL database is unavailable")
	}
	if w.identity.Version != txIngressWALVersion || w.identity.ChainID == 0 || w.identity.GenesisHash == (common.Hash{}) {
		return errors.New("invalid ingress WAL chain identity")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.stopped {
		return errors.New("ingress WAL cannot be started")
	}
	if err := w.ensureIdentityLocked(); err != nil {
		return err
	}
	if err := w.ensureManifestLocked(); err != nil {
		return err
	}
	if err := w.recoverLocked(); err != nil {
		return err
	}
	var generation, sequence [8]byte
	binary.BigEndian.PutUint64(generation[:], w.generation)
	binary.BigEndian.PutUint64(sequence[:], w.sequence)
	w.operationMu.Lock()
	w.operationSeed = crypto.Keccak256Hash(
		[]byte("CPH_INGRESS_WAL_OPERATION_SEED_V1"),
		w.identity.GenesisHash[:], generation[:], sequence[:], w.digest[:],
	)
	w.operationNonce = 0
	w.operationMu.Unlock()
	if parent == nil {
		parent = context.Background()
	}
	w.ctx, w.cancel = context.WithCancel(parent)
	w.admissionMu.Lock()
	if w.stopStarted {
		w.admissionMu.Unlock()
		w.cancel()
		return errors.New("ingress WAL cannot be started during shutdown")
	}
	w.appendClosed = false
	w.appendDone = w.ctx.Done()
	w.admissionMu.Unlock()
	w.started = true
	w.wg.Add(2)
	go w.commitLoop()
	go w.compactLoop()
	return nil
}

func (w *txIngressWAL) ensureManifestLocked() error {
	has, err := w.db.Has(txIngressWALManifestKey)
	if err != nil {
		return err
	}
	if has {
		raw, err := w.db.Get(txIngressWALManifestKey)
		if err != nil {
			return err
		}
		var manifest txIngressWALManifest
		if decodeErr := rlp.DecodeBytes(raw, &manifest); decodeErr != nil || manifest.Version != txIngressWALVersion {
			return errors.New("invalid ingress WAL generation manifest")
		}
		w.generation = manifest.Generation
		return nil
	}
	manifest := txIngressWALManifest{Version: txIngressWALVersion, Generation: 0}
	encoded, encodeErr := rlp.EncodeToBytes(&manifest)
	if encodeErr != nil {
		return encodeErr
	}
	batch := w.db.NewBatch()
	if putErr := batch.Put(txIngressWALManifestKey, encoded); putErr != nil {
		return putErr
	}
	if writeErr := writeTxIngressWALSync(batch, "persist ingress WAL generation manifest"); writeErr != nil {
		return writeErr
	}
	w.generation = 0
	return nil
}

func (w *txIngressWAL) ensureIdentityLocked() error {
	has, err := w.db.Has(txIngressWALIdentityKey)
	if err != nil {
		return err
	}
	if has {
		raw, err := w.db.Get(txIngressWALIdentityKey)
		if err != nil {
			return err
		}
		var stored txIngressWALIdentity
		if err := rlp.DecodeBytes(raw, &stored); err != nil || stored != w.identity {
			return errors.New("ingress WAL belongs to a different or obsolete chain")
		}
		return nil
	}
	raw, err := rlp.EncodeToBytes(&w.identity)
	if err != nil {
		return err
	}
	batch := w.db.NewBatch()
	if err := batch.Put(txIngressWALIdentityKey, raw); err != nil {
		return err
	}
	return writeTxIngressWALSync(batch, "persist ingress WAL identity")
}

func writeTxIngressWALSync(batch ethdb.Batch, operation string) error {
	syncBatch, ok := batch.(ethdb.SyncBatch)
	if !ok {
		return fmt.Errorf("%s: database does not support synchronous batches", operation)
	}
	if err := syncBatch.WriteSync(); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

// recoverLocked validates the hash chain and repairs only a terminal torn
// record/tail. Corruption before the final record is never silently skipped.
func (w *txIngressWAL) recoverLocked() error {
	recordPrefix := txIngressWALRecordPrefixForGeneration(w.generation)
	tailKey := txIngressWALTailKeyForGeneration(w.generation)
	iterator := w.db.NewIterator(recordPrefix, nil)
	defer iterator.Release()
	var (
		expected                 uint64 = 1
		previous                 common.Hash
		records                  int
		totalBytes               int64
		pendingKey, pendingValue []byte
	)
	consume := func(key, value []byte, terminal bool) error {
		if len(key) != len(recordPrefix)+8 || binary.BigEndian.Uint64(key[len(recordPrefix):]) != expected {
			return fmt.Errorf("non-contiguous ingress WAL sequence: want=%d", expected)
		}
		frame, err := decodeTxIngressWALFrame(w.generation, key, value, expected, previous)
		if err != nil {
			if !terminal {
				return err
			}
			return w.truncateTornTailLocked(key, expected-1, previous)
		}
		recordBytes := int64(len(key) + len(value) + len(txIngressWALEventKeyForGeneration(w.generation, frame.EventID)) + 8)
		if records >= w.maxRecords || totalBytes > w.maxBytes-recordBytes {
			return fmt.Errorf("ingress WAL capacity exceeded during recovery: records=%d/%d bytes=%d+%d/%d", records, w.maxRecords, totalBytes, recordBytes, w.maxBytes)
		}
		mapped, err := w.db.Get(txIngressWALEventKeyForGeneration(w.generation, frame.EventID))
		if err != nil || len(mapped) != 8 || binary.BigEndian.Uint64(mapped) != frame.Sequence {
			return fmt.Errorf("ingress WAL event index mismatch at record %d", frame.Sequence)
		}
		records++
		totalBytes += recordBytes
		expected++
		previous = frame.Checksum
		return nil
	}
	for iterator.Next() {
		if pendingKey != nil {
			if err := consume(pendingKey, pendingValue, false); err != nil {
				return err
			}
		}
		pendingKey = append(pendingKey[:0], iterator.Key()...)
		pendingValue = append(pendingValue[:0], iterator.Value()...)
	}
	if err := iterator.Error(); err != nil {
		return err
	}
	if pendingKey != nil {
		before := expected
		if err := consume(pendingKey, pendingValue, true); err != nil {
			return err
		}
		// A terminal torn record was removed and did not advance expected.
		if expected == before {
			pendingKey = nil
		}
	}
	tail := txIngressWALTail{Sequence: expected - 1, Digest: previous}
	rawTail, err := w.db.Get(tailKey)
	if err == nil {
		var stored txIngressWALTail
		if decodeErr := rlp.DecodeBytes(rawTail, &stored); decodeErr == nil && stored == tail {
			w.sequence, w.digest, w.records, w.bytes = tail.Sequence, tail.Digest, records, totalBytes
			if w.generation == 0 {
				w.sinceCompactRecords, w.sinceCompactBytes = records, totalBytes
			}
			return nil
		}
	}
	encodedTail, err := rlp.EncodeToBytes(&tail)
	if err != nil {
		return err
	}
	batch := w.db.NewBatch()
	if err := batch.Put(tailKey, encodedTail); err != nil {
		return err
	}
	if err := writeTxIngressWALSync(batch, "repair ingress WAL tail"); err != nil {
		return err
	}
	w.sequence, w.digest, w.records, w.bytes = tail.Sequence, tail.Digest, records, totalBytes
	if w.generation == 0 {
		w.sinceCompactRecords, w.sinceCompactBytes = records, totalBytes
	}
	return nil
}

func (w *txIngressWAL) truncateTornTailLocked(key []byte, sequence uint64, digest common.Hash) error {
	batch := w.db.NewBatch()
	if err := batch.Delete(key); err != nil {
		return err
	}
	iterator := w.db.NewIterator(txIngressWALEventPrefixForGeneration(w.generation), nil)
	for iterator.Next() {
		value := iterator.Value()
		if len(value) == 8 && binary.BigEndian.Uint64(value) > sequence {
			if err := batch.Delete(append([]byte(nil), iterator.Key()...)); err != nil {
				iterator.Release()
				return err
			}
		}
	}
	iteratorErr := iterator.Error()
	iterator.Release()
	if iteratorErr != nil {
		return iteratorErr
	}
	encodedTail, err := rlp.EncodeToBytes(&txIngressWALTail{Sequence: sequence, Digest: digest})
	if err != nil {
		return err
	}
	if err := batch.Put(txIngressWALTailKeyForGeneration(w.generation), encodedTail); err != nil {
		return err
	}
	return writeTxIngressWALSync(batch, "truncate torn ingress WAL tail")
}

func (w *txIngressWAL) Stop() {
	if w == nil {
		return
	}
	w.admissionMu.Lock()
	if w.stopStarted {
		stopDone := w.stopDone
		w.admissionMu.Unlock()
		if stopDone != nil {
			<-stopDone
		}
		return
	}
	w.stopStarted = true
	appendersDone := w.closeAppendAdmissionLocked()
	stopDone := w.stopDone
	w.admissionMu.Unlock()
	w.mu.Lock()
	w.stopped = true
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if appendersDone != nil {
		<-appendersDone
	}
	w.wg.Wait()
	if stopDone != nil {
		close(stopDone)
	}
}

// beginAppend admits exactly the producers which may still enqueue into
// appendCh. Stop and the commit loop close this gate before their final drain;
// any producer that already crossed it is then waited out. This makes the
// buffered channel a bounded handoff rather than a place where a select can
// strand work after shutdown just because both send and ctx.Done were ready.
func (w *txIngressWAL) beginAppend() (<-chan struct{}, error) {
	w.admissionMu.Lock()
	if w.appendClosed || w.appendDone == nil {
		w.admissionMu.Unlock()
		return nil, errors.New("ingress WAL is not running")
	}
	w.appenders++
	done := w.appendDone
	w.admissionMu.Unlock()
	return done, nil
}

func (w *txIngressWAL) endAppend() {
	w.admissionMu.Lock()
	defer w.admissionMu.Unlock()
	if w.appenders < 1 {
		return
	}
	w.appenders--
	if w.appendClosed && w.appenders == 0 && w.appendersDone != nil {
		close(w.appendersDone)
		w.appendersDone = nil
	}
}

func (w *txIngressWAL) closeAppendAdmissionLocked() <-chan struct{} {
	w.appendClosed = true
	if w.appenders > 0 && w.appendersDone == nil {
		w.appendersDone = make(chan struct{})
	}
	return w.appendersDone
}

func (w *txIngressWAL) closeAppendAdmissionAndWait() {
	w.admissionMu.Lock()
	done := w.closeAppendAdmissionLocked()
	w.admissionMu.Unlock()
	if done != nil {
		<-done
	}
}

func (w *txIngressWAL) Append(ctx context.Context, kind txIngressWALEventKind, batchID, eventID common.Hash, payload []byte) (uint64, error) {
	if w == nil || w.db == nil {
		return 0, errors.New("ingress WAL is unavailable")
	}
	if kind < txIngressWALInboundReceived || kind > txIngressWALOutboxApplied || batchID == (common.Hash{}) || eventID == (common.Hash{}) || len(payload) == 0 {
		return 0, errors.New("invalid ingress WAL append")
	}
	requestBytes := int64(len(payload) + 256)
	if requestBytes > w.maxGroupBytes {
		return 0, fmt.Errorf("ingress WAL record exceeds group byte limit: bytes=%d limit=%d", requestBytes, w.maxGroupBytes)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request := &txIngressWALAppendRequest{
		kind: kind, batchID: batchID, eventID: eventID, payload: append([]byte(nil), payload...), bytes: requestBytes,
		result: make(chan txIngressWALAppendResult, 1),
	}
	storeDone, err := w.beginAppend()
	if err != nil {
		return 0, err
	}
	enqueued := false
	select {
	case w.appendCh <- request:
		enqueued = true
	case <-ctx.Done():
	case <-storeDone:
	}
	w.endAppend()
	if !enqueued {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("ingress WAL stopped before append")
	}
	select {
	case result := <-request.result:
		return result.sequence, result.err
	case <-ctx.Done():
		// Ownership transfers when queued; a retry is idempotent by EventID.
		return 0, ctx.Err()
	case <-storeDone:
		return 0, errors.New("ingress WAL stopped during append")
	}
}

func (w *txIngressWAL) runningErrLocked() error {
	if w.poison != nil {
		return fmt.Errorf("ingress WAL is poisoned until restart: %w", w.poison)
	}
	if !w.started || w.stopped || w.ctx == nil {
		return errors.New("ingress WAL is not running")
	}
	return nil
}

func (w *txIngressWAL) commitLoop() {
	defer w.wg.Done()
	var carry *txIngressWALAppendRequest
	for {
		first := carry
		carry = nil
		if first == nil {
			select {
			case <-w.ctx.Done():
				w.closeAppendAdmissionAndWait()
				w.failQueued(errors.New("ingress WAL stopped before append"))
				return
			case first = <-w.appendCh:
			}
		}
		if first == nil {
			continue
		}
		group := []*txIngressWALAppendRequest{first}
		bytesUsed := first.bytes
		timer := time.NewTimer(w.interval)
	collect:
		for len(group) < w.maxGroup {
			select {
			case request := <-w.appendCh:
				if request == nil {
					continue
				}
				if bytesUsed > w.maxGroupBytes-request.bytes {
					carry = request
					break collect
				}
				group = append(group, request)
				bytesUsed += request.bytes
			case <-timer.C:
				break collect
			case <-w.ctx.Done():
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		w.commit(group)
	}
}

func (w *txIngressWAL) failQueued(err error) {
	for {
		select {
		case request := <-w.appendCh:
			if request != nil {
				request.result <- txIngressWALAppendResult{err: err}
			}
		default:
			return
		}
	}
}

func (w *txIngressWAL) requestCompaction() {
	if w == nil || w.compactCh == nil {
		return
	}
	select {
	case w.compactCh <- struct{}{}:
	default:
	}
}

// compactLoop keeps expensive checkpoint construction off the single group
// commit loop. The signal is deliberately coalesced: the checkpoint catches
// every record committed before its final manifest handoff, so queuing one
// worker per threshold crossing would only create redundant generations.
func (w *txIngressWAL) compactLoop() {
	defer w.wg.Done()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.compactCh:
			_ = w.compactConditional(false, 0, nil)
		}
	}
}

func (w *txIngressWAL) commit(requests []*txIngressWALAppendRequest) {
	results := make([]txIngressWALAppendResult, len(requests))
	// Automatic checkpoints normally run in compactLoop and never occupy the
	// commit loop. If callers have consumed the entire hard capacity before that
	// background work can finish, apply backpressure here and wait for one
	// serialized checkpoint before retrying the group. This is an emergency
	// path for tiny configured limits, not the steady-state compaction path.
	w.mu.Lock()
	emergencyGeneration := w.generation
	emergency := w.runningErrLocked() == nil && w.capacityPressureLocked(requests)
	w.mu.Unlock()
	if emergency {
		if err := w.compactConditional(false, emergencyGeneration, requests); err != nil {
			for _, request := range requests {
				request.result <- txIngressWALAppendResult{err: err}
			}
			return
		}
	}
	w.mu.Lock()
	if err := w.runningErrLocked(); err != nil {
		w.mu.Unlock()
		for _, request := range requests {
			request.result <- txIngressWALAppendResult{err: err}
		}
		return
	}
	batch := w.db.NewBatch()
	sequence, previous := w.sequence, w.digest
	projectedRecords, projectedBytes := w.records, w.bytes
	staged := make(map[common.Hash]txIngressWALAppendResult)
	stagedRequests := make(map[common.Hash]*txIngressWALAppendRequest)
	newRecords := 0
	var fatalErr error
	capacityPressure := false
	for index, request := range requests {
		if duplicate, ok := staged[request.eventID]; ok {
			original := stagedRequests[request.eventID]
			if original == nil || original.kind != request.kind || original.batchID != request.batchID || !bytes.Equal(original.payload, request.payload) {
				results[index].err = fmt.Errorf("ingress WAL EventID collision for %s", request.eventID)
				continue
			}
			results[index] = duplicate
			continue
		}
		eventKey := txIngressWALEventKeyForGeneration(w.generation, request.eventID)
		hasEvent, err := w.db.Has(eventKey)
		if err != nil {
			fatalErr = fmt.Errorf("check ingress WAL event index: %w", err)
			break
		}
		if hasEvent {
			mapped, err := w.db.Get(eventKey)
			if err != nil {
				fatalErr = fmt.Errorf("read ingress WAL event index: %w", err)
				break
			}
			if len(mapped) != 8 {
				fatalErr = errors.New("invalid ingress WAL event index")
				break
			}
			existingSequence := binary.BigEndian.Uint64(mapped)
			raw, err := w.db.Get(txIngressWALRecordKeyForGeneration(w.generation, existingSequence))
			if err != nil {
				fatalErr = fmt.Errorf("read idempotent ingress WAL record: %w", err)
				break
			}
			var existing txIngressWALFrame
			if err := rlp.DecodeBytes(raw, &existing); err != nil || existing.EventID != request.eventID || existing.Kind != request.kind ||
				existing.BatchID != request.batchID || !bytes.Equal(existing.Payload, request.payload) {
				results[index].err = fmt.Errorf("ingress WAL EventID collision for %s", request.eventID)
				continue
			}
			results[index].sequence = existingSequence
			staged[request.eventID] = results[index]
			stagedRequests[request.eventID] = request
			continue
		}
		sequence++
		frame := &txIngressWALFrame{
			Version: txIngressWALVersion, Sequence: sequence, Previous: previous,
			Kind: request.kind, BatchID: request.batchID, EventID: request.eventID, Payload: request.payload,
		}
		encoded, err := encodeTxIngressWALFrame(frame)
		if err != nil {
			fatalErr = err
			break
		}
		recordKey := txIngressWALRecordKeyForGeneration(w.generation, sequence)
		recordBytes := int64(len(recordKey) + len(encoded) + len(eventKey) + 8)
		if projectedRecords >= w.maxRecords || projectedBytes > w.maxBytes-recordBytes {
			results[index].err = fmt.Errorf("ingress WAL capacity exceeded: records=%d/%d bytes=%d+%d/%d", projectedRecords, w.maxRecords, projectedBytes, recordBytes, w.maxBytes)
			capacityPressure = true
			sequence--
			continue
		}
		mapped := make([]byte, 8)
		binary.BigEndian.PutUint64(mapped, sequence)
		if err := batch.Put(recordKey, encoded); err != nil {
			fatalErr = err
			break
		}
		if err := batch.Put(eventKey, mapped); err != nil {
			fatalErr = err
			break
		}
		previous = frame.Checksum
		projectedRecords++
		projectedBytes += recordBytes
		newRecords++
		results[index].sequence = sequence
		staged[request.eventID] = results[index]
		stagedRequests[request.eventID] = request
	}
	if fatalErr == nil && newRecords > 0 {
		encodedTail, err := rlp.EncodeToBytes(&txIngressWALTail{Sequence: sequence, Digest: previous})
		if err != nil {
			fatalErr = err
		} else if err := batch.Put(txIngressWALTailKeyForGeneration(w.generation), encodedTail); err != nil {
			fatalErr = err
		}
	}
	if fatalErr == nil && newRecords > 0 {
		if err := writeTxIngressWALSync(batch, "append ingress WAL group"); err != nil {
			w.poison = fmt.Errorf("ambiguous ingress WAL group fsync failure: %w", err)
			fatalErr = w.poison
		} else {
			addedBytes := projectedBytes - w.bytes
			w.sequence, w.digest, w.records, w.bytes = sequence, previous, projectedRecords, projectedBytes
			w.sinceCompactRecords += newRecords
			w.sinceCompactBytes += addedBytes
		}
	}
	compact := fatalErr == nil && (capacityPressure || w.shouldCompactLocked(nil))
	w.mu.Unlock()
	if compact {
		w.requestCompaction()
	}
	if fatalErr != nil {
		for _, request := range requests {
			request.result <- txIngressWALAppendResult{err: fatalErr}
		}
		return
	}
	for index, request := range requests {
		request.result <- results[index]
	}
}

// Replay presents the validated prefix that existed when Replay began. Events
// appended by the callback have higher sequence numbers and are intentionally
// left for the next restart/replay pass.
func (w *txIngressWAL) Replay(visit func(*txIngressWALFrame) error) error {
	if w == nil || visit == nil {
		return nil
	}
	// Keep the selected generation from being retired while its immutable
	// records are read, but do not take the append mutex for the bulk scan.
	w.compactMu.Lock()
	w.mu.Lock()
	if err := w.runningErrLocked(); err != nil {
		w.mu.Unlock()
		w.compactMu.Unlock()
		return err
	}
	generation, sequence, digest := w.generation, w.sequence, w.digest
	w.mu.Unlock()
	frames, replayDigest, err := w.readFramesRange(generation, 1, sequence, common.Hash{})
	w.compactMu.Unlock()
	if err != nil {
		return err
	}
	if replayDigest != digest {
		return errors.New("ingress WAL replay snapshot digest mismatch")
	}
	for _, frame := range frames {
		if err := visit(frame); err != nil {
			return fmt.Errorf("replay ingress WAL record %d: %w", frame.Sequence, err)
		}
	}
	return nil
}

func (w *txIngressWAL) readFramesRange(generation, first, last uint64, previous common.Hash) ([]*txIngressWALFrame, common.Hash, error) {
	if last < first {
		return nil, previous, nil
	}
	frames := make([]*txIngressWALFrame, 0, int(last-first+1))
	for sequence := first; sequence <= last; sequence++ {
		key := txIngressWALRecordKeyForGeneration(generation, sequence)
		raw, err := w.db.Get(key)
		if err != nil {
			return nil, previous, fmt.Errorf("read ingress WAL replay record %d: %w", sequence, err)
		}
		frame, err := decodeTxIngressWALFrame(generation, key, raw, sequence, previous)
		if err != nil {
			return nil, previous, err
		}
		frames = append(frames, frame)
		previous = frame.Checksum
	}
	return frames, previous, nil
}

type txIngressWALCanonicalEvent struct {
	kind    txIngressWALEventKind
	batchID common.Hash
	eventID common.Hash
	payload []byte
}

type txIngressWALCanonicalOutboxMutation struct {
	event    txIngressWALCanonicalEvent
	sequence uint64
	semantic common.Hash
}

func (w *txIngressWAL) capacityPressureLocked(requests []*txIngressWALAppendRequest) bool {
	if w.records == 0 || len(requests) == 0 {
		return false
	}
	incomingBytes := int64(0)
	for _, request := range requests {
		if request != nil {
			incomingBytes += request.bytes
		}
	}
	return len(requests) > w.maxRecords-w.records || incomingBytes > w.maxBytes-w.bytes
}

func (w *txIngressWAL) shouldCompactLocked(requests []*txIngressWALAppendRequest) bool {
	if w.records == 0 {
		return false
	}
	incomingBytes := int64(0)
	for _, request := range requests {
		if request != nil {
			incomingBytes += request.bytes
		}
	}
	recordThreshold := w.maxRecords * 3 / 4
	if bounded := w.maxGroup * 64; recordThreshold > bounded {
		recordThreshold = bounded
	}
	if recordThreshold < w.maxGroup {
		recordThreshold = w.maxGroup
	}
	if recordThreshold > w.maxRecords {
		recordThreshold = w.maxRecords
	}
	byteThreshold := w.maxBytes * 3 / 4
	if bounded := w.maxGroupBytes * 8; byteThreshold > bounded {
		byteThreshold = bounded
	}
	if byteThreshold < w.maxGroupBytes {
		byteThreshold = w.maxGroupBytes
	}
	if byteThreshold > w.maxBytes {
		byteThreshold = w.maxBytes
	}
	return w.records > w.maxRecords-len(requests) || w.bytes > w.maxBytes-incomingBytes ||
		w.sinceCompactRecords >= recordThreshold || w.sinceCompactBytes >= byteThreshold
}

// txIngressWALCheckpoint is an inactive generation under construction. Its
// records and indexes are synchronously written in bounded batches, but it has
// no authoritative manifest (and intentionally no tail) until finalHandoff.
type txIngressWALCheckpoint struct {
	generation uint64
	sequence   uint64
	digest     common.Hash
	records    int
	bytes      int64

	// Delta records arrived after the canonical source snapshot. They are copied
	// verbatim as events, preserving correctness without re-running an unbounded
	// canonicalization while append traffic remains live.
	deltaRecords int
	deltaBytes   int64
	seenEvents   map[common.Hash]struct{}
}

// Compact checkpoints the active immutable generation into a canonical live
// generation. Snapshot validation, canonicalization, target writes, catch-up,
// and old-generation cleanup happen without the append mutex. Only the final
// tail+manifest fsync is serialized with group commits.
func (w *txIngressWAL) Compact() error {
	return w.compactConditional(true, 0, nil)
}

// compactConditional rechecks its trigger only after acquiring compactMu. This
// prevents a capacity waiter or coalesced background signal from building a
// redundant second generation after another checkpoint already recovered the
// space it needed.
func (w *txIngressWAL) compactConditional(force bool, expectedGeneration uint64, requests []*txIngressWALAppendRequest) error {
	if w == nil {
		return nil
	}
	w.compactMu.Lock()
	defer w.compactMu.Unlock()

	w.mu.Lock()
	if err := w.runningErrLocked(); err != nil {
		w.mu.Unlock()
		return err
	}
	if !force {
		if requests != nil {
			if w.generation != expectedGeneration || !w.capacityPressureLocked(requests) {
				w.mu.Unlock()
				return nil
			}
		} else if !w.shouldCompactLocked(nil) {
			w.mu.Unlock()
			return nil
		}
	}
	sourceGeneration, sourceSequence, sourceDigest := w.generation, w.sequence, w.digest
	w.mu.Unlock()

	err := w.compactGeneration(sourceGeneration, sourceSequence, sourceDigest)
	if err == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// A stopped WAL has no future callers to protect, and cancellation during
	// shutdown must not manufacture a persistent poison. Any failure while the
	// WAL is live is fail-closed because an fsync error may be ambiguous.
	if w.started && !w.stopped {
		if w.poison == nil {
			w.poison = fmt.Errorf("ingress WAL compaction failed; restart required: %w", err)
		}
		return w.poison
	}
	return err
}

func (w *txIngressWAL) compactGeneration(sourceGeneration, sourceSequence uint64, sourceDigest common.Hash) error {
	if sourceGeneration == ^uint64(0) {
		return errors.New("ingress WAL generation exhausted")
	}
	newGeneration := sourceGeneration + 1
	// A crash before an earlier manifest switch may have left this future
	// generation partially written. It is non-authoritative. Durable bounded
	// deletion can run concurrently with appends to the active generation.
	if err := w.deleteGeneration(newGeneration, true); err != nil {
		return err
	}
	frames, snapshotDigest, err := w.readFramesRange(sourceGeneration, 1, sourceSequence, common.Hash{})
	if err != nil {
		return err
	}
	if snapshotDigest != sourceDigest {
		return errors.New("ingress WAL checkpoint snapshot digest mismatch")
	}
	events, err := w.canonicalEvents(frames)
	if err != nil {
		return err
	}
	checkpoint := &txIngressWALCheckpoint{
		generation: newGeneration,
		seenEvents: make(map[common.Hash]struct{}, len(events)),
	}
	if err := w.appendCheckpointEvents(checkpoint, events, false); err != nil {
		return err
	}

	// Follow the immutable source tail in bounded record windows. Appends remain
	// single-generation writes; once copied here, each delta has the checkpoint's
	// own sequence and hash-chain predecessor.
	copiedSource, sourcePrevious := sourceSequence, sourceDigest
	catchupRecords := w.maxGroup * 8
	if catchupRecords < 1 {
		catchupRecords = 1
	}
	if catchupRecords > 16384 {
		catchupRecords = 16384
	}
	for {
		w.mu.Lock()
		if err := w.runningErrLocked(); err != nil {
			w.mu.Unlock()
			return err
		}
		if w.generation != sourceGeneration || w.sequence < copiedSource {
			w.mu.Unlock()
			return errors.New("ingress WAL generation changed during checkpoint")
		}
		observedSequence, observedDigest := w.sequence, w.digest
		w.mu.Unlock()

		if observedSequence > copiedSource {
			end := observedSequence
			if remaining := end - copiedSource; remaining > uint64(catchupRecords) {
				end = copiedSource + uint64(catchupRecords)
			}
			delta, deltaDigest, err := w.readFramesRange(sourceGeneration, copiedSource+1, end, sourcePrevious)
			if err != nil {
				return err
			}
			if end == observedSequence && deltaDigest != observedDigest {
				return errors.New("ingress WAL checkpoint catch-up digest mismatch")
			}
			deltaEvents := make([]txIngressWALCanonicalEvent, len(delta))
			for index, frame := range delta {
				deltaEvents[index] = txIngressWALCanonicalEvent{
					kind: frame.Kind, batchID: frame.BatchID, eventID: frame.EventID, payload: frame.Payload,
				}
			}
			if err := w.appendCheckpointEvents(checkpoint, deltaEvents, true); err != nil {
				return err
			}
			copiedSource, sourcePrevious = end, deltaDigest
			continue
		}

		// Bounded handoff: if a commit won the mutex after the observation above,
		// retry catch-up. Otherwise only this two-key synchronous batch is executed
		// while append commits are excluded.
		w.mu.Lock()
		if err := w.runningErrLocked(); err != nil {
			w.mu.Unlock()
			return err
		}
		if w.generation != sourceGeneration {
			w.mu.Unlock()
			return errors.New("ingress WAL generation changed during checkpoint handoff")
		}
		if w.sequence != copiedSource {
			w.mu.Unlock()
			continue
		}
		if w.digest != sourcePrevious {
			w.mu.Unlock()
			return errors.New("ingress WAL source digest changed during checkpoint handoff")
		}
		if err := w.finalizeCheckpointLocked(checkpoint); err != nil {
			w.mu.Unlock()
			return err
		}
		oldGeneration := w.generation
		w.generation, w.sequence, w.digest = checkpoint.generation, checkpoint.sequence, checkpoint.digest
		w.records, w.bytes = checkpoint.records, checkpoint.bytes
		w.sinceCompactRecords, w.sinceCompactBytes = checkpoint.deltaRecords, checkpoint.deltaBytes
		w.mu.Unlock()

		// The manifest already names the complete target. Old keys are garbage and
		// can be reclaimed without delaying either appends or Compact's correctness.
		_ = w.deleteGeneration(oldGeneration, false)
		return nil
	}
}

func (w *txIngressWAL) appendCheckpointEvents(checkpoint *txIngressWALCheckpoint, events []txIngressWALCanonicalEvent, delta bool) error {
	batch := w.db.NewBatch()
	batchRecords := 0
	flush := func() error {
		if batchRecords == 0 {
			return nil
		}
		if err := writeTxIngressWALSync(batch, "write ingress WAL checkpoint generation"); err != nil {
			return err
		}
		batch.Reset()
		batchRecords = 0
		return nil
	}
	for _, event := range events {
		if event.kind < txIngressWALInboundReceived || event.kind > txIngressWALOutboxApplied || event.batchID == (common.Hash{}) || event.eventID == (common.Hash{}) || len(event.payload) == 0 {
			return errors.New("invalid canonical ingress WAL event")
		}
		if _, duplicate := checkpoint.seenEvents[event.eventID]; duplicate {
			return fmt.Errorf("canonical ingress WAL EventID collision for %s", event.eventID)
		}
		checkpoint.sequence++
		frame := &txIngressWALFrame{
			Version: txIngressWALVersion, Sequence: checkpoint.sequence, Previous: checkpoint.digest,
			Kind: event.kind, BatchID: event.batchID, EventID: event.eventID, Payload: event.payload,
		}
		encoded, err := encodeTxIngressWALFrame(frame)
		if err != nil {
			return err
		}
		recordKey := txIngressWALRecordKeyForGeneration(checkpoint.generation, checkpoint.sequence)
		eventKey := txIngressWALEventKeyForGeneration(checkpoint.generation, event.eventID)
		recordBytes := int64(len(recordKey) + len(encoded) + len(eventKey) + 8)
		if checkpoint.records >= w.maxRecords || checkpoint.bytes > w.maxBytes-recordBytes {
			return fmt.Errorf("canonical ingress WAL exceeds capacity: records=%d/%d bytes=%d+%d/%d", checkpoint.records, w.maxRecords, checkpoint.bytes, recordBytes, w.maxBytes)
		}
		if batchRecords > 0 && (batchRecords >= w.maxGroup || int64(batch.ValueSize()+len(recordKey)+len(encoded)+len(eventKey)+8) > w.maxGroupBytes) {
			if err := flush(); err != nil {
				return err
			}
		}
		mapped := make([]byte, 8)
		binary.BigEndian.PutUint64(mapped, checkpoint.sequence)
		if err := batch.Put(recordKey, encoded); err != nil {
			return err
		}
		if err := batch.Put(eventKey, mapped); err != nil {
			return err
		}
		checkpoint.seenEvents[event.eventID] = struct{}{}
		checkpoint.digest = frame.Checksum
		checkpoint.records++
		checkpoint.bytes += recordBytes
		batchRecords++
		if delta {
			checkpoint.deltaRecords++
			checkpoint.deltaBytes += recordBytes
		}
	}
	return flush()
}

func (w *txIngressWAL) finalizeCheckpointLocked(checkpoint *txIngressWALCheckpoint) error {
	encodedTail, err := rlp.EncodeToBytes(&txIngressWALTail{Sequence: checkpoint.sequence, Digest: checkpoint.digest})
	if err != nil {
		return err
	}
	encodedManifest, err := rlp.EncodeToBytes(&txIngressWALManifest{Version: txIngressWALVersion, Generation: checkpoint.generation})
	if err != nil {
		return err
	}
	switchBatch := w.db.NewBatch()
	if err := switchBatch.Put(txIngressWALTailKeyForGeneration(checkpoint.generation), encodedTail); err != nil {
		return err
	}
	if err := switchBatch.Put(txIngressWALManifestKey, encodedManifest); err != nil {
		return err
	}
	return writeTxIngressWALSync(switchBatch, "switch ingress WAL checkpoint generation")
}

func (w *txIngressWAL) deleteGeneration(generation uint64, durable bool) error {
	prefixes := [][]byte{txIngressWALRecordPrefixForGeneration(generation), txIngressWALEventPrefixForGeneration(generation)}
	for _, prefix := range prefixes {
		iterator := w.db.NewIterator(prefix, nil)
		batch := w.db.NewBatch()
		count, keyBytes := 0, 0
		flush := func() error {
			if count == 0 {
				return nil
			}
			var err error
			if durable {
				err = writeTxIngressWALSync(batch, "erase orphan ingress WAL generation before reuse")
			} else {
				err = batch.Write()
			}
			if err != nil {
				return err
			}
			batch.Reset()
			count, keyBytes = 0, 0
			return nil
		}
		for iterator.Next() {
			key := append([]byte(nil), iterator.Key()...)
			if err := batch.Delete(key); err != nil {
				iterator.Release()
				return err
			}
			count++
			keyBytes += len(key)
			if count >= w.maxGroup || int64(keyBytes) >= w.maxGroupBytes {
				if err := flush(); err != nil {
					iterator.Release()
					return err
				}
			}
		}
		iteratorErr := iterator.Error()
		iterator.Release()
		if iteratorErr != nil {
			return iteratorErr
		}
		if err := flush(); err != nil {
			return err
		}
	}
	tailBatch := w.db.NewBatch()
	if err := tailBatch.Delete(txIngressWALTailKeyForGeneration(generation)); err != nil {
		return err
	}
	if durable {
		return writeTxIngressWALSync(tailBatch, "erase orphan ingress WAL tail before reuse")
	}
	return tailBatch.Write()
}

func (w *txIngressWAL) canonicalEvents(frames []*txIngressWALFrame) ([]txIngressWALCanonicalEvent, error) {
	localIntents := make(map[common.Hash]*txQUICBatch)
	localIntentEvents := make(map[common.Hash]txIngressWALCanonicalEvent)
	localOutcomeEvents := make(map[common.Hash]txIngressWALCanonicalEvent)
	localAcceptedBatches := make(map[common.Hash]*txQUICBatch)
	outbox := make(map[common.Hash]txIngressWALOutboxProjection)
	outboxDeletions := make(map[common.Hash]txIngressWALCanonicalOutboxMutation)
	pendingOutboxMutations := make(map[common.Hash]txIngressWALCanonicalOutboxMutation)
	pendingOutboxMutationGroups := make(map[common.Hash]map[common.Hash]struct{})
	nonces := make(map[string]txOutboxNonceState)
	inbound := make(map[string]txIngressWALInboundProjection)
	for _, frame := range frames {
		switch frame.Kind {
		case txIngressWALLocalIntent:
			intent, _, err := decodeTxQUICBatch(frame.Payload)
			if err != nil || intent.BatchID != frame.BatchID {
				return nil, errors.New("invalid local intent while compacting ingress WAL")
			}
			localIntents[frame.EventID] = intent
			localIntentEvents[frame.EventID] = txIngressWALCanonicalEvent{
				kind: frame.Kind, batchID: frame.BatchID, eventID: frame.EventID,
				payload: append([]byte(nil), frame.Payload...),
			}
		case txIngressWALLocalOutcome:
			var outcome txIngressWALLocalOutcomePayload
			if err := rlp.DecodeBytes(frame.Payload, &outcome); err != nil {
				return nil, err
			}
			intent := localIntents[outcome.IntentID]
			if intent == nil || intent.BatchID != frame.BatchID || int(outcome.ItemCount) != len(intent.Items) {
				return nil, errors.New("local outcome mismatches intent while compacting ingress WAL")
			}
			batch, payload, err := txIngressWALAcceptedBatch(intent, outcome.AcceptedBitmap)
			if err != nil {
				return nil, err
			}
			if batch != nil {
				record := TxOutboxRecord{BatchID: batch.BatchID, Payload: payload, CreatedAt: txOutboxStableCreatedAt(batch.Certificate)}
				if err := mergeLocalOutcomeProjection(outbox, record); err != nil {
					return nil, err
				}
				delete(outboxDeletions, batch.BatchID)
			}
			localAcceptedBatches[outcome.IntentID] = batch
			localOutcomeEvents[outcome.IntentID] = txIngressWALCanonicalEvent{
				kind: frame.Kind, batchID: frame.BatchID, eventID: frame.EventID,
				payload: append([]byte(nil), frame.Payload...),
			}
		case txIngressWALOutboxNonce:
			var payload txIngressWALOutboxNoncePayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return nil, err
			}
			state := payload.State
			if state.Sender == (common.Address{}) || state.Epoch != frame.BatchID || state.ReservedThrough == 0 ||
				state.Epoch != txQUICSenderEpoch(w.identity.ChainID, w.identity.GenesisHash, state.Sender) {
				return nil, errors.New("invalid outbox nonce while compacting ingress WAL")
			}
			nonces[string(txOutboxNonceKey(state.Sender, state.Epoch))] = state
		case txIngressWALOutboxEnqueued, txIngressWALOutboxState, txIngressWALOutboxDeleted:
			var payload txIngressWALOutboxPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return nil, err
			}
			if payload.Record.BatchID != frame.BatchID || payload.Record.BatchID == (common.Hash{}) {
				return nil, errors.New("invalid outbox identity while compacting ingress WAL")
			}
			ownsPayload := frame.Kind == txIngressWALOutboxEnqueued || payload.Supersedes != (common.Hash{})
			if ownsPayload && (len(payload.Record.Payload) == 0 || txOutboxBatchID(payload.Record.Payload) != payload.Record.BatchID || payload.Record.CreatedAt == 0) {
				return nil, errors.New("invalid outbox payload while compacting ingress WAL")
			}
			var destructive *txIngressWALCanonicalOutboxMutation
			if frame.Kind == txIngressWALOutboxDeleted || (payload.Supersedes != (common.Hash{}) && payload.Supersedes != frame.BatchID) {
				semantic := txIngressWALOutboxMutationSemanticID(frame.Kind, frame.BatchID, frame.Payload)
				mutation := txIngressWALCanonicalOutboxMutation{
					event: txIngressWALCanonicalEvent{
						kind: frame.Kind, batchID: frame.BatchID, eventID: frame.EventID,
						payload: append([]byte(nil), frame.Payload...),
					},
					sequence: frame.Sequence,
					semantic: semantic,
				}
				destructive = &mutation
				pendingOutboxMutations[frame.EventID] = mutation
				group := pendingOutboxMutationGroups[semantic]
				if group == nil {
					group = make(map[common.Hash]struct{})
					pendingOutboxMutationGroups[semantic] = group
				}
				group[frame.EventID] = struct{}{}
			}
			if payload.Supersedes != (common.Hash{}) && payload.Supersedes != payload.Record.BatchID {
				outbox[payload.Supersedes] = txIngressWALOutboxProjection{deleted: true}
				outboxDeletions[payload.Supersedes] = *destructive
			}
			if frame.Kind == txIngressWALOutboxDeleted {
				outbox[frame.BatchID] = txIngressWALOutboxProjection{deleted: true}
				outboxDeletions[frame.BatchID] = *destructive
			} else if frame.Kind == txIngressWALOutboxState && !ownsPayload {
				current, ok := outbox[frame.BatchID]
				if !ok || current.deleted || len(current.record.Payload) == 0 {
					return nil, errors.New("outbox state precedes enqueue while compacting ingress WAL")
				}
				current.record.Placement = cloneTxOutboxPlacementState(payload.Record.Placement)
				current.retry = payload.Retry
				outbox[frame.BatchID] = current
				delete(outboxDeletions, frame.BatchID)
			} else {
				outbox[frame.BatchID] = txIngressWALOutboxProjection{record: payload.Record, retry: payload.Retry}
				delete(outboxDeletions, frame.BatchID)
			}
		case txIngressWALOutboxApplied:
			var payload txIngressWALOutboxAppliedPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return nil, err
			}
			mutation, ok := pendingOutboxMutations[payload.MutationID]
			if !ok || mutation.event.batchID != frame.BatchID {
				return nil, errors.New("outbox applied marker precedes or mismatches its mutation while compacting ingress WAL")
			}
			for eventID := range pendingOutboxMutationGroups[mutation.semantic] {
				delete(pendingOutboxMutations, eventID)
			}
			delete(pendingOutboxMutationGroups, mutation.semantic)
		case txIngressWALInboundReceived:
			var payload txIngressWALInboundReceivedPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return nil, err
			}
			if payload.Packet.BatchID != frame.BatchID {
				return nil, errors.New("invalid inbound receive while compacting ingress WAL")
			}
			if _, err := newTxQUICAckExpectation(&payload.Packet); err != nil {
				return nil, err
			}
			key := txIngressWALPacketProjectionKey(&payload.Packet)
			current := inbound[key]
			current.packet = payload.Packet
			inbound[key] = current
		case txIngressWALInboundOutcome:
			var payload txIngressWALInboundOutcomePayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return nil, err
			}
			identity := txQUICPacket{BatchID: payload.BatchID, Sender: payload.Sender, SenderEpoch: payload.SenderEpoch, Nonce: payload.Nonce}
			key := txIngressWALPacketProjectionKey(&identity)
			current, ok := inbound[key]
			if !ok || payload.BatchID != frame.BatchID {
				return nil, errors.New("inbound outcome precedes receive while compacting ingress WAL")
			}
			expectation, err := newTxQUICAckExpectation(&current.packet)
			if err != nil || validateTxQUICAckOutcome(&payload.Ack, expectation) != nil {
				return nil, errors.New("invalid inbound outcome while compacting ingress WAL")
			}
			ack := payload.Ack
			current.outcome = &ack
			inbound[key] = current
		case txIngressWALInboundApplied:
			var payload txIngressWALInboundAppliedPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return nil, err
			}
			identity := txQUICPacket{BatchID: payload.BatchID, Sender: payload.Sender, SenderEpoch: payload.SenderEpoch, Nonce: payload.Nonce}
			key := txIngressWALPacketProjectionKey(&identity)
			current, ok := inbound[key]
			if !ok || current.outcome == nil || payload.BatchID != frame.BatchID {
				return nil, errors.New("inbound applied precedes outcome while compacting ingress WAL")
			}
			current.applied = true
			inbound[key] = current
		}
	}

	events := make([]txIngressWALCanonicalEvent, 0, len(localIntents)*2+len(inbound)*2+len(pendingOutboxMutations)+len(outbox)+len(nonces))
	localIDs := make([]common.Hash, 0, len(localIntents))
	recoverableOutboxIDs := make(map[common.Hash]struct{})
	for id := range localIntents {
		_, completed := localOutcomeEvents[id]
		if !completed {
			localIDs = append(localIDs, id)
			continue
		}
		batch := localAcceptedBatches[id]
		if batch == nil {
			continue
		}
		for _, keep := range w.recoverableLocalItems(batch.Items) {
			if keep {
				localIDs = append(localIDs, id)
				recoverableOutboxIDs[batch.BatchID] = struct{}{}
				break
			}
		}
	}
	sort.Slice(localIDs, func(i, j int) bool { return bytes.Compare(localIDs[i][:], localIDs[j][:]) < 0 })
	for _, id := range localIDs {
		events = append(events, localIntentEvents[id])
		if outcome, completed := localOutcomeEvents[id]; completed {
			events = append(events, outcome)
		}
	}
	inboundKeys := make([]string, 0, len(inbound))
	for key, state := range inbound {
		if !state.applied {
			inboundKeys = append(inboundKeys, key)
		}
	}
	sort.Strings(inboundKeys)
	for _, key := range inboundKeys {
		state := inbound[key]
		receivedPayload, err := rlp.EncodeToBytes(&txIngressWALInboundReceivedPayload{Packet: state.packet})
		if err != nil {
			return nil, err
		}
		receivedID, err := txQUICRLPHash([]interface{}{"CPH_INGRESS_WAL_RECEIVED_V1", state.packet.BatchID, state.packet.Sender, state.packet.SenderEpoch, state.packet.Nonce})
		if err != nil {
			return nil, err
		}
		events = append(events, txIngressWALCanonicalEvent{kind: txIngressWALInboundReceived, batchID: state.packet.BatchID, eventID: receivedID, payload: receivedPayload})
		if state.outcome != nil {
			outcomePayload, err := rlp.EncodeToBytes(&txIngressWALInboundOutcomePayload{
				BatchID: state.packet.BatchID, Sender: state.packet.Sender, SenderEpoch: state.packet.SenderEpoch, Nonce: state.packet.Nonce, Ack: *state.outcome,
			})
			if err != nil {
				return nil, err
			}
			events = append(events, txIngressWALCanonicalEvent{
				kind: txIngressWALInboundOutcome, batchID: state.packet.BatchID,
				eventID: txIngressWALEventID(txIngressWALInboundOutcome, state.packet.BatchID, outcomePayload), payload: outcomePayload,
			})
		}
	}
	// Destructive outbox mutations are retained byte-for-byte until a durable
	// OutboxApplied marker proves that the mutable projection was synchronously
	// updated. Emit them before the final active-set snapshot: if an old delete
	// was later superseded by a re-enqueue of the same identity, the canonical
	// active record must win during replay.
	canonicalMutations := make(map[common.Hash]txIngressWALCanonicalOutboxMutation, len(pendingOutboxMutations)+len(recoverableOutboxIDs))
	for _, mutation := range pendingOutboxMutations {
		canonicalMutations[mutation.event.eventID] = mutation
	}
	// A completed local delivery still owns the only durable copy of a pending
	// transaction after the mutable outbox entry is ACKed and removed. Retain
	// its deletion evidence alongside the intent, otherwise replaying the
	// compacted WAL would synthesize a fresh outbox enqueue from LocalOutcome.
	for id := range recoverableOutboxIDs {
		if state, ok := outbox[id]; ok && state.deleted {
			mutation, ok := outboxDeletions[id]
			if !ok {
				return nil, errors.New("recoverable local transaction is missing outbox deletion evidence")
			}
			canonicalMutations[mutation.event.eventID] = mutation
		}
	}
	pendingMutations := make([]txIngressWALCanonicalOutboxMutation, 0, len(canonicalMutations))
	for _, mutation := range canonicalMutations {
		pendingMutations = append(pendingMutations, mutation)
	}
	sort.Slice(pendingMutations, func(i, j int) bool { return pendingMutations[i].sequence < pendingMutations[j].sequence })
	for _, mutation := range pendingMutations {
		events = append(events, mutation.event)
	}
	outboxIDs := make([]common.Hash, 0, len(outbox))
	for id, state := range outbox {
		if !state.deleted {
			outboxIDs = append(outboxIDs, id)
		}
	}
	sort.Slice(outboxIDs, func(i, j int) bool { return bytes.Compare(outboxIDs[i][:], outboxIDs[j][:]) < 0 })
	for _, id := range outboxIDs {
		state := outbox[id]
		// A checkpoint owns the current active projection in one full record.
		// Live exact-duplicate stores consult the striped projection first and do
		// not append a zero-state enqueue, so placement/retry cannot be rewound.
		payload, err := rlp.EncodeToBytes(&txIngressWALOutboxPayload{Record: state.record, Retry: state.retry})
		if err != nil {
			return nil, err
		}
		events = append(events, txIngressWALCanonicalEvent{
			kind: txIngressWALOutboxEnqueued, batchID: id,
			eventID: txIngressWALEventID(txIngressWALOutboxEnqueued, id, payload), payload: payload,
		})
	}
	nonceKeys := make([]string, 0, len(nonces))
	for key := range nonces {
		nonceKeys = append(nonceKeys, key)
	}
	sort.Strings(nonceKeys)
	for _, key := range nonceKeys {
		state := nonces[key]
		payload, err := rlp.EncodeToBytes(&txIngressWALOutboxNoncePayload{State: state})
		if err != nil {
			return nil, err
		}
		events = append(events, txIngressWALCanonicalEvent{
			kind: txIngressWALOutboxNonce, batchID: state.Epoch,
			eventID: txIngressWALEventID(txIngressWALOutboxNonce, state.Epoch, payload), payload: payload,
		})
	}
	return events, nil
}

type txIngressWALInboundReceivedPayload struct {
	Packet txQUICPacket
}

type txIngressWALInboundOutcomePayload struct {
	BatchID     common.Hash
	Sender      common.Address
	SenderEpoch common.Hash
	Nonce       uint64
	Ack         txQUICAck
}

type txIngressWALInboundAppliedPayload struct {
	BatchID     common.Hash
	Sender      common.Address
	SenderEpoch common.Hash
	Nonce       uint64
}

type txIngressWALLocalOutcomePayload struct {
	IntentID       common.Hash
	ItemCount      uint32
	AcceptedBitmap []byte
}

type txIngressWALOutboxPayload struct {
	Record     TxOutboxRecord
	Retry      txOutboxRetryState
	Supersedes common.Hash
}

type txIngressWALOutboxNoncePayload struct {
	State txOutboxNonceState
}

type txIngressWALOutboxAppliedPayload struct {
	MutationID common.Hash
}

func txIngressWALEventID(kind txIngressWALEventKind, batchID common.Hash, payload []byte) common.Hash {
	return crypto.Keccak256Hash([]byte("CPH_INGRESS_WAL_EVENT_V1"), []byte{byte(kind)}, batchID[:], payload)
}

func txIngressWALOutboxMutationSemanticID(kind txIngressWALEventKind, batchID common.Hash, payload []byte) common.Hash {
	if kind == txIngressWALOutboxDeleted {
		// Placement/retry snapshots carried by a stale caller do not change the
		// effect of deleting this identity from the mutable projection.
		return crypto.Keccak256Hash([]byte("CPH_INGRESS_WAL_OUTBOX_DELETE_V1"), batchID[:])
	}
	return txIngressWALEventID(kind, batchID, payload)
}

// nextOperationEventID assigns an incarnation to a mutable ingress operation. A
// content-only EventID cannot distinguish enqueue-delete-enqueue lifecycles of
// the same semantic batch before the old generation is compacted. The startup
// durable tail plus a process-local reservation counter is unique for every
// concurrently prepared operation; after restart, any committed operation has
// changed that tail (or its generation), while an uncommitted reservation is
// safe to reuse. ID allocation has its own short lock: taking the commit mutex
// here would prevent independent producers from joining a group while its
// predecessor is inside fsync.
func (w *txIngressWAL) nextOperationEventID(domain string, kind txIngressWALEventKind, batchID common.Hash, payload []byte) (common.Hash, error) {
	if w == nil {
		return common.Hash{}, errors.New("ingress WAL is unavailable")
	}
	w.operationMu.Lock()
	defer w.operationMu.Unlock()
	if w.operationSeed == (common.Hash{}) {
		return common.Hash{}, errors.New("ingress WAL is not running")
	}
	if w.operationNonce == ^uint64(0) {
		return common.Hash{}, errors.New("ingress WAL operation nonce exhausted")
	}
	w.operationNonce++
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], w.operationNonce)
	return crypto.Keccak256Hash(
		[]byte(domain),
		w.operationSeed[:], nonce[:],
		[]byte{byte(kind)}, batchID[:], payload,
	), nil
}

func (w *txIngressWAL) appendInboundReceived(ctx context.Context, packet *txQUICPacket) error {
	if packet == nil {
		return errors.New("nil ingress WAL packet")
	}
	payload, err := rlp.EncodeToBytes(&txIngressWALInboundReceivedPayload{Packet: *packet})
	if err != nil {
		return err
	}
	eventID, err := txQUICRLPHash([]interface{}{"CPH_INGRESS_WAL_RECEIVED_V1", packet.BatchID, packet.Sender, packet.SenderEpoch, packet.Nonce})
	if err != nil {
		return err
	}
	_, err = w.Append(ctx, txIngressWALInboundReceived, packet.BatchID, eventID, payload)
	return err
}

func (w *txIngressWAL) appendInboundOutcome(ctx context.Context, packet *txQUICPacket, ack txQUICAck) error {
	if packet == nil {
		return errors.New("nil ingress WAL packet")
	}
	payload, err := rlp.EncodeToBytes(&txIngressWALInboundOutcomePayload{
		BatchID: packet.BatchID, Sender: packet.Sender, SenderEpoch: packet.SenderEpoch, Nonce: packet.Nonce, Ack: ack,
	})
	if err != nil {
		return err
	}
	_, err = w.Append(ctx, txIngressWALInboundOutcome, packet.BatchID, txIngressWALEventID(txIngressWALInboundOutcome, packet.BatchID, payload), payload)
	return err
}

func (w *txIngressWAL) appendInboundApplied(ctx context.Context, packet *txQUICPacket) error {
	if packet == nil {
		return errors.New("nil applied ingress WAL packet")
	}
	payload, err := rlp.EncodeToBytes(&txIngressWALInboundAppliedPayload{
		BatchID: packet.BatchID, Sender: packet.Sender, SenderEpoch: packet.SenderEpoch, Nonce: packet.Nonce,
	})
	if err != nil {
		return err
	}
	_, err = w.Append(ctx, txIngressWALInboundApplied, packet.BatchID, txIngressWALEventID(txIngressWALInboundApplied, packet.BatchID, payload), payload)
	return err
}

func (w *txIngressWAL) appendLocalIntent(ctx context.Context, batch *txQUICBatch) (common.Hash, error) {
	if batch == nil || batch.BatchID == (common.Hash{}) {
		return common.Hash{}, errors.New("invalid local ingress WAL intent")
	}
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		return common.Hash{}, err
	}
	eventID, err := w.nextOperationEventID("CPH_INGRESS_WAL_LOCAL_INTENT_OPERATION_V1", txIngressWALLocalIntent, batch.BatchID, payload)
	if err != nil {
		return common.Hash{}, err
	}
	_, err = w.Append(ctx, txIngressWALLocalIntent, batch.BatchID, eventID, payload)
	return eventID, err
}

func (w *txIngressWAL) appendLocalOutcome(ctx context.Context, batchID, intentID common.Hash, itemCount int, accepted []byte) error {
	if batchID == (common.Hash{}) || intentID == (common.Hash{}) || itemCount <= 0 || itemCount > int(^uint32(0)) || len(accepted) != txQUICBitmapBytes(itemCount) || !txQUICBitmapPaddingZero(accepted, itemCount) {
		return errors.New("invalid local ingress WAL outcome")
	}
	payload, err := rlp.EncodeToBytes(&txIngressWALLocalOutcomePayload{
		IntentID: intentID, ItemCount: uint32(itemCount), AcceptedBitmap: append([]byte(nil), accepted...),
	})
	if err != nil {
		return err
	}
	eventID := txIngressWALEventID(txIngressWALLocalOutcome, batchID, payload)
	_, err = w.Append(ctx, txIngressWALLocalOutcome, batchID, eventID, payload)
	return err
}

func (w *txIngressWAL) appendOutbox(ctx context.Context, kind txIngressWALEventKind, record TxOutboxRecord, retry txOutboxRetryState) error {
	return w.appendOutboxProjection(ctx, kind, record, retry, common.Hash{})
}

func (w *txIngressWAL) appendOutboxProjection(ctx context.Context, kind txIngressWALEventKind, record TxOutboxRecord, retry txOutboxRetryState, supersedes common.Hash) error {
	_, err := w.appendOutboxProjectionTracked(ctx, kind, record, retry, supersedes)
	return err
}

func (w *txIngressWAL) appendOutboxProjectionTracked(ctx context.Context, kind txIngressWALEventKind, record TxOutboxRecord, retry txOutboxRetryState, supersedes common.Hash) (common.Hash, error) {
	walRecord := record
	// The enqueue (and a residual replacement) owns transaction bytes. Later
	// delivery checkpoints append only compact state deltas, so a retry does not
	// rewrite a multi-megabyte transaction into the WAL.
	if (kind == txIngressWALOutboxState && supersedes == (common.Hash{})) || kind == txIngressWALOutboxDeleted {
		walRecord.Payload = nil
		walRecord.CreatedAt = 0
	}
	payload, err := rlp.EncodeToBytes(&txIngressWALOutboxPayload{Record: walRecord, Retry: retry, Supersedes: supersedes})
	if err != nil {
		return common.Hash{}, err
	}
	eventID, err := w.nextOperationEventID("CPH_INGRESS_WAL_OUTBOX_OPERATION_V1", kind, record.BatchID, payload)
	if err != nil {
		return common.Hash{}, err
	}
	_, err = w.Append(ctx, kind, record.BatchID, eventID, payload)
	return eventID, err
}

func (w *txIngressWAL) appendOutboxApplied(ctx context.Context, batchID, mutationID common.Hash) error {
	if batchID == (common.Hash{}) || mutationID == (common.Hash{}) {
		return errors.New("invalid applied outbox WAL mutation")
	}
	payload, err := rlp.EncodeToBytes(&txIngressWALOutboxAppliedPayload{MutationID: mutationID})
	if err != nil {
		return err
	}
	_, err = w.Append(ctx, txIngressWALOutboxApplied, batchID, txIngressWALEventID(txIngressWALOutboxApplied, batchID, payload), payload)
	return err
}

func (w *txIngressWAL) appendOutboxNonce(ctx context.Context, state txOutboxNonceState) error {
	payload, err := rlp.EncodeToBytes(&txIngressWALOutboxNoncePayload{State: state})
	if err != nil {
		return err
	}
	_, err = w.Append(ctx, txIngressWALOutboxNonce, state.Epoch, txIngressWALEventID(txIngressWALOutboxNonce, state.Epoch, payload), payload)
	return err
}

func ingressWALDatabasePrefixes() [][]byte {
	return [][]byte{txIngressWALIdentityKey, txIngressWALManifestKey, txIngressWALTailKey, txIngressWALRecordPrefix, txIngressWALEventPrefix, txIngressWALGenerationPrefix}
}

type txIngressWALOutboxProjection struct {
	record  TxOutboxRecord
	retry   txOutboxRetryState
	deleted bool
}

// mergeLocalOutcomeProjection makes repeated local intents idempotent without
// erasing delivery progress already checkpointed for their identical accepted
// batch. A LocalOutcome after a durable deletion is a new active incarnation
// and intentionally starts from the base record again.
func mergeLocalOutcomeProjection(projection map[common.Hash]txIngressWALOutboxProjection, record TxOutboxRecord) error {
	current, exists := projection[record.BatchID]
	if exists && !current.deleted {
		if current.record.BatchID != record.BatchID || !bytes.Equal(current.record.Payload, record.Payload) || current.record.CreatedAt == 0 {
			return errors.New("duplicate local outcome conflicts with active outbox projection")
		}
		return nil
	}
	projection[record.BatchID] = txIngressWALOutboxProjection{record: record}
	return nil
}

func txIngressWALAcceptedBatch(intent *txQUICBatch, accepted []byte) (*txQUICBatch, []byte, error) {
	if intent == nil || len(intent.Items) == 0 || len(accepted) != txQUICBitmapBytes(len(intent.Items)) || !txQUICBitmapPaddingZero(accepted, len(intent.Items)) {
		return nil, nil, errors.New("invalid local ingress WAL accepted bitmap")
	}
	items := make([]*txQUICItem, 0, len(intent.Items))
	for index, item := range intent.Items {
		if txQUICBitmapHas(accepted, index) {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return nil, nil, nil
	}
	batch, _, err := newTxQUICBatch(intent.ChainID, intent.GenesisHash, intent.Certificate, items)
	if err != nil {
		return nil, nil, err
	}
	payload, err := rlp.EncodeToBytes(batch)
	if err != nil {
		return nil, nil, err
	}
	return batch, payload, nil
}

func txOutboxStableCreatedAt(certificate *types.CommonTxAdmissionBatch) uint64 {
	createdAt := uint64(time.Now().UnixNano())
	if certificate != nil {
		if timestamp := certificate.Timestamp; timestamp > 0 && timestamp <= ^uint64(0)/uint64(time.Second) {
			createdAt = timestamp * uint64(time.Second)
		}
	}
	return createdAt
}

// replayWALOutboxProjection rebuilds the mutable delivery index before its
// scheduler starts. Replaying the same prefix repeatedly produces identical
// keys and values.
func (q *TxQUICIngress) replayWALOutboxProjection() error {
	if q == nil || q.wal == nil || q.outbox == nil {
		return nil
	}
	projection := make(map[common.Hash]txIngressWALOutboxProjection)
	pendingOutboxMutations := make(map[common.Hash]txIngressWALCanonicalOutboxMutation)
	pendingOutboxMutationGroups := make(map[common.Hash]map[common.Hash]struct{})
	nonces := make(map[string]txOutboxNonceState)
	localIntents := make(map[common.Hash]*txQUICBatch)
	if err := q.wal.Replay(func(frame *txIngressWALFrame) error {
		if frame.Kind == txIngressWALLocalIntent {
			batch, _, err := decodeTxQUICBatch(frame.Payload)
			if err != nil {
				return fmt.Errorf("decode local ingress WAL intent: %w", err)
			}
			if batch.BatchID != frame.BatchID {
				return errors.New("local ingress WAL intent identity mismatch")
			}
			if err := q.verifyTxQUICBatchBlobSidecars(batch); err != nil {
				return fmt.Errorf("verify local ingress WAL blob sidecars: %w", err)
			}
			localIntents[frame.EventID] = batch
			return nil
		}
		if frame.Kind == txIngressWALLocalOutcome {
			var outcome txIngressWALLocalOutcomePayload
			if err := rlp.DecodeBytes(frame.Payload, &outcome); err != nil {
				return fmt.Errorf("decode local ingress WAL outcome: %w", err)
			}
			intent := localIntents[outcome.IntentID]
			if intent == nil || intent.BatchID != frame.BatchID || int(outcome.ItemCount) != len(intent.Items) {
				return errors.New("local ingress WAL outcome precedes or mismatches its intent")
			}
			batch, payload, err := txIngressWALAcceptedBatch(intent, outcome.AcceptedBitmap)
			if err != nil {
				return err
			}
			if batch != nil {
				record := TxOutboxRecord{BatchID: batch.BatchID, Payload: payload, CreatedAt: txOutboxStableCreatedAt(batch.Certificate)}
				if err := mergeLocalOutcomeProjection(projection, record); err != nil {
					return err
				}
			}
			return nil
		}
		if frame.Kind == txIngressWALOutboxNonce {
			var payload txIngressWALOutboxNoncePayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return fmt.Errorf("decode outbox nonce projection: %w", err)
			}
			state := payload.State
			if state.Sender == (common.Address{}) || state.Epoch != frame.BatchID || state.ReservedThrough == 0 ||
				state.Epoch != txQUICSenderEpoch(q.config.ChainID, q.config.GenesisHash, state.Sender) {
				return errors.New("invalid outbox WAL nonce projection")
			}
			nonces[string(txOutboxNonceKey(state.Sender, state.Epoch))] = state
			return nil
		}
		if frame.Kind == txIngressWALOutboxApplied {
			var payload txIngressWALOutboxAppliedPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return fmt.Errorf("decode applied outbox WAL mutation: %w", err)
			}
			mutation, ok := pendingOutboxMutations[payload.MutationID]
			if !ok || mutation.event.batchID != frame.BatchID {
				return errors.New("applied outbox WAL marker precedes or mismatches its mutation")
			}
			for eventID := range pendingOutboxMutationGroups[mutation.semantic] {
				delete(pendingOutboxMutations, eventID)
			}
			delete(pendingOutboxMutationGroups, mutation.semantic)
			return nil
		}
		if frame.Kind < txIngressWALOutboxEnqueued || frame.Kind > txIngressWALOutboxDeleted {
			return nil
		}
		var payload txIngressWALOutboxPayload
		if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
			return fmt.Errorf("decode outbox projection: %w", err)
		}
		if payload.Record.BatchID != frame.BatchID || payload.Record.BatchID == (common.Hash{}) {
			return errors.New("outbox WAL projection identity mismatch")
		}
		ownsPayload := frame.Kind == txIngressWALOutboxEnqueued || payload.Supersedes != (common.Hash{})
		if ownsPayload && (len(payload.Record.Payload) == 0 || txOutboxBatchID(payload.Record.Payload) != payload.Record.BatchID || payload.Record.CreatedAt == 0) {
			return errors.New("invalid outbox WAL projection record")
		}
		if ownsPayload {
			batch, _, err := decodeTxQUICBatch(payload.Record.Payload)
			if err != nil {
				return fmt.Errorf("decode outbox WAL batch: %w", err)
			}
			if batch.BatchID != payload.Record.BatchID || batch.ChainID != q.config.ChainID || batch.GenesisHash != q.config.GenesisHash {
				return errors.New("outbox WAL batch identity mismatch")
			}
			if err := q.verifyTxQUICBatchBlobSidecars(batch); err != nil {
				return fmt.Errorf("verify outbox WAL blob sidecars: %w", err)
			}
		}
		if frame.Kind == txIngressWALOutboxDeleted || (payload.Supersedes != (common.Hash{}) && payload.Supersedes != frame.BatchID) {
			semantic := txIngressWALOutboxMutationSemanticID(frame.Kind, frame.BatchID, frame.Payload)
			pendingOutboxMutations[frame.EventID] = txIngressWALCanonicalOutboxMutation{
				event: txIngressWALCanonicalEvent{
					kind: frame.Kind, batchID: frame.BatchID, eventID: frame.EventID,
					payload: append([]byte(nil), frame.Payload...),
				},
				sequence: frame.Sequence,
				semantic: semantic,
			}
			group := pendingOutboxMutationGroups[semantic]
			if group == nil {
				group = make(map[common.Hash]struct{})
				pendingOutboxMutationGroups[semantic] = group
			}
			group[frame.EventID] = struct{}{}
		}
		if payload.Supersedes != (common.Hash{}) && payload.Supersedes != payload.Record.BatchID {
			projection[payload.Supersedes] = txIngressWALOutboxProjection{deleted: true}
		}
		if frame.Kind == txIngressWALOutboxDeleted {
			projection[frame.BatchID] = txIngressWALOutboxProjection{deleted: true}
		} else if frame.Kind == txIngressWALOutboxState && !ownsPayload {
			current, ok := projection[frame.BatchID]
			if !ok || current.deleted || len(current.record.Payload) == 0 {
				return errors.New("outbox WAL state precedes its enqueue record")
			}
			current.record.Placement = cloneTxOutboxPlacementState(payload.Record.Placement)
			current.retry = payload.Retry
			projection[frame.BatchID] = current
		} else {
			projection[frame.BatchID] = txIngressWALOutboxProjection{record: payload.Record, retry: payload.Retry}
		}
		return nil
	}); err != nil {
		return err
	}
	ids := make([]common.Hash, 0, len(projection))
	for id := range projection {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	batch := q.outbox.db.NewBatch()
	flush := func() error {
		if batch.ValueSize() == 0 {
			return nil
		}
		if err := writeTxIngressWALSync(batch, "materialize outbox WAL projection"); err != nil {
			return err
		}
		batch.Reset()
		return nil
	}
	for _, id := range ids {
		state := projection[id]
		if state.deleted {
			if err := batch.Delete(txOutboxRecordKey(id)); err != nil {
				return err
			}
			if err := batch.Delete(txOutboxRetryKey(id)); err != nil {
				return err
			}
		} else {
			encodedRecord, err := rlp.EncodeToBytes(&state.record)
			if err != nil {
				return err
			}
			if err := batch.Put(txOutboxRecordKey(id), encodedRecord); err != nil {
				return err
			}
			if state.retry.Attempts == 0 && state.retry.NextRetry == 0 && state.retry.LastError == "" {
				if err := batch.Delete(txOutboxRetryKey(id)); err != nil {
					return err
				}
			} else {
				encodedRetry, err := rlp.EncodeToBytes(&state.retry)
				if err != nil {
					return err
				}
				if err := batch.Put(txOutboxRetryKey(id), encodedRetry); err != nil {
					return err
				}
			}
		}
		if batch.ValueSize() >= int(q.wal.maxGroupBytes) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	nonceKeys := make([]string, 0, len(nonces))
	for key := range nonces {
		nonceKeys = append(nonceKeys, key)
	}
	sort.Strings(nonceKeys)
	for _, key := range nonceKeys {
		state := nonces[key]
		encoded, err := rlp.EncodeToBytes(&state)
		if err != nil {
			return err
		}
		if err := batch.Put([]byte(key), encoded); err != nil {
			return err
		}
		if batch.ValueSize() >= int(q.wal.maxGroupBytes) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	// Only after the entire mutable projection is durable may compaction discard
	// delete/replacement evidence. If this append fails, replay fails closed and
	// the unmarked mutation remains the recovery authority on the next start.
	pendingMutations := make([]txIngressWALCanonicalOutboxMutation, 0, len(pendingOutboxMutations))
	for _, mutation := range pendingOutboxMutations {
		pendingMutations = append(pendingMutations, mutation)
	}
	sort.Slice(pendingMutations, func(i, j int) bool { return pendingMutations[i].sequence < pendingMutations[j].sequence })
	ctx := q.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for _, mutation := range pendingMutations {
		if err := q.wal.appendOutboxApplied(ctx, mutation.event.batchID, mutation.event.eventID); err != nil {
			return fmt.Errorf("confirm applied outbox WAL mutation %s: %w", mutation.event.eventID, err)
		}
	}
	return nil
}

type txIngressWALInboundProjection struct {
	packet  txQUICPacket
	outcome *txQUICAck
	applied bool
}

func txIngressWALPacketProjectionKey(packet *txQUICPacket) string {
	if packet == nil {
		return ""
	}
	key := make([]byte, common.HashLength+common.AddressLength+common.HashLength+8)
	copy(key, packet.BatchID[:])
	offset := common.HashLength
	copy(key[offset:], packet.Sender[:])
	offset += common.AddressLength
	copy(key[offset:], packet.SenderEpoch[:])
	binary.BigEndian.PutUint64(key[len(key)-8:], packet.Nonce)
	return string(key)
}

// replayWALInboundProjection materializes durable outcomes before the normal
// ingress restore publishes them. A received-only tail is safely resumed: its
// transaction becomes pool-visible only after the received record was fsynced.
func (q *TxQUICIngress) replayWALInboundProjection() error {
	if q == nil || q.wal == nil || q.ingress == nil {
		return nil
	}
	projection := make(map[string]txIngressWALInboundProjection)
	if err := q.wal.Replay(func(frame *txIngressWALFrame) error {
		switch frame.Kind {
		case txIngressWALInboundReceived:
			var payload txIngressWALInboundReceivedPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return err
			}
			if payload.Packet.BatchID != frame.BatchID {
				return errors.New("received WAL packet identity mismatch")
			}
			if _, err := newTxQUICAckExpectation(&payload.Packet); err != nil {
				return err
			}
			if err := q.verifyTxQUICPacketBlobSidecars(&payload.Packet); err != nil {
				return fmt.Errorf("verify inbound WAL blob sidecars: %w", err)
			}
			key := txIngressWALPacketProjectionKey(&payload.Packet)
			current := projection[key]
			current.packet = payload.Packet
			projection[key] = current
		case txIngressWALInboundOutcome:
			var payload txIngressWALInboundOutcomePayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return err
			}
			if payload.BatchID != frame.BatchID || payload.Sender == (common.Address{}) || payload.SenderEpoch == (common.Hash{}) || payload.Nonce == 0 {
				return errors.New("outcome WAL packet identity mismatch")
			}
			identity := txQUICPacket{BatchID: payload.BatchID, Sender: payload.Sender, SenderEpoch: payload.SenderEpoch, Nonce: payload.Nonce}
			key := txIngressWALPacketProjectionKey(&identity)
			current, ok := projection[key]
			if !ok {
				return errors.New("outcome WAL record precedes its received record")
			}
			expectation, err := newTxQUICAckExpectation(&current.packet)
			if err != nil {
				return err
			}
			if err := validateTxQUICAckOutcome(&payload.Ack, expectation); err != nil {
				return err
			}
			ack := payload.Ack
			current.outcome = &ack
			projection[key] = current
		case txIngressWALInboundApplied:
			var payload txIngressWALInboundAppliedPayload
			if err := rlp.DecodeBytes(frame.Payload, &payload); err != nil {
				return err
			}
			identity := txQUICPacket{BatchID: payload.BatchID, Sender: payload.Sender, SenderEpoch: payload.SenderEpoch, Nonce: payload.Nonce}
			key := txIngressWALPacketProjectionKey(&identity)
			current, ok := projection[key]
			if !ok || current.outcome == nil || payload.BatchID != frame.BatchID {
				return errors.New("applied WAL record precedes its inbound outcome")
			}
			current.applied = true
			projection[key] = current
		}
		return nil
	}); err != nil {
		return err
	}
	keys := make([]string, 0, len(projection))
	for key := range projection {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := projection[key]
		if entry.applied {
			continue
		}
		packet := &entry.packet
		ack := entry.outcome
		if ack == nil {
			if err := q.verifyAndStoreAdmissionCertificate(packet.Certificate, packet.Items, false); err != nil {
				return fmt.Errorf("resume received-only WAL admission %s: %w", packet.Certificate.AdmissionID, err)
			}
			computed := q.processTxQUICIngressPacketVerified(packet, nil)
			if err := q.wal.appendInboundOutcome(q.ctx, packet, computed); err != nil {
				return fmt.Errorf("resume received-only WAL outcome: %w", err)
			}
			ack = &computed
		}
		unlock := q.ingress.LockPacket(packet)
		_, err := q.ingress.StoreSyncLocked(q.ctx, packet, *ack)
		unlock()
		if err != nil {
			return fmt.Errorf("materialize inbound WAL outcome: %w", err)
		}
		if err := q.wal.appendInboundApplied(q.ctx, packet); err != nil {
			return fmt.Errorf("mark inbound WAL outcome materialized: %w", err)
		}
	}
	return nil
}

type txQUICLocalWALIntentSet struct {
	batches   []*txQUICBatch
	intentIDs []common.Hash
}

func (q *TxQUICIngress) persistVerifiedLocalTxsIntent(ctx context.Context, txs []*types.Transaction, admissions []core.CommonRPCAdmissionResult, am *accounts.Manager) (*txQUICLocalWALIntentSet, error) {
	if q == nil || q.wal == nil || !q.config.BridgeEnabled || q.outbox == nil {
		return nil, errors.New("unified local ingress WAL is unavailable")
	}
	if len(txs) == 0 || len(txs) != len(admissions) || len(txs) > txQUICMaxBridgeQueueItems {
		return nil, fmt.Errorf("invalid local ingress intent alignment: txs=%d admissions=%d", len(txs), len(admissions))
	}
	if am == nil {
		am = q.am
	}
	groups, err := q.txQUICBridgeGroups(txs, admissions, am, true)
	if err != nil {
		return nil, err
	}
	set := new(txQUICLocalWALIntentSet)
	var persistItems func(*types.CommonTxAdmissionBatch, []txQUICBridgeItem) error
	persistItems = func(certificate *types.CommonTxAdmissionBatch, bridgeItems []txQUICBridgeItem) error {
		items := make([]*txQUICItem, len(bridgeItems))
		for index, item := range bridgeItems {
			items[index] = &txQUICItem{AdmissionIndex: item.admissionIndex, Tx: item.tx, BlobSidecar: item.blobSidecar}
		}
		batch, _, err := newTxQUICBatch(q.config.ChainID, q.config.GenesisHash, certificate, items)
		if err != nil {
			return err
		}
		encoded, err := rlp.EncodeToBytes(batch)
		if err != nil {
			return err
		}
		if int64(len(encoded)) > q.durableBatchByteLimit() {
			if len(bridgeItems) == 1 {
				return fmt.Errorf("local ingress intent exceeds WAL micro-batch limit: size=%d limit=%d", len(encoded), q.durableBatchByteLimit())
			}
			middle := len(bridgeItems) / 2
			if err := persistItems(certificate, bridgeItems[:middle]); err != nil {
				return err
			}
			return persistItems(certificate, bridgeItems[middle:])
		}
		intentID, err := q.wal.appendLocalIntent(ctx, batch)
		if err != nil {
			return fmt.Errorf("persist local ingress intent: %w", err)
		}
		set.batches = append(set.batches, batch)
		set.intentIDs = append(set.intentIDs, intentID)
		return nil
	}
	for _, group := range groups {
		if err := persistItems(group.certificate, group.items); err != nil {
			return nil, err
		}
	}
	return set, nil
}

func (q *TxQUICIngress) completeVerifiedLocalTxsIntent(ctx context.Context, set *txQUICLocalWALIntentSet, accepted map[common.Hash]struct{}, am *accounts.Manager) error {
	if q == nil || q.wal == nil || q.outbox == nil || set == nil || len(set.batches) == 0 || len(set.batches) != len(set.intentIDs) {
		return errors.New("invalid local ingress WAL completion")
	}
	_ = am // retained for the internal API used by existing replay call sites
	for intentIndex, intent := range set.batches {
		if intent == nil || len(intent.Items) == 0 {
			return errors.New("invalid local ingress WAL intent batch")
		}
		bitmap := make([]byte, txQUICBitmapBytes(len(intent.Items)))
		for index, item := range intent.Items {
			if item == nil || item.Tx == nil {
				return fmt.Errorf("local ingress intent item %d is incomplete", index)
			}
			if _, ok := accepted[item.Tx.Hash()]; !ok {
				continue
			}
			txQUICBitmapSet(bitmap, index)
		}
		intentID := set.intentIDs[intentIndex]
		_, payload, err := txIngressWALAcceptedBatch(intent, bitmap)
		if err != nil {
			return err
		}
		appendOutcome := func(durableCtx context.Context) error {
			if err := q.wal.appendLocalOutcome(durableCtx, intent.BatchID, intentID, len(intent.Items), bitmap); err != nil {
				return fmt.Errorf("persist local ingress pool outcome: %w", err)
			}
			return nil
		}
		if len(payload) == 0 {
			if err := appendOutcome(ctx); err != nil {
				return err
			}
			continue
		}
		if _, err := q.outbox.storeLocalOutcomeVerifiedSync(ctx, payload, appendOutcome); err != nil {
			return err
		}
	}
	return nil
}

func (q *TxQUICIngress) replayWALLocalIntents() error {
	if q == nil || q.wal == nil || q.outbox == nil || q.txpool == nil {
		return nil
	}
	intents := make(map[common.Hash]*txQUICBatch)
	outcomes := make(map[common.Hash]txIngressWALLocalOutcomePayload)
	if err := q.wal.Replay(func(frame *txIngressWALFrame) error {
		switch frame.Kind {
		case txIngressWALLocalIntent:
			batch, _, err := decodeTxQUICBatch(frame.Payload)
			if err != nil {
				return err
			}
			if batch.BatchID != frame.BatchID {
				return errors.New("local ingress replay intent identity mismatch")
			}
			if err := q.verifyTxQUICBatchBlobSidecars(batch); err != nil {
				return fmt.Errorf("verify local ingress replay blob sidecars: %w", err)
			}
			intents[frame.EventID] = batch
		case txIngressWALLocalOutcome:
			var outcome txIngressWALLocalOutcomePayload
			if err := rlp.DecodeBytes(frame.Payload, &outcome); err != nil {
				return err
			}
			intent := intents[outcome.IntentID]
			if intent == nil || intent.BatchID != frame.BatchID || int(outcome.ItemCount) != len(intent.Items) {
				return errors.New("local ingress replay outcome identity mismatch")
			}
			outcomes[outcome.IntentID] = outcome
		}
		return nil
	}); err != nil {
		return err
	}
	ids := make([]common.Hash, 0, len(intents))
	for id := range intents {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	for _, id := range ids {
		intent := intents[id]
		replayIntent := intent
		outcome, completed := outcomes[id]
		if completed {
			accepted, _, err := txIngressWALAcceptedBatch(intent, outcome.AcceptedBitmap)
			if err != nil {
				return err
			}
			if accepted == nil {
				continue
			}
			keep := q.wal.recoverableLocalItems(accepted.Items)
			items := make([]*txQUICItem, 0, len(accepted.Items))
			for index, item := range accepted.Items {
				if keep[index] {
					items = append(items, item)
				}
			}
			if len(items) == 0 {
				continue
			}
			replayIntent = &txQUICBatch{
				ChainID: intent.ChainID, GenesisHash: intent.GenesisHash,
				Certificate: intent.Certificate, Items: items,
			}
		}
		if err := q.verifyAndStoreAdmissionCertificate(replayIntent.Certificate, replayIntent.Items, false); err != nil {
			return fmt.Errorf("restore local ingress admission %s: %w", intent.Certificate.AdmissionID, err)
		}
		txs, err := packetItemsToTxs(&txQUICPacket{Certificate: replayIntent.Certificate, Items: replayIntent.Items})
		if err != nil {
			return err
		}
		poolResults := q.txpool.AddLocalsAsync(txs)
		accepted := make(map[common.Hash]struct{}, len(txs))
		for index, tx := range txs {
			if index >= len(poolResults) {
				return errors.New("txpool omitted local ingress replay result")
			}
			if poolResults[index] == nil || errors.Is(poolResults[index], core.ErrAlreadyKnown) || errors.Is(poolResults[index], core.ErrNonceTooLow) {
				accepted[tx.Hash()] = struct{}{}
			}
		}
		if completed {
			continue
		}
		if err := q.completeVerifiedLocalTxsIntent(q.ctx, &txQUICLocalWALIntentSet{batches: []*txQUICBatch{intent}, intentIDs: []common.Hash{id}}, accepted, q.am); err != nil {
			return fmt.Errorf("complete restored local ingress intent %s: %w", id, err)
		}
	}
	return nil
}
