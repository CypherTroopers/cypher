package eth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cypherium/cypher/core/types"
)

// txPoolIngressSource identifies the two durability-qualified producers that
// may publish into the transaction pool. Separate FIFO queues and alternating
// dequeue priority prevent either RPC or QUIC bursts from starving the other.
type txPoolIngressSource uint8

const (
	txPoolIngressRPC txPoolIngressSource = iota
	txPoolIngressQUIC
	txPoolIngressSourceCount
)

type txPoolIngressTarget interface {
	AddLocalsAsync([]*types.Transaction) []error
	AddRemotes([]*types.Transaction) []error
}

type txPoolIngressSchedulerConfig struct {
	Workers  int
	MaxJobs  int
	MaxTxs   int
	MaxBytes int64
}

type txPoolIngressJob struct {
	source   txPoolIngressSource
	txs      []*types.Transaction
	bytes    int64
	response chan txPoolIngressResponse
}

type txPoolIngressResponse struct {
	results []error
	err     error
}

// txPoolIngressScheduler is owned by TxQUICIngress and therefore shared by
// every EthAPIBackend/RPC service and the live QUIC receiver on the node. It is
// intentionally downstream of the unified WAL. Startup replay bypasses it so
// recovery cannot deadlock behind live admission backpressure.
type txPoolIngressScheduler struct {
	target txPoolIngressTarget
	config txPoolIngressSchedulerConfig

	mu           sync.Mutex
	started      bool
	stopped      bool
	ctx          context.Context
	cancel       context.CancelFunc
	queues       [txPoolIngressSourceCount][]*txPoolIngressJob
	next         txPoolIngressSource
	pendingJobs  int
	pendingTxs   int
	pendingBytes int64
	capacityCh   chan struct{}
	workCh       chan struct{}
	wg           sync.WaitGroup
}

func newTxPoolIngressScheduler(target txPoolIngressTarget, config txPoolIngressSchedulerConfig) *txPoolIngressScheduler {
	if config.Workers <= 0 {
		config.Workers = 1
	}
	if config.MaxJobs < config.Workers {
		config.MaxJobs = config.Workers
	}
	if config.MaxTxs < config.MaxJobs {
		config.MaxTxs = config.MaxJobs
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = txQUICMicroBatchMaxWireBytes * int64(config.Workers)
	}
	return &txPoolIngressScheduler{
		target: target, config: config, next: txPoolIngressRPC,
		capacityCh: make(chan struct{}), workCh: make(chan struct{}, config.MaxJobs),
	}
}

func txPoolIngressSchedulerConfigFor(config TxQUICConfig) txPoolIngressSchedulerConfig {
	workers := minPositiveInt(config.IngressWorkers, txQUICMaxIngressWorkers)
	maxJobs := workers * 4
	if maxJobs > config.BridgeQueueSize {
		maxJobs = config.BridgeQueueSize
	}
	return txPoolIngressSchedulerConfig{
		Workers:  workers,
		MaxJobs:  maxJobs,
		MaxTxs:   config.BridgeQueueSize,
		MaxBytes: config.BridgeQueueMaxBytes,
	}
}

func (s *txPoolIngressScheduler) Start(parent context.Context) error {
	if s == nil || s.target == nil {
		return errors.New("transaction ingress scheduler target is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return errors.New("transaction ingress scheduler cannot be started")
	}
	if parent == nil {
		parent = context.Background()
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	s.started = true
	s.wg.Add(s.config.Workers)
	for worker := 0; worker < s.config.Workers; worker++ {
		go s.worker()
	}
	return nil
}

func (s *txPoolIngressScheduler) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	cancel := s.cancel
	queued := make([]*txPoolIngressJob, 0, s.pendingJobs)
	for source := txPoolIngressSource(0); source < txPoolIngressSourceCount; source++ {
		queued = append(queued, s.queues[source]...)
		s.queues[source] = nil
	}
	for _, job := range queued {
		s.pendingJobs--
		s.pendingTxs -= len(job.txs)
		s.pendingBytes -= job.bytes
	}
	s.signalCapacityLocked()
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	stopErr := errors.New("transaction ingress scheduler stopped before pool publication")
	for _, job := range queued {
		job.response <- txPoolIngressResponse{err: stopErr}
	}
	s.wg.Wait()
}

func txPoolIngressJobBytes(txs []*types.Transaction) (int64, error) {
	if len(txs) == 0 {
		return 0, errors.New("transaction ingress job is empty")
	}
	var total int64
	for index, tx := range txs {
		if tx == nil {
			return 0, fmt.Errorf("transaction ingress job item %d is nil", index)
		}
		size := uint64(tx.Size())
		if size == 0 || !addTxPoolIngressJobBytes(&total, size) {
			return 0, errors.New("transaction ingress job byte size overflow")
		}
		sidecar := tx.BlobSidecar()
		if sidecar == nil {
			continue
		}
		// Transaction.Size is the canonical execution envelope and deliberately
		// excludes EIP-4844 pooled sidecars. The live and pool schedulers retain
		// those bytes with the transaction, so charge all variable blob data and
		// fixed commitment/proof data before reserving node-global capacity.
		for _, blob := range sidecar.Blobs {
			if !addTxPoolIngressJobBytes(&total, uint64(len(blob))) {
				return 0, errors.New("transaction ingress job byte size overflow")
			}
		}
		if !addTxPoolIngressJobArrayBytes(&total, len(sidecar.Commitments), len(types.KZGCommitment{})) ||
			!addTxPoolIngressJobArrayBytes(&total, len(sidecar.Proofs), len(types.KZGProof{})) {
			return 0, errors.New("transaction ingress job byte size overflow")
		}
	}
	return total, nil
}

func addTxPoolIngressJobBytes(total *int64, amount uint64) bool {
	const maxInt64 = int64(^uint64(0) >> 1)
	if total == nil || *total < 0 || amount > uint64(maxInt64-*total) {
		return false
	}
	*total += int64(amount)
	return true
}

func addTxPoolIngressJobArrayBytes(total *int64, count int, itemBytes int) bool {
	if count < 0 || itemBytes < 0 {
		return false
	}
	if count == 0 || itemBytes == 0 {
		return true
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if total == nil || *total < 0 || uint64(count) > uint64(maxInt64-*total)/uint64(itemBytes) {
		return false
	}
	*total += int64(uint64(count) * uint64(itemBytes))
	return true
}

// Submit blocks for bounded capacity. Once queued, publication belongs to the
// node even if the caller stops waiting; its buffered response keeps workers
// independent from an abandoned RPC or QUIC stream.
func (s *txPoolIngressScheduler) Submit(ctx context.Context, source txPoolIngressSource, txs []*types.Transaction) ([]error, error) {
	if s == nil || source >= txPoolIngressSourceCount {
		return nil, errors.New("invalid transaction ingress scheduler submission")
	}
	bytes, err := txPoolIngressJobBytes(txs)
	if err != nil {
		return nil, err
	}
	if len(txs) > s.config.MaxTxs || bytes > s.config.MaxBytes {
		return nil, fmt.Errorf("transaction ingress job exceeds scheduler capacity: txs=%d/%d bytes=%d/%d", len(txs), s.config.MaxTxs, bytes, s.config.MaxBytes)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	job := &txPoolIngressJob{
		source: source, txs: append([]*types.Transaction(nil), txs...), bytes: bytes,
		response: make(chan txPoolIngressResponse, 1),
	}
	for {
		s.mu.Lock()
		if err := s.runningErrLocked(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if s.hasCapacityLocked(len(job.txs), job.bytes) {
			s.queues[source] = append(s.queues[source], job)
			s.pendingJobs++
			s.pendingTxs += len(job.txs)
			s.pendingBytes += job.bytes
			s.workCh <- struct{}{}
			storeDone := s.ctx.Done()
			s.mu.Unlock()
			select {
			case response := <-job.response:
				return response.results, response.err
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-storeDone:
				return nil, errors.New("transaction ingress scheduler stopped during pool publication")
			}
		}
		changed := s.capacityCh
		storeDone := s.ctx.Done()
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-storeDone:
			return nil, errors.New("transaction ingress scheduler stopped while waiting for capacity")
		}
	}
}

func (s *txPoolIngressScheduler) runningErrLocked() error {
	if !s.started || s.stopped || s.ctx == nil {
		return errors.New("transaction ingress scheduler is not running")
	}
	return nil
}

func (s *txPoolIngressScheduler) hasCapacityLocked(txs int, bytes int64) bool {
	return s.pendingJobs < s.config.MaxJobs &&
		s.pendingTxs <= s.config.MaxTxs-txs &&
		s.pendingBytes <= s.config.MaxBytes-bytes
}

func (s *txPoolIngressScheduler) signalCapacityLocked() {
	close(s.capacityCh)
	s.capacityCh = make(chan struct{})
}

func (s *txPoolIngressScheduler) dequeueLocked() *txPoolIngressJob {
	first := s.next
	second := txPoolIngressRPC
	if first == txPoolIngressRPC {
		second = txPoolIngressQUIC
	}
	selected := first
	if len(s.queues[selected]) == 0 {
		selected = second
	}
	if len(s.queues[selected]) == 0 {
		return nil
	}
	job := s.queues[selected][0]
	s.queues[selected][0] = nil
	if len(s.queues[selected]) == 1 {
		s.queues[selected] = nil
	} else {
		s.queues[selected] = s.queues[selected][1:]
	}
	if selected == txPoolIngressRPC {
		s.next = txPoolIngressQUIC
	} else {
		s.next = txPoolIngressRPC
	}
	return job
}

func (s *txPoolIngressScheduler) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.workCh:
		}
		s.mu.Lock()
		job := s.dequeueLocked()
		s.mu.Unlock()
		if job == nil {
			continue
		}
		results := s.execute(job)
		s.mu.Lock()
		s.pendingJobs--
		s.pendingTxs -= len(job.txs)
		s.pendingBytes -= job.bytes
		s.signalCapacityLocked()
		s.mu.Unlock()
		job.response <- txPoolIngressResponse{results: results}
	}
}

func (s *txPoolIngressScheduler) execute(job *txPoolIngressJob) (results []error) {
	results = make([]error, len(job.txs))
	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("transaction ingress pool publication panicked: %v", recovered)
			for index := range results {
				results[index] = err
			}
		}
	}()
	var returned []error
	if job.source == txPoolIngressRPC {
		returned = s.target.AddLocalsAsync(job.txs)
	} else {
		returned = s.target.AddRemotes(job.txs)
	}
	for index := range results {
		if index < len(returned) {
			results[index] = returned[index]
		} else {
			results[index] = errors.New("transaction pool omitted ingress result")
		}
	}
	return results
}
