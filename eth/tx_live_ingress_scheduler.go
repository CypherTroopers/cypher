package eth

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// txLiveIngressScheduler bounds the complete live admission pipeline before
// either RPC or QUIC can consume signature, WAL, admission-index, TxPool, or
// outbox resources. It is deliberately separate from txPoolIngressScheduler:
// a live lease remains held while a request waits for pool publication, so
// sharing the same worker queue would create a self-deadlock.
type txLiveIngressScheduler struct {
	config txLiveIngressSchedulerConfig

	mu             sync.Mutex
	started        bool
	stopped        bool
	queues         [txPoolIngressSourceCount][]*txLiveIngressRequest
	next           txPoolIngressSource
	activeJobs     int
	activeTxs      int
	activeBytes    int64
	pendingJobs    int
	pendingTxs     int
	pendingBytes   int64
	capacityChange chan struct{}
	stopCh         chan struct{}
}

type txLiveIngressSchedulerConfig struct {
	MaxActiveJobs   int
	MaxActiveTxs    int
	MaxActiveBytes  int64
	MaxPendingJobs  int
	MaxPendingTxs   int
	MaxPendingBytes int64
}

type txLiveIngressRequest struct {
	source  txPoolIngressSource
	txs     int
	bytes   int64
	granted bool
	ready   chan struct{}
}

func newTxLiveIngressScheduler(config txLiveIngressSchedulerConfig) *txLiveIngressScheduler {
	if config.MaxActiveJobs <= 0 {
		config.MaxActiveJobs = 1
	}
	if config.MaxActiveTxs < config.MaxActiveJobs {
		config.MaxActiveTxs = config.MaxActiveJobs
	}
	if config.MaxActiveBytes <= 0 {
		config.MaxActiveBytes = txQUICMicroBatchMaxWireBytes
	}
	if config.MaxPendingJobs < config.MaxActiveJobs {
		config.MaxPendingJobs = config.MaxActiveJobs
	}
	if config.MaxPendingTxs < config.MaxActiveTxs {
		config.MaxPendingTxs = config.MaxActiveTxs
	}
	if config.MaxPendingBytes < config.MaxActiveBytes {
		config.MaxPendingBytes = config.MaxActiveBytes
	}
	return &txLiveIngressScheduler{
		config:         config,
		next:           txPoolIngressRPC,
		capacityChange: make(chan struct{}),
		stopCh:         make(chan struct{}),
	}
}

func txLiveIngressSchedulerConfigFor(config TxQUICConfig) txLiveIngressSchedulerConfig {
	activeJobs := minPositiveInt(config.IngressWorkers, txQUICMaxIngressWorkers)
	activeTxs := activeJobs * txQUICMicroBatchMaxTxs
	activeBytes := config.MaxInflightPayloadBytes
	if activeBytes <= 0 {
		activeBytes = int64(activeJobs) * txQUICMicroBatchMaxWireBytes
	}
	pendingJobs := activeJobs * 4
	pendingTxs := config.BridgeQueueSize
	if pendingTxs < activeTxs {
		pendingTxs = activeTxs
	}
	pendingBytes := config.BridgeQueueMaxBytes
	if pendingBytes < activeBytes {
		pendingBytes = activeBytes
	}
	return txLiveIngressSchedulerConfig{
		MaxActiveJobs: activeJobs, MaxActiveTxs: activeTxs, MaxActiveBytes: activeBytes,
		MaxPendingJobs: pendingJobs, MaxPendingTxs: pendingTxs, MaxPendingBytes: pendingBytes,
	}
}

func (s *txLiveIngressScheduler) Start() error {
	if s == nil {
		return errors.New("live transaction ingress scheduler is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return errors.New("live transaction ingress scheduler cannot be started")
	}
	s.started = true
	return nil
}

func (s *txLiveIngressScheduler) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	for source := txPoolIngressSource(0); source < txPoolIngressSourceCount; source++ {
		for index := range s.queues[source] {
			s.queues[source][index] = nil
		}
		s.queues[source] = nil
	}
	s.pendingJobs = s.activeJobs
	s.pendingTxs = s.activeTxs
	s.pendingBytes = s.activeBytes
	s.signalCapacityLocked()
	close(s.stopCh)
	s.mu.Unlock()
}

// Acquire reserves one fair, node-global live-admission lease. pending counts
// include active work, so an authenticated flood cannot create an unbounded
// goroutine queue while all workers are saturated.
func (s *txLiveIngressScheduler) Acquire(ctx context.Context, source txPoolIngressSource, txs int, bytes int64) (func(), error) {
	if s == nil || source >= txPoolIngressSourceCount || txs <= 0 || bytes <= 0 {
		return nil, errors.New("invalid live transaction ingress request")
	}
	if txs > s.config.MaxActiveTxs || bytes > s.config.MaxActiveBytes {
		return nil, fmt.Errorf("live transaction ingress request exceeds active capacity: txs=%d/%d bytes=%d/%d", txs, s.config.MaxActiveTxs, bytes, s.config.MaxActiveBytes)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request := &txLiveIngressRequest{source: source, txs: txs, bytes: bytes, ready: make(chan struct{})}
	for {
		s.mu.Lock()
		if err := s.runningErrLocked(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if s.hasPendingCapacityLocked(txs, bytes) {
			s.queues[source] = append(s.queues[source], request)
			s.pendingJobs++
			s.pendingTxs += txs
			s.pendingBytes += bytes
			s.dispatchLocked()
			stopCh := s.stopCh
			s.mu.Unlock()
			select {
			case <-request.ready:
				return s.releaseFunc(request), nil
			case <-ctx.Done():
				s.mu.Lock()
				if request.granted {
					s.mu.Unlock()
					return s.releaseFunc(request), nil
				}
				s.removeQueuedLocked(request)
				s.mu.Unlock()
				return nil, ctx.Err()
			case <-stopCh:
				s.mu.Lock()
				if request.granted {
					s.mu.Unlock()
					return s.releaseFunc(request), nil
				}
				s.mu.Unlock()
				return nil, errors.New("live transaction ingress scheduler stopped while waiting")
			}
		}
		changed := s.capacityChange
		stopCh := s.stopCh
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-stopCh:
			return nil, errors.New("live transaction ingress scheduler stopped before enqueue")
		}
	}
}

func (s *txLiveIngressScheduler) runningErrLocked() error {
	if !s.started || s.stopped {
		return errors.New("live transaction ingress scheduler is not running")
	}
	return nil
}

func (s *txLiveIngressScheduler) hasPendingCapacityLocked(txs int, bytes int64) bool {
	return s.pendingJobs < s.config.MaxPendingJobs &&
		s.pendingTxs <= s.config.MaxPendingTxs-txs &&
		s.pendingBytes <= s.config.MaxPendingBytes-bytes
}

func (s *txLiveIngressScheduler) canActivateLocked(request *txLiveIngressRequest) bool {
	return request != nil && s.activeJobs < s.config.MaxActiveJobs &&
		s.activeTxs <= s.config.MaxActiveTxs-request.txs &&
		s.activeBytes <= s.config.MaxActiveBytes-request.bytes
}

func (s *txLiveIngressScheduler) dispatchLocked() {
	for s.activeJobs < s.config.MaxActiveJobs {
		first := s.next
		second := txPoolIngressRPC
		if first == txPoolIngressRPC {
			second = txPoolIngressQUIC
		}
		selected := txPoolIngressSourceCount
		for _, source := range []txPoolIngressSource{first, second} {
			if len(s.queues[source]) > 0 && s.canActivateLocked(s.queues[source][0]) {
				selected = source
				break
			}
		}
		if selected == txPoolIngressSourceCount {
			return
		}
		request := s.queues[selected][0]
		s.queues[selected][0] = nil
		s.queues[selected] = s.queues[selected][1:]
		request.granted = true
		s.activeJobs++
		s.activeTxs += request.txs
		s.activeBytes += request.bytes
		if selected == txPoolIngressRPC {
			s.next = txPoolIngressQUIC
		} else {
			s.next = txPoolIngressRPC
		}
		close(request.ready)
	}
}

func (s *txLiveIngressScheduler) removeQueuedLocked(request *txLiveIngressRequest) {
	queue := s.queues[request.source]
	for index, queued := range queue {
		if queued != request {
			continue
		}
		copy(queue[index:], queue[index+1:])
		queue[len(queue)-1] = nil
		s.queues[request.source] = queue[:len(queue)-1]
		s.pendingJobs--
		s.pendingTxs -= request.txs
		s.pendingBytes -= request.bytes
		s.signalCapacityLocked()
		s.dispatchLocked()
		return
	}
}

func (s *txLiveIngressScheduler) releaseFunc(request *txLiveIngressRequest) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.activeJobs--
			s.activeTxs -= request.txs
			s.activeBytes -= request.bytes
			s.pendingJobs--
			s.pendingTxs -= request.txs
			s.pendingBytes -= request.bytes
			s.signalCapacityLocked()
			if !s.stopped {
				s.dispatchLocked()
			}
			s.mu.Unlock()
		})
	}
}

func (s *txLiveIngressScheduler) signalCapacityLocked() {
	close(s.capacityChange)
	s.capacityChange = make(chan struct{})
}
