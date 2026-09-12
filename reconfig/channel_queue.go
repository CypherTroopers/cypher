package reconfig

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet/network"
)

const (
	hotstuffQueueInputCapacity      = 64
	hotstuffPriorityInputCapacity   = 32
	hotstuffQueueMaxEntries         = 4096
	hotstuffPriorityQueueMaxEntries = 256
	hotstuffQueueMaxBytes           = 64 * 1024 * 1024
	hotstuffPriorityQueueMaxBytes   = 8 * 1024 * 1024
	hotstuffQueueProducerWait       = 100 * time.Millisecond
	hotstuffQueueEntryOverheadBytes = 256
	// A lagging replica can receive several certified views from the same
	// authenticated leader while asynchronous body/state validation catches up.
	// Eight entries proved too small in a normal two-chain catch-up and allowed
	// a QCBroadcast to be dropped. Thirty-two still reserves capacity for every
	// member of the maximum 100-node committee (3,200 < 4,096 global entries).
	hotstuffQueuePerSenderEntries = 32
	hotstuffQueuePerSenderBytes   = 640 * 1024
	hotstuffQueueRecentDigestMax  = 4096
	hotstuffQueueReplayTTL        = 5 * time.Second
)

// hotstuffMessageQueue serializes all producers through one channel-owned,
// strictly bounded queue. Local liveness and self-delivery messages use a
// priority lane so they cannot sit behind a remote flood. Once a lane is full,
// producers receive bounded backpressure and then fail rather than growing an
// unbounded slice or leaking blocked network goroutines.
type hotstuffMessageQueue struct {
	input         chan hotstuffQueueEntry
	priorityInput chan *hotstuffMsg
	next          chan *hotstuffMsg

	admissionMu    sync.Mutex
	pendingDigests map[[32]byte]struct{}
	recentDigests  map[[32]byte]time.Time
	recentOrder    []hotstuffRecentDigest
	senderEntries  map[string]int
	senderBytes    map[string]int
	pendingEntries int
	pendingBytes   int
}

type hotstuffRecentDigest struct {
	digest  [32]byte
	expires time.Time
}

type hotstuffQueueEntry struct {
	msg    *hotstuffMsg
	bytes  int
	sender string
	digest [32]byte
	remote bool
}

func newHotstuffMessageQueue() *hotstuffMessageQueue {
	q := &hotstuffMessageQueue{
		input:          make(chan hotstuffQueueEntry, hotstuffQueueInputCapacity),
		priorityInput:  make(chan *hotstuffMsg, hotstuffPriorityInputCapacity),
		next:           make(chan *hotstuffMsg),
		pendingDigests: make(map[[32]byte]struct{}),
		recentDigests:  make(map[[32]byte]time.Time),
		senderEntries:  make(map[string]int),
		senderBytes:    make(map[string]int),
	}
	go q.run()
	return q
}

func (q *hotstuffMessageQueue) purgeRecentLocked(now time.Time) {
	for len(q.recentOrder) > 0 {
		oldest := q.recentOrder[0]
		current, exists := q.recentDigests[oldest.digest]
		if exists && current == oldest.expires && now.Before(current) && len(q.recentDigests) <= hotstuffQueueRecentDigestMax {
			break
		}
		q.recentOrder[0] = hotstuffRecentDigest{}
		q.recentOrder = q.recentOrder[1:]
		if exists && current == oldest.expires && (!now.Before(current) || len(q.recentDigests) > hotstuffQueueRecentDigestMax) {
			delete(q.recentDigests, oldest.digest)
		}
	}
}

func hotstuffQueueSender(msg *hotstuffMsg) string {
	if msg != nil && msg.sid != nil {
		return msg.sid.Address.String()
	}
	if msg != nil && msg.hMsg != nil && msg.hMsg.Id != "" {
		return msg.hMsg.Id
	}
	return "local"
}

func hotstuffQueueDigest(msg *hotstuffMsg, sender string) ([32]byte, bool) {
	if msg == nil || msg.hMsg == nil {
		return [32]byte{}, false
	}
	canonical := *msg.hMsg
	canonical.ReceivedAt = time.Time{}
	encoded, err := rlp.EncodeToBytes(&canonical)
	if err != nil {
		return [32]byte{}, false
	}
	payload := make([]byte, 0, len(sender)+1+len(encoded))
	payload = append(payload, sender...)
	payload = append(payload, 0)
	payload = append(payload, encoded...)
	return sha256.Sum256(payload), true
}

// reserveNormal accounts for messages before they enter the shared input
// channel. This prevents one authenticated Byzantine peer from occupying the
// channel buffer and preserves capacity for every other committee member.
func (q *hotstuffMessageQueue) reserveNormal(msg *hotstuffMsg) (hotstuffQueueEntry, bool) {
	entry := hotstuffQueueEntry{msg: msg, bytes: queuedHotstuffMessageBytes(msg), sender: hotstuffQueueSender(msg), remote: msg != nil && msg.sid != nil}
	if entry.bytes > hotstuffQueueMaxBytes || (entry.remote && entry.bytes > hotstuffQueuePerSenderBytes) {
		return hotstuffQueueEntry{}, false
	}
	if entry.remote {
		digest, ok := hotstuffQueueDigest(msg, entry.sender)
		if !ok {
			return hotstuffQueueEntry{}, false
		}
		entry.digest = digest
	}

	q.admissionMu.Lock()
	defer q.admissionMu.Unlock()
	now := time.Now()
	q.purgeRecentLocked(now)
	if q.pendingEntries >= hotstuffQueueMaxEntries || q.pendingBytes+entry.bytes > hotstuffQueueMaxBytes {
		return hotstuffQueueEntry{}, false
	}
	if entry.remote {
		if _, duplicate := q.pendingDigests[entry.digest]; duplicate {
			return hotstuffQueueEntry{}, false
		}
		if expires, replay := q.recentDigests[entry.digest]; replay && now.Before(expires) {
			return hotstuffQueueEntry{}, false
		}
		if q.senderEntries[entry.sender] >= hotstuffQueuePerSenderEntries ||
			q.senderBytes[entry.sender]+entry.bytes > hotstuffQueuePerSenderBytes {
			return hotstuffQueueEntry{}, false
		}
		q.pendingDigests[entry.digest] = struct{}{}
		q.senderEntries[entry.sender]++
		q.senderBytes[entry.sender] += entry.bytes
	}
	q.pendingEntries++
	q.pendingBytes += entry.bytes
	return entry, true
}

func (q *hotstuffMessageQueue) releaseNormal(entry hotstuffQueueEntry, processed bool) {
	q.admissionMu.Lock()
	defer q.admissionMu.Unlock()
	if entry.remote {
		delete(q.pendingDigests, entry.digest)
		if processed {
			expires := time.Now().Add(hotstuffQueueReplayTTL)
			q.recentDigests[entry.digest] = expires
			q.recentOrder = append(q.recentOrder, hotstuffRecentDigest{digest: entry.digest, expires: expires})
			q.purgeRecentLocked(time.Now())
		}
		if q.senderEntries[entry.sender] <= 1 {
			delete(q.senderEntries, entry.sender)
		} else {
			q.senderEntries[entry.sender]--
		}
		if q.senderBytes[entry.sender] <= entry.bytes {
			delete(q.senderBytes, entry.sender)
		} else {
			q.senderBytes[entry.sender] -= entry.bytes
		}
	}
	if q.pendingEntries > 0 {
		q.pendingEntries--
	}
	q.pendingBytes -= entry.bytes
	if q.pendingBytes < 0 {
		q.pendingBytes = 0
	}
}

func queuedHotstuffMessageBytes(msg *hotstuffMsg) int {
	if msg == nil || msg.hMsg == nil {
		return hotstuffQueueEntryOverheadBytes
	}
	h := msg.hMsg
	total := hotstuffQueueEntryOverheadBytes + len(h.Id) + len(h.PubKey) + len(h.AuthSig)
	for _, field := range [][]byte{h.DataA, h.DataB, h.DataC, h.DataD, h.DataE, h.DataF, h.DataG} {
		total += len(field)
	}
	return total
}

func (q *hotstuffMessageQueue) run() {
	priorityQueue := make([]hotstuffQueueEntry, 0, 64)
	queue := make([]hotstuffQueueEntry, 0, 256)
	priorityBytes, normalBytes := 0, 0
	for {
		var priorityIn <-chan *hotstuffMsg
		if len(priorityQueue) < hotstuffPriorityQueueMaxEntries && priorityBytes < hotstuffPriorityQueueMaxBytes {
			priorityIn = q.priorityInput
		}
		var normalIn <-chan hotstuffQueueEntry
		if len(queue) < hotstuffQueueMaxEntries && normalBytes < hotstuffQueueMaxBytes {
			normalIn = q.input
		}

		// Drain one already-buffered priority input before considering normal
		// traffic. The cap checks above keep this preference memory-bounded.
		if priorityIn != nil {
			select {
			case msg := <-priorityIn:
				if msg != nil {
					size := queuedHotstuffMessageBytes(msg)
					priorityQueue = append(priorityQueue, hotstuffQueueEntry{msg: msg, bytes: size})
					priorityBytes += size
				}
				continue
			default:
			}
		}

		var out chan *hotstuffMsg
		var next *hotstuffMsg
		usePriority := len(priorityQueue) > 0
		if usePriority {
			out = q.next
			next = priorityQueue[0].msg
		} else if len(queue) > 0 {
			out = q.next
			next = queue[0].msg
		}
		select {
		case msg := <-priorityIn:
			if msg != nil {
				size := queuedHotstuffMessageBytes(msg)
				priorityQueue = append(priorityQueue, hotstuffQueueEntry{msg: msg, bytes: size})
				priorityBytes += size
			}
		case entry := <-normalIn:
			if entry.msg != nil {
				queue = append(queue, entry)
				normalBytes += entry.bytes
			}
		case out <- next:
			if usePriority {
				priorityBytes -= priorityQueue[0].bytes
				priorityQueue[0] = hotstuffQueueEntry{}
				priorityQueue = priorityQueue[1:]
			} else {
				normalBytes -= queue[0].bytes
				q.releaseNormal(queue[0], true)
				queue[0] = hotstuffQueueEntry{}
				queue = queue[1:]
			}
		}
	}
}

func pushHotstuffWithTimeout(ch chan<- *hotstuffMsg, msg *hotstuffMsg) bool {
	if msg == nil {
		return false
	}
	timer := time.NewTimer(hotstuffQueueProducerWait)
	defer timer.Stop()
	select {
	case ch <- msg:
		return true
	case <-timer.C:
		return false
	}
}

func pushHotstuffEntryWithTimeout(ch chan<- hotstuffQueueEntry, entry hotstuffQueueEntry) bool {
	timer := time.NewTimer(hotstuffQueueProducerWait)
	defer timer.Stop()
	select {
	case ch <- entry:
		return true
	case <-timer.C:
		return false
	}
}

func (q *hotstuffMessageQueue) push(msg *hotstuffMsg) bool {
	if q == nil {
		return false
	}
	entry, ok := q.reserveNormal(msg)
	if !ok {
		return false
	}
	if pushHotstuffEntryWithTimeout(q.input, entry) {
		return true
	}
	q.releaseNormal(entry, false)
	return false
}

func (q *hotstuffMessageQueue) pushPriority(msg *hotstuffMsg) bool {
	return q != nil && pushHotstuffWithTimeout(q.priorityInput, msg)
}

const (
	// Two workers are deliberate: the active view can start while one superseded
	// execution unwinds from the non-interruptible EVM. The latest-wins queue below
	// retains only the newest waiting view, so repeated view changes cannot drop
	// the current Prepare or create unbounded validation CPU/memory pressure.
	proposalValidationWorkers       = 2
	proposalValidationQueueCapacity = 1
	// Proposal construction uses a separate scheduler from validator execution.
	// A superseded EVM run is not immediately interruptible, so two workers let the
	// newest view start while one stale build unwinds. Only one latest waiting job
	// is retained and publication is independently serialized on the HotStuff loop.
	proposalBuildWorkers             = 2
	proposalBuildQueueCapacity       = 1
	proposalManifestDispatchCapacity = 8
	proposalManifestDispatchWorkers  = 4
	proposalFailedTxCleanupCapacity  = 8
)

type hotstuffMsg struct {
	sid   *network.ServerIdentity
	lastN uint64
	hMsg  *hotstuff.HotstuffMessage
}

type proposalValidationJob struct {
	request              *hotstuff.FHSProposalValidationRequest
	highQCRequest        *hotstuff.FHSHighQCValidationRequest
	parentVerified       *core.VerifiedProposal
	ctx                  context.Context
	cancel               context.CancelFunc
	serviceGeneration    uint64
	validationGeneration uint64
}

type proposalValidationControl struct {
	key        hotstuff.FHSProposalValidationKey
	keyHash    common.Hash
	generation uint64
	cancel     context.CancelFunc
}

type proposalBuildJob struct {
	request                *hotstuff.FHSProposalBuildRequest
	ctx                    context.Context
	cancel                 context.CancelFunc
	serviceGeneration      uint64
	constructionGeneration uint64
}

type proposalBuildControl struct {
	key        hotstuff.FHSProposalBuildKey
	generation uint64
	cancel     context.CancelFunc
}

type proposalManifestDispatch struct {
	body              *proposalBodyMsg
	destinations      []string
	serviceGeneration uint64
}

type proposalFailedTxCleanup struct {
	txs               types.Transactions
	serviceGeneration uint64
}

type proposalBodyAuthority struct {
	key     hotstuff.FHSProposalValidationKey
	keyHash common.Hash
}

type highQCValidationControl struct {
	key         hotstuff.FHSHighQCValidationKey
	qcNumber    uint64
	generation  uint64
	resultReady bool
	applied     bool
	cancel      context.CancelFunc
	authorized  map[common.Hash]proposalBodyAuthority
}

func (s *Service) ScheduleFHSProposalValidation(request *hotstuff.FHSProposalValidationRequest) error {
	if request == nil || request.Key.ProposalID == (common.Hash{}) || len(request.ProposalRef) == 0 || s.proposalValidationJobs == nil {
		return fmt.Errorf("invalid FHS proposal validation request")
	}
	cloned := &hotstuff.FHSProposalValidationRequest{
		Key:         request.Key,
		ProposalRef: append([]byte(nil), request.ProposalRef...),
		Extra:       append([]byte(nil), request.Extra...),
		ParentQC:    hotstuff.CloneSignedState(request.ParentQC),
	}
	ref, err := types.DecodeHotstuffProposalRef(cloned.ProposalRef)
	if err != nil || ref.ProposalID() != cloned.Key.ProposalID {
		return fmt.Errorf("invalid FHS proposal validation reference")
	}
	serviceGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	if atomic.LoadInt32(&s.runningState) != 1 || serviceGeneration == 0 {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	parentVerified := s.snapshotFHSCertifiedVerified(ref.ParentHash)

	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	// A manager-owned HighQC worker must outlive ordinary view cleanup. The
	// Prepare that depends on it is already retained as a manager continuation;
	// reject this direct scheduling attempt without cancelling or draining the
	// shared queue, then let the HighQC result replay the exact Prepare.
	activeHighQC := s.activeHighQCValidation
	if active := activeHighQC; active != nil && !active.applied {
		return hotstuff.ErrProposalValidationPending
	}
	if active := s.activeProposalValidation; active != nil {
		if active.key.ViewNumber > cloned.Key.ViewNumber {
			return hotstuff.ErrOldState
		}
		if active.key == cloned.Key {
			return nil
		}
	}
	s.cancelProposalValidationLocked()
	for {
		select {
		case stale := <-s.proposalValidationJobs:
			if stale != nil && stale.highQCRequest != nil {
				// An applied HighQC normally has no queued worker, but preserve the
				// manager-owned job if result publication and queue observation race.
				select {
				case s.proposalValidationJobs <- stale:
					return hotstuff.ErrProposalValidationPending
				default:
					return fmt.Errorf("FHS proposal scheduler could not preserve HighQC work")
				}
			}
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			goto queueDrained
		}
	}

queueDrained:
	s.proposalValidationSeq++
	if s.proposalValidationSeq == 0 {
		s.proposalValidationSeq++
	}
	validationGeneration := s.proposalValidationSeq
	ctx, cancel := context.WithCancel(context.Background())
	job := &proposalValidationJob{
		request:              cloned,
		parentVerified:       parentVerified,
		ctx:                  ctx,
		cancel:               cancel,
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}
	s.activeProposalValidation = &proposalValidationControl{
		key:        cloned.Key,
		keyHash:    ref.KeyHash,
		generation: validationGeneration,
		cancel:     cancel,
	}
	select {
	case s.proposalValidationJobs <- job:
		return nil
	default:
		s.activeProposalValidation = nil
		cancel()
		return fmt.Errorf("FHS proposal validation scheduler invariant failed")
	}
}

func (s *Service) ScheduleFHSHighQCValidation(request *hotstuff.FHSHighQCValidationRequest) error {
	if request == nil || request.QC == nil || request.Key.RequestID == 0 || request.Key.QCID == (common.Hash{}) ||
		request.Key.TargetView == 0 || s.proposalValidationJobs == nil {
		return fmt.Errorf("invalid FHS HighQC validation request")
	}
	id, err := hotstuff.SignedStateID(request.QC)
	if err != nil || id.Hash() != request.Key.QCID || request.Key.TargetView <= request.QC.Number {
		return fmt.Errorf("invalid FHS HighQC validation identity")
	}
	cloned := &hotstuff.FHSHighQCValidationRequest{Key: request.Key, QC: hotstuff.CloneSignedState(request.QC)}
	serviceGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	if atomic.LoadInt32(&s.runningState) != 1 || serviceGeneration == 0 {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}

	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	// Preflight semantic certificate order before touching the running worker.
	// TargetView is only continuation metadata and must never make the same QC
	// cancel/restart identical body and EVM validation work.
	previousHighQC := s.activeHighQCValidation
	if active := previousHighQC; active != nil {
		if active.key == cloned.Key {
			return nil
		}
		if active.key.QCID == cloned.Key.QCID {
			if !active.resultReady {
				return hotstuff.ErrProposalValidationPending
			}
		} else if active.qcNumber >= cloned.QC.Number && !cloned.Key.SelectProposalParent && !active.applied {
			return hotstuff.ErrOldState
		}
	}
	if active := s.activeProposalValidation; active != nil {
		if active.key.ViewNumber > cloned.Key.TargetView {
			return hotstuff.ErrOldState
		}
	}
	// Temporarily remove queued jobs without cancelling them. The new semantic
	// QC must be enqueued successfully before any manager-owned work is stopped.
	var displaced []*proposalValidationJob
	for {
		select {
		case stale := <-s.proposalValidationJobs:
			if stale != nil {
				displaced = append(displaced, stale)
			}
		default:
			goto highQCQueueDrained
		}
	}

highQCQueueDrained:
	s.proposalValidationSeq++
	if s.proposalValidationSeq == 0 {
		s.proposalValidationSeq++
	}
	validationGeneration := s.proposalValidationSeq
	ctx, cancel := context.WithCancel(context.Background())
	job := &proposalValidationJob{
		highQCRequest:        cloned,
		ctx:                  ctx,
		cancel:               cancel,
		serviceGeneration:    serviceGeneration,
		validationGeneration: validationGeneration,
	}
	newControl := &highQCValidationControl{
		key: cloned.Key, qcNumber: cloned.QC.Number, generation: validationGeneration, cancel: cancel,
		authorized: make(map[common.Hash]proposalBodyAuthority),
	}
	select {
	case s.proposalValidationJobs <- job:
		// Publication into the bounded queue is the replacement linearization
		// point. Only now may the previous semantic QC and proposal jobs stop.
		s.activeHighQCValidation = newControl
		if previousHighQC != nil && previousHighQC.cancel != nil {
			previousHighQC.cancel()
		}
		s.cancelProposalValidationLocked()
		for _, stale := range displaced {
			if stale.cancel != nil {
				stale.cancel()
			}
		}
		return nil
	default:
		cancel()
		for _, stale := range displaced {
			select {
			case s.proposalValidationJobs <- stale:
			default:
				return fmt.Errorf("FHS HighQC validation scheduler could not restore displaced work")
			}
		}
		// The old registry and queued work remain authoritative. ErrOldState is
		// the manager contract that restores its previous pending request.
		return hotstuff.ErrOldState
	}
}

func (s *Service) isProposalValidationJobActive(job *proposalValidationJob) bool {
	if s == nil || job == nil || job.ctx == nil || job.ctx.Err() != nil ||
		atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != job.serviceGeneration {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if job.highQCRequest != nil {
		active := s.activeHighQCValidation
		return active != nil && active.key == job.highQCRequest.Key && active.generation == job.validationGeneration
	}
	if job.request == nil {
		return false
	}
	active := s.activeProposalValidation
	return active != nil && active.key == job.request.Key && active.generation == job.validationGeneration
}

func (s *Service) markHighQCValidationResultReady(key hotstuff.FHSHighQCValidationKey, generation uint64) bool {
	if s == nil || generation == 0 {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key || active.generation != generation {
		return false
	}
	active.resultReady = true
	return true
}

func (s *Service) markHighQCValidationApplied(key hotstuff.FHSHighQCValidationKey, generation uint64) bool {
	if s == nil || generation == 0 {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key || active.generation != generation || !active.resultReady {
		return false
	}
	active.applied = true
	return true
}

func (s *Service) isProposalValidationOutputActive(output *proposalValidationOutput) bool {
	if s == nil || output == nil || output.ref == nil {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeProposalValidation
	return active != nil && active.generation == output.validationGeneration &&
		active.key.ViewNumber == output.ref.ViewNumber && active.key.ViewID == output.ref.ViewID &&
		active.key.LeaderID == output.ref.LeaderID && active.key.ProposalID == output.ref.ProposalID()
}

func (s *Service) isHighQCValidationOutputActive(output *fhsHighQCValidationOutput) bool {
	if s == nil || output == nil {
		return false
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	return active != nil && active.key == output.key && active.generation == output.validationGeneration
}

func (s *Service) authorizeHighQCProposalBody(key hotstuff.FHSHighQCValidationKey, generation uint64, ref *types.HotstuffProposalRef) error {
	if s == nil || ref == nil || key.RequestID == 0 || generation == 0 {
		return hotstuff.ErrOldState
	}
	s.muProposalValidation.Lock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key || active.generation != generation {
		s.muProposalValidation.Unlock()
		return hotstuff.ErrOldState
	}
	active.authorized[ref.ProposalID()] = proposalBodyAuthority{
		key: hotstuff.FHSProposalValidationKey{
			ViewNumber: ref.ViewNumber,
			ViewID:     ref.ViewID,
			LeaderID:   ref.LeaderID,
			ProposalID: ref.ProposalID(),
		},
		keyHash: ref.KeyHash,
	}
	s.muProposalValidation.Unlock()
	if err := s.extendDeferredFHSRecoveryPeers(ref.KeyHash); err != nil {
		return fmt.Errorf("authorize deferred FHS repair committee: %w", err)
	}
	return nil
}

// activeHighQCProposalBodyIDs snapshots the cryptographically verified repair
// set without exposing the validation registry. Durable proposal GC treats
// these entries as temporarily live until the exact HighQC worker completes;
// otherwise a catch-up longer than the ordinary unsolicited cache budget can
// collect its own oldest bodies before the serialized install begins.
func (s *Service) activeHighQCProposalBodyIDs() map[common.Hash]struct{} {
	protected := make(map[common.Hash]struct{})
	if s == nil {
		return protected
	}
	s.muProposalValidation.Lock()
	if active := s.activeHighQCValidation; active != nil {
		for proposalID := range active.authorized {
			protected[proposalID] = struct{}{}
		}
	}
	s.muProposalValidation.Unlock()
	return protected
}

// cancelProposalValidationLocked requires muProposalValidation. The scheduler
// owns one proposal at a time; HighQC work has a separate lifetime.
func (s *Service) cancelProposalValidationLocked() {
	if active := s.activeProposalValidation; active != nil && active.cancel != nil {
		active.cancel()
	}
	s.activeProposalValidation = nil
}

func (s *Service) finishProposalValidation(key hotstuff.FHSProposalValidationKey) {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeProposalValidation
	if active == nil || active.key != key {
		return
	}
	s.cancelProposalValidationLocked()
}

func (s *Service) finishHighQCValidation(key hotstuff.FHSHighQCValidationKey) {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	active := s.activeHighQCValidation
	if active == nil || active.key != key {
		return
	}
	if active.cancel != nil {
		active.cancel()
	}
	s.activeHighQCValidation = nil
}

func (s *Service) cancelInactiveProposalValidations(activeView uint64) {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	if active := s.activeProposalValidation; active != nil && active.key.ViewNumber != activeView {
		s.cancelProposalValidationLocked()
	}
	// HighQC work is owned by the manager's semantic QC continuation, not by an
	// individual active view. It ends only on semantic replacement, completion,
	// epoch transition or shutdown.
}

func (s *Service) cancelAllProposalValidations() {
	if s == nil {
		return
	}
	s.muProposalValidation.Lock()
	defer s.muProposalValidation.Unlock()
	s.cancelProposalValidationLocked()
	if active := s.activeHighQCValidation; active != nil {
		if active.cancel != nil {
			active.cancel()
		}
		s.activeHighQCValidation = nil
	}
	for {
		select {
		case stale := <-s.proposalValidationJobs:
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			return
		}
	}
}

func (s *Service) proposalValidationWorker() {
	for job := range s.proposalValidationJobs {
		if !s.isProposalValidationJobActive(job) {
			continue
		}
		if request := job.highQCRequest; request != nil {
			output, err := s.stageFHSHighQC(job.ctx, request.Key, request.QC, job.serviceGeneration, job.validationGeneration)
			if !s.isProposalValidationJobActive(job) {
				continue
			}
			result := &hotstuff.FHSHighQCValidationResult{Key: request.Key, Err: err, ApplicationData: output}
			if !s.markHighQCValidationResultReady(request.Key, job.validationGeneration) {
				continue
			}
			select {
			case s.highQCValidationResults <- result:
			case <-job.ctx.Done():
			}
			continue
		}
		request := job.request
		output, err := s.validateHotstuffProposalApplication(job.ctx, request.ProposalRef, request.Extra, request.Key.ViewNumber, request.ParentQC, job.parentVerified, job.serviceGeneration, job.validationGeneration)
		if !s.isProposalValidationJobActive(job) {
			continue
		}
		result := &hotstuff.FHSProposalValidationResult{Key: request.Key, Err: err, ApplicationData: output}
		select {
		case s.proposalValidationResults <- result:
		case <-job.ctx.Done():
		}
	}
}

func (s *Service) ScheduleFHSProposalBuild(request *hotstuff.FHSProposalBuildRequest) error {
	if request == nil || request.Key.RequestID == 0 || request.Key.ViewNumber == 0 || request.Key.ViewID == (common.Hash{}) ||
		request.Key.LeaderID == "" || len(request.CurrentState) == 0 || s.proposalBuildJobs == nil {
		return fmt.Errorf("invalid FHS proposal construction request")
	}
	cloned := &hotstuff.FHSProposalBuildRequest{
		Key:          request.Key,
		CurrentState: append([]byte(nil), request.CurrentState...),
		ParentQC:     hotstuff.CloneSignedState(request.ParentQC),
	}
	if hotstuff.StateDigest(cloned.CurrentState) != cloned.Key.CurrentStateDigest {
		return fmt.Errorf("FHS proposal construction state mismatch")
	}
	parentQCID, err := fhsQCIdentityHash(cloned.ParentQC)
	if err != nil {
		return err
	}
	if parentQCID != cloned.Key.ParentQCID {
		return fmt.Errorf("FHS proposal construction parent QC mismatch")
	}
	serviceGeneration := atomic.LoadUint64(&s.proposalValidationGeneration)
	if atomic.LoadInt32(&s.runningState) != 1 || serviceGeneration == 0 {
		return types.ErrNotRunning
	}

	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	if atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != serviceGeneration {
		return types.ErrNotRunning
	}
	if atomic.LoadInt32(&s.fhsEpochTransition) != 0 {
		return hotstuff.ErrOldState
	}
	if active := s.activeProposalBuild; active != nil {
		if active.key == cloned.Key {
			return nil
		}
		if active.key.ViewNumber > cloned.Key.ViewNumber {
			return hotstuff.ErrOldState
		}
		if active.cancel != nil {
			active.cancel()
		}
		s.activeProposalBuild = nil
	}
	for {
		select {
		case stale := <-s.proposalBuildJobs:
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			goto proposalBuildQueueDrained
		}
	}

proposalBuildQueueDrained:
	s.proposalBuildSeq++
	if s.proposalBuildSeq == 0 {
		s.proposalBuildSeq++
	}
	constructionGeneration := s.proposalBuildSeq
	ctx, cancel := context.WithCancel(context.Background())
	job := &proposalBuildJob{
		request:                cloned,
		ctx:                    ctx,
		cancel:                 cancel,
		serviceGeneration:      serviceGeneration,
		constructionGeneration: constructionGeneration,
	}
	s.activeProposalBuild = &proposalBuildControl{key: cloned.Key, generation: constructionGeneration, cancel: cancel}
	select {
	case s.proposalBuildJobs <- job:
		return nil
	default:
		s.activeProposalBuild = nil
		cancel()
		return fmt.Errorf("FHS proposal construction scheduler invariant failed")
	}
}

func (s *Service) isProposalBuildJobActive(job *proposalBuildJob) bool {
	if s == nil || job == nil || job.request == nil || job.ctx == nil || job.ctx.Err() != nil ||
		atomic.LoadInt32(&s.runningState) != 1 || atomic.LoadUint64(&s.proposalValidationGeneration) != job.serviceGeneration {
		return false
	}
	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	active := s.activeProposalBuild
	return active != nil && active.key == job.request.Key && active.generation == job.constructionGeneration
}

func (s *Service) proposalBuildWorker() {
	for job := range s.proposalBuildJobs {
		if !s.isProposalBuildJobActive(job) {
			continue
		}
		output, err := s.stageFHSProposalBuild(job)
		if !s.isProposalBuildJobActive(job) {
			continue
		}
		result := &hotstuff.FHSProposalBuildResult{Key: job.request.Key, Err: err, ApplicationData: output}
		if output != nil {
			result.TProposal = append([]byte(nil), output.proposalRef...)
			result.Extra = append([]byte(nil), output.extra...)
		}
		select {
		case s.proposalBuildResults <- result:
		case <-job.ctx.Done():
		}
	}
}

func (s *Service) reserveProposalManifestDispatch() error {
	select {
	case s.proposalManifestSlots <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("proposal manifest dispatch queue saturated")
	}
}

func (s *Service) releaseProposalManifestDispatch() {
	select {
	case <-s.proposalManifestSlots:
	default:
		panic("proposal manifest dispatch reservation underflow")
	}
}

func (s *Service) reserveProposalFailedTxCleanup() error {
	select {
	case s.proposalFailedTxSlots <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("proposal failed-TX cleanup queue saturated")
	}
}

func (s *Service) releaseProposalFailedTxCleanup() {
	select {
	case <-s.proposalFailedTxSlots:
	default:
		panic("proposal failed-TX cleanup reservation underflow")
	}
}

func (s *Service) proposalManifestDispatchWorker() {
	for job := range s.proposalManifestJobs {
		if job != nil && job.body != nil && atomic.LoadInt32(&s.runningState) == 1 &&
			atomic.LoadUint64(&s.proposalValidationGeneration) == job.serviceGeneration {
			s.dispatchProposalManifest(job.body, job.destinations, job.serviceGeneration)
		}
		s.releaseProposalManifestDispatch()
	}
}

func (s *Service) proposalFailedTxCleanupWorker() {
	for job := range s.proposalFailedTxJobs {
		if job != nil && len(job.txs) > 0 && s.removeFailedProposalTxs != nil && atomic.LoadInt32(&s.runningState) == 1 &&
			atomic.LoadUint64(&s.proposalValidationGeneration) == job.serviceGeneration {
			s.removeFailedProposalTxs(job.txs)
			log.Warn("Removed failed proposal txs from txpool", "count", len(job.txs))
		}
		s.releaseProposalFailedTxCleanup()
	}
}

func (s *Service) finishProposalBuild(key hotstuff.FHSProposalBuildKey) {
	s.muProposalBuild.Lock()
	defer s.muProposalBuild.Unlock()
	active := s.activeProposalBuild
	if active == nil || active.key != key {
		return
	}
	if active.cancel != nil {
		active.cancel()
	}
	s.activeProposalBuild = nil
}

// cancelAllProposalBuildsLocked requires muProposalBuild.
func (s *Service) cancelAllProposalBuildsLocked() {
	if active := s.activeProposalBuild; active != nil {
		if active.cancel != nil {
			active.cancel()
		}
		s.activeProposalBuild = nil
	}
	for {
		select {
		case stale := <-s.proposalBuildJobs:
			if stale != nil && stale.cancel != nil {
				stale.cancel()
			}
		default:
			return
		}
	}
}

func (s *Service) enqueueHotstuffPriority(msg *hotstuffMsg) bool {
	if s == nil || s.hotstuffMsgQ == nil || msg == nil {
		return false
	}
	if !s.hotstuffMsgQ.pushPriority(msg) {
		code := uint32(0)
		if msg.hMsg != nil {
			code = msg.hMsg.Code
		}
		log.Debug("drop hotstuff priority message after bounded queue backpressure", "code", hotstuff.ReadableMsgType(code))
		return false
	}
	return true
}

func (s *Service) enqueueHotstuff(msg *hotstuffMsg) {
	if s == nil || s.hotstuffMsgQ == nil || msg == nil {
		return
	}
	if !s.hotstuffMsgQ.push(msg) {
		code := uint32(0)
		if msg.hMsg != nil {
			code = msg.hMsg.Code
		}
		log.Debug("drop hotstuff network message after bounded queue backpressure", "code", hotstuff.ReadableMsgType(code))
	}
}
