package reconfig

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/cypherium/cypher/rlp"
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
	hotstuffQueuePerSenderEntries   = 8
	hotstuffQueuePerSenderBytes     = 640 * 1024
	hotstuffQueueRecentDigestMax    = 4096
	hotstuffQueueReplayTTL          = 5 * time.Second
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

func (q *hotstuffMessageQueue) pop() *hotstuffMsg {
	if q == nil {
		return nil
	}
	select {
	case msg := <-q.next:
		return msg
	default:
		return nil
	}
}
