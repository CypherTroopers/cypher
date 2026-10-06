package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/rlp"
)

const (
	helloMsg = iota
	requestMsg
	responseMsg
)

var ErrUnavailable = errors.New("relay unavailable or capacity exhausted")

// Request carries no caller-chosen network address. The application resolves
// Target (a committee public key) against Generation in its canonical chain.
// Payload is opaque and never rewritten by routing.
type Request struct {
	ID         common.Hash
	Kind       uint64
	ChainID    uint64
	Genesis    common.Hash
	Generation common.Hash
	KeyNumber  uint64
	Target     []byte
	Hops       uint64
	Expires    uint64 // Unix milliseconds, bounded at every hop
	Payload    []byte
}

type response struct {
	ID      common.Hash
	Failed  bool
	Payload []byte
}
type hello struct {
	Version uint64
	ChainID uint64
	Genesis common.Hash
}
type result struct {
	payload []byte
	err     error
}
type frame struct {
	code  uint64
	value interface{}
	size  int64
}

// Hooks must authenticate both the immutable request and the committee reply.
// Gateway is only called by a fixed egress worker pool on opt-in gateways.
type Hooks struct {
	ValidateRequest func(*Request) error
	ValidateReply   func(*Request, []byte) error
	Gateway         func(context.Context, *Request) ([]byte, error)
}

type peer struct {
	id               enode.ID
	p                *p2p.Peer
	rw               p2p.MsgReadWriter
	out              chan frame
	done             chan struct{}
	ready            bool
	outstanding      int
	outstandingBytes int64
	queued           int64 // includes currently writing frame; guarded by Relay.mu
	tokens           float64
	bytes            float64
	last             time.Time
}
type pending struct {
	req        Request
	parents    map[enode.ID]bool
	children   map[enode.ID]bool
	waiters    map[chan result]bool
	cost       int64
	tried      map[enode.ID]bool
	candidates []enode.ID
	nextTry    time.Time
	wave       time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
}
type cached struct {
	payload []byte
	until   time.Time
}
type job struct {
	from  *peer
	req   *Request
	reply *response
	entry *pending
	cost  int64
}

type Relay struct {
	config                                           Config
	chainID                                          uint64
	genesis                                          common.Hash
	hooks                                            Hooks
	mu                                               sync.Mutex
	peers                                            map[enode.ID]*peer
	pending                                          map[common.Hash]*pending
	cache                                            map[common.Hash]cached
	pendingBytes, workBytes, cacheBytes, egressBytes int64
	waiters                                          int
	jobs                                             chan job
	egress                                           chan *pending
	ctx                                              context.Context
	cancel                                           context.CancelFunc
	wg                                               sync.WaitGroup
	ioWG                                             sync.WaitGroup
	routeSequence                                    uint64
	started                                          bool
}

func New(config Config, chainID uint64, genesis common.Hash, hooks Hooks) (*Relay, error) {
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if chainID == 0 || genesis == (common.Hash{}) || hooks.ValidateRequest == nil || hooks.ValidateReply == nil || (c.Gateway && hooks.Gateway == nil) {
		return nil, errors.New("relay requires chain identity and authenticated application hooks")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Relay{config: c, chainID: chainID, genesis: genesis, hooks: hooks,
		peers: make(map[enode.ID]*peer), pending: make(map[common.Hash]*pending), cache: make(map[common.Hash]cached),
		jobs: make(chan job, c.MaxPending), egress: make(chan *pending, c.MaxPending), ctx: ctx, cancel: cancel}, nil
}

func (r *Relay) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.ctx.Err() != nil {
		return
	}
	r.started = true
	for i := 0; i < r.config.Workers; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	if r.config.Gateway {
		for i := 0; i < r.config.GatewayWorkers; i++ {
			r.wg.Add(1)
			go r.gatewayWorker()
		}
	}
	r.wg.Add(1)
	go r.expirer()
}

func (r *Relay) Stop() {
	r.cancel()
	r.mu.Lock()
	for _, p := range r.peers {
		disconnectPeer(p, p2p.DiscQuitting)
	}
	for _, p := range r.pending {
		r.finishLocked(p, nil, ErrUnavailable)
	}
	r.cache = make(map[common.Hash]cached)
	r.cacheBytes = 0
	r.mu.Unlock()
	r.wg.Wait()
	r.ioWG.Wait()
	// Work queues retain no payloads after shutdown.
	for {
		select {
		case j := <-r.jobs:
			r.releaseWork(j.cost)
		default:
			goto drained
		}
	}
drained:
	for {
		select {
		case p := <-r.egress:
			r.mu.Lock()
			r.egressBytes -= p.cost
			r.mu.Unlock()
		default:
			return
		}
	}
}

func (r *Relay) Protocol() p2p.Protocol {
	return p2p.Protocol{Name: "cphrelay", Version: Version, Length: 3, Run: r.runPeer}
}

func requestID(q *Request) common.Hash {
	encoded, _ := rlp.EncodeToBytes([]interface{}{"cypher-common-relay-v1", q.Kind, q.ChainID, q.Genesis, q.Generation, q.KeyNumber, q.Target, q.Payload})
	return crypto.Keccak256Hash(encoded)
}

func (r *Relay) check(q *Request) error {
	now := uint64(time.Now().UnixMilli())
	if q.ChainID != r.chainID || q.Genesis != r.genesis || q.Generation == (common.Hash{}) ||
		q.Hops == 0 || q.Hops > r.config.Hops || len(q.Target) == 0 || len(q.Target) > 128 ||
		len(q.Payload) == 0 || len(q.Payload) > MaxPayload || q.Expires <= now || q.Expires > now+uint64(r.config.Timeout/time.Millisecond)+1000 ||
		q.ID != requestID(q) {
		return errors.New("invalid relay request")
	}
	return r.hooks.ValidateRequest(q)
}

// Do waits for a portable, independently verified committee response. Local or
// relay queue acceptance is never success. Context cancellation leaves bounded
// transit work to its original deadline and removes only this local waiter.
func (r *Relay) Do(ctx context.Context, q Request) ([]byte, error) {
	q.ChainID = r.chainID
	q.Genesis = r.genesis
	q.Hops = r.config.Hops
	q.Expires = uint64(time.Now().Add(r.config.Timeout).UnixMilli())
	q.ID = requestID(&q)
	if err := r.check(&q); err != nil {
		return nil, err
	}
	w := make(chan result, 1)
	r.mu.Lock()
	if !r.started || r.ctx.Err() != nil || r.waiters >= r.config.MaxPending {
		r.mu.Unlock()
		return nil, ErrUnavailable
	}
	if err := r.routeLocked(&q, nil, w); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if p := r.pending[q.ID]; p != nil && p.waiters[w] {
			delete(p.waiters, w)
			r.waiters--
		}
		r.mu.Unlock()
	}()
	select {
	case out := <-w:
		return out.payload, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.ctx.Done():
		return nil, ErrUnavailable
	}
}

func (r *Relay) routeLocked(q *Request, from *peer, waiter chan result) error {
	if hit, ok := r.cache[q.ID]; ok && time.Now().Before(hit.until) {
		// Request validation already checked current canonical generation.
		if waiter != nil {
			waiter <- result{payload: hit.payload}
		} else {
			r.sendLocked(from, responseMsg, response{ID: q.ID, Payload: hit.payload})
		}
		return nil
	}
	if p := r.pending[q.ID]; p != nil {
		if from != nil {
			if _, loop := p.tried[from.id]; loop {
				r.sendLocked(from, responseMsg, response{ID: q.ID, Failed: true})
				return nil
			}
			if !p.parents[from.id] {
				if !r.reserveParentLocked(from, p.cost) {
					return ErrUnavailable
				}
				p.parents[from.id] = true
			}
		}
		if waiter != nil {
			p.waiters[waiter] = true
			r.waiters++
		}
		return nil
	}
	cost := int64(len(q.Payload) + len(q.Target) + 512)
	if len(r.pending) >= r.config.MaxPending || cost > r.config.MaxPendingBytes-r.pendingBytes {
		return ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(r.ctx, time.UnixMilli(int64(q.Expires)))
	p := &pending{tried: make(map[enode.ID]bool), req: *q, parents: make(map[enode.ID]bool), children: make(map[enode.ID]bool), waiters: make(map[chan result]bool), cost: cost, ctx: ctx, cancel: cancel}
	if from != nil {
		if !r.reserveParentLocked(from, cost) {
			cancel()
			return ErrUnavailable
		}
		p.parents[from.id] = true
	}
	if waiter != nil {
		p.waiters[waiter] = true
		r.waiters++
	}
	r.pending[q.ID] = p
	r.pendingBytes += cost
	if r.config.Gateway {
		if cost > r.config.MaxPendingBytes-r.egressBytes {
			r.finishLocked(p, nil, ErrUnavailable)
			return nil
		}
		select {
		case r.egress <- p:
			r.egressBytes += cost
			return nil
		default:
			r.finishLocked(p, nil, ErrUnavailable)
			return nil
		}
	}
	if q.Hops <= 1 {
		r.finishLocked(p, nil, ErrUnavailable)
		return nil
	}
	candidates := make([]*peer, 0, len(r.peers))
	for _, peer := range r.peers {
		if peer.ready && (from == nil || peer.id != from.id) {
			candidates = append(candidates, peer)
		}
	}
	// A bounded scalar salt rotates ordering on retries of the same semantic request.
	r.routeSequence++
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], r.routeSequence)
	sort.Slice(candidates, func(i, j int) bool {
		a := crypto.Keccak256Hash(q.ID[:], salt[:], candidates[i].id[:])
		b := crypto.Keccak256Hash(q.ID[:], salt[:], candidates[j].id[:])
		return bytes.Compare(a[:], b[:]) < 0
	})
	for _, peer := range candidates {
		p.candidates = append(p.candidates, peer.id)
	}
	waves := (len(candidates) + r.config.Fanout - 1) / r.config.Fanout
	p.wave = time.Until(time.UnixMilli(int64(q.Expires))) / time.Duration(waves+1)
	if p.wave < 100*time.Millisecond {
		p.wave = 100 * time.Millisecond
	}
	r.advanceLocked(p)
	return nil
}

func (r *Relay) reserveParentLocked(peer *peer, cost int64) bool {
	if peer.outstanding >= r.config.PeerPending || cost > r.config.PeerPendingBytes-peer.outstandingBytes {
		return false
	}
	peer.outstanding++
	peer.outstandingBytes += cost
	return true
}

// Only Fanout children are outstanding at a time. Timed-out waves are retired;
// their late replies cannot complete the request. Every viable neighbor is tried.
func (r *Relay) advanceLocked(p *pending) {
	next := p.req
	next.Hops--
	for len(p.candidates) > 0 && len(p.children) < r.config.Fanout {
		id := p.candidates[0]
		p.candidates = p.candidates[1:]
		if p.parents[id] || p.tried[id] {
			continue
		}
		peer := r.peers[id]
		if peer == nil || !peer.ready {
			continue
		}
		p.tried[id] = true
		if r.sendLocked(peer, requestMsg, next) {
			p.children[id] = true
		}
	}
	p.nextTry = time.Now().Add(p.wave)
	if len(p.children) == 0 {
		r.finishLocked(p, nil, ErrUnavailable)
	}
}

func (r *Relay) finishLocked(p *pending, payload []byte, err error) {
	if r.pending[p.req.ID] != p {
		return
	}
	delete(r.pending, p.req.ID)
	r.pendingBytes -= p.cost
	p.cancel()
	if err == nil && len(payload) > 0 && len(payload) <= MaxReply {
		// Evict expired or oldest entries; both entry count and bytes are bounded.
		for len(r.cache) >= r.config.CacheEntries || r.cacheBytes+int64(len(payload)) > r.config.CacheBytes {
			var oldest common.Hash
			var until time.Time
			for id, c := range r.cache {
				if until.IsZero() || c.until.Before(until) {
					oldest = id
					until = c.until
				}
			}
			if until.IsZero() {
				break
			}
			r.cacheBytes -= int64(len(r.cache[oldest].payload))
			delete(r.cache, oldest)
		}
		if old, ok := r.cache[p.req.ID]; ok {
			r.cacheBytes -= int64(len(old.payload))
		}
		r.cache[p.req.ID] = cached{payload: payload, until: time.UnixMilli(int64(p.req.Expires))}
		r.cacheBytes += int64(len(payload))
	}
	for w := range p.waiters {
		w <- result{payload: payload, err: err}
		r.waiters--
	}
	for id := range p.parents {
		if peer := r.peers[id]; peer != nil {
			peer.outstanding--
			peer.outstandingBytes -= p.cost
			r.sendLocked(peer, responseMsg, response{ID: p.req.ID, Failed: err != nil, Payload: payload})
		}
	}
}

func (r *Relay) sendLocked(p *peer, code uint64, value interface{}) bool {
	if p == nil {
		return false
	}
	// Account encoded bytes including envelopes, independently of queue length.
	encoded, err := rlp.EncodeToBytes(value)
	if err != nil || len(encoded) > maxWire || int64(len(encoded)) > r.config.PeerQueueBytes-p.queued {
		return false
	}
	f := frame{code: code, value: rlp.RawValue(encoded), size: int64(len(encoded))}
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case p.out <- f:
		p.queued += f.size
		return true
	default:
		return false
	}
}

func (r *Relay) releaseWork(cost int64) { r.mu.Lock(); r.workBytes -= cost; r.mu.Unlock() }

func (r *Relay) worker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case j := <-r.jobs:
			if j.req != nil {
				err := r.check(j.req)
				r.mu.Lock()
				if err == nil && r.peers[j.from.id] == j.from && r.ctx.Err() == nil {
					err = r.routeLocked(j.req, j.from, nil)
				}
				if err != nil {
					r.sendLocked(j.from, responseMsg, response{ID: j.req.ID, Failed: true})
				}
				r.mu.Unlock()
			} else {
				err := errors.New("relay path failed")
				if !j.reply.Failed {
					err = r.hooks.ValidateReply(&j.entry.req, j.reply.Payload)
				}
				r.mu.Lock()
				if r.pending[j.entry.req.ID] == j.entry && j.entry.children[j.from.id] {
					if err == nil {
						r.finishLocked(j.entry, j.reply.Payload, nil)
					} else {
						delete(j.entry.children, j.from.id)
						if len(j.entry.children) == 0 {
							r.advanceLocked(j.entry)
						}
					}
				}
				r.mu.Unlock()
			}
			r.releaseWork(j.cost)
		}
	}
}

func (r *Relay) gatewayWorker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case p := <-r.egress:
			if p.ctx.Err() != nil {
				r.mu.Lock()
				r.egressBytes -= p.cost
				r.mu.Unlock()
				continue
			}
			payload, err := r.hooks.Gateway(p.ctx, &p.req)
			if err == nil {
				if len(payload) == 0 || len(payload) > MaxReply {
					err = errors.New("invalid gateway reply size")
				} else {
					err = r.hooks.ValidateReply(&p.req, payload)
				}
			}
			r.mu.Lock()
			r.egressBytes -= p.cost
			r.finishLocked(p, payload, err)
			r.mu.Unlock()
		}
	}
}

func (r *Relay) expirer() {
	defer r.wg.Done()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-tick.C:
			r.mu.Lock()
			for _, p := range r.pending {
				if p.ctx.Err() != nil {
					r.finishLocked(p, nil, ErrUnavailable)
				} else if !r.config.Gateway && len(p.candidates) > 0 && !now.Before(p.nextTry) {
					p.children = make(map[enode.ID]bool)
					r.advanceLocked(p)
				}
			}
			for id, c := range r.cache {
				if !now.Before(c.until) {
					r.cacheBytes -= int64(len(c.payload))
					delete(r.cache, id)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *Relay) runPeer(p *p2p.Peer, rw p2p.MsgReadWriter) error {
	r.mu.Lock()
	if r.ctx.Err() != nil || len(r.peers) >= r.config.MaxPeers || r.peers[p.ID()] != nil {
		r.mu.Unlock()
		return ErrUnavailable
	}
	if !p.Reserved() && r.config.ReservedSlots > 0 {
		public := 0
		for _, existing := range r.peers {
			if !existing.p.Reserved() {
				public++
			}
		}
		if public >= r.config.MaxPeers-r.config.ReservedSlots {
			r.mu.Unlock()
			return ErrUnavailable
		}
	}
	peer := &peer{id: p.ID(), p: p, rw: rw, out: make(chan frame, r.config.PeerQueue), done: make(chan struct{}), last: time.Now(), tokens: float64(r.config.RequestsPerSecond), bytes: float64(r.config.BytesPerSecond) + maxWire}
	r.peers[p.ID()] = peer
	r.ioWG.Add(2)
	defer r.ioWG.Done()
	r.sendLocked(peer, helloMsg, hello{Version, r.chainID, r.genesis})
	r.mu.Unlock()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer r.ioWG.Done()
		for {
			select {
			case <-peer.done:
				return
			case <-r.ctx.Done():
				return
			case f := <-peer.out:
				err := p2p.Send(rw, f.code, f.value)
				r.mu.Lock()
				peer.queued -= f.size
				r.mu.Unlock()
				if err != nil {
					disconnectPeer(peer, p2p.DiscNetworkError)
					return
				}
			}
		}
	}()
	defer func() {
		r.mu.Lock()
		delete(r.peers, peer.id)
		close(peer.done)
		for _, q := range r.pending {
			if q.parents[peer.id] {
				peer.outstanding--
				peer.outstandingBytes -= q.cost
				delete(q.parents, peer.id)
			}
			if _, ok := q.children[peer.id]; ok {
				delete(q.children, peer.id)
				if len(q.children) == 0 && !r.config.Gateway {
					r.advanceLocked(q)
				}
			}
		}
		r.mu.Unlock()
		disconnectPeer(peer, p2p.DiscQuitting)
		<-writerDone
		r.mu.Lock()
		peer.queued = 0
		r.mu.Unlock()
	}()
	msg, err := rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != helloMsg || msg.Size > 128 {
		return errors.New("invalid relay hello")
	}
	var h hello
	if err = decodeMessage(msg, &h); err != nil {
		return err
	}
	if h.Version != Version || h.ChainID != r.chainID || h.Genesis != r.genesis {
		return errors.New("relay chain mismatch")
	}
	r.mu.Lock()
	peer.ready = true
	r.mu.Unlock()
	for {
		msg, err = rw.ReadMsg()
		if err != nil {
			return err
		}
		if (msg.Code != requestMsg && msg.Code != responseMsg) || msg.Size > maxWire || (msg.Code == responseMsg && msg.Size > MaxReply+128) {
			return errors.New("oversize or unknown relay message")
		}
		cost := int64(msg.Size)
		r.mu.Lock()
		now := time.Now()
		dt := now.Sub(peer.last).Seconds()
		peer.last = now
		peer.tokens = min(float64(r.config.RequestsPerSecond), peer.tokens+dt*float64(r.config.RequestsPerSecond))
		peer.bytes = min(float64(r.config.BytesPerSecond)+maxWire, peer.bytes+dt*float64(r.config.BytesPerSecond))
		allowed := peer.tokens >= 1 && peer.bytes >= float64(cost) && cost <= r.config.MaxPendingBytes-r.workBytes
		if allowed {
			peer.tokens--
			peer.bytes -= float64(cost)
			r.workBytes += cost
		}
		r.mu.Unlock()
		if !allowed {
			return ErrUnavailable
		}
		j := job{from: peer, cost: cost}
		if msg.Code == requestMsg {
			j.req = new(Request)
			err = decodeMessage(msg, j.req)
		} else {
			j.reply = new(response)
			err = decodeMessage(msg, j.reply)
			if err == nil {
				r.mu.Lock()
				j.entry = r.pending[j.reply.ID]
				matched := j.entry != nil && j.entry.children[peer.id]
				r.mu.Unlock()
				// Late hedged responses are normal. Rate-charge and discard them,
				// never let an unsolicited response complete another request.
				if !matched {
					r.releaseWork(cost)
					continue
				}
			}
		}
		if err != nil {
			r.releaseWork(cost)
			return err
		}
		select {
		case r.jobs <- j:
		case <-r.ctx.Done():
			r.releaseWork(cost)
			return ErrUnavailable
		default:
			r.releaseWork(cost)
			return ErrUnavailable
		}
	}
}

func decodeMessage(msg p2p.Msg, out interface{}) error {
	b, err := io.ReadAll(io.LimitReader(msg.Payload, int64(msg.Size)+1))
	if err != nil {
		return err
	}
	if len(b) != int(msg.Size) {
		return fmt.Errorf("relay message size mismatch")
	}
	return rlp.DecodeBytes(b, out)
}

// Real protocol transports unblock through Peer.Disconnect. MsgPipe and other
// explicitly closeable adapters are closed too, allowing lifecycle tests to join.
func disconnectPeer(p *peer, reason p2p.DiscReason) {
	p.p.Disconnect(reason)
	if c, ok := p.rw.(io.Closer); ok {
		_ = c.Close()
	}
}
