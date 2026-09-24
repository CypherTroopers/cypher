package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

type Relay struct {
	mu        sync.Mutex
	config    Config
	backend   Backend
	signer    Signer
	store     *store
	state     diskState
	validated map[protocol.Hash]bool
	nextTry   map[protocol.Hash]time.Time
	fault     error
	closed    bool
	// Local scheduling hints carry no authentication state and reset on Open.
	// Keep history rotation separate from the durable pending-owner turn.
	historySequence [4]uint64
	historyOwner    [4]common.Address
	activeSequence  [4]uint64
	activeOwner     [4]common.Address
	historyTurn     [4]bool
	// A disposable planner hint accelerates the next authenticated inbox range.
	// It is not a completion/validity cache: Observe and leadership gates still
	// run. Alternate with ordinary reconciliation, preserving every old intent.
	inboxHint      protocol.Hash
	inboxHintUntil time.Time
	inboxHintTurn  bool
}

func Open(dir string, c Config, b Backend, s Signer) (*Relay, error) {
	if b == nil || s == nil {
		return nil, errors.New("relay backend and sign-only signer required")
	}
	if _, err := c.binding(); err != nil {
		return nil, err
	}
	copyConfig := c
	copyConfig.Payers = map[Lane]common.Address{}
	copyConfig.GasLimits = map[Lane]uint64{}
	for l, p := range c.Payers {
		copyConfig.Payers[l] = p
	}
	for l, g := range c.GasLimits {
		copyConfig.GasLimits[l] = g
	}
	copyConfig.GasPrice = new(big.Int).Set(c.GasPrice)
	copyConfig.MaxGasCost = new(big.Int).Set(c.MaxGasCost)
	w, d, err := openStore(dir, copyConfig)
	if err != nil {
		return nil, err
	}
	return &Relay{config: copyConfig, backend: b, signer: s, store: w, state: d, validated: map[protocol.Hash]bool{}, nextTry: map[protocol.Hash]time.Time{}}, nil
}
func (r *Relay) hook(name string) error {
	if r.config.Hook != nil {
		if err := r.config.Hook(name); err != nil {
			r.fault = errors.Join(ErrStore, err)
			return r.fault
		}
	}
	return nil
}
func (r *Relay) usable() error {
	if r.closed {
		return errors.New("relay closed")
	}
	return r.fault
}
func (r *Relay) persist(d diskState) error {
	var pruned []protocol.Hash
	for {
		err := validateState(d, r.config, r.state.Binding)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrCapacity) {
			return err
		}
		referenced := map[protocol.Hash]bool{}
		for _, x := range d.Records {
			for _, id := range x.Job.Dependencies {
				referenced[id] = true
			}
		}
		oldest := -1
		for i, x := range d.Records {
			if old := r.find(x.Job.ID); old >= 0 && r.state.Records[old].Phase == "complete" && x.Phase == "complete" && r.validated[x.Job.ID] && !referenced[x.Job.ID] && (oldest < 0 || x.LocalID < d.Records[oldest].LocalID) {
				oldest = i
			}
		}
		if oldest < 0 {
			return ErrCapacity
		}
		pruned = append(pruned, d.Records[oldest].Job.ID)
		d.Records = append(d.Records[:oldest], d.Records[oldest+1:]...)
	}
	if err := r.store.save(d); err != nil {
		r.fault = errors.Join(ErrStore, err)
		return r.fault
	}
	r.state = d
	for _, id := range pruned {
		delete(r.validated, id)
		delete(r.nextTry, id)
	}
	return nil
}
func (r *Relay) find(id protocol.Hash) int {
	for i, x := range r.state.Records {
		if x.Job.ID == id {
			return i
		}
	}
	return -1
}
func (r *Relay) Enqueue(j Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.usable(); err != nil {
		return err
	}
	if err := validateJob(j); err != nil {
		return err
	}
	if i := r.find(j.ID); i >= 0 {
		a, _ := rlp.EncodeToBytes(r.state.Records[i].Job)
		b, _ := rlp.EncodeToBytes(j)
		if !bytes.Equal(a, b) {
			return ErrConflict
		}
		return nil
	}
	for _, id := range j.Dependencies {
		if r.find(id) < 0 {
			return errors.New("relay dependency must already be durable")
		}
	}
	d := cloneState(r.state)
	if d.Next == ^uint64(0) {
		return ErrCapacity
	}
	d.Records = append(d.Records, Record{LocalID: d.Next, Job: cloneJob(j), Phase: "queued"})
	d.Next++
	if err := r.persist(d); err != nil {
		return err
	}
	return r.hook("after_intent")
}
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.store.lock.Close()
}
func (r *Relay) Status() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.state.Records))
	for i, x := range r.state.Records {
		out[i] = cloneRecord(x)
		if (x.Phase == "complete" || x.Phase == "completed_pending_nonce") && !r.validated[x.Job.ID] {
			out[i].Phase = "revalidation_wait"
		}
	}
	return out
}
func (r *Relay) update(index int, record Record) error {
	d := cloneState(r.state)
	index = r.find(record.Job.ID)
	if index < 0 {
		return errors.New("relay record unavailable")
	}
	d.Records[index] = record
	if len(record.PriorAttempts) != 0 {
		d.Version = 2
	}
	return r.persist(d)
}
func (r *Relay) failure(index int, record Record, err error) error {
	if err == nil {
		return nil
	}
	record.LastError = err.Error()
	if len(record.LastError) > 512 {
		record.LastError = record.LastError[:512]
	}
	if errors.Is(err, ErrInvalidJob) {
		record.Phase = "quarantined"
	} else if record.Attempt.GasLimit == 0 && record.Phase != "complete" {
		record.Phase = "waiting"
	}
	if e := r.update(index, record); e != nil {
		return e
	}
	return err
}
func (r *Relay) dependenciesReady(j Job) bool {
	for _, id := range j.Dependencies {
		if !r.validated[id] {
			return false
		}
	}
	return true
}
func (r *Relay) payerBusy(index int, payer common.Address) bool {
	for i, x := range r.state.Records {
		if i != index && x.Job.Lane != Inbox && x.Attempt.GasLimit != 0 && x.Phase != "complete" && r.config.Payers[x.Job.Lane] == payer {
			return true
		}
	}
	return false
}

// prioritizeInbox is deliberately private to the authenticated network planner.
// Public Enqueue and persisted labels cannot grant scheduling priority.
func (r *Relay) prioritizeInbox(id protocol.Hash) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inboxHint, r.inboxHintUntil = id, time.Now().Add(3*time.Second)
}

// selectRecord gives ready owners a rotating opportunity within rotating lanes.
// The cursors are persisted before network work, so failures do not reset fairness.
func (r *Relay) selectRecord() (int, bool) {
	now := time.Now()
	for offset := 0; offset < 4; offset++ {
		lane := Lane((int(r.state.LaneCursor)+offset)%4 + 1)
		var candidates []int
		for i, x := range r.state.Records {
			if x.Job.Lane != lane || x.Phase == "quarantined" || x.Phase == "nonce_conflict" || (x.Phase == "complete" && r.validated[x.Job.ID]) || now.Before(r.nextTry[x.Job.ID]) {
				continue
			}
			// A reserved nonce must be authenticated/reconciled before this payer
			// can submit another native job. Defer only unsigned active siblings;
			// cold completed records still require proof revalidation, and Inbox
			// or another payer must retain independent scheduling opportunities.
			if lane != Inbox && x.Attempt.GasLimit == 0 && x.Phase != "complete" && r.payerBusy(i, r.config.Payers[lane]) {
				continue
			}
			candidates = append(candidates, i)
		}
		if len(candidates) == 0 {
			continue
		}
		if lane == Inbox && !r.inboxHintTurn && now.Before(r.inboxHintUntil) {
			for _, i := range candidates {
				if r.state.Records[i].Job.ID == r.inboxHint && r.state.Records[i].Phase != "complete" {
					r.inboxHintTurn = true
					return i, true
				}
			}
		}
		var active, history []int
		for _, i := range candidates {
			x := r.state.Records[i]
			if x.Phase == "complete" {
				history = append(history, i)
			} else {
				active = append(active, i)
			}
		}
		lastSequence, lastOwner := r.historySequence[lane-1], r.historyOwner[lane-1]
		if len(active) > 0 && (len(history) == 0 || !r.historyTurn[lane-1]) {
			candidates = active
			lastSequence, lastOwner = r.activeSequence[lane-1], r.activeOwner[lane-1]
			for _, i := range active {
				// One unresolved nonce per payer; each native lane has one payer.
				// Its owner must reconcile before unsigned siblings can proceed.
				if lane != Inbox && r.state.Records[i].Attempt.GasLimit != 0 {
					return i, false
				}
			}
		} else {
			candidates = history
		}
		sort.Slice(candidates, func(i, j int) bool {
			a, b := r.state.Records[candidates[i]], r.state.Records[candidates[j]]
			ad, bd := a.Job.Owner != lastOwner, b.Job.Owner != lastOwner
			if ad != bd {
				return ad
			}
			ap, bp := a.LocalID > lastSequence, b.LocalID > lastSequence
			if ap != bp {
				return ap
			}
			return a.LocalID < b.LocalID
		})
		if lane == Inbox {
			r.inboxHintTurn = false
		}
		return candidates[0], false
	}
	return -1, false
}
func (r *Relay) Step(parent context.Context) error {
	return r.step(parent, true)
}

// Reconcile authenticates completion and payer nonce progress without reserving
// a new nonce, signing, or sending anything. A standby DEX participant uses this
// to stop treating work completed by the current leader as outstanding.
func (r *Relay) Reconcile(parent context.Context) error {
	return r.step(parent, false)
}

func (r *Relay) step(parent context.Context, submit bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.usable(); err != nil {
		return err
	}
	index, hinted := r.selectRecord()
	if index < 0 {
		return nil
	}
	record := cloneRecord(r.state.Records[index])
	d := cloneState(r.state)
	d.LaneCursor = uint8(record.Job.Lane % 4)
	d.LastSequence[record.Job.Lane-1] = record.LocalID
	d.LastOwner[record.Job.Lane-1] = record.Job.Owner
	if err := r.persist(d); err != nil {
		return err
	}
	if hinted {
		// Priority must not reset the ordinary cursor to the frontier: doing
		// that would repeatedly reconcile only the first old pending intent.
	} else if record.Phase == "complete" {
		r.historySequence[record.Job.Lane-1] = record.LocalID
		r.historyOwner[record.Job.Lane-1] = record.Job.Owner
		r.historyTurn[record.Job.Lane-1] = false
	} else {
		r.activeSequence[record.Job.Lane-1] = record.LocalID
		r.activeOwner[record.Job.Lane-1] = record.Job.Owner
		r.historyTurn[record.Job.Lane-1] = true
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	// Read-only standby reconciliation must not push the submission retry
	// deadline forward on every loop, or Reconcile followed by Step would
	// indefinitely starve a lone pending job on the current leader.
	if submit {
		r.nextTry[record.Job.ID] = time.Now().Add(250 * time.Millisecond)
	}
	obs, err := r.backend.Observe(ctx, cloneJob(record.Job), record.Attempt)
	if err != nil {
		return r.failure(index, record, err)
	}
	if !obs.verified || len(obs.proof) == 0 || len(obs.proof) > clxevidence.MaxEvidenceBytes || obs.anchor.Validate() != nil || obs.anchor.ChainID != r.config.Domain.ChainID || obs.anchor.Genesis != r.config.Domain.Genesis || obs.anchor.DEXID != r.config.Domain.DEXID || obs.anchor.Custody != [20]byte(r.config.Custody) {
		return r.failure(index, record, errors.New("relay observation is not authenticated"))
	}
	if err := r.hook("after_proof"); err != nil {
		return err
	}
	record.Proof = append([]byte(nil), obs.proof...)
	record.LastError = ""
	if obs.conflict != "" {
		record.Phase = "nonce_conflict"
		record.LastError = obs.conflict
		if len(record.LastError) > 512 {
			record.LastError = record.LastError[:512]
		}
		return r.update(index, record)
	}
	if record.Phase == "complete" && !obs.completed {
		record.Phase = "nonce_conflict"
		record.LastError = "stored completion not present in authenticated state"
		return r.update(index, record)
	}
	if record.Job.Lane == Inbox {
		if obs.completed {
			return r.complete(index, record)
		}
		if !submit {
			return r.update(index, record)
		}
		if !obs.ready || !r.dependenciesReady(record.Job) {
			record.Phase = "waiting"
			return r.update(index, record)
		}
		if record.Attempt.Sends == ^uint64(0) {
			return r.failure(index, record, ErrCapacity)
		}
		record.Attempt.Sends++
		record.Phase = "submitted"
		if err := r.update(index, record); err != nil {
			return err
		}
		if err := r.hook("before_send"); err != nil {
			return err
		}
		_, err = r.backend.SendDEX(ctx, append([]byte(nil), record.Job.Payload...))
		if e := r.hook("after_send"); e != nil {
			return e
		}
		return r.failure(index, record, err)
	}
	if obs.balance == nil || obs.balance.Sign() < 0 || obs.balance.BitLen() > 256 {
		return r.failure(index, record, errors.New("relay payer account proof unavailable"))
	}
	if record.Attempt.GasLimit != 0 && obs.nonce > record.Attempt.Nonce {
		if obs.completed {
			return r.complete(index, record)
		}
		record.Phase = "nonce_conflict"
		record.LastError = "authenticated payer nonce consumed without expected completion"
		return r.update(index, record)
	}
	if obs.completed && len(record.Attempt.Raw) == 0 && len(record.PriorAttempts) == 0 {
		record.Attempt = Attempt{}
		return r.complete(index, record)
	}
	if record.Attempt.GasLimit != 0 && obs.nonce < record.Attempt.Nonce {
		return r.failure(index, record, errors.New("authenticated nonce regressed; wait"))
	}
	if !submit {
		if obs.completed {
			// Another sender completed the business operation. Our signed TX
			// and unconsumed nonce remain durable for a later local leader term.
			record.Phase = "completed_pending_nonce"
		}
		if err := r.update(index, record); err != nil {
			return err
		}
		if obs.completed {
			r.validated[record.Job.ID] = true
		}
		return nil
	}
	if !obs.ready && !obs.completed {
		if record.Attempt.GasLimit == 0 {
			record.Phase = "waiting"
		}
		return r.update(index, record)
	}
	if !r.dependenciesReady(record.Job) && record.Attempt.GasLimit == 0 {
		record.Phase = "waiting"
		return r.update(index, record)
	}
	payer := r.config.Payers[record.Job.Lane]
	gasLimit := r.config.EffectiveGasLimit(record.Job.Lane)
	if obs.requiredGas > gasLimit {
		record.LastError = "gas_budget_wait: native execution and calldata exceed effective transaction budget"
		if record.Attempt.GasLimit == 0 {
			record.Phase = "waiting"
		}
		return r.update(index, record)
	}
	if record.Attempt.GasLimit > gasLimit {
		// Correct only the one obsolete protocol-cap template. The account
		// nonce above came from authenticated CLX state, not mempool or ACK.
		// Never forget a possibly delivered old signature when preserving the
		// nonce for a replacement with identical business payload/payer/price.
		if obs.nonce != record.Attempt.Nonce || len(record.PriorAttempts) != 0 || record.Attempt.GasLimit != r.config.GasLimits[record.Job.Lane] {
			return r.failure(index, record, ErrConflict)
		}
		cost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), record.Attempt.GasPrice.Big())
		if obs.balance.Cmp(cost) < 0 {
			record.LastError = "gas_wait"
			return r.update(index, record)
		}
		if err := r.hook("before_gas_replacement"); err != nil {
			return err
		}
		record.PriorAttempts = []Attempt{record.Attempt}
		record.Attempt = Attempt{Nonce: record.Attempt.Nonce, GasLimit: gasLimit, GasPrice: record.Attempt.GasPrice}
		record.Phase = "prepared"
		if err := r.update(index, record); err != nil {
			return err
		}
		if err := r.hook("after_gas_replacement"); err != nil {
			return err
		}
	}
	if record.Attempt.GasLimit == 0 {
		if r.payerBusy(index, payer) {
			record.Phase = "waiting"
			record.LastError = "payer has an unresolved nonce"
			return r.update(index, record)
		}
		cost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), r.config.GasPrice)
		if obs.balance.Cmp(cost) < 0 {
			record.Phase = "waiting"
			record.LastError = "gas_wait"
			return r.update(index, record)
		}
		price, _ := protocol.AmountFromBig(r.config.GasPrice)
		record.Attempt = Attempt{Nonce: obs.nonce, GasLimit: gasLimit, GasPrice: price}
		record.Phase = "prepared"
		if err := r.update(index, record); err != nil {
			return err
		}
		if err := r.hook("after_prepared"); err != nil {
			return err
		}
	}
	if len(record.Attempt.Raw) == 0 {
		template := types.NewTransaction(record.Attempt.Nonce, r.config.Custody, new(big.Int), record.Attempt.GasLimit, record.Attempt.GasPrice.Big(), record.Job.Payload)
		signed, err := r.signer.Sign(ctx, payer, template, new(big.Int).SetUint64(r.config.Domain.ChainID))
		if err != nil {
			return r.failure(index, record, err)
		}
		if signed == nil {
			return r.failure(index, record, errors.New("signer returned no transaction"))
		}
		raw, err := rlp.EncodeToBytes(signed)
		if err != nil {
			return r.failure(index, record, err)
		}
		record.Attempt.Raw = raw
		record.Attempt.Hash = signed.Hash()
		if err := verifySigned(r.config, record.Job, record.Attempt); err != nil {
			// This untrusted signer response must never enter the durable TX
			// journal. Keep the already reserved template/nonce and quarantine.
			record.Attempt.Raw = nil
			record.Attempt.Hash = common.Hash{}
			return r.failure(index, record, errors.Join(ErrInvalidJob, err))
		}
		record.Phase = "signed"
		if err := r.update(index, record); err != nil {
			return err
		}
		if err := r.hook("after_signed"); err != nil {
			return err
		}
	}
	if record.Attempt.Sends == ^uint64(0) {
		return r.failure(index, record, ErrCapacity)
	}
	record.Attempt.Sends++
	record.Phase = "submitted"
	if obs.completed {
		record.Phase = "completed_pending_nonce"
	}
	if err := r.update(index, record); err != nil {
		return err
	}
	if obs.completed {
		r.validated[record.Job.ID] = true
	}
	if err := r.hook("before_send"); err != nil {
		return err
	}
	hash, err := r.backend.SendRawTransaction(ctx, append([]byte(nil), record.Attempt.Raw...))
	if e := r.hook("after_send"); e != nil {
		return e
	}
	if err != nil {
		return r.failure(index, record, err)
	}
	if hash != record.Attempt.Hash {
		return r.failure(index, record, errors.New("RPC ACK transaction hash mismatch"))
	}
	record.Attempt.ACK = hash
	return r.update(index, record)
}
func (r *Relay) complete(index int, record Record) error {
	record.Phase = "complete"
	record.LastError = ""
	if err := r.update(index, record); err != nil {
		return err
	}
	r.validated[record.Job.ID] = true
	return r.hook("after_completion")
}
func (r *Relay) Run(ctx context.Context) error {
	timer := time.NewTicker(250 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := r.Step(ctx); err != nil {
			r.mu.Lock()
			fatal := r.fault != nil || r.closed
			r.mu.Unlock()
			if fatal {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func verifySigned(c Config, j Job, a Attempt) error {
	if len(a.Raw) == 0 || len(a.Raw) > 65*1024 {
		return errors.New("relay signed transaction size")
	}
	var tx types.Transaction
	if err := rlp.DecodeBytes(a.Raw, &tx); err != nil {
		return err
	}
	canonical, err := rlp.EncodeToBytes(&tx)
	if err != nil || !bytes.Equal(canonical, a.Raw) {
		return errors.New("relay signed transaction noncanonical")
	}
	if !tx.Protected() || tx.ChainId().Cmp(new(big.Int).SetUint64(c.Domain.ChainID)) != 0 || tx.To() == nil || *tx.To() != c.Custody || tx.Value().Sign() != 0 || tx.Nonce() != a.Nonce || tx.Gas() != a.GasLimit || tx.GasPrice().Cmp(a.GasPrice.Big()) != 0 || !bytes.Equal(tx.Data(), j.Payload) || tx.Hash() != a.Hash {
		return errors.New("signer changed transaction template")
	}
	sender, err := types.Sender(types.NewEIP155Signer(new(big.Int).SetUint64(c.Domain.ChainID)), &tx)
	if err != nil || sender != c.Payers[j.Lane] {
		return fmt.Errorf("relay signed transaction sender/chain: %v", err)
	}
	return nil
}

// ReplaceUnsent is explicit replanning after authenticated source state changes.
// Enqueue retains strict duplicate-payload semantics. No reserved/signed attempt
// can be changed, even when a signer timed out before returning its result.
func (r *Relay) ReplaceUnsent(j Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.usable(); err != nil {
		return err
	}
	if err := validateJob(j); err != nil {
		return err
	}
	index := r.find(j.ID)
	if index < 0 {
		return errors.New("relay replacement job absent")
	}
	old := r.state.Records[index]
	if old.Job.Lane != j.Lane || old.Job.Owner != j.Owner || old.Attempt.GasLimit != 0 || len(old.Attempt.Raw) != 0 || old.Attempt.Sends != 0 || (old.Phase != "queued" && old.Phase != "waiting" && old.Phase != "quarantined") {
		return ErrConflict
	}
	a, _ := rlp.EncodeToBytes(old.Job.Dependencies)
	b, _ := rlp.EncodeToBytes(j.Dependencies)
	if !bytes.Equal(a, b) {
		return ErrConflict
	}
	old.Job = cloneJob(j)
	old.Phase = "queued"
	old.Proof = nil
	old.LastError = ""
	if err := r.update(index, old); err != nil {
		return err
	}
	delete(r.validated, j.ID)
	delete(r.nextTry, j.ID)
	return nil
}
