package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/cypherium/cypher/dex/instrumentation"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/dex/accounting"
	"github.com/cypherium/cypher/dex/protocol"
)

const MaxStateBytes = 1024 * 1024

type Lot struct {
	Quantity int64
	Entry    string
}
type Account struct {
	Cash  string
	Nonce uint64
	Lots  []Lot
}
type Order struct {
	ID       uint64
	Owner    string
	Side     int8
	Quantity uint64
	Price    string
	Flags    uint8
	Time     uint64
}
type State struct {
	Version                                                                 uint16
	Config                                                                  protocol.Hash
	Height                                                                  uint64
	Accounts                                                                map[string]*Account
	Orders                                                                  []Order
	Mark                                                                    string
	Rate                                                                    int64
	FeedSequence, ValidUntil, LastFunding                                   uint64
	PendingFunding                                                          uint64
	InboxCursor                                                             uint64
	Fees, Support, Insurance, Dust, WithdrawReserved, RewardReserved, Total string
	PeriodFees                                                              string
	RewardPeriod                                                            uint64
	Frozen                                                                  bool
}
type Config struct {
	Domain  protocol.Domain
	Oracle  [20]byte
	Custody [20]byte
	// Deposits are copied from an authenticated finalized CLX StateDB snapshot.
	// No caller-supplied amount or HTTP read is used while executing a proposal.
	Deposits           []protocol.Deposit
	Support, Insurance string
	CLXHeight          uint64
	CLXHash            protocol.Hash
	NativeInbox        bool `json:",omitempty"`
}
type Engine struct {
	config     Config
	commitment protocol.Hash
}

func (e *Engine) Domain() protocol.Domain  { return e.config.Domain }
func (e *Engine) Custody() [20]byte        { return e.config.Custody }
func (e *Engine) Oracle() [20]byte         { return e.config.Oracle }
func (e *Engine) NativeInboxEnabled() bool { return e.config.NativeInbox }
func (e *Engine) Validate(s *State) error  { return e.validate(s) }

type Delta struct {
	InboxStart, InboxEnd                    uint64
	InboxRoot                               protocol.Hash
	DepositTotal, Fees, Dust, InsuranceUsed string
	Withdrawals                             []protocol.Claim
}

func number(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("internal noninteger")
	}
	return n
}
func zero() *big.Int         { return new(big.Int) }
func sum(a, b string) string { return new(big.Int).Add(number(a), number(b)).String() }
func sub(a, b string) string { return new(big.Int).Sub(number(a), number(b)).String() }
func validInteger(s string, signed bool) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.String() == s && n.BitLen() <= 128 && (signed || n.Sign() >= 0)
}
func id(a [20]byte) string      { return hex.EncodeToString(a[:]) }
func address(s string) [20]byte { var a [20]byte; b, _ := hex.DecodeString(s); copy(a[:], b); return a }
func position(a *Account) int64 {
	var q int64
	for _, l := range a.Lots {
		q += l.Quantity
	}
	return q
}
func abs(q int64) uint64 {
	if q < 0 {
		return uint64(-q)
	}
	return uint64(q)
}

func New(c Config) (*Engine, error) {
	if !c.Domain.Valid() || c.Oracle == ([20]byte{}) || c.Custody == ([20]byte{}) || c.CLXHash == (protocol.Hash{}) || len(c.Deposits) > 128 || !validInteger(c.Support, false) || !validInteger(c.Insurance, false) {
		return nil, errors.New("ENGINE_CONFIG")
	}
	if c.NativeInbox && (len(c.Deposits) != 0 || c.Support != "0" || c.Insurance != "0") {
		return nil, errors.New("NATIVE_GENESIS_MUST_BE_EMPTY")
	}
	for i, d := range c.Deposits {
		if _, err := d.Encode(); err != nil {
			return nil, err
		}
		if d.ID != uint64(i) || d.Domain != c.Domain || d.Custody != c.Custody || d.CLXHeight != c.CLXHeight || d.CLXHash != c.CLXHash {
			return nil, errors.New("UNAUTHENTICATED_DEPOSIT")
		}
	}
	c.Deposits = append([]protocol.Deposit(nil), c.Deposits...)
	raw, _ := json.Marshal(c)
	instrumentation.EngineCreated()
	return &Engine{config: c, commitment: protocol.Digest("common-dex/engine-config/v1", raw)}, nil
}
func (e *Engine) Genesis() (*State, error) {
	s := &State{Version: 1, Config: e.commitment, Accounts: map[string]*Account{id(e.config.Oracle): {Cash: "0", Lots: []Lot{}}}, Orders: []Order{}, Mark: "0", Fees: "0", Support: e.config.Support, Insurance: e.config.Insurance, Dust: "0", WithdrawReserved: "0", RewardReserved: "0", Total: sum(e.config.Support, e.config.Insurance), PeriodFees: "0"}
	return s, e.validate(s)
}
func (s *State) Encode() ([]byte, error) {
	raw, err := json.Marshal(s)
	if len(raw) > MaxStateBytes {
		return nil, errors.New("STATE_SIZE")
	}
	return raw, err
}
func (s *State) Root() (protocol.Hash, error) {
	raw, err := s.Encode()
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.Digest("common-dex/engine-state/v1", raw), nil
}
func (e *Engine) Decode(raw []byte) (*State, error) {
	if len(raw) == 0 || len(raw) > MaxStateBytes {
		return nil, errors.New("STATE_SIZE")
	}
	var s State
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return nil, err
	}
	canonical, err := s.Encode()
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errors.New("NONCANONICAL_STATE")
	}
	return &s, e.validate(&s)
}
func clone(s *State) *State {
	raw, _ := s.Encode()
	var out State
	_ = json.Unmarshal(raw, &out)
	return &out
}
func (e *Engine) validate(s *State) error {
	if s == nil || s.Version != 1 || s.Config != e.commitment || len(s.Accounts) == 0 || len(s.Accounts) > 16 || len(s.Orders) > 64 || s.InboxCursor > e.inboxLimit() {
		return errors.New("STATE_BOUND")
	}
	if s.LastFunding > s.Height || (s.PendingFunding != 0 && (s.PendingFunding%10 != 0 || s.PendingFunding > s.Height || s.LastFunding >= s.PendingFunding)) {
		return errors.New("FUNDING_STATE")
	}
	for _, v := range []string{s.Mark, s.Fees, s.Support, s.Insurance, s.Dust, s.WithdrawReserved, s.RewardReserved, s.Total, s.PeriodFees} {
		if !validInteger(v, false) {
			return errors.New("STATE_AMOUNT")
		}
	}
	var net int64
	rights := zero()
	for owner, a := range s.Accounts {
		if len(owner) != 40 || id(address(owner)) != owner || a == nil || !validInteger(a.Cash, true) || len(a.Lots) > 64 {
			return errors.New("ACCOUNT_BOUND")
		}
		rights.Add(rights, number(a.Cash))
		var sign int64
		for _, l := range a.Lots {
			if l.Quantity == 0 || abs(l.Quantity) > 1_000_000_000_000 || l.Quantity%100000 != 0 || !validInteger(l.Entry, false) {
				return errors.New("LOT_BOUND")
			}
			if sign != 0 && (sign > 0) != (l.Quantity > 0) {
				return errors.New("FIFO_SIGN")
			}
			sign = l.Quantity
			p, err := accounting.PnL(l.Entry, s.Mark, new(big.Int).SetInt64(l.Quantity).String())
			if err != nil {
				return err
			}
			rights.Add(rights, number(p))
			net += l.Quantity
		}
	}
	if net != 0 {
		return errors.New("UNBALANCED_POSITION")
	}
	seen := make(map[string]bool)
	for _, o := range s.Orders {
		key := o.Owner + new(big.Int).SetUint64(o.ID).String()
		if s.Accounts[o.Owner] == nil || o.ID == 0 || seen[key] || o.Quantity == 0 || o.Quantity > 1e12 || o.Quantity%100000 != 0 || (o.Side != 1 && o.Side != -1) || o.Flags > 7 || o.Time > s.Height {
			return errors.New("ORDER_STATE")
		}
		seen[key] = true
		if _, err := accounting.Notional(o.Price, new(big.Int).SetUint64(o.Quantity).String()); err != nil {
			return err
		}
	}
	for _, v := range []string{s.Fees, s.Support, s.Insurance, s.Dust, s.WithdrawReserved, s.RewardReserved} {
		rights.Add(rights, number(v))
	}
	if rights.Cmp(number(s.Total)) != 0 {
		return errors.New("CONSERVATION")
	}
	return nil
}
func equity(s *State, owner string) (*big.Int, error) {
	a := s.Accounts[owner]
	eq := number(a.Cash)
	for _, l := range a.Lots {
		p, err := accounting.PnL(l.Entry, s.Mark, new(big.Int).SetInt64(l.Quantity).String())
		if err != nil {
			return nil, err
		}
		eq.Add(eq, number(p))
	}
	return eq, nil
}
func reserve(s *State, owner string) (*big.Int, error) {
	a := s.Accounts[owner]
	req := zero()
	im, err := accounting.Charge(s.Mark, new(big.Int).SetInt64(position(a)).String(), "100000")
	if err != nil {
		return nil, err
	}
	req.Add(req, number(im))
	for _, o := range s.Orders {
		if o.Owner != owner {
			continue
		}
		q := new(big.Int).SetUint64(o.Quantity).String()
		fee, err := accounting.Charge(o.Price, q, "300")
		if err != nil {
			return nil, err
		}
		req.Add(req, number(fee))
		if o.Flags&ReduceOnly == 0 {
			im, err := accounting.Charge(s.Mark, q, "100000")
			if err != nil {
				return nil, err
			}
			req.Add(req, number(im))
		}
	}
	return req, nil
}
func risk(s *State, owner string) error {
	eq, err := equity(s, owner)
	if err != nil {
		return err
	}
	req, err := reserve(s, owner)
	if err != nil {
		return err
	}
	if eq.Cmp(req) < 0 {
		return errors.New("INITIAL_MARGIN")
	}
	return nil
}
func sortedOrders(s *State, side int8) []int {
	indices := []int{}
	for i, o := range s.Orders {
		if o.Side == -side {
			indices = append(indices, i)
		}
	}
	sort.Slice(indices, func(i, j int) bool {
		a, b := s.Orders[indices[i]], s.Orders[indices[j]]
		c := number(a.Price).Cmp(number(b.Price))
		if c == 0 {
			return a.Time < b.Time
		}
		if side > 0 {
			return c < 0
		}
		return c > 0
	})
	return indices
}

func (e *Engine) inboxLimit() uint64 {
	if e.config.NativeInbox {
		return protocol.MaxInboxEntries
	}
	return uint64(len(e.config.Deposits))
}
