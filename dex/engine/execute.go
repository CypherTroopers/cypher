package engine

import (
	"encoding/binary"
	"errors"
	"github.com/cypherium/cypher/dex/instrumentation"
	"math/big"

	"github.com/cypherium/cypher/dex/accounting"
	"github.com/cypherium/cypher/dex/protocol"
)

func fresh(s *State) bool { return s.FeedSequence != 0 && s.Height <= s.ValidUntil }
func (e *Engine) Apply(parent *State, raw []byte, height uint64) (*State, Delta, error) {
	instrumentation.ActionExecuted()
	d := Delta{DepositTotal: "0", Fees: "0", Dust: "0", InsuranceUsed: "0", Withdrawals: []protocol.Claim{}}
	fail := func(err error) (*State, Delta, error) { return nil, Delta{}, err }
	if err := e.validate(parent); err != nil {
		return fail(err)
	}
	if parent.Height == ^uint64(0) || height != parent.Height+1 {
		return fail(errors.New("ACTION_HEIGHT"))
	}
	a, err := Decode(raw)
	if err != nil {
		return fail(err)
	}
	if a.Epoch != e.config.Domain.EpochKey() {
		return fail(errors.New("ACTION_REPLAY_DOMAIN"))
	}
	s := clone(parent)
	s.Height = height
	if height%10 == 0 && s.PendingFunding == 0 {
		for _, account := range s.Accounts {
			if position(account) != 0 {
				s.PendingFunding = height
				break
			}
		}
	}
	owner := id(a.Owner)
	account := s.Accounts[owner]
	if account == nil {
		if a.Kind != Credit || len(s.Accounts) >= 16 {
			return fail(errors.New("UNKNOWN_ACCOUNT"))
		}
		account = &Account{Cash: "0", Lots: []Lot{}}
		s.Accounts[owner] = account
	}
	if account.Nonce == ^uint64(0) || a.Nonce != account.Nonce+1 {
		return fail(errors.New("ACTION_NONCE"))
	}
	if s.Frozen && a.Kind != Noop && a.Kind != Cancel && a.Kind != Oracle {
		return fail(errors.New("FROZEN"))
	}
	if s.PendingFunding != 0 && a.Kind != Noop && a.Kind != Cancel && a.Kind != Oracle && a.Kind != Funding {
		return fail(errors.New("FUNDING_PENDING"))
	}
	if a.Kind != Noop && a.Kind != Credit && a.Kind != Oracle && a.Kind != Cancel && !fresh(s) {
		return fail(errors.New("ORACLE_STALE"))
	}
	d.InboxStart = s.InboxCursor
	d.InboxEnd = s.InboxCursor
	switch a.Kind {
	case Noop:
		if a.Owner != e.config.Oracle {
			return fail(errors.New("ORACLE_AUTH"))
		}
	case RewardClose:
		// This step only advances the authenticated nonce/clock. The execution
		// wrapper verifies the bound package and reserves its computed rewards.
		if a.Owner != e.config.Oracle {
			return fail(errors.New("ORACLE_AUTH"))
		}
	case Credit:
		if e.config.NativeInbox {
			return fail(errors.New("FINALIZED_INBOX_EVIDENCE_REQUIRED"))
		}
		if a.DepositID != s.InboxCursor || a.DepositID >= uint64(len(e.config.Deposits)) {
			return fail(errors.New("DEPOSIT_CURSOR"))
		}
		dep := e.config.Deposits[a.DepositID]
		if dep.Owner != a.Owner {
			return fail(errors.New("DEPOSIT_OWNER"))
		}
		v := dep.Amount.Big().String()
		account.Cash = sum(account.Cash, v)
		s.Total = sum(s.Total, v)
		s.InboxCursor++
		d.DepositTotal = v
		d.InboxEnd = s.InboxCursor
		d.InboxRoot, err = protocol.DepositInboxRoot([]protocol.Deposit{dep})
		if err != nil {
			return fail(err)
		}
	case Oracle:
		if a.Owner != e.config.Oracle || a.FeedSequence != s.FeedSequence+1 || a.FundingRate < -10000 || a.FundingRate > 10000 || a.ValidUntil < height || height > ^uint64(0)-100 || a.ValidUntil > height+100 {
			return fail(errors.New("ORACLE_UPDATE"))
		}
		p := a.Price.Big().String()
		if _, err := accounting.Notional(p, "100000000"); err != nil {
			return fail(err)
		}
		s.Mark = p
		s.Rate = a.FundingRate
		s.FeedSequence = a.FeedSequence
		s.ValidUntil = a.ValidUntil
	case Cancel:
		if err := cancel(s, owner, a.OrderID); err != nil {
			return fail(err)
		}
	case Place, Amend:
		if a.Kind == Amend {
			if err := cancel(s, owner, a.OrderID); err != nil {
				return fail(err)
			}
		}
		if err := e.place(s, a, false); err != nil {
			return fail(err)
		}
	case Withdraw:
		if position(account) != 0 {
			return fail(errors.New("OPEN_POSITION"))
		}
		for _, o := range s.Orders {
			if o.Owner == owner {
				return fail(errors.New("OPEN_ORDER"))
			}
		}
		v := a.Amount.Big().String()
		if number(account.Cash).Cmp(number(v)) < 0 {
			return fail(errors.New("INSUFFICIENT_CASH"))
		}
		account.Cash = sub(account.Cash, v)
		s.WithdrawReserved = sum(s.WithdrawReserved, v)
		var key [28]byte
		copy(key[:20], a.Owner[:])
		binary.BigEndian.PutUint64(key[20:], a.Nonce)
		d.Withdrawals = append(d.Withdrawals, protocol.Claim{Domain: e.config.Domain, Sequence: height, Kind: protocol.Withdrawal, ID: protocol.Digest("common-dex/withdraw-id/v1", key[:]), Owner: a.Owner, Recipient: a.Recipient, Amount: a.Amount})
	case Funding:
		if a.Owner != e.config.Oracle || (height%10 != 0 && s.PendingFunding == 0) || s.LastFunding >= height {
			return fail(errors.New("FUNDING_SLOT"))
		}
		positions := map[string]string{}
		for who, v := range s.Accounts {
			positions[who] = new(big.Int).SetInt64(position(v)).String()
		}
		fund, err := accounting.Funding(s.Mark, positions, new(big.Int).SetInt64(s.Rate).String())
		if err != nil {
			return fail(err)
		}
		for who, delta := range fund.CashDeltas {
			s.Accounts[who].Cash = sum(s.Accounts[who].Cash, delta)
		}
		s.Dust = sum(s.Dust, fund.Dust)
		s.LastFunding = height
		s.PendingFunding = 0
	case Liquidate:
		if a.Owner != e.config.Oracle {
			return fail(errors.New("ORACLE_AUTH"))
		}
		target := id(a.Target)
		victim := s.Accounts[target]
		if victim == nil {
			return fail(errors.New("UNKNOWN_ACCOUNT"))
		}
		q := position(victim)
		eq, err := equity(s, target)
		if err != nil {
			return fail(err)
		}
		mm, err := accounting.Charge(s.Mark, new(big.Int).SetInt64(q).String(), "50000")
		if err != nil {
			return fail(err)
		}
		if q == 0 || eq.Cmp(number(mm)) > 0 {
			return fail(errors.New("NOT_LIQUIDATABLE"))
		}
		kept := s.Orders[:0]
		for _, o := range s.Orders {
			if o.Owner != target {
				kept = append(kept, o)
			}
		}
		s.Orders = kept
		side := int8(-1)
		rate := int64(95)
		if q < 0 {
			side = 1
			rate = 105
		}
		// Round inward to the permitted collar. A sell floor rounded down can
		// admit a price below 95% (and becomes zero at the minimum price tick).
		// Buy ceilings round down; sell floors round up, using one division so
		// a fractional atom is not discarded before the tick rounding.
		numerator := new(big.Int).Mul(number(s.Mark), big.NewInt(rate))
		denominator := big.NewInt(100 * accounting.PriceTick)
		limit, remainder := new(big.Int), new(big.Int)
		limit.QuoRem(numerator, denominator, remainder)
		if side < 0 && remainder.Sign() != 0 {
			limit.Add(limit, big.NewInt(1))
		}
		limit.Mul(limit, big.NewInt(accounting.PriceTick))
		liquidation := Action{Owner: a.Target, OrderID: height, Side: side, Quantity: abs(q), Price: Amount(limit.String()), Flags: IOC | ReduceOnly}
		if err := e.place(s, liquidation, true); err != nil {
			return fail(err)
		}
		victim = s.Accounts[target]
		if position(victim) == 0 && number(victim.Cash).Sign() < 0 {
			insurance, err := accounting.ResolveInsurance(victim.Cash, s.Insurance)
			if err != nil {
				return fail(err)
			}
			victim.Cash = insurance.Cash
			s.Insurance = insurance.Insurance
			if insurance.Status == "FROZEN" {
				s.Frozen = true
			}
		}
	}
	// Matching replaces the private state value, so reacquire the account.
	s.Accounts[owner].Nonce = a.Nonce
	d.Fees = sub(s.Fees, parent.Fees)
	d.Dust = sub(s.Dust, parent.Dust)
	d.InsuranceUsed = sub(parent.Insurance, s.Insurance)
	if err := e.validate(s); err != nil {
		return fail(err)
	}
	return s, d, nil
}

func cancel(s *State, owner string, orderID uint64) error {
	for i, o := range s.Orders {
		if o.Owner == owner && o.ID == orderID {
			s.Orders = append(s.Orders[:i], s.Orders[i+1:]...)
			return nil
		}
	}
	return errors.New("ORDER_NOT_FOUND")
}
func crosses(side int8, limit, price string) bool {
	c := number(limit).Cmp(number(price))
	return side > 0 && c >= 0 || side < 0 && c <= 0
}
func reduceValid(a *Account, side int8, q uint64) bool {
	p := position(a)
	return p != 0 && (p > 0) != (side > 0) && q <= abs(p)
}

func (e *Engine) place(s *State, a Action, liquidation bool) error {
	owner := id(a.Owner)
	price := a.Price.Big().String()
	if _, err := accounting.Notional(price, new(big.Int).SetUint64(a.Quantity).String()); err != nil {
		return err
	}
	for _, o := range s.Orders {
		if o.Owner == owner && o.ID == a.OrderID {
			return errors.New("DUPLICATE_ORDER")
		}
	}
	if a.Flags&ReduceOnly != 0 && !reduceValid(s.Accounts[owner], a.Side, a.Quantity) {
		return errors.New("REDUCE_ONLY")
	}
	if a.Flags&PostOnly != 0 {
		for _, i := range sortedOrders(s, a.Side) {
			if crosses(a.Side, price, s.Orders[i].Price) {
				return errors.New("POST_ONLY_CROSS")
			}
		}
	}
	remaining := a.Quantity
	for remaining > 0 {
		indices := sortedOrders(s, a.Side)
		if len(indices) == 0 {
			break
		}
		i := indices[0]
		maker := s.Orders[i]
		if !crosses(a.Side, price, maker.Price) {
			break
		}
		if maker.Owner == owner {
			return errors.New("SELF_TRADE")
		}
		if maker.Flags&ReduceOnly != 0 && !reduceValid(s.Accounts[maker.Owner], maker.Side, maker.Quantity) {
			s.Orders = append(s.Orders[:i], s.Orders[i+1:]...)
			continue
		}
		if err := risk(s, maker.Owner); err != nil {
			s.Orders = append(s.Orders[:i], s.Orders[i+1:]...)
			continue
		}
		q := remaining
		if maker.Quantity < q {
			q = maker.Quantity
		}
		trial := clone(s)
		trial.Orders[i].Quantity -= q
		if trial.Orders[i].Quantity == 0 {
			trial.Orders = append(trial.Orders[:i], trial.Orders[i+1:]...)
		}
		if err := trade(trial, owner, a.Side, maker.Owner, maker.Price, q); err != nil {
			return err
		}
		if err := risk(trial, maker.Owner); err != nil {
			s.Orders = append(s.Orders[:i], s.Orders[i+1:]...)
			continue
		}
		if !liquidation {
			if err := risk(trial, owner); err != nil {
				return err
			}
		}
		*s = *trial
		remaining -= q
	}
	if remaining > 0 && a.Flags&IOC == 0 {
		if len(s.Orders) >= 64 {
			return errors.New("ORDER_CAPACITY")
		}
		s.Orders = append(s.Orders, Order{a.OrderID, owner, a.Side, remaining, price, a.Flags, s.Height})
		if err := risk(s, owner); err != nil {
			return err
		}
	}
	return nil
}

func trade(s *State, taker string, side int8, maker, price string, q uint64) error {
	for index, who := range []string{taker, maker} {
		direction := int64(side)
		rate := "300"
		if index == 1 {
			direction = -direction
			rate = "100"
		}
		a := s.Accounts[who]
		remaining := int64(q) * direction
		for remaining != 0 && len(a.Lots) > 0 && (a.Lots[0].Quantity > 0) != (remaining > 0) {
			lot := a.Lots[0]
			closed := abs(remaining)
			if abs(lot.Quantity) < closed {
				closed = abs(lot.Quantity)
			}
			signed := int64(closed)
			if lot.Quantity < 0 {
				signed = -signed
			}
			pnl, err := accounting.PnL(lot.Entry, price, new(big.Int).SetInt64(signed).String())
			if err != nil {
				return err
			}
			a.Cash = sum(a.Cash, pnl)
			remaining += signed
			a.Lots[0].Quantity -= signed
			if a.Lots[0].Quantity == 0 {
				a.Lots = a.Lots[1:]
			}
		}
		if remaining != 0 {
			if len(a.Lots) >= 64 {
				return errors.New("LOT_CAPACITY")
			}
			a.Lots = append(a.Lots, Lot{remaining, price})
		}
		fee, err := accounting.Charge(price, new(big.Int).SetUint64(q).String(), rate)
		if err != nil {
			return err
		}
		a.Cash = sub(a.Cash, fee)
		s.Fees = sum(s.Fees, fee)
		s.PeriodFees = sum(s.PeriodFees, fee)
	}
	return nil
}
