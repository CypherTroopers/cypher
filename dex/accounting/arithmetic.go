// Package accounting implements isolated devnet integer arithmetic. It is not a
// matching engine, custody implementation, participation authenticator, or
// settlement adapter. All public amounts are canonical decimal strings so no
// mutable big.Int storage crosses the API boundary.
package accounting

import (
	"errors"
	"math/big"
	"sort"
)

const (
	QuantityScale = 100000000
	QuantityLot   = 100000
	PriceTick     = 1000
	PPM           = 1000000
	MaxAccounts   = 1024
	MaxValidators = 7
)

func bi(n int64) *big.Int { return big.NewInt(n) }
func maxMagnitude() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(bi(1), 128), bi(1))
}

func checked(n *big.Int, signed bool) (*big.Int, error) {
	if (!signed && n.Sign() < 0) || new(big.Int).Abs(n).Cmp(maxMagnitude()) > 0 {
		return nil, errors.New("RANGE")
	}
	return new(big.Int).Set(n), nil
}

func parse(s string, signed bool) (*big.Int, error) {
	start := 0
	if len(s) > 0 && s[0] == '-' {
		start = 1
	}
	if len(s) == start || (s[start] == '0' && (len(s)-start > 1 || start == 1)) {
		return nil, errors.New("INTEGER")
	}
	for _, c := range s[start:] {
		if c < '0' || c > '9' {
			return nil, errors.New("INTEGER")
		}
	}
	// Reject huge inputs before big.Int allocation; 128-bit magnitudes need at
	// most 39 decimal digits. The optional minus is counted separately.
	if len(s)-start > 39 {
		return nil, errors.New("RANGE")
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.New("INTEGER")
	}
	return checked(n, signed)
}

func price(s string) (*big.Int, error) {
	n, err := parse(s, false)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 || new(big.Int).Mod(n, bi(PriceTick)).Sign() != 0 {
		return nil, errors.New("PRICE_TICK")
	}
	return n, nil
}

func quantity(s string) (*big.Int, error) {
	n, err := parse(s, true)
	if err != nil {
		return nil, err
	}
	if new(big.Int).Mod(n, bi(QuantityLot)).Sign() != 0 {
		return nil, errors.New("QUANTITY_LOT")
	}
	return n, nil
}

func result(n *big.Int, signed bool) (string, error) {
	v, err := checked(n, signed)
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

func ceilPositive(n, d *big.Int) *big.Int {
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(n, d, rem)
	if rem.Sign() != 0 {
		q.Add(q, bi(1))
	}
	return q
}

func minimum(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

// Notional returns CLX atoms for the absolute BTC quantity.
func Notional(p, q string) (string, error) {
	pv, err := price(p)
	if err != nil {
		return "", err
	}
	qv, err := quantity(q)
	if err != nil {
		return "", err
	}
	n, rem := new(big.Int), new(big.Int)
	n.QuoRem(new(big.Int).Mul(pv, new(big.Int).Abs(qv)), bi(QuantityScale), rem)
	if rem.Sign() != 0 {
		return "", errors.New("NONINTEGRAL_NOTIONAL")
	}
	return result(n, false)
}

// Charge computes a fee or margin requirement with atom rounding upward.
func Charge(p, q, ratePPM string) (string, error) {
	ns, err := Notional(p, q)
	if err != nil {
		return "", err
	}
	n, _ := parse(ns, false)
	r, err := parse(ratePPM, true)
	if err != nil {
		return "", err
	}
	if r.Sign() < 0 || r.Cmp(bi(PPM)) > 0 {
		return "", errors.New("RATE")
	}
	return result(ceilPositive(new(big.Int).Mul(n, r), bi(PPM)), false)
}

// PnL is the exact realized cashflow for a closed signed FIFO lot.
func PnL(entry, exit, q string) (string, error) {
	e, err := price(entry)
	if err != nil {
		return "", err
	}
	x, err := price(exit)
	if err != nil {
		return "", err
	}
	qv, err := quantity(q)
	if err != nil {
		return "", err
	}
	n, rem := new(big.Int), new(big.Int)
	n.QuoRem(new(big.Int).Mul(qv, new(big.Int).Sub(x, e)), bi(QuantityScale), rem)
	if rem.Sign() != 0 {
		return "", errors.New("NONINTEGRAL_PNL")
	}
	return result(n, true)
}

type FundingResult struct {
	CashDeltas map[string]string `json:"cash_deltas"`
	Dust       string            `json:"dust"`
}

// Funding takes a zero-net-quantity snapshot. Positive rate charges longs.
func Funding(p string, positions map[string]string, ratePPM string) (FundingResult, error) {
	fail := func(err error) (FundingResult, error) { return FundingResult{}, err }
	pv, err := price(p)
	if err != nil {
		return fail(err)
	}
	r, err := parse(ratePPM, true)
	if err != nil {
		return fail(err)
	}
	if new(big.Int).Abs(r).Cmp(bi(10000)) > 0 {
		return fail(errors.New("FUNDING_RATE"))
	}
	if len(positions) == 0 || len(positions) > MaxAccounts {
		return fail(errors.New("ACCOUNT_BOUND"))
	}
	qs := make(map[string]*big.Int, len(positions))
	net := bi(0)
	for id, raw := range positions {
		q, err := quantity(raw)
		if err != nil {
			return fail(err)
		}
		qs[id] = q
		net.Add(net, q)
	}
	if net.Sign() != 0 {
		return fail(errors.New("UNBALANCED_POSITION"))
	}
	out := FundingResult{CashDeltas: make(map[string]string, len(positions))}
	sum := bi(0)
	denom := new(big.Int).Mul(bi(QuantityScale), bi(PPM))
	for id, q := range qs {
		n := new(big.Int).Mul(new(big.Int).Mul(q, pv), r)
		var delta *big.Int
		if n.Sign() > 0 {
			delta = new(big.Int).Neg(ceilPositive(n, denom))
		} else {
			delta = new(big.Int).Quo(new(big.Int).Neg(n), denom)
		}
		s, err := result(delta, true)
		if err != nil {
			return fail(err)
		}
		out.CashDeltas[id] = s
		sum.Add(sum, delta)
	}
	out.Dust, err = result(new(big.Int).Neg(sum), false)
	if err != nil {
		return fail(err)
	}
	return out, nil
}

type InsuranceResult struct {
	Cash          string `json:"cash"`
	Insurance     string `json:"insurance"`
	InsuranceUsed string `json:"insurance_used"`
	UncoveredDebt string `json:"uncovered_debt"`
	Status        string `json:"status"`
}

// ResolveInsurance is only valid once the distressed account has no position.
// The caller must enforce that precondition; this arithmetic API has no state.
func ResolveInsurance(cash, insurance string) (InsuranceResult, error) {
	b, err := parse(cash, true)
	if err != nil {
		return InsuranceResult{}, err
	}
	i, err := parse(insurance, false)
	if err != nil {
		return InsuranceResult{}, err
	}
	used := bi(0)
	if b.Sign() < 0 {
		used = minimum(new(big.Int).Neg(b), i)
	}
	b.Add(b, used)
	i.Sub(i, used)
	debt, status := bi(0), "NORMAL"
	if b.Sign() < 0 {
		debt.Neg(b)
		status = "FROZEN"
	}
	return InsuranceResult{b.String(), i.String(), used.String(), debt.String(), status}, nil
}

type RewardInput struct {
	Fees      string            `json:"fees"`
	Support   string            `json:"support"`
	Allowance string            `json:"allowance"`
	Cap       string            `json:"cap"`
	Points    map[string]string `json:"points"`
	RhoNum    string            `json:"rho_num,omitempty"`
	RhoDen    string            `json:"rho_den,omitempty"`
}

type RewardResult struct {
	Budget           string            `json:"budget"`
	FromFees         string            `json:"from_fees"`
	FromSupport      string            `json:"from_support"`
	FeesRemaining    string            `json:"fees_remaining"`
	SupportRemaining string            `json:"support_remaining"`
	Allocations      map[string]string `json:"allocations"`
}

// Reward reserves a bounded pool and apportions it by authenticated points.
// Authentication, period uniqueness, and recipient binding belong to callers.
func Reward(in RewardInput) (RewardResult, error) {
	fail := func(err error) (RewardResult, error) { return RewardResult{}, err }
	vs := make([]*big.Int, 4)
	for idx, s := range []string{in.Fees, in.Support, in.Allowance, in.Cap} {
		v, err := parse(s, false)
		if err != nil {
			return fail(err)
		}
		vs[idx] = v
	}
	fees, support, allowance, cap := vs[0], vs[1], vs[2], vs[3]
	if in.RhoNum == "" {
		in.RhoNum = "1"
	}
	if in.RhoDen == "" {
		in.RhoDen = "2"
	}
	num, err := parse(in.RhoNum, true)
	if err != nil {
		return fail(err)
	}
	den, err := parse(in.RhoDen, true)
	if err != nil {
		return fail(err)
	}
	if num.Sign() < 0 || den.Sign() <= 0 || num.Cmp(den) > 0 {
		return fail(errors.New("RHO"))
	}
	if len(in.Points) == 0 || len(in.Points) > MaxValidators {
		return fail(errors.New("VALIDATOR_BOUND"))
	}
	scores, total := make(map[string]*big.Int, len(in.Points)), bi(0)
	for id, raw := range in.Points {
		score, err := parse(raw, false)
		if err != nil {
			return fail(err)
		}
		if score.Cmp(bi(10)) > 0 {
			return fail(errors.New("POINT_BOUND"))
		}
		scores[id] = score
		total.Add(total, score)
	}
	share := new(big.Int).Quo(new(big.Int).Mul(fees, num), den)
	budget := bi(0)
	if total.Sign() > 0 {
		budget = minimum(new(big.Int).Add(share, minimum(support, allowance)), cap)
	}
	fromFees := minimum(share, budget)
	fromSupport := new(big.Int).Sub(budget, fromFees)
	alloc, remainders := make(map[string]*big.Int), make(map[string]*big.Int)
	ids, paid := make([]string, 0, len(scores)), bi(0)
	for id, score := range scores {
		q, rem := bi(0), bi(0)
		if total.Sign() > 0 {
			q.QuoRem(new(big.Int).Mul(budget, score), total, rem)
		}
		alloc[id], remainders[id] = q, rem
		ids = append(ids, id)
		paid.Add(paid, q)
	}
	sort.Slice(ids, func(i, j int) bool {
		c := remainders[ids[i]].Cmp(remainders[ids[j]])
		if c == 0 {
			return ids[i] < ids[j]
		}
		return c > 0
	})
	left := new(big.Int).Sub(budget, paid)
	// Largest-remainder apportionment leaves less than one atom per identity.
	if !left.IsInt64() || left.Sign() < 0 || left.Int64() >= int64(len(ids)) {
		return fail(errors.New("ALLOCATION"))
	}
	for idx := int64(0); idx < left.Int64(); idx++ {
		alloc[ids[idx]].Add(alloc[ids[idx]], bi(1))
	}
	out := RewardResult{budget.String(), fromFees.String(), fromSupport.String(),
		new(big.Int).Sub(fees, fromFees).String(), new(big.Int).Sub(support, fromSupport).String(), make(map[string]string)}
	for id, value := range alloc {
		out.Allocations[id] = value.String()
	}
	return out, nil
}

type EquityAccount struct {
	Cash     string `json:"cash"`
	Quantity string `json:"quantity"`
	Entry    string `json:"entry"`
}

type EquityInput struct {
	Mark     string                   `json:"mark"`
	Accounts map[string]EquityAccount `json:"accounts"`
	Custody  string                   `json:"custody"`
	Pools    string                   `json:"pools"`
}

type EquityResult struct {
	Cash       string `json:"cash"`
	Unrealized string `json:"unrealized"`
	Rights     string `json:"rights"`
}

// EquityConservation handles asymmetric closes: realized PnL alone need not
// sum to zero while open positions remain. Every account must be included.
func EquityConservation(in EquityInput) (EquityResult, error) {
	fail := func(err error) (EquityResult, error) { return EquityResult{}, err }
	if _, err := price(in.Mark); err != nil {
		return fail(err)
	}
	if len(in.Accounts) == 0 || len(in.Accounts) > MaxAccounts {
		return fail(errors.New("ACCOUNT_BOUND"))
	}
	cash, unrealized, net := bi(0), bi(0), bi(0)
	for _, a := range in.Accounts {
		q, err := quantity(a.Quantity)
		if err != nil {
			return fail(err)
		}
		net.Add(net, q)
		c, err := parse(a.Cash, true)
		if err != nil {
			return fail(err)
		}
		cash.Add(cash, c)
		ps, err := PnL(a.Entry, in.Mark, a.Quantity)
		if err != nil {
			return fail(err)
		}
		p, _ := parse(ps, true)
		unrealized.Add(unrealized, p)
	}
	if net.Sign() != 0 {
		return fail(errors.New("UNBALANCED_POSITION"))
	}
	pool, err := parse(in.Pools, false)
	if err != nil {
		return fail(err)
	}
	custody, err := parse(in.Custody, false)
	if err != nil {
		return fail(err)
	}
	rights := new(big.Int).Add(new(big.Int).Add(cash, unrealized), pool)
	if custody.Cmp(rights) != 0 {
		return fail(errors.New("CONSERVATION"))
	}
	cs, err := result(cash, true)
	if err != nil {
		return fail(err)
	}
	us, err := result(unrealized, true)
	if err != nil {
		return fail(err)
	}
	return EquityResult{cs, us, rights.String()}, nil
}
