package reconfig_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
)

// exerciseDEXFinancialEconomy extends only the owned isolated scenario. It never
// submits these later financial roots to CLX, whose previously paid11CLX remains
// unchanged. Callback indices are the trace's alice0,bob1,oracle2. Callers should
// read account nonces again before signing further actions after this helper.
func exerciseDEXFinancialEconomy(t *testing.T, children []*dexFinancialChild, init testnet.Init, firstHeight uint64, sign func(int, uint8, func(*engine.Action)) []byte) uint64 {
	t.Helper()
	if len(children) != 7 || firstHeight < 4 || firstHeight+24 >= init.MaxHeight || sign == nil {
		t.Fatal("economic fixture bounds")
	}
	ordinary := children[0].cli != nil
	all := []int{0, 1, 2, 3, 4, 5, 6}
	live := all
	next := firstHeight
	positionsOpen, fundingPending := false, false
	offset := [4]uint64{}
	makeAction := func(who int, kind uint8, change func(*engine.Action), reject bool) []byte {
		raw := sign(who, kind, func(a *engine.Action) {
			if a.Nonce <= offset[who] {
				t.Fatal("economic nonce fixture")
			}
			a.Nonce -= offset[who]
			if change != nil {
				change(a)
			}
		})
		if reject {
			offset[who]++
		}
		return raw
	}
	var put func(int, uint8, func(*engine.Action)) uint64
	wait := func(indices []int, height uint64, final bool) {
		statuses := waitDEXFinancial(t, children, func(statuses []testnet.Response) bool {
			for _, i := range indices {
				s := statuses[i].Status
				if s == nil || s.Certified < height {
					return false
				}
			}
			return true
		})
		if !final {
			return
		}
		// Certified height alone does not imply finality: a skipped leader can
		// leave the last QC edge non-consecutive in view. Supply bounded signed
		// descendants and observe the actual FHS result, without changing its rule.
		for extra := 0; ; extra++ {
			ready := true
			for _, i := range indices {
				ready = ready && statuses[i].Status.Finalized >= height-1
			}
			if ready {
				return
			}
			if extra == len(children) || next >= init.MaxHeight {
				t.Fatal("economic finality descendant budget exhausted")
			}
			put(2, engine.Noop, nil)
			statuses = make([]testnet.Response, len(children))
			for _, i := range indices {
				statuses[i] = children[i].ok(t, testnet.Request{Op: "status"})
			}
		}
	}
	put = func(who int, kind uint8, change func(*engine.Action)) uint64 {
		h := next
		raw := makeAction(who, kind, change, false)
		children[0].ok(t, testnet.Request{Op: "action", Height: h, Raw: raw})
		wait(live, h, false)
		if h%10 == 0 && positionsOpen && kind != engine.Funding {
			fundingPending = true
		}
		if kind == engine.Funding {
			fundingPending = false
		}
		next++
		return h
	}
	load := func(index int, height uint64) (testnet.Response, *engine.State) {
		r := children[index].ok(t, testnet.Request{Op: "checkpoint", Height: height})
		var f devnet.FinancialState
		var s engine.State
		if err := json.Unmarshal(r.State, &f); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(f.Engine, &s); err != nil {
			t.Fatal(err)
		}
		if r.Checkpoint == nil || r.Checkpoint.Sequence != height || s.Height != height || s.Total != "225000000000000000000" {
			t.Fatal("economic state/total", height, s.Total)
		}
		w, ok := new(big.Int).SetString(s.WithdrawReserved, 10)
		if !ok {
			t.Fatal("withdraw reserve")
		}
		rw, ok := new(big.Int).SetString(s.RewardReserved, 10)
		if !ok || w.Add(w, rw).String() != "11000000000000000000" {
			t.Fatal("economic fixture changed11CLX reserve")
		}
		sum := new(big.Int)
		for _, account := range s.Accounts {
			v, ok := new(big.Int).SetString(account.Cash, 10)
			if !ok {
				t.Fatal("cash integer")
			}
			sum.Add(sum, v)
		}
		for _, value := range []string{s.Fees, s.Support, s.Insurance, s.Dust, s.WithdrawReserved, s.RewardReserved} {
			v, ok := new(big.Int).SetString(value, 10)
			if !ok {
				t.Fatal("bucket integer")
			}
			sum.Add(sum, v)
		}
		if sum.String() != s.Total {
			t.Fatal("financial economic cash/pool conservation", sum, s.Total)
		}
		return r, &s
	}
	check := func(height uint64, label string) *engine.State {
		var previous testnet.Response
		var state *engine.State
		for count, index := range live {
			r, s := load(index, height)
			if count > 0 && (*r.Checkpoint != *previous.Checkpoint || !bytes.Equal(r.State, previous.State)) {
				t.Fatalf("economic root divergence %s node%d", label, index)
			}
			previous, state = r, s
		}
		t.Logf("DEX_FINANCIAL_ECONOMY stage=%s finalized=%d root=%x total=225CLX reserved=11CLX mark=%s insurance=%s frozen=%v", label, height, previous.Checkpoint.PostRoot, state.Mark, state.Insurance, state.Frozen)
		return state
	}
	position := func(a *engine.Account) int64 {
		var q int64
		for _, lot := range a.Lots {
			q += lot.Quantity
		}
		return q
	}
	wait(all, firstHeight-1, true)
	_, baseline := load(0, firstHeight-2)
	feed := baseline.FeedSequence
	oracle := func(price int64, validUntil uint64) func(*engine.Action) {
		feed++
		seq := feed
		return func(a *engine.Action) {
			a.Price = engine.Amount(nativeUnits(price).String())
			a.FeedSequence = seq
			a.FundingRate = 0
			a.ValidUntil = validUntil
		}
	}
	order := func(id uint64, side int8, price int64, quantity uint64, flags uint8) func(*engine.Action) {
		return func(a *engine.Action) {
			a.OrderID = id
			a.Side = side
			a.Price = engine.Amount(nativeUnits(price).String())
			a.Quantity = quantity
			a.Flags = flags
		}
	}
	// Explicitly expire the feed, keep its old value, and cancel a real resting
	// order. No local wall clock fabricates a fresh mark or closes a position.
	put(2, engine.Oracle, oracle(100, firstHeight+2))
	rawBob := makeAction(1, engine.Place, order(8001, -1, 100, 10000000, engine.PostOnly), false)
	bobAction, err := engine.Decode(rawBob)
	if err != nil {
		t.Fatal(err)
	}
	bob := bobAction.Owner
	children[0].ok(t, testnet.Request{Op: "action", Height: next, Raw: rawBob})
	wait(live, next, false)
	next++
	put(2, engine.Noop, nil)
	cancelHeight := put(1, engine.Cancel, func(a *engine.Action) { a.OrderID = 8001 })
	put(2, engine.Noop, nil)
	wait(live, next-1, true)
	stale := check(cancelHeight, "oracle-stopped-cancel")
	if stale.Mark != nativeUnits(100).String() || stale.FeedSequence != feed || stale.ValidUntil >= stale.Height || len(stale.Orders) != 0 {
		t.Fatal("stopped oracle became fresh or cancel failed")
	}
	reject := func(who int, kind uint8, change func(*engine.Action), reason string) {
		raw := makeAction(who, kind, change, true)
		children[0].ok(t, testnet.Request{Op: "action", Height: next, Raw: raw})
		id := protocol.Digest("common-dex/ingress-action/v1", raw)
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			for _, child := range children {
				var status map[string]string
				if err := child.cli.http("GET", "/v1/action-status?id="+hex.EncodeToString(id[:]), nil, &status); err == nil && status["stage"] == "rejected" {
					if !strings.Contains(status["reason"], reason) {
						t.Fatal("wrong economic rejection", status)
					}
					t.Logf("DEX_FINANCIAL_ECONOMIC_REJECT reason=%s id=%x", status["reason"], id)
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("economic HTTP candidate did not reject", reason)
	}
	if ordinary {
		reject(1, engine.Place, order(8004, 1, 100, 10000000, engine.ReduceOnly), "ORACLE_STALE")
	} else {
		t.Log("NOT_RUN actual HTTP stale reduce-only rejection on height-assigned fixture; native CLI mempool required")
	}

	// One authenticated holder becomes unreachable for all new financial data.
	// Other registered nodes still execute and retain the same domain's data.
	children[6].ok(t, testnet.Request{Op: "partition", Allowed: []bool{false, false, false, false, false, false, true}})
	live = all[:6]
	put(2, engine.Oracle, oracle(100, firstHeight+60))
	// Keep the opening trade away from a scheduled funding boundary. Positions
	// are flat before these noops, so no funding obligation is silently skipped.
	for next%10 == 0 || next%10 == 9 {
		put(2, engine.Noop, nil)
	}
	put(1, engine.Place, order(8002, -1, 100, 500000000, 0))
	rawAlice := makeAction(0, engine.Place, order(8002, 1, 100, 500000000, 0), false)
	aliceAction, err := engine.Decode(rawAlice)
	if err != nil {
		t.Fatal(err)
	}
	alice := aliceAction.Owner
	children[0].ok(t, testnet.Request{Op: "action", Height: next, Raw: rawAlice})
	wait(live, next, false)
	next++
	positionsOpen = true
	// If construction crosses a funding slot, execute an authenticated zero-rate
	// funding action before liquidation. Zero rate still records the real slot.
	maybeFunding := func() {
		if next%10 == 0 || fundingPending {
			put(2, engine.Funding, nil)
		}
	}
	maybeFunding()
	put(2, engine.Oracle, oracle(1, firstHeight+60))
	maybeFunding()
	unfilledHeight := put(2, engine.Liquidate, func(a *engine.Action) { a.Target = alice })
	put(2, engine.Noop, nil)
	wait(live, next-1, true)
	unfilled := check(unfilledHeight, "abrupt-price-no-counterparty")
	if position(unfilled.Accounts[hex.EncodeToString(alice[:])]) != 500000000 || position(unfilled.Accounts[hex.EncodeToString(bob[:])]) != -500000000 || unfilled.Insurance != baseline.Insurance || unfilled.Frozen {
		t.Fatal("unfilled liquidation invented transfer/insurance")
	}
	missing := children[6].call(t, testnet.Request{Op: "checkpoint", Height: unfilledHeight})
	if missing.Error == "" {
		t.Fatal("isolated holder claimed unavailable financial data")
	}
	t.Logf("DEX_FINANCIAL_DA_UNAVAILABLE holder=6 knownHeight=%d error=%s", unfilledHeight, missing.Error)
	children[6].ok(t, testnet.Request{Op: "partition", Allowed: []bool{true, true, true, true, true, true, true}})
	children[6].ok(t, testnet.Request{Op: "repair"})
	live = all
	wait(all, next-1, true)
	check(unfilledHeight, "holder-repaired")
	maybeFunding()
	put(1, engine.Place, order(8003, 1, 1, 500000000, engine.ReduceOnly))
	maybeFunding()
	freezeHeight := put(2, engine.Liquidate, func(a *engine.Action) { a.Target = alice })
	positionsOpen = false
	put(2, engine.Noop, nil)
	wait(live, next-1, true)
	frozen := check(freezeHeight, "actual-close-insurance-exhausted")
	victim := frozen.Accounts[hex.EncodeToString(alice[:])]
	debt, ok := new(big.Int).SetString(victim.Cash, 10)
	if !ok || !frozen.Frozen || frozen.Insurance != "0" || debt.Sign() >= 0 || position(victim) != 0 || position(frozen.Accounts[hex.EncodeToString(bob[:])]) != 0 {
		t.Fatal("bad debt was not retained/frozen after real close")
	}
	if ordinary {
		reject(1, engine.Withdraw, func(a *engine.Action) { a.Amount = engine.Amount("1"); a.Recipient = bob }, "FROZEN")
	} else {
		t.Log("NOT_RUN actual HTTP frozen withdrawal rejection on height-assigned fixture; native CLI mempool required")
	}
	end := put(2, engine.Noop, nil)
	wait(live, end, true)
	check(end-1, "frozen-market-noop-remains-conservative")
	t.Log(fmt.Sprintf("DEX_FINANCIAL_ECONOMY_COMPLETE next=%d financial roots after18 intentionally not submitted to CLX; paid native custody remains separate", next))
	return next
}
