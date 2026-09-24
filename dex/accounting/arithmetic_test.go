package accounting

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"sync"
	"testing"
)

func TestIndependentGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/accounting.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID        string          `json:"id"`
			Operation string          `json:"operation"`
			Input     json.RawMessage `json:"input"`
			Result    json.RawMessage `json:"result"`
			Error     string          `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "common-dex-accounting-v0" {
		t.Fatal("unexpected schema")
	}
	for _, v := range vectors.Cases {
		t.Run(v.ID, func(t *testing.T) {
			got, err := evaluateGolden(v.Operation, v.Input)
			if v.Error != "" {
				if err == nil || err.Error() != v.Error {
					t.Fatalf("expected %s; got %v", v.Error, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var actual, expected any
			if err := json.Unmarshal(raw, &actual); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(v.Result, &expected); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("expected %s\ngot %s", v.Result, raw)
			}
		})
	}
}

func evaluateGolden(op string, raw json.RawMessage) (any, error) {
	switch op {
	case "notional", "charge", "pnl", "insurance":
		var in map[string]string
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		switch op {
		case "notional":
			return Notional(in["price"], in["quantity"])
		case "charge":
			return Charge(in["price"], in["quantity"], in["rate_ppm"])
		case "pnl":
			return PnL(in["entry"], in["exit"], in["quantity"])
		case "insurance":
			return ResolveInsurance(in["cash"], in["insurance"])
		}
	case "funding":
		var in struct {
			Price     string            `json:"price"`
			Positions map[string]string `json:"positions"`
			Rate      string            `json:"rate_ppm"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		return Funding(in.Price, in.Positions, in.Rate)
	case "reward":
		var in RewardInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		return Reward(in)
	case "equity":
		var in EquityInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, err
		}
		return EquityConservation(in)
	case "trace":
		return arithmeticTrace()
	}
	return nil, fmt.Errorf("unknown golden operation %q", op)
}

// This test fixture posts arithmetic entries only. No node/native transfer,
// order matching, finality, receipt authentication, or claims verification runs.
func arithmeticTrace() (any, error) {
	a := map[string]string{"alice": "100000000000000000000", "bob": "100000000000000000000"}
	s := map[string]string{"custody": "225000000000000000000", "fees": "0", "support": "20000000000000000000",
		"insurance": "5000000000000000000", "funding_dust": "0", "withdrawal_reserved": "0", "reward_reserved": "0"}
	steps := []any{}
	add := func(values map[string]string, key, delta string) {
		v, _ := new(big.Int).SetString(values[key], 10)
		d, _ := new(big.Int).SetString(delta, 10)
		values[key] = v.Add(v, d).String()
	}
	neg := func(n string) string {
		v, _ := new(big.Int).SetString(n, 10)
		return v.Neg(v).String()
	}
	snapshot := func(action string) error {
		total := bi(0)
		ac := make(map[string]string)
		for key, raw := range a {
			v, _ := new(big.Int).SetString(raw, 10)
			total.Add(total, v)
			ac[key] = raw
		}
		step := map[string]any{"action": action, "accounts": ac}
		for key, raw := range s {
			step[key] = raw
			if key != "custody" {
				v, _ := new(big.Int).SetString(raw, 10)
				total.Add(total, v)
			}
		}
		if total.String() != s["custody"] {
			return fmt.Errorf("conservation at %s", action)
		}
		steps = append(steps, step)
		return nil
	}
	fee := func(who, p, rate string) error {
		f, err := Charge(p, "100000000", rate)
		if err != nil {
			return err
		}
		add(a, who, neg(f))
		add(s, "fees", f)
		return nil
	}
	if err := snapshot("deposits_and_funded_pools"); err != nil {
		return nil, err
	}
	if err := fee("alice", "100000000000000000000", "300"); err != nil {
		return nil, err
	}
	if err := fee("bob", "100000000000000000000", "100"); err != nil {
		return nil, err
	}
	if err := snapshot("open_pair_at_100_CLX_per_BTC"); err != nil {
		return nil, err
	}
	f, err := Funding("105000000000000000000", map[string]string{"alice": "100000000", "bob": "-100000000"}, "1000")
	if err != nil {
		return nil, err
	}
	for who, delta := range f.CashDeltas {
		add(a, who, delta)
	}
	add(s, "funding_dust", f.Dust)
	if err := snapshot("funding_at_105_CLX_per_BTC"); err != nil {
		return nil, err
	}
	pnl, err := PnL("100000000000000000000", "110000000000000000000", "100000000")
	if err != nil {
		return nil, err
	}
	add(a, "alice", pnl)
	add(a, "bob", neg(pnl))
	if err := fee("alice", "110000000000000000000", "300"); err != nil {
		return nil, err
	}
	if err := fee("bob", "110000000000000000000", "100"); err != nil {
		return nil, err
	}
	if err := snapshot("close_pair_at_110_CLX_per_BTC"); err != nil {
		return nil, err
	}
	r, err := Reward(RewardInput{Fees: s["fees"], Support: s["support"], Allowance: "2000000000000000000", Cap: "1000000000000000000",
		Points: map[string]string{"v1": "2", "v2": "1", "v3": "1", "v4": "0", "v5": "0", "v6": "0", "v7": "0"}})
	if err != nil {
		return nil, err
	}
	s["fees"], s["support"], s["reward_reserved"] = r.FeesRemaining, r.SupportRemaining, r.Budget
	if err := snapshot("funded_reward_reservation"); err != nil {
		return nil, err
	}
	add(a, "alice", "-10000000000000000000")
	add(s, "withdrawal_reserved", "10000000000000000000")
	if err := snapshot("withdrawal_reservation"); err != nil {
		return nil, err
	}
	add(s, "withdrawal_reserved", "-10000000000000000000")
	add(s, "custody", "-10000000000000000000")
	if err := snapshot("native_withdrawal_paid"); err != nil {
		return nil, err
	}
	add(s, "custody", neg(s["reward_reserved"]))
	s["reward_reserved"] = "0"
	if err := snapshot("native_rewards_paid"); err != nil {
		return nil, err
	}
	return map[string]any{"steps": steps, "reward_allocations": r.Allocations}, nil
}

func TestAPIBoundsAndOwnership(t *testing.T) {
	for _, bad := range []string{"", "+1000", "-0", "00", "1e3", "１０００", " 1000", "1000\n"} {
		if _, err := Notional(bad, "100000"); err == nil {
			t.Fatalf("accepted price %q", bad)
		}
	}
	if _, err := ResolveInsurance("0", "-1"); err == nil {
		t.Fatal("negative insurance accepted")
	}
	if _, err := Charge("1000", "100000", "-1"); err == nil {
		t.Fatal("negative rate accepted")
	}
	if _, err := Funding("1000", map[string]string{}, "0"); err == nil {
		t.Fatal("empty snapshot accepted")
	}
	positions := map[string]string{"alice": "100000", "bob": "-100000"}
	in := RewardInput{Fees: "0", Support: "10", Allowance: "10", Cap: "10", Points: map[string]string{"v1": "1", "v2": "1"}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := Funding("1000", positions, "1")
			if err != nil {
				t.Error(err)
				return
			}
			r, err := Reward(in)
			if err != nil {
				t.Error(err)
				return
			}
			// Returned maps/decimal values are independently owned. Mutating
			// one result must not corrupt input or any simultaneous result.
			f.CashDeltas["alice"] = "modified"
			r.Allocations["v1"] = "modified"
		}()
	}
	wg.Wait()
	if positions["alice"] != "100000" || in.Points["v1"] != "1" {
		t.Fatal("input mutated")
	}
	f, err := Funding("1000", positions, "1")
	if err != nil || f.CashDeltas["alice"] != "-1" {
		t.Fatal("result aliases prior call")
	}
	r, err := Reward(in)
	if err != nil || r.Allocations["v1"] != "5" {
		t.Fatal("reward result aliases prior call")
	}
}
