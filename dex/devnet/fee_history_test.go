package devnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

func TestFinancialV6IndependentFeeHistory320(t *testing.T) {
	raw, err := os.ReadFile("../testdata/financial_storage.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema int
		Steps  []struct {
			Height, Close               uint64
			Fee, Outstanding, Canonical string
		}
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || vectors.Schema != 1 || len(vectors.Steps) != 320 {
		t.Fatal("golden inventory", err)
	}
	h := newFeeHistory()
	for _, v := range vectors.Steps {
		if err := h.append(v.Height, makeAmount(v.Fee)); err != nil {
			t.Fatal(err)
		}
		if v.Close != 0 {
			if err := h.close(v.Close); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.validate(v.Height, h.ClosedPeriod, v.Outstanding); err != nil {
			t.Fatal(v.Height, err)
		}
		raw, err := json.Marshal(h)
		if err != nil || string(raw) != v.Canonical {
			t.Fatalf("height %d independent fee frontier mismatch: %v", v.Height, err)
		}
		// Cold canonical roundtrip after every step; no hidden cumulative cache.
		var restored FeeHistory
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		h = &restored
	}
	if h.ClosedPeriod != 31 || len(h.Open) > 2 {
		t.Fatal("closed history remained hot")
	}
}

func TestFinancialV6FeeBacklogPreservesZeroFeeWorkAndClose(t *testing.T) {
	h := newFeeHistory()
	for i := uint64(0); i < MaxOpenFeePeriods; i++ {
		if err := h.append(i*10+1, makeAmount("1")); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := json.Marshal(h)
	if err := h.append(161, makeAmount("1")); !errors.Is(err, ErrFeeHistoryCapacity) {
		t.Fatal("unbounded nonzero backlog", err)
	}
	after, _ := json.Marshal(h)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity rejection mutated fee obligations")
	}
	if err := h.append(1001, protocol.Amount{}); err != nil {
		t.Fatal("zero-fee work blocked by reward withholding", err)
	}
	if err := h.close(2); err == nil {
		t.Fatal("skipped unpaid period")
	}
	if err := h.close(1); err != nil {
		t.Fatal(err)
	}
	if err := h.append(1002, makeAmount("1")); err != nil {
		t.Fatal("closed capacity did not resume", err)
	}
	if err := h.validate(1002, 1, "16"); err != nil {
		t.Fatal(err)
	}
	if err := h.close(1); err == nil {
		t.Fatal("closed period counted twice")
	}
}

func TestFinancialV6FeeSnapshotRejectsAlteredFrontierAndAmounts(t *testing.T) {
	h := newFeeHistory()
	_ = h.append(1, makeAmount("7"))
	_ = h.append(11, makeAmount("9"))
	_ = h.close(1)
	raw, _ := json.Marshal(h)
	for name, mutate := range map[string]func(*FeeHistory){
		"version":             func(x *FeeHistory) { x.Version++ },
		"frontier":            func(x *FeeHistory) { x.ClosedPeriod++ },
		"root":                func(x *FeeHistory) { x.ClosedRoot = protocol.Hash{} },
		"closed amount bound": func(x *FeeHistory) { x.ClosedTotal[0] = 1 },
		"unpaid missing":      func(x *FeeHistory) { x.Open = []PeriodFee{} },
		"period replay":       func(x *FeeHistory) { x.Open[0].Period = 1 },
		"future":              func(x *FeeHistory) { x.Open[0].Period = 3 },
		"amount":              func(x *FeeHistory) { x.Open[0].Total = makeAmount("8") },
		"last fee":            func(x *FeeHistory) { x.LastFee = makeAmount("10") },
	} {
		t.Run(name, func(t *testing.T) {
			var bad FeeHistory
			_ = json.Unmarshal(raw, &bad)
			mutate(&bad)
			if bad.validate(14, 1, "9") == nil {
				t.Fatal("corrupt financial frontier accepted")
			}
		})
	}
}
