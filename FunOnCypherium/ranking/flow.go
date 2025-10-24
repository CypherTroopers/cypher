package main

import (
	"math/big"
	"strings"
	"time"
)

type flowTotalsView struct {
	InflowWei  string `json:"inflowWei"`
	OutflowWei string `json:"outflowWei"`
	InflowCph  string `json:"inflowCph"`
	OutflowCph string `json:"outflowCph"`
}

func (s *rankingServer) computeFlowSummary(address string) *flowSummary {
	addr := strings.ToLower(address)
	now := time.Now()
	last7d := now.Add(-7 * 24 * time.Hour)
	last24h := now.Add(-24 * time.Hour)

	transfers7d := s.transferStore.forAddress(addr, last7d)
	transfers24h := s.transferStore.forAddress(addr, last24h)

	totals7d := flowTotals{Inflow: big.NewInt(0), Outflow: big.NewInt(0)}
	totals24h := flowTotals{Inflow: big.NewInt(0), Outflow: big.NewInt(0)}

	for _, tx := range transfers7d {
		value := new(big.Int).Set(tx.Value)
		if tx.To == addr {
			totals7d.Inflow.Add(totals7d.Inflow, value)
		}
		if tx.From == addr {
			totals7d.Outflow.Add(totals7d.Outflow, value)
		}
	}

	for _, tx := range transfers24h {
		value := new(big.Int).Set(tx.Value)
		if tx.To == addr {
			totals24h.Inflow.Add(totals24h.Inflow, value)
		}
		if tx.From == addr {
			totals24h.Outflow.Add(totals24h.Outflow, value)
		}
	}

	flows := map[string]flowTotalsView{
		"last7d":  newFlowTotalsView(totals7d),
		"last24h": newFlowTotalsView(totals24h),
	}

	return &flowSummary{
		GeneratedAt:     now,
		GeneratedAtUnix: now.Unix(),
		GeneratedAtUTC:  now.UTC().Format(time.RFC1123),
		Flows:           flows,
	}
}

func newFlowTotalsView(t flowTotals) flowTotalsView {
	inflow := t.Inflow
	if inflow == nil {
		inflow = big.NewInt(0)
	}
	outflow := t.Outflow
	if outflow == nil {
		outflow = big.NewInt(0)
	}
	return flowTotalsView{
		InflowWei:  inflow.String(),
		OutflowWei: outflow.String(),
		InflowCph:  weiToCphString(inflow),
		OutflowCph: weiToCphString(outflow),
	}
}
