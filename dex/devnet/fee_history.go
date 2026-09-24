package devnet

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
)

const MaxOpenFeePeriods = 16

var ErrFeeHistoryCapacity = errors.New("unclosed fee period capacity: close authenticated reward backlog")

type PeriodFee struct {
	Period uint64
	Total  protocol.Amount
}

// FeeHistory retains all unclosed fee obligations, while closed periods are
// represented by a sequential accumulator. Historical details remain in the
// authenticated finalized-state archive, not in the active execution state.
type FeeHistory struct {
	Version      uint16
	ClosedPeriod uint64
	ClosedTotal  protocol.Amount
	ClosedRoot   protocol.Hash
	Open         []PeriodFee
	LastFee      protocol.Amount
}

func newFeeHistory() *FeeHistory { return &FeeHistory{Version: 1, Open: []PeriodFee{}} }

func (h *FeeHistory) validate(height, closed uint64, outstanding string) error {
	if h == nil || h.Version != 1 || h.Open == nil || len(h.Open) > MaxOpenFeePeriods || h.ClosedPeriod != closed || closed > height/rewards.PeriodBlocks || !h.ClosedTotal.Valid() || !h.LastFee.Valid() || (closed == 0 && (h.ClosedTotal != (protocol.Amount{}) || h.ClosedRoot != (protocol.Hash{}))) || (closed != 0 && h.ClosedRoot == (protocol.Hash{})) {
		return errors.New("fee history frontier/bound")
	}
	last, sum := closed, new(big.Int)
	for _, p := range h.Open {
		if p.Period <= last || height == 0 || p.Period > (height-1)/rewards.PeriodBlocks+1 || !p.Total.Valid() || p.Total == (protocol.Amount{}) {
			return errors.New("fee history period/order/amount")
		}
		last = p.Period
		sum.Add(sum, p.Total.Big())
		if sum.BitLen() > 128 {
			return errors.New("fee history sum bound")
		}
	}
	if sum.String() != outstanding || (height == 0 && h.LastFee != (protocol.Amount{})) {
		return errors.New("fee history outstanding mismatch")
	}
	if height > 0 && h.LastFee.Big().Cmp(h.period((height-1)/rewards.PeriodBlocks+1).Big()) > 0 {
		return errors.New("fee history last fee exceeds period")
	}
	return nil
}

func (h *FeeHistory) period(period uint64) protocol.Amount {
	for _, p := range h.Open {
		if p.Period == period {
			return p.Total
		}
	}
	return protocol.Amount{}
}

func (h *FeeHistory) append(height uint64, fee protocol.Amount) error {
	if height == 0 || !fee.Valid() {
		return errors.New("fee history append height/amount")
	}
	period := (height-1)/rewards.PeriodBlocks + 1
	if period <= h.ClosedPeriod {
		return errors.New("fee history append closed period")
	}
	if fee != (protocol.Amount{}) {
		if len(h.Open) > 0 && h.Open[len(h.Open)-1].Period == period {
			p := &h.Open[len(h.Open)-1]
			total, err := protocol.AmountFromBig(new(big.Int).Add(p.Total.Big(), fee.Big()))
			if err != nil {
				return err
			}
			p.Total = total
		} else {
			if len(h.Open) >= MaxOpenFeePeriods {
				return ErrFeeHistoryCapacity
			}
			h.Open = append(h.Open, PeriodFee{period, fee})
		}
	}
	h.LastFee = fee
	return nil
}

func (h *FeeHistory) close(period uint64) error {
	if h.ClosedPeriod == ^uint64(0) || period != h.ClosedPeriod+1 {
		return errors.New("fee history nonsequential close")
	}
	fee := h.period(period)
	total, err := protocol.AmountFromBig(new(big.Int).Add(h.ClosedTotal.Big(), fee.Big()))
	if err != nil {
		return err
	}
	var payload [72]byte
	copy(payload[:32], h.ClosedRoot[:])
	binary.BigEndian.PutUint64(payload[32:40], period)
	copy(payload[40:], fee[:])
	h.ClosedRoot = protocol.Digest("common-dex/closed-fee-period/v1", payload[:])
	h.ClosedPeriod, h.ClosedTotal = period, total
	if len(h.Open) > 0 && h.Open[0].Period == period {
		h.Open = append([]PeriodFee{}, h.Open[1:]...)
	}
	return nil
}
