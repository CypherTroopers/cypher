package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
)

const FinanceSummarySize = 456

// FinanceSummary authenticates bounded devnet bucket transfers, not execution validity.
type FinanceSummary struct {
	Version           uint16
	Domain            Domain
	Custody           [20]byte
	Sequence          uint64
	Previous          Hash
	DepositTotal      Amount
	CollectedFees     Amount
	FundingDust       Amount
	InsuranceUsed     Amount
	WithdrawalTotal   Amount
	RewardFromFees    Amount
	RewardFromSupport Amount
	RewardPeriod      uint64
	FeePeriodFirst    uint64
	FeePeriodLast     uint64
	ParticipationRoot Hash
}

func AmountFromBig(n *big.Int) (Amount, error) {
	var a Amount
	if n == nil || n.Sign() < 0 || n.BitLen() > 128 {
		return a, errors.New("amount outside devnet u128")
	}
	n.FillBytes(a[:])
	return a, nil
}
func (a Amount) Big() *big.Int { return new(big.Int).SetBytes(a[:]) }
func (a Amount) Valid() bool {
	for _, b := range a[:16] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (f FinanceSummary) Validate() error {
	if f.Version != 1 || !f.Domain.Valid() || f.Custody == ([20]byte{}) || f.Sequence == 0 {
		return errors.New("invalid finance domain/sequence")
	}
	for _, a := range []Amount{f.DepositTotal, f.CollectedFees, f.FundingDust, f.InsuranceUsed, f.WithdrawalTotal, f.RewardFromFees, f.RewardFromSupport} {
		if !a.Valid() {
			return errors.New("finance amount exceeds u128")
		}
	}
	if f.RewardPeriod == 0 {
		if f.RewardFromFees != (Amount{}) || f.RewardFromSupport != (Amount{}) || f.FeePeriodFirst != 0 || f.FeePeriodLast != 0 || f.ParticipationRoot != (Hash{}) {
			return errors.New("noncanonical absent reward period")
		}
	} else if f.FeePeriodFirst == 0 || f.FeePeriodLast < f.FeePeriodFirst || f.FeePeriodLast > f.Sequence || f.ParticipationRoot == (Hash{}) {
		return errors.New("invalid reward period range")
	}
	return nil
}
func (f FinanceSummary) Encode() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, f)
	return b.Bytes(), err
}
func DecodeFinanceSummary(raw []byte) (FinanceSummary, error) {
	var f FinanceSummary
	if len(raw) != FinanceSummarySize {
		return f, errors.New("noncanonical finance length")
	}
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &f); err != nil {
		return f, err
	}
	return f, f.Validate()
}
func (f FinanceSummary) Hash() (Hash, error) {
	raw, err := f.Encode()
	if err != nil {
		return Hash{}, err
	}
	return Digest("common-dex/finance/v1", raw), nil
}
