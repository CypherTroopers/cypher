// Package engine implements a bounded, isolated BTC/CLX devnet market. It is
// never imported by the CLX settlement verifier or enabled on production nodes.
package engine

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/protocol"
)

const (
	ActionSize       = 217
	SignedActionSize = ActionSize + 65
)

const (
	Noop = uint8(iota)
	Credit
	Oracle
	Place
	Cancel
	Amend
	Withdraw
	Funding
	Liquidate
	RewardClose
)

const (
	IOC        = uint8(1)
	PostOnly   = uint8(2)
	ReduceOnly = uint8(4)
)

type Action struct {
	Version      uint16
	Epoch        protocol.Hash
	Kind         uint8
	Owner        [20]byte
	Nonce        uint64
	OrderID      uint64
	Side         int8
	Quantity     uint64
	Price        protocol.Amount
	Recipient    [20]byte
	Amount       protocol.Amount
	DepositID    uint64
	FeedSequence uint64
	FundingRate  int64
	ValidUntil   uint64
	Target       [20]byte
	Flags        uint8
}

func (a Action) Encode() ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, a); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (a Action) validate() error {
	if a.Version != 1 || a.Epoch == (protocol.Hash{}) || a.Owner == ([20]byte{}) || a.Nonce == 0 {
		return errors.New("ACTION_DOMAIN")
	}
	e := Action{Version: a.Version, Epoch: a.Epoch, Kind: a.Kind, Owner: a.Owner, Nonce: a.Nonce}
	switch a.Kind {
	case Noop, Funding:
	case Credit:
		e.DepositID = a.DepositID
	case Oracle:
		e.Price = a.Price
		e.FeedSequence = a.FeedSequence
		e.FundingRate = a.FundingRate
		e.ValidUntil = a.ValidUntil
	case Place, Amend:
		e.OrderID = a.OrderID
		e.Side = a.Side
		e.Quantity = a.Quantity
		e.Price = a.Price
		e.Flags = a.Flags
		if a.OrderID == 0 || (a.Side != 1 && a.Side != -1) || a.Quantity == 0 || a.Quantity > 1_000_000_000_000 || a.Quantity%100000 != 0 || a.Flags > 7 || a.Flags&3 == 3 {
			return errors.New("ORDER_SHAPE")
		}
	case Cancel:
		e.OrderID = a.OrderID
		if a.OrderID == 0 {
			return errors.New("ORDER_ID")
		}
	case Withdraw:
		e.Recipient = a.Recipient
		e.Amount = a.Amount
		if a.Recipient == ([20]byte{}) || a.Amount == (protocol.Amount{}) {
			return errors.New("WITHDRAWAL_SHAPE")
		}
	case Liquidate, RewardClose:
		e.Target = a.Target
		if a.Target == ([20]byte{}) {
			return errors.New("LIQUIDATION_TARGET")
		}
	default:
		return errors.New("ACTION_KIND")
	}
	if e != a {
		return errors.New("NONCANONICAL_ACTION_FIELDS")
	}
	if new(big.Int).SetBytes(a.Amount[:]).BitLen() > 128 || new(big.Int).SetBytes(a.Price[:]).BitLen() > 128 {
		return errors.New("AMOUNT_BOUND")
	}
	return nil
}

func Sign(a Action, key *ecdsa.PrivateKey) ([]byte, error) {
	raw, err := a.Encode()
	if err != nil {
		return nil, err
	}
	if key == nil || crypto.PubkeyToAddress(key.PublicKey) != common.Address(a.Owner) {
		return nil, errors.New("SIGNER")
	}
	h := protocol.Digest("common-dex/action/v1", raw)
	sig, err := crypto.Sign(h[:], key)
	if err != nil {
		return nil, err
	}
	return append(raw, sig...), nil
}

func Decode(raw []byte) (Action, error) {
	var a Action
	if len(raw) != SignedActionSize {
		return a, errors.New("ACTION_LENGTH")
	}
	if err := binary.Read(bytes.NewReader(raw[:ActionSize]), binary.BigEndian, &a); err != nil {
		return Action{}, err
	}
	if err := a.validate(); err != nil {
		return Action{}, err
	}
	sig := raw[ActionSize:]
	if !crypto.ValidateSignatureValues(sig[64], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), true) {
		return Action{}, errors.New("SIGNATURE_CANONICAL")
	}
	h := protocol.Digest("common-dex/action/v1", raw[:ActionSize])
	pub, err := crypto.SigToPub(h[:], sig)
	if err != nil {
		return Action{}, err
	}
	if crypto.PubkeyToAddress(*pub) != common.Address(a.Owner) {
		return Action{}, errors.New("SIGNER")
	}
	return a, nil
}

func Amount(s string) protocol.Amount {
	var a protocol.Amount
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 128 {
		panic("fixture amount outside uint128")
	}
	n.FillBytes(a[:])
	return a
}
