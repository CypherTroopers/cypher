package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const DepositSize = 236
const MaxDepositsPerCheckpoint = 128

type Deposit struct {
	Version   uint16
	Domain    Domain
	Custody   [20]byte
	ID        uint64
	Owner     [20]byte
	Amount    Amount
	CLXHeight uint64
	CLXHash   Hash
}

func (d Deposit) Validate() error {
	if d.Version != 1 || !d.Domain.Valid() || d.Custody == ([20]byte{}) || d.Owner == ([20]byte{}) || !d.Amount.Valid() || d.Amount == (Amount{}) || d.CLXHash == (Hash{}) {
		return errors.New("invalid native deposit")
	}
	return nil
}
func (d Deposit) Encode() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, d)
	return b.Bytes(), err
}
func DecodeDeposit(raw []byte) (Deposit, error) {
	var d Deposit
	if len(raw) != DepositSize {
		return d, errors.New("noncanonical deposit length")
	}
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &d); err != nil {
		return d, err
	}
	return d, d.Validate()
}
func (d Deposit) Hash() (Hash, error) {
	raw, err := d.Encode()
	if err != nil {
		return Hash{}, err
	}
	return Digest("common-dex/deposit/v1", raw), nil
}
func DepositInboxRoot(deposits []Deposit) (Hash, error) {
	if len(deposits) > MaxDepositsPerCheckpoint {
		return Hash{}, errors.New("deposit range limit")
	}
	hashes := make([]Hash, len(deposits))
	for i, d := range deposits {
		if i > 0 && (deposits[i-1].ID == ^uint64(0) || d.ID != deposits[i-1].ID+1) {
			return Hash{}, errors.New("deposit range gap")
		}
		h, err := d.Hash()
		if err != nil {
			return Hash{}, err
		}
		hashes[i] = h
	}
	root, _, err := BuildCountedTree(hashes)
	return root, err
}
