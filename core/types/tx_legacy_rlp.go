package types

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/rlp"
)

// ErrTxIntegerOutOfRange identifies a transaction integer which cannot be
// represented by Ethereum's canonical uint256 transaction fields.
var ErrTxIntegerOutOfRange = errors.New("transaction integer is outside uint256 range")

// ValidateIntegerBounds performs the allocation-free integer range check used
// at transaction trust boundaries. Ethereum transaction fields represented by
// big.Int locally must remain non-negative and no wider than 256 bits.
func (tx *Transaction) ValidateIntegerBounds() error {
	if tx == nil || tx.data == nil {
		return nil
	}
	return validateTypedIntegerBounds(tx.data)
}

// legacyTxRLP is deliberately distinct from txdata so EncodeRLP can validate
// before delegating to the generic encoder without recursively invoking itself.
type legacyTxRLP struct {
	AccountNonce uint64
	Price        *big.Int
	GasLimit     uint64
	Recipient    *common.Address `rlp:"nil"`
	Amount       *big.Int
	Payload      []byte
	V            *big.Int
	R            *big.Int
	S            *big.Int
}

// EncodeRLP rejects programmatically constructed out-of-range values before
// the encoder walks or serializes their arbitrarily large big.Int storage.
func (tx *txdata) EncodeRLP(w io.Writer) error {
	if tx == nil {
		return errors.New("cannot encode nil legacy transaction")
	}
	if err := validateTypedIntegerBounds(tx); err != nil {
		return err
	}
	return rlp.Encode(w, &legacyTxRLP{
		AccountNonce: tx.AccountNonce,
		Price:        tx.Price,
		GasLimit:     tx.GasLimit,
		Recipient:    tx.Recipient,
		Amount:       tx.Amount,
		Payload:      tx.Payload,
		V:            tx.V,
		R:            tx.R,
		S:            tx.S,
	})
}

// DecodeRLP checks each legacy uint256 element's RLP payload length before
// allocating a big.Int. This prevents a sub-megabyte raw transaction from
// turning one fee or signature field into an unbounded big-number workload.
func (tx *txdata) DecodeRLP(s *rlp.Stream) error {
	if _, err := s.List(); err != nil {
		return fmt.Errorf("legacy transaction: %w", err)
	}
	nonce, err := s.Uint()
	if err != nil {
		return legacyFieldDecodeError("nonce", err)
	}
	price, err := decodeLegacyUint256(s, "gasPrice")
	if err != nil {
		return err
	}
	gas, err := s.Uint()
	if err != nil {
		return legacyFieldDecodeError("gas", err)
	}
	recipient, err := decodeLegacyRecipient(s)
	if err != nil {
		return err
	}
	amount, err := decodeLegacyUint256(s, "value")
	if err != nil {
		return err
	}
	payload, err := s.Bytes()
	if err != nil {
		return legacyFieldDecodeError("input", err)
	}
	v, err := decodeLegacyUint256(s, "v")
	if err != nil {
		return err
	}
	r, err := decodeLegacyUint256(s, "r")
	if err != nil {
		return err
	}
	sigS, err := decodeLegacyUint256(s, "s")
	if err != nil {
		return err
	}
	if err := s.ListEnd(); err != nil {
		return fmt.Errorf("legacy transaction: %w", err)
	}
	*tx = txdata{
		AccountNonce: nonce,
		Price:        price,
		GasLimit:     gas,
		Recipient:    recipient,
		Amount:       amount,
		Payload:      payload,
		V:            v,
		R:            r,
		S:            sigS,
	}
	return nil
}

func decodeLegacyUint256(s *rlp.Stream, field string) (*big.Int, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, legacyFieldDecodeError(field, err)
	}
	if kind == rlp.List {
		return nil, legacyFieldDecodeError(field, rlp.ErrExpectedString)
	}
	// Byte values store their one content byte in the RLP tag and report a
	// payload size of zero. All String values report their actual byte width.
	if kind == rlp.String && size > 32 {
		return nil, fmt.Errorf("legacy transaction %s: %w", field, ErrTxIntegerOutOfRange)
	}
	encoded, err := s.Bytes()
	if err != nil {
		return nil, legacyFieldDecodeError(field, err)
	}
	// Integer zero must use the empty-string encoding. A zero content byte is
	// non-canonical even though it is within the uint256 width.
	if len(encoded) > 0 && encoded[0] == 0 {
		return nil, legacyFieldDecodeError(field, rlp.ErrCanonInt)
	}
	return new(big.Int).SetBytes(encoded), nil
}

func decodeLegacyRecipient(s *rlp.Stream) (*common.Address, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, legacyFieldDecodeError("to", err)
	}
	if kind == rlp.List {
		return nil, legacyFieldDecodeError("to", rlp.ErrExpectedString)
	}
	if kind == rlp.String && size != 0 && size != common.AddressLength {
		return nil, fmt.Errorf("legacy transaction to: address has %d bytes, want %d", size, common.AddressLength)
	}
	encoded, err := s.Bytes()
	if err != nil {
		return nil, legacyFieldDecodeError("to", err)
	}
	if len(encoded) == 0 {
		return nil, nil
	}
	if len(encoded) != common.AddressLength {
		return nil, fmt.Errorf("legacy transaction to: address has %d bytes, want %d", len(encoded), common.AddressLength)
	}
	var recipient common.Address
	copy(recipient[:], encoded)
	return &recipient, nil
}

func legacyFieldDecodeError(field string, err error) error {
	return fmt.Errorf("legacy transaction %s: %w", field, err)
}
