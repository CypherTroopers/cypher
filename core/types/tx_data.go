package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
)

// TxData is the internal consensus/wire payload carried by Transaction.
// Legacy transactions use txdata/LegacyTx. Typed transactions will add
// AccessListTx/DynamicFeeTx/BlobTx/SetCodeTx/NativeTxV1 implementations as the
// migration progresses.
type TxData interface {
	txType() uint8
	copy() TxData

	chainID() *big.Int
	accessList() AccessList
	data() []byte
	gas() uint64
	gasPrice() *big.Int
	gasFeeCap() *big.Int
	gasTipCap() *big.Int
	value() *big.Int
	nonce() uint64
	to() *common.Address
	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(v, r, s *big.Int)
}

// txdata is the legacy Ethereum transaction payload. The generated JSON codec
// still targets this name, so it is preserved while LegacyTx gives the modern
// code a clearer type name.
type txdata struct {
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64          `json:"gas"      gencodec:"required"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

type LegacyTx = txdata

func (tx *txdata) txType() uint8 { return LegacyTxType }

func (tx *txdata) copy() TxData {
	cpy := &txdata{
		AccountNonce: tx.AccountNonce,
		GasLimit:     tx.GasLimit,
	}
	if tx.Price != nil {
		cpy.Price = new(big.Int).Set(tx.Price)
	} else {
		cpy.Price = new(big.Int)
	}
	if tx.Recipient != nil {
		to := *tx.Recipient
		cpy.Recipient = &to
	}
	if tx.Amount != nil {
		cpy.Amount = new(big.Int).Set(tx.Amount)
	} else {
		cpy.Amount = new(big.Int)
	}
	if len(tx.Payload) > 0 {
		cpy.Payload = common.CopyBytes(tx.Payload)
	}
	if tx.V != nil {
		cpy.V = new(big.Int).Set(tx.V)
	} else {
		cpy.V = new(big.Int)
	}
	if tx.R != nil {
		cpy.R = new(big.Int).Set(tx.R)
	} else {
		cpy.R = new(big.Int)
	}
	if tx.S != nil {
		cpy.S = new(big.Int).Set(tx.S)
	} else {
		cpy.S = new(big.Int)
	}
	return cpy
}

func (tx *txdata) chainID() *big.Int      { return deriveChainId(tx.V) }
func (tx *txdata) accessList() AccessList { return nil }
func (tx *txdata) data() []byte           { return common.CopyBytes(tx.Payload) }
func (tx *txdata) gas() uint64            { return tx.GasLimit }
func (tx *txdata) gasPrice() *big.Int     { return new(big.Int).Set(tx.Price) }
func (tx *txdata) gasFeeCap() *big.Int    { return tx.gasPrice() }
func (tx *txdata) gasTipCap() *big.Int    { return tx.gasPrice() }
func (tx *txdata) value() *big.Int        { return new(big.Int).Set(tx.Amount) }
func (tx *txdata) nonce() uint64          { return tx.AccountNonce }

func (tx *txdata) to() *common.Address {
	if tx.Recipient == nil {
		return nil
	}
	to := *tx.Recipient
	return &to
}

func (tx *txdata) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *txdata) setSignatureValues(v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}
