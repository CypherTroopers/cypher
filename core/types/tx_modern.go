package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
)

const (
	LegacyTxType     = 0x00
	AccessListTxType = 0x01
	DynamicFeeTxType = 0x02
	BlobTxType       = 0x03
	SetCodeTxType    = 0x04
)

type AccessTuple struct {
	Address     common.Address `json:"address"`
	StorageKeys []common.Hash  `json:"storageKeys"`
}

type AccessList []AccessTuple

type AccessListTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	Gas        uint64
	To         *common.Address `rlp:"nil"`
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	V, R, S    *big.Int
}

type DynamicFeeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *common.Address `rlp:"nil"`
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	V, R, S    *big.Int
}

type BlobTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         common.Address
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	BlobFeeCap *big.Int
	BlobHashes []common.Hash
	Sidecar    *BlobTxSidecar `rlp:"-"`
	V, R, S    *big.Int
}

type SetCodeAuthorization struct {
	ChainID *big.Int       `json:"chainId"`
	Address common.Address `json:"address"`
	Nonce   uint64         `json:"nonce"`
	V, R, S *big.Int       `json:"-"`
}

type SetCodeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         common.Address
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	AuthList   []SetCodeAuthorization
	V, R, S    *big.Int
}

func (tx *Transaction) Type() uint8 {
	if tx == nil || tx.data == nil {
		return LegacyTxType
	}
	return tx.data.txType()
}

func (tx *Transaction) GasFeeCap() *big.Int {
	if tx == nil || tx.data == nil {
		return new(big.Int)
	}
	return tx.data.gasFeeCap()
}

func (tx *Transaction) GasTipCap() *big.Int {
	if tx == nil || tx.data == nil {
		return new(big.Int)
	}
	return tx.data.gasTipCap()
}

func (tx *Transaction) BlobGasFeeCap() *big.Int {
	if tx == nil || tx.data == nil {
		return new(big.Int)
	}
	if inner, ok := tx.data.(*BlobTx); ok && inner.BlobFeeCap != nil {
		return new(big.Int).Set(inner.BlobFeeCap)
	}
	return new(big.Int)
}

func (tx *Transaction) BlobHashes() []common.Hash {
	if tx == nil || tx.data == nil {
		return nil
	}
	if inner, ok := tx.data.(*BlobTx); ok {
		return copyHashList(inner.BlobHashes)
	}
	return nil
}

func (tx *Transaction) BlobSidecar() *BlobTxSidecar {
	if tx == nil || tx.data == nil {
		return nil
	}
	if inner, ok := tx.data.(*BlobTx); ok {
		return inner.Sidecar
	}
	return nil
}

func (tx *Transaction) WithBlobSidecar(sidecar *BlobTxSidecar) *Transaction {
	if tx == nil || tx.Type() != BlobTxType {
		return tx
	}
	cpy := *tx
	cpy.data = tx.data.copy()
	if inner, ok := cpy.data.(*BlobTx); ok {
		inner.Sidecar = sidecar.Copy()
	}
	return &cpy
}

func (tx *Transaction) AccessList() AccessList {
	if tx == nil || tx.data == nil {
		return nil
	}
	return tx.data.accessList()
}

func (tx *Transaction) EffectiveGasTip(baseFee *big.Int) (*big.Int, error) {
	if baseFee == nil {
		return tx.GasTipCap(), nil
	}
	feeCap := tx.GasFeeCap()
	if feeCap.Cmp(baseFee) < 0 {
		return nil, ErrGasFeeCapTooLow
	}
	tip := new(big.Int).Sub(feeCap, baseFee)
	if gasTipCap := tx.GasTipCap(); tip.Cmp(gasTipCap) > 0 {
		tip.Set(gasTipCap)
	}
	return tip, nil
}

func (tx *Transaction) EffectiveGasTipValue(baseFee *big.Int) *big.Int {
	tip, err := tx.EffectiveGasTip(baseFee)
	if err != nil {
		return new(big.Int)
	}
	return tip
}
