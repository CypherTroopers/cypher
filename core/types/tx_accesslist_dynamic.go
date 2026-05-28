package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
)

func copyBig(x *big.Int) *big.Int {
	if x == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(x)
}

func copyAddressPtr(addr *common.Address) *common.Address {
	if addr == nil {
		return nil
	}
	cpy := *addr
	return &cpy
}

func copyAccessList(list AccessList) AccessList {
	if len(list) == 0 {
		return nil
	}
	cpy := make(AccessList, len(list))
	for i, tuple := range list {
		cpy[i].Address = tuple.Address
		if len(tuple.StorageKeys) > 0 {
			cpy[i].StorageKeys = make([]common.Hash, len(tuple.StorageKeys))
			copy(cpy[i].StorageKeys, tuple.StorageKeys)
		}
	}
	return cpy
}

func (tx *AccessListTx) txType() uint8 { return AccessListTxType }
func (tx *AccessListTx) copy() TxData {
	return &AccessListTx{
		ChainID:    copyBig(tx.ChainID),
		Nonce:      tx.Nonce,
		GasPrice:   copyBig(tx.GasPrice),
		Gas:        tx.Gas,
		To:         copyAddressPtr(tx.To),
		Value:      copyBig(tx.Value),
		Data:       common.CopyBytes(tx.Data),
		AccessList: copyAccessList(tx.AccessList),
		V:          copyBig(tx.V),
		R:          copyBig(tx.R),
		S:          copyBig(tx.S),
	}
}
func (tx *AccessListTx) chainID() *big.Int                      { return copyBig(tx.ChainID) }
func (tx *AccessListTx) accessList() AccessList                 { return copyAccessList(tx.AccessList) }
func (tx *AccessListTx) data() []byte                           { return common.CopyBytes(tx.Data) }
func (tx *AccessListTx) gas() uint64                            { return tx.Gas }
func (tx *AccessListTx) gasPrice() *big.Int                     { return copyBig(tx.GasPrice) }
func (tx *AccessListTx) gasFeeCap() *big.Int                    { return copyBig(tx.GasPrice) }
func (tx *AccessListTx) gasTipCap() *big.Int                    { return copyBig(tx.GasPrice) }
func (tx *AccessListTx) value() *big.Int                        { return copyBig(tx.Value) }
func (tx *AccessListTx) nonce() uint64                          { return tx.Nonce }
func (tx *AccessListTx) to() *common.Address                    { return copyAddressPtr(tx.To) }
func (tx *AccessListTx) rawSignatureValues() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }
func (tx *AccessListTx) setSignatureValues(v, r, s *big.Int)    { tx.V, tx.R, tx.S = v, r, s }

func (tx *DynamicFeeTx) txType() uint8 { return DynamicFeeTxType }
func (tx *DynamicFeeTx) copy() TxData {
	return &DynamicFeeTx{
		ChainID:    copyBig(tx.ChainID),
		Nonce:      tx.Nonce,
		GasTipCap:  copyBig(tx.GasTipCap),
		GasFeeCap:  copyBig(tx.GasFeeCap),
		Gas:        tx.Gas,
		To:         copyAddressPtr(tx.To),
		Value:      copyBig(tx.Value),
		Data:       common.CopyBytes(tx.Data),
		AccessList: copyAccessList(tx.AccessList),
		V:          copyBig(tx.V),
		R:          copyBig(tx.R),
		S:          copyBig(tx.S),
	}
}
func (tx *DynamicFeeTx) chainID() *big.Int                      { return copyBig(tx.ChainID) }
func (tx *DynamicFeeTx) accessList() AccessList                 { return copyAccessList(tx.AccessList) }
func (tx *DynamicFeeTx) data() []byte                           { return common.CopyBytes(tx.Data) }
func (tx *DynamicFeeTx) gas() uint64                            { return tx.Gas }
func (tx *DynamicFeeTx) gasPrice() *big.Int                     { return copyBig(tx.GasFeeCap) }
func (tx *DynamicFeeTx) gasFeeCap() *big.Int                    { return copyBig(tx.GasFeeCap) }
func (tx *DynamicFeeTx) gasTipCap() *big.Int                    { return copyBig(tx.GasTipCap) }
func (tx *DynamicFeeTx) value() *big.Int                        { return copyBig(tx.Value) }
func (tx *DynamicFeeTx) nonce() uint64                          { return tx.Nonce }
func (tx *DynamicFeeTx) to() *common.Address                    { return copyAddressPtr(tx.To) }
func (tx *DynamicFeeTx) rawSignatureValues() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }
func (tx *DynamicFeeTx) setSignatureValues(v, r, s *big.Int)    { tx.V, tx.R, tx.S = v, r, s }
