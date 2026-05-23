package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
)

func copyHashList(list []common.Hash) []common.Hash {
	if len(list) == 0 {
		return nil
	}
	cpy := make([]common.Hash, len(list))
	copy(cpy, list)
	return cpy
}

func copyAuthorizationList(list []SetCodeAuthorization) []SetCodeAuthorization {
	if len(list) == 0 {
		return nil
	}
	cpy := make([]SetCodeAuthorization, len(list))
	for i, auth := range list {
		cpy[i] = SetCodeAuthorization{
			ChainID: copyBig(auth.ChainID),
			Address: auth.Address,
			Nonce:   auth.Nonce,
			V:       copyBig(auth.V),
			R:       copyBig(auth.R),
			S:       copyBig(auth.S),
		}
	}
	return cpy
}

func (tx *BlobTx) txType() uint8 { return BlobTxType }

func (tx *BlobTx) copy() TxData {
	var sidecar *BlobTxSidecar
	if tx.Sidecar != nil {
		sidecar = tx.Sidecar.Copy()
	}
	return &BlobTx{
		ChainID:    copyBig(tx.ChainID),
		Nonce:      tx.Nonce,
		GasTipCap:  copyBig(tx.GasTipCap),
		GasFeeCap:  copyBig(tx.GasFeeCap),
		Gas:        tx.Gas,
		To:         tx.To,
		Value:      copyBig(tx.Value),
		Data:       common.CopyBytes(tx.Data),
		AccessList: copyAccessList(tx.AccessList),
		BlobFeeCap: copyBig(tx.BlobFeeCap),
		BlobHashes: copyHashList(tx.BlobHashes),
		Sidecar:    sidecar,
		V:          copyBig(tx.V),
		R:          copyBig(tx.R),
		S:          copyBig(tx.S),
	}
}

func (tx *BlobTx) chainID() *big.Int                      { return copyBig(tx.ChainID) }
func (tx *BlobTx) accessList() AccessList                 { return copyAccessList(tx.AccessList) }
func (tx *BlobTx) data() []byte                           { return common.CopyBytes(tx.Data) }
func (tx *BlobTx) gas() uint64                            { return tx.Gas }
func (tx *BlobTx) gasPrice() *big.Int                     { return copyBig(tx.GasFeeCap) }
func (tx *BlobTx) gasFeeCap() *big.Int                    { return copyBig(tx.GasFeeCap) }
func (tx *BlobTx) gasTipCap() *big.Int                    { return copyBig(tx.GasTipCap) }
func (tx *BlobTx) value() *big.Int                        { return copyBig(tx.Value) }
func (tx *BlobTx) nonce() uint64                          { return tx.Nonce }
func (tx *BlobTx) to() *common.Address                    { to := tx.To; return &to }
func (tx *BlobTx) rawSignatureValues() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }
func (tx *BlobTx) setSignatureValues(v, r, s *big.Int)    { tx.V, tx.R, tx.S = v, r, s }

func (tx *SetCodeTx) txType() uint8 { return SetCodeTxType }

func (tx *SetCodeTx) copy() TxData {
	return &SetCodeTx{
		ChainID:    copyBig(tx.ChainID),
		Nonce:      tx.Nonce,
		GasTipCap:  copyBig(tx.GasTipCap),
		GasFeeCap:  copyBig(tx.GasFeeCap),
		Gas:        tx.Gas,
		To:         tx.To,
		Value:      copyBig(tx.Value),
		Data:       common.CopyBytes(tx.Data),
		AccessList: copyAccessList(tx.AccessList),
		AuthList:   copyAuthorizationList(tx.AuthList),
		V:          copyBig(tx.V),
		R:          copyBig(tx.R),
		S:          copyBig(tx.S),
	}
}

func (tx *SetCodeTx) chainID() *big.Int                      { return copyBig(tx.ChainID) }
func (tx *SetCodeTx) accessList() AccessList                 { return copyAccessList(tx.AccessList) }
func (tx *SetCodeTx) data() []byte                           { return common.CopyBytes(tx.Data) }
func (tx *SetCodeTx) gas() uint64                            { return tx.Gas }
func (tx *SetCodeTx) gasPrice() *big.Int                     { return copyBig(tx.GasFeeCap) }
func (tx *SetCodeTx) gasFeeCap() *big.Int                    { return copyBig(tx.GasFeeCap) }
func (tx *SetCodeTx) gasTipCap() *big.Int                    { return copyBig(tx.GasTipCap) }
func (tx *SetCodeTx) value() *big.Int                        { return copyBig(tx.Value) }
func (tx *SetCodeTx) nonce() uint64                          { return tx.Nonce }
func (tx *SetCodeTx) to() *common.Address                    { to := tx.To; return &to }
func (tx *SetCodeTx) rawSignatureValues() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }
func (tx *SetCodeTx) setSignatureValues(v, r, s *big.Int)    { tx.V, tx.R, tx.S = v, r, s }
