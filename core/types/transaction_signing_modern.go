package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

// modernSigner is a compatibility signer for modern Ethereum transaction
// formats. Legacy transactions delegate to EIP-155. Typed transaction signing
// hashes follow EIP-2930/EIP-1559/EIP-4844/EIP-7702 typed transaction rules.
type modernSigner struct {
	EIP155Signer
	fork string
}

func newModernSigner(chainID *big.Int, fork string) modernSigner {
	return modernSigner{EIP155Signer: NewEIP155Signer(chainID), fork: fork}
}

func NewEIP2930Signer(chainID *big.Int) Signer { return newModernSigner(chainID, "berlin") }
func NewLondonSigner(chainID *big.Int) Signer  { return newModernSigner(chainID, "london") }
func NewCancunSigner(chainID *big.Int) Signer  { return newModernSigner(chainID, "cancun") }
func NewPragueSigner(chainID *big.Int) Signer  { return newModernSigner(chainID, "prague") }

func (s modernSigner) Equal(other Signer) bool {
	o, ok := other.(modernSigner)
	return ok && s.fork == o.fork && s.chainId.Cmp(o.chainId) == 0
}

func (s modernSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() == LegacyTxType {
		return s.EIP155Signer.Sender(tx)
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	v, r, sigs := tx.RawSignatureValues()
	if v == nil || v.Sign() < 0 || v.BitLen() > 8 || v.Uint64() > 1 {
		return common.Address{}, ErrInvalidSig
	}
	// Typed transactions carry recovery id as 0/1. recoverPlain expects 27/28.
	typedV := new(big.Int).Add(v, big.NewInt(27))
	return recoverPlain(s.Hash(tx), r, sigs, typedV, true)
}

func (s modernSigner) SignatureValues(tx *Transaction, sig []byte) (r, ss, v *big.Int, err error) {
	if tx.Type() == LegacyTxType {
		return s.EIP155Signer.SignatureValues(tx, sig)
	}
	if len(sig) != crypto.SignatureLength {
		return nil, nil, nil, ErrInvalidSig
	}
	r = new(big.Int).SetBytes(sig[:32])
	ss = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64]})
	return r, ss, v, nil
}

func (s modernSigner) Hash(tx *Transaction) common.Hash {
	switch inner := tx.data.(type) {
	case *AccessListTx:
		return prefixedRlpHash(AccessListTxType, []interface{}{
			inner.ChainID,
			inner.Nonce,
			inner.GasPrice,
			inner.Gas,
			inner.To,
			inner.Value,
			inner.Data,
			inner.AccessList,
		})
	case *DynamicFeeTx:
		return prefixedRlpHash(DynamicFeeTxType, []interface{}{
			inner.ChainID,
			inner.Nonce,
			inner.GasTipCap,
			inner.GasFeeCap,
			inner.Gas,
			inner.To,
			inner.Value,
			inner.Data,
			inner.AccessList,
		})
	case *BlobTx:
		return prefixedRlpHash(BlobTxType, []interface{}{
			inner.ChainID,
			inner.Nonce,
			inner.GasTipCap,
			inner.GasFeeCap,
			inner.Gas,
			inner.To,
			inner.Value,
			inner.Data,
			inner.AccessList,
			inner.BlobFeeCap,
			inner.BlobHashes,
		})
	case *SetCodeTx:
		return prefixedRlpHash(SetCodeTxType, []interface{}{
			inner.ChainID,
			inner.Nonce,
			inner.GasTipCap,
			inner.GasFeeCap,
			inner.Gas,
			inner.To,
			inner.Value,
			inner.Data,
			inner.AccessList,
			inner.AuthList,
		})
	default:
		return s.EIP155Signer.Hash(tx)
	}
}

func prefixedRlpHash(typ uint8, x interface{}) common.Hash {
	payload, _ := rlp.EncodeToBytes(x)
	return crypto.Keccak256Hash(append([]byte{typ}, payload...))
}
