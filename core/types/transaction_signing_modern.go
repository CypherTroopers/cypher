package types

import (
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/rlp"
)

// modernSigner is a compatibility signer for modern Ethereum transaction
// formats. Legacy transactions delegate to EIP-155. Typed transaction signing
// hashes follow EIP-2930/EIP-1559/EIP-4844/EIP-7702 typed transaction rules
// and the genesis-native NativeTxV1 domain.
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

// NewNativeSigner signs NativeTxV1 without coupling callers to an Ethereum
// fork name. Genesis configuration must select a modern signer for block
// execution; the dedicated constructor is intended for native admission/RPC.
func NewNativeSigner(chainID *big.Int) Signer { return newModernSigner(chainID, "native-v1") }

func (s modernSigner) Equal(other Signer) bool {
	o, ok := other.(modernSigner)
	return ok && s.fork == o.fork && s.chainId.Cmp(o.chainId) == 0
}

func (s modernSigner) Sender(tx *Transaction) (common.Address, error) {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return common.Address{}, err
	}
	if tx.Type() == LegacyTxType {
		return s.EIP155Signer.Sender(tx)
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	if inner, ok := tx.data.(*NativeTxV1); ok {
		if err := ValidateNativeManifest(inner); err != nil {
			return common.Address{}, err
		}
	}
	v, r, sigs := tx.RawSignatureValues()
	if v == nil || v.Sign() < 0 || v.BitLen() > 8 || v.Uint64() > 1 {
		return common.Address{}, ErrInvalidSig
	}
	// Typed transactions carry recovery id as 0/1. recoverPlain expects 27/28.
	typedV := new(big.Int).Add(v, big.NewInt(27))
	from, err := recoverPlain(s.Hash(tx), r, sigs, typedV, true)
	if err != nil {
		return common.Address{}, err
	}
	if inner, ok := tx.data.(*NativeTxV1); ok && from != inner.Payer {
		return common.Address{}, ErrNativePayerMismatch
	}
	return from, nil
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
	if err := tx.ValidateIntegerBounds(); err != nil {
		return common.Hash{}
	}
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
	case *NativeTxV1:
		return prefixedRlpHash(NativeTxType, inner.signingFields())
	default:
		return s.EIP155Signer.Hash(tx)
	}
}

func prefixedRlpHash(typ uint8, x interface{}) common.Hash {
	payload, _ := rlp.EncodeToBytes(x)
	return crypto.Keccak256Hash(append([]byte{typ}, payload...))
}
