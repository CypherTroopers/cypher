package types

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
)

// DelegationPrefix is the EIP-7702 delegation designator prefix. Code with
// this prefix followed by an address delegates execution to that address.
var DelegationPrefix = []byte{0xef, 0x01, 0x00}

// ParseDelegation extracts the target address from an EIP-7702 delegation
// designator. Delegations have the exact form 0xef0100 || address.
func ParseDelegation(code []byte) (common.Address, bool) {
	if len(code) != len(DelegationPrefix)+common.AddressLength || !bytes.HasPrefix(code, DelegationPrefix) {
		return common.Address{}, false
	}
	return common.BytesToAddress(code[len(DelegationPrefix):]), true
}

// AddressToDelegation creates an EIP-7702 delegation designator for addr.
func AddressToDelegation(addr common.Address) []byte {
	delegation := make([]byte, len(DelegationPrefix)+common.AddressLength)
	copy(delegation, DelegationPrefix)
	copy(delegation[len(DelegationPrefix):], addr[:])
	return delegation
}

// SigHash returns the EIP-7702 authorization signing hash:
// keccak256(0x05 || rlp([chain_id, address, nonce])).
func (auth *SetCodeAuthorization) SigHash() common.Hash {
	return prefixedRlpHash(0x05, []interface{}{
		auth.ChainID,
		auth.Address,
		auth.Nonce,
	})
}

// SignSetCode signs an EIP-7702 authorization with prv. The input is copied so
// callers can safely reuse both the unsigned authorization and its big.Int
// fields.
func SignSetCode(prv *ecdsa.PrivateKey, auth SetCodeAuthorization) (SetCodeAuthorization, error) {
	hash := auth.SigHash()
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return SetCodeAuthorization{}, err
	}
	return SetCodeAuthorization{
		ChainID: copyBig(auth.ChainID),
		Address: auth.Address,
		Nonce:   auth.Nonce,
		V:       newBigFromByte(sig[64]),
		R:       newBigFromBytes(sig[:32]),
		S:       newBigFromBytes(sig[32:64]),
	}, nil
}

// Authority recovers the account which signed this EIP-7702 authorization.
// EIP-2 low-s rules and the typed-signature y-parity range are enforced before
// public-key recovery.
func (auth *SetCodeAuthorization) Authority() (common.Address, error) {
	if auth == nil || auth.V == nil || auth.R == nil || auth.S == nil ||
		auth.V.Sign() < 0 || auth.V.BitLen() > 1 {
		return common.Address{}, ErrInvalidSig
	}
	v := byte(auth.V.Uint64())
	if !crypto.ValidateSignatureValues(v, auth.R, auth.S, true) {
		return common.Address{}, ErrInvalidSig
	}
	hash := auth.SigHash()
	var sig [crypto.SignatureLength]byte
	auth.R.FillBytes(sig[:32])
	auth.S.FillBytes(sig[32:64])
	sig[64] = v
	pub, err := crypto.Ecrecover(hash[:], sig[:])
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) != 65 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	return common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]), nil
}

// SetCodeAuthorizations returns a deep copy of the transaction's EIP-7702
// authorization list. It returns nil for other transaction types.
func (tx *Transaction) SetCodeAuthorizations() []SetCodeAuthorization {
	if tx == nil {
		return nil
	}
	inner, ok := tx.data.(*SetCodeTx)
	if !ok {
		return nil
	}
	return copyAuthorizationList(inner.AuthList)
}

// SetCodeAuthorities returns each valid authorizing account once, preserving
// the order of its first valid authorization. Invalid signatures are skipped.
func (tx *Transaction) SetCodeAuthorities() []common.Address {
	if tx == nil {
		return nil
	}
	inner, ok := tx.data.(*SetCodeTx)
	if !ok {
		return nil
	}
	seen := make(map[common.Address]struct{}, len(inner.AuthList))
	authorities := make([]common.Address, 0, len(inner.AuthList))
	for i := range inner.AuthList {
		address, err := inner.AuthList[i].Authority()
		if err != nil {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		authorities = append(authorities, address)
	}
	return authorities
}

func newBigFromByte(value byte) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}

func newBigFromBytes(value []byte) *big.Int {
	return new(big.Int).SetBytes(value)
}
