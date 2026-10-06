package types

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
)

// NativeAccessMode describes the strongest access a transaction may perform on
// a declared state resource.
type NativeAccessMode uint8

const (
	NativeAccessRead NativeAccessMode = iota + 1
	NativeAccessWrite
)

// NativeResourceKind separates account metadata from contract storage.
type NativeResourceKind uint8

const (
	NativeResourceAccount NativeResourceKind = iota + 1
	NativeResourceStorage
)

// NativeResource is the unhashed identity used to derive the deterministic
// execution dependency graph. Account resources require a zero Slot.
type NativeResource struct {
	Kind    NativeResourceKind `json:"kind"`
	Address common.Address     `json:"address"`
	Slot    common.Hash        `json:"slot"`
}

// NativeAccess is one signed read/write declaration. Accesses in a NativeTxV1
// must be strictly sorted by resource identity and must not contain duplicates.
type NativeAccess struct {
	Resource NativeResource   `json:"resource"`
	Mode     NativeAccessMode `json:"mode"`
}

// NativeTxV1 is the consensus payload for NativeTxType. Field order is also
// the RLP wire order. Every field except V/R/S is included in the signing hash.
//
// NativeTxV1 deliberately has no Ethereum account nonce. Replay protection is
// provided by a payer-scoped ReplaySequence plus the recent-block validity
// window, and admission must use the native pool instead of the legacy
// sender/nonce pool.
type NativeTxV1 struct {
	ChainID           *big.Int
	RecentBlockHash   common.Hash
	RecentBlockNumber uint64
	ValidUntil        uint64
	Payer             common.Address
	ReplaySequence    uint64
	// To is always present. Native contract deployment is a future system-program
	// instruction, never nonce-derived contract creation.
	To                    common.Address
	Value                 *big.Int
	Data                  []byte
	MaxFeePerCompute      *big.Int
	PriorityFeePerCompute *big.Int
	ComputeLimit          uint64
	MemoryLimit           uint64
	LogLimit              uint64
	OutputLimit           uint64
	Accesses              []NativeAccess
	V, R, S               *big.Int
}

var (
	ErrInvalidNativeManifest    = errors.New("invalid native transaction manifest")
	ErrNonCanonicalNativeAccess = errors.New("native transaction accesses are not strictly canonical")
	ErrNativePayerMismatch      = fmt.Errorf("%w: native transaction payer does not match signer", ErrInvalidSig)
)

// ValidateNativeManifest checks the consensus shape of the complete declared
// state footprint. Ordering is Kind, Address, Slot; Mode is not part of the
// resource identity, so declaring the same resource twice is non-canonical.
// The fee payer must be writable. The execution target must be declared at
// least read-only, and must be writable when value is transferred.
func ValidateNativeManifest(tx *NativeTxV1) error {
	if tx == nil {
		return fmt.Errorf("%w: nil transaction", ErrInvalidNativeManifest)
	}
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return fmt.Errorf("%w: negative value", ErrInvalidNativeManifest)
	}
	if tx.ValidUntil < tx.RecentBlockNumber {
		return fmt.Errorf("%w: valid-until block %d precedes recent block %d", ErrInvalidNativeManifest, tx.ValidUntil, tx.RecentBlockNumber)
	}
	var payerWritable, targetDeclared, targetWritable bool
	accountModes := make(map[common.Address]NativeAccessMode)
	for index, access := range tx.Accesses {
		if access.Mode != NativeAccessRead && access.Mode != NativeAccessWrite {
			return fmt.Errorf("%w: access %d has mode %d", ErrInvalidNativeManifest, index, access.Mode)
		}
		switch access.Resource.Kind {
		case NativeResourceAccount:
			if access.Resource.Slot != (common.Hash{}) {
				return fmt.Errorf("%w: account access %d has a storage slot", ErrInvalidNativeManifest, index)
			}
		case NativeResourceStorage:
			// Slot zero is a valid storage key.
		default:
			return fmt.Errorf("%w: access %d has resource kind %d", ErrInvalidNativeManifest, index, access.Resource.Kind)
		}
		if index > 0 && compareNativeResource(tx.Accesses[index-1].Resource, access.Resource) >= 0 {
			return fmt.Errorf("%w: %w at index %d", ErrInvalidNativeManifest, ErrNonCanonicalNativeAccess, index)
		}
		if access.Resource.Kind != NativeResourceAccount {
			continue
		}
		accountModes[access.Resource.Address] = access.Mode
		if access.Resource.Address == tx.Payer && access.Mode == NativeAccessWrite {
			payerWritable = true
		}
		if access.Resource.Address == tx.To {
			targetDeclared = true
			targetWritable = access.Mode == NativeAccessWrite
		}
	}
	if !payerWritable {
		return fmt.Errorf("%w: payer account is not declared writable", ErrInvalidNativeManifest)
	}
	if !targetDeclared {
		return fmt.Errorf("%w: execution target account is not declared", ErrInvalidNativeManifest)
	}
	if tx.Value != nil && tx.Value.Sign() > 0 && !targetWritable {
		return fmt.Errorf("%w: value target account is not declared writable", ErrInvalidNativeManifest)
	}
	// Every slot is subordinate to its account. Requiring an account read makes
	// a structural account write conflict with all storage work at that address,
	// while transactions touching independent slots may still share the account
	// read and execute in one wave.
	for index, access := range tx.Accesses {
		if access.Resource.Kind != NativeResourceStorage {
			continue
		}
		if mode := accountModes[access.Resource.Address]; mode != NativeAccessRead && mode != NativeAccessWrite {
			return fmt.Errorf("%w: storage access %d has no account declaration for %s", ErrInvalidNativeManifest, index, access.Resource.Address)
		}
	}
	return nil
}

func compareNativeResource(a, b NativeResource) int {
	if a.Kind < b.Kind {
		return -1
	}
	if a.Kind > b.Kind {
		return 1
	}
	if cmp := bytes.Compare(a.Address[:], b.Address[:]); cmp != 0 {
		return cmp
	}
	return bytes.Compare(a.Slot[:], b.Slot[:])
}

func copyNativeAccesses(accesses []NativeAccess) []NativeAccess {
	if len(accesses) == 0 {
		return nil
	}
	cpy := make([]NativeAccess, len(accesses))
	copy(cpy, accesses)
	return cpy
}

func (tx *NativeTxV1) txType() uint8 { return NativeTxType }

func (tx *NativeTxV1) copy() TxData {
	return &NativeTxV1{
		ChainID:               copyBig(tx.ChainID),
		RecentBlockHash:       tx.RecentBlockHash,
		RecentBlockNumber:     tx.RecentBlockNumber,
		ValidUntil:            tx.ValidUntil,
		Payer:                 tx.Payer,
		ReplaySequence:        tx.ReplaySequence,
		To:                    tx.To,
		Value:                 copyBig(tx.Value),
		Data:                  common.CopyBytes(tx.Data),
		MaxFeePerCompute:      copyBig(tx.MaxFeePerCompute),
		PriorityFeePerCompute: copyBig(tx.PriorityFeePerCompute),
		ComputeLimit:          tx.ComputeLimit,
		MemoryLimit:           tx.MemoryLimit,
		LogLimit:              tx.LogLimit,
		OutputLimit:           tx.OutputLimit,
		Accesses:              copyNativeAccesses(tx.Accesses),
		V:                     copyBig(tx.V),
		R:                     copyBig(tx.R),
		S:                     copyBig(tx.S),
	}
}

func (tx *NativeTxV1) chainID() *big.Int { return copyBig(tx.ChainID) }
func (tx *NativeTxV1) accessList() AccessList {
	// The signed native manifest is also the EVM warm-access declaration. This
	// makes declared accounts/slots cheap to access without introducing a
	// second, potentially inconsistent access list into NativeTxV1.
	list := make(AccessList, 0, len(tx.Accesses))
	indexes := make(map[common.Address]int, len(tx.Accesses))
	for _, access := range tx.Accesses {
		index, exists := indexes[access.Resource.Address]
		if !exists {
			index = len(list)
			indexes[access.Resource.Address] = index
			list = append(list, AccessTuple{Address: access.Resource.Address})
		}
		if access.Resource.Kind == NativeResourceStorage {
			list[index].StorageKeys = append(list[index].StorageKeys, access.Resource.Slot)
		}
	}
	return list
}
func (tx *NativeTxV1) data() []byte        { return common.CopyBytes(tx.Data) }
func (tx *NativeTxV1) gas() uint64         { return tx.ComputeLimit }
func (tx *NativeTxV1) gasPrice() *big.Int  { return copyBig(tx.MaxFeePerCompute) }
func (tx *NativeTxV1) gasFeeCap() *big.Int { return copyBig(tx.MaxFeePerCompute) }
func (tx *NativeTxV1) gasTipCap() *big.Int { return copyBig(tx.PriorityFeePerCompute) }
func (tx *NativeTxV1) value() *big.Int     { return copyBig(tx.Value) }

// nonce returns zero only to satisfy the shared TxData interface. NativeTxV1
// must never be admitted to a sender/nonce-indexed legacy transaction pool.
func (tx *NativeTxV1) nonce() uint64 { return 0 }

func (tx *NativeTxV1) to() *common.Address {
	to := tx.To
	return &to
}

func (tx *NativeTxV1) rawSignatureValues() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }
func (tx *NativeTxV1) setSignatureValues(v, r, s *big.Int)    { tx.V, tx.R, tx.S = v, r, s }

func (tx *NativeTxV1) signingFields() []interface{} {
	return []interface{}{
		tx.ChainID,
		tx.RecentBlockHash,
		tx.RecentBlockNumber,
		tx.ValidUntil,
		tx.Payer,
		tx.ReplaySequence,
		tx.To,
		tx.Value,
		tx.Data,
		tx.MaxFeePerCompute,
		tx.PriorityFeePerCompute,
		tx.ComputeLimit,
		tx.MemoryLimit,
		tx.LogLimit,
		tx.OutputLimit,
		tx.Accesses,
	}
}

func (tx *Transaction) RecentBlockHash() common.Hash {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.RecentBlockHash
	}
	return common.Hash{}
}

func (tx *Transaction) RecentBlockNumber() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.RecentBlockNumber
	}
	return 0
}

func (tx *Transaction) ValidUntil() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.ValidUntil
	}
	return 0
}

func (tx *Transaction) Payer() common.Address {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.Payer
	}
	return common.Address{}
}

// ReplaySequence returns the signed payer-scoped replay sequence for a native
// transaction. Zero is the first valid sequence and is therefore not a
// sentinel value.
func (tx *Transaction) ReplaySequence() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.ReplaySequence
	}
	return 0
}

func (tx *Transaction) ComputeLimit() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.ComputeLimit
	}
	return 0
}

func (tx *Transaction) MemoryLimit() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.MemoryLimit
	}
	return 0
}

func (tx *Transaction) LogLimit() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.LogLimit
	}
	return 0
}

func (tx *Transaction) OutputLimit() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return inner.OutputLimit
	}
	return 0
}

func (tx *Transaction) MaxFeePerCompute() *big.Int {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return copyBig(inner.MaxFeePerCompute)
	}
	return new(big.Int)
}

func (tx *Transaction) PriorityFeePerCompute() *big.Int {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return copyBig(inner.PriorityFeePerCompute)
	}
	return new(big.Int)
}

func (tx *Transaction) NativeAccesses() []NativeAccess {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return copyNativeAccesses(inner.Accesses)
	}
	return nil
}

func (tx *Transaction) NativeAccessCount() uint64 {
	if inner, ok := tx.data.(*NativeTxV1); ok {
		return uint64(len(inner.Accesses))
	}
	return 0
}

// NativeAccessAt returns one immutable signed manifest entry by value. It lets
// consensus hot paths iterate without allocating a defensive copy of the full
// manifest; callers cannot mutate the transaction through the returned value.
func (tx *Transaction) NativeAccessAt(index uint64) (NativeAccess, bool) {
	if inner, ok := tx.data.(*NativeTxV1); ok && index < uint64(len(inner.Accesses)) {
		return inner.Accesses[index], true
	}
	return NativeAccess{}, false
}

// ValidateNativeManifest validates the transaction's signed native access
// declaration. It rejects non-native transactions.
func (tx *Transaction) ValidateNativeManifest() error {
	if tx == nil || tx.data == nil {
		return fmt.Errorf("%w: nil or uninitialized transaction", ErrInvalidNativeManifest)
	}
	inner, ok := tx.data.(*NativeTxV1)
	if !ok {
		return fmt.Errorf("%w: transaction type %d", ErrInvalidNativeManifest, tx.Type())
	}
	return ValidateNativeManifest(inner)
}
