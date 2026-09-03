// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"container/heap"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid transaction v, r, s values")
	ErrInvalidV   = errors.New("invalid transaction v")
)

type Transaction struct {
	data      TxData
	routeHint TxRouteHint
	time      time.Time

	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

// IsInitialized reports whether the transaction has a decoded or constructed
// inner payload. It lets trust-boundary validation reject a zero Transaction
// value without calling accessors which require an inner payload.
func (tx *Transaction) IsInitialized() bool {
	return tx != nil && tx.data != nil
}

type TxRouteHint uint8

const (
	TxRouteAuto TxRouteHint = iota
	TxRouteFast
	TxRouteSlow
)

type txdataMarshaling struct {
	AccountNonce hexutil.Uint64
	Price        *hexutil.Big
	GasLimit     hexutil.Uint64
	Amount       *hexutil.Big
	Payload      hexutil.Bytes
	V            *hexutil.Big
	R            *hexutil.Big
	S            *hexutil.Big
}

func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, gasPrice, data)
}

func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, gasPrice, data)
}

func newTransaction(nonce uint64, to *common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := &txdata{AccountNonce: nonce, Recipient: to, Payload: data, Amount: new(big.Int), GasLimit: gasLimit, Price: new(big.Int), V: new(big.Int), R: new(big.Int), S: new(big.Int)}
	if amount != nil {
		d.Amount.Set(amount)
	}
	if gasPrice != nil {
		d.Price.Set(gasPrice)
	}
	return &Transaction{data: d, time: time.Now()}
}

func (tx *Transaction) legacyData() *txdata {
	if tx == nil || tx.data == nil {
		return nil
	}
	if d, ok := tx.data.(*txdata); ok {
		return d
	}
	return nil
}

func (tx *Transaction) ChainId() *big.Int { return tx.data.chainID() }

func (tx *Transaction) Protected() bool {
	v, _, _ := tx.RawSignatureValues()
	return isProtectedV(v)
}

func isProtectedV(V *big.Int) bool {
	if V == nil {
		return false
	}
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	return true
}

func (tx *Transaction) EncodeRLP(w io.Writer) error {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return err
	}
	if tx.Type() == LegacyTxType {
		return rlp.Encode(w, tx.data)
	}
	payload, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	// EIP-2718 typed transactions are encoded as a single RLP string
	// containing TransactionType || TransactionPayload when embedded in
	// block bodies or eth protocol transaction lists.
	return rlp.Encode(w, payload)
}

func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}

	if kind == rlp.String {
		payload, err := s.Bytes()
		if err != nil {
			return err
		}
		err = tx.UnmarshalBinary(payload)
		if err == nil {
			tx.size.Store(common.StorageSize(len(payload)))
		}
		return err
	}

	var dec txdata
	err = dec.DecodeRLP(s)
	if err == nil {
		tx.data = &dec
		tx.setDecodedDefaults()
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}
	return err
}

type txJSON struct {
	Type                  *hexutil.Uint64        `json:"type,omitempty"`
	ChainID               *hexutil.Big           `json:"chainId,omitempty"`
	Nonce                 hexutil.Uint64         `json:"nonce"`
	GasPrice              *hexutil.Big           `json:"gasPrice,omitempty"`
	GasTipCap             *hexutil.Big           `json:"maxPriorityFeePerGas,omitempty"`
	GasFeeCap             *hexutil.Big           `json:"maxFeePerGas,omitempty"`
	BlobFeeCap            *hexutil.Big           `json:"maxFeePerBlobGas,omitempty"`
	Gas                   hexutil.Uint64         `json:"gas"`
	To                    *common.Address        `json:"to"`
	Value                 *hexutil.Big           `json:"value"`
	Input                 hexutil.Bytes          `json:"input"`
	AccessList            *AccessList            `json:"accessList,omitempty"`
	BlobHashes            []common.Hash          `json:"blobVersionedHashes,omitempty"`
	AuthList              []SetCodeAuthorization `json:"authorizationList,omitempty"`
	RecentBlockHash       *common.Hash           `json:"recentBlockHash,omitempty"`
	RecentBlockNumber     *hexutil.Uint64        `json:"recentBlockNumber,omitempty"`
	ValidUntil            *hexutil.Uint64        `json:"validUntil,omitempty"`
	Payer                 *common.Address        `json:"payer,omitempty"`
	ReplaySequence        *hexutil.Uint64        `json:"replaySequence,omitempty"`
	MaxFeePerCompute      *hexutil.Big           `json:"maxFeePerCompute,omitempty"`
	PriorityFeePerCompute *hexutil.Big           `json:"maxPriorityFeePerCompute,omitempty"`
	ComputeLimit          *hexutil.Uint64        `json:"computeLimit,omitempty"`
	MemoryLimit           *hexutil.Uint64        `json:"memoryLimit,omitempty"`
	LogLimit              *hexutil.Uint64        `json:"logLimit,omitempty"`
	OutputLimit           *hexutil.Uint64        `json:"outputLimit,omitempty"`
	NativeAccesses        []NativeAccess         `json:"accesses,omitempty"`
	RouteHint             TxRouteHint            `json:"routeHint,omitempty"`
	YParity               *hexutil.Uint64        `json:"yParity,omitempty"`
	V                     *hexutil.Big           `json:"v"`
	R                     *hexutil.Big           `json:"r"`
	S                     *hexutil.Big           `json:"s"`
	Hash                  *common.Hash           `json:"hash,omitempty"`
}

type txJSONUnmarshal struct {
	Type                  *hexutil.Uint64        `json:"type"`
	ChainID               *hexutil.Big           `json:"chainId"`
	Nonce                 *hexutil.Uint64        `json:"nonce"`
	GasPrice              *hexutil.Big           `json:"gasPrice"`
	GasTipCap             *hexutil.Big           `json:"maxPriorityFeePerGas"`
	GasFeeCap             *hexutil.Big           `json:"maxFeePerGas"`
	BlobFeeCap            *hexutil.Big           `json:"maxFeePerBlobGas"`
	Gas                   *hexutil.Uint64        `json:"gas"`
	To                    *common.Address        `json:"to"`
	Value                 *hexutil.Big           `json:"value"`
	Input                 *hexutil.Bytes         `json:"input"`
	AccessList            *AccessList            `json:"accessList"`
	BlobHashes            []common.Hash          `json:"blobVersionedHashes"`
	AuthList              []SetCodeAuthorization `json:"authorizationList"`
	RecentBlockHash       *common.Hash           `json:"recentBlockHash"`
	RecentBlockNumber     *hexutil.Uint64        `json:"recentBlockNumber"`
	ValidUntil            *hexutil.Uint64        `json:"validUntil"`
	Payer                 *common.Address        `json:"payer"`
	ReplaySequence        *hexutil.Uint64        `json:"replaySequence"`
	MaxFeePerCompute      *hexutil.Big           `json:"maxFeePerCompute"`
	PriorityFeePerCompute *hexutil.Big           `json:"maxPriorityFeePerCompute"`
	ComputeLimit          *hexutil.Uint64        `json:"computeLimit"`
	MemoryLimit           *hexutil.Uint64        `json:"memoryLimit"`
	LogLimit              *hexutil.Uint64        `json:"logLimit"`
	OutputLimit           *hexutil.Uint64        `json:"outputLimit"`
	NativeAccesses        *[]NativeAccess        `json:"accesses"`
	RouteHint             *TxRouteHint           `json:"routeHint"`
	YParity               *hexutil.Uint64        `json:"yParity"`
	V                     *hexutil.Big           `json:"v"`
	R                     *hexutil.Big           `json:"r"`
	S                     *hexutil.Big           `json:"s"`
}

func jsonBig(x *big.Int) *hexutil.Big {
	if x == nil {
		return (*hexutil.Big)(new(big.Int))
	}
	return (*hexutil.Big)(x)
}

func jsonUint64(x uint64) hexutil.Uint64 { return hexutil.Uint64(x) }

func jsonUint64Ptr(x uint64) *hexutil.Uint64 {
	value := jsonUint64(x)
	return &value
}

func (tx *Transaction) MarshalJSON() ([]byte, error) {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return nil, err
	}
	if inner, ok := tx.data.(*NativeTxV1); ok {
		if err := ValidateNativeManifest(inner); err != nil {
			return nil, err
		}
	}
	v, r, s := tx.RawSignatureValues()
	hash := tx.Hash()
	typ := hexutil.Uint64(tx.Type())
	enc := txJSON{Type: &typ, ChainID: jsonBig(tx.ChainId()), Nonce: jsonUint64(tx.Nonce()), GasPrice: jsonBig(tx.GasPrice()), Gas: jsonUint64(tx.Gas()), To: tx.To(), Value: jsonBig(tx.Value()), Input: tx.Data(), RouteHint: tx.routeHint, V: jsonBig(v), R: jsonBig(r), S: jsonBig(s), Hash: &hash}
	if tx.Type() >= AccessListTxType && tx.Type() <= SetCodeTxType {
		if v == nil || v.Sign() < 0 || v.BitLen() > 1 {
			return nil, ErrInvalidSig
		}
		parity := hexutil.Uint64(v.Uint64())
		enc.YParity = &parity
		accessList := tx.AccessList()
		if accessList == nil {
			accessList = AccessList{}
		}
		enc.AccessList = &accessList
	}
	switch inner := tx.data.(type) {
	case *DynamicFeeTx:
		enc.GasTipCap = jsonBig(inner.GasTipCap)
		enc.GasFeeCap = jsonBig(inner.GasFeeCap)
	case *BlobTx:
		enc.GasTipCap = jsonBig(inner.GasTipCap)
		enc.GasFeeCap = jsonBig(inner.GasFeeCap)
		enc.BlobFeeCap = jsonBig(inner.BlobFeeCap)
		enc.BlobHashes = copyHashList(inner.BlobHashes)
	case *SetCodeTx:
		enc.GasTipCap = jsonBig(inner.GasTipCap)
		enc.GasFeeCap = jsonBig(inner.GasFeeCap)
		enc.AuthList = copyAuthorizationList(inner.AuthList)
	case *NativeTxV1:
		recentBlockHash := inner.RecentBlockHash
		payer := inner.Payer
		enc.GasPrice = nil
		enc.RecentBlockHash = &recentBlockHash
		enc.RecentBlockNumber = jsonUint64Ptr(inner.RecentBlockNumber)
		enc.ValidUntil = jsonUint64Ptr(inner.ValidUntil)
		enc.Payer = &payer
		enc.ReplaySequence = jsonUint64Ptr(inner.ReplaySequence)
		enc.MaxFeePerCompute = jsonBig(inner.MaxFeePerCompute)
		enc.PriorityFeePerCompute = jsonBig(inner.PriorityFeePerCompute)
		enc.ComputeLimit = jsonUint64Ptr(inner.ComputeLimit)
		enc.MemoryLimit = jsonUint64Ptr(inner.MemoryLimit)
		enc.LogLimit = jsonUint64Ptr(inner.LogLimit)
		enc.OutputLimit = jsonUint64Ptr(inner.OutputLimit)
		enc.NativeAccesses = copyNativeAccesses(inner.Accesses)
	}
	return json.Marshal(enc)
}

func requiredBig(x *hexutil.Big) *big.Int {
	if x == nil {
		return new(big.Int)
	}
	return (*big.Int)(x)
}

func requiredUint64(x *hexutil.Uint64) uint64 {
	if x == nil {
		return 0
	}
	return uint64(*x)
}

func requiredBytes(x *hexutil.Bytes) []byte {
	if x == nil {
		return nil
	}
	return common.CopyBytes(*x)
}

func requiredAddress(x *common.Address) common.Address {
	if x == nil {
		return common.Address{}
	}
	return *x
}

func requiredHash(x *common.Hash) common.Hash {
	if x == nil {
		return common.Hash{}
	}
	return *x
}

func validateJSONSignature(v, r, s *big.Int, typed bool) error {
	if v == nil || r == nil || s == nil {
		return nil
	}
	if v.Sign() == 0 && r.Sign() == 0 && s.Sign() == 0 {
		return nil
	}
	if typed {
		if v.BitLen() > 8 || v.Uint64() > 1 {
			return ErrInvalidSig
		}
		if !crypto.ValidateSignatureValues(byte(v.Uint64()), r, s, false) {
			return ErrInvalidSig
		}
		return nil
	}
	var V byte
	if isProtectedV(v) {
		chainID := deriveChainId(v).Uint64()
		V = byte(v.Uint64() - 35 - 2*chainID)
	} else {
		V = byte(v.Uint64() - 27)
	}
	if !crypto.ValidateSignatureValues(V, r, s, false) {
		return ErrInvalidSig
	}
	return nil
}

// resolveTypedJSONParity accepts the Execution API's yParity field while
// retaining v as a deprecated compatibility alias. If a peer supplies both,
// they must describe the same recovery identifier.
func resolveTypedJSONParity(v *hexutil.Big, yParity *hexutil.Uint64) (*big.Int, error) {
	if yParity == nil {
		if v == nil {
			return nil, errors.New("missing 'yParity' or 'v' field in transaction")
		}
		return requiredBig(v), nil
	}
	if uint64(*yParity) > 1 {
		return nil, ErrInvalidSig
	}
	parity := new(big.Int).SetUint64(uint64(*yParity))
	if v != nil && (*big.Int)(v).Cmp(parity) != 0 {
		return nil, errors.New("transaction v and yParity fields disagree")
	}
	return parity, nil
}

func (tx *Transaction) UnmarshalJSON(input []byte) error {
	var dec txJSONUnmarshal
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Type == nil || uint64(*dec.Type) == LegacyTxType {
		var legacy txdata
		if err := legacy.UnmarshalJSON(input); err != nil {
			return err
		}
		if err := validateTypedIntegerBounds(&legacy); err != nil {
			return err
		}
		if err := validateJSONSignature(legacy.V, legacy.R, legacy.S, false); err != nil {
			return err
		}
		*tx = Transaction{data: &legacy, time: time.Now()}
	} else {
		v, err := resolveTypedJSONParity(dec.V, dec.YParity)
		if err != nil {
			return err
		}
		r, sigs := requiredBig(dec.R), requiredBig(dec.S)
		if err := validateJSONSignature(v, r, sigs, true); err != nil {
			return err
		}
		accessList := AccessList(nil)
		if dec.AccessList != nil {
			accessList = *dec.AccessList
		}
		switch uint64(*dec.Type) {
		case AccessListTxType:
			inner := &AccessListTx{ChainID: requiredBig(dec.ChainID), Nonce: requiredUint64(dec.Nonce), GasPrice: requiredBig(dec.GasPrice), Gas: requiredUint64(dec.Gas), To: dec.To, Value: requiredBig(dec.Value), Data: requiredBytes(dec.Input), AccessList: accessList, V: v, R: r, S: sigs}
			*tx = Transaction{data: inner, time: time.Now()}
		case DynamicFeeTxType:
			inner := &DynamicFeeTx{ChainID: requiredBig(dec.ChainID), Nonce: requiredUint64(dec.Nonce), GasTipCap: requiredBig(dec.GasTipCap), GasFeeCap: requiredBig(dec.GasFeeCap), Gas: requiredUint64(dec.Gas), To: dec.To, Value: requiredBig(dec.Value), Data: requiredBytes(dec.Input), AccessList: accessList, V: v, R: r, S: sigs}
			*tx = Transaction{data: inner, time: time.Now()}
		case BlobTxType:
			inner := &BlobTx{ChainID: requiredBig(dec.ChainID), Nonce: requiredUint64(dec.Nonce), GasTipCap: requiredBig(dec.GasTipCap), GasFeeCap: requiredBig(dec.GasFeeCap), Gas: requiredUint64(dec.Gas), To: requiredAddress(dec.To), Value: requiredBig(dec.Value), Data: requiredBytes(dec.Input), AccessList: accessList, BlobFeeCap: requiredBig(dec.BlobFeeCap), BlobHashes: copyHashList(dec.BlobHashes), V: v, R: r, S: sigs}
			*tx = Transaction{data: inner, time: time.Now()}
		case SetCodeTxType:
			inner := &SetCodeTx{ChainID: requiredBig(dec.ChainID), Nonce: requiredUint64(dec.Nonce), GasTipCap: requiredBig(dec.GasTipCap), GasFeeCap: requiredBig(dec.GasFeeCap), Gas: requiredUint64(dec.Gas), To: requiredAddress(dec.To), Value: requiredBig(dec.Value), Data: requiredBytes(dec.Input), AccessList: accessList, AuthList: copyAuthorizationList(dec.AuthList), V: v, R: r, S: sigs}
			*tx = Transaction{data: inner, time: time.Now()}
		default:
			return errors.New("unsupported transaction type in JSON; EVM consensus accepts only types 0 through 4")
		}
		if err := validateTypedIntegerBounds(tx.data); err != nil {
			return err
		}
	}
	if dec.RouteHint != nil {
		tx.routeHint = *dec.RouteHint
	}
	return nil
}

func (tx *Transaction) Data() []byte           { return tx.data.data() }
func (tx *Transaction) RouteHint() TxRouteHint { return tx.routeHint }

func (tx *Transaction) WithRouteHint(hint TxRouteHint) *Transaction {
	cpy := *tx
	cpy.data = tx.data.copy()
	cpy.routeHint = hint
	return &cpy
}

func (tx *Transaction) V() *big.Int        { v, _, _ := tx.RawSignatureValues(); return v }
func (tx *Transaction) Gas() uint64        { return tx.data.gas() }
func (tx *Transaction) GasPrice() *big.Int { return tx.data.gasPrice() }
func (tx *Transaction) GasPriceCmp(other *Transaction) int {
	return tx.GasPrice().Cmp(other.GasPrice())
}
func (tx *Transaction) GasPriceIntCmp(other *big.Int) int { return tx.GasPrice().Cmp(other) }
func (tx *Transaction) Value() *big.Int                   { return tx.data.value() }
func (tx *Transaction) Nonce() uint64                     { return tx.data.nonce() }

// CheckNonce is false for NativeTxV1 because its replay domain is the signed
// payer sequence and recent-block validity window. Native transactions require
// a dedicated pool and must not enter legacy sender/nonce admission.
func (tx *Transaction) CheckNonce() bool    { return tx.Type() != NativeTxType }
func (tx *Transaction) To() *common.Address { return tx.data.to() }

func (tx *Transaction) Hash() common.Hash {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return common.Hash{}
	}
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	var v common.Hash
	if tx.Type() == LegacyTxType {
		v = rlpHash(tx)
	} else if enc, err := tx.MarshalBinary(); err == nil {
		v = crypto.Keccak256Hash(enc)
	}
	tx.hash.Store(v)
	return v
}

func (tx *Transaction) Size() common.StorageSize {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return 0
	}
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	if tx.Type() == LegacyTxType {
		rlp.Encode(&c, tx.data)
	} else if enc, err := tx.MarshalBinary(); err == nil {
		c.Write(enc)
	}
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// AccessListEntryCounts returns the number of access-list addresses and
// storage keys without copying the access list. Consensus work metering calls
// this on immutable transactions before EVM execution, where the public
// AccessList accessor's defensive deep copy would otherwise amplify memory
// pressure for a maximum-size proposal.
func (tx *Transaction) AccessListEntryCounts() (addresses, storageKeys uint64, overflow bool) {
	if tx == nil || tx.data == nil {
		return 0, 0, false
	}
	var accessList AccessList
	switch inner := tx.data.(type) {
	case *AccessListTx:
		accessList = inner.AccessList
	case *DynamicFeeTx:
		accessList = inner.AccessList
	case *BlobTx:
		accessList = inner.AccessList
	case *SetCodeTx:
		accessList = inner.AccessList
	case *NativeTxV1:
		// Use the manifest resource count as a conservative address-work bound
		// without allocating a map before manifest validation. It is exact or an
		// overestimate and never rejects a valid transaction below the native
		// per-transaction resource ceiling.
		addresses = uint64(len(inner.Accesses))
		for _, access := range inner.Accesses {
			if access.Resource.Kind == NativeResourceStorage {
				if storageKeys == ^uint64(0) {
					return addresses, storageKeys, true
				}
				storageKeys++
			}
		}
		return addresses, storageKeys, false
	default:
		return 0, 0, false
	}
	addresses = uint64(len(accessList))
	for index := range accessList {
		count := uint64(len(accessList[index].StorageKeys))
		if count > ^uint64(0)-storageKeys {
			return addresses, storageKeys, true
		}
		storageKeys += count
	}
	return addresses, storageKeys, false
}

// SetCodeAuthorizationCount returns the EIP-7702 authorization count without
// making the deep copy required by SetCodeAuthorizations.
func (tx *Transaction) SetCodeAuthorizationCount() uint64 {
	if tx == nil {
		return 0
	}
	inner, ok := tx.data.(*SetCodeTx)
	if !ok {
		return 0
	}
	return uint64(len(inner.AuthList))
}

func (tx *Transaction) AsMessage(s Signer) (Message, error) {
	msg := Message{txType: tx.Type(), nonce: tx.Nonce(), gasLimit: tx.Gas(), gasPrice: tx.GasPrice(), gasFeeCap: tx.GasFeeCap(), gasTipCap: tx.GasTipCap(), blobGasFeeCap: tx.BlobGasFeeCap(), blobGas: tx.BlobGas(), to: tx.To(), amount: tx.Value(), data: tx.Data(), accessList: tx.AccessList(), blobHashes: tx.BlobHashes(), authList: tx.SetCodeAuthorizations(), checkNonce: tx.CheckNonce()}
	if inner, ok := tx.data.(*NativeTxV1); ok {
		msg.recentBlockHash = inner.RecentBlockHash
		msg.recentBlockNumber = inner.RecentBlockNumber
		msg.validUntil = inner.ValidUntil
		msg.payer = inner.Payer
		msg.replaySequence = inner.ReplaySequence
		msg.memoryLimit = inner.MemoryLimit
		msg.logLimit = inner.LogLimit
		msg.outputLimit = inner.OutputLimit
		// NativeTxV1 data is immutable after Transaction construction. Message's
		// public accessor remains defensive, so sharing this internal slice avoids
		// another full-manifest allocation on every execution.
		msg.nativeAccesses = inner.Accesses
	}
	var err error
	msg.from, err = Sender(s, tx)
	return msg, err
}

func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	if err := tx.ValidateIntegerBounds(); err != nil {
		return nil, err
	}
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{data: tx.data.copy(), time: tx.time}
	cpy.data.setSignatureValues(v, r, s)
	if err := cpy.ValidateIntegerBounds(); err != nil {
		return nil, err
	}
	return cpy, nil
}

func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas()))
	total.Add(total, tx.Value())
	total.Add(total, tx.BlobGasCost())
	return total
}

func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) { return tx.data.rawSignatureValues() }

type Transactions []*Transaction

func (s Transactions) Len() int      { return len(s) }
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp returns the exact trie-leaf value defined by EIP-2718. Legacy
// transactions remain an RLP list, while typed transactions must be the raw
// type || payload envelope and must not receive the extra RLP string wrapper
// used when they are embedded in a block body.
func (s Transactions) GetRlp(i int) []byte {
	enc, err := s[i].MarshalBinary()
	if err != nil {
		panic(err)
	}
	return enc
}

func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))
	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}
	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}
	return keep
}

type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].Nonce() < s[j].Nonce() }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type TxByPriceAndTime Transactions

func (s TxByPriceAndTime) Len() int { return len(s) }
func (s TxByPriceAndTime) Less(i, j int) bool {
	cmp := s[i].GasPrice().Cmp(s[j].GasPrice())
	if cmp == 0 {
		return s[i].time.Before(s[j].time)
	}
	return cmp > 0
}
func (s TxByPriceAndTime) Swap(i, j int)       { s[i], s[j] = s[j], s[i] }
func (s *TxByPriceAndTime) Push(x interface{}) { *s = append(*s, x.(*Transaction)) }
func (s *TxByPriceAndTime) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

type TransactionsByPriceAndNonce struct {
	txs         map[common.Address]Transactions
	heads       TxByPriceAndTime
	config      *params.ChainConfig
	blockNumber *big.Int
}

func NewTransactionsByPriceAndNonce(config *params.ChainConfig, blockNumber *big.Int, txs map[common.Address]Transactions) *TransactionsByPriceAndNonce {
	number := new(big.Int)
	if blockNumber != nil {
		number.Set(blockNumber)
	}
	heads := make(TxByPriceAndTime, 0, len(txs))
	for from, accTxs := range txs {
		signer := MakeSignerAutoJudgement(config, number, accTxs[0].V())
		acc, err := Sender(signer, accTxs[0])
		if err == nil {
			heads = append(heads, accTxs[0])
			txs[acc] = accTxs[1:]
		} else {
			log.Info("Failed to recovered sender address, this transaction is skipped", "from", from, "nonce", accTxs[0].Nonce(), "err", err)
		}
		if from != acc {
			delete(txs, from)
		}
	}
	heap.Init(&heads)
	return &TransactionsByPriceAndNonce{txs: txs, heads: heads, config: config, blockNumber: number}
}

func (t *TransactionsByPriceAndNonce) Peek() *Transaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Copy returns an independent proposal cursor over the same immutable
// transactions. Proposal builders use it to perform a speculative selection
// pass without exposing partially consumed ordering state when execution is
// retried from the same parent.
// The transaction objects themselves are intentionally shared: neither heap
// ordering nor Shift/Pop mutates a transaction.
func (t *TransactionsByPriceAndNonce) Copy() *TransactionsByPriceAndNonce {
	if t == nil {
		return nil
	}
	txs := make(map[common.Address]Transactions, len(t.txs))
	for address, transactions := range t.txs {
		txs[address] = append(Transactions(nil), transactions...)
	}
	heads := append(TxByPriceAndTime(nil), t.heads...)
	number := new(big.Int)
	if t.blockNumber != nil {
		number.Set(t.blockNumber)
	}
	return &TransactionsByPriceAndNonce{
		txs:         txs,
		heads:       heads,
		config:      t.config,
		blockNumber: number,
	}
}

func (t *TransactionsByPriceAndNonce) Shift() {
	if len(t.heads) == 0 {
		return
	}
	current := t.heads[0]
	acc, err := Sender(MakeSignerAutoJudgement(t.config, t.blockNumber, current.V()), current)
	if err != nil {
		heap.Pop(&t.heads)
		return
	}
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		t.heads[0], t.txs[acc] = txs[0], txs[1:]
		heap.Fix(&t.heads, 0)
	} else {
		heap.Pop(&t.heads)
	}
}
func (t *TransactionsByPriceAndNonce) Pop() { heap.Pop(&t.heads) }

type Message struct {
	txType            uint8
	to                *common.Address
	from              common.Address
	nonce             uint64
	amount            *big.Int
	gasLimit          uint64
	gasPrice          *big.Int
	gasFeeCap         *big.Int
	gasTipCap         *big.Int
	blobGasFeeCap     *big.Int
	blobGas           uint64
	data              []byte
	accessList        AccessList
	blobHashes        []common.Hash
	authList          []SetCodeAuthorization
	recentBlockHash   common.Hash
	recentBlockNumber uint64
	validUntil        uint64
	payer             common.Address
	replaySequence    uint64
	memoryLimit       uint64
	logLimit          uint64
	outputLimit       uint64
	nativeAccesses    []NativeAccess
	checkNonce        bool
}

func NewMessage(from common.Address, to *common.Address, nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, checkNonce bool) Message {
	return NewMessageWithFeeFields(from, to, nonce, amount, gasLimit, gasPrice, gasPrice, gasPrice, data, nil, checkNonce)
}

// NewMessageWithFeeFields constructs a message with explicit EIP-1559 fee fields
// and access list support while keeping legacy gasPrice behavior intact.
func NewMessageWithFeeFields(from common.Address, to *common.Address, nonce uint64, amount *big.Int, gasLimit uint64, gasPrice, gasFeeCap, gasTipCap *big.Int, data []byte, accessList AccessList, checkNonce bool) Message {
	msg := Message{from: from, to: to, nonce: nonce, gasLimit: gasLimit, checkNonce: checkNonce}
	if amount != nil {
		msg.amount = new(big.Int).Set(amount)
	} else {
		msg.amount = new(big.Int)
	}
	if gasPrice != nil {
		msg.gasPrice = new(big.Int).Set(gasPrice)
	} else {
		msg.gasPrice = new(big.Int)
	}
	if gasFeeCap != nil {
		msg.gasFeeCap = new(big.Int).Set(gasFeeCap)
	} else {
		msg.gasFeeCap = new(big.Int).Set(msg.gasPrice)
	}
	if gasTipCap != nil {
		msg.gasTipCap = new(big.Int).Set(gasTipCap)
	} else {
		msg.gasTipCap = new(big.Int).Set(msg.gasPrice)
	}
	if len(data) > 0 {
		msg.data = common.CopyBytes(data)
	}
	if len(accessList) > 0 {
		msg.accessList = copyAccessList(accessList)
	}
	return msg
}

// NewMessageWithModernFields constructs a call message with the additional
// EIP-4844 and EIP-7702 fields used by eth_call and estimateGas. Transaction
// execution obtains the same fields through Transaction.AsMessage.
func NewMessageWithModernFields(txType uint8, from common.Address, to *common.Address, nonce uint64, amount *big.Int, gasLimit uint64, gasPrice, gasFeeCap, gasTipCap, blobGasFeeCap *big.Int, data []byte, accessList AccessList, blobHashes []common.Hash, authList []SetCodeAuthorization, checkNonce bool) Message {
	msg := NewMessageWithFeeFields(from, to, nonce, amount, gasLimit, gasPrice, gasFeeCap, gasTipCap, data, accessList, checkNonce)
	msg.txType = txType
	if txType == SetCodeTxType {
		msg.authList = copyAuthorizationList(authList)
	}
	if txType == BlobTxType {
		if blobGasFeeCap != nil {
			msg.blobGasFeeCap = new(big.Int).Set(blobGasFeeCap)
		}
		msg.blobHashes = copyHashList(blobHashes)
		msg.blobGas = uint64(len(blobHashes)) * params.BlobTxBlobGasPerBlob
	}
	return msg
}

func (m Message) From() common.Address { return m.from }
func (m Message) To() *common.Address  { return m.to }
func (m Message) GasPrice() *big.Int   { return m.gasPrice }
func (m Message) GasFeeCap() *big.Int {
	if m.gasFeeCap == nil {
		return m.gasPrice
	}
	return m.gasFeeCap
}
func (m Message) GasTipCap() *big.Int {
	if m.gasTipCap == nil {
		return m.gasPrice
	}
	return m.gasTipCap
}
func (m Message) BlobGasFeeCap() *big.Int {
	if m.blobGasFeeCap == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(m.blobGasFeeCap)
}
func (m Message) BlobGas() uint64           { return m.blobGas }
func (m Message) AccessList() AccessList    { return copyAccessList(m.accessList) }
func (m Message) BlobHashes() []common.Hash { return copyHashList(m.blobHashes) }
func (m Message) Type() uint8               { return m.txType }
func (m Message) SetCodeAuthorizations() []SetCodeAuthorization {
	return copyAuthorizationList(m.authList)
}
func (m Message) RecentBlockHash() common.Hash   { return m.recentBlockHash }
func (m Message) RecentBlockNumber() uint64      { return m.recentBlockNumber }
func (m Message) ValidUntil() uint64             { return m.validUntil }
func (m Message) Payer() common.Address          { return m.payer }
func (m Message) ReplaySequence() uint64         { return m.replaySequence }
func (m Message) MemoryLimit() uint64            { return m.memoryLimit }
func (m Message) LogLimit() uint64               { return m.logLimit }
func (m Message) OutputLimit() uint64            { return m.outputLimit }
func (m Message) NativeAccesses() []NativeAccess { return copyNativeAccesses(m.nativeAccesses) }
func (m Message) Value() *big.Int                { return m.amount }
func (m Message) Gas() uint64                    { return m.gasLimit }
func (m Message) Nonce() uint64                  { return m.nonce }
func (m Message) Data() []byte                   { return m.data }
func (m Message) CheckNonce() bool               { return m.checkNonce }
