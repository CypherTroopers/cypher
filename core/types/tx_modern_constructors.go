package types

import "time"

// NewTx wraps typed transaction data into a Transaction. The input is copied so
// callers can safely reuse or mutate their original tx data after construction.
func NewTx(inner TxData) *Transaction {
	return &Transaction{data: inner.copy(), time: time.Now()}
}

// NewDynamicFeeTx wraps EIP-1559 dynamic fee transaction data into a Transaction.
func NewDynamicFeeTx(inner *DynamicFeeTx) *Transaction {
	return NewTx(inner)
}
