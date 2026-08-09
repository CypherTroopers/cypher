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

package core

import "errors"

var (
	// ErrKnownBlock is returned when a block to import is already known locally.
	ErrKnownBlock = errors.New("block already known")

	// ErrBlacklistedHash is returned if a block to import is on the blacklist.
	ErrBlacklistedHash = errors.New("blacklisted hash")

	// ErrNoGenesis is returned when there is no Genesis Block.
	ErrNoGenesis = errors.New("genesis not found in chain")
)

// List of evm-call-message pre-checking errors. All state transition messages will
// be pre-checked before execution. If any invalidation detected, the corresponding
// error should be returned which is defined here.
//
// - If the pre-checking happens in the miner, then the transaction won't be packed.
// - If the pre-checking happens in the block processing procedure, then a "BAD BLOCk"
// error should be emitted.
var (
	// ErrNonceTooLow is returned if the nonce of a transaction is lower than the
	// one present in the local chain.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrNonceTooHigh is returned if the nonce of a transaction is higher than the
	// next one expected based on the local chain.
	ErrNonceTooHigh = errors.New("nonce too high")

	// ErrNonceMax is returned when executing a transaction would wrap the
	// sender's uint64 account nonce.
	ErrNonceMax = errors.New("nonce has max value")

	// ErrSenderNoEOA implements EIP-3607. Prague delegation designators are the
	// only executable code permitted on a transaction sender account.
	ErrSenderNoEOA = errors.New("sender not an eoa")

	// ErrGasLimitReached is returned by the gas pool if the amount of gas required
	// by a transaction is higher than what's left in the block.
	ErrGasLimitReached = errors.New("gas limit reached")

	// ErrInsufficientFundsForTransfer is returned if the transaction sender doesn't
	// have enough funds for transfer(topmost call only).
	ErrInsufficientFundsForTransfer = errors.New("insufficient funds for transfer")

	// ErrInsufficientFunds is returned if the total cost of executing a transaction
	// is higher than the balance of the user's account.
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")

	// ErrGasUintOverflow is returned when calculating gas usage.
	ErrGasUintOverflow = errors.New("gas uint64 overflow")

	// ErrIntrinsicGas is returned if the transaction is specified to use less gas
	// than required to start the invocation.
	ErrIntrinsicGas = errors.New("intrinsic gas too low")

	// ErrFloorDataGas is returned when a Prague transaction's gas limit cannot
	// cover the EIP-7623 calldata floor.
	ErrFloorDataGas = errors.New("gas limit below calldata floor")

	// ErrTxGasLimitExceeded is returned when an Osaka transaction exceeds the
	// protocol-wide per-transaction gas cap.
	ErrTxGasLimitExceeded = errors.New("transaction gas limit exceeds protocol maximum")

	// ErrMaxInitCodeSizeExceeded is returned when Shanghai initcode exceeds
	// the EIP-3860 limit.
	ErrMaxInitCodeSizeExceeded = errors.New("max initcode size exceeded")

	// ErrGasFeeCapTooLow is returned if maxFeePerGas is lower than block baseFee.
	ErrGasFeeCapTooLow = errors.New("max fee per gas less than block base fee")

	// ErrGasTipAboveFeeCap is returned if maxPriorityFeePerGas exceeds maxFeePerGas.
	ErrGasTipAboveFeeCap = errors.New("max priority fee per gas higher than max fee per gas")

	// ErrBlobFeeCapTooLow is returned if maxFeePerBlobGas is lower than blob base fee.
	ErrBlobFeeCapTooLow = errors.New("max fee per blob gas less than blob base fee")

	// ErrBlobDAUnavailable rejects BlobTxs until ColossusX has an authenticated
	// blob-sidecar propagation and persistence path. Accepting only the versioned
	// hashes would let a block become canonical without its data being available.
	ErrBlobDAUnavailable = errors.New("blob transaction data availability is unavailable in ColossusX")

	// ErrTxTypeNotSupported is returned when a typed transaction is used before
	// the fork which introduces it.
	ErrTxTypeNotSupported = errors.New("transaction type not supported at this fork")

	// ErrSetCodeTxCreate is returned when an EIP-7702 transaction attempts
	// contract creation instead of calling an existing address.
	ErrSetCodeTxCreate = errors.New("set code transaction cannot create a contract")

	// ErrEmptyAuthList is returned when an EIP-7702 transaction has no
	// authorization tuples.
	ErrEmptyAuthList = errors.New("set code transaction authorization list is empty")

	// ErrTipVeryHigh is returned if maxPriorityFeePerGas exceeds 2^256-1.
	ErrTipVeryHigh = errors.New("max priority fee per gas higher than 2^256-1")

	// ErrFeeCapVeryHigh is returned if maxFeePerGas exceeds 2^256-1.
	ErrFeeCapVeryHigh = errors.New("max fee per gas higher than 2^256-1")

	// ErrAbortBlocksProcessing is returned if bc.insertChain is interrupted under raft mode
	ErrAbortBlocksProcessing = errors.New("abort during blocks processing")
)

// EIP-7702 authorization errors are informational while processing an
// authorization list. Invalid tuples are skipped without aborting the
// enclosing transaction.
var (
	ErrAuthorizationWrongChainID       = errors.New("EIP-7702 authorization chain ID mismatch")
	ErrAuthorizationNonceOverflow      = errors.New("EIP-7702 authorization nonce > 64 bit")
	ErrAuthorizationInvalidSignature   = errors.New("EIP-7702 authorization has invalid signature")
	ErrAuthorizationDestinationHasCode = errors.New("EIP-7702 authorization destination is a contract")
	ErrAuthorizationNonceMismatch      = errors.New("EIP-7702 authorization nonce does not match current account nonce")
)
