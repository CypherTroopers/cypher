// Copyright 2018 The go-ethereum Authors
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

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/params"
)

const maxSignerBlobBuilders = 64

var signerBlobBuilderSlots = make(chan struct{}, signerBlobBuilderBudget())

func signerBlobBuilderBudget() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > maxSignerBlobBuilders {
		return maxSignerBlobBuilders
	}
	return workers
}

func acquireSignerBlobBuilder(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case signerBlobBuilderSlots <- struct{}{}:
		return func() { <-signerBlobBuilderSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type ValidationInfo struct {
	Typ     string `json:"type"`
	Message string `json:"message"`
}
type ValidationMessages struct {
	Messages []ValidationInfo
}

const (
	WARN = "WARNING"
	CRIT = "CRITICAL"
	INFO = "Info"
)

func (vs *ValidationMessages) Crit(msg string) {
	vs.Messages = append(vs.Messages, ValidationInfo{CRIT, msg})
}
func (vs *ValidationMessages) Warn(msg string) {
	vs.Messages = append(vs.Messages, ValidationInfo{WARN, msg})
}
func (vs *ValidationMessages) Info(msg string) {
	vs.Messages = append(vs.Messages, ValidationInfo{INFO, msg})
}

// / getWarnings returns an error with all messages of type WARN of above, or nil if no warnings were present
func (v *ValidationMessages) getWarnings() error {
	var messages []string
	for _, msg := range v.Messages {
		if msg.Typ == WARN || msg.Typ == CRIT {
			messages = append(messages, msg.Message)
		}
	}
	if len(messages) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(messages, ","))
	}
	return nil
}

// SendTxArgs represents the arguments to submit a transaction
type SendTxArgs struct {
	From                 common.MixedcaseAddress  `json:"from"`
	To                   *common.MixedcaseAddress `json:"to"`
	Gas                  hexutil.Uint64           `json:"gas"`
	GasPrice             hexutil.Big              `json:"gasPrice"`
	MaxFeePerGas         *hexutil.Big             `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *hexutil.Big             `json:"maxPriorityFeePerGas,omitempty"`
	Value                hexutil.Big              `json:"value"`
	Nonce                hexutil.Uint64           `json:"nonce"`
	// We accept "data" and "input" for backwards-compatibility reasons.
	Data  *hexutil.Bytes `json:"data"`
	Input *hexutil.Bytes `json:"input,omitempty"`

	// Standard EVM typed-transaction fields. Type is optional because legacy
	// Clef clients historically selected the envelope from the populated fields.
	Type       *hexutil.Uint64   `json:"type,omitempty"`
	AccessList *types.AccessList `json:"accessList,omitempty"`
	ChainID    *hexutil.Big      `json:"chainId,omitempty"`

	// EIP-4844 transaction and EIP-7594 Osaka pooled-sidecar fields. A
	// Clef-signed BlobTx must carry the version-1 cell proofs so the returned raw
	// bytes can be submitted through eth_sendRawTransaction without losing data
	// availability.
	MaxFeePerBlobGas    *hexutil.Big     `json:"maxFeePerBlobGas,omitempty"`
	BlobVersionedHashes []common.Hash    `json:"blobVersionedHashes,omitempty"`
	BlobVersion         byte             `json:"blobVersion,omitempty"`
	Blobs               []kzg.Blob       `json:"blobs,omitempty"`
	Commitments         []kzg.Commitment `json:"commitments,omitempty"`
	Proofs              []kzg.Proof      `json:"proofs,omitempty"`

	// EIP-7702 authorization tuples are already signed by their respective
	// authorities. Clef signs the outer SetCode transaction.
	AuthorizationList []types.SetCodeAuthorization `json:"authorizationList,omitempty"`
}

func (args SendTxArgs) String() string {
	// A blob is 128 KiB and up to six are valid in one request. Keep Clef's
	// audit line bounded while retaining the commitments and versioned hashes
	// needed to identify what was approved. Cell proofs are deterministic from
	// the blobs and would otherwise add roughly 12 KiB of hex per blob.
	blobCount, proofCount := len(args.Blobs), len(args.Proofs)
	args.Blobs = nil
	args.Proofs = nil
	s, err := json.Marshal(args)
	if err == nil {
		if blobCount > 0 || proofCount > 0 {
			return fmt.Sprintf("%s [blobs=%d proofs=%d redacted]", s, blobCount, proofCount)
		}
		return string(s)
	}
	return err.Error()
}

func (args *SendTxArgs) transactionData() ([]byte, error) {
	if args == nil {
		return nil, errors.New("nil transaction arguments")
	}
	if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
		return nil, errors.New(`both "data" and "input" are set and not equal`)
	}
	if args.Input != nil {
		return common.CopyBytes(*args.Input), nil
	}
	if args.Data != nil {
		return common.CopyBytes(*args.Data), nil
	}
	return nil, nil
}

func (args *SendTxArgs) transactionType() (uint8, error) {
	if args == nil {
		return 0, errors.New("nil transaction arguments")
	}
	hasBlobFields := args.MaxFeePerBlobGas != nil || args.BlobVersionedHashes != nil || args.BlobVersion != 0 ||
		args.Blobs != nil || args.Commitments != nil || args.Proofs != nil
	hasSetCodeFields := args.AuthorizationList != nil
	if hasBlobFields && hasSetCodeFields {
		return 0, errors.New("blob and set-code transaction fields cannot be combined")
	}
	if args.Type != nil {
		txType := uint64(*args.Type)
		switch txType {
		case types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType:
			return uint8(txType), nil
		default:
			return 0, fmt.Errorf("unsupported EVM transaction type %d (only types 0-4 are accepted)", txType)
		}
	}
	switch {
	case hasBlobFields:
		return types.BlobTxType, nil
	case hasSetCodeFields:
		return types.SetCodeTxType, nil
	case args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil:
		return types.DynamicFeeTxType, nil
	case args.AccessList != nil:
		return types.AccessListTxType, nil
	default:
		return types.LegacyTxType, nil
	}
}

func resolveSignerChainID(requested *hexutil.Big, configured *big.Int, typed bool) (*big.Int, error) {
	var chainID *big.Int
	if requested != nil {
		chainID = new(big.Int).Set(requested.ToInt())
		if configured != nil && chainID.Cmp(configured) != 0 {
			return nil, fmt.Errorf("transaction chainId %s does not match signer chainId %s", chainID, configured)
		}
	} else if configured != nil {
		chainID = new(big.Int).Set(configured)
	}
	if chainID != nil && (chainID.Sign() < 0 || chainID.BitLen() > 256) {
		return nil, fmt.Errorf("transaction chainId is outside uint256 range")
	}
	if typed && chainID == nil {
		return nil, errors.New("chainId is required for typed transactions")
	}
	return chainID, nil
}

func signerBig(value *hexutil.Big) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value.ToInt())
}

func validateSignerUint256(name string, value *big.Int) error {
	if value != nil && (value.Sign() < 0 || value.BitLen() > 256) {
		return fmt.Errorf("transaction %s is outside uint256 range", name)
	}
	return nil
}

func (args *SendTxArgs) validateEnvelopeFields(txType uint8) error {
	hasDynamicFees := args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil
	hasBlobFields := args.MaxFeePerBlobGas != nil || args.BlobVersionedHashes != nil || args.BlobVersion != 0 ||
		args.Blobs != nil || args.Commitments != nil || args.Proofs != nil
	hasSetCodeFields := args.AuthorizationList != nil
	legacyPriceSet := (*big.Int)(&args.GasPrice).Sign() != 0

	switch txType {
	case types.LegacyTxType:
		if args.AccessList != nil || hasDynamicFees || hasBlobFields || hasSetCodeFields {
			return errors.New("legacy transaction type does not support typed transaction fields")
		}
	case types.AccessListTxType:
		if hasDynamicFees || hasBlobFields || hasSetCodeFields {
			return errors.New("access-list transaction type does not support dynamic, blob, or authorization fields")
		}
	case types.DynamicFeeTxType:
		if args.MaxFeePerGas == nil || args.MaxPriorityFeePerGas == nil {
			return errors.New("dynamic-fee transaction requires maxFeePerGas and maxPriorityFeePerGas")
		}
		if legacyPriceSet {
			return errors.New("dynamic-fee transaction cannot also specify gasPrice")
		}
		if hasBlobFields || hasSetCodeFields {
			return errors.New("dynamic-fee transaction type does not support blob or authorization fields")
		}
	case types.BlobTxType:
		if args.MaxFeePerGas == nil || args.MaxPriorityFeePerGas == nil {
			return errors.New("blob transaction requires maxFeePerGas and maxPriorityFeePerGas")
		}
		if args.MaxFeePerBlobGas == nil {
			return errors.New("blob transaction requires maxFeePerBlobGas")
		}
		if args.BlobVersion != 0 && args.BlobVersion != types.BlobSidecarVersion1 {
			return fmt.Errorf("blob wrapper version %d is not supported by genesis Osaka", args.BlobVersion)
		}
		if legacyPriceSet {
			return errors.New("blob transaction cannot also specify gasPrice")
		}
		if hasSetCodeFields {
			return errors.New("blob transaction does not support authorizationList")
		}
		if args.To == nil {
			return errors.New("transaction recipient must be set for blob transactions")
		}
	case types.SetCodeTxType:
		if args.MaxFeePerGas == nil || args.MaxPriorityFeePerGas == nil {
			return errors.New("set-code transaction requires maxFeePerGas and maxPriorityFeePerGas")
		}
		if legacyPriceSet {
			return errors.New("set-code transaction cannot also specify gasPrice")
		}
		if hasBlobFields {
			return errors.New("set-code transaction does not support blob fields")
		}
		if args.To == nil {
			return errors.New("transaction recipient must be set for set-code transactions")
		}
		if len(args.AuthorizationList) == 0 {
			return errors.New("set-code transaction requires a non-empty authorizationList")
		}
	default:
		return fmt.Errorf("unsupported EVM transaction type %d (only types 0-4 are accepted)", txType)
	}
	if args.MaxFeePerGas != nil && args.MaxPriorityFeePerGas != nil &&
		args.MaxFeePerGas.ToInt().Cmp(args.MaxPriorityFeePerGas.ToInt()) < 0 {
		return errors.New("maxFeePerGas must be greater than or equal to maxPriorityFeePerGas")
	}
	return nil
}

func (args *SendTxArgs) blobSidecar(ctx context.Context) (*types.BlobTxSidecar, []common.Hash, error) {
	if len(args.Blobs) == 0 {
		return nil, nil, errors.New("blob transaction requires blobs for pooled propagation")
	}
	if len(args.Blobs) > params.BlobTxMaxBlobs {
		return nil, nil, fmt.Errorf("blob transaction has %d blobs, maximum is %d", len(args.Blobs), params.BlobTxMaxBlobs)
	}
	if args.Commitments != nil && len(args.Commitments) != len(args.Blobs) {
		return nil, nil, fmt.Errorf("blob sidecar commitment count %d does not match blob count %d", len(args.Commitments), len(args.Blobs))
	}
	wantProofs := len(args.Blobs) * types.BlobCellProofsPerBlob
	if args.Proofs != nil && len(args.Proofs) != wantProofs {
		return nil, nil, fmt.Errorf("Osaka blob sidecar proof count %d does not match required cell proof count %d", len(args.Proofs), wantProofs)
	}
	release, err := acquireSignerBlobBuilder(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	commitments := append([]kzg.Commitment(nil), args.Commitments...)
	if commitments == nil {
		commitments = make([]kzg.Commitment, len(args.Blobs))
		for i := range args.Blobs {
			commitment, err := kzg.BlobToCommitment(&args.Blobs[i])
			if err != nil {
				return nil, nil, fmt.Errorf("compute blob commitment %d: %w", i, err)
			}
			commitments[i] = commitment
		}
	}
	proofs := append([]kzg.Proof(nil), args.Proofs...)
	if proofs == nil {
		proofs = make([]kzg.Proof, 0, wantProofs)
		for i := range args.Blobs {
			blobProofs, err := kzg.ComputeCellProofs(&args.Blobs[i])
			if err != nil {
				return nil, nil, fmt.Errorf("compute blob cell proofs %d: %w", i, err)
			}
			if len(blobProofs) != types.BlobCellProofsPerBlob {
				return nil, nil, fmt.Errorf("compute blob cell proofs %d: have %d proofs, want %d", i, len(blobProofs), types.BlobCellProofsPerBlob)
			}
			proofs = append(proofs, blobProofs...)
		}
	}
	if err := kzg.VerifyCellProofs(args.Blobs, commitments, proofs); err != nil {
		return nil, nil, fmt.Errorf("verify Osaka blob cell proofs: %w", err)
	}

	blobs := make([]types.Blob, len(args.Blobs))
	typedCommitments := make([]types.KZGCommitment, len(commitments))
	typedProofs := make([]types.KZGProof, len(proofs))
	for i := range args.Blobs {
		blobs[i] = append(types.Blob(nil), args.Blobs[i][:]...)
		typedCommitments[i] = types.KZGCommitment(commitments[i])
	}
	for i := range proofs {
		typedProofs[i] = types.KZGProof(proofs[i])
	}
	sidecar := types.NewBlobTxSidecar(types.BlobSidecarVersion1, blobs, typedCommitments, typedProofs)
	hashes := sidecar.BlobHashes()
	if args.BlobVersionedHashes != nil {
		if err := sidecar.ValidateBlobHashes(args.BlobVersionedHashes); err != nil {
			return nil, nil, fmt.Errorf("blob sidecar: %w", err)
		}
		hashes = append([]common.Hash(nil), args.BlobVersionedHashes...)
	}
	return sidecar, hashes, nil
}

// toTransaction converts Clef's mixed-case JSON arguments into one of the five
// standard EVM envelopes accepted by this network. configuredChainID is the
// signer's domain and must match an explicitly supplied chainId.
func (args *SendTxArgs) toTransaction(ctx context.Context, configuredChainID *big.Int) (*types.Transaction, error) {
	if ctx == nil {
		return nil, errors.New("nil transaction context")
	}
	txType, err := args.transactionType()
	if err != nil {
		return nil, err
	}
	if err := args.validateEnvelopeFields(txType); err != nil {
		return nil, err
	}
	input, err := args.transactionData()
	if err != nil {
		return nil, err
	}
	chainID, err := resolveSignerChainID(args.ChainID, configuredChainID, txType != types.LegacyTxType)
	if err != nil {
		return nil, err
	}

	var to *common.Address
	if args.To != nil {
		address := args.To.Address()
		to = &address
	}
	value := new(big.Int).Set((*big.Int)(&args.Value))
	gasPrice := new(big.Int).Set((*big.Int)(&args.GasPrice))
	for _, field := range []struct {
		name  string
		value *big.Int
	}{
		{"value", value},
		{"gasPrice", gasPrice},
		{"maxFeePerGas", signerBig(args.MaxFeePerGas)},
		{"maxPriorityFeePerGas", signerBig(args.MaxPriorityFeePerGas)},
		{"maxFeePerBlobGas", signerBig(args.MaxFeePerBlobGas)},
	} {
		if err := validateSignerUint256(field.name, field.value); err != nil {
			return nil, err
		}
	}
	var tx *types.Transaction
	switch txType {
	case types.LegacyTxType:
		if to == nil {
			tx = types.NewContractCreation(uint64(args.Nonce), value, uint64(args.Gas), gasPrice, input)
		} else {
			tx = types.NewTransaction(uint64(args.Nonce), *to, value, uint64(args.Gas), gasPrice, input)
		}
	case types.AccessListTxType:
		inner := &types.AccessListTx{
			ChainID: chainID, Nonce: uint64(args.Nonce), GasPrice: gasPrice,
			Gas: uint64(args.Gas), To: to, Value: value, Data: input,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		tx = types.NewTx(inner)
	case types.DynamicFeeTxType:
		inner := &types.DynamicFeeTx{
			ChainID: chainID, Nonce: uint64(args.Nonce),
			GasTipCap: signerBig(args.MaxPriorityFeePerGas), GasFeeCap: signerBig(args.MaxFeePerGas),
			Gas: uint64(args.Gas), To: to, Value: value, Data: input,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		tx = types.NewTx(inner)
	case types.BlobTxType:
		sidecar, hashes, err := args.blobSidecar(ctx)
		if err != nil {
			return nil, err
		}
		inner := &types.BlobTx{
			ChainID: chainID, Nonce: uint64(args.Nonce),
			GasTipCap: signerBig(args.MaxPriorityFeePerGas), GasFeeCap: signerBig(args.MaxFeePerGas),
			Gas: uint64(args.Gas), To: *to, Value: value, Data: input,
			BlobFeeCap: signerBig(args.MaxFeePerBlobGas), BlobHashes: hashes, Sidecar: sidecar,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		tx = types.NewTx(inner)
	case types.SetCodeTxType:
		inner := &types.SetCodeTx{
			ChainID: chainID, Nonce: uint64(args.Nonce),
			GasTipCap: signerBig(args.MaxPriorityFeePerGas), GasFeeCap: signerBig(args.MaxFeePerGas),
			Gas: uint64(args.Gas), To: *to, Value: value, Data: input,
			AuthList: args.AuthorizationList,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		tx = types.NewTx(inner)
	}
	if err := tx.ValidateIntegerBounds(); err != nil {
		return nil, err
	}
	return tx, nil
}
