// Copyright 2015 The go-ethereum Authors
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

package ethapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/abi"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	//"github.com/cypherium/cypher/accounts/scwallet"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/consensus/clique"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	kzg "github.com/cypherium/cypher/crypto/kzg4844"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"

	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

type TransactionType uint8

const (
	FillTransaction TransactionType = iota + 1
	RawTransaction
	NormalTransaction
)

// PublicEthereumAPI provides an API to access Ethereum related information.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicEthereumAPI struct {
	b Backend
}

// NewPublicEthereumAPI creates a new Ethereum protocol API.
func NewPublicEthereumAPI(b Backend) *PublicEthereumAPI {
	return &PublicEthereumAPI{b}
}

// GasPrice returns a suggestion for a gas price.
func (s *PublicEthereumAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	price := fixedGasPricePerGas()
	return (*hexutil.Big)(price), nil
}

// FeeHistoryResult models the response object for eth_feeHistory.
type FeeHistoryResult struct {
	OldestBlock   *hexutil.Big     `json:"oldestBlock"`
	BaseFeePerGas []*hexutil.Big   `json:"baseFeePerGas"`
	GasUsedRatio  []float64        `json:"gasUsedRatio"`
	Reward        [][]*hexutil.Big `json:"reward,omitempty"`
}

type gasTipCapSuggester interface {
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
}

func fixedBaseFeePerGas() *big.Int {
	return big.NewInt(params.FixedBaseFeePerGas)
}

func fixedGasPricePerGas() *big.Int {
	// Keep public eth_gasPrice stable for normal wallet transfers.
	// Normal transfer fee: 21000 gas * 1 gwei = 0.000021.
	return big.NewInt(params.FixedTransferGasPricePerGas)
}

func fixedMaxPriorityFeePerGas() *big.Int {
	return big.NewInt(params.FixedPriorityFeePerGas)
}

func suggestGasTipCap(ctx context.Context, b Backend) (*big.Int, error) {
	// Fixed-fee policy for MetaMask-compatible RPC:
	// eth_gasPrice stays 1 gwei, and the suggested priority fee is 0.2 gwei.
	// The canonical block baseFeePerGas is handled separately by block/header code.
	return fixedMaxPriorityFeePerGas(), nil
}

// MaxPriorityFeePerGas returns a suggestion for maxPriorityFeePerGas.
func (s *PublicEthereumAPI) MaxPriorityFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	tip, err := suggestGasTipCap(ctx, s.b)
	if err != nil {
		return nil, err
	}
	if tip == nil || tip.Sign() < 0 {
		tip = fixedMaxPriorityFeePerGas()
	}
	return (*hexutil.Big)(tip), nil
}

// FeeHistory returns base fee and gas usage history for recent blocks.
func (s *PublicEthereumAPI) FeeHistory(ctx context.Context, blockCount hexutil.Uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*FeeHistoryResult, error) {
	count := uint64(blockCount)
	if count == 0 {
		return nil, errors.New("blockCount must be greater than 0")
	}
	if count > 1024 {
		return nil, errors.New("blockCount exceeds maximum of 1024")
	}
	for i, p := range rewardPercentiles {
		if p < 0 || p > 100 {
			return nil, errors.New("reward percentile out of range")
		}
		if i > 0 && p < rewardPercentiles[i-1] {
			return nil, errors.New("reward percentiles must be in ascending order")
		}
	}
	endHeader, err := s.b.HeaderByNumber(ctx, lastBlock)
	if err != nil {
		return nil, err
	}
	if endHeader == nil && lastBlock == rpc.PendingBlockNumber {
		endHeader, err = s.b.HeaderByNumber(ctx, rpc.LatestBlockNumber)
		if err != nil {
			return nil, err
		}
	}
	if endHeader == nil {
		return nil, errors.New("last block header not found")
	}
	end := endHeader.Number.Uint64()
	if count > end+1 {
		count = end + 1
	}
	oldest := end + 1 - count
	result := &FeeHistoryResult{
		OldestBlock:   (*hexutil.Big)(new(big.Int).SetUint64(oldest)),
		BaseFeePerGas: make([]*hexutil.Big, count+1),
		GasUsedRatio:  make([]float64, count),
	}
	if len(rewardPercentiles) > 0 {
		result.Reward = make([][]*hexutil.Big, count)
	}
	tipDefault, _ := suggestGasTipCap(ctx, s.b)
	if tipDefault == nil || tipDefault.Sign() < 0 {
		tipDefault = fixedMaxPriorityFeePerGas()
	}
	legacyFallbackPrice := fixedBaseFeePerGas()
	var lastBaseFee *big.Int
	for i := uint64(0); i < count; i++ {
		number := oldest + i
		header, err := s.b.HeaderByNumber(ctx, rpc.BlockNumber(number))
		if err != nil {
			return nil, err
		}
		if header == nil {
			return nil, fmt.Errorf("header %d not found", number)
		}
		baseFee := header.BaseFee
		if baseFee == nil || baseFee.Sign() == 0 {
			baseFee = legacyFallbackPrice
		}
		lastBaseFee = new(big.Int).Set(baseFee)
		result.BaseFeePerGas[i] = (*hexutil.Big)(new(big.Int).Set(baseFee))
		if header.GasLimit > 0 {
			result.GasUsedRatio[i] = float64(header.GasUsed) / float64(header.GasLimit)
		}
		if len(rewardPercentiles) > 0 {
			row := make([]*hexutil.Big, len(rewardPercentiles))
			for j := range rewardPercentiles {
				row[j] = (*hexutil.Big)(new(big.Int).Set(tipDefault))
			}
			result.Reward[i] = row
		}
	}
	if lastBaseFee == nil {
		lastBaseFee = new(big.Int).Set(legacyFallbackPrice)
	}
	result.BaseFeePerGas[count] = (*hexutil.Big)(new(big.Int).Set(lastBaseFee))
	return result, nil
}

// ProtocolVersion returns the current Ethereum protocol version this node supports
func (s *PublicEthereumAPI) ProtocolVersion() hexutil.Uint {
	return hexutil.Uint(s.b.ProtocolVersion())
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up to date or has not
// yet received the latest block headers from its pears. In case it is synchronizing:
// - startingBlock: block number this node started to synchronise from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
func (s *PublicEthereumAPI) Syncing() (interface{}, error) {
	progress := s.b.Downloader().Progress()

	// Return not syncing if the synchronisation already completed
	if progress.CurrentBlock >= progress.HighestBlock {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock": hexutil.Uint64(progress.StartingBlock),
		"currentBlock":  hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":  hexutil.Uint64(progress.HighestBlock),
		"pulledStates":  hexutil.Uint64(progress.PulledStates),
		"knownStates":   hexutil.Uint64(progress.KnownStates),
	}, nil
}

// PublicTxPoolAPI offers and API for the transaction pool. It only operates on data that is non confidential.
type PublicTxPoolAPI struct {
	b Backend
}

// NewPublicTxPoolAPI creates a new tx pool service that gives information about the transaction pool.
func NewPublicTxPoolAPI(b Backend) *PublicTxPoolAPI {
	return &PublicTxPoolAPI{b}
}

// Content returns the transactions contained within the transaction pool.
func (s *PublicTxPoolAPI) Content() map[string]map[string]map[string]*RPCTransaction {
	content := map[string]map[string]map[string]*RPCTransaction{
		"pending": make(map[string]map[string]*RPCTransaction),
		"queued":  make(map[string]map[string]*RPCTransaction),
	}
	pending, queue := s.b.TxPoolContent()

	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = newRPCPendingTransaction(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = newRPCPendingTransaction(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// Status returns the number of pending and queued transaction in the pool.
func (s *PublicTxPoolAPI) Status() map[string]hexutil.Uint {
	pending, queue := s.b.Stats()
	return map[string]hexutil.Uint{
		"pending": hexutil.Uint(pending),
		"queued":  hexutil.Uint(queue),
	}
}

// Inspect retrieves the content of the transaction pool and flattens it into an
// easily inspectable list.
func (s *PublicTxPoolAPI) Inspect() map[string]map[string]map[string]string {
	content := map[string]map[string]map[string]string{
		"pending": make(map[string]map[string]string),
		"queued":  make(map[string]map[string]string),
	}
	pending, queue := s.b.TxPoolContent()

	// Define a formatter to flatten a transaction into a string
	var format = func(tx *types.Transaction) string {
		if to := tx.To(); to != nil {
			return fmt.Sprintf("%s: %v wei + %v gas × %v wei", tx.To().Hex(), tx.Value(), tx.Gas(), tx.GasPrice())
		}
		return fmt.Sprintf("contract creation: %v wei + %v gas × %v wei", tx.Value(), tx.Gas(), tx.GasPrice())
	}
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// PublicAccountAPI provides an API to access accounts managed by this node.
// It offers only methods that can retrieve accounts.
type PublicAccountAPI struct {
	am *accounts.Manager
}

// NewPublicAccountAPI creates a new PublicAccountAPI.
func NewPublicAccountAPI(am *accounts.Manager) *PublicAccountAPI {
	return &PublicAccountAPI{am: am}
}

// Accounts returns the collection of accounts this node manages
func (s *PublicAccountAPI) Accounts() []common.Address {
	return s.am.Accounts()
}

// PrivateAccountAPI provides an API to access accounts managed by this node.
// It offers methods to create, (un)lock en list accounts. Some methods accept
// passwords and are therefore considered private by default.
type PrivateAccountAPI struct {
	am        *accounts.Manager
	nonceLock *AddrLocker
	b         Backend
}

// NewPrivateAccountAPI create a new PrivateAccountAPI.
func NewPrivateAccountAPI(b Backend, nonceLock *AddrLocker) *PrivateAccountAPI {
	return &PrivateAccountAPI{
		am:        b.AccountManager(),
		nonceLock: nonceLock,
		b:         b,
	}
}

// listAccounts will return a list of addresses for accounts this node manages.
func (s *PrivateAccountAPI) ListAccounts() []common.Address {
	return s.am.Accounts()
}

// rawWallet is a JSON representation of an accounts.Wallet interface, with its
// data contents extracted into plain fields.
type rawWallet struct {
	URL      string             `json:"url"`
	Status   string             `json:"status"`
	Failure  string             `json:"failure,omitempty"`
	Accounts []accounts.Account `json:"accounts,omitempty"`
}

// ListWallets will return a list of wallets this node manages.
func (s *PrivateAccountAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		status, failure := wallet.Status()

		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}

// OpenWallet initiates a hardware wallet opening procedure, establishing a USB
// connection and attempting to authenticate via the provided passphrase. Note,
// the method may return an extra challenge requiring a second open (e.g. the
// Trezor PIN matrix challenge).
func (s *PrivateAccountAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}

// DeriveAccount requests a HD wallet to derive a new account, optionally pinning
// it for later reuse.
func (s *PrivateAccountAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}

// NewAccount will create a new account and returns the address for the new account.
func (s *PrivateAccountAPI) NewAccount(password string) (common.Address, error) {
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := ks.NewAccount(password)
	if err == nil {
		log.Info("Your new key was generated", "address", acc.Address)
		log.Warn("Please backup your key file!", "path", acc.URL.Path)
		log.Warn("Please remember your password!")
		return acc.Address, nil
	}
	return common.Address{}, err
}

// NewAccountEd25519 will create a new account and returns the address for the new account.
func (s *PrivateAccountAPI) NewAccountEd25519(password string) (common.Address, error) {
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := ks.NewAccount25519(password)
	if err == nil {
		log.Info("Your new key was generated", "address", acc.Address)
		log.Warn("Please backup your key file!", "path", acc.URL.Path)
		log.Warn("Please remember your password!")
		return acc.Address, nil
	}
	return common.Address{}, err
}

// fetchKeystore retrieves the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager) (*keystore.KeyStore, error) {
	if ks := am.Backends(keystore.KeyStoreType); len(ks) > 0 {
		return ks[0].(*keystore.KeyStore), nil
	}
	return nil, errors.New("local keystore not used")
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
func (s *PrivateAccountAPI) ImportRawKey(privkey string, password string) (common.Address, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return common.Address{}, err
	}
	ks, err := fetchKeystore(s.am)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := ks.ImportECDSA(key, password)
	return acc.Address, err
}

// UnlockAccount will unlock the account associated with the given address with
// the given password for duration seconds. If duration is nil it will use a
// default of 300 seconds. It returns an indication if the account was unlocked.
func (s *PrivateAccountAPI) UnlockAccount(ctx context.Context, addr common.Address, password string, duration *uint64) (bool, error) {
	// When the API is exposed by external RPC(http, ws etc), unless the user
	// explicitly specifies to allow the insecure account unlocking, otherwise
	// it is disabled.
	if s.b.ExtRPCEnabled() && !s.b.AccountManager().Config().InsecureUnlockAllowed {
		return false, errors.New("account unlock with HTTP access is forbidden")
	}

	const max = uint64(time.Duration(math.MaxInt64) / time.Second)
	var d time.Duration
	if duration == nil {
		d = 300 * time.Second
	} else if *duration > max {
		return false, errors.New("unlock duration too large")
	} else {
		d = time.Duration(*duration) * time.Second
	}
	err := s.unlockAccount(addr, password, d)
	if err != nil {
		log.Warn("Failed account unlock attempt", "address", addr, "err", err)
	}
	return err == nil, err
}

func (s *PrivateAccountAPI) unlockAccount(addr common.Address, password string, duration time.Duration) error {
	acct := accounts.Account{Address: addr}

	backend, err := s.am.Backend(acct)
	if err != nil {
		return err
	}

	switch b := backend.(type) {
	//??	case *pluggable.Backend:
	//??		return b.TimedUnlock(acct, password, duration)
	case *keystore.KeyStore:
		return b.TimedUnlock(acct, password, duration)
	default:
		return errors.New("unlock only supported for keystore or plugin wallets")
	}
}

// LockAccount will lock the account associated with the given address when it's unlocked.
func (s *PrivateAccountAPI) LockAccount(addr common.Address) bool {
	if err := s.lockAccount(addr); err != nil {
		log.Warn("Failed account lock attempt", "address", addr, "err", err)
		return false
	}

	return true
}

func (s *PrivateAccountAPI) lockAccount(addr common.Address) error {
	acct := accounts.Account{Address: addr}

	backend, err := s.am.Backend(acct)
	if err != nil {
		return err
	}

	switch b := backend.(type) {
	//??	case *pluggable.Backend:
	//??		return b.Lock(acct)
	case *keystore.KeyStore:
		return b.Lock(addr)
	default:
		return errors.New("lock only supported for keystore or plugin wallets")
	}
}

// signTransaction sets defaults and signs the given transaction
// NOTE: the caller needs to ensure that the nonceLock is held, if applicable,
// and release it after the transaction has been submitted to the tx pool
func (s *PrivateAccountAPI) signTransaction(ctx context.Context, args *SendTxArgs, passwd string) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.am.Find(account)
	if err != nil {
		return nil, err
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Assemble the transaction and sign with the wallet
	chainID := args.transactionChainID(s.b)
	tx := args.toTransaction(chainID)

	return wallet.SignTxWithPassphrase(account, passwd, tx, chainID)
}

// SendTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.To. If the given passwd isn't
// able to decrypt the key it fails.
func (s *PrivateAccountAPI) SendTransaction(ctx context.Context, args SendTxArgs, passwd string) (common.Hash, error) {
	if !args.requestsNativeTransaction(s.b) && args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	signed, err := s.signTransaction(ctx, &args, passwd)
	if err != nil {
		log.Warn("Failed transaction send attempt", "from", args.From, "to", args.To, "value", args.Value.ToInt(), "err", err)
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed, true)
}

// SignTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.To. If the given passwd isn't
// able to decrypt the key it fails. The transaction is returned in RLP-form, not broadcast
// to other nodes
func (s *PrivateAccountAPI) SignTransaction(ctx context.Context, args SendTxArgs, passwd string) (*SignTransactionResult, error) {
	// No need to obtain the noncelock mutex, since we won't be sending this
	// tx into the transaction pool, but right back to the user
	if !args.requestsNativeTransaction(s.b) && args.Gas == nil {
		return nil, fmt.Errorf("gas not specified")
	}
	if !args.requestsNativeTransaction(s.b) && args.Nonce == nil {
		return nil, fmt.Errorf("nonce not specified")
	}
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Before actually sign the transaction, ensure the transaction fee is reasonable.
	if err := checkTxFeeWithBlob(args.txFeeCapForValidation(), args.feeWorkForValidation(), args.blobFeeCapForValidation(), args.blobGasForFeeValidation(), s.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	signed, err := s.signTransaction(ctx, &args, passwd)
	if err != nil {
		log.Warn("Failed transaction sign attempt", "from", args.From, "to", args.To, "value", args.Value.ToInt(), "err", err)
		return nil, err
	}
	data, err := marshalTransactionForRPC(signed)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// Sign calculates an Ethereum ECDSA signature for:
// keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The key used to calculate the signature is decrypted with the given password.
//
// https://github.com/cypherium/cypher/wiki/Management-APIs#personal_sign
func (s *PrivateAccountAPI) Sign(ctx context.Context, data hexutil.Bytes, addr common.Address, passwd string) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Assemble sign the data with the wallet
	signature, err := wallet.SignTextWithPassphrase(account, passwd, data)
	if err != nil {
		log.Warn("Failed data sign attempt", "address", addr, "err", err)
		return nil, err
	}
	signature[crypto.RecoveryIDOffset] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return signature, nil
}

// EcRecover returns the address for the account that was used to create the signature.
// Note, this function is compatible with eth_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19Ethereum Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be 27 or 28 for legacy reasons.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#personal_ecRecover
func (s *PrivateAccountAPI) EcRecover(ctx context.Context, data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("signature must be %d bytes long", crypto.SignatureLength)
	}
	if sig[crypto.RecoveryIDOffset] != 27 && sig[crypto.RecoveryIDOffset] != 28 {
		return common.Address{}, fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.SigToPub(accounts.TextHash(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

// SignAndSendTransaction was renamed to SendTransaction. This method is deprecated
// and will be removed in the future. It primary goal is to give clients time to update.
func (s *PrivateAccountAPI) SignAndSendTransaction(ctx context.Context, args SendTxArgs, passwd string) (common.Hash, error) {
	return s.SendTransaction(ctx, args, passwd)
}

func (s *PrivateAccountAPI) UnlockAll(ctx context.Context, password string, duration *uint64) (bool, error) {
	for _, wallet := range s.am.Wallets() {
		for _, account := range wallet.Accounts() {
			b, err := s.UnlockAccount(ctx, account.Address, password, duration)
			if err != nil {
				return b, err
			}
		}
	}
	return true, nil
}

/*??
// InitializeWallet initializes a new wallet at the provided URL, by generating and returning a new private key.
func (s *PrivateAccountAPI) InitializeWallet(ctx context.Context, url string) (string, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return "", err
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	seed := bip39.NewSeed(mnemonic, "")

	switch wallet := wallet.(type) {
	//?? case *scwallet.Wallet:
	//??	return mnemonic, wallet.Initialize(seed)
	default:
		return "", fmt.Errorf("specified wallet does not support initialization")
	}
}
// Unpair deletes a pairing between wallet and cypher.
func (s *PrivateAccountAPI) Unpair(ctx context.Context, url string, pin string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}

	switch wallet := wallet.(type) {
	 case *scwallet.Wallet:
		return wallet.Unpair([]byte(pin))
	default:
		return fmt.Errorf("specified wallet does not support pairing")
	}
}
*/

// PublicBlockChainAPI provides an API to access the Ethereum blockchain.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicBlockChainAPI struct {
	b Backend
}

// NewPublicBlockChainAPI creates a new Ethereum blockchain API.
func NewPublicBlockChainAPI(b Backend) *PublicBlockChainAPI {
	return &PublicBlockChainAPI{b}
}

// ChainId returns the chainID value for transaction replay protection.
func (s *PublicBlockChainAPI) ChainId() *hexutil.Big {
	return (*hexutil.Big)(s.b.ChainConfig().ChainID)
}

// BlockNumber returns the block number of the chain head.
func (s *PublicBlockChainAPI) BlockNumber() hexutil.Uint64 {
	header, _ := s.b.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return hexutil.Uint64(header.Number.Uint64())
}

func (s *PublicBlockChainAPI) KeyBlockNumber() hexutil.Uint64 {
	keyblock := s.b.GetKeyBlockChain().CurrentBlock()
	return hexutil.Uint64(keyblock.NumberU64())
}

func (s *PublicBlockChainAPI) RescueCommittee(args bftview.RescueCommitteeArgs) (bool, error) {
	committee, keyBlockHash, err := s.b.RescueCommittee(args.ConfigPath)
	if err != nil {
		return false, err
	}
	if (keyBlockHash == common.Hash{}) {
		return false, errors.New("key block hash is empty (invalid config)")
	}
	keyblock := s.b.GetKeyBlockChain().GetBlockByHash(keyBlockHash)
	bftview.SetRescueMode(keyblock.NumberU64(), keyblock.Hash(), committee)
	return true, nil
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (s *PublicBlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	return (*hexutil.Big)(state.GetBalance(address)), state.Error()
}

// Result structs for GetProof
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}
type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
func (s *PublicBlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	storageTrie := state.StorageTrie(address)
	storageHash := types.EmptyRootHash
	codeHash := state.GetCodeHash(address)
	storageProof := make([]StorageResult, len(storageKeys))

	// if we have a storageTrie, (which means the account exists), we can update the storagehash
	if storageTrie != nil {
		storageHash = storageTrie.Hash()
	} else {
		// no storageTrie means the account does not exist, so the codeHash is the hash of an empty bytearray.
		codeHash = crypto.Keccak256Hash(nil)
	}

	// create the proof for the storageKeys
	for i, key := range storageKeys {
		if storageTrie != nil {
			proof, storageError := state.GetStorageProof(address, common.HexToHash(key))
			if storageError != nil {
				return nil, storageError
			}
			storageProof[i] = StorageResult{key, (*hexutil.Big)(state.GetState(address, common.HexToHash(key)).Big()), common.ToHexArray(proof)}
		} else {
			storageProof[i] = StorageResult{key, &hexutil.Big{}, []string{}}
		}
	}

	// create the accountProof
	accountProof, proofErr := state.GetProof(address)
	if proofErr != nil {
		return nil, proofErr
	}

	return &AccountResult{
		Address:      address,
		AccountProof: common.ToHexArray(accountProof),
		Balance:      (*hexutil.Big)(state.GetBalance(address)),
		CodeHash:     codeHash,
		Nonce:        hexutil.Uint64(state.GetNonce(address)),
		StorageHash:  storageHash,
		StorageProof: storageProof,
	}, state.Error()
}

// GetHeaderByNumber returns the requested canonical block header.
// * When blockNr is -1 the chain head is returned.
// * When blockNr is -2 the pending chain head is returned.
func (s *PublicBlockChainAPI) GetHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (map[string]interface{}, error) {
	header, err := s.b.HeaderByNumber(ctx, number)
	if header != nil && err == nil {
		response := s.rpcMarshalHeader(ctx, header)
		if number == rpc.PendingBlockNumber {
			// Pending header need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetHeaderByHash returns the requested header by hash.
func (s *PublicBlockChainAPI) GetHeaderByHash(ctx context.Context, hash common.Hash) map[string]interface{} {
	header, _ := s.b.HeaderByHash(ctx, hash)
	if header != nil {
		return s.rpcMarshalHeader(ctx, header)
	}
	return nil
}

// GetBlockByNumber returns the requested canonical block.
//   - When blockNr is -1 the chain head is returned.
//   - When blockNr is -2 the pending chain head is returned.
//   - When fullTx is true all transactions in the block are returned, otherwise
//     only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, number)
	if block != nil && err == nil {
		response, err := s.rpcMarshalBlock(ctx, block, true, fullTx)
		if err == nil && number == rpc.PendingBlockNumber {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByHash(ctx, hash)
	if block != nil {
		return s.rpcMarshalBlock(ctx, block, true, fullTx)
	}
	return nil, err
}

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index. When fullTx is true
// all transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", blockNr, "hash", block.Hash(), "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcMarshalBlock(ctx, block, false, false)
	}
	return nil, err
}

func (s *PublicBlockChainAPI) GetKeyBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (map[string]interface{}, error) {
	kbc := s.b.GetKeyBlockChain()
	var keyblock *types.KeyBlock
	if blockNr == rpc.LatestBlockNumber {
		keyblock = kbc.CurrentBlock()
	} else {
		keyblock = kbc.GetBlockByNumber(uint64(blockNr))
	}
	if keyblock != nil {
		response, err := s.rpcOutputKeyBlock(keyblock)
		return response, err
	}
	return nil, types.ErrNotFindBlock
}

func (s *PublicBlockChainAPI) GetKeyBlockByHash(ctx context.Context, blockHash common.Hash) (map[string]interface{}, error) {
	keyblock := s.b.GetKeyBlockChain().GetBlockByHash(blockHash)
	if keyblock != nil {
		response, err := s.rpcOutputKeyBlock(keyblock)
		return response, err
	}
	return nil, types.ErrNotFindBlock
}

func (s *PublicBlockChainAPI) GetKeyBlocksByNumbers(ctx context.Context, blockNrs []int64) ([]interface{}, error) {
	response := make([]interface{}, 0, len(blockNrs))

	for _, blockNr := range blockNrs {
		//log.Debug("GetKeyBlocksByNumbers", "block", blockNr)

		block, _ := s.b.KeyBlockByNumber(ctx, rpc.BlockNumber(blockNr))
		if block != nil {
			//log.Debug("GetKeyBlocksByNumbers blockbynumber", "hash", block.Hash().Hex())
			rpcBlock, err := s.rpcOutputKeyBlock(block)
			if err != nil {
				//log.Debug("GetKeyBlocksByNumbers rpcOutputKeyBlock error ", "error", err)
				continue
			}
			response = append(response, rpcBlock)
		}
	}

	return response, nil
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index. When fullTx is true
// all transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.BlockByHash(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", block.Number(), "hash", blockHash, "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcMarshalBlock(ctx, block, false, false)
	}
	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
func (s *PublicBlockChainAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
func (s *PublicBlockChainAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}
func (s *PublicBlockChainAPI) GetCommitteeMember(ctx context.Context, blockNr rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	committeeMembers, err := s.b.CommitteeMembers(ctx, blockNr)
	if committeeMembers != nil {
		return nil, err
	}
	return nil, err
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (s *PublicBlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (s *PublicBlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, key string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	res := state.GetState(address, common.HexToHash(key))
	return res[:], state.Error()
}

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From                 *common.Address              `json:"from"`
	To                   *common.Address              `json:"to"`
	Gas                  *hexutil.Uint64              `json:"gas"`
	GasPrice             *hexutil.Big                 `json:"gasPrice"`
	MaxFeePerGas         *hexutil.Big                 `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big                 `json:"maxPriorityFeePerGas"`
	Value                *hexutil.Big                 `json:"value"`
	Nonce                *hexutil.Uint64              `json:"nonce"`
	Data                 *hexutil.Bytes               `json:"data"`
	Input                *hexutil.Bytes               `json:"input"`
	AccessList           *types.AccessList            `json:"accessList"`
	ChainID              *hexutil.Big                 `json:"chainId"`
	MaxFeePerBlobGas     *hexutil.Big                 `json:"maxFeePerBlobGas"`
	BlobVersionedHashes  []common.Hash                `json:"blobVersionedHashes"`
	AuthorizationList    []types.SetCodeAuthorization `json:"authorizationList"`
}

func (args *CallArgs) callData() []byte {
	if args.Input != nil {
		return *args.Input
	}
	if args.Data != nil {
		return *args.Data
	}
	return nil
}

// validateCallArgs rejects ambiguous call objects instead of silently
// simulating a different EVM envelope than the wallet supplied.
func (args *CallArgs) validateCallArgs(b Backend) error {
	if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
		return errors.New(`both "data" and "input" are set and not equal. Please use "input" to pass transaction call data`)
	}
	if args.GasPrice != nil && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil) {
		return errors.New(`both "gasPrice" and EIP-1559 fee fields are set`)
	}
	if args.GasPrice != nil && args.AuthorizationList != nil {
		return errors.New(`both "gasPrice" and "authorizationList" are set`)
	}
	if args.ChainID != nil {
		if b == nil || b.ChainConfig() == nil || b.ChainConfig().ChainID == nil {
			return errors.New("chainId cannot be validated because the node chain ID is unavailable")
		}
		have, want := args.ChainID.ToInt(), b.ChainConfig().ChainID
		if have.Cmp(want) != 0 {
			return fmt.Errorf("chainId does not match node's (have=%v, want=%v)", have, want)
		}
	}
	return nil
}

// ToMessage converts CallArgs to the Message type used by the core evm
func (args *CallArgs) ToMessage(globalGasCap uint64) types.Message {
	// Set sender address or use zero address if none specified.
	var addr common.Address
	if args.From != nil {
		addr = *args.From
	}

	// Set default gas & gas price if none were set
	gas := globalGasCap
	if gas == 0 {
		gas = uint64(math.MaxUint64 / 2)
	}
	if args.Gas != nil {
		gas = uint64(*args.Gas)
	}
	if globalGasCap != 0 && globalGasCap < gas {
		log.Warn("Caller gas above allowance, capping", "requested", gas, "cap", globalGasCap)
		gas = globalGasCap
	}
	gasPrice := new(big.Int)
	if args.GasPrice != nil {
		gasPrice = args.GasPrice.ToInt()
	}
	gasFeeCap := gasPrice
	if args.MaxFeePerGas != nil {
		gasFeeCap = args.MaxFeePerGas.ToInt()
	}
	gasTipCap := gasPrice
	if args.MaxPriorityFeePerGas != nil {
		gasTipCap = args.MaxPriorityFeePerGas.ToInt()
	} else if args.MaxFeePerGas != nil {
		gasTipCap = args.MaxFeePerGas.ToInt()
	}
	if args.GasPrice == nil {
		gasPrice = gasFeeCap
	}

	value := new(big.Int)
	if args.Value != nil {
		value = args.Value.ToInt()
	}

	data := args.callData()

	var accessList types.AccessList
	if args.AccessList != nil {
		accessList = *args.AccessList
	}
	var blobFeeCap *big.Int
	if args.MaxFeePerBlobGas != nil {
		blobFeeCap = args.MaxFeePerBlobGas.ToInt()
	}
	txType := uint8(types.LegacyTxType)
	switch {
	case len(args.AuthorizationList) > 0:
		txType = types.SetCodeTxType
	case args.MaxFeePerBlobGas != nil || len(args.BlobVersionedHashes) > 0:
		txType = types.BlobTxType
	case args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil:
		txType = types.DynamicFeeTxType
	case args.AccessList != nil:
		txType = types.AccessListTxType
	}
	var nonce uint64
	if args.Nonce != nil {
		nonce = uint64(*args.Nonce)
	}
	msg := types.NewMessageWithModernFields(txType, addr, args.To, nonce, value, gas, gasPrice, gasFeeCap, gasTipCap, blobFeeCap, data, accessList, args.BlobVersionedHashes, args.AuthorizationList, false)
	return msg
}

// account indicates the overriding fields of account during the execution of
// a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if statDiff is set, all diff will be applied first and then execute the call
// message.
type account struct {
	Nonce     *hexutil.Uint64              `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

func DoCall(ctx context.Context, b Backend, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides map[common.Address]account, vmCfg vm.Config, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())
	if err := args.validateCallArgs(b); err != nil {
		return nil, err
	}

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	// Override the fields of specified contracts before execution.
	for addr, account := range overrides {
		// Override account nonce.
		if account.Nonce != nil {
			state.SetNonce(addr, uint64(*account.Nonce))
		}
		// Override account(contract) code.
		if account.Code != nil {
			state.SetCode(addr, *account.Code)
		}
		// Override account balance.
		if account.Balance != nil {
			state.SetBalance(addr, (*big.Int)(*account.Balance))
		}
		if account.State != nil && account.StateDiff != nil {
			return nil, fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
		}
		// Replace entire state if caller requires.
		if account.State != nil {
			state.SetStorage(addr, *account.State)
		}
		// Apply state diff into specified accounts.
		if account.StateDiff != nil {
			for key, value := range *account.StateDiff {
				state.SetState(addr, key, value)
			}
		}
	}
	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	msg := args.ToMessage(globalGasCap)
	evm, vmError, err := b.GetEVM(ctx, msg, state, header)
	if err != nil {
		return nil, err
	}
	// eth_call/estimateGas messages default to a zero gas price. Lower the
	// execution base fees as well, otherwise the London fee-cap invariant
	// (feeCap >= baseFee) rejects an otherwise valid simulation before the EVM
	// runs. This mirrors geth's NoBaseFee call semantics and also makes BASEFEE
	// and BLOBBASEFEE return zero for an unpriced simulation.
	lowerUnpricedCallFees(evm, msg)
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	result, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return nil, err
	}
	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.Gas())
	}
	return result, nil
}

func lowerUnpricedCallFees(evm *vm.EVM, msg core.Message) {
	if evm != nil && msg != nil && msg.GasPrice().Sign() == 0 {
		evm.Context.BaseFee = new(big.Int)
		evm.Context.BlobBaseFee = new(big.Int)
	}
}

func newRevertError(result *core.ExecutionResult) *revertError {
	reason, errUnpack := abi.UnpackRevert(result.Revert())
	err := errors.New("execution reverted")
	if errUnpack == nil {
		err = fmt.Errorf("execution reverted: %v", reason)
	}
	return &revertError{
		error:  err,
		reason: hexutil.Encode(result.Revert()),
	}
}

// revertError is an API error that encompassas an EVM revertal with JSON error
// code and a binary data blob.
type revertError struct {
	error
	reason string // revert reason hex encoded
}

// ErrorCode returns the JSON error code for a revertal.
// See: https://github.com/ethereum/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
func (e *revertError) ErrorCode() int {
	return 3
}

// ErrorData returns the hex encoded revert reason.
func (e *revertError) ErrorData() interface{} {
	return e.reason
}

// Call executes the given transaction on the state for the given block number.
//
// Additionally, the caller can specify a batch of contract for fields overriding.
//
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
// - replaced the default 5s time out with the value passed in vm.calltimeout
// - multi tenancy verification
func (s *PublicBlockChainAPI) Call(ctx context.Context, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *map[common.Address]account) (hexutil.Bytes, error) {
	var accounts map[common.Address]account
	if overrides != nil {
		accounts = *overrides
	}

	result, err := DoCall(ctx, s.b, args, blockNrOrHash, accounts, vm.Config{}, s.b.CallTimeOut(), s.b.RPCGasCap())
	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result)
	}
	return result.Return(), result.Err
}

func hasCallData(data *hexutil.Bytes) bool {
	return data != nil && len(*data) > 0
}

func hasAccessList(accessList *types.AccessList) bool {
	return accessList != nil && len(*accessList) > 0
}

func hasModernExecutionFields(blobFeeCap *hexutil.Big, blobHashes []common.Hash, authList []types.SetCodeAuthorization) bool {
	return blobFeeCap != nil || len(blobHashes) > 0 || len(authList) > 0
}

func isActivePrecompile(b Backend, header *types.Header, address common.Address) bool {
	if header == nil {
		header = b.CurrentHeader()
	}
	config := b.ChainConfig()
	if config == nil || header == nil || header.Number == nil {
		return false
	}
	return vm.IsPrecompiledContract(address, config.CypheriumRules(header.Number, header.Time))
}

func isPlainValueTransferCall(ctx context.Context, b Backend, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash) (bool, error) {
	if args.To == nil {
		return false, nil
	}
	if hasCallData(args.Data) || hasCallData(args.Input) || hasAccessList(args.AccessList) ||
		hasModernExecutionFields(args.MaxFeePerBlobGas, args.BlobVersionedHashes, args.AuthorizationList) {
		return false, nil
	}
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return false, err
	}
	if isActivePrecompile(b, header, *args.To) || len(state.GetCode(*args.To)) > 0 {
		return false, nil
	}
	return true, nil
}

func isPlainValueTransferSendTx(ctx context.Context, b Backend, args *SendTxArgs, blockNrOrHash rpc.BlockNumberOrHash) (bool, error) {
	if args == nil {
		return false, nil
	}
	if args.To == nil {
		return false, nil
	}
	if hasCallData(args.Data) || hasCallData(args.Input) || hasAccessList(args.AccessList) ||
		hasModernExecutionFields(args.MaxFeePerBlobGas, args.BlobVersionedHashes, args.AuthorizationList) || args.hasBlobSidecarFields() {
		return false, nil
	}
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return false, err
	}
	if isActivePrecompile(b, header, *args.To) || len(state.GetCode(*args.To)) > 0 {
		return false, nil
	}
	return true, nil
}

func DoEstimateGas(ctx context.Context, b Backend, args CallArgs, blockNrOrHash rpc.BlockNumberOrHash, gasCap uint64) (hexutil.Uint64, error) {
	if err := args.validateCallArgs(b); err != nil {
		return 0, err
	}
	// Binary search the gas requirement, as it may be higher than the amount used
	var (
		lo  uint64 = params.TxGas - 1
		hi  uint64
		cap uint64
	)
	// Use zero address if sender unspecified.
	if args.From == nil {
		args.From = new(common.Address)
	}

	// Keep normal EOA-to-EOA native coin transfers fixed at 21000 gas regardless of txpool load.
	// Contract calls, contract creation, data transactions, and access-list transactions still use
	// the regular EVM binary-search estimator below.
	plainValueTransfer, err := isPlainValueTransferCall(ctx, b, args, blockNrOrHash)
	if err != nil {
		return 0, err
	}
	if plainValueTransfer {
		return hexutil.Uint64(params.TxGas), nil
	}

	// Determine the highest gas limit can be used during the estimation.
	if args.Gas != nil && uint64(*args.Gas) >= params.TxGas {
		hi = uint64(*args.Gas)
	} else {
		// Retrieve the block to act as the gas ceiling
		block, err := b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return 0, err
		}
		hi = block.GasLimit()
	}
	// Recap the highest gas allowance with the account's available balance.
	// Dynamic-fee transactions reserve the fee cap during pre-check, so use the
	// same cap here instead of treating a nil legacy gasPrice as unlimited.
	feeCap := args.GasPrice
	if args.MaxFeePerGas != nil {
		feeCap = args.MaxFeePerGas
	}
	if feeCap != nil && feeCap.ToInt().BitLen() != 0 {
		state, _, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return 0, err
		}
		balance := state.GetBalance(*args.From) // from can't be nil
		available := new(big.Int).Set(balance)
		if args.Value != nil {
			if args.Value.ToInt().Cmp(available) >= 0 {
				return 0, errors.New("insufficient funds for transfer")
			}
			available.Sub(available, args.Value.ToInt())
		}
		if args.MaxFeePerBlobGas != nil && len(args.BlobVersionedHashes) > 0 {
			blobGas := new(big.Int).Mul(
				new(big.Int).SetUint64(params.BlobTxBlobGasPerBlob),
				new(big.Int).SetUint64(uint64(len(args.BlobVersionedHashes))),
			)
			blobCost := blobGas.Mul(blobGas, args.MaxFeePerBlobGas.ToInt())
			if blobCost.Cmp(available) >= 0 {
				return 0, errors.New("insufficient funds for blob fee")
			}
			available.Sub(available, blobCost)
		}
		allowance := new(big.Int).Div(available, feeCap.ToInt())

		// If the allowance is larger than maximum uint64, skip checking
		if allowance.IsUint64() && hi > allowance.Uint64() {
			transfer := args.Value
			if transfer == nil {
				transfer = new(hexutil.Big)
			}
			log.Warn("Gas estimation capped by limited funds", "original", hi, "balance", balance,
				"sent", transfer.ToInt(), "gasprice", feeCap.ToInt(), "fundable", allowance)
			hi = allowance.Uint64()
		}
	}
	// Recap the highest gas allowance with specified gascap.
	if gasCap != 0 && hi > gasCap {
		log.Warn("Caller gas above allowance, capping", "requested", hi, "cap", gasCap)
		hi = gasCap
	}
	cap = hi

	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(gas uint64) (bool, *core.ExecutionResult, error) {
		args.Gas = (*hexutil.Uint64)(&gas)

		result, err := DoCall(ctx, b, args, blockNrOrHash, nil, vm.Config{}, 0, gasCap)
		if err != nil {
			if errors.Is(err, core.ErrIntrinsicGas) {
				return true, nil, nil // Special case, raise gas limit
			}
			return true, nil, err // Bail out
		}
		return result.Failed(), result, nil
	}
	// Execute the binary search and hone in on an executable gas limit
	for lo+1 < hi {
		mid := (hi + lo) / 2
		failed, _, err := executable(mid)

		// If the error is not nil(consensus error), it means the provided message
		// call or transaction will never be accepted no matter how much gas it is
		// assigned. Return the error directly, don't struggle any more.
		if err != nil {
			return 0, err
		}
		if failed {
			lo = mid
		} else {
			hi = mid
		}
	}
	// Reject the transaction as invalid if it still fails at the highest allowance
	if hi == cap {
		failed, result, err := executable(hi)
		if err != nil {
			return 0, err
		}
		if failed {
			if result != nil && result.Err != vm.ErrOutOfGas {
				if len(result.Revert()) > 0 {
					return 0, newRevertError(result)
				}
				return 0, result.Err
			}
			// Otherwise, the specified gas cap is too low
			return 0, fmt.Errorf("gas required exceeds allowance (%d)", cap)
		}
	}
	return hexutil.Uint64(hi), nil
}

// EstimateGas returns an estimate of the amount of gas needed to execute the
// given transaction against the current pending block.
func (s *PublicBlockChainAPI) EstimateGas(ctx context.Context, args CallArgs) (hexutil.Uint64, error) {
	blockNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	return DoEstimateGas(ctx, s.b, args, blockNrOrHash, s.b.RPCGasCap())
}

// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a transaction in debug mode as well as transaction
// execution status, the amount of gas used and the return value
type ExecutionResult struct {
	Gas         uint64         `json:"gas"`
	Failed      bool           `json:"failed"`
	ReturnValue string         `json:"returnValue"`
	StructLogs  []StructLogRes `json:"structLogs"`
}

// StructLogRes stores a structured log emitted by the EVM while replaying a
// transaction in debug mode
type StructLogRes struct {
	Pc      uint64             `json:"pc"`
	Op      string             `json:"op"`
	Gas     uint64             `json:"gas"`
	GasCost uint64             `json:"gasCost"`
	Depth   int                `json:"depth"`
	Error   error              `json:"error,omitempty"`
	Stack   *[]string          `json:"stack,omitempty"`
	Memory  *[]string          `json:"memory,omitempty"`
	Storage *map[string]string `json:"storage,omitempty"`
}

// FormatLogs formats EVM returned structured logs for json output
func FormatLogs(logs []vm.StructLog) []StructLogRes {
	formatted := make([]StructLogRes, len(logs))
	for index, trace := range logs {
		formatted[index] = StructLogRes{
			Pc:      trace.Pc,
			Op:      trace.Op.String(),
			Gas:     trace.Gas,
			GasCost: trace.GasCost,
			Depth:   trace.Depth,
			Error:   trace.Err,
		}
		if trace.Stack != nil {
			stack := make([]string, len(trace.Stack))
			for i, stackValue := range trace.Stack {
				stack[i] = fmt.Sprintf("%x", math.PaddedBigBytes(stackValue, 32))
			}
			formatted[index].Stack = &stack
		}
		if trace.Memory != nil {
			memory := make([]string, 0, (len(trace.Memory)+31)/32)
			for i := 0; i+32 <= len(trace.Memory); i += 32 {
				memory = append(memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
			}
			formatted[index].Memory = &memory
		}
		if trace.Storage != nil {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
			}
			formatted[index].Storage = &storage
		}
	}
	return formatted
}

// RPCMarshalHeader converts the given header to the RPC output .
func RPCMarshalHeader(head *types.Header) map[string]interface{} {
	baseFee := head.BaseFee
	if baseFee == nil || baseFee.Sign() == 0 {
		baseFee = fixedBaseFeePerGas()
	}
	result := map[string]interface{}{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"extraData":        hexutil.Bytes(head.Extra),
		"size":             hexutil.Uint64(head.Size()),
		"gasLimit":         hexutil.Uint64(head.GasLimit),
		"gasUsed":          hexutil.Uint64(head.GasUsed),
		"timestamp":        hexutil.Uint64(head.Time),
		"baseFeePerGas":    (*hexutil.Big)(baseFee),
		"blockType":        head.BlockType,
		"keyHash":          head.KeyHash,
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}
	result["withdrawalsRoot"] = head.WithdrawalsHash
	result["blobGasUsed"] = hexutil.Uint64(head.BlobGasUsed)
	result["excessBlobGas"] = hexutil.Uint64(head.ExcessBlobGas)
	result["parentBeaconBlockRoot"] = head.ParentBeaconRoot
	result["requestsHash"] = head.RequestsHash
	return result
}

// RPCMarshalBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
func RPCMarshalBlock(block *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields := RPCMarshalHeader(block.Header())
	fields["size"] = hexutil.Uint64(block.Size())

	if inclTx {
		formatTx := func(tx *types.Transaction) (interface{}, error) {
			return tx.Hash(), nil
		}
		if fullTx {
			formatTx = func(tx *types.Transaction) (interface{}, error) {
				return newRPCTransactionFromBlockHash(block, tx.Hash()), nil
			}
		}
		txs := block.Transactions()
		transactions := make([]interface{}, len(txs))
		var err error
		for i, tx := range txs {
			if transactions[i], err = formatTx(tx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}
	uncles := block.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes

	return fields, nil
}

// rpcMarshalHeader uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *PublicBlockChainAPI) rpcMarshalHeader(ctx context.Context, header *types.Header) map[string]interface{} {
	fields := RPCMarshalHeader(header)
	fields["totalDifficulty"] = (*hexutil.Big)(s.b.GetTd(ctx, header.Hash()))
	return fields
}

// rpcMarshalBlock uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *PublicBlockChainAPI) rpcMarshalBlock(ctx context.Context, b *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields, err := RPCMarshalBlock(b, inclTx, fullTx)
	if err != nil {
		return nil, err
	}
	if keyblock, keyErr := s.b.KeyBlockByHash(ctx, b.KeyHash()); keyErr == nil && keyblock != nil {
		fields["miner"] = common.HexToAddress(keyblock.OutAddress(1))
	}
	if inclTx {
		fields["totalDifficulty"] = (*hexutil.Big)(s.b.GetTd(ctx, b.Hash()))
	}
	return fields, err
}

// RPCMarshalKeyBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
func RPCMarshalKeyBlock(b *types.KeyBlock) (map[string]interface{}, error) {
	head := b.Header() // copies the header once
	fields := map[string]interface{}{
		"keyBlockNumber": head.Number.Uint64(),
		"difficulty":     (*hexutil.Big)(head.Difficulty),
		"hash":           b.Hash(),
		"parentHash":     head.ParentHash,
		"nonce":          head.Nonce,
		"mixDigest":      head.MixDigest,
		"timestamp":      head.Time,
		"committeeHash":  head.CommitteeHash,
		"blockType":      head.BlockType,
		"TxBlockNumber":  head.T_Number,
	}

	fields["inPubKey"] = b.InPubKey()
	fields["inAddress"] = b.InAddress()
	fields["outPubKey"] = b.OutPubKey()
	fields["outAddress"] = b.OutAddress(0)
	fields["leaderPubKey"] = b.LeaderPubKey()
	fields["leaderAddress"] = b.LeaderAddress()

	return fields, nil
}

func (s *PublicBlockChainAPI) rpcOutputKeyBlock(b *types.KeyBlock) (map[string]interface{}, error) {
	fields, err := RPCMarshalKeyBlock(b)
	if err != nil {
		return nil, err
	}
	return fields, err
}

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
type RPCTransaction struct {
	BlockHash                *common.Hash                 `json:"blockHash"`
	BlockNumber              *hexutil.Big                 `json:"blockNumber"`
	From                     common.Address               `json:"from"`
	Gas                      hexutil.Uint64               `json:"gas"`
	GasPrice                 *hexutil.Big                 `json:"gasPrice"`
	Hash                     common.Hash                  `json:"hash"`
	TransactionHash          common.Hash                  `json:"transactionHash"`
	Input                    hexutil.Bytes                `json:"input"`
	Nonce                    hexutil.Uint64               `json:"nonce"`
	To                       *common.Address              `json:"to"`
	TransactionIndex         *hexutil.Uint64              `json:"transactionIndex"`
	Value                    *hexutil.Big                 `json:"value"`
	Type                     hexutil.Uint64               `json:"type"`
	ChainID                  *hexutil.Big                 `json:"chainId,omitempty"`
	GasFeeCap                *hexutil.Big                 `json:"maxFeePerGas,omitempty"`
	GasTipCap                *hexutil.Big                 `json:"maxPriorityFeePerGas,omitempty"`
	Accesses                 *types.AccessList            `json:"accessList,omitempty"`
	BlobGasFeeCap            *hexutil.Big                 `json:"maxFeePerBlobGas,omitempty"`
	BlobVersionedHashes      []common.Hash                `json:"blobVersionedHashes,omitempty"`
	AuthorizationList        []types.SetCodeAuthorization `json:"authorizationList,omitempty"`
	Payer                    *common.Address              `json:"payer,omitempty"`
	ReplaySequence           *hexutil.Uint64              `json:"replaySequence,omitempty"`
	RecentBlockHash          *common.Hash                 `json:"recentBlockHash,omitempty"`
	RecentBlockNumber        *hexutil.Uint64              `json:"recentBlockNumber,omitempty"`
	ValidUntil               *hexutil.Uint64              `json:"validUntil,omitempty"`
	NativeAccesses           []types.NativeAccess         `json:"accesses,omitempty"`
	MaxFeePerCompute         *hexutil.Big                 `json:"maxFeePerCompute,omitempty"`
	MaxPriorityFeePerCompute *hexutil.Big                 `json:"maxPriorityFeePerCompute,omitempty"`
	ComputeLimit             *hexutil.Uint64              `json:"computeLimit,omitempty"`
	MemoryLimit              *hexutil.Uint64              `json:"memoryLimit,omitempty"`
	LogLimit                 *hexutil.Uint64              `json:"logLimit,omitempty"`
	OutputLimit              *hexutil.Uint64              `json:"outputLimit,omitempty"`
	YParity                  *hexutil.Uint64              `json:"yParity,omitempty"`
	V                        *hexutil.Big                 `json:"v"`
	R                        *hexutil.Big                 `json:"r"`
	S                        *hexutil.Big                 `json:"s"`

	CommonTxAdmissionRoot           *common.Hash    `json:"commonTxAdmissionRoot,omitempty"`
	CommonTxRewardRoot              *common.Hash    `json:"commonTxRewardRoot,omitempty"`
	CommonTxApprover                *common.Address `json:"commonTxApprover,omitempty"`
	CommonTxApproverReward          *hexutil.Big    `json:"commonTxApproverReward,omitempty"`
	CommonTxBurn                    *hexutil.Big    `json:"commonTxBurn,omitempty"`
	CommonTxAdmissionID             *common.Hash    `json:"commonTxAdmissionId,omitempty"`
	CommonTxAdmissionTxRoot         *common.Hash    `json:"commonTxAdmissionTxRoot,omitempty"`
	CommonTxAdmissionGenesisHash    *common.Hash    `json:"commonTxAdmissionGenesisHash,omitempty"`
	CommonTxAdmissionBatchIndex     *hexutil.Uint64 `json:"commonTxAdmissionBatchIndex,omitempty"`
	CommonTxAdmissionItemIndex      *hexutil.Uint64 `json:"commonTxAdmissionItemIndex,omitempty"`
	CommonTxAdmissionChainID        *hexutil.Big    `json:"commonTxAdmissionChainId,omitempty"`
	CommonTxAdmissionKeyBlockNumber *hexutil.Uint64 `json:"commonTxAdmissionKeyBlockNumber,omitempty"`
	CommonTxAdmissionTimestamp      *hexutil.Uint64 `json:"commonTxAdmissionTimestamp,omitempty"`
	CommonTxAdmissionSignature      hexutil.Bytes   `json:"commonTxAdmissionSignature,omitempty"`
}

func rpcTransactionSigner(tx *types.Transaction) types.Signer {
	if tx.Type() != types.LegacyTxType {
		return types.LatestSignerForChainID(tx.ChainId())
	}
	if tx.Protected() {
		return types.NewEIP155Signer(tx.ChainId())
	}
	return types.HomesteadSigner{}
}

func isEIP1559Transaction(tx *types.Transaction) bool {
	if tx == nil {
		return false
	}
	switch tx.Type() {
	case types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType:
		return true
	default:
		return false
	}
}

func effectiveTransactionGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
	if tx == nil {
		return new(big.Int)
	}
	price := new(big.Int).Set(tx.GasPrice())
	if !isEIP1559Transaction(tx) || baseFee == nil {
		return price
	}
	if tip, err := tx.EffectiveGasTip(baseFee); err == nil {
		return new(big.Int).Add(new(big.Int).Set(baseFee), tip)
	}
	return price
}

func setRPCTransactionEffectiveGasPrice(result *RPCTransaction, tx *types.Transaction, baseFee *big.Int) {
	if result != nil && isEIP1559Transaction(tx) && baseFee != nil {
		result.GasPrice = (*hexutil.Big)(effectiveTransactionGasPrice(tx, baseFee))
	}
}

func commonRPCAdmissionForBlockTransaction(block *types.Block, txHash common.Hash) (*types.CommonTxAdmissionBatch, uint32, uint16, bool) {
	if block == nil {
		return nil, 0, 0, false
	}
	txIndex := -1
	for index, tx := range block.Transactions() {
		if tx != nil && tx.Hash() == txHash {
			txIndex = index
			break
		}
	}
	refs := block.CommonTxAdmissionRefs()
	if txIndex < 0 || txIndex >= len(refs) {
		return nil, 0, 0, false
	}
	ref := refs[txIndex]
	batches := block.CommonTxAdmissionBatches()
	if int(ref.Batch) >= len(batches) || batches[ref.Batch] == nil {
		return nil, 0, 0, false
	}
	batch := batches[ref.Batch]
	if int(ref.Item) >= len(batch.TxHashes) || batch.TxHashes[ref.Item] != txHash {
		return nil, 0, 0, false
	}
	return batch, ref.Batch, ref.Item, true
}

func addBlobRPCReceiptFields(fields map[string]interface{}, config *params.ChainConfig, block *types.Block, tx *types.Transaction) {
	if fields == nil || tx == nil || tx.Type() != types.BlobTxType {
		return
	}
	fields["blobGasUsed"] = hexutil.Uint64(tx.BlobGas())
	if block != nil {
		header := block.Header()
		fields["blobGasPrice"] = (*hexutil.Big)(params.CalcBlobBaseFeeAtTime(config, header.Time, header.ExcessBlobGas))
	}
}

func fillCommonRPCTransactionFields(result *RPCTransaction, block *types.Block, txHash common.Hash) {
	if result == nil || block == nil {
		return
	}

	header := block.Header()
	admissionRoot := header.CommonTxAdmissionRoot
	rewardRoot := header.CommonTxRewardRoot

	result.CommonTxAdmissionRoot = &admissionRoot
	result.CommonTxRewardRoot = &rewardRoot

	if admission, batchIndexValue, itemIndexValue, ok := commonRPCAdmissionForBlockTransaction(block, txHash); ok {
		approver := admission.Miner
		admissionID := admission.AdmissionID
		txRoot := admission.TxRoot
		genesisHash := admission.GenesisHash
		batchIndex := hexutil.Uint64(batchIndexValue)
		itemIndex := hexutil.Uint64(itemIndexValue)
		keyBlockNumber := hexutil.Uint64(admission.KeyBlockNumber)
		timestamp := hexutil.Uint64(admission.Timestamp)

		result.CommonTxApprover = &approver
		result.CommonTxAdmissionID = &admissionID
		result.CommonTxAdmissionTxRoot = &txRoot
		result.CommonTxAdmissionGenesisHash = &genesisHash
		result.CommonTxAdmissionBatchIndex = &batchIndex
		result.CommonTxAdmissionItemIndex = &itemIndex
		if admission.ChainID != nil {
			result.CommonTxAdmissionChainID = (*hexutil.Big)(new(big.Int).Set(admission.ChainID))
		}
		result.CommonTxAdmissionKeyBlockNumber = &keyBlockNumber
		result.CommonTxAdmissionTimestamp = &timestamp
		result.CommonTxAdmissionSignature = hexutil.Bytes(admission.Signature)
	}

	for _, reward := range block.CommonTxRewards() {
		if reward == nil || reward.TxHash != txHash {
			continue
		}

		approver := reward.Approver
		result.CommonTxApprover = &approver

		if reward.ApproverReward != nil {
			result.CommonTxApproverReward = (*hexutil.Big)(new(big.Int).Set(reward.ApproverReward))
		}
		if reward.Burn != nil {
			result.CommonTxBurn = (*hexutil.Big)(new(big.Int).Set(reward.Burn))
		}

		break
	}
}

func addCommonRPCReceiptFields(fields map[string]interface{}, block *types.Block, txHash common.Hash) {
	if fields == nil || block == nil {
		return
	}

	header := block.Header()
	fields["commonTxAdmissionRoot"] = header.CommonTxAdmissionRoot
	fields["commonTxRewardRoot"] = header.CommonTxRewardRoot

	if admission, batchIndex, itemIndex, ok := commonRPCAdmissionForBlockTransaction(block, txHash); ok {
		fields["commonTxApprover"] = admission.Miner
		fields["commonTxAdmissionId"] = admission.AdmissionID
		fields["commonTxAdmissionTxRoot"] = admission.TxRoot
		fields["commonTxAdmissionGenesisHash"] = admission.GenesisHash
		fields["commonTxAdmissionBatchIndex"] = hexutil.Uint64(batchIndex)
		fields["commonTxAdmissionItemIndex"] = hexutil.Uint64(itemIndex)

		if admission.ChainID != nil {
			fields["commonTxAdmissionChainId"] = (*hexutil.Big)(new(big.Int).Set(admission.ChainID))
		}

		fields["commonTxAdmissionKeyBlockNumber"] = hexutil.Uint64(admission.KeyBlockNumber)
		fields["commonTxAdmissionTimestamp"] = hexutil.Uint64(admission.Timestamp)
		fields["commonTxAdmissionSignature"] = hexutil.Bytes(admission.Signature)
	}

	for _, reward := range block.CommonTxRewards() {
		if reward == nil || reward.TxHash != txHash {
			continue
		}

		fields["commonTxApprover"] = reward.Approver

		if reward.ApproverReward != nil {
			fields["commonTxApproverReward"] = (*hexutil.Big)(new(big.Int).Set(reward.ApproverReward))
		}
		if reward.Burn != nil {
			fields["commonTxBurn"] = (*hexutil.Big)(new(big.Int).Set(reward.Burn))
		}

		break
	}
}

// newRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
func newRPCTransaction(tx *types.Transaction, blockHash common.Hash, blockNumber uint64, index uint64) *RPCTransaction {
	signer := rpcTransactionSigner(tx)
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()
	txType := hexutil.Uint64(tx.Type())

	result := &RPCTransaction{
		From:            from,
		Gas:             hexutil.Uint64(tx.Gas()),
		GasPrice:        (*hexutil.Big)(tx.GasPrice()),
		Hash:            tx.Hash(),
		TransactionHash: tx.Hash(),
		Input:           hexutil.Bytes(tx.Data()),
		Nonce:           hexutil.Uint64(tx.Nonce()),
		To:              tx.To(),
		Type:            txType,
		Value:           (*hexutil.Big)(tx.Value()),
		V:               (*hexutil.Big)(v),
		R:               (*hexutil.Big)(r),
		S:               (*hexutil.Big)(s),
	}
	// EIP-2718 typed transactions expose their 0/1 recovery identifier through
	// yParity. Keep v as well for compatibility with older wallet clients, while
	// omitting yParity from legacy transactions whose V also carries EIP-155's
	// chain-id encoding.
	if tx.Type() >= types.AccessListTxType && tx.Type() <= types.SetCodeTxType && v != nil {
		yParity := hexutil.Uint64(v.Uint64())
		result.YParity = &yParity
	}
	if chainID := tx.ChainId(); chainID != nil && (tx.Type() != types.LegacyTxType || tx.Protected()) {
		result.ChainID = (*hexutil.Big)(new(big.Int).Set(chainID))
	}
	switch tx.Type() {
	case types.AccessListTxType:
		accessList := tx.AccessList()
		result.Accesses = &accessList
	case types.DynamicFeeTxType:
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		accessList := tx.AccessList()
		result.Accesses = &accessList
	case types.BlobTxType:
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		result.BlobGasFeeCap = (*hexutil.Big)(tx.BlobGasFeeCap())
		result.BlobVersionedHashes = tx.BlobHashes()
		accessList := tx.AccessList()
		result.Accesses = &accessList
	case types.SetCodeTxType:
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		accessList := tx.AccessList()
		result.Accesses = &accessList
		result.AuthorizationList = tx.SetCodeAuthorizations()
	case types.NativeTxType:
		payer := tx.Payer()
		replaySequence := hexutil.Uint64(tx.ReplaySequence())
		recentBlockHash := tx.RecentBlockHash()
		recentBlockNumber := hexutil.Uint64(tx.RecentBlockNumber())
		validUntil := hexutil.Uint64(tx.ValidUntil())
		computeLimit := hexutil.Uint64(tx.ComputeLimit())
		memoryLimit := hexutil.Uint64(tx.MemoryLimit())
		logLimit := hexutil.Uint64(tx.LogLimit())
		outputLimit := hexutil.Uint64(tx.OutputLimit())
		result.Payer = &payer
		result.ReplaySequence = &replaySequence
		result.RecentBlockHash = &recentBlockHash
		result.RecentBlockNumber = &recentBlockNumber
		result.ValidUntil = &validUntil
		result.NativeAccesses = tx.NativeAccesses()
		result.MaxFeePerCompute = (*hexutil.Big)(tx.MaxFeePerCompute())
		result.MaxPriorityFeePerCompute = (*hexutil.Big)(tx.PriorityFeePerCompute())
		result.ComputeLimit = &computeLimit
		result.MemoryLimit = &memoryLimit
		result.LogLimit = &logLimit
		result.OutputLimit = &outputLimit
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = &blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = (*hexutil.Uint64)(&index)
	}
	return result
}

// newRPCPendingTransaction returns a pending transaction that will serialize to the RPC representation
func newRPCPendingTransaction(tx *types.Transaction) *RPCTransaction {
	return newRPCTransaction(tx, common.Hash{}, 0, 0)
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(b *types.Block, index uint64) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	tx := txs[index]
	result := newRPCTransaction(tx, b.Hash(), b.NumberU64(), index)
	setRPCTransactionEffectiveGasPrice(result, tx, b.Header().BaseFee)
	fillCommonRPCTransactionFields(result, b, tx.Hash())
	return result
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a transaction given a block and a transaction index.
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := txs[index].MarshalBinary()
	return blob
}

// newRPCTransactionFromBlockHash returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockHash(b *types.Block, hash common.Hash) *RPCTransaction {
	for idx, tx := range b.Transactions() {
		if tx.Hash() == hash {
			return newRPCTransactionFromBlockIndex(b, uint64(idx))
		}
	}
	return nil
}

// PublicTransactionPoolAPI exposes methods for the RPC interface
type PublicTransactionPoolAPI struct {
	b         Backend
	am        *accounts.Manager
	nonceLock *AddrLocker

	// The single-request coalescer and batch RPCs share one bounded ingress
	// scheduler. Pending accounting includes coalescer, queued, and in-flight
	// work, so no request shape can bypass the node-global limits.
	singleRawTxMu              sync.Mutex
	singleRawTxQueue           []*singleRawTxRequest
	singleRawTxPendingCount    int
	singleRawTxPendingBytes    int
	singleRawTxWorkerRunning   bool
	singleRawTxCoalesceDelay   time.Duration
	singleRawTxQueueCountLimit int
	singleRawTxQueueBytesLimit int
	rawTxIngressQueue          []*rawTxIngressJob
	rawTxIngressWorkers        int
	rawTxIngressActiveJobs     int
	rawTxBackendWorkers        int
	rawTxActiveSenders         map[common.Address]uint32
	rawTxAccepting             bool
	rawTxLifecycleWG           sync.WaitGroup
	rawTxWorkerWG              sync.WaitGroup
	rawTxStopOnce              sync.Once

	// Only used for AutoTransaction API
	autoTransactionRunning bool
	quitAutoTransaction    int32
}

// NewPublicTransactionPoolAPI creates a new RPC service with methods specific for the transaction pool.
func NewPublicTransactionPoolAPI(b Backend, nonceLock *AddrLocker) *PublicTransactionPoolAPI {
	return &PublicTransactionPoolAPI{
		b:                          b,
		am:                         b.AccountManager(),
		nonceLock:                  nonceLock,
		singleRawTxCoalesceDelay:   singleRawTxDefaultCoalesceDelay,
		singleRawTxQueueCountLimit: singleRawTxDefaultQueueCountLimit,
		singleRawTxQueueBytesLimit: singleRawTxDefaultQueueBytesLimit,
		rawTxBackendWorkers:        defaultRawTxBackendWorkers(),
		rawTxAccepting:             true,
	}
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (s *PublicTransactionPoolAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
func (s *PublicTransactionPoolAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
func (s *PublicTransactionPoolAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
func (s *PublicTransactionPoolAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the transaction for the given block number and index.
func (s *PublicTransactionPoolAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the transaction for the given block hash and index.
func (s *PublicTransactionPoolAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (s *PublicTransactionPoolAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	// Ask transaction pool for the nonce which includes pending transactions
	if blockNr, ok := blockNrOrHash.Number(); ok && blockNr == rpc.PendingBlockNumber {
		nonce, err := s.b.GetPoolNonce(ctx, address)
		if err != nil {
			return nil, err
		}
		return (*hexutil.Uint64)(&nonce), nil
	}
	// Resolve block number and use its state to ask for the nonce
	state, _, err := s.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

// GetTransactionByHash returns the transaction for the given hash
func (s *PublicTransactionPoolAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	// Try to return an already finalized transaction
	tx, blockHash, blockNumber, index, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		result := newRPCTransaction(tx, blockHash, blockNumber, index)
		if block, blockErr := s.b.BlockByHash(ctx, blockHash); blockErr == nil && block != nil {
			setRPCTransactionEffectiveGasPrice(result, tx, block.Header().BaseFee)
			fillCommonRPCTransactionFields(result, block, hash)
		}
		return result, nil
	}
	// No finalized transaction, try to retrieve it from the pool
	if tx := s.b.GetPoolTransaction(hash); tx != nil {
		return newRPCPendingTransaction(tx), nil
	}

	// Transaction unknown, return as such
	return nil, nil
}

// GetRawTransactionByHash returns the bytes of the transaction for the given hash.
func (s *PublicTransactionPoolAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	tx, _, _, _, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		if tx = s.b.GetPoolTransaction(hash); tx == nil {
			// Transaction not found anywhere, abort
			return nil, nil
		}
	}
	// Serialize to RLP and return
	return tx.MarshalBinary()
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
func (s *PublicTransactionPoolAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index, err := s.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, nil
	}
	if tx == nil || blockHash == (common.Hash{}) {
		return nil, nil
	}
	receipts, err := s.b.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if len(receipts) <= int(index) {
		return nil, nil
	}
	receipt := receipts[index]

	block, _ := s.b.BlockByHash(ctx, blockHash)

	signer := rpcTransactionSigner(tx)
	from, _ := types.Sender(signer, tx)

	effectiveGasPrice := new(big.Int).Set(tx.GasPrice())
	if isEIP1559Transaction(tx) {
		baseFee := fixedBaseFeePerGas()
		if block != nil {
			if headerBaseFee := block.Header().BaseFee; headerBaseFee != nil {
				baseFee = new(big.Int).Set(headerBaseFee)
			}
		}
		if tip, tipErr := tx.EffectiveGasTip(baseFee); tipErr == nil {
			effectiveGasPrice = new(big.Int).Add(new(big.Int).Set(baseFee), tip)
		}
	}

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(index),
		"type":              hexutil.Uint64(tx.Type()),
		"effectiveGasPrice": (*hexutil.Big)(effectiveGasPrice),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
	}

	fields["status"] = hexutil.Uint(receipt.Status)
	addBlobRPCReceiptFields(fields, s.b.ChainConfig(), block, tx)

	if receipt.Logs == nil {
		fields["logs"] = [][]*types.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	addCommonRPCReceiptFields(fields, block, hash)
	return fields, nil
}

// sign is a helper function that signs a transaction with the private key of the given address.
func (s *PublicTransactionPoolAPI) sign(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the transaction
	return wallet.SignTx(account, tx, s.b.ChainConfig().ChainID)
}

// SendTxArgs represents the arguments to sumbit a new transaction into the transaction pool.
type SendTxArgs struct {
	From                     common.Address               `json:"from"`
	To                       *common.Address              `json:"to"`
	Gas                      *hexutil.Uint64              `json:"gas"`
	GasPrice                 *hexutil.Big                 `json:"gasPrice"`
	MaxFeePerGas             *hexutil.Big                 `json:"maxFeePerGas"`
	MaxPriorityFeePerGas     *hexutil.Big                 `json:"maxPriorityFeePerGas"`
	AccessList               *types.AccessList            `json:"accessList"`
	ChainID                  *hexutil.Big                 `json:"chainId"`
	MaxFeePerBlobGas         *hexutil.Big                 `json:"maxFeePerBlobGas"`
	BlobVersionedHashes      []common.Hash                `json:"blobVersionedHashes"`
	Blobs                    []kzg.Blob                   `json:"blobs"`
	Commitments              []kzg.Commitment             `json:"commitments"`
	Proofs                   []kzg.Proof                  `json:"proofs"`
	AuthorizationList        []types.SetCodeAuthorization `json:"authorizationList"`
	Type                     *hexutil.Uint64              `json:"type"`
	Value                    *hexutil.Big                 `json:"value"`
	Nonce                    *hexutil.Uint64              `json:"nonce"`
	Payer                    *common.Address              `json:"payer"`
	ReplaySequence           *hexutil.Uint64              `json:"replaySequence"`
	RecentBlockHash          *common.Hash                 `json:"recentBlockHash"`
	RecentBlockNumber        *hexutil.Uint64              `json:"recentBlockNumber"`
	ValidUntil               *hexutil.Uint64              `json:"validUntil"`
	NativeAccesses           *[]types.NativeAccess        `json:"accesses"`
	MaxFeePerCompute         *hexutil.Big                 `json:"maxFeePerCompute"`
	MaxPriorityFeePerCompute *hexutil.Big                 `json:"maxPriorityFeePerCompute"`
	ComputeLimit             *hexutil.Uint64              `json:"computeLimit"`
	MemoryLimit              *hexutil.Uint64              `json:"memoryLimit"`
	LogLimit                 *hexutil.Uint64              `json:"logLimit"`
	OutputLimit              *hexutil.Uint64              `json:"outputLimit"`
	// We accept "data" and "input" for backwards-compatibility reasons. "input" is the
	// newer name and should be preferred by clients.
	Data  *hexutil.Bytes `json:"data"`
	Input *hexutil.Bytes `json:"input"`

	// blobSidecarVersion is derived from the active fork by setDefaults. It is
	// not user-controlled JSON input.
	blobSidecarVersion byte
}

type SendTxOpts struct {
	UseSlowLane bool `json:"useSlowLane"`
}

func (args *SendTxArgs) txFeeCapForValidation() *big.Int {
	if args.MaxFeePerCompute != nil {
		return args.MaxFeePerCompute.ToInt()
	}
	if args.MaxFeePerGas != nil {
		return args.MaxFeePerGas.ToInt()
	}
	if args.GasPrice != nil {
		return args.GasPrice.ToInt()
	}
	return new(big.Int)
}

func (args *SendTxArgs) blobFeeCapForValidation() *big.Int {
	if args != nil && args.MaxFeePerBlobGas != nil {
		return args.MaxFeePerBlobGas.ToInt()
	}
	return new(big.Int)
}

func (args *SendTxArgs) blobGasForFeeValidation() uint64 {
	if args == nil {
		return 0
	}
	count := len(args.BlobVersionedHashes)
	if count == 0 {
		count = len(args.Blobs)
	}
	return uint64(count) * params.BlobTxBlobGasPerBlob
}

func (args *SendTxArgs) transactionChainID(b Backend) *big.Int {
	config := b.ChainConfig()
	if config == nil || config.ChainID == nil {
		return nil
	}
	txType := uint64(types.LegacyTxType)
	if args.Type != nil {
		txType = uint64(*args.Type)
	}
	if args.requestsNativeTransaction(b) || args.ChainID != nil || args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil || args.AccessList != nil || args.MaxFeePerBlobGas != nil || len(args.BlobVersionedHashes) > 0 || args.hasBlobSidecarFields() || len(args.AuthorizationList) > 0 || txType != types.LegacyTxType {
		return config.ChainID
	}
	if block := b.CurrentBlock(); block != nil && config.IsEIP155(block.Number()) {
		return config.ChainID
	}
	return nil
}

// setDefaults is a helper function that fills in default values for unspecified tx fields.
func (args *SendTxArgs) setDefaults(ctx context.Context, b Backend) error {
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
		return errors.New(`both "data" and "input" are set and not equal. Please use "input" to pass transaction call data`)
	}
	if args.requestsNativeTransaction(b) {
		if !nativeTransactionsRequired(b) {
			return errNativeTransactionsDisabled
		}
		return args.setNativeDefaults(ctx, b)
	}
	if args.hasNativeFields() || (args.Type != nil && uint64(*args.Type) == types.NativeTxType) {
		return errNativeTransactionsDisabled
	}
	if args.ChainID != nil {
		if b == nil || b.ChainConfig() == nil || b.ChainConfig().ChainID == nil {
			return errors.New("chainId cannot be validated because the node chain ID is unavailable")
		}
		have, want := args.ChainID.ToInt(), b.ChainConfig().ChainID
		if have.Cmp(want) != 0 {
			return fmt.Errorf("chainId does not match node's (have=%v, want=%v)", have, want)
		}
	}
	if args.Nonce == nil {
		nonce, err := b.GetPoolNonce(ctx, args.From)
		if err != nil {
			return err
		}
		args.Nonce = (*hexutil.Uint64)(&nonce)
	}

	pendingBlockNr := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	plainValueTransfer, err := isPlainValueTransferSendTx(ctx, b, args, pendingBlockNr)
	if err != nil {
		return err
	}
	if plainValueTransfer && args.Gas == nil {
		gas := hexutil.Uint64(params.TxGas)
		args.Gas = &gas
	}

	txType := uint64(types.LegacyTxType)
	if args.Type != nil {
		txType = uint64(*args.Type)
		switch txType {
		case types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType:
		default:
			return fmt.Errorf("unsupported transaction type %d", txType)
		}
	}
	forceLegacy := args.Type != nil && txType == types.LegacyTxType
	forceAccessList := args.Type != nil && txType == types.AccessListTxType
	forceDynamic := args.Type != nil && txType == types.DynamicFeeTxType
	forceBlob := args.Type != nil && txType == types.BlobTxType
	forceSetCode := args.Type != nil && txType == types.SetCodeTxType
	blobRequested := forceBlob || args.MaxFeePerBlobGas != nil || len(args.BlobVersionedHashes) > 0 || args.hasBlobSidecarFields()
	setCodeRequested := forceSetCode || len(args.AuthorizationList) > 0
	if blobRequested && setCodeRequested {
		return errors.New("blob and set-code transaction fields cannot be combined")
	}
	if plainValueTransfer && args.GasPrice == nil && args.MaxFeePerGas == nil && args.MaxPriorityFeePerGas == nil && args.Type == nil && !blobRequested && !setCodeRequested {
		args.GasPrice = (*hexutil.Big)(fixedGasPricePerGas())
	}
	if args.GasPrice != nil && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil || blobRequested || setCodeRequested) {
		return errors.New(`both "gasPrice" and EIP-1559 fee fields are set`)
	}
	if forceLegacy && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil || args.AccessList != nil || blobRequested || setCodeRequested) {
		return errors.New(`legacy transaction type does not support typed transaction fields`)
	}
	if forceAccessList && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil || blobRequested || setCodeRequested) {
		return errors.New(`access list transaction type does not support dynamic fee fields`)
	}
	if forceDynamic && (blobRequested || setCodeRequested) {
		return errors.New(`dynamic fee transaction type does not support blob or authorization fields`)
	}
	if blobRequested {
		if args.To == nil {
			return errors.New("blob transaction requires a recipient")
		}
		if args.MaxFeePerBlobGas == nil || args.MaxFeePerBlobGas.ToInt().Sign() <= 0 {
			return errors.New("blob transaction requires a positive maxFeePerBlobGas")
		}
		if err := args.setBlobSidecarDefaults(ctx, blobSidecarVersionForBackend(b)); err != nil {
			return err
		}
		for _, hash := range args.BlobVersionedHashes {
			if hash[0] != types.BlobCommitmentVersionKZG {
				return errors.New("blobVersionedHashes contains an unsupported version")
			}
		}
	}
	if setCodeRequested {
		if args.To == nil {
			return errors.New("set-code transaction requires a recipient")
		}
		if len(args.AuthorizationList) == 0 {
			return errors.New("set-code transaction requires authorizationList")
		}
	}
	head, _ := b.HeaderByNumber(ctx, rpc.PendingBlockNumber)
	if head == nil {
		head = b.CurrentHeader()
	}
	londonActive := head != nil && b.ChainConfig().IsLondon(head.Number)
	dynamicRequested := args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil || forceDynamic || blobRequested || setCodeRequested
	autoDynamic := londonActive && args.GasPrice == nil && !forceLegacy && !forceAccessList && !dynamicRequested
	if dynamicRequested || autoDynamic {
		tip, _ := suggestGasTipCap(ctx, b)
		if tip == nil || tip.Sign() < 0 {
			tip = fixedMaxPriorityFeePerGas()
		}
		if args.MaxPriorityFeePerGas == nil {
			args.MaxPriorityFeePerGas = (*hexutil.Big)(new(big.Int).Set(tip))
		}
		baseFee := new(big.Int)
		if londonActive {
			baseFee = fixedBaseFeePerGas()
		}
		if head != nil && head.BaseFee != nil {
			baseFee = new(big.Int).Set(head.BaseFee)
		}
		if args.MaxFeePerGas == nil {
			feeCap := new(big.Int).Add(baseFee, args.MaxPriorityFeePerGas.ToInt())
			if feeCap.Sign() <= 0 {
				feeCap = new(big.Int).Set(args.MaxPriorityFeePerGas.ToInt())
			}
			args.MaxFeePerGas = (*hexutil.Big)(feeCap)
		}
		if args.MaxFeePerGas.ToInt().Cmp(args.MaxPriorityFeePerGas.ToInt()) < 0 {
			return errors.New("maxFeePerGas must be greater than or equal to maxPriorityFeePerGas")
		}
		if baseFee.Sign() > 0 && args.MaxFeePerGas.ToInt().Cmp(baseFee) < 0 {
			return errors.New("maxFeePerGas is lower than current base fee")
		}
	} else if args.GasPrice == nil {
		price, err := b.SuggestPrice(ctx)
		if err != nil {
			return err
		}
		args.GasPrice = (*hexutil.Big)(price)
	}
	if args.To == nil {
		// Contract creation
		var input []byte
		if args.Data != nil {
			input = *args.Data
		} else if args.Input != nil {
			input = *args.Input
		}
		if len(input) == 0 {
			return errors.New(`contract creation without any data provided`)
		}
	}
	// Estimate the gas usage if necessary.
	if args.Gas == nil {
		// For backwards-compatibility reason, we try both input and data
		// but input is preferred.
		input := args.Input
		if input == nil {
			input = args.Data
		}
		callArgs := CallArgs{
			From:                 &args.From, // From shouldn't be nil
			To:                   args.To,
			GasPrice:             args.GasPrice,
			MaxFeePerGas:         args.MaxFeePerGas,
			MaxPriorityFeePerGas: args.MaxPriorityFeePerGas,
			Value:                args.Value,
			Data:                 input,
			AccessList:           args.AccessList,
			MaxFeePerBlobGas:     args.MaxFeePerBlobGas,
			BlobVersionedHashes:  args.BlobVersionedHashes,
			AuthorizationList:    args.AuthorizationList,
		}
		pendingBlockNr := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
		estimated, err := DoEstimateGas(ctx, b, callArgs, pendingBlockNr, b.RPCGasCap())
		if err != nil {
			return err
		}
		args.Gas = &estimated
		log.Trace("Estimate gas usage automatically", "gas", args.Gas)
	}
	return nil
}

func (args *SendTxArgs) toTransaction(chainID *big.Int) *types.Transaction {
	var input []byte
	if args.Input != nil {
		input = *args.Input
	} else if args.Data != nil {
		input = *args.Data
	}
	chainIDCopy := new(big.Int)
	if chainID != nil {
		chainIDCopy.Set(chainID)
	}
	txType := uint64(types.LegacyTxType)
	if args.Type != nil {
		txType = uint64(*args.Type)
	}
	if txType == types.NativeTxType {
		return args.toNativeTransaction(chainIDCopy, input)
	}
	setCodeRequested := txType == types.SetCodeTxType || len(args.AuthorizationList) > 0
	if setCodeRequested {
		inner := &types.SetCodeTx{
			ChainID:   chainIDCopy,
			Nonce:     uint64(*args.Nonce),
			GasTipCap: (*big.Int)(args.MaxPriorityFeePerGas),
			GasFeeCap: (*big.Int)(args.MaxFeePerGas),
			Gas:       uint64(*args.Gas),
			To:        *args.To,
			Value:     (*big.Int)(args.Value),
			Data:      input,
			AuthList:  args.AuthorizationList,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		return types.NewTx(inner)
	}
	blobRequested := txType == types.BlobTxType || args.MaxFeePerBlobGas != nil || len(args.BlobVersionedHashes) > 0 || args.hasBlobSidecarFields()
	if blobRequested {
		inner := &types.BlobTx{
			ChainID:    chainIDCopy,
			Nonce:      uint64(*args.Nonce),
			GasTipCap:  (*big.Int)(args.MaxPriorityFeePerGas),
			GasFeeCap:  (*big.Int)(args.MaxFeePerGas),
			Gas:        uint64(*args.Gas),
			To:         *args.To,
			Value:      (*big.Int)(args.Value),
			Data:       input,
			BlobFeeCap: (*big.Int)(args.MaxFeePerBlobGas),
			BlobHashes: args.BlobVersionedHashes,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		tx := types.NewTx(inner)
		if sidecar := args.blobSidecar(); sidecar != nil {
			tx = tx.WithBlobSidecar(sidecar)
		}
		return tx
	}
	dynamicRequested := args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil || txType == types.DynamicFeeTxType
	if dynamicRequested {
		inner := &types.DynamicFeeTx{
			ChainID:   chainIDCopy,
			Nonce:     uint64(*args.Nonce),
			GasTipCap: (*big.Int)(args.MaxPriorityFeePerGas),
			GasFeeCap: (*big.Int)(args.MaxFeePerGas),
			Gas:       uint64(*args.Gas),
			To:        args.To,
			Value:     (*big.Int)(args.Value),
			Data:      input,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		return types.NewDynamicFeeTx(inner)
	}
	accessListRequested := args.AccessList != nil || txType == types.AccessListTxType
	if accessListRequested {
		inner := &types.AccessListTx{
			ChainID:  chainIDCopy,
			Nonce:    uint64(*args.Nonce),
			GasPrice: (*big.Int)(args.GasPrice),
			Gas:      uint64(*args.Gas),
			To:       args.To,
			Value:    (*big.Int)(args.Value),
			Data:     input,
		}
		if args.AccessList != nil {
			inner.AccessList = *args.AccessList
		}
		return types.NewTx(inner)
	}
	if args.To == nil {
		return types.NewContractCreation(uint64(*args.Nonce), (*big.Int)(args.Value), uint64(*args.Gas), (*big.Int)(args.GasPrice), input)
	}
	return types.NewTransaction(uint64(*args.Nonce), *args.To, (*big.Int)(args.Value), uint64(*args.Gas), (*big.Int)(args.GasPrice), input)
}

// SubmitTransaction is a helper function that submits tx to txPool and logs a message.
func SubmitTransaction(ctx context.Context, b Backend, tx *types.Transaction, sync bool) (common.Hash, error) {
	if tx == nil {
		return common.Hash{}, errors.New("transaction is nil")
	}
	if tx.Type() == types.NativeTxType {
		return common.Hash{}, errNativeTransactionsDisabled
	}
	log.Trace("SubmitTransaction", "tx chainid", tx.ChainId(), "tx", tx.V())
	// If the transaction fee cap is already specified, ensure the
	// fee of the given transaction is _reasonable_.
	if err := checkTxFeeWithBlob(tx.GasFeeCap(), tx.Gas(), tx.BlobGasFeeCap(), tx.BlobGas(), b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	signer := types.MakeSignerAutoJudgement(b.ChainConfig(), b.CurrentBlock().Number(), tx.V())
	from, err := types.Sender(signer, tx)
	if err != nil {
		return common.Hash{}, err
	}
	if err := b.SendTx(ctx, tx, sync); err != nil {
		return common.Hash{}, err
	}
	emitSubmittedTransactionCheckpoint(tx, from)
	return tx.Hash(), nil
}

func emitSubmittedTransactionCheckpoint(tx *types.Transaction, from common.Address) {
	if tx == nil {
		return
	}
	if tx.To() == nil {
		addr := crypto.CreateAddress(from, tx.Nonce())
		//log.Info("Submitted contract creation", "fullhash", tx.Hash().Hex(), "to", addr.Hex())
		log.EmitCheckpoint(log.TxCreated, "tx", tx.Hash().Hex(), "to", addr.Hex())
	} else {
		//log.Info("Submitted transaction", "fullhash", tx.Hash().Hex(), "recipient", tx.To())
		log.EmitCheckpoint(log.TxCreated, "tx", tx.Hash().Hex(), "to", tx.To().Hex())
	}
}

// SendTransaction creates a transaction for the given argument, sign it and submit it to the
// transaction pool.
func (s *PublicTransactionPoolAPI) SendTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if !args.requestsNativeTransaction(s.b) && args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	// Assemble the transaction and sign with the wallet
	chainID := args.transactionChainID(s.b)
	tx := args.toTransaction(chainID)
	if tx.RouteHint() == types.TxRouteAuto {
		tx = tx.WithRouteHint(types.TxRouteFast)
	}

	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed, true)
}

func (s *PublicTransactionPoolAPI) SendTransactionWithOpts(ctx context.Context, args SendTxArgs, opts SendTxOpts) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if !args.requestsNativeTransaction(s.b) && args.Nonce == nil {
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}

	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	chainID := args.transactionChainID(s.b)
	tx := args.toTransaction(chainID)
	if opts.UseSlowLane {
		tx = tx.WithRouteHint(types.TxRouteSlow)
	} else {
		tx = tx.WithRouteHint(types.TxRouteFast)
	}

	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, s.b, signed, true)
}

// FillTransaction fills the defaults (nonce, gas, gasPrice) on a given unsigned transaction,
// and returns it to the caller for further processing (signing + broadcast)
func (s *PublicTransactionPoolAPI) FillTransaction(ctx context.Context, args SendTxArgs) (*SignTransactionResult, error) {
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Assemble the transaction and obtain rlp
	tx := args.toTransaction(args.transactionChainID(s.b))
	data, err := marshalTransactionForRPC(tx)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, tx}, nil
}

func (s *PublicTransactionPoolAPI) autoTrans(ctx context.Context, delay int) {
	noceMap := make(map[common.Address]uint64)
	addresses := make([]common.Address, 0) // return [] instead of nil if empty

	for _, wallet := range s.am.Wallets() {
		for _, account := range wallet.Accounts() {
			if !strings.Contains(account.URL.Path, "ED25519") {
				addresses = append(addresses, account.Address)
				noceMap[account.Address], _ = s.b.GetPoolNonce(ctx, account.Address)
			}
		}
	}
	if len(addresses) < 2 {
		return
	}
	/*
		var (
			headCh = make(chan core.ChainHeadEvent)
		)
		sub := s.b.SubscribeChainHeadEvent(headCh)
		if sub == nil {
			return
		}
		defer sub.Unsubscribe()
	*/
	delayTm := time.Duration(delay) * time.Millisecond
	s.autoTransactionRunning = true
	atomic.StoreInt32(&s.quitAutoTransaction, 0)
	for {
		if atomic.LoadInt32(&s.quitAutoTransaction) == 1 {
			log.Error("AutoTrans loop out")
			break
		}

		n := int64(len(addresses))
		tmNow := time.Now().Unix()
		fromIndex := tmNow % n
		toIndex := fromIndex + 1
		if toIndex > n-1 {
			toIndex = 0
		}
		addrfrom := addresses[fromIndex]

		account := accounts.Account{Address: addrfrom}
		wallet, err := s.b.AccountManager().Find(account)
		if err != nil {
			log.Error("AutoTrans failed to find in the local account")
			break
		}
	labelReSend:
		txNonce := noceMap[addrfrom]
		noceMap[addrfrom]++
		log.Debug("AutoTrans", "fromIndex", fromIndex, "nonce", txNonce)
		amount := 20000000000000000 //+ tmNow //balanceFrom.Uint64() / 1000
		tx := types.NewTransaction(txNonce, addresses[toIndex], big.NewInt(int64(amount)), uint64(21000), big.NewInt(18100000000), []byte{})

		signed, err := wallet.SignTx(account, tx, nil)
		if err != nil {
			log.Info("AutoTrans failed to sign transaction", "sign error", err)
			break
		}
		log.Debug("AutoTrans...1")
		hash, err := SubmitTransaction(ctx, s.b, signed, true)
		if err != nil || hash == (common.Hash{}) { //&& err != core.ErrAlreadyKnown {
			log.Error("AutoTrans failed to submit transaction", "amount", amount, "nonce", txNonce, "submit error", err)
			//if err == core.ErrReplaceUnderpriced {
			//	txNonce = txNonce + 1
			time.Sleep(delayTm)
			txNonce, _ = s.b.GetPoolNonce(ctx, addrfrom)
			noceMap[addrfrom] = txNonce
			goto labelReSend
			//}
			//break
		}
		log.Debug("AutoTrans...2")
		time.Sleep(delayTm)
		/*
			num := 0
			for {
				num++
				if num > 1000 {
					break
				}
				hasNewBlock := false
				pending, _ := s.b.Stats()
				if pending == 0 {
					break
				}
				select {
				case head := <-headCh:
					log.Debug("AutoTrans", "number", head.Block.NumberU64())
					hasNewBlock = true
				}
				if hasNewBlock {
					break
				}
				time.Sleep(delayTm)
			}
		*/
	}

	s.autoTransactionRunning = false
}

// AutoTransaction creates repeated transactions for the given argument, sign them and submit them to the
// transaction pool,this api is ONLY used for test.
func (s *PublicTransactionPoolAPI) AutoTransaction(ctx context.Context, run int, delay int) string {
	//log.Info("Auto transaction: ","autoTx", fmt.Sprintf("run = %d , from = %s, to = %s", run, from.Hex(), to.Hex()))
	if run > 0 {
		if !s.autoTransactionRunning {
			go s.autoTrans(ctx, delay)
			return "Auto transaction is started."
		} else {
			return "Auto-transaction has already been running."
		}
	} else {
		if s.autoTransactionRunning {
			atomic.StoreInt32(&s.quitAutoTransaction, 1)
			return "Auto transaction will stopped."
		} else {
			return "Auto-transaction is not running."
		}
	}
}

const (
	// A public request is bounded independently from the transport batches it
	// produces. The million-item envelope covers a five-second 200k TPS burst
	// without ever constructing an unbounded TxPool/TxQUIC operation.
	MaxRawTxRequestCount = params.NativeParallelHardMaxTransactions
	// Hex JSON doubles the wire size. Sixty MiB leaves framing headroom below
	// the RPC server's 128 MiB request ceiling.
	MaxRawTxRequestBytes = 60 * 1024 * 1024

	// Backend and TxQUIC work remains bounded to fixed micro-batches. These are
	// scheduling limits, not the public request limit above.
	MaxRawTxBatchCount = 512
	MaxRawTxBatchBytes = 4 * 1024 * 1024
	// Backend calls overlap so independent admission signatures and durable
	// outbox writes can be group-committed. TxPool mutation remains serialized
	// by the pool lock, and the fixed bound prevents an RPC burst from creating
	// one goroutine per micro-batch.
	rawTxBackendMinWorkers = 8
	rawTxBackendMaxWorkers = 64
	// A bulk RPC keeps at most two backend waves admitted at once. This keeps a
	// million-item request from materializing one scheduler job per sender while
	// leaving one full wave queued behind the active workers.
	rawTxIngressOutstandingWaves = 2

	// Parallel eth_sendRawTransaction calls share this short collection window.
	// Pending work includes both queued and currently submitted transactions so
	// a slow backend cannot turn the coalescer into unbounded memory storage.
	singleRawTxDefaultCoalesceDelay   = 2 * time.Millisecond
	singleRawTxDefaultQueueCountLimit = MaxRawTxRequestCount
	// The node-global queue is independent from one public request and can absorb
	// a five-second million-transfer burst without relaxing the 60 MiB request
	// ceiling. Count and byte limits both apply to queued plus in-flight work.
	singleRawTxDefaultQueueBytesLimit = 256 * 1024 * 1024
)

var errRawTxIngressStopped = errors.New("raw transaction ingress is stopped")

func defaultRawTxBackendWorkers() int {
	return rawTxBackendWorkersForCPU(runtime.GOMAXPROCS(0))
}

func rawTxBackendWorkersForCPU(workers int) int {
	if workers < rawTxBackendMinWorkers {
		return rawTxBackendMinWorkers
	}
	if workers > rawTxBackendMaxWorkers {
		return rawTxBackendMaxWorkers
	}
	return workers
}

// Stop closes raw-transaction admission, drains every job that already crossed
// the node-owned boundary, and joins the coalescer and backend workers. It is
// safe to call concurrently and must complete before the TxQUIC/WAL lifecycle
// is stopped.
func (s *PublicTransactionPoolAPI) Stop() {
	if s == nil {
		return
	}
	s.rawTxStopOnce.Do(func() {
		s.singleRawTxMu.Lock()
		s.rawTxAccepting = false
		s.singleRawTxMu.Unlock()

		// Producers and accepted single calls keep this counter positive while
		// they are allowed to add node-owned jobs. Waiting for it first makes the
		// subsequent worker wait immune to WaitGroup Add/Wait races.
		s.rawTxLifecycleWG.Wait()
		s.rawTxWorkerWG.Wait()
	})
}

// RawTxResult is aligned with one eth_sendRawTransactions input. A decoded
// transaction retains its hash even when fee, sender, pool, or outbox handling
// fails, allowing clients to reconcile partial batches safely.
type RawTxResult struct {
	Hash  *common.Hash `json:"hash,omitempty"`
	Error string       `json:"error,omitempty"`
}

type rawTxSubmissionResult struct {
	hash    common.Hash
	decoded bool
	err     error
}

type rawTxPreparedTransaction struct {
	tx      *types.Transaction
	sender  common.Address
	decoded bool
	err     error
}

type rawTxPreparationStats struct {
	decode         time.Duration
	prepare        time.Duration
	senderRecovery time.Duration
	totalBytes     int
}

type singleRawTxRequest struct {
	encoded   hexutil.Bytes
	routeHint types.TxRouteHint
	response  chan singleRawTxResponse
}

type singleRawTxResponse struct {
	result rawTxSubmissionResult
	err    error
}

type rawTxMicroBatch struct {
	start     int
	end       int
	bytes     int
	oversized bool
}

type rawTxIngressJob struct {
	encoded        []hexutil.Bytes
	routeHints     []types.TxRouteHint
	prepared       []rawTxPreparedTransaction
	single         []*singleRawTxRequest
	senders        []common.Address
	resultIndexes  []int
	current        *types.Block
	ctx            context.Context
	completion     chan<- rawTxIngressCompletion
	pendingCount   int
	pendingBytes   int
	lifecycleUnits int
}

type rawTxIngressCompletion struct {
	indexes []int
	results []rawTxSubmissionResult
}

func validateRawTransactionSignatureSize(tx *types.Transaction, config *params.ChainConfig) error {
	if tx == nil {
		return types.ErrInvalidSig
	}
	v, r, s := tx.RawSignatureValues()
	if v == nil || r == nil || s == nil || v.Sign() < 0 || r.Sign() < 0 || s.Sign() < 0 {
		return types.ErrInvalidSig
	}
	// R and S are secp256k1 scalars. Legacy V additionally carries chain ID,
	// whose configured size is allowed, but an unauthenticated raw RPC must not
	// feed megabyte-sized integers into signer selection or decimal logging.
	if r.BitLen() > 256 || s.BitLen() > 256 {
		return types.ErrInvalidSig
	}
	maxVBits := 256
	if config != nil && config.ChainID != nil && config.ChainID.BitLen()+2 > maxVBits {
		maxVBits = config.ChainID.BitLen() + 2
	}
	if v.BitLen() > maxVBits {
		return types.ErrInvalidSig
	}
	return nil
}

// rawTransactionSignerClass mirrors MakeSignerAutoJudgement, whose result can
// only be the active fork signer or EIP-155 signer. Keeping this bounded class
// avoids attacker-controlled big.Int string keys and per-transaction logging.
func rawTransactionSignerClass(config *params.ChainConfig, v *big.Int) uint8 {
	if config == nil || config.ChainID == nil || v == nil || v.Cmp(big.NewInt(28)) <= 0 {
		return 0
	}
	maxRecoverV := new(big.Int).Lsh(new(big.Int).Set(config.ChainID), 1)
	maxRecoverV.Add(maxRecoverV, big.NewInt(36))
	if v.Cmp(maxRecoverV) <= 0 {
		return 1
	}
	return 0
}

func decodeRawTransaction(encodedTx hexutil.Bytes, routeHint types.TxRouteHint) (*types.Transaction, error) {
	if len(encodedTx) > 0 && encodedTx[0] == types.NativeTxType {
		return nil, errNativeTransactionsDisabled
	}
	tx := new(types.Transaction)
	if len(encodedTx) > 0 && encodedTx[0] < 0x80 {
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
	} else if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return nil, err
	}
	if routeHint == types.TxRouteAuto {
		routeHint = types.TxRouteFast
	}
	return tx.WithRouteHint(routeHint), nil
}

func validateRawTransactionRequest(encoded []hexutil.Bytes) error {
	if len(encoded) == 0 {
		return fmt.Errorf("raw transaction batch is empty")
	}
	if len(encoded) > MaxRawTxRequestCount {
		return fmt.Errorf("raw transaction request count %d exceeds limit %d", len(encoded), MaxRawTxRequestCount)
	}
	totalBytes := 0
	for _, raw := range encoded {
		if len(raw) > MaxRawTxRequestBytes-totalBytes {
			return fmt.Errorf("raw transaction request bytes exceed limit %d", MaxRawTxRequestBytes)
		}
		totalBytes += len(raw)
	}
	return nil
}

func (s *PublicTransactionPoolAPI) prepareRawTransactions(encoded []hexutil.Bytes, routeHints []types.TxRouteHint, current *types.Block) ([]rawTxPreparedTransaction, rawTxPreparationStats) {
	type uniqueRawTransactionKey struct {
		hash      common.Hash
		routeHint types.TxRouteHint
	}

	started := time.Now()
	prepared := make([]rawTxPreparedTransaction, len(encoded))
	decodedTxs := make([]*types.Transaction, len(encoded))
	decodeErrs := make([]error, len(encoded))
	core.RunBoundedCryptoJobs(len(encoded), func(index int) {
		routeHint := types.TxRouteFast
		if index < len(routeHints) && routeHints[index] != types.TxRouteAuto {
			routeHint = routeHints[index]
		}
		decodedTxs[index], decodeErrs[index] = decodeRawTransaction(encoded[index], routeHint)
	})
	stats := rawTxPreparationStats{decode: time.Since(started)}

	representativeByKey := make(map[uniqueRawTransactionKey]int, len(encoded))
	duplicateOf := make([]int, len(encoded))
	for index := range duplicateOf {
		duplicateOf[index] = -1
	}
	signers := make([]types.Signer, len(encoded))
	recoverable := make([]int, 0, len(encoded))
	signerCache := make(map[uint8]types.Signer, 2)
	for index, raw := range encoded {
		stats.totalBytes += len(raw)
		tx, err := decodedTxs[index], decodeErrs[index]
		if err != nil {
			prepared[index].err = err
			continue
		}
		prepared[index].tx = tx
		prepared[index].decoded = true
		key := uniqueRawTransactionKey{hash: tx.Hash(), routeHint: tx.RouteHint()}
		if representative, exists := representativeByKey[key]; exists {
			duplicateOf[index] = representative
			continue
		}
		representativeByKey[key] = index
		if err := validateRawTransactionSignatureSize(tx, s.b.ChainConfig()); err != nil {
			prepared[index].err = err
			continue
		}
		if err := checkTxFeeWithBlob(tx.GasFeeCap(), tx.Gas(), tx.BlobGasFeeCap(), tx.BlobGas(), s.b.RPCTxFeeCap()); err != nil {
			prepared[index].err = err
			continue
		}
		class := rawTransactionSignerClass(s.b.ChainConfig(), tx.V())
		signer := signerCache[class]
		if signer == nil {
			switch class {
			case 1:
				signer = types.NewEIP155Signer(s.b.ChainConfig().ChainID)
			default:
				signer = types.MakeSigner(s.b.ChainConfig(), current.Number())
			}
			signerCache[class] = signer
		}
		signers[index] = signer
		recoverable = append(recoverable, index)
	}
	stats.prepare = time.Since(started) - stats.decode

	recoveryStarted := time.Now()
	core.RunBoundedCryptoJobs(len(recoverable), func(position int) {
		index := recoverable[position]
		prepared[index].sender, prepared[index].err = types.Sender(signers[index], prepared[index].tx)
	})
	stats.senderRecovery = time.Since(recoveryStarted)
	for index, representative := range duplicateOf {
		if representative < 0 {
			continue
		}
		prepared[index].tx = prepared[representative].tx
		prepared[index].sender = prepared[representative].sender
		prepared[index].decoded = prepared[representative].decoded
		prepared[index].err = prepared[representative].err
	}
	return prepared, stats
}

func (s *PublicTransactionPoolAPI) submitPreparedRawTransactionMicroBatch(ctx context.Context, prepared []rawTxPreparedTransaction) ([]rawTxSubmissionResult, int, time.Duration) {
	type uniqueRawTransaction struct {
		tx      *types.Transaction
		sender  common.Address
		indexes []int
		err     error
	}
	type uniqueRawTransactionKey struct {
		hash      common.Hash
		routeHint types.TxRouteHint
	}

	results := make([]rawTxSubmissionResult, len(prepared))
	validTxs := make(types.Transactions, 0, len(prepared))
	validEntries := make([]*uniqueRawTransaction, 0, len(prepared))
	entries := make([]*uniqueRawTransaction, 0, len(prepared))
	entryByKey := make(map[uniqueRawTransactionKey]*uniqueRawTransaction, len(prepared))
	for index, item := range prepared {
		if !item.decoded || item.tx == nil {
			results[index].err = item.err
			continue
		}
		results[index].decoded = true
		results[index].hash = item.tx.Hash()
		key := uniqueRawTransactionKey{hash: results[index].hash, routeHint: item.tx.RouteHint()}
		if entry := entryByKey[key]; entry != nil {
			entry.indexes = append(entry.indexes, index)
			continue
		}
		entry := &uniqueRawTransaction{tx: item.tx, sender: item.sender, indexes: []int{index}, err: item.err}
		entryByKey[key] = entry
		entries = append(entries, entry)
		if entry.err == nil {
			validTxs = append(validTxs, entry.tx)
			validEntries = append(validEntries, entry)
		}
	}

	backendElapsed := time.Duration(0)
	if len(validTxs) > 0 {
		backendStarted := time.Now()
		backendResults := s.b.SendTxBatch(ctx, validTxs)
		backendElapsed = time.Since(backendStarted)
		if len(backendResults) != len(validTxs) {
			log.Error("Transaction backend returned misaligned batch results", "transactions", len(validTxs), "results", len(backendResults))
		}
		for index, entry := range validEntries {
			if index >= len(backendResults) {
				entry.err = fmt.Errorf("transaction backend omitted batch result")
				continue
			}
			entry.err = backendResults[index]
			if entry.err == nil {
				emitSubmittedTransactionCheckpoint(entry.tx, entry.sender)
			}
		}
	}
	for _, entry := range entries {
		for _, index := range entry.indexes {
			results[index].err = entry.err
		}
	}
	return results, len(validTxs), backendElapsed
}

func (s *PublicTransactionPoolAPI) submitRawTransactionMicroBatch(ctx context.Context, encoded []hexutil.Bytes, routeHints []types.TxRouteHint, current *types.Block) []rawTxSubmissionResult {
	started := time.Now()
	prepared, stats := s.prepareRawTransactions(encoded, routeHints, current)
	results, validCount, backendElapsed := s.submitPreparedRawTransactionMicroBatch(ctx, prepared)
	log.Debug("Submitted raw transaction batch", "requested", len(encoded), "decoded", validCount, "bytes", stats.totalBytes,
		"decode", stats.decode, "prepare", stats.prepare, "senderRecovery", stats.senderRecovery,
		"backend", backendElapsed, "total", time.Since(started))
	return results
}

func splitRawTransactionMicroBatches(encoded []hexutil.Bytes) []rawTxMicroBatch {
	microBatches := make([]rawTxMicroBatch, 0, (len(encoded)+MaxRawTxBatchCount-1)/MaxRawTxBatchCount)
	for start := 0; start < len(encoded); {
		if len(encoded[start]) > MaxRawTxBatchBytes {
			microBatches = append(microBatches, rawTxMicroBatch{
				start: start, end: start + 1, bytes: len(encoded[start]), oversized: true,
			})
			start++
			continue
		}
		end, batchBytes := start, 0
		for end < len(encoded) && end-start < MaxRawTxBatchCount {
			nextBytes := len(encoded[end])
			if end > start && nextBytes > MaxRawTxBatchBytes-batchBytes {
				break
			}
			batchBytes += nextBytes
			end++
		}
		microBatches = append(microBatches, rawTxMicroBatch{start: start, end: end, bytes: batchBytes})
		start = end
	}
	return microBatches
}

func (s *PublicTransactionPoolAPI) beginRawTxIngressProducer() error {
	s.singleRawTxMu.Lock()
	defer s.singleRawTxMu.Unlock()
	if !s.rawTxAccepting {
		return errRawTxIngressStopped
	}
	// The accepting gate and the first positive Add share the same lock. Stop
	// closes the gate before waiting, so a zero counter can never race a new Add.
	s.rawTxLifecycleWG.Add(1)
	return nil
}

func (s *PublicTransactionPoolAPI) rawTxIngressCapacityErrorLocked(count, bytes int) error {
	if count < 0 || s.singleRawTxPendingCount > s.singleRawTxQueueCountLimit || count > s.singleRawTxQueueCountLimit-s.singleRawTxPendingCount {
		return fmt.Errorf("raw transaction ingress busy: queue count exceeds limit %d", s.singleRawTxQueueCountLimit)
	}
	if bytes < 0 || s.singleRawTxPendingBytes > s.singleRawTxQueueBytesLimit || bytes > s.singleRawTxQueueBytesLimit-s.singleRawTxPendingBytes {
		return fmt.Errorf("raw transaction ingress busy: queue bytes exceed limit %d", s.singleRawTxQueueBytesLimit)
	}
	return nil
}

func (s *PublicTransactionPoolAPI) startRawTxIngressWorkersLocked() int {
	available := s.rawTxBackendWorkers - s.rawTxIngressWorkers
	if available <= 0 || len(s.rawTxIngressQueue) == 0 {
		return 0
	}
	reservedSenders := make(map[common.Address]struct{}, len(s.rawTxActiveSenders))
	for sender := range s.rawTxActiveSenders {
		reservedSenders[sender] = struct{}{}
	}
	runnable := 0
	for _, job := range s.rawTxIngressQueue {
		blocked := false
		for _, sender := range job.senders {
			if _, exists := reservedSenders[sender]; exists {
				blocked = true
				break
			}
		}
		if !blocked {
			runnable++
		}
		// A blocked multi-sender job still owns its place for every sender.
		// Reserving all of them prevents a younger job from bypassing it on
		// a sender that was not the immediate cause of the block.
		for _, sender := range job.senders {
			reservedSenders[sender] = struct{}{}
		}
	}
	waitingWorkers := s.rawTxIngressWorkers - s.rawTxIngressActiveJobs
	start := runnable - waitingWorkers
	if start <= 0 {
		return 0
	}
	if start > available {
		start = available
	}
	s.rawTxIngressWorkers += start
	return start
}

func (s *PublicTransactionPoolAPI) enqueueReservedRawTxIngressJobs(jobs []*rawTxIngressJob) {
	if len(jobs) == 0 {
		return
	}
	s.singleRawTxMu.Lock()
	s.rawTxIngressQueue = append(s.rawTxIngressQueue, jobs...)
	startWorkers := s.startRawTxIngressWorkersLocked()
	if startWorkers > 0 {
		s.rawTxWorkerWG.Add(startWorkers)
	}
	s.singleRawTxMu.Unlock()
	for worker := 0; worker < startWorkers; worker++ {
		go s.runRawTxIngressWorker()
	}
}

func (s *PublicTransactionPoolAPI) reserveRawTxIngressCapacity(count, bytes int) error {
	s.singleRawTxMu.Lock()
	defer s.singleRawTxMu.Unlock()
	if err := s.rawTxIngressCapacityErrorLocked(count, bytes); err != nil {
		return err
	}
	s.singleRawTxPendingCount += count
	s.singleRawTxPendingBytes += bytes
	return nil
}

func (s *PublicTransactionPoolAPI) releaseRawTxIngressCapacity(count, bytes int) {
	s.singleRawTxMu.Lock()
	s.singleRawTxPendingCount -= count
	s.singleRawTxPendingBytes -= bytes
	s.singleRawTxMu.Unlock()
}

func (s *PublicTransactionPoolAPI) dequeueRawTxIngressJobLocked() *rawTxIngressJob {
	reservedSenders := make(map[common.Address]struct{}, len(s.rawTxActiveSenders))
	for sender := range s.rawTxActiveSenders {
		reservedSenders[sender] = struct{}{}
	}
	for queueIndex, job := range s.rawTxIngressQueue {
		runnable := true
		for _, sender := range job.senders {
			if _, reserved := reservedSenders[sender]; reserved {
				runnable = false
				break
			}
		}
		for _, sender := range job.senders {
			reservedSenders[sender] = struct{}{}
		}
		if !runnable {
			continue
		}
		if s.rawTxActiveSenders == nil && len(job.senders) > 0 {
			s.rawTxActiveSenders = make(map[common.Address]uint32)
		}
		for _, sender := range job.senders {
			s.rawTxActiveSenders[sender]++
		}
		s.rawTxIngressActiveJobs++
		copy(s.rawTxIngressQueue[queueIndex:], s.rawTxIngressQueue[queueIndex+1:])
		last := len(s.rawTxIngressQueue) - 1
		s.rawTxIngressQueue[last] = nil
		s.rawTxIngressQueue = s.rawTxIngressQueue[:last]
		if len(s.rawTxIngressQueue) == 0 {
			s.rawTxIngressQueue = nil
		}
		return job
	}
	return nil
}

func (s *PublicTransactionPoolAPI) finishRawTxIngressJob(job *rawTxIngressJob) {
	s.singleRawTxMu.Lock()
	for _, sender := range job.senders {
		users := s.rawTxActiveSenders[sender]
		if users <= 1 {
			delete(s.rawTxActiveSenders, sender)
		} else {
			s.rawTxActiveSenders[sender] = users - 1
		}
	}
	s.singleRawTxPendingCount -= job.pendingCount
	s.singleRawTxPendingBytes -= job.pendingBytes
	s.rawTxIngressActiveJobs--
	startWorkers := 0
	if len(job.senders) > 1 {
		// Completing one multi-sender job can unblock several independent
		// successor chains. The current worker covers one; start any additional
		// lanes now instead of serializing them until another enqueue arrives.
		startWorkers = s.startRawTxIngressWorkersLocked()
	}
	if startWorkers > 0 {
		s.rawTxWorkerWG.Add(startWorkers)
	}
	s.singleRawTxMu.Unlock()
	for worker := 0; worker < startWorkers; worker++ {
		go s.runRawTxIngressWorker()
	}
}

func (s *PublicTransactionPoolAPI) executeRawTxIngressJob(job *rawTxIngressJob) (results []rawTxSubmissionResult) {
	results = make([]rawTxSubmissionResult, len(job.encoded))
	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("raw transaction backend panicked: %v", recovered)
			for index := range results {
				if index < len(job.prepared) && job.prepared[index].decoded && job.prepared[index].tx != nil {
					results[index].decoded = true
					results[index].hash = job.prepared[index].tx.Hash()
				}
				results[index].err = err
			}
		}
	}()
	if job.prepared == nil {
		return s.submitRawTransactionMicroBatch(job.ctx, job.encoded, job.routeHints, job.current)
	}
	if len(job.prepared) != len(job.encoded) {
		err := fmt.Errorf("prepared raw transaction count %d does not match encoded count %d", len(job.prepared), len(job.encoded))
		for index := range results {
			results[index].err = err
		}
		return results
	}
	started := time.Now()
	var validCount int
	var backendElapsed time.Duration
	results, validCount, backendElapsed = s.submitPreparedRawTransactionMicroBatch(job.ctx, job.prepared)
	log.Debug("Submitted raw transaction batch", "requested", len(job.encoded), "decoded", validCount, "bytes", job.pendingBytes,
		"decode", time.Duration(0), "prepare", time.Duration(0), "senderRecovery", time.Duration(0),
		"backend", backendElapsed, "total", time.Since(started))
	return results
}

func deliverSingleRawTxResponses(requests []*singleRawTxRequest, results []rawTxSubmissionResult, err error) {
	for index, request := range requests {
		response := singleRawTxResponse{err: err}
		if err == nil {
			if index < len(results) {
				response.result = results[index]
			} else {
				response.err = fmt.Errorf("raw transaction backend returned %d results for %d transactions", len(results), len(requests))
			}
		}
		request.response <- response
	}
}

func (s *PublicTransactionPoolAPI) runRawTxIngressWorker() {
	defer s.rawTxWorkerWG.Done()
	for {
		s.singleRawTxMu.Lock()
		job := s.dequeueRawTxIngressJobLocked()
		if job == nil {
			s.rawTxIngressWorkers--
			s.singleRawTxMu.Unlock()
			return
		}
		s.singleRawTxMu.Unlock()

		results := s.executeRawTxIngressJob(job)
		s.finishRawTxIngressJob(job)
		if job.single != nil {
			deliverSingleRawTxResponses(job.single, results, nil)
		} else if job.completion != nil {
			// Bulk callers may stop waiting after request cancellation. The
			// request-scoped channel is sized for every admitted job, so node-owned
			// completion and capacity release never depend on a live RPC waiter.
			job.completion <- rawTxIngressCompletion{indexes: job.resultIndexes, results: results}
		}
		if job.lifecycleUnits > 0 {
			s.rawTxLifecycleWG.Add(-job.lifecycleUnits)
		}
	}
}

func (s *PublicTransactionPoolAPI) partitionPreparedRawTransactions(encoded []hexutil.Bytes, prepared []rawTxPreparedTransaction) [][]int {
	microBatches := splitRawTransactionMicroBatches(encoded)
	if len(microBatches) != 1 || microBatches[0].oversized || len(encoded) < 2 {
		partitions := make([][]int, 0, len(microBatches))
		for _, batch := range microBatches {
			indexes := make([]int, batch.end-batch.start)
			for index := range indexes {
				indexes[index] = batch.start + index
			}
			partitions = append(partitions, indexes)
		}
		return partitions
	}

	type senderKey struct {
		known  bool
		sender common.Address
	}
	type senderGroup struct {
		indexes []int
		bytes   int
	}
	groups := make([]senderGroup, 0)
	groupBySender := make(map[senderKey]int)
	for index, item := range prepared {
		key := senderKey{}
		if item.err == nil && item.tx != nil {
			key.known = true
			key.sender = item.sender
		}
		groupIndex, exists := groupBySender[key]
		if !exists {
			groupIndex = len(groups)
			groupBySender[key] = groupIndex
			groups = append(groups, senderGroup{})
		}
		groups[groupIndex].indexes = append(groups[groupIndex].indexes, index)
		groups[groupIndex].bytes += len(encoded[index])
	}
	workerCount := s.rawTxBackendWorkers
	if workerCount > len(groups) {
		workerCount = len(groups)
	}
	if workerCount <= 1 {
		indexes := make([]int, len(encoded))
		for index := range indexes {
			indexes[index] = index
		}
		return [][]int{indexes}
	}

	// Place the heaviest sender groups first, then restore input order inside
	// each backend batch. A sender never crosses batches, so nonce/replacement
	// ordering stays serial while independent senders fill the available lanes.
	sort.SliceStable(groups, func(left, right int) bool {
		if groups[left].bytes != groups[right].bytes {
			return groups[left].bytes > groups[right].bytes
		}
		return len(groups[left].indexes) > len(groups[right].indexes)
	})
	partitions := make([][]int, workerCount)
	partitionBytes := make([]int, workerCount)
	for _, group := range groups {
		target := 0
		for candidate := 1; candidate < workerCount; candidate++ {
			if partitionBytes[candidate] < partitionBytes[target] ||
				(partitionBytes[candidate] == partitionBytes[target] && len(partitions[candidate]) < len(partitions[target])) {
				target = candidate
			}
		}
		partitions[target] = append(partitions[target], group.indexes...)
		partitionBytes[target] += group.bytes
	}
	for _, partition := range partitions {
		sort.Ints(partition)
	}
	return partitions
}

func rawTxPreparedSenders(prepared []rawTxPreparedTransaction) []common.Address {
	seen := make(map[common.Address]struct{})
	senders := make([]common.Address, 0)
	for _, item := range prepared {
		if item.err != nil || item.tx == nil {
			continue
		}
		if _, exists := seen[item.sender]; exists {
			continue
		}
		seen[item.sender] = struct{}{}
		senders = append(senders, item.sender)
	}
	return senders
}

func (s *PublicTransactionPoolAPI) prepareRawTxIngressJob(encoded []hexutil.Bytes, routeHints []types.TxRouteHint, current *types.Block) (prepared []rawTxPreparedTransaction, stats rawTxPreparationStats, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			prepared = nil
			stats = rawTxPreparationStats{}
			err = fmt.Errorf("prepare raw transaction batch: %v", recovered)
		}
	}()
	prepared, stats = s.prepareRawTransactions(encoded, routeHints, current)
	return prepared, stats, nil
}

func (s *PublicTransactionPoolAPI) prepareSingleRawTxIngressJobs(batch []*singleRawTxRequest, current *types.Block) (jobs []*rawTxIngressJob, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			jobs = nil
			err = fmt.Errorf("prepare raw transaction coalescer wave: %v", recovered)
		}
	}()
	encoded := make([]hexutil.Bytes, len(batch))
	routeHints := make([]types.TxRouteHint, len(batch))
	for index, request := range batch {
		encoded[index] = request.encoded
		routeHints[index] = request.routeHint
	}
	started := time.Now()
	prepared, stats := s.prepareRawTransactions(encoded, routeHints, current)
	log.Debug("Prepared raw transaction coalescer wave", "requested", len(encoded), "bytes", stats.totalBytes,
		"decode", stats.decode, "prepare", stats.prepare, "senderRecovery", stats.senderRecovery, "total", time.Since(started))
	partitions := s.partitionPreparedRawTransactions(encoded, prepared)
	jobs = make([]*rawTxIngressJob, 0, len(partitions))
	for _, partition := range partitions {
		job := &rawTxIngressJob{
			encoded:  make([]hexutil.Bytes, len(partition)),
			prepared: make([]rawTxPreparedTransaction, len(partition)),
			single:   make([]*singleRawTxRequest, len(partition)),
			current:  current,
			ctx:      context.Background(),
		}
		for position, index := range partition {
			job.encoded[position] = encoded[index]
			job.prepared[position] = prepared[index]
			job.single[position] = batch[index]
			job.pendingBytes += len(encoded[index])
		}
		job.pendingCount = len(partition)
		job.senders = rawTxPreparedSenders(job.prepared)
		// Each single request acquired one lifecycle unit at admission. The
		// backend job releases those units only after all responses are delivered.
		job.lifecycleUnits = len(partition)
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (s *PublicTransactionPoolAPI) submitRawTransactionBatch(ctx context.Context, encoded []hexutil.Bytes) ([]rawTxSubmissionResult, error) {
	if err := s.beginRawTxIngressProducer(); err != nil {
		return nil, err
	}
	defer s.rawTxLifecycleWG.Done()
	if err := validateRawTransactionRequest(encoded); err != nil {
		return nil, err
	}
	current := s.b.CurrentBlock()
	if current == nil {
		return nil, fmt.Errorf("current block is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	results := make([]rawTxSubmissionResult, len(encoded))
	resolved := make([]bool, len(encoded))
	workerCount := s.rawTxBackendWorkers
	if workerCount < 1 {
		workerCount = 1
	}
	maxOutstanding := workerCount * rawTxIngressOutstandingWaves
	completions := make(chan rawTxIngressCompletion, maxOutstanding)
	outstanding := 0
	workCtx := context.WithoutCancel(ctx)

	applyCompletion := func(completion rawTxIngressCompletion) {
		for position, resultIndex := range completion.indexes {
			if resultIndex < 0 || resultIndex >= len(results) {
				continue
			}
			if position < len(completion.results) {
				results[resultIndex] = completion.results[position]
			} else {
				results[resultIndex].err = fmt.Errorf("raw transaction backend omitted scheduled result")
			}
			resolved[resultIndex] = true
		}
		outstanding--
	}
	cancelUnresolved := func(err error) {
		for index := range results {
			if !resolved[index] {
				results[index].err = err
			}
		}
	}
	waitForCompletion := func() bool {
		select {
		case completion := <-completions:
			applyCompletion(completion)
			return true
		case <-ctx.Done():
			cancelUnresolved(ctx.Err())
			return false
		}
	}

	for _, batch := range splitRawTransactionMicroBatches(encoded) {
		// Do not decode an unbounded tail while two complete backend waves are
		// already node-owned. At most one 512-item prepared micro-batch exists
		// outside this fixed-size completion window.
		for outstanding >= maxOutstanding {
			if !waitForCompletion() {
				return results, nil
			}
		}
		if err := ctx.Err(); err != nil {
			cancelUnresolved(err)
			return results, nil
		}
		// A transaction larger than one transport batch cannot be forwarded
		// durably. Reject just that item without affecting neighboring items.
		if batch.oversized {
			results[batch.start].err = fmt.Errorf("raw transaction bytes %d exceed per-transaction limit %d", batch.bytes, MaxRawTxBatchBytes)
			resolved[batch.start] = true
			continue
		}
		if err := s.reserveRawTxIngressCapacity(batch.end-batch.start, batch.bytes); err != nil {
			for index := batch.start; index < len(results); index++ {
				results[index].err = err
				resolved[index] = true
			}
			break
		}
		batchEncoded := encoded[batch.start:batch.end]
		prepareStarted := time.Now()
		prepared, stats, err := s.prepareRawTxIngressJob(batchEncoded, nil, current)
		if err != nil {
			s.releaseRawTxIngressCapacity(batch.end-batch.start, batch.bytes)
			for index := batch.start; index < len(results); index++ {
				results[index].err = err
				resolved[index] = true
			}
			break
		}
		log.Debug("Prepared raw transaction batch", "requested", len(batchEncoded), "bytes", stats.totalBytes,
			"decode", stats.decode, "prepare", stats.prepare, "senderRecovery", stats.senderRecovery, "total", time.Since(prepareStarted))

		partitions := s.partitionPreparedRawTransactions(batchEncoded, prepared)
		if len(partitions) == 0 || len(partitions) > maxOutstanding {
			s.releaseRawTxIngressCapacity(batch.end-batch.start, batch.bytes)
			err := fmt.Errorf("raw transaction scheduler produced %d partitions for limit %d", len(partitions), maxOutstanding)
			for index := batch.start; index < len(results); index++ {
				results[index].err = err
				resolved[index] = true
			}
			break
		}
		for outstanding+len(partitions) > maxOutstanding {
			if !waitForCompletion() {
				s.releaseRawTxIngressCapacity(batch.end-batch.start, batch.bytes)
				return results, nil
			}
		}
		if err := ctx.Err(); err != nil {
			s.releaseRawTxIngressCapacity(batch.end-batch.start, batch.bytes)
			cancelUnresolved(err)
			return results, nil
		}

		jobs := make([]*rawTxIngressJob, 0, len(partitions))
		for _, partition := range partitions {
			job := &rawTxIngressJob{
				encoded:        make([]hexutil.Bytes, len(partition)),
				prepared:       make([]rawTxPreparedTransaction, len(partition)),
				resultIndexes:  make([]int, len(partition)),
				current:        current,
				ctx:            workCtx,
				completion:     completions,
				pendingCount:   len(partition),
				lifecycleUnits: 1,
			}
			for position, localIndex := range partition {
				job.encoded[position] = batchEncoded[localIndex]
				job.prepared[position] = prepared[localIndex]
				job.resultIndexes[position] = batch.start + localIndex
				job.pendingBytes += len(batchEncoded[localIndex])
			}
			job.senders = rawTxPreparedSenders(job.prepared)
			jobs = append(jobs, job)
		}
		// Seed hashes and deterministic preflight errors before enqueue. If the
		// RPC is cancelled while the backend is still running, the caller can
		// reconcile every admitted transaction without waiting for node work.
		for localIndex, item := range prepared {
			resultIndex := batch.start + localIndex
			if item.decoded && item.tx != nil {
				results[resultIndex].decoded = true
				results[resultIndex].hash = item.tx.Hash()
			}
			if item.err != nil {
				results[resultIndex].err = item.err
				resolved[resultIndex] = true
			}
		}
		// The producer lifecycle unit remains held while jobs are added, so a
		// concurrent Stop cannot begin its zero-counter Wait before these jobs
		// become visible to the scheduler.
		s.rawTxLifecycleWG.Add(len(jobs))
		s.enqueueReservedRawTxIngressJobs(jobs)
		outstanding += len(jobs)
	}
	// Work that crossed enqueue is node-owned and runs with cancellation
	// detached. The caller may abandon this wait; every admitted completion has
	// a buffered slot and the worker releases shared capacity before delivery.
	for outstanding > 0 {
		if !waitForCompletion() {
			return results, nil
		}
	}
	return results, nil
}

func (s *PublicTransactionPoolAPI) enqueueSingleRawTransaction(encodedTx hexutil.Bytes, routeHint types.TxRouteHint) (<-chan singleRawTxResponse, error) {
	if len(encodedTx) > MaxRawTxBatchBytes {
		return nil, fmt.Errorf("raw transaction bytes %d exceed per-transaction limit %d", len(encodedTx), MaxRawTxBatchBytes)
	}

	s.singleRawTxMu.Lock()
	if !s.rawTxAccepting {
		s.singleRawTxMu.Unlock()
		return nil, errRawTxIngressStopped
	}
	if err := s.rawTxIngressCapacityErrorLocked(1, len(encodedTx)); err != nil {
		s.singleRawTxMu.Unlock()
		return nil, err
	}
	// The RPC decoder owns encodedTx only for the lifetime of this call. Keep an
	// independent copy because cancellation stops waiting, not node-side work.
	request := &singleRawTxRequest{routeHint: routeHint, response: make(chan singleRawTxResponse, 1)}
	request.encoded = append(hexutil.Bytes(nil), encodedTx...)
	s.singleRawTxQueue = append(s.singleRawTxQueue, request)
	s.singleRawTxPendingCount++
	s.singleRawTxPendingBytes += len(request.encoded)
	s.rawTxLifecycleWG.Add(1)
	startWorker := !s.singleRawTxWorkerRunning
	if startWorker {
		s.singleRawTxWorkerRunning = true
		s.rawTxWorkerWG.Add(1)
	}
	s.singleRawTxMu.Unlock()

	if startWorker {
		go s.runSingleRawTxCoalescer()
	}
	return request.response, nil
}

func (s *PublicTransactionPoolAPI) takeSingleRawTxBatch() []*singleRawTxRequest {
	s.singleRawTxMu.Lock()
	defer s.singleRawTxMu.Unlock()

	if len(s.singleRawTxQueue) == 0 {
		s.singleRawTxWorkerRunning = false
		return nil
	}
	waveCount := s.rawTxBackendWorkers * MaxRawTxBatchCount
	waveBytes := s.rawTxBackendWorkers * MaxRawTxBatchBytes
	end, batchBytes := 0, 0
	for end < len(s.singleRawTxQueue) && end < waveCount {
		nextBytes := len(s.singleRawTxQueue[end].encoded)
		if end > 0 && nextBytes > waveBytes-batchBytes {
			break
		}
		batchBytes += nextBytes
		end++
	}
	batch := append([]*singleRawTxRequest(nil), s.singleRawTxQueue[:end]...)
	for index := 0; index < end; index++ {
		s.singleRawTxQueue[index] = nil
	}
	if end == len(s.singleRawTxQueue) {
		s.singleRawTxQueue = nil
	} else {
		s.singleRawTxQueue = s.singleRawTxQueue[end:]
	}
	return batch
}

func (s *PublicTransactionPoolAPI) runSingleRawTxCoalescer() {
	defer s.rawTxWorkerWG.Done()
	if delay := s.singleRawTxCoalesceDelay; delay > 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}
	for {
		batch := s.takeSingleRawTxBatch()
		if len(batch) == 0 {
			return
		}
		// RPC cancellation only abandons the response wait. Once admitted to this
		// bounded scheduler, durable pool/outbox submission belongs to the node.
		current := s.b.CurrentBlock()
		if current == nil {
			err := fmt.Errorf("current block is unavailable")
			batchBytes := 0
			for _, request := range batch {
				batchBytes += len(request.encoded)
			}
			s.releaseRawTxIngressCapacity(len(batch), batchBytes)
			deliverSingleRawTxResponses(batch, nil, err)
			s.rawTxLifecycleWG.Add(-len(batch))
			continue
		}
		jobs, err := s.prepareSingleRawTxIngressJobs(batch, current)
		if err != nil || len(jobs) == 0 {
			if err == nil {
				err = errors.New("raw transaction coalescer produced no backend jobs")
			}
			batchBytes := 0
			for _, request := range batch {
				batchBytes += len(request.encoded)
			}
			s.releaseRawTxIngressCapacity(len(batch), batchBytes)
			deliverSingleRawTxResponses(batch, nil, err)
			s.rawTxLifecycleWG.Add(-len(batch))
			continue
		}
		// Jobs retain direct request/result alignment and release their reserved
		// count and bytes independently. The collector immediately proceeds to the
		// next wave instead of waiting for this wave's backend completions.
		s.enqueueReservedRawTxIngressJobs(jobs)
	}
}

// SendRawTransactions accepts a bounded burst and submits it as fixed-size
// backend micro-batches. Structural request errors have no side effects;
// transaction-specific failures are returned in input order.
func (s *PublicTransactionPoolAPI) SendRawTransactions(ctx context.Context, encoded []hexutil.Bytes) ([]RawTxResult, error) {
	submissions, err := s.submitRawTransactionBatch(ctx, encoded)
	if err != nil {
		return nil, err
	}
	results := make([]RawTxResult, len(submissions))
	for i, submission := range submissions {
		if submission.decoded {
			hash := submission.hash
			results[i].Hash = &hash
		}
		if submission.err != nil {
			results[i].Error = submission.err.Error()
		}
	}
	return results, nil
}

// SendRawTransaction will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce.
func (s *PublicTransactionPoolAPI) SendRawTransaction(ctx context.Context, encodedTx hexutil.Bytes) (common.Hash, error) {
	return s.sendRawTransactionWithRoute(ctx, encodedTx, types.TxRouteFast)
}

func (s *PublicTransactionPoolAPI) sendRawTransactionWithRoute(ctx context.Context, encodedTx hexutil.Bytes, routeHint types.TxRouteHint) (common.Hash, error) {
	// A request cancelled before admission has not crossed the node-side work
	// boundary. Reject it without consuming coalescer capacity or creating
	// admission/outbox state. Cancellation after enqueue remains intentionally
	// detached so accepted durable work is never abandoned with the client.
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return common.Hash{}, err
		}
	}
	responseCh, err := s.enqueueSingleRawTransaction(encodedTx, routeHint)
	if err != nil {
		return common.Hash{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case response := <-responseCh:
		if response.err != nil {
			return common.Hash{}, response.err
		}
		if response.result.err != nil {
			return common.Hash{}, response.result.err
		}
		return response.result.hash, nil
	case <-ctx.Done():
		return common.Hash{}, ctx.Err()
	}
}

func (s *PublicTransactionPoolAPI) SendRawTransactionWithOpts(ctx context.Context, encodedTx hexutil.Bytes, opts SendTxOpts) (common.Hash, error) {
	log.Info("SendRawTransactionWithOpts")
	routeHint := types.TxRouteFast
	if opts.UseSlowLane {
		routeHint = types.TxRouteSlow
	}
	return s.sendRawTransactionWithRoute(ctx, encodedTx, routeHint)
}

// Sign calculates an ECDSA signature for:
// keccack256("\x19Ethereum Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign
func (s *PublicTransactionPoolAPI) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Sign the requested hash with the wallet
	signature, err := wallet.SignText(account, data)
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	}
	return signature, err
}

// SignTransactionResult represents a RLP encoded signed transaction.
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTransaction will sign the given transaction with the from account.
// The node needs to have the private key of the account corresponding with
// the given from address and it needs to be unlocked.
func (s *PublicTransactionPoolAPI) SignTransaction(ctx context.Context, args SendTxArgs) (*SignTransactionResult, error) {
	if !args.requestsNativeTransaction(s.b) && args.Gas == nil {
		return nil, fmt.Errorf("gas not specified")
	}
	if !args.requestsNativeTransaction(s.b) && args.Nonce == nil {
		return nil, fmt.Errorf("nonce not specified")
	}
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Before actually sign the transaction, ensure the transaction fee is reasonable.
	if err := checkTxFeeWithBlob(args.txFeeCapForValidation(), args.feeWorkForValidation(), args.blobFeeCapForValidation(), args.blobGasForFeeValidation(), s.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	tx, err := s.sign(args.From, args.toTransaction(args.transactionChainID(s.b)))
	if err != nil {
		return nil, err
	}
	data, err := marshalTransactionForRPC(tx)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, tx}, nil
}

// PendingTransactions returns the transactions that are in the transaction pool
// and have a from address that is one of the accounts this node manages.
func (s *PublicTransactionPoolAPI) PendingTransactions() ([]*RPCTransaction, error) {
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return nil, err
	}
	accounts := make(map[common.Address]struct{})
	for _, wallet := range s.b.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			accounts[account.Address] = struct{}{}
		}
	}
	transactions := make([]*RPCTransaction, 0, len(pending))
	for _, tx := range pending {
		signer := rpcTransactionSigner(tx)
		from, _ := types.Sender(signer, tx)
		if _, exists := accounts[from]; exists {
			transactions = append(transactions, newRPCPendingTransaction(tx))
		}
	}
	return transactions, nil
}

// Resend accepts an existing transaction and a new gas price and limit. It will remove
// the given transaction from the pool and reinsert it with the new gas price and limit.
func (s *PublicTransactionPoolAPI) Resend(ctx context.Context, sendArgs SendTxArgs, gasPrice *hexutil.Big, gasLimit *hexutil.Uint64) (common.Hash, error) {
	if sendArgs.Nonce == nil {
		return common.Hash{}, fmt.Errorf("missing transaction nonce in transaction spec")
	}
	if err := sendArgs.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	matchTx := sendArgs.toTransaction(sendArgs.transactionChainID(s.b))

	// Before replacing the old transaction, ensure the _new_ transaction fee is reasonable.
	var price = matchTx.GasPrice()
	if gasPrice != nil {
		price = gasPrice.ToInt()
	}
	var gas = matchTx.Gas()
	if gasLimit != nil {
		gas = uint64(*gasLimit)
	}
	if err := checkTxFeeWithBlob(price, gas, matchTx.BlobGasFeeCap(), matchTx.BlobGas(), s.b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	// Iterate the pending list for replacement
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return common.Hash{}, err
	}
	for _, p := range pending {
		signer := rpcTransactionSigner(p)
		wantSigHash := signer.Hash(matchTx)

		if pFrom, err := types.Sender(signer, p); err == nil && pFrom == sendArgs.From && signer.Hash(p) == wantSigHash {
			// Match. Re-sign and send the transaction.
			if gasPrice != nil && (*big.Int)(gasPrice).Sign() != 0 {
				sendArgs.GasPrice = gasPrice
			}
			if gasLimit != nil && *gasLimit != 0 {
				sendArgs.Gas = gasLimit
			}
			signedTx, err := s.sign(sendArgs.From, sendArgs.toTransaction(sendArgs.transactionChainID(s.b)))
			if err != nil {
				return common.Hash{}, err
			}
			if err = s.b.SendTx(ctx, signedTx, true); err != nil {
				return common.Hash{}, err
			}
			return signedTx.Hash(), nil
		}
	}

	return common.Hash{}, fmt.Errorf("transaction %#x not found", matchTx.Hash())
}

// PublicDebugAPI is the collection of Ethereum APIs exposed over the public
// debugging endpoint.
type PublicDebugAPI struct {
	b Backend
}

// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the Ethereum service.
func NewPublicDebugAPI(b Backend) *PublicDebugAPI {
	return &PublicDebugAPI{b: b}
}

// GetBlockRlp retrieves the RLP encoded for of a single block.
func (api *PublicDebugAPI) GetBlockRlp(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", encoded), nil
}

// TestSignCliqueBlock fetches the given block number, and attempts to sign it as a clique header with the
// given address, returning the address of the recovered signature
//
// This is a temporary method to debug the externalsigner integration,
// TODO: Remove this method when the integration is mature
func (api *PublicDebugAPI) TestSignCliqueBlock(ctx context.Context, address common.Address, number uint64) (common.Address, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return common.Address{}, fmt.Errorf("block #%d not found", number)
	}
	header := block.Header()
	header.Extra = make([]byte, 32+65)
	encoded := clique.CliqueRLP(header)

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: address}
	wallet, err := api.b.AccountManager().Find(account)
	if err != nil {
		return common.Address{}, err
	}

	signature, err := wallet.SignData(account, accounts.MimetypeClique, encoded)
	if err != nil {
		return common.Address{}, err
	}
	sealHash := clique.SealHash(header).Bytes()
	log.Info("test signing of clique block",
		"Sealhash", fmt.Sprintf("%x", sealHash),
		"signature", fmt.Sprintf("%x", signature))
	pubkey, err := crypto.Ecrecover(sealHash, signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer, nil
}

// PrintBlock retrieves a block and returns its pretty printed form.
func (api *PublicDebugAPI) PrintBlock(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return spew.Sdump(block), nil
}

// SeedHash retrieves the seed hash of a block.
func (api *PublicDebugAPI) SeedHash(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return fmt.Sprintf("0x%x", colossusX.SeedHash(number)), nil
}

// PrivateDebugAPI is the collection of Ethereum APIs exposed over the private
// debugging endpoint.
type PrivateDebugAPI struct {
	b Backend
}

// NewPrivateDebugAPI creates a new API definition for the private debug methods
// of the Ethereum service.
func NewPrivateDebugAPI(b Backend) *PrivateDebugAPI {
	return &PrivateDebugAPI{b: b}
}

// ChaindbProperty returns leveldb properties of the key-value database.
func (api *PrivateDebugAPI) ChaindbProperty(property string) (string, error) {
	if property == "" {
		property = "leveldb.stats"
	} else if !strings.HasPrefix(property, "leveldb.") {
		property = "leveldb." + property
	}
	return api.b.ChainDb().Stat(property)
}

// ChaindbCompact flattens the entire key-value database into a single level,
// removing all unused slots and merging all keys.
func (api *PrivateDebugAPI) ChaindbCompact() error {
	for b := byte(0); b < 255; b++ {
		log.Info("Compacting chain database", "range", fmt.Sprintf("0x%0.2X-0x%0.2X", b, b+1))
		if err := api.b.ChainDb().Compact([]byte{b}, []byte{b + 1}); err != nil {
			log.Error("Database compaction failed", "err", err)
			return err
		}
	}
	return nil
}

// SetHead rewinds the head of the blockchain to a previous block.
func (api *PrivateDebugAPI) SetHead(number hexutil.Uint64) {
	api.b.SetHead(uint64(number))
}

// PublicNetAPI offers network related RPC methods
type PublicNetAPI struct {
	net            *p2p.Server
	networkVersion uint64
}

// NewPublicNetAPI creates a new net API instance.
func NewPublicNetAPI(net *p2p.Server, networkVersion uint64) *PublicNetAPI {
	return &PublicNetAPI{net, networkVersion}
}

// Listening returns an indication if the node is listening for network connections.
func (s *PublicNetAPI) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
func (s *PublicNetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(s.net.PeerCount())
}

// Version returns the current ethereum protocol version.
func (s *PublicNetAPI) Version() string {
	return fmt.Sprintf("%d", s.networkVersion)
}

// checkTxFee is an internal function used to check whether the fee of
// the given transaction is _reasonable_(under the cap).
func checkTxFee(gasPrice *big.Int, gas uint64, cap float64) error {
	return checkTxFeeWithBlob(gasPrice, gas, nil, 0, cap)
}

// checkTxFeeWithBlob applies the RPC safety cap to the transaction's complete
// maximum fee exposure. EIP-4844 blob gas is a separate fee market, but it is
// still part of the amount a managed-account caller authorizes.
func checkTxFeeWithBlob(gasPrice *big.Int, gas uint64, blobGasPrice *big.Int, blobGas uint64, cap float64) error {
	// Short circuit if there is no cap for transaction fee at all.
	if cap == 0 {
		return nil
	}
	feeWei := new(big.Int)
	if gasPrice != nil && gas != 0 {
		feeWei.Mul(gasPrice, new(big.Int).SetUint64(gas))
	}
	if blobGasPrice != nil && blobGas != 0 {
		blobFee := new(big.Int).Mul(blobGasPrice, new(big.Int).SetUint64(blobGas))
		feeWei.Add(feeWei, blobFee)
	}
	feeEth := new(big.Float).Quo(new(big.Float).SetInt(feeWei), new(big.Float).SetInt(big.NewInt(params.Ether)))
	feeFloat, _ := feeEth.Float64()
	if feeFloat > cap {
		return fmt.Errorf("tx fee (%.2f ether) exceeds the configured cap (%.2f ether)", feeFloat, cap)
	}
	return nil
}

// PublicPowCandidateAPI offers and API for the pow candidate.
type PublicPowCandidateAPI struct {
	pc *core.CandidatePool
}

// PublicPowCandidateAPI creates a new pow candidate service that gives information about the pow candidates.
func NewPublicPowCandidateAPI(b Backend) *PublicPowCandidateAPI {
	return &PublicPowCandidateAPI{b.CandidatePool()}
}

type RPCCandidate struct {
	Version    string      `json:"version"`
	ParentHash common.Hash `json:"parentHash"`
	Number     *big.Int    `json:"number"`
	Difficulty *big.Int    `json:"difficulty"`

	Time      *big.Int         `json:"timestamp"`
	Nonce     types.BlockNonce `json:"nonce"`
	MixDigest common.Hash      `json:"mixDigest"`
	Ip        net.IP           `json:"ip"`
	PubKey    string           `json:"pubKey"`

	//Version				string					`json:"version"`
}

func (s *PublicPowCandidateAPI) Content() []RPCCandidate {
	candidates := s.pc.Content()
	result := make([]RPCCandidate, 0)

	for _, candidate := range candidates {
		rpcCandidate := RPCCandidate{
			ParentHash: candidate.KeyCandidate.ParentHash,
			Number:     candidate.KeyCandidate.Number,
			Difficulty: candidate.KeyCandidate.Difficulty,
			Time:       big.NewInt(int64(candidate.KeyCandidate.Time)),
			Nonce:      candidate.KeyCandidate.Nonce,
			MixDigest:  candidate.KeyCandidate.MixDigest,
			Ip:         candidate.IP,
			PubKey:     candidate.PubKey,
		}

		result = append(result, rpcCandidate)
	}

	return result
}
