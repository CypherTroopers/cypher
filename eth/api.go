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

package eth

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"

	"runtime"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
	"github.com/cypherium/cypher/trie"
	//"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"golang.org/x/crypto/ed25519"
)

// PublicEthereumAPI provides an API to access Ethereum full node-related
// information.
type PublicEthereumAPI struct {
	e *Ethereum
}

// NewPublicEthereumAPI creates a new Ethereum protocol API for full nodes.
func NewPublicEthereumAPI(e *Ethereum) *PublicEthereumAPI {
	return &PublicEthereumAPI{e}
}

// Etherbase is the address that mining rewards will be send to
func (api *PublicEthereumAPI) Etherbase() (common.Address, error) {
	return api.e.Etherbase()
}

// Coinbase is the address that mining rewards will be send to (alias for Etherbase)
func (api *PublicEthereumAPI) Coinbase() (common.Address, error) {
	return api.Etherbase()
}

// Hashrate returns the POW hashrate
func (api *PublicEthereumAPI) Hashrate() hexutil.Uint64 {
	return hexutil.Uint64(api.e.Miner().HashRate())
}

// ChainId is the EIP-155 replay-protection chain id for the current ethereum chain config.
func (api *PublicEthereumAPI) ChainId() hexutil.Uint64 {
	chainID := api.e.blockchain.Config().ChainID
	return (hexutil.Uint64)(chainID.Uint64())
}

// CommonTxInfo returns Cypherium common RPC admission and reward information for a finalized tx.
func (api *PublicEthereumAPI) CommonTxInfo(hash common.Hash) (map[string]interface{}, error) {
	_, blockHash, blockNumber, index := rawdb.ReadTransaction(api.e.chainDb, hash)
	if blockHash == (common.Hash{}) {
		return nil, nil
	}
	block := api.e.blockchain.GetBlock(blockHash, blockNumber)
	if block == nil {
		return nil, nil
	}
	header := block.Header()
	fields := map[string]interface{}{
		"transactionHash":       hash,
		"blockHash":             blockHash,
		"blockNumber":           hexutil.Uint64(blockNumber),
		"transactionIndex":      hexutil.Uint64(index),
		"commonTxAdmissionRoot": header.CommonTxAdmissionRoot,
		"commonTxRewardRoot":    header.CommonTxRewardRoot,
	}
	for _, admission := range block.CommonTxAdmissions() {
		if admission == nil || admission.TxHash != hash {
			continue
		}
		fields["commonRpcMiner"] = admission.Miner
		fields["commonTxAdmissionChainId"] = (*hexutil.Big)(admission.ChainID)
		fields["commonTxAdmissionKeyBlockNumber"] = hexutil.Uint64(admission.KeyBlockNumber)
		fields["commonTxAdmissionTxBlockNumber"] = hexutil.Uint64(admission.TxBlockNumber)
		fields["commonTxAdmissionTimestamp"] = hexutil.Uint64(admission.Timestamp)
		fields["commonTxAdmissionSignature"] = hexutil.Bytes(admission.Signature)
		break
	}
	for _, reward := range block.CommonTxRewards() {
		if reward == nil || reward.TxHash != hash {
			continue
		}
		fields["commonRpcMiner"] = reward.Miner
		fields["commonRpcReward"] = (*hexutil.Big)(reward.Reward)
		fields["commonRpcBurn"] = (*hexutil.Big)(reward.Burn)
		break
	}
	return fields, nil
}

func (api *PublicEthereumAPI) Status() string {
	var s string
	i := bftview.IamMember()

	if i >= 0 {
		if i == 0 {
			s = "I'm leader."
		} else {
			s = "I'm committee member."
		}
	} else {
		s += "I'm common node."

	}
	if api.e.IsMining() {
		s += "is Running."
	} else {
		s += "Stopped."
	}
	if api.e.ServiceIsRunning() {
		s += "&& in service."
	} else {
		s += "&& not in service."
	}
	return s
}
func (api *PublicEthereumAPI) CommitteeMembers(ctx context.Context, blockNr rpc.BlockNumber) ([]*common.Cnode, error) {

	c, err := api.e.APIBackend.CommitteeMembers(ctx, blockNr)
	return c, err
}

// PublicMinerAPI provides an API to control the miner.
// It offers only methods that operate on data that pose no security risk when it is publicly accessible.
type PublicMinerAPI struct {
	e *Ethereum
}

// NewPublicMinerAPI create a new PublicMinerAPI instance.
func NewPublicMinerAPI(e *Ethereum) *PublicMinerAPI {
	return &PublicMinerAPI{e}
}

// Mining returns an indication if this node is currently mining.
func (api *PublicMinerAPI) Mining() bool {
	return api.e.IsMining()
}

// PrivateMinerAPI provides private RPC methods to control the miner.
// These methods can be abused by external users and must be considered insecure for use by untrusted users.
type PrivateMinerAPI struct {
	e *Ethereum
}

// NewPrivateMinerAPI create a new RPC service which controls the miner of this node.
func NewPrivateMinerAPI(e *Ethereum) *PrivateMinerAPI {
	return &PrivateMinerAPI{e: e}
}

// Start starts the miner with the given number of threads. If threads is nil,
// the number of workers started is equal to the number of logical CPUs that are
// usable by this process. If mining is already running, this method adjust the
// number of threads allowed to use and updates the minimum price required by the
// transaction pool.
/*??
func (api *PrivateMinerAPI) Start(threads *int) error {
	if threads == nil {
		return api.e.StartMining(runtime.NumCPU())
	}
	return api.e.StartMining(*threads)
}

*/
func (api *PrivateMinerAPI) Start(threads *int, addr common.Address, password string) (string, error) {
	miningThreads := runtime.NumCPU()
	if threads != nil {
		miningThreads = *threads
	}
	if api.e.IsMining() {
		api.e.setMiningThreads(miningThreads)
		return "Mining threads updated", nil
	}

	var (
		err    error
		eb     common.Address
		prvKey ed25519.PrivateKey
		pubKey ed25519.PublicKey
	)

	//log.Info("miner.start", "threads", miningThreads, "addr", addr, "passwd", password)

	server := &common.NodeConfig{}

	if addr != (common.Address{}) {
		eb = addr
	}

	for _, wallet := range api.e.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			if account.Address == eb {
				//wallet.GetPubKey(account, passwd)
				pubKey, prvKey, err = wallet.GetKeyPair(account, password)
				if err != nil {
					log.Error("Cannot start reconfig without public key of coinbase", "err", err)
					return "", fmt.Errorf("Coinbase missing public key: %v", err)
				}
				server.Public = common.HexString(pubKey)
				server.Private = common.HexString(prvKey)
				//log.Info("miner.start", "addr", eb, "pub", server.Public)
			}
		}
	}

	if pubKey == nil || prvKey == nil {
		log.Error("Cannot start reconfig without correct public key")
		return "", errors.New("missing public key")
	}
	log.Warn("pubKey", "pubKey", server.Public) //, "prvKey", server.Private)
	log.Warn("exip", "ip", api.e.ExtIP(), "port", api.e.config.RnetPort)
	server.Ip = api.e.ExtIP().String()
	server.Port = api.e.config.RnetPort
	server.Coinbase = eb.Hex()
	api.e.reconfig.MinerStart(server)
	// Start the miner and return
	// Set the number of threads if the seal engine supports it
	//if threads == nil {
	//	threads = new(int)
	//} else if *threads == 0 {
	//	*threads = -1 // Disable the miner from within
	//}
	//type threaded interface {
	//	SetThreads(threads int)
	//}
	//if th, ok := api.e.engine.(threaded); ok {
	//	log.Info("Updated mining threads", "threads", *threads)
	//	th.SetThreads(*threads)
	//}
	if err := api.e.StartMining(miningThreads, true, eb, pubKey); err != nil {
		return "", err
	}
	return "Mining started", nil
}

// Stop terminates the miner, both at the consensus engine level as well as at
// the block creation level.
func (api *PrivateMinerAPI) Stop() {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := api.e.engine.(threaded); ok {
		th.SetThreads(-1)
	}
	api.e.StopMining()
	api.e.reconfig.MinerStop()
}

func (api *PrivateMinerAPI) Status() string {
	var s string
	i := bftview.IamMember()
	if i >= 0 {
		if i == 0 {
			s = "I'm leader."
		} else {
			s = "I'm committee member."
		}
	} else {
		s = "I'm common node."

	}
	return s
}
