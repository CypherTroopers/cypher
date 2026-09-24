package reconfig_test

import (
	"context"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/rpc"
)

// The only host is an owned config3 CLX test process. This follows ordinary
// ETH network flow; it never inserts or repairs blocks from the coordinator.
func nativeETHTransport(b *reconfig.ReconfigBackend, dir string) (func() error, func(), error) {
	path := filepath.Join(dir, "eth-nodekey")
	key, err := crypto.LoadECDSA(path)
	if os.IsNotExist(err) {
		key, err = crypto.GenerateKey()
		if err == nil {
			err = crypto.SaveECDSA(path, key)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	listen := "127.0.0.1:0"
	saved, err := os.ReadFile(filepath.Join(dir, "eth-listen"))
	if err == nil {
		listen = string(saved)
		host, portText, e := net.SplitHostPort(listen)
		port, pErr := strconv.Atoi(portText)
		if e != nil || pErr != nil || host != "127.0.0.1" || port < 1 || port > 65535 {
			return nil, nil, errors.New("unsafe owned ETH listen endpoint")
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	chain := b.BlockChain()
	pm, err := eth.NewProtocolManager(chain.Config(), nil, downloader.FullSync, chain.Config().ChainID.Uint64(), b.EventMux(), b.TxPool(), b.Engine(), chain, b.ChainDb(), 0, nil, b.CandidatePool())
	if err != nil {
		return nil, nil, err
	}
	server := &p2p.Server{Config: p2p.Config{PrivateKey: key, Name: "native-clx-owned-fixture", NoDiscovery: true, MaxPeers: 16, ListenAddr: listen, Protocols: pm.Protocols()}}
	var started bool
	var mu sync.Mutex
	start := func() error {
		mu.Lock()
		defer mu.Unlock()
		if started {
			return nil
		}
		if err := server.Start(); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "eth-listen"), []byte(server.ListenAddr), 0600); err != nil {
			server.Stop()
			return err
		}
		pm.Start(16)
		started = true
		rewardETHPeers.Store(b, server.Self().URLv4())
		return nil
	}
	stop := func() {
		mu.Lock()
		defer mu.Unlock()
		if !started {
			return
		}
		rewardETHPeers.Delete(b)
		server.Stop()
		pm.Stop()
		started = false
	}
	return start, stop, nil
}
func (b *rewardReceiptBackend) BlockByNumber(_ context.Context, n rpc.BlockNumber) (*types.Block, error) {
	chain := b.backend.BlockChain()
	if n == rpc.LatestBlockNumber {
		return chain.CurrentBlock(), nil
	}
	if n < 0 {
		return nil, errors.New("explicit/latest block required")
	}
	block := chain.GetBlockByNumber(uint64(n))
	if block == nil {
		return nil, errors.New("canonical block unavailable")
	}
	return block, nil
}
func (b *rewardReceiptBackend) HeaderByNumber(ctx context.Context, n rpc.BlockNumber) (*types.Header, error) {
	block, err := b.BlockByNumber(ctx, n)
	if err != nil {
		return nil, err
	}
	return block.Header(), nil
}
func (b *rewardReceiptBackend) GetTd(_ context.Context, hash common.Hash) *big.Int {
	block := b.backend.BlockChain().GetBlockByHash(hash)
	if block == nil {
		return nil
	}
	return b.backend.BlockChain().GetTd(hash, block.NumberU64())
}
func (b *rewardReceiptBackend) KeyBlockByHash(_ context.Context, hash common.Hash) (*types.KeyBlock, error) {
	return b.backend.KeyBlockChain().GetBlockByHash(hash), nil
}
func (a *rewardReceiptAPI) BlockNumber() hexutil.Uint64 {
	return ethapi.NewPublicBlockChainAPI(a.backend).BlockNumber()
}
func (a *rewardReceiptAPI) GetBlockByNumber(ctx context.Context, n rpc.BlockNumber, full bool) (map[string]interface{}, error) {
	return ethapi.NewPublicBlockChainAPI(a.backend).GetBlockByNumber(ctx, n, full)
}
func (a *rewardReceiptAPI) GetCLXFinalityWitness(ctx context.Context, n rpc.BlockNumber) (*ethapi.CLXFinalityWitness, error) {
	return ethapi.NewPublicBlockChainAPI(a.backend).GetCLXFinalityWitness(ctx, n)
}
func (a *rewardReceiptAPI) GetDEXInboxEntries(ctx context.Context, hash common.Hash, start, count hexutil.Uint64) ([]hexutil.Bytes, error) {
	return ethapi.NewPublicBlockChainAPI(a.backend).GetDEXInboxEntries(ctx, hash, start, count)
}
