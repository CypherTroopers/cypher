package main

import (
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

type rankingServer struct {
	ipcPath                string
	basePath               string
	port                   int
	rpcClient              rpcCaller
	walletStore            *walletStore
	transferStore          *transferStore
	flowCache              map[string]*flowCacheEntry
	flowCacheMu            sync.Mutex
	trackedAddresses       map[string]struct{}
	trackedMu              sync.RWMutex
	latestBlockMu          sync.RWMutex
	latestProcessed        *big.Int
	backfillStateMu        sync.Mutex
	backfillState          map[string]*backfillStatus
	watchlist              []string
	metrics                *metricsState
	accountScan            *accountScanState
	scanMu                 sync.Mutex
	accountScanPageSize    int
	accountScanPagesPerRun int
	rpcRetryAttempts       int
	rpcRetryBackoff        time.Duration
}

func newRankingServer(ipcPath, basePath string, port int) (*rankingServer, error) {
	client, err := newIPCRPCClient(ipcPath)
	if err != nil {
		return nil, fmt.Errorf("connect ipc: %w", err)
	}

	srv := &rankingServer{
		ipcPath:                ipcPath,
		basePath:               basePath,
		port:                   port,
		rpcClient:              client,
		walletStore:            newWalletStore(),
		transferStore:          newTransferStore(),
		flowCache:              make(map[string]*flowCacheEntry),
		trackedAddresses:       make(map[string]struct{}),
		latestProcessed:        big.NewInt(0),
		backfillState:          make(map[string]*backfillStatus),
		watchlist:              parseAddressList(os.Getenv("WATCHLIST_ADDRESSES"), nil),
		metrics:                newMetricsState(),
		accountScan:            &accountScanState{},
		accountScanPageSize:    defaultAccountScanPageSize,
		accountScanPagesPerRun: defaultAccountScanPages,
		rpcRetryAttempts:       defaultRPCRetryAttempts,
		rpcRetryBackoff:        defaultRPCRetryBackoff,
	}

	srv.accountScanPageSize = getEnvInt("ACCOUNT_SCAN_PAGE_SIZE", 1, srv.accountScanPageSize)
	srv.accountScanPagesPerRun = getEnvInt("ACCOUNT_SCAN_PAGES_PER_TICK", 0, srv.accountScanPagesPerRun)
	srv.rpcRetryAttempts = getEnvInt("RPC_RETRY_ATTEMPTS", 1, srv.rpcRetryAttempts)
	srv.rpcRetryBackoff = getEnvDuration("RPC_RETRY_BACKOFF", srv.rpcRetryBackoff)

	tracked := parseAddressList(os.Getenv("TRACKED_ADDRESSES"), defaultTrackedAddresses)
	for _, addr := range tracked {
		srv.trackedAddresses[addr] = struct{}{}
	}
	return srv, nil
}

func (s *rankingServer) close() {
	if s.rpcClient != nil {
		s.rpcClient.Close()
	}
}
