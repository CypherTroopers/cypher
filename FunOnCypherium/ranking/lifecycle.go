package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"
)

func (s *rankingServer) clearFlowCache() {
	s.flowCacheMu.Lock()
	s.flowCache = make(map[string]*flowCacheEntry)
	s.flowCacheMu.Unlock()
}

func (s *rankingServer) updateNewBlocks(ctx context.Context) error {
	latest, err := s.getBlockNumber(ctx)
	if err != nil {
		return err
	}

	s.latestBlockMu.RLock()
	start := new(big.Int).Set(s.latestProcessed)
	s.latestBlockMu.RUnlock()

	if latest.Cmp(start) <= 0 {
		return nil
	}

	addresses := make(map[string]struct{})
	newTransfers := make([]*transfer, 0)

	cursor := new(big.Int).Add(start, big.NewInt(1))
	for cursor.Cmp(latest) <= 0 {
		block, err := s.fetchBlock(ctx, cursor)
		if err != nil {
			log.Printf("[BLOCK] fetch %s failed: %v", cursor.String(), err)
			cursor.Add(cursor, big.NewInt(1))
			continue
		}
		if block != nil {
			transfers, addrSet, _ := s.collectTrackedTransfers(block)
			for addr := range addrSet {
				addresses[addr] = struct{}{}
			}
			if len(transfers) > 0 {
				newTransfers = append(newTransfers, transfers...)
			}
		}
		cursor.Add(cursor, big.NewInt(1))
	}

	if len(addresses) > 0 {
		unique := make([]string, 0, len(addresses))
		for addr := range addresses {
			unique = append(unique, addr)
		}
		if err := s.fetchAndStoreBalances(ctx, unique); err != nil {
			log.Printf("[BLOCK] balance refresh failed: %v", err)
		}
	}

	if len(newTransfers) > 0 {
		s.transferStore.upsertMany(newTransfers)
		s.clearFlowCache()
	}

	s.latestBlockMu.Lock()
	s.latestProcessed = latest
	s.latestBlockMu.Unlock()
	s.metrics.recordBlockUpdate(time.Now())
	return nil
}

func (s *rankingServer) runTicker(interval time.Duration, job func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), interval)
		job(ctx)
		cancel()
		<-ticker.C
	}
}

func (s *rankingServer) startSchedulers() {
	go s.runTicker(30*time.Second, func(ctx context.Context) {
		if err := s.updateNewBlocks(ctx); err != nil {
			log.Printf("[CRON] update blocks failed: %v", err)
		}
		if err := s.updateWatchlistBalances(ctx); err != nil {
			log.Printf("[CRON] watchlist refresh failed: %v", err)
		}
	})

	go s.runTicker(3*time.Minute, func(ctx context.Context) {
		log.Printf("[CRON] Full account scan via debug_accountRange")
		if err := s.scanStateAccounts(ctx); err != nil {
			log.Printf("[CRON] state scan failed: %v", err)
		}
	})
}

func (s *rankingServer) bootstrap(ctx context.Context) error {
	if _, err := s.getBlockNumber(ctx); err != nil {
		return fmt.Errorf("ping block number: %w", err)
	}

	if err := s.scanStateAccounts(ctx); err != nil {
		log.Printf("[INIT] scanStateAccounts failed: %v", err)
	}

	head, err := s.getBlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("head block: %w", err)
	}
	s.latestBlockMu.Lock()
	s.latestProcessed = head
	s.latestBlockMu.Unlock()

	if err := s.ensureRecentTransferHistory(ctx); err != nil {
		log.Printf("[INIT] ensureRecentTransferHistory failed: %v", err)
	}
	if err := s.updateWatchlistBalances(ctx); err != nil {
		log.Printf("[INIT] updateWatchlistBalances failed: %v", err)
	}

	s.startSchedulers()
	return nil
}
