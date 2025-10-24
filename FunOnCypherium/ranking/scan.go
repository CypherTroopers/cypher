package main

import (
	"context"
	"log"
	"math/big"
	"time"
)

func (s *rankingServer) scanStateAccounts(ctx context.Context) error {
	return s.scanStateAccountsWithLimit(ctx, s.accountScanPagesPerRun)
}

func (s *rankingServer) scanStateAccountsWithLimit(ctx context.Context, maxPages int) error {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	startTime := time.Now()

	s.accountScan.mu.Lock()
	cursor := s.accountScan.cursor
	if cursor == "" {
		s.accountScan.cycleStart = startTime
	}
	s.accountScan.mu.Unlock()

	pageSize := s.accountScanPageSize
	if pageSize <= 0 {
		pageSize = defaultAccountScanPageSize
	}

	pages := 0
	currentCursor := cursor
	var lastErr error

	for {
		if maxPages > 0 && pages >= maxPages {
			break
		}

		var resp accountRangeResponse
		if err := s.callContext(ctx, &resp, "debug_accountRange", "latest", currentCursor, pageSize, true, true, false); err != nil {
			lastErr = err
			break
		}

		for addr, account := range resp.Accounts {
			balance := big.NewInt(0)
			if account.Balance != nil {
				balance.Set(account.Balance.Int())
			}
			s.walletStore.upsert(addr, balance)
		}

		pages++
		if resp.Next == "" {
			s.accountScan.mu.Lock()
			cycleStart := s.accountScan.cycleStart
			s.accountScan.cursor = ""
			s.accountScan.cycleStart = time.Time{}
			s.accountScan.mu.Unlock()

			var cycleDuration time.Duration
			if !cycleStart.IsZero() {
				cycleDuration = time.Since(cycleStart)
			}
			s.metrics.recordAccountScan(pages, time.Since(startTime), nil, true, cycleDuration)
			log.Printf("[SCAN] completed full account scan (%d pages)", pages)
			return nil
		}

		currentCursor = resp.Next
		s.accountScan.mu.Lock()
		s.accountScan.cursor = currentCursor
		s.accountScan.mu.Unlock()

		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
	}

	s.metrics.recordAccountScan(pages, time.Since(startTime), lastErr, false, 0)
	if lastErr != nil {
		log.Printf("[SCAN] halted after %d pages from cursor %q: %v", pages, currentCursor, lastErr)
		return lastErr
	}

	log.Printf("[SCAN] processed %d pages, next cursor %q", pages, currentCursor)
	return nil
}

func (s *rankingServer) updateWatchlistBalances(ctx context.Context) error {
	if len(s.watchlist) == 0 {
		return nil
	}
	return s.fetchAndStoreBalances(ctx, s.watchlist)
}

func (s *rankingServer) backfillLastNDays(ctx context.Context, days int) error {
	if days <= 0 {
		return nil
	}
	minTimestamp := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	blockNumber, err := s.getBlockNumber(ctx)
	if err != nil {
		return err
	}

	log.Printf("[BACKFILL] start: last %dd from head #%s", days, blockNumber.String())
	current := new(big.Int).Set(blockNumber)
	zero := big.NewInt(0)
	one := big.NewInt(1)

	for current.Cmp(zero) >= 0 {
		block, err := s.fetchBlock(ctx, current)
		if err != nil {
			log.Printf("[BACKFILL] block %s fetch failed: %v", current.String(), err)
			current.Sub(current, one)
			continue
		}
		if block == nil {
			current.Sub(current, one)
			continue
		}

		transfers, _, timestamp := s.collectTrackedTransfers(block)
		if len(transfers) > 0 {
			s.transferStore.upsertMany(transfers)
		}

		if timestamp.Before(minTimestamp) {
			break
		}
		current.Sub(current, one)
	}

	s.clearFlowCache()
	log.Printf("[BACKFILL] done")
	return nil
}

func (s *rankingServer) ensureRecentTransferHistory(ctx context.Context) error {
	tracked := s.copyTrackedAddresses()
	if len(tracked) == 0 {
		return nil
	}

	minTimestamp := time.Now().Add(-7 * 24 * time.Hour)
	for addr := range tracked {
		transfers := s.transferStore.forAddress(addr, minTimestamp)
		if len(transfers) > 0 {
			return nil
		}
	}

	log.Printf("[BACKFILL] Filling last 7 days for tracked addresses...")
	return s.backfillLastNDays(ctx, 7)
}
