package main

import (
	"context"
	"errors"
	"log"
	"math/big"
	"strings"
	"time"
)

func (s *rankingServer) queueAddressBackfill(address string) *backfillStatus {
	lower := strings.ToLower(address)
	if lower == "" {
		return nil
	}

	s.trackedMu.Lock()
	s.trackedAddresses[lower] = struct{}{}
	s.trackedMu.Unlock()

	s.backfillStateMu.Lock()
	if status, ok := s.backfillState[lower]; ok {
		s.backfillStateMu.Unlock()
		return status
	}

	status := &backfillStatus{state: "pending", done: make(chan struct{})}
	s.backfillState[lower] = status
	s.backfillStateMu.Unlock()

	go func(addr string, st *backfillStatus) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		err := s.backfillAddressHistory(ctx, addr)
		s.backfillStateMu.Lock()
		if err != nil {
			st.state = "error"
			st.err = err
			delete(s.backfillState, addr)
		} else {
			st.state = "complete"
		}
		close(st.done)
		s.backfillStateMu.Unlock()

		if err != nil {
			log.Printf("[BACKFILL] Failed to populate full history for %s: %v", addr, err)
		}
	}(lower, status)

	return status
}

func (s *rankingServer) ensureWalletHistoryCoverage(address string) {
	status := s.queueAddressBackfill(address)
	if status == nil {
		return
	}
	<-status.done
	if status.err != nil {
		log.Printf("[BACKFILL] History coverage attempt failed for %s: %v", address, status.err)
	}
}

func (s *rankingServer) backfillAddressHistory(ctx context.Context, address string) error {
	tracked := map[string]struct{}{address: {}}
	blockNumber, err := s.getBlockNumber(ctx)
	if err != nil {
		return err
	}

	log.Printf("[BACKFILL] start full history scan for %s from block #%s", address, blockNumber.String())
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
		if block != nil {
			transfers, _, _ := s.collectTransfers(block, tracked)
			if len(transfers) > 0 {
				s.transferStore.upsertMany(transfers)
			}
		}
		current.Sub(current, one)
	}

	log.Printf("[BACKFILL] completed full history scan for %s", address)
	return nil
}

func (s *rankingServer) getFlowSummary(ctx context.Context, address string) (*flowSummary, error) {
	now := time.Now()
	s.flowCacheMu.Lock()
	if entry, ok := s.flowCache[address]; ok {
		if now.Sub(entry.CachedAt) < flowCacheTTL {
			summary := entry.Summary
			s.flowCacheMu.Unlock()
			return summary, nil
		}
	}
	s.flowCacheMu.Unlock()

	summary := s.computeFlowSummary(address)
	if summary == nil {
		return nil, errors.New("failed to compute flow summary")
	}

	s.flowCacheMu.Lock()
	s.flowCache[address] = &flowCacheEntry{Summary: summary, CachedAt: now}
	s.flowCacheMu.Unlock()
	return summary, nil
}
