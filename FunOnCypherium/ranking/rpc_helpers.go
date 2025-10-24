package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"
)

func (s *rankingServer) fetchBalance(ctx context.Context, address string) (*big.Int, error) {
	var hex string
	addr := normalizeHexString(address)
	if err := s.callContext(ctx, &hex, "eth_getBalance", addr, "latest"); err != nil {
		return nil, err
	}
	return parseHexBig(hex)
}

func parseHexBig(hexValue string) (*big.Int, error) {
	if strings.TrimSpace(hexValue) == "" {
		return big.NewInt(0), nil
	}
	value, err := parseBigIntString(hexValue)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (s *rankingServer) fetchBlock(ctx context.Context, number *big.Int) (*rpcBlock, error) {
	tag := "latest"
	if number != nil {
		tag = fmt.Sprintf("0x%x", number)
	}

	var block *rpcBlock
	if err := s.callContext(ctx, &block, "eth_getBlockByNumber", tag, true); err != nil {
		return nil, err
	}
	return block, nil
}

func parseBlockTimestamp(raw *flexibleHexUint64) time.Time {
	if raw == nil {
		return time.Unix(0, 0)
	}
	ts := raw.Uint64()
	if ts > 1_000_000_000_000 {
		ts /= 1000
	}
	return time.Unix(int64(ts), 0)
}

func (s *rankingServer) collectTransfers(block *rpcBlock, tracked map[string]struct{}) ([]*transfer, map[string]struct{}, time.Time) {
	transfers := make([]*transfer, 0)
	addresses := make(map[string]struct{})
	if block == nil {
		return transfers, addresses, time.Unix(0, 0)
	}

	timestamp := parseBlockTimestamp(block.Timestamp)
	for _, tx := range block.Transactions {
		from := normalizeHexString(tx.From)
		var to string
		if tx.To != nil {
			to = normalizeHexString(*tx.To)
		}

		if from != "" {
			addresses[from] = struct{}{}
		}
		if to != "" {
			addresses[to] = struct{}{}
		}

		track := true
		if tracked != nil {
			_, fromTracked := tracked[from]
			_, toTracked := tracked[to]
			track = fromTracked || toTracked
		}
		if !track {
			continue
		}

		value := big.NewInt(0)
		if tx.Value != nil {
			if v := tx.Value.Int(); v != nil {
				value = new(big.Int).Set(v)
			}
		}

		transfers = append(transfers, &transfer{
			Hash:      normalizeHexString(tx.Hash),
			From:      from,
			To:        to,
			Value:     value,
			Timestamp: timestamp,
		})
	}

	return transfers, addresses, timestamp
}

func (s *rankingServer) collectTrackedTransfers(block *rpcBlock) ([]*transfer, map[string]struct{}, time.Time) {
	return s.collectTransfers(block, s.copyTrackedAddresses())
}

func (s *rankingServer) copyTrackedAddresses() map[string]struct{} {
	s.trackedMu.RLock()
	defer s.trackedMu.RUnlock()
	copied := make(map[string]struct{}, len(s.trackedAddresses))
	for addr := range s.trackedAddresses {
		copied[addr] = struct{}{}
	}
	return copied
}

func (s *rankingServer) fetchAndStoreBalances(ctx context.Context, addresses []string) error {
	if len(addresses) == 0 {
		return nil
	}

	for _, addr := range addresses {
		balance, err := s.fetchBalance(ctx, addr)
		if err != nil {
			log.Printf("[RPC] balance fetch failed for %s: %v", addr, err)
			continue
		}
		s.walletStore.upsert(addr, balance)
	}

	return nil
}

func normalizeHexString(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "0x") && !strings.HasPrefix(trimmed, "0X") {
		trimmed = "0x" + trimmed
	}
	return strings.ToLower(trimmed)
}
