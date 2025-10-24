package main

import (
	"context"
	"math/big"
	"strings"
	"time"
)

func (s *rankingServer) callContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	attempts := s.rpcRetryAttempts
	if attempts <= 0 {
		attempts = 1
	}

	backoff := s.rpcRetryBackoff
	if backoff <= 0 {
		backoff = defaultRPCRetryBackoff
	}

	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		err = s.rpcClient.CallContext(ctx, result, method, args...)
		if err == nil {
			if attempt > 0 {
				s.metrics.recordRPCRetry(attempt)
			}
			return nil
		}

		if ctx.Err() != nil {
			break
		}

		s.metrics.recordRPCFailure()

		if attempt == attempts-1 {
			break
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff *= 2
	}

	return err
}

func (s *rankingServer) getBlockNumber(ctx context.Context) (*big.Int, error) {
	var hex string
	if err := s.callContext(ctx, &hex, "eth_blockNumber"); err != nil {
		return nil, err
	}
	value := new(big.Int)
	if len(hex) == 0 {
		return value, nil
	}
	if strings.HasPrefix(hex, "0x") {
		hex = hex[2:]
	}
	value.SetString(hex, 16)
	return value, nil
}
