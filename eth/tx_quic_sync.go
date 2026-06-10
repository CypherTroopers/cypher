// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package eth

import (
	"fmt"
	"strings"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/core/types"
)

func (q *TxQUICIngress) SendLocalTxsWithAdmissionsSync(txs []*types.Transaction, admissions []*types.CommonTxAdmission, am *accounts.Manager) error {
	if q == nil {
		return fmt.Errorf("txquic ingress is nil")
	}
	if !q.config.BridgeEnabled {
		return fmt.Errorf("txquic bridge is not enabled")
	}
	if len(txs) == 0 {
		return fmt.Errorf("no txs to forward")
	}

	payload, err := q.encodeTxPayload(txs, admissions, am)
	if err != nil {
		return err
	}

	endpoint, err := q.forwardPayloadSync(payload)
	if err != nil {
		return fmt.Errorf("txquic sync forward failed: txs=%d admissions=%d err=%w", len(txs), len(admissions), err)
	}

	txQUICIngressForwardMeter.Mark(1)
	log.Debug("TxQUIC bridge sync forwarded tx batch", "txs", len(txs), "admissions", len(admissions), "endpoint", endpoint, "forwarded", 1)
	return nil
}

func (q *TxQUICIngress) forwardPayloadSync(payload []byte) (string, error) {
	mode := strings.ToLower(q.config.RoutingMode)
	if mode == "local" || mode == "" {
		return "", fmt.Errorf("txquic sync forward has no remote endpoints in routing mode %q", q.config.RoutingMode)
	}

	endpoints := append([]string{}, q.config.LeaderEndpoints...)
	if mode == "committee-backup" {
		endpoints = append(endpoints, q.config.BackupEndpoints...)
	}
	if len(endpoints) == 0 {
		return "", fmt.Errorf("txquic sync forward has no endpoints")
	}

	errs := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if err := q.forwardPayload(endpoint, payload); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
			log.Debug("TxQUIC sync forward failed", "endpoint", endpoint, "err", err)
			continue
		}
		return endpoint, nil
	}

	return "", fmt.Errorf("all endpoints failed: %s", strings.Join(errs, "; "))
}
