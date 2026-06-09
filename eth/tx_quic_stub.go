// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

//go:build !txquic
// +build !txquic

package eth

import (
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/log"
)

// TxQUICIngress is a no-op implementation used for default GOPATH/vendor builds.
// Build with -tags txquic to enable the production QUIC transaction ingress.
type TxQUICIngress struct {
	config TxQUICConfig
}

func NewTxQUICIngress(config TxQUICConfig, txpool *core.TxPool) *TxQUICIngress {
	return &TxQUICIngress{config: config}
}

func (q *TxQUICIngress) Start() error {
	if q != nil && q.config.Enabled {
		log.Warn("TxQUIC ingress requested, but this binary was built without -tags txquic")
	}
	return nil
}

func (q *TxQUICIngress) Stop() {}
