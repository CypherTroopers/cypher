package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type metricsState struct {
	mu                          sync.RWMutex
	lastAccountScan             time.Time
	lastAccountScanDuration     time.Duration
	lastAccountScanPages        int
	lastAccountScanCompleted    bool
	lastAccountScanError        string
	lastFullAccountScan         time.Time
	lastFullAccountScanDuration time.Duration
	lastBlockUpdate             time.Time
	rpcFailures                 uint64
	rpcRetries                  uint64
}

type metricsSnapshot struct {
	LastAccountScan                   time.Time `json:"lastAccountScan"`
	LastAccountScanDurationMillis     int64     `json:"lastAccountScanDurationMillis"`
	LastAccountScanPages              int       `json:"lastAccountScanPages"`
	LastAccountScanCompleted          bool      `json:"lastAccountScanCompleted"`
	LastAccountScanError              string    `json:"lastAccountScanError,omitempty"`
	LastFullAccountScan               time.Time `json:"lastFullAccountScan"`
	LastFullAccountScanDurationMillis int64     `json:"lastFullAccountScanDurationMillis"`
	LastBlockUpdate                   time.Time `json:"lastBlockUpdate"`
	RPCFailures                       uint64    `json:"rpcFailures"`
	RPCRetries                        uint64    `json:"rpcRetries"`
	AccountScanCursor                 string    `json:"accountScanCursor"`
	AccountScanCycleStartedAt         time.Time `json:"accountScanCycleStartedAt"`
}

type accountScanState struct {
	mu         sync.Mutex
	cursor     string
	cycleStart time.Time
}

type accountScanSnapshot struct {
	Cursor         string
	CycleStartedAt time.Time
}

func newMetricsState() *metricsState {
	return &metricsState{}
}

func (m *metricsState) recordAccountScan(pages int, duration time.Duration, err error, completed bool, cycleDuration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.lastAccountScan = now
	m.lastAccountScanDuration = duration
	m.lastAccountScanPages = pages
	m.lastAccountScanCompleted = completed
	if err != nil {
		m.lastAccountScanError = err.Error()
	} else {
		m.lastAccountScanError = ""
	}
	if completed {
		m.lastFullAccountScan = now
		m.lastFullAccountScanDuration = cycleDuration
	}
}

func (m *metricsState) recordBlockUpdate(ts time.Time) {
	m.mu.Lock()
	m.lastBlockUpdate = ts
	m.mu.Unlock()
}

func (m *metricsState) recordRPCFailure() {
	atomic.AddUint64(&m.rpcFailures, 1)
}

func (m *metricsState) recordRPCRetry(extra int) {
	if extra > 0 {
		atomic.AddUint64(&m.rpcRetries, uint64(extra))
	}
}

func (m *metricsState) snapshot() metricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snap := metricsSnapshot{
		LastAccountScan:                   m.lastAccountScan,
		LastAccountScanDurationMillis:     durationToMillis(m.lastAccountScanDuration),
		LastAccountScanPages:              m.lastAccountScanPages,
		LastAccountScanCompleted:          m.lastAccountScanCompleted,
		LastFullAccountScan:               m.lastFullAccountScan,
		LastFullAccountScanDurationMillis: durationToMillis(m.lastFullAccountScanDuration),
		LastBlockUpdate:                   m.lastBlockUpdate,
		RPCFailures:                       atomic.LoadUint64(&m.rpcFailures),
		RPCRetries:                        atomic.LoadUint64(&m.rpcRetries),
	}
	if m.lastAccountScanError != "" {
		snap.LastAccountScanError = m.lastAccountScanError
	}
	return snap
}

func (a *accountScanState) snapshot() accountScanSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return accountScanSnapshot{
		Cursor:         a.cursor,
		CycleStartedAt: a.cycleStart,
	}
}
