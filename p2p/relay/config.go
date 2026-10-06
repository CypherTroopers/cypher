// Package relay implements bounded request/response routing over authenticated
// RLPx peers. Only application-verified replies can complete a request.
package relay

import (
	"fmt"
	"time"
)

const (
	Version    = 1
	MaxPayload = 4 * 1024 * 1024
	MaxReply   = 272 * 1024 // includes 512 bounded TxQUIC permanent outcomes
	maxWire    = MaxPayload + 4096
)

type Config struct {
	Enabled           bool
	Gateway           bool
	MaxPeers          int
	ReservedSlots     int `toml:"-"`
	MaxPending        int
	MaxPendingBytes   int64
	PeerPending       int
	PeerPendingBytes  int64
	PeerQueue         int
	PeerQueueBytes    int64
	Workers           int
	GatewayWorkers    int
	Fanout            int
	Hops              uint64
	Timeout           time.Duration
	RequestsPerSecond int
	BytesPerSecond    int64
	CacheEntries      int
	CacheBytes        int64
}

func (c Config) normalized() (Config, error) {
	if c.MaxPeers == 0 {
		c.MaxPeers = 64
	}
	if c.MaxPending == 0 {
		c.MaxPending = 128
	}
	if c.MaxPendingBytes == 0 {
		c.MaxPendingBytes = 128 << 20
	}
	if c.PeerPending == 0 {
		c.PeerPending = min(16, c.MaxPending)
	}
	if c.PeerPendingBytes == 0 {
		c.PeerPendingBytes = min(int64(16<<20), c.MaxPendingBytes)
	}
	if c.PeerQueue == 0 {
		c.PeerQueue = 16
	}
	if c.PeerQueueBytes == 0 {
		c.PeerQueueBytes = 8 << 20
	}
	if c.Workers == 0 {
		c.Workers = 4
	}
	if c.GatewayWorkers == 0 {
		c.GatewayWorkers = 8
	}
	if c.Fanout == 0 {
		c.Fanout = 2
	}
	if c.Hops == 0 {
		c.Hops = 3
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	if c.RequestsPerSecond == 0 {
		c.RequestsPerSecond = 64
	}
	if c.BytesPerSecond == 0 {
		c.BytesPerSecond = 8 << 20
	}
	if c.CacheEntries == 0 {
		c.CacheEntries = 128
	}
	if c.CacheBytes == 0 {
		c.CacheBytes = 4 << 20
	}
	if c.ReservedSlots < 0 || c.ReservedSlots > c.MaxPeers || c.MaxPeers < 1 || c.MaxPeers > 256 || c.MaxPending < 1 || c.MaxPending > 4096 ||
		c.MaxPendingBytes < MaxPayload || c.MaxPendingBytes > 1<<30 ||
		c.PeerPending < 1 || c.PeerPending > c.MaxPending || c.PeerPendingBytes < MaxPayload || c.PeerPendingBytes > c.MaxPendingBytes ||
		c.PeerQueue < 1 || c.PeerQueue > 256 || c.PeerQueueBytes < maxWire || c.PeerQueueBytes > 64<<20 ||
		c.Workers < 1 || c.Workers > 32 || c.GatewayWorkers < 1 || c.GatewayWorkers > 32 ||
		c.Fanout < 1 || c.Fanout > 3 || c.Hops > 4 || c.Timeout < time.Second || c.Timeout > 30*time.Second ||
		c.RequestsPerSecond < 1 || c.RequestsPerSecond > 10000 || c.BytesPerSecond < 1 || c.BytesPerSecond > 1<<30 ||
		c.CacheEntries < 1 || c.CacheEntries > 4096 || c.CacheBytes < MaxReply || c.CacheBytes > 64<<20 {
		return c, fmt.Errorf("invalid relay resource limits")
	}
	return c, nil
}
