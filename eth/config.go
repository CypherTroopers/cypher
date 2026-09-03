// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/eth/gasprice"
	"github.com/cypherium/cypher/miner"
	"github.com/cypherium/cypher/params"
)

var DefaultFullGPOConfig = gasprice.Config{Blocks: 20, Percentile: 60}
var DefaultLightGPOConfig = gasprice.Config{Blocks: 2, Percentile: 60}

func nativeMinerGasBounds(chainConfig *params.ChainConfig, floor, ceil uint64) (uint64, uint64) {
	if chainConfig == nil || !chainConfig.NativeParallelEnabled() {
		return floor, ceil
	}
	// Genesis-native execution uses one consensus capacity target. Leaving the
	// legacy 3.37G default ceiling in place would slowly decay a 2^44 genesis
	// header until even a maximum native transaction could never be proposed.
	target := chainConfig.NativeParallel.MaxComputePerBlock
	return target, target
}

var DefaultConfig = Config{
	SyncMode: downloader.FastSync,
	colossusX: colossusX.Config{
		CacheDir:         "colossusX",
		CachesInMem:      2,
		CachesOnDisk:     3,
		CachesLockMmap:   false,
		DatasetsInMem:    1,
		DatasetsOnDisk:   2,
		DatasetsLockMmap: false,
	},
	NetworkId:               1,
	LightPeers:              100,
	UltraLightFraction:      75,
	DatabaseCache:           512,
	TrieCleanCache:          154,
	TrieCleanCacheJournal:   "triecache",
	TrieCleanCacheRejournal: 60 * time.Minute,
	TrieDirtyCache:          256,
	TrieTimeout:             60 * time.Minute,
	SnapshotCache:           102,
	Miner: miner.Config{
		GasFloor: params.MinGasLimit,
		GasCeil:  params.GenesisGasLimit,
		GasPrice: big.NewInt(params.GWei),
		Recommit: 3 * time.Second,
	},
	TxPool:      core.DefaultTxPoolConfig,
	RPCGasCap:   9000000000000000000,
	GPO:         DefaultFullGPOConfig,
	RPCTxFeeCap: 100,
	TxQUIC: TxQUICConfig{
		Enabled:       false,
		AutoRole:      true,
		BridgeEnabled: false,
		// Retain a five-second burst at the 200k TPS architecture target.
		// Bytes remain independently bounded so large calldata/blob traffic
		// applies backpressure before count capacity is exhausted.
		BridgeQueueSize:          int(params.NativeParallelHardMaxTransactions),
		BridgeQueueMaxBytes:      defaultTxQUICBridgeQueueMaxBytes,
		BridgeWorkers:            64,
		BridgeBatchInterval:      10 * time.Millisecond,
		OutboxMaxRecords:         defaultTxOutboxMaxRecords,
		OutboxMaxBytes:           defaultTxOutboxMaxBytes,
		OutboxWorkers:            64,
		OutboxRetryMin:           defaultTxOutboxRetryMin,
		OutboxRetryMax:           defaultTxOutboxRetryMax,
		IngressWorkers:           256,
		MaxInflightPayloadBytes:  512 * 1024 * 1024,
		ReplayWindow:             65536,
		MaxClockSkew:             30 * time.Second,
		MaxPacketAge:             10 * time.Minute,
		NonceReservation:         4096,
		IngressCommitInterval:    time.Millisecond,
		IngressCommitMaxRequests: 64,
		IngressCommitMaxBytes:    16 * 1024 * 1024,
		// Keep duplicate ACKs for the full accepted packet-age window without
		// retaining burst manifests for a day. Replay nonces remain durable after
		// the ACK body is collected.
		IngressAckRetention:  10 * time.Minute,
		HTTP3Enabled:         false,
		Addr:                 "0.0.0.0",
		Port:                 4444,
		PortOffset:           2000,
		MaxIncomingStreams:   256,
		MaxIncomingConns:     256,
		ReadTimeout:          10 * time.Second,
		WriteTimeout:         10 * time.Second,
		ForwardTimeout:       15 * time.Second,
		ForwardHedgeDelay:    100 * time.Millisecond,
		MaxTxsPerIPPerSecond: 500000,
		BurstTxsPerIP:        1000000,
		RateBucketMaxEntries: 65536,
		RateBucketIdleTTL:    10 * time.Minute,
	},
}

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "darwin" {
		DefaultConfig.colossusX.DatasetDir = filepath.Join(home, "Library", "colossusX")
	} else if runtime.GOOS == "windows" {
		localappdata := os.Getenv("LOCALAPPDATA")
		if localappdata != "" {
			DefaultConfig.colossusX.DatasetDir = filepath.Join(localappdata, "colossusX")
		} else {
			DefaultConfig.colossusX.DatasetDir = filepath.Join(home, "AppData", "Local", "colossusX")
		}
	} else {
		DefaultConfig.colossusX.DatasetDir = filepath.Join(home, ".colossusX")
	}
}

func (c *Config) ColossusX() *colossusX.Config { return &c.colossusX }

//go:generate gencodec -type Config -formats toml -out gen_config.go

type TxQUICConfig struct {
	ChainID      uint64      `toml:"-"`
	GenesisHash  common.Hash `toml:"-"`
	FairHotstuff bool        `toml:"-"`

	Enabled       bool `toml:",omitempty"`
	AutoRole      bool `toml:",omitempty"`
	BridgeEnabled bool `toml:",omitempty"`

	BridgeQueueSize         int           `toml:",omitempty"`
	BridgeQueueMaxBytes     int64         `toml:",omitempty"`
	BridgeWorkers           int           `toml:",omitempty"`
	BridgeBatchInterval     time.Duration `toml:",omitempty"`
	OutboxMaxRecords        int           `toml:",omitempty"`
	OutboxMaxBytes          int64         `toml:",omitempty"`
	OutboxWorkers           int           `toml:",omitempty"`
	OutboxRetryMin          time.Duration `toml:",omitempty"`
	OutboxRetryMax          time.Duration `toml:",omitempty"`
	IngressWorkers          int           `toml:",omitempty"`
	MaxInflightPayloadBytes int64         `toml:",omitempty"`
	ReplayWindow            uint64        `toml:",omitempty"`
	MaxClockSkew            time.Duration `toml:",omitempty"`
	MaxPacketAge            time.Duration `toml:",omitempty"`
	NonceReservation        uint64        `toml:",omitempty"`

	IngressCommitInterval    time.Duration `toml:",omitempty"`
	IngressCommitMaxRequests int           `toml:",omitempty"`
	IngressCommitMaxBytes    int64         `toml:",omitempty"`
	IngressAckRetention      time.Duration `toml:",omitempty"`

	HTTP3Enabled  bool   `toml:",omitempty"`
	HTTP3Addr     string `toml:",omitempty"`
	HTTP3Port     int    `toml:",omitempty"`
	HTTP3CertFile string `toml:",omitempty"`
	HTTP3KeyFile  string `toml:",omitempty"`

	Addr       string `toml:",omitempty"`
	Port       int    `toml:",omitempty"`
	PortOffset int    `toml:",omitempty"`

	MaxIncomingStreams int64 `toml:",omitempty"`
	MaxIncomingConns   int   `toml:",omitempty"`

	ReadTimeout    time.Duration `toml:",omitempty"`
	WriteTimeout   time.Duration `toml:",omitempty"`
	ForwardTimeout time.Duration `toml:",omitempty"`
	// ForwardHedgeDelay staggers one additional committee request when the
	// quorum-sized initial window is blocked by a straggler.
	ForwardHedgeDelay time.Duration `toml:",omitempty"`

	MaxTxsPerIPPerSecond int           `toml:",omitempty"`
	BurstTxsPerIP        int           `toml:",omitempty"`
	RateBucketMaxEntries int           `toml:",omitempty"`
	RateBucketIdleTTL    time.Duration `toml:",omitempty"`

	AllowIPs []string `toml:",omitempty"`

	AllowedSigners []common.Address `toml:",omitempty"`
}

// UnmarshalTOML preserves security-sensitive defaults when an operator sets
// only part of [Eth.TxQUIC]. Without this merge, omitted booleans such as
// AutoRole silently become false because the generated parent decoder replaces
// the complete nested struct.
func (c *TxQUICConfig) UnmarshalTOML(unmarshal func(interface{}) error) error {
	type plain TxQUICConfig
	decoded := plain(DefaultConfig.TxQUIC)
	if err := unmarshal(&decoded); err != nil {
		return err
	}
	*c = TxQUICConfig(decoded)
	return nil
}

type Config struct {
	GenesisKey *core.GenesisKey `toml:",omitempty"`
	Genesis    *core.Genesis    `toml:",omitempty"`

	NetworkId uint64
	SyncMode  downloader.SyncMode

	DiscoveryURLs []string

	NoPruning  bool
	NoPrefetch bool

	TxLookupLimit uint64 `toml:",omitempty"`

	Whitelist map[uint64]common.Hash `toml:"-"`

	LightServ    int  `toml:",omitempty"`
	LightIngress int  `toml:",omitempty"`
	LightEgress  int  `toml:",omitempty"`
	LightPeers   int  `toml:",omitempty"`
	LightNoPrune bool `toml:",omitempty"`

	UltraLightServers      []string `toml:",omitempty"`
	UltraLightFraction     int      `toml:",omitempty"`
	UltraLightOnlyAnnounce bool     `toml:",omitempty"`

	SkipBcVersionCheck bool `toml:"-"`
	DatabaseHandles    int  `toml:"-"`
	DatabaseCache      int
	DatabaseFreezer    string

	TrieCleanCache          int
	TrieCleanCacheJournal   string        `toml:",omitempty"`
	TrieCleanCacheRejournal time.Duration `toml:",omitempty"`
	TrieDirtyCache          int
	TrieTimeout             time.Duration
	SnapshotCache           int

	Miner miner.Config

	colossusX colossusX.Config

	TxPool core.TxPoolConfig

	GPO gasprice.Config

	TxQUIC TxQUICConfig

	EnablePreimageRecording bool

	DocRoot          string `toml:"-"`
	EWASMInterpreter string
	EVMInterpreter   string

	RPCGasCap uint64 `toml:",omitempty"`

	RPCTxFeeCap float64 `toml:",omitempty"`

	Checkpoint       *params.TrustedCheckpoint      `toml:",omitempty"`
	CheckpointOracle *params.CheckpointOracleConfig `toml:",omitempty"`

	EVMCallTimeOut time.Duration

	EnableMultitenancy bool

	RnetPort   string
	ExternalIp string
	EnableTPS  bool
}
