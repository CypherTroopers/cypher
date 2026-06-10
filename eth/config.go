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
		Enabled:                      false,
		AutoRole:                     true,
		BridgeEnabled:                false,
		BridgeQueueSize:              3000000,
		BridgeWorkers:                8,
		BridgeBatchInterval:          10 * time.Millisecond,
		HTTP3Enabled:                 false,
		Addr:                         "0.0.0.0",
		Port:                         4444,
		PortOffset:                   2000,
		MaxPayload:                   64 * 1024 * 1024,
		MaxTxsPerBatch:               16384,
		MaxIncomingStreams:           8192,
		MaxIncomingConns:             4096,
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 5 * time.Second,
		ForwardTimeout:               3 * time.Second,
		MaxTxsPerIPPerSecond:         100000,
		BurstTxsPerIP:                200000,
		RequireAuth:                  true,
		Ack:                          true,
		RoutingMode:                  "leader-only",
		ForwardTLSInsecureSkipVerify: true,
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
	Enabled       bool `toml:",omitempty"`
	AutoRole      bool `toml:",omitempty"`
	BridgeEnabled bool `toml:",omitempty"`

	BridgeQueueSize     int           `toml:",omitempty"`
	BridgeWorkers       int           `toml:",omitempty"`
	BridgeBatchInterval time.Duration `toml:",omitempty"`

	HTTP3Enabled  bool   `toml:",omitempty"`
	HTTP3Addr     string `toml:",omitempty"`
	HTTP3Port     int    `toml:",omitempty"`
	HTTP3CertFile string `toml:",omitempty"`
	HTTP3KeyFile  string `toml:",omitempty"`

	Addr       string `toml:",omitempty"`
	Port       int    `toml:",omitempty"`
	PortOffset int    `toml:",omitempty"`

	MaxPayload         int64 `toml:",omitempty"`
	MaxTxsPerBatch     int   `toml:",omitempty"`
	MaxIncomingStreams int64 `toml:",omitempty"`
	MaxIncomingConns   int   `toml:",omitempty"`

	ReadTimeout    time.Duration `toml:",omitempty"`
	WriteTimeout   time.Duration `toml:",omitempty"`
	ForwardTimeout time.Duration `toml:",omitempty"`

	MaxTxsPerIPPerSecond int `toml:",omitempty"`
	BurstTxsPerIP        int `toml:",omitempty"`

	AllowIPs []string `toml:",omitempty"`

	TLSCertFile string `toml:",omitempty"`
	TLSKeyFile  string `toml:",omitempty"`

	RequireAuth    bool             `toml:",omitempty"`
	AllowedSigners []common.Address `toml:",omitempty"`
	Ack            bool             `toml:",omitempty"`

	RoutingMode     string   `toml:",omitempty"`
	LeaderEndpoints []string `toml:",omitempty"`
	BackupEndpoints []string `toml:",omitempty"`

	ForwardServerName            string `toml:",omitempty"`
	ForwardTLSCAFile             string `toml:",omitempty"`
	ForwardTLSInsecureSkipVerify bool   `toml:",omitempty"`
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
