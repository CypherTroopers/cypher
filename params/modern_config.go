package params

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/cypherium/cypher/common"
)

// BlobConfig stores EIP-4844-style blob gas scheduling parameters for a fork.
type BlobConfig struct {
	Target                int `json:"target"`
	Max                   int `json:"max"`
	BaseFeeUpdateFraction int `json:"baseFeeUpdateFraction"`
}

// BlobScheduleConfig stores blob gas parameters by fork name. It mirrors the
// modern go-ethereum chain config surface while keeping Cypherium consensus
// independent from Ethereum PoS/Beacon consensus.
type BlobScheduleConfig struct {
	Cancun *BlobConfig `json:"cancun,omitempty"`
	Prague *BlobConfig `json:"prague,omitempty"`
	Osaka  *BlobConfig `json:"osaka,omitempty"`
	BPO1   *BlobConfig `json:"bpo1,omitempty"`
	BPO2   *BlobConfig `json:"bpo2,omitempty"`
	BPO3   *BlobConfig `json:"bpo3,omitempty"`
	BPO4   *BlobConfig `json:"bpo4,omitempty"`
	BPO5   *BlobConfig `json:"bpo5,omitempty"`
}

// ModernForkConfig holds fork fields that do not exist in the original
// Cypherium ChainConfig struct. They are attached to ChainConfig pointers by
// JSON decode and explicit setters so we can add modern EVM fork behavior
// without deleting Cypherium-specific fields such as committee, rnetport,
// maxCodeSize and fixedCommittee.
type ModernForkConfig struct {
	BerlinBlock       *big.Int            `json:"berlinBlock,omitempty"`
	LondonBlock       *big.Int            `json:"londonBlock,omitempty"`
	ArrowGlacierBlock *big.Int            `json:"arrowGlacierBlock,omitempty"`
	GrayGlacierBlock  *big.Int            `json:"grayGlacierBlock,omitempty"`
	ShanghaiTime      *uint64             `json:"shanghaiTime,omitempty"`
	CancunTime        *uint64             `json:"cancunTime,omitempty"`
	PragueTime        *uint64             `json:"pragueTime,omitempty"`
	OsakaTime         *uint64             `json:"osakaTime,omitempty"`
	BPO1Time          *uint64             `json:"bpo1Time,omitempty"`
	BPO2Time          *uint64             `json:"bpo2Time,omitempty"`
	BPO3Time          *uint64             `json:"bpo3Time,omitempty"`
	BPO4Time          *uint64             `json:"bpo4Time,omitempty"`
	BPO5Time          *uint64             `json:"bpo5Time,omitempty"`
	BlobSchedule      *BlobScheduleConfig `json:"blobSchedule,omitempty"`
}

var modernForkConfigs sync.Map // map[*ChainConfig]*ModernForkConfig

func (c *ChainConfig) SetModernForkConfig(cfg *ModernForkConfig) {
	if c == nil {
		return
	}
	if cfg == nil {
		modernForkConfigs.Delete(c)
		return
	}
	modernForkConfigs.Store(c, cfg)
}

func (c *ChainConfig) ModernForkConfig() *ModernForkConfig {
	if c == nil {
		return nil
	}
	if cfg, ok := modernForkConfigs.Load(c); ok {
		return cfg.(*ModernForkConfig)
	}
	return nil
}

func (c *ChainConfig) IsBerlin(num *big.Int) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return isForked(cfg.BerlinBlock, num)
	}
	return false
}

func (c *ChainConfig) IsLondon(num *big.Int) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return isForked(cfg.LondonBlock, num)
	}
	return false
}

func (c *ChainConfig) IsShanghai(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.ShanghaiTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsCancun(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.CancunTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsPrague(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.PragueTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsOsaka(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.OsakaTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsBPO1(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.BPO1Time, timestamp)
	}
	return false
}

func (c *ChainConfig) IsBPO2(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.BPO2Time, timestamp)
	}
	return false
}

func (c *ChainConfig) IsBPO3(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.BPO3Time, timestamp)
	}
	return false
}

func (c *ChainConfig) IsBPO4(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.BPO4Time, timestamp)
	}
	return false
}

func (c *ChainConfig) IsBPO5(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return c.IsLondon(num) && isTimestampForked(cfg.BPO5Time, timestamp)
	}
	return false
}

func isTimestampForked(s *uint64, timestamp uint64) bool {
	return s != nil && timestamp >= *s
}

func (c *ChainConfig) checkModernForkOrder() error {
	modern := c.ModernForkConfig()
	if modern == nil {
		return nil
	}
	if modern.BerlinBlock == nil && modern.LondonBlock != nil {
		return fmt.Errorf("unsupported fork ordering: berlinBlock not enabled, but londonBlock enabled at %v", modern.LondonBlock)
	}
	if modern.BerlinBlock != nil && modern.LondonBlock != nil && modern.BerlinBlock.Cmp(modern.LondonBlock) > 0 {
		return fmt.Errorf("unsupported fork ordering: berlinBlock enabled at %v, but londonBlock enabled at %v", modern.BerlinBlock, modern.LondonBlock)
	}
	if modern.ShanghaiTime != nil && modern.LondonBlock == nil {
		return fmt.Errorf("unsupported fork ordering: londonBlock not enabled, but shanghaiTime enabled at %d", *modern.ShanghaiTime)
	}
	timestamps := []struct {
		name string
		at   *uint64
	}{
		{name: "shanghaiTime", at: modern.ShanghaiTime},
		{name: "cancunTime", at: modern.CancunTime},
		{name: "pragueTime", at: modern.PragueTime},
		{name: "osakaTime", at: modern.OsakaTime},
	}
	for i := 1; i < len(timestamps); i++ {
		previous, current := timestamps[i-1], timestamps[i]
		if previous.at == nil && current.at != nil {
			return fmt.Errorf("unsupported fork ordering: %s not enabled, but %s enabled at %d", previous.name, current.name, *current.at)
		}
		if previous.at != nil && current.at != nil && *previous.at > *current.at {
			return fmt.Errorf("unsupported fork ordering: %s enabled at %d, but %s enabled at %d", previous.name, *previous.at, current.name, *current.at)
		}
	}
	// BPO forks are optional parameter-only forks. A later numbered BPO may be
	// configured without filling every earlier slot, but every configured BPO
	// must follow Osaka and the preceding configured timestamp.
	lastName, lastTime := "osakaTime", modern.OsakaTime
	for _, fork := range []struct {
		name string
		at   *uint64
	}{
		{name: "bpo1Time", at: modern.BPO1Time},
		{name: "bpo2Time", at: modern.BPO2Time},
		{name: "bpo3Time", at: modern.BPO3Time},
		{name: "bpo4Time", at: modern.BPO4Time},
		{name: "bpo5Time", at: modern.BPO5Time},
	} {
		if fork.at == nil {
			continue
		}
		if lastTime == nil {
			return fmt.Errorf("unsupported fork ordering: %s not enabled, but %s enabled at %d", lastName, fork.name, *fork.at)
		}
		if *lastTime > *fork.at {
			return fmt.Errorf("unsupported fork ordering: %s enabled at %d, but %s enabled at %d", lastName, *lastTime, fork.name, *fork.at)
		}
		lastName, lastTime = fork.name, fork.at
	}
	if modern.CancunTime != nil {
		if modern.BlobSchedule == nil {
			return fmt.Errorf("Cancun requires blobSchedule")
		}
		for _, fork := range []struct {
			name   string
			active bool
			config *BlobConfig
		}{
			{name: "cancun", active: modern.CancunTime != nil, config: modern.BlobSchedule.Cancun},
			{name: "prague", active: modern.PragueTime != nil, config: modern.BlobSchedule.Prague},
			{name: "osaka", active: modern.OsakaTime != nil, config: modern.BlobSchedule.Osaka},
			{name: "bpo1", active: modern.BPO1Time != nil, config: modern.BlobSchedule.BPO1},
			{name: "bpo2", active: modern.BPO2Time != nil, config: modern.BlobSchedule.BPO2},
			{name: "bpo3", active: modern.BPO3Time != nil, config: modern.BlobSchedule.BPO3},
			{name: "bpo4", active: modern.BPO4Time != nil, config: modern.BlobSchedule.BPO4},
			{name: "bpo5", active: modern.BPO5Time != nil, config: modern.BlobSchedule.BPO5},
		} {
			if !fork.active {
				continue
			}
			if fork.config == nil || fork.config.Target <= 0 || fork.config.Max < fork.config.Target || fork.config.BaseFeeUpdateFraction <= 0 || uint64(fork.config.Max) > ^uint64(0)/BlobTxBlobGasPerBlob {
				return fmt.Errorf("invalid %s blob schedule", fork.name)
			}
		}
	}
	return nil
}

// CypheriumModernForks returns the modern EVM fork activation flags for
// Cypherium. This deliberately does not use Ethereum merge/PoS activation as a
// gate: ColossusX remains the consensus engine, while modern EVM forks are
// activated from chain config.
type CypheriumModernForks struct {
	IsBerlin, IsLondon bool
	IsShanghai         bool
	IsCancun           bool
	IsPrague           bool
	IsOsaka            bool
}

func (c *ChainConfig) CypheriumModernForks(num *big.Int, timestamp uint64) CypheriumModernForks {
	return CypheriumModernForks{
		IsBerlin:   c.IsBerlin(num),
		IsLondon:   c.IsLondon(num),
		IsShanghai: c.IsShanghai(num, timestamp),
		IsCancun:   c.IsCancun(num, timestamp),
		IsPrague:   c.IsPrague(num, timestamp),
		IsOsaka:    c.IsOsaka(num, timestamp),
	}
}

type chainConfigJSON struct {
	ChainID *big.Int `json:"chainId"`

	HomesteadBlock *big.Int    `json:"homesteadBlock,omitempty"`
	DAOForkBlock   *big.Int    `json:"daoForkBlock,omitempty"`
	DAOForkSupport bool        `json:"daoForkSupport,omitempty"`
	EIP150Block    *big.Int    `json:"eip150Block,omitempty"`
	EIP150Hash     common.Hash `json:"eip150Hash,omitempty"`
	EIP155Block    *big.Int    `json:"eip155Block,omitempty"`
	EIP158Block    *big.Int    `json:"eip158Block,omitempty"`

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"`
	PetersburgBlock     *big.Int `json:"petersburgBlock,omitempty"`
	IstanbulBlock       *big.Int `json:"istanbulBlock,omitempty"`
	MuirGlacierBlock    *big.Int `json:"muirGlacierBlock,omitempty"`
	YoloV1Block         *big.Int `json:"yoloV1Block,omitempty"`
	EWASMBlock          *big.Int `json:"ewasmBlock,omitempty"`

	BerlinBlock       *big.Int            `json:"berlinBlock,omitempty"`
	LondonBlock       *big.Int            `json:"londonBlock,omitempty"`
	ArrowGlacierBlock *big.Int            `json:"arrowGlacierBlock,omitempty"`
	GrayGlacierBlock  *big.Int            `json:"grayGlacierBlock,omitempty"`
	ShanghaiTime      *uint64             `json:"shanghaiTime,omitempty"`
	CancunTime        *uint64             `json:"cancunTime,omitempty"`
	PragueTime        *uint64             `json:"pragueTime,omitempty"`
	OsakaTime         *uint64             `json:"osakaTime,omitempty"`
	BPO1Time          *uint64             `json:"bpo1Time,omitempty"`
	BPO2Time          *uint64             `json:"bpo2Time,omitempty"`
	BPO3Time          *uint64             `json:"bpo3Time,omitempty"`
	BPO4Time          *uint64             `json:"bpo4Time,omitempty"`
	BPO5Time          *uint64             `json:"bpo5Time,omitempty"`
	BlobSchedule      *BlobScheduleConfig `json:"blobSchedule,omitempty"`

	ColossusX *colossusXConfig `json:"colossusX,omitempty"`
	Clique    *CliqueConfig    `json:"clique,omitempty"`
	Istanbul  *IstanbulConfig  `json:"istanbul,omitempty"`

	HasPrivate             bool                  `json:"hasPrivate"`
	TransactionSizeLimit   uint64                `json:"txnSizeLimit"`
	MaxCodeSize            uint64                `json:"maxCodeSize"`
	MaxCodeSizeChangeBlock *big.Int              `json:"maxCodeSizeChangeBlock,omitempty"`
	MaxCodeSizeConfig      []MaxCodeConfigStruct `json:"maxCodeSizeConfig,omitempty"`
	GenCommittee           GenesisCommittee      `json:"committee"`
	RnetPort               string                `json:"rnetport,omitempty"`
	RnetTransport          string                `json:"rnettransport,omitempty"`
	RnetFallbackTransport  string                `json:"rnetfallbacktransport,omitempty"`
	FixedCommittee         bool                  `json:"fixedCommittee,omitempty"`
	FixedLeader            bool                  `json:"fixedLeader,omitempty"`
	FairHotstuff           bool                  `json:"fairHotstuff,omitempty"`
	FairHotstuffSeed       common.Hash           `json:"fairHotstuffSeed,omitempty"`
	CommonRPCSigners       []common.Address      `json:"commonRPCSigners,omitempty"`
	NativeParallel         *NativeParallelConfig `json:"nativeParallel,omitempty"`
	EnabledTPS             bool                  `json:"enabledTPS,omitempty"`
}

func (c *ChainConfig) UnmarshalJSON(input []byte) error {
	// The public genesis schema is deliberately EVM-only. Reject the former
	// spelling even when its value is null: silently ignoring an old genesis is
	// dangerous because it can make otherwise identical nodes disagree about
	// which transaction envelope is valid.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(input, &fields); err != nil {
		return err
	}
	var evmParallel json.RawMessage
	for key, value := range fields {
		switch {
		case strings.EqualFold(key, "nativeParallel"):
			return fmt.Errorf("chain config field %q is unsupported; use evmParallel", key)
		case strings.EqualFold(key, "evmParallel"):
			if key != "evmParallel" {
				return fmt.Errorf("chain config field %q is unsupported; use evmParallel", key)
			}
			evmParallel = value
		}
	}
	if len(evmParallel) != 0 && string(evmParallel) != "null" {
		var parallelFields map[string]json.RawMessage
		if err := json.Unmarshal(evmParallel, &parallelFields); err != nil {
			return fmt.Errorf("decode evmParallel: %w", err)
		}
		for key := range parallelFields {
			if strings.EqualFold(key, "version") {
				return fmt.Errorf("evmParallel field %q is unsupported; this genesis defines the execution profile directly", key)
			}
			if strings.EqualFold(key, "requireNativeTransactions") {
				return fmt.Errorf("evmParallel field %q is unsupported; public consensus accepts only Ethereum transaction types 0 through 4", key)
			}
		}
	}

	var dec chainConfigJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if len(evmParallel) != 0 {
		if err := json.Unmarshal(evmParallel, &dec.NativeParallel); err != nil {
			return fmt.Errorf("decode evmParallel: %w", err)
		}
	}
	c.ChainID = dec.ChainID
	c.HomesteadBlock = dec.HomesteadBlock
	c.DAOForkBlock = dec.DAOForkBlock
	c.DAOForkSupport = dec.DAOForkSupport
	c.EIP150Block = dec.EIP150Block
	c.EIP150Hash = dec.EIP150Hash
	c.EIP155Block = dec.EIP155Block
	c.EIP158Block = dec.EIP158Block
	c.ByzantiumBlock = dec.ByzantiumBlock
	c.ConstantinopleBlock = dec.ConstantinopleBlock
	c.PetersburgBlock = dec.PetersburgBlock
	c.IstanbulBlock = dec.IstanbulBlock
	c.MuirGlacierBlock = dec.MuirGlacierBlock
	c.YoloV1Block = dec.YoloV1Block
	c.EWASMBlock = dec.EWASMBlock
	c.colossusX = dec.ColossusX
	c.Clique = dec.Clique
	c.Istanbul = dec.Istanbul
	c.HasPrivate = dec.HasPrivate
	c.TransactionSizeLimit = dec.TransactionSizeLimit
	c.MaxCodeSize = dec.MaxCodeSize
	c.MaxCodeSizeChangeBlock = dec.MaxCodeSizeChangeBlock
	c.MaxCodeSizeConfig = dec.MaxCodeSizeConfig
	c.GenCommittee = dec.GenCommittee
	c.RnetPort = dec.RnetPort
	c.RnetTransport = dec.RnetTransport
	c.RnetFallbackTransport = dec.RnetFallbackTransport
	c.FixedCommittee = dec.FixedCommittee
	c.FixedLeader = dec.FixedLeader
	c.FairHotstuff = dec.FairHotstuff
	c.FairHotstuffSeed = dec.FairHotstuffSeed
	c.CommonRPCSigners = append([]common.Address(nil), dec.CommonRPCSigners...)
	c.NativeParallel = dec.NativeParallel
	c.EnabledTPS = dec.EnabledTPS
	c.SetModernForkConfig(&ModernForkConfig{
		BerlinBlock:       dec.BerlinBlock,
		LondonBlock:       dec.LondonBlock,
		ArrowGlacierBlock: dec.ArrowGlacierBlock,
		GrayGlacierBlock:  dec.GrayGlacierBlock,
		ShanghaiTime:      dec.ShanghaiTime,
		CancunTime:        dec.CancunTime,
		PragueTime:        dec.PragueTime,
		OsakaTime:         dec.OsakaTime,
		BPO1Time:          dec.BPO1Time,
		BPO2Time:          dec.BPO2Time,
		BPO3Time:          dec.BPO3Time,
		BPO4Time:          dec.BPO4Time,
		BPO5Time:          dec.BPO5Time,
		BlobSchedule:      dec.BlobSchedule,
	})
	return nil
}

func (c *ChainConfig) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("null"), nil
	}
	if c.NativeParallel != nil && c.NativeParallel.RequireNativeTransactions {
		return nil, fmt.Errorf("evmParallel supports only Ethereum transaction types 0 through 4")
	}
	enc := chainConfigJSONFromConfig(c)
	parallel := enc.NativeParallel
	enc.NativeParallel = nil
	encoded, err := json.Marshal(&enc)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	if parallel != nil {
		parallelJSON, err := json.Marshal(parallel)
		if err != nil {
			return nil, err
		}
		var parallelFields map[string]json.RawMessage
		if err := json.Unmarshal(parallelJSON, &parallelFields); err != nil {
			return nil, err
		}
		delete(parallelFields, "requireNativeTransactions")
		parallelJSON, err = json.Marshal(parallelFields)
		if err != nil {
			return nil, err
		}
		fields["evmParallel"] = parallelJSON
	}
	return json.Marshal(fields)
}

func chainConfigJSONFromConfig(c *ChainConfig) chainConfigJSON {
	enc := chainConfigJSON{
		ChainID:                c.ChainID,
		HomesteadBlock:         c.HomesteadBlock,
		DAOForkBlock:           c.DAOForkBlock,
		DAOForkSupport:         c.DAOForkSupport,
		EIP150Block:            c.EIP150Block,
		EIP150Hash:             c.EIP150Hash,
		EIP155Block:            c.EIP155Block,
		EIP158Block:            c.EIP158Block,
		ByzantiumBlock:         c.ByzantiumBlock,
		ConstantinopleBlock:    c.ConstantinopleBlock,
		PetersburgBlock:        c.PetersburgBlock,
		IstanbulBlock:          c.IstanbulBlock,
		MuirGlacierBlock:       c.MuirGlacierBlock,
		YoloV1Block:            c.YoloV1Block,
		EWASMBlock:             c.EWASMBlock,
		ColossusX:              c.colossusX,
		Clique:                 c.Clique,
		Istanbul:               c.Istanbul,
		HasPrivate:             c.HasPrivate,
		TransactionSizeLimit:   c.TransactionSizeLimit,
		MaxCodeSize:            c.MaxCodeSize,
		MaxCodeSizeChangeBlock: c.MaxCodeSizeChangeBlock,
		MaxCodeSizeConfig:      c.MaxCodeSizeConfig,
		GenCommittee:           c.GenCommittee,
		RnetPort:               c.RnetPort,
		RnetTransport:          c.RnetTransport,
		RnetFallbackTransport:  c.RnetFallbackTransport,
		FixedCommittee:         c.FixedCommittee,
		FixedLeader:            c.FixedLeader,
		FairHotstuff:           c.FairHotstuff,
		FairHotstuffSeed:       c.FairHotstuffSeed,
		CommonRPCSigners:       append([]common.Address(nil), c.CommonRPCSigners...),
		NativeParallel:         c.NativeParallel,
		EnabledTPS:             c.EnabledTPS,
	}
	if cfg := c.ModernForkConfig(); cfg != nil {
		enc.BerlinBlock = cfg.BerlinBlock
		enc.LondonBlock = cfg.LondonBlock
		enc.ArrowGlacierBlock = cfg.ArrowGlacierBlock
		enc.GrayGlacierBlock = cfg.GrayGlacierBlock
		enc.ShanghaiTime = cfg.ShanghaiTime
		enc.CancunTime = cfg.CancunTime
		enc.PragueTime = cfg.PragueTime
		enc.OsakaTime = cfg.OsakaTime
		enc.BPO1Time = cfg.BPO1Time
		enc.BPO2Time = cfg.BPO2Time
		enc.BPO3Time = cfg.BPO3Time
		enc.BPO4Time = cfg.BPO4Time
		enc.BPO5Time = cfg.BPO5Time
		enc.BlobSchedule = cfg.BlobSchedule
	}
	return enc
}

// CypheriumRules returns the execution-layer rules for Cypherium.
// ColossusX remains the consensus engine; modern EVM forks are activated
// only from ChainConfig and timestamp/block schedule.
func (c *ChainConfig) CypheriumRules(num *big.Int, timestamp uint64) Rules {
	rules := c.Rules(num)
	rules.IsBerlin = c.IsBerlin(num)
	rules.IsLondon = c.IsLondon(num)
	rules.IsShanghai = c.IsShanghai(num, timestamp)
	rules.IsCancun = c.IsCancun(num, timestamp)
	rules.IsPrague = c.IsPrague(num, timestamp)
	rules.IsOsaka = c.IsOsaka(num, timestamp)
	return rules
}
