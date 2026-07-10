package params

import (
	"encoding/json"
	"math/big"
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
		return isTimestampForked(cfg.ShanghaiTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsCancun(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return isTimestampForked(cfg.CancunTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsPrague(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return isTimestampForked(cfg.PragueTime, timestamp)
	}
	return false
}

func (c *ChainConfig) IsOsaka(num *big.Int, timestamp uint64) bool {
	if cfg := c.ModernForkConfig(); cfg != nil {
		return isTimestampForked(cfg.OsakaTime, timestamp)
	}
	return false
}

func isTimestampForked(s *uint64, timestamp uint64) bool {
	return s != nil && timestamp >= *s
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
	FixedCommittee         bool                  `json:"fixedCommittee,omitempty"`
	FixedLeader            bool                  `json:"fixedLeader,omitempty"`
	FairHotstuff           bool                  `json:"fairHotstuff,omitempty"`
	EnabledTPS             bool                  `json:"enabledTPS,omitempty"`
}

func (c *ChainConfig) UnmarshalJSON(input []byte) error {
	var dec chainConfigJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
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
	c.FixedCommittee = dec.FixedCommittee
	c.FixedLeader = dec.FixedLeader
	c.FairHotstuff = dec.FairHotstuff
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
		BlobSchedule:      dec.BlobSchedule,
	})
	return nil
}

func (c *ChainConfig) MarshalJSON() ([]byte, error) {
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
		FixedCommittee:         c.FixedCommittee,
		FixedLeader:            c.FixedLeader,
		FairHotstuff:           c.FairHotstuff,
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
		enc.BlobSchedule = cfg.BlobSchedule
	}
	return json.Marshal(&enc)
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
