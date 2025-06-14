// Copyright 2016 The go-ethereum Authors
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

package params

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
)

// Genesis hashes to enforce below configs on.
var (
	MainnetGenesisHash = common.HexToHash("0xe8186a2e15328b38547348dec5d25b051bc1d17681c66b8c8ac15c06afa223c6") //Chenged
	RopstenGenesisHash = common.HexToHash("0x1d2bc30c28ad041bc4e426dfe92327d5dff58d442d671106e32309d4e374bd85")
	RinkebyGenesisHash = common.HexToHash("0x6341fd3daf94b748c72ced5a5b26028f2474f5f00d824504e4fa37a75767e177")
	GoerliGenesisHash  = common.HexToHash("0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")
	YoloV1GenesisHash  = common.HexToHash("0xc3fd235071f24f93865b0850bd2a2119b30f7224d18a0e34c7bbf549ad7e3d36")
)

// TrustedCheckpoints associates each known checkpoint with the genesis hash of
// the chain it belongs to.
var TrustedCheckpoints = map[common.Hash]*TrustedCheckpoint{
	MainnetGenesisHash: MainnetTrustedCheckpoint,
	RopstenGenesisHash: RopstenTrustedCheckpoint,
	RinkebyGenesisHash: RinkebyTrustedCheckpoint,
	GoerliGenesisHash:  GoerliTrustedCheckpoint,
}

// CheckpointOracles associates each known checkpoint oracles with the genesis hash of
// the chain it belongs to.
var CheckpointOracles = map[common.Hash]*CheckpointOracleConfig{
//	MainnetGenesisHash: MainnetCheckpointOracle,
	RopstenGenesisHash: RopstenCheckpointOracle,
	RinkebyGenesisHash: RinkebyCheckpointOracle,
	GoerliGenesisHash:  GoerliCheckpointOracle,
}

var (
	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = &ChainConfig{
		ChainID:             big.NewInt(16166), //Changed
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.HexToHash("0xe8186a2e15328b38547348dec5d25b051bc1d17681c66b8c8ac15c06afa223c6"), //Chaneged
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		Ethash:              new(EthashConfig)}

	// MainnetTrustedCheckpoint contains the light client trusted checkpoint for the main network.
	MainnetTrustedCheckpoint = &TrustedCheckpoint{
          SectionIndex: 182, // Block 182,529 section index (182,529 ÷ 1000 ≈ 182)
          SectionHead:  common.HexToHash("0x32d96527ae12d49f4cd75d4446cece1324dcc4d54d63f48ddbec7596ab7a061b"),
          CHTRoot:      common.HexToHash("0x997a477225b460cdc2f92a0e6abb16823144af38836254f99a5a4a58aab1e5bd"),
          BloomRoot:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
      }

	// MainnetCheckpointOracle contains a set of configs for the main network oracle.
//	MainnetCheckpointOracle = &CheckpointOracleConfig{
//		Address: common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"),
//		Signers: []common.Address{
//			common.HexToAddress("0x1b2C260efc720BE89101890E4Db589b44E950527"), // Peter
//			common.HexToAddress("0x78d1aD571A1A09D60D9BBf25894b44e4C8859595"), // Martin
//			common.HexToAddress("0x286834935f4A8Cfb4FF4C77D5770C2775aE2b0E7"), // Zsolt
//			common.HexToAddress("0xb86e2B0Ab5A4B1373e40c51A7C712c70Ba2f9f8E"), // Gary
//			common.HexToAddress("0x0DF8fa387C602AE62559cC4aFa4972A7045d6707"), // Guillaume
//		},
//		Threshold: 2,
//	}


	// RopstenChainConfig contains the chain parameters to run a node on the Ropsten test network.
	RopstenChainConfig = &ChainConfig{
		ChainID:             big.NewInt(16164),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.HexToHash("0x1d2bc30c28ad041bc4e426dfe92327d5dff58d442d671106e32309d4e374bd85"),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		Ethash:              new(EthashConfig),
	}

	// RopstenTrustedCheckpoint contains the light client trusted checkpoint for the Ropsten test network.
	RopstenTrustedCheckpoint = &TrustedCheckpoint{
		SectionIndex: 260,
		SectionHead:  common.HexToHash("0xdcf714d033b8be3f0786515649d76e526157f811e5ae89c59dbfd53029d0d165"),
		CHTRoot:      common.HexToHash("0x987759454d404cd393a6a7743da64610076f167e989ec2cf9e0c0be6578d1304"),
		BloomRoot:    common.HexToHash("0xb8ee6d34cc30d61410717e2dc1af3294bc056f4b32a5eed5f6f386a8c1daa2b1"),
	}

	// RopstenCheckpointOracle contains a set of configs for the Ropsten test network oracle.
	RopstenCheckpointOracle = &CheckpointOracleConfig{
		Address: common.HexToAddress("0xEF79475013f154E6A65b54cB2742867791bf0B84"),
		Signers: []common.Address{
			common.HexToAddress("0x32162F3581E88a5f62e8A61892B42C46E2c18f7b"), // Peter
			common.HexToAddress("0x78d1aD571A1A09D60D9BBf25894b44e4C8859595"), // Martin
			common.HexToAddress("0x286834935f4A8Cfb4FF4C77D5770C2775aE2b0E7"), // Zsolt
			common.HexToAddress("0xb86e2B0Ab5A4B1373e40c51A7C712c70Ba2f9f8E"), // Gary
			common.HexToAddress("0x0DF8fa387C602AE62559cC4aFa4972A7045d6707"), // Guillaume
		},
		Threshold: 2,
	}

	// RinkebyChainConfig contains the chain parameters to run a node on the Rinkeby test network.
	RinkebyChainConfig = &ChainConfig{
		ChainID:             big.NewInt(4),
		HomesteadBlock:      big.NewInt(1),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(2),
		EIP150Hash:          common.HexToHash("0x9b095b36c15eaf13044373aef8ee0bd3a382a5abb92e402afa44b8249c3a90e9"),
		EIP155Block:         big.NewInt(3),
		EIP158Block:         big.NewInt(3),
		ByzantiumBlock:      big.NewInt(103),
		ConstantinopleBlock: big.NewInt(366),
		PetersburgBlock:     big.NewInt(432),
		IstanbulBlock:       big.NewInt(543),
		MuirGlacierBlock:    nil,
		Clique: &CliqueConfig{
			Period: 15,
			Epoch:  30000,
		},
	}

	// RinkebyTrustedCheckpoint contains the light client trusted checkpoint for the Rinkeby test network.
	RinkebyTrustedCheckpoint = &TrustedCheckpoint{
		SectionIndex: 214,
		SectionHead:  common.HexToHash("0x297b4daf21db636e76555c9d3e302d79a8efe3a3434143b9bcf61187ce8abcb1"),
		CHTRoot:      common.HexToHash("0x602044234a4ba8534286240200cde6e5797ae40151cbdd2dbf8eb8c0486a2c63"),
		BloomRoot:    common.HexToHash("0x9ccf6840ecc541b290c7b9f19edcba3e5f39206b05cd4ae5a7754040783d47d9"),
	}

	// RinkebyCheckpointOracle contains a set of configs for the Rinkeby test network oracle.
	RinkebyCheckpointOracle = &CheckpointOracleConfig{
		Address: common.HexToAddress("0xebe8eFA441B9302A0d7eaECc277c09d20D684540"),
		Signers: []common.Address{
			common.HexToAddress("0xd9c9cd5f6779558b6e0ed4e6acf6b1947e7fa1f3"), // Peter
			common.HexToAddress("0x78d1aD571A1A09D60D9BBf25894b44e4C8859595"), // Martin
			common.HexToAddress("0x286834935f4A8Cfb4FF4C77D5770C2775aE2b0E7"), // Zsolt
			common.HexToAddress("0xb86e2B0Ab5A4B1373e40c51A7C712c70Ba2f9f8E"), // Gary
		},
		Threshold: 2,
	}

	// GoerliChainConfig contains the chain parameters to run a node on the Görli test network.
	GoerliChainConfig = &ChainConfig{
		ChainID:             big.NewInt(5),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(156),
		MuirGlacierBlock:    nil,
		Clique: &CliqueConfig{
			Period: 15,
			Epoch:  30000,
		},
	}

	// GoerliTrustedCheckpoint contains the light client trusted checkpoint for the Görli test network.
	GoerliTrustedCheckpoint = &TrustedCheckpoint{
		SectionIndex: 99,
		SectionHead:  common.HexToHash("0xc9f09369acd657d5f77e6a389a68f673bf909ad98c269800c08229d75c1a90e3"),
		CHTRoot:      common.HexToHash("0x523218630348e98fa9f4e7fc3054aff717982d79c700cbecf5730c1479f21c6e"),
		BloomRoot:    common.HexToHash("0x75219ad4a3ec4682b89dd248ee56b52ef26fe577a426f4813297550deb5c4cb2"),
	}

	// GoerliCheckpointOracle contains a set of configs for the Goerli test network oracle.
	GoerliCheckpointOracle = &CheckpointOracleConfig{
		Address: common.HexToAddress("0x18CA0E045F0D772a851BC7e48357Bcaab0a0795D"),
		Signers: []common.Address{
			common.HexToAddress("0x4769bcaD07e3b938B7f43EB7D278Bc7Cb9efFb38"), // Peter
			common.HexToAddress("0x78d1aD571A1A09D60D9BBf25894b44e4C8859595"), // Martin
			common.HexToAddress("0x286834935f4A8Cfb4FF4C77D5770C2775aE2b0E7"), // Zsolt
			common.HexToAddress("0xb86e2B0Ab5A4B1373e40c51A7C712c70Ba2f9f8E"), // Gary
			common.HexToAddress("0x0DF8fa387C602AE62559cC4aFa4972A7045d6707"), // Guillaume
		},
		Threshold: 2,
	}

	// YoloV1ChainConfig contains the chain parameters to run a node on the YOLOv1 test network.
	YoloV1ChainConfig = &ChainConfig{
		ChainID:             big.NewInt(133519467574833),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    nil,
		YoloV1Block:         big.NewInt(0),
		Clique: &CliqueConfig{
			Period: 15,
			Epoch:  30000,
		},
	}

	// AllEthashProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Ethash consensus.
	//
	// This configuration is intentionally not using keyed fields to force anyone
	// adding flags to the config to also have to set these fields.
	AllEthashProtocolChanges = &ChainConfig{big.NewInt(1337), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, new(EthashConfig), nil, nil, false, 32, 35, big.NewInt(0), nil, nil, "", false}

	// AllCliqueProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Clique consensus.
	//
	// This configuration is intentionally not using keyed fields to force anyone
	// adding flags to the config to also have to set these fields.
	AllCliqueProtocolChanges = &ChainConfig{big.NewInt(1337), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, nil, &CliqueConfig{Period: 0, Epoch: 30000}, nil, false, 32, 32, big.NewInt(0), nil, nil, "", false}

	TestChainConfig = &ChainConfig{big.NewInt(10), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, new(EthashConfig), nil, nil, false, 32, 32, big.NewInt(0), nil, nil, "", false}
	TestRules       = TestChainConfig.Rules(new(big.Int))

	CypherTestChainConfig = &ChainConfig{big.NewInt(10), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, new(EthashConfig), nil, nil, true, 64, 32, big.NewInt(0), nil, nil, "", false}
)

// TrustedCheckpoint represents a set of post-processed trie roots (CHT and
// BloomTrie) associated with the appropriate section index and head hash. It is
// used to start light syncing from this checkpoint and avoid downloading the
// entire header chain while still being able to securely access old headers/logs.
type TrustedCheckpoint struct {
	SectionIndex uint64      `json:"sectionIndex"`
	SectionHead  common.Hash `json:"sectionHead"`
	CHTRoot      common.Hash `json:"chtRoot"`
	BloomRoot    common.Hash `json:"bloomRoot"`
}

// HashEqual returns an indicator comparing the itself hash with given one.
func (c *TrustedCheckpoint) HashEqual(hash common.Hash) bool {
	if c.Empty() {
		return hash == common.Hash{}
	}
	return c.Hash() == hash
}

// Hash returns the hash of checkpoint's four key fields(index, sectionHead, chtRoot and bloomTrieRoot).
func (c *TrustedCheckpoint) Hash() common.Hash {
	buf := make([]byte, 8+3*common.HashLength)
	binary.BigEndian.PutUint64(buf, c.SectionIndex)
	copy(buf[8:], c.SectionHead.Bytes())
	copy(buf[8+common.HashLength:], c.CHTRoot.Bytes())
	copy(buf[8+2*common.HashLength:], c.BloomRoot.Bytes())
	return crypto.Keccak256Hash(buf)
}

// Empty returns an indicator whether the checkpoint is regarded as empty.
func (c *TrustedCheckpoint) Empty() bool {
	return c.SectionHead == (common.Hash{}) || c.CHTRoot == (common.Hash{}) || c.BloomRoot == (common.Hash{})
}

// CheckpointOracleConfig represents a set of checkpoint contract(which acts as an oracle)
// config which used for light client checkpoint syncing.
type CheckpointOracleConfig struct {
	Address   common.Address   `json:"address"`
	Signers   []common.Address `json:"signers"`
	Threshold uint64           `json:"threshold"`
}

type MaxCodeConfigStruct struct {
	Block *big.Int `json:"block,omitempty"`
	Size  uint64   `json:"size,omitempty"`
}

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection

	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)

	DAOForkBlock   *big.Int `json:"daoForkBlock,omitempty"`   // TheDAO hard-fork switch block (nil = no fork)
	DAOForkSupport bool     `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork

	// EIP150 implements the Gas price changes (https://github.com/ethereum/EIPs/issues/150)
	EIP150Block *big.Int    `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	EIP150Hash  common.Hash `json:"eip150Hash,omitempty"`  // EIP150 HF hash (needed for header only clients as only gas pricing changed)

	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`      // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)
	PetersburgBlock     *big.Int `json:"petersburgBlock,omitempty"`     // Petersburg switch block (nil = same as Constantinople)
	IstanbulBlock       *big.Int `json:"istanbulBlock,omitempty"`       // Istanbul switch block (nil = no fork, 0 = already on istanbul)
	MuirGlacierBlock    *big.Int `json:"muirGlacierBlock,omitempty"`    // Eip-2384 (bomb delay) switch block (nil = no fork, 0 = already activated)

	YoloV1Block *big.Int `json:"yoloV1Block,omitempty"` // YOLO v1: https://github.com/ethereum/EIPs/pull/2657 (Ephemeral testnet)
	EWASMBlock  *big.Int `json:"ewasmBlock,omitempty"`  // EWASM switch block (nil = no fork, 0 = already activated)

	// Various consensus engines
	Ethash   *EthashConfig   `json:"ethash,omitempty"`
	Clique   *CliqueConfig   `json:"clique,omitempty"`
	Istanbul *IstanbulConfig `json:"istanbul,omitempty"`

	HasPrivate             bool     `json:"hasPrivate"`   // Cypher flag
	TransactionSizeLimit   uint64   `json:"txnSizeLimit"` // Cypher - transaction size limit
	MaxCodeSize            uint64   `json:"maxCodeSize"`  // Cypher -  maximum CodeSize of contract
	MaxCodeSizeChangeBlock *big.Int `json:"maxCodeSizeChangeBlock,omitempty"`
	// to track multiple changes to maxCodeSize
	MaxCodeSizeConfig []MaxCodeConfigStruct `json:"maxCodeSizeConfig,omitempty"`

	GenCommittee GenesisCommittee `json:"committee"      gencodec:"required"`
	RnetPort     string           `json:"rnetport,omitempty"`
	EnabledTPS   bool
}
type GenesisCommittee map[int]common.Cnode

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c *EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
type CliqueConfig struct {
	Period                 uint64 `json:"period"`                 // Number of seconds between blocks to enforce
	Epoch                  uint64 `json:"epoch"`                  // Epoch length to reset votes and checkpoint
	AllowedFutureBlockTime uint64 `json:"allowedFutureBlockTime"` // Max time (in seconds) from current time allowed for blocks, before they're considered future blocks
}

// String implements the stringer interface, returning the consensus engine details.
func (c *CliqueConfig) String() string {
	return "clique"
}

// IstanbulConfig is the consensus engine configs for Istanbul based sealing.
type IstanbulConfig struct {
	Epoch          uint64   `json:"epoch"`                    // Epoch length to reset votes and checkpoint
	ProposerPolicy uint64   `json:"policy"`                   // The policy for proposer selection
	Ceil2Nby3Block *big.Int `json:"ceil2Nby3Block,omitempty"` // Number of confirmations required to move from one state to next [2F + 1 to Ceil(2N/3)]
}

// String implements the stringer interface, returning the consensus engine details.
func (c *IstanbulConfig) String() string {
	return "istanbul"
}

// String implements the fmt.Stringer interface.
func (c *ChainConfig) String() string {
	var engine interface{}
	switch {
	case c.Ethash != nil:
		engine = c.Ethash
	case c.Clique != nil:
		engine = c.Clique
	case c.Istanbul != nil:
		engine = c.Istanbul
	default:
		engine = "unknown"
	}
	return fmt.Sprintf("{ChainID: %v Homestead: %v DAO: %v DAOSupport: %v EIP150: %v EIP155: %v EIP158: %v Byzantium: %v HasPrivate: %v Constantinople: %v TransactionSizeLimit: %v MaxCodeSize: %v Petersburg: %v Istanbul: %v, Muir Glacier: %v YOLO v1: %v PrivacyEnhancements: %v Engine: %v}",
		c.ChainID,
		c.HomesteadBlock,
		c.DAOForkBlock,
		c.DAOForkSupport,
		c.EIP150Block,
		c.EIP155Block,
		c.EIP158Block,
		c.ByzantiumBlock,
		c.HasPrivate,
		c.ConstantinopleBlock,
		c.TransactionSizeLimit,
		c.MaxCodeSize,
		c.PetersburgBlock,
		c.IstanbulBlock,
		c.MuirGlacierBlock,
		c.YoloV1Block,
		engine,
	)
}

// validate code size and transaction size limit
func (c *ChainConfig) IsValid() error {

	if c.TransactionSizeLimit < 32 || c.TransactionSizeLimit > 128 {
		return errors.New("Genesis transaction size limit must be between 32 and 128")
	}

	if c.MaxCodeSize != 0 && (c.MaxCodeSize < 24 || c.MaxCodeSize > 128) {
		return errors.New("Genesis max code size must be between 24 and 128")
	}

	return nil
}

// IsHomestead returns whether num is either equal to the homestead block or greater.
func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isForked(c.HomesteadBlock, num)
}

// IsDAOFork returns whether num is either equal to the DAO fork block or greater.
func (c *ChainConfig) IsDAOFork(num *big.Int) bool {
	return isForked(c.DAOForkBlock, num)
}

// IsEIP150 returns whether num is either equal to the EIP150 fork block or greater.
func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isForked(c.EIP150Block, num)
}

// IsEIP155 returns whether num is either equal to the EIP155 fork block or greater.
func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isForked(c.EIP155Block, num)
}

// IsEIP158 returns whether num is either equal to the EIP158 fork block or greater.
func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isForked(c.EIP158Block, num)
}

// IsByzantium returns whether num is either equal to the Byzantium fork block or greater.
func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isForked(c.ByzantiumBlock, num)
}

// IsConstantinople returns whether num is either equal to the Constantinople fork block or greater.
func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isForked(c.ConstantinopleBlock, num)
}

// IsMuirGlacier returns whether num is either equal to the Muir Glacier (EIP-2384) fork block or greater.
func (c *ChainConfig) IsMuirGlacier(num *big.Int) bool {
	return isForked(c.MuirGlacierBlock, num)
}

// IsPetersburg returns whether num is either
// - equal to or greater than the PetersburgBlock fork block,
// - OR is nil, and Constantinople is active
func (c *ChainConfig) IsPetersburg(num *big.Int) bool {
	return isForked(c.PetersburgBlock, num) || c.PetersburgBlock == nil && isForked(c.ConstantinopleBlock, num)
}

// IsIstanbul returns whether num is either equal to the Istanbul fork block or greater.
func (c *ChainConfig) IsIstanbul(num *big.Int) bool {
	return isForked(c.IstanbulBlock, num)
}

// IsYoloV1 returns whether num is either equal to the YoloV1 fork block or greater.
func (c *ChainConfig) IsYoloV1(num *big.Int) bool {
	return isForked(c.YoloV1Block, num)
}

// IsEWASM returns whether num represents a block number after the EWASM fork
func (c *ChainConfig) IsEWASM(num *big.Int) bool {
	return isForked(c.EWASMBlock, num)
}

// IsMaxCodeSizeChangeBlock returns whether num represents a block number
// where maxCodeSize change was done
func (c *ChainConfig) IsMaxCodeSizeChangeBlock(num *big.Int) bool {
	return isForked(c.MaxCodeSizeChangeBlock, num)
}

// GetMaxCodeSize returns maxCodeSize for the given block number
func (c *ChainConfig) GetMaxCodeSize(num *big.Int) int {
	maxCodeSize := MaxCodeSize

	if len(c.MaxCodeSizeConfig) > 0 {
		for _, data := range c.MaxCodeSizeConfig {
			if data.Block.Cmp(num) > 0 {
				break
			}
			maxCodeSize = int(data.Size) * 1024
		}
	} else if c.MaxCodeSize > 0 {
		if c.MaxCodeSizeChangeBlock != nil && c.MaxCodeSizeChangeBlock.Cmp(big.NewInt(0)) >= 0 {
			if c.IsMaxCodeSizeChangeBlock(num) {
				maxCodeSize = int(c.MaxCodeSize) * 1024
			}
		} else {
			maxCodeSize = int(c.MaxCodeSize) * 1024
		}
	}
	return maxCodeSize
}

// validates the maxCodeSizeConfig data passed in config
func (c *ChainConfig) CheckMaxCodeConfigData() error {
	if c.MaxCodeSize != 0 || (c.MaxCodeSizeChangeBlock != nil && c.MaxCodeSizeChangeBlock.Cmp(big.NewInt(0)) >= 0) {
		return errors.New("maxCodeSize & maxCodeSizeChangeBlock deprecated. Consider using maxCodeSizeConfig")
	}
	// validate max code size data
	// 1. Code size should not be less than 24 and greater than 128
	// 2. block entries are in ascending order
	prevBlock := big.NewInt(0)
	for _, data := range c.MaxCodeSizeConfig {
		if data.Size < 24 || data.Size > 128 {
			return errors.New("Genesis max code size must be between 24 and 128")
		}
		if data.Block == nil {
			return errors.New("Block number not given in maxCodeSizeConfig data")
		}
		if data.Block.Cmp(prevBlock) < 0 {
			return errors.New("invalid maxCodeSize detail, block order has to be ascending")
		}
		prevBlock = data.Block
	}

	return nil
}

// checks if changes to maxCodeSizeConfig proposed are compatible
// with already existing genesis data
func isMaxCodeSizeConfigCompatible(c1, c2 *ChainConfig, head *big.Int) (error, *big.Int, *big.Int) {
	if len(c1.MaxCodeSizeConfig) == 0 && len(c2.MaxCodeSizeConfig) == 0 {
		// maxCodeSizeConfig not used. return
		return nil, big.NewInt(0), big.NewInt(0)
	}

	// existing config had maxCodeSizeConfig and new one does not have the same return error
	if len(c1.MaxCodeSizeConfig) > 0 && len(c2.MaxCodeSizeConfig) == 0 {
		return fmt.Errorf("genesis file missing max code size information"), head, head
	}

	if len(c2.MaxCodeSizeConfig) > 0 && len(c1.MaxCodeSizeConfig) == 0 {
		return nil, big.NewInt(0), big.NewInt(0)
	}

	// check the number of records below current head in both configs
	// if they do not match throw an error
	c1RecsBelowHead := 0
	for _, data := range c1.MaxCodeSizeConfig {
		if data.Block.Cmp(head) <= 0 {
			c1RecsBelowHead++
		} else {
			break
		}
	}

	c2RecsBelowHead := 0
	for _, data := range c2.MaxCodeSizeConfig {
		if data.Block.Cmp(head) <= 0 {
			c2RecsBelowHead++
		} else {
			break
		}
	}

	// if the count of past records is not matching return error
	if c1RecsBelowHead != c2RecsBelowHead {
		return errors.New("maxCodeSizeConfig data incompatible. updating maxCodeSize for past"), head, head
	}

	// validate that each past record is matching exactly. if not return error
	for i := 0; i < c1RecsBelowHead; i++ {
		if c1.MaxCodeSizeConfig[i].Block.Cmp(c2.MaxCodeSizeConfig[i].Block) != 0 ||
			c1.MaxCodeSizeConfig[i].Size != c2.MaxCodeSizeConfig[i].Size {
			return errors.New("maxCodeSizeConfig data incompatible. maxCodeSize historical data does not match"), head, head
		}
	}

	return nil, big.NewInt(0), big.NewInt(0)
}

// CheckConfigForkOrder checks that we don't "skip" any forks, cypher isn't pluggable enough
// to guarantee that forks
func (c *ChainConfig) CheckConfigForkOrder() error {
	type fork struct {
		name     string
		block    *big.Int
		optional bool // if true, the fork may be nil and next fork is still allowed
	}
	var lastFork fork
	for _, cur := range []fork{
		{name: "homesteadBlock", block: c.HomesteadBlock},
		{name: "daoForkBlock", block: c.DAOForkBlock, optional: true},
		{name: "eip150Block", block: c.EIP150Block},
		{name: "eip155Block", block: c.EIP155Block},
		{name: "eip158Block", block: c.EIP158Block},
		{name: "byzantiumBlock", block: c.ByzantiumBlock},
		{name: "constantinopleBlock", block: c.ConstantinopleBlock},
		{name: "petersburgBlock", block: c.PetersburgBlock},
		{name: "istanbulBlock", block: c.IstanbulBlock},
		{name: "muirGlacierBlock", block: c.MuirGlacierBlock, optional: true},
		{name: "yoloV1Block", block: c.YoloV1Block},
	} {
		if lastFork.name != "" {
			// Next one must be higher number
			if lastFork.block == nil && cur.block != nil {
				return fmt.Errorf("unsupported fork ordering: %v not enabled, but %v enabled at %v",
					lastFork.name, cur.name, cur.block)
			}
			if lastFork.block != nil && cur.block != nil {
				if lastFork.block.Cmp(cur.block) > 0 {
					return fmt.Errorf("unsupported fork ordering: %v enabled at %v, but %v enabled at %v",
						lastFork.name, lastFork.block, cur.name, cur.block)
				}
			}
		}
		// If it was optional and not set, then ignore it
		if !cur.optional || cur.block != nil {
			lastFork = cur
		}
	}
	return nil
}

// isForkIncompatible returns true if a fork scheduled at s1 cannot be rescheduled to
// block s2 because head is already past the fork.
func isForkIncompatible(s1, s2, head *big.Int) bool {
	return (isForked(s1, head) || isForked(s2, head)) && !configNumEqual(s1, s2)
}

// isForked returns whether a fork scheduled at block s is active at the given head block.
func isForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func configNumEqual(x, y *big.Int) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return x.Cmp(y) == 0
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string
	// block numbers of the stored and new configurations
	StoredConfig, NewConfig *big.Int
	// the block number to which the local chain must be rewound to correct the error
	RewindTo uint64
}

func newCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{what, storedblock, newblock, 0}
	if rew != nil && rew.Sign() > 0 {
		err.RewindTo = rew.Uint64() - 1
	}
	return err
}

func (err *ConfigCompatError) Error() string {
	return fmt.Sprintf("mismatching %s in database (have %d, want %d, rewindto %d)", err.What, err.StoredConfig, err.NewConfig, err.RewindTo)
}

// Rules wraps ChainConfig and is merely syntactic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
type Rules struct {
	ChainID                                                 *big.Int
	IsHomestead, IsEIP150, IsEIP155, IsEIP158               bool
	IsByzantium, IsConstantinople, IsPetersburg, IsIstanbul bool
	IsYoloV1                                                bool
}

// Rules ensures c's ChainID is not nil.
func (c *ChainConfig) Rules(num *big.Int) Rules {
	chainID := c.ChainID
	if chainID == nil {
		chainID = new(big.Int)
	}
	return Rules{
		ChainID:          new(big.Int).Set(chainID),
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
		IsPetersburg:     c.IsPetersburg(num),
		IsIstanbul:       c.IsIstanbul(num),
		IsYoloV1:         c.IsYoloV1(num),
	}
}
