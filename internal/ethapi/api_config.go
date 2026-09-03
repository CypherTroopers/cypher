package ethapi

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/params"
)

// EthConfigResult is the EIP-7910 response envelope. Next and Last are nil
// when no future execution fork is configured.
type EthConfigResult struct {
	Current *EthForkConfig `json:"current"`
	Next    *EthForkConfig `json:"next"`
	Last    *EthForkConfig `json:"last"`
}

// EthForkConfig reports the execution features the node can actually provide.
// EIP-7910 normally requires all Ethereum CL system contracts. Cypherium omits
// unsupported CL-dependent entries from SystemContracts rather than advertising
// its fail-closed stubs as functional integrations.
type EthForkConfig struct {
	ActivationTime  uint64                    `json:"activationTime"`
	BlobSchedule    *EthBlobSchedule          `json:"blobSchedule"`
	ChainID         string                    `json:"chainId"`
	ForkID          string                    `json:"forkId"`
	Precompiles     map[string]common.Address `json:"precompiles"`
	SystemContracts map[string]common.Address `json:"systemContracts"`
}

type EthBlobSchedule struct {
	BaseFeeUpdateFraction uint64 `json:"baseFeeUpdateFraction"`
	Max                   uint64 `json:"max"`
	Target                uint64 `json:"target"`
}

type modernConfigStage struct {
	name       string
	execution  string
	activation uint64
	blobs      *params.BlobConfig
}

// Config implements EIP-7910's eth_config RPC method for Cancun and later.
// Cypherium executes these EVM forks under ColossusX, so CL-dependent system
// contracts are omitted instead of being presented as working Ethereum
// Beacon-chain integrations.
func (s *PublicEthereumAPI) Config() (*EthConfigResult, error) {
	if s == nil || s.b == nil {
		return nil, errors.New("eth_config backend is unavailable")
	}
	config := s.b.ChainConfig()
	if config == nil || config.ChainID == nil || config.ChainID.Sign() <= 0 {
		return nil, errors.New("eth_config requires a positive chain ID")
	}
	head := s.b.CurrentHeader()
	if head == nil || head.Number == nil {
		return nil, errors.New("eth_config current header is unavailable")
	}
	database := s.b.ChainDb()
	if database == nil {
		return nil, errors.New("eth_config chain database is unavailable")
	}
	genesisHash := rawdb.ReadCanonicalHash(database, 0)
	if genesisHash == (common.Hash{}) {
		return nil, errors.New("eth_config genesis hash is unavailable")
	}
	stages, err := configuredModernStages(config)
	if err != nil {
		return nil, err
	}
	currentIndex := -1
	for i := range stages {
		if stages[i].activation <= head.Time {
			currentIndex = i
		}
	}
	if currentIndex < 0 {
		return nil, errors.New("eth_config is only defined for Cancun-or-later heads")
	}
	current := makeEthForkConfig(config, genesisHash, stages[currentIndex])
	result := &EthConfigResult{Current: current}
	if currentIndex+1 < len(stages) {
		nextIndex := currentIndex + 1
		for nextIndex+1 < len(stages) && stages[nextIndex+1].activation == stages[nextIndex].activation {
			nextIndex++
		}
		result.Next = makeEthForkConfig(config, genesisHash, stages[nextIndex])
		result.Last = makeEthForkConfig(config, genesisHash, stages[len(stages)-1])
	}
	return result, nil
}

func configuredModernStages(config *params.ChainConfig) ([]modernConfigStage, error) {
	modern := config.ModernForkConfig()
	if modern == nil || modern.CancunTime == nil || modern.BlobSchedule == nil || modern.BlobSchedule.Cancun == nil {
		return nil, errors.New("eth_config requires a configured Cancun blob schedule")
	}
	stages := []modernConfigStage{{name: "cancun", execution: "cancun", activation: *modern.CancunTime, blobs: modern.BlobSchedule.Cancun}}
	if modern.PragueTime != nil {
		if modern.BlobSchedule.Prague == nil {
			return nil, errors.New("eth_config requires a configured Prague blob schedule")
		}
		stages = append(stages, modernConfigStage{name: "prague", execution: "prague", activation: *modern.PragueTime, blobs: modern.BlobSchedule.Prague})
	}
	if modern.OsakaTime != nil {
		if modern.BlobSchedule.Osaka == nil {
			return nil, errors.New("eth_config requires a configured Osaka blob schedule")
		}
		stages = append(stages, modernConfigStage{name: "osaka", execution: "osaka", activation: *modern.OsakaTime, blobs: modern.BlobSchedule.Osaka})
	}
	for _, fork := range []struct {
		name   string
		at     *uint64
		config *params.BlobConfig
	}{
		{name: "bpo1", at: modern.BPO1Time, config: modern.BlobSchedule.BPO1},
		{name: "bpo2", at: modern.BPO2Time, config: modern.BlobSchedule.BPO2},
		{name: "bpo3", at: modern.BPO3Time, config: modern.BlobSchedule.BPO3},
		{name: "bpo4", at: modern.BPO4Time, config: modern.BlobSchedule.BPO4},
		{name: "bpo5", at: modern.BPO5Time, config: modern.BlobSchedule.BPO5},
	} {
		if fork.at == nil {
			continue
		}
		if modern.OsakaTime == nil {
			return nil, errors.New("eth_config requires Osaka before " + fork.name)
		}
		if fork.config == nil {
			return nil, errors.New("eth_config requires a configured " + fork.name + " blob schedule")
		}
		// EIP-7892 BPO forks inherit Osaka's execution surface and alter only
		// the three blob scheduling parameters.
		stages = append(stages, modernConfigStage{name: fork.name, execution: "osaka", activation: *fork.at, blobs: fork.config})
	}
	for i, stage := range stages {
		if stage.blobs.Target <= 0 || stage.blobs.Max < stage.blobs.Target || stage.blobs.BaseFeeUpdateFraction <= 0 {
			return nil, errors.New("eth_config contains an invalid " + stage.name + " blob schedule")
		}
		if i > 0 && stage.activation < stages[i-1].activation {
			return nil, errors.New("eth_config contains an out-of-order modern fork schedule")
		}
	}
	return stages, nil
}

func makeEthForkConfig(config *params.ChainConfig, genesisHash common.Hash, stage modernConfigStage) *EthForkConfig {
	result := &EthForkConfig{
		ActivationTime: stage.activation,
		BlobSchedule: &EthBlobSchedule{
			BaseFeeUpdateFraction: uint64(stage.blobs.BaseFeeUpdateFraction),
			Max:                   uint64(stage.blobs.Max),
			Target:                uint64(stage.blobs.Target),
		},
		ChainID:         hexutil.EncodeBig(config.ChainID),
		ForkID:          modernForkHash(config, genesisHash, stage.activation),
		Precompiles:     precompilesForStage(stage.execution),
		SystemContracts: make(map[string]common.Address),
	}
	if stage.execution == "prague" || stage.execution == "osaka" {
		result.SystemContracts["HISTORY_STORAGE_ADDRESS"] = params.HistoryStorageAddress
	}
	return result
}

func precompilesForStage(stage string) map[string]common.Address {
	result := map[string]common.Address{
		"ECREC":                common.BytesToAddress([]byte{0x01}),
		"SHA256":               common.BytesToAddress([]byte{0x02}),
		"RIPEMD160":            common.BytesToAddress([]byte{0x03}),
		"ID":                   common.BytesToAddress([]byte{0x04}),
		"MODEXP":               common.BytesToAddress([]byte{0x05}),
		"BN254_ADD":            common.BytesToAddress([]byte{0x06}),
		"BN254_MUL":            common.BytesToAddress([]byte{0x07}),
		"BN254_PAIRING":        common.BytesToAddress([]byte{0x08}),
		"BLAKE2F":              common.BytesToAddress([]byte{0x09}),
		"KZG_POINT_EVALUATION": common.BytesToAddress([]byte{0x0a}),
	}
	if stage == "prague" || stage == "osaka" {
		result["BLS12_G1ADD"] = common.BytesToAddress([]byte{0x0b})
		result["BLS12_G1MSM"] = common.BytesToAddress([]byte{0x0c})
		result["BLS12_G2ADD"] = common.BytesToAddress([]byte{0x0d})
		result["BLS12_G2MSM"] = common.BytesToAddress([]byte{0x0e})
		result["BLS12_PAIRING_CHECK"] = common.BytesToAddress([]byte{0x0f})
		result["BLS12_MAP_FP_TO_G1"] = common.BytesToAddress([]byte{0x10})
		result["BLS12_MAP_FP2_TO_G2"] = common.BytesToAddress([]byte{0x11})
	}
	if stage == "osaka" {
		result["P256VERIFY"] = common.BytesToAddress([]byte{0x01, 0x00})
	}
	return result
}

// modernForkHash implements the EIP-6122 checksum needed by EIP-7910. The
// older core/forkid package only includes block-number forks, so it cannot
// produce a correct Shanghai-and-later FORK_HASH.
func modernForkHash(config *params.ChainConfig, genesisHash common.Hash, throughTimestamp uint64) string {
	checksum := crc32.ChecksumIEEE(genesisHash[:])
	for _, fork := range configuredBlockForks(config) {
		checksum = updateForkChecksum(checksum, fork)
	}
	modern := config.ModernForkConfig()
	if modern != nil {
		timestamps := []uint64{}
		for _, fork := range []*uint64{
			modern.ShanghaiTime, modern.CancunTime, modern.PragueTime, modern.OsakaTime,
			modern.BPO1Time, modern.BPO2Time, modern.BPO3Time, modern.BPO4Time, modern.BPO5Time,
		} {
			if fork != nil && *fork > 0 && *fork <= throughTimestamp {
				timestamps = append(timestamps, *fork)
			}
		}
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })
		for i, fork := range timestamps {
			if i == 0 || fork != timestamps[i-1] {
				checksum = updateForkChecksum(checksum, fork)
			}
		}
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], checksum)
	return hexutil.Encode(encoded[:])
}

func configuredBlockForks(config *params.ChainConfig) []uint64 {
	if config == nil {
		return nil
	}
	typeOfConfig := reflect.TypeOf(params.ChainConfig{})
	valueOfConfig := reflect.ValueOf(config).Elem()
	forks := make([]uint64, 0)
	bigIntType := reflect.TypeOf(new(big.Int))
	for i := 0; i < typeOfConfig.NumField(); i++ {
		field := typeOfConfig.Field(i)
		if !strings.HasSuffix(field.Name, "Block") || field.Type != bigIntType {
			continue
		}
		fork := valueOfConfig.Field(i).Interface().(*big.Int)
		if fork != nil && fork.Sign() > 0 {
			forks = append(forks, fork.Uint64())
		}
	}
	if modern := config.ModernForkConfig(); modern != nil {
		for _, fork := range []*big.Int{modern.BerlinBlock, modern.LondonBlock, modern.ArrowGlacierBlock, modern.GrayGlacierBlock} {
			if fork != nil && fork.Sign() > 0 {
				forks = append(forks, fork.Uint64())
			}
		}
	}
	sort.Slice(forks, func(i, j int) bool { return forks[i] < forks[j] })
	unique := forks[:0]
	for _, fork := range forks {
		if len(unique) == 0 || unique[len(unique)-1] != fork {
			unique = append(unique, fork)
		}
	}
	return unique
}

func updateForkChecksum(checksum uint32, fork uint64) uint32 {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], fork)
	return crc32.Update(checksum, crc32.IEEETable, encoded[:])
}
