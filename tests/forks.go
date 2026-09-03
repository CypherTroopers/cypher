package tests

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/cypherium/cypher/params"
)

// AvailableForks returns the fork names accepted by the evm t8n tool.
func AvailableForks() []string {
	return []string{
		"Frontier",
		"Homestead",
		"EIP150",
		"EIP158",
		"Byzantium",
		"Constantinople",
		"Petersburg",
		"Istanbul",
		"Berlin",
		"London",
		"Shanghai",
		"Cancun",
		"Prague",
		"Osaka",
	}
}

// GetChainConfig returns a ChainConfig for the requested fork name and any
// extra EIPs encoded as Fork+EIP syntax. This is a small compatibility helper
// for cmd/evm/internal/t8ntool; it does not alter ColossusX consensus.
func GetChainConfig(name string) (*params.ChainConfig, []int, error) {
	if name == "" {
		name = "Istanbul"
	}
	parts := strings.Split(name, "+")
	fork := strings.ToLower(parts[0])
	extraEIPs := make([]int, 0, len(parts)-1)
	for _, part := range parts[1:] {
		if part == "" {
			continue
		}
		eip, err := strconv.Atoi(part)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid extra eip %q", part)
		}
		extraEIPs = append(extraEIPs, eip)
	}

	cfg := *params.AllcolossusXProtocolChanges
	cfg.ChainID = big.NewInt(1)
	cfg.HomesteadBlock = nil
	cfg.EIP150Block = nil
	cfg.EIP155Block = nil
	cfg.EIP158Block = nil
	cfg.ByzantiumBlock = nil
	cfg.ConstantinopleBlock = nil
	cfg.PetersburgBlock = nil
	cfg.IstanbulBlock = nil
	cfg.MuirGlacierBlock = nil
	cfg.YoloV1Block = nil
	cfg.EWASMBlock = nil
	cfg.SetModernForkConfig(nil)

	zero := big.NewInt(0)
	timeZero := uint64(0)
	enableHomestead := func() { cfg.HomesteadBlock = zero }
	enableEIP150 := func() { enableHomestead(); cfg.EIP150Block = zero }
	enableEIP155158 := func() { enableEIP150(); cfg.EIP155Block = zero; cfg.EIP158Block = zero }
	enableByzantium := func() { enableEIP155158(); cfg.ByzantiumBlock = zero }
	enableConstantinople := func() { enableByzantium(); cfg.ConstantinopleBlock = zero }
	enablePetersburg := func() { enableConstantinople(); cfg.PetersburgBlock = zero }
	enableIstanbul := func() { enablePetersburg(); cfg.IstanbulBlock = zero }
	enableBerlin := func() {
		enableIstanbul()
		cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: zero})
	}
	enableLondon := func() {
		enableIstanbul()
		cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: zero, LondonBlock: zero})
	}
	enableShanghai := func() {
		enableIstanbul()
		cfg.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: zero, LondonBlock: zero, ShanghaiTime: &timeZero})
	}
	enableCancun := func() {
		enableIstanbul()
		cfg.SetModernForkConfig(&params.ModernForkConfig{
			BerlinBlock: zero, LondonBlock: zero, ShanghaiTime: &timeZero, CancunTime: &timeZero,
			BlobSchedule: &params.BlobScheduleConfig{
				Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			},
		})
	}
	enablePrague := func() {
		enableIstanbul()
		cfg.SetModernForkConfig(&params.ModernForkConfig{
			BerlinBlock: zero, LondonBlock: zero, ShanghaiTime: &timeZero, CancunTime: &timeZero, PragueTime: &timeZero,
			BlobSchedule: &params.BlobScheduleConfig{
				Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
				Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			},
		})
	}
	enableOsaka := func() {
		enableIstanbul()
		cfg.SetModernForkConfig(&params.ModernForkConfig{
			BerlinBlock: zero, LondonBlock: zero, ShanghaiTime: &timeZero, CancunTime: &timeZero, PragueTime: &timeZero, OsakaTime: &timeZero,
			BlobSchedule: &params.BlobScheduleConfig{
				Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
				Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
				Osaka:  &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			},
		})
	}

	switch fork {
	case "frontier":
	case "homestead":
		enableHomestead()
	case "eip150", "tangerinewhistle":
		enableEIP150()
	case "eip158", "spuriousdragon":
		enableEIP155158()
	case "byzantium":
		enableByzantium()
	case "constantinople":
		enableConstantinople()
	case "petersburg":
		enablePetersburg()
	case "istanbul":
		enableIstanbul()
	case "berlin":
		enableBerlin()
	case "london":
		enableLondon()
	case "shanghai":
		enableShanghai()
	case "cancun":
		enableCancun()
	case "prague":
		enablePrague()
	case "osaka":
		enableOsaka()
	default:
		return nil, nil, fmt.Errorf("unsupported fork %q", name)
	}
	return &cfg, extraEIPs, nil
}
