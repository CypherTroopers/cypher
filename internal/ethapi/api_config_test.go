package ethapi

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
)

type configAPITestBackend struct {
	*londonAPITestBackend
	database ethdb.Database
	config   *params.ChainConfig
	header   *types.Header
}

func (b *configAPITestBackend) ChainDb() ethdb.Database          { return b.database }
func (b *configAPITestBackend) ChainConfig() *params.ChainConfig { return b.config }
func (b *configAPITestBackend) CurrentHeader() *types.Header     { return b.header }

func newConfigAPITestBackend(t *testing.T, timestamp uint64, modern *params.ModernForkConfig) (*configAPITestBackend, common.Hash) {
	t.Helper()
	database := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { database.Close() })
	genesisHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	rawdb.WriteCanonicalHash(database, genesisHash, 0)
	config := &params.ChainConfig{ChainID: big.NewInt(1337)}
	config.SetModernForkConfig(modern)
	return &configAPITestBackend{
		londonAPITestBackend: newLondonAPITestBackend(),
		database:             database,
		config:               config,
		header:               &types.Header{Number: big.NewInt(1), Time: timestamp},
	}, genesisHash
}

func TestEthConfigOsakaAtGenesisReportsFunctionalSurface(t *testing.T) {
	zero := uint64(0)
	backend, genesisHash := newConfigAPITestBackend(t, 0, &params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		PragueTime:   &zero,
		OsakaTime:    &zero,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			Osaka:  &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
		},
	})
	result, err := NewPublicEthereumAPI(backend).Config()
	if err != nil {
		t.Fatalf("eth_config failed: %v", err)
	}
	if result.Next != nil || result.Last != nil {
		t.Fatalf("genesis Osaka should have no future config: %#v", result)
	}
	current := result.Current
	if current.ActivationTime != 0 || current.ChainID != "0x539" {
		t.Fatalf("current identity mismatch: %#v", current)
	}
	wantForkID := forkIDFromValues(genesisHash)
	if current.ForkID != wantForkID {
		t.Fatalf("forkId = %s, want %s", current.ForkID, wantForkID)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal eth_config: %v", err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("unmarshal eth_config wire form: %v", err)
	}
	currentWire, ok := wire["current"].(map[string]interface{})
	if !ok {
		t.Fatalf("current JSON object missing: %s", encoded)
	}
	for _, field := range []string{"activationTime", "blobSchedule", "chainId", "forkId", "precompiles", "systemContracts"} {
		if _, exists := currentWire[field]; !exists {
			t.Fatalf("official EIP-7910 field %s missing: %s", field, encoded)
		}
	}
	if len(currentWire) != 6 || currentWire["chainId"] != "0x539" {
		t.Fatalf("non-standard current JSON shape: %s", encoded)
	}
	if forkID, ok := currentWire["forkId"].(string); !ok || len(forkID) != 10 || forkID[:2] != "0x" {
		t.Fatalf("forkId wire format is not four-byte hex: %s", encoded)
	}
	if wire["next"] != nil || wire["last"] != nil {
		t.Fatalf("next/last must encode as null: %s", encoded)
	}
	if len(current.Precompiles) != 18 || current.Precompiles["P256VERIFY"] != common.BytesToAddress([]byte{0x01, 0x00}) {
		t.Fatalf("Osaka precompiles mismatch: %#v", current.Precompiles)
	}
	if len(current.SystemContracts) != 1 || current.SystemContracts["HISTORY_STORAGE_ADDRESS"] != params.HistoryStorageAddress {
		t.Fatalf("functional system contracts mismatch: %#v", current.SystemContracts)
	}
	for _, unsupported := range []string{"BEACON_ROOTS_ADDRESS", "CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS", "DEPOSIT_CONTRACT_ADDRESS", "WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS"} {
		if _, claimedFunctional := current.SystemContracts[unsupported]; claimedFunctional {
			t.Fatalf("unsupported %s advertised as functional", unsupported)
		}
	}
}

func TestEthConfigCurrentNextAndLast(t *testing.T) {
	shanghai, cancun, prague, osaka := uint64(0), uint64(10), uint64(20), uint64(30)
	backend, genesisHash := newConfigAPITestBackend(t, prague, &params.ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &shanghai,
		CancunTime:   &cancun,
		PragueTime:   &prague,
		OsakaTime:    &osaka,
		BlobSchedule: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &params.BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			Osaka:  &params.BlobConfig{Target: 6, Max: 12, BaseFeeUpdateFraction: 5007716},
		},
	})
	result, err := NewPublicEthereumAPI(backend).Config()
	if err != nil {
		t.Fatalf("eth_config failed: %v", err)
	}
	if result.Current.ActivationTime != prague || result.Next == nil || result.Next.ActivationTime != osaka || result.Last == nil || result.Last.ActivationTime != osaka {
		t.Fatalf("current/next/last selection mismatch: %#v", result)
	}
	if result.Current.ForkID != forkIDFromValues(genesisHash, cancun, prague) {
		t.Fatalf("Prague forkId = %s", result.Current.ForkID)
	}
	if result.Next.ForkID != forkIDFromValues(genesisHash, cancun, prague, osaka) {
		t.Fatalf("Osaka forkId = %s", result.Next.ForkID)
	}
	if len(result.Current.Precompiles) != 17 || len(result.Next.Precompiles) != 18 {
		t.Fatalf("fork precompile counts mismatch: Prague=%d Osaka=%d", len(result.Current.Precompiles), len(result.Next.Precompiles))
	}
}

func forkIDFromValues(genesisHash common.Hash, forks ...uint64) string {
	checksum := crc32.ChecksumIEEE(genesisHash[:])
	for _, fork := range forks {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], fork)
		checksum = crc32.Update(checksum, crc32.IEEETable, encoded[:])
	}
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], checksum)
	return "0x" + common.Bytes2Hex(result[:])
}
