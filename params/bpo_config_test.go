package params

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestBPOConfigJSONRoundTrip(t *testing.T) {
	zero, bpo1, bpo2 := uint64(0), uint64(100), uint64(200)
	config := &ChainConfig{ChainID: big.NewInt(12367)}
	config.SetModernForkConfig(&ModernForkConfig{
		BerlinBlock:  big.NewInt(0),
		LondonBlock:  big.NewInt(0),
		ShanghaiTime: &zero,
		CancunTime:   &zero,
		PragueTime:   &zero,
		OsakaTime:    &zero,
		BPO1Time:     &bpo1,
		BPO2Time:     &bpo2,
		BlobSchedule: &BlobScheduleConfig{
			Cancun: &BlobConfig{Target: 3, Max: 6, BaseFeeUpdateFraction: 3338477},
			Prague: &BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			Osaka:  &BlobConfig{Target: 6, Max: 9, BaseFeeUpdateFraction: 5007716},
			BPO1:   &BlobConfig{Target: 10, Max: 15, BaseFeeUpdateFraction: 8346193},
			BPO2:   &BlobConfig{Target: 14, Max: 21, BaseFeeUpdateFraction: 11684671},
		},
	})

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ChainConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	modern := decoded.ModernForkConfig()
	if modern == nil || modern.BPO1Time == nil || *modern.BPO1Time != bpo1 || modern.BPO2Time == nil || *modern.BPO2Time != bpo2 {
		t.Fatalf("BPO activation times did not survive round trip: %#v", modern)
	}
	if modern.BlobSchedule == nil || modern.BlobSchedule.BPO1 == nil || modern.BlobSchedule.BPO1.Target != 10 || modern.BlobSchedule.BPO2 == nil || modern.BlobSchedule.BPO2.Max != 21 {
		t.Fatalf("BPO schedules did not survive round trip: %#v", modern.BlobSchedule)
	}
}
