package core

import (
	"math/big"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
)

func TestIsFastLaneEligible(t *testing.T) {
	to := common.HexToAddress("0x1")

	regular := types.NewTransaction(0, to, big.NewInt(1), txLaneFastMaxGasPerTx, big.NewInt(1), make([]byte, txLaneFastMaxDataBytes))
	if !IsFastLaneEligible(regular) {
		t.Fatalf("expected regular bounded call tx to be fast-lane eligible")
	}

	deploy := types.NewContractCreation(0, big.NewInt(1), txLaneFastMaxGasPerTx, big.NewInt(1), []byte{0x60, 0x00})
	if IsFastLaneEligible(deploy) {
		t.Fatalf("expected contract-creation tx to be slow-lane")
	}

	heavyGas := types.NewTransaction(1, to, big.NewInt(1), txLaneFastMaxGasPerTx+1, big.NewInt(1), nil)
	if IsFastLaneEligible(heavyGas) {
		t.Fatalf("expected tx above fast-lane gas limit to be slow-lane")
	}

	heavyData := types.NewTransaction(2, to, big.NewInt(1), 21000, big.NewInt(1), make([]byte, txLaneFastMaxDataBytes+1))
	if IsFastLaneEligible(heavyData) {
		t.Fatalf("expected tx above fast-lane data limit to be slow-lane")
	}

	// RouteHint is not signed or included in canonical transaction encoding.
	// It must therefore have no effect on deterministic lane classification.
	if !IsFastLaneEligible(regular.WithRouteHint(types.TxRouteSlow)) {
		t.Fatalf("unsigned slow route hint changed bounded native transaction lane")
	}
	if IsFastLaneEligible(heavyData.WithRouteHint(types.TxRouteFast)) {
		t.Fatalf("unsigned fast route hint changed heavy transaction lane")
	}
}
