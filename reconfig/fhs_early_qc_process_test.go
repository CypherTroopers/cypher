package reconfig

import (
	"testing"
	"time"
)

// Only Prepare delivery to one nonleader is dropped. Its own NewView has
// already installed an empty volatile view; authenticated QC broadcasts and
// proposal-body repair must still catch it up through normal state execution.
func TestFHSProcessRecoveryQCBeforePrepare(t *testing.T) {
	children, laggard := newFHSRecoveryProcesses(t)
	for i, child := range children {
		child.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{DropPrepare: i == laggard}})
		child.call(t, fhsProcessCommand{Op: "workload", Workload: i != laggard})
		child.call(t, fhsProcessCommand{Op: "start"})
	}
	final := waitFHSProcesses(t, children, 70*time.Second, func(statuses []fhsProcessReport) bool {
		for _, status := range statuses {
			if status.Height < 1 || status.Certified < 2 {
				return false
			}
		}
		return statuses[laggard].DroppedPrepare > 0
	})
	requireFHSCanonicalAgreement(t, children, final, 1)
	for _, status := range final {
		if status.CanonicalFirstTx != status.FixtureFirstTx || status.RewardReceiptStatus != 1 || status.RewardStateRoot != final[0].RewardStateRoot || status.RewardReceiptGas != final[0].RewardReceiptGas {
			t.Fatal("QC-only catchup differs in executed transaction, receipt, or state root")
		}
	}
	if final[laggard].Submitted != 0 {
		t.Fatal("QC-only laggard unexpectedly submitted fixture transactions")
	}
	t.Logf("QC_BEFORE_PREPARE laggard_pid=%d dropped_prepares=%d finalized=%d certified=%d canonical1=%s; seven independent QUIC validators agree on hash, receipt, gas and state root",
		final[laggard].PID, final[laggard].DroppedPrepare, final[laggard].Height, final[laggard].Certified, final[laggard].Canonical[1].Hex())
}
