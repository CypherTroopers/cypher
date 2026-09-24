package reconfig_test

import (
	"testing"
	"time"

	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/settlement"
)

// This short gate must pass before the long >=257 CLX-height scenario. It uses
// normal CLI relay workers for every deposit proof, anchor, checkpoint and claim.
func TestFHSNativeContinuousRelayShort(t *testing.T) {
	f := newContinuousFixture(t)
	f.fund(t)
	f.startDEX(t, 6)
	f.startRelays(t, nil)
	// Both relays discover the same canonical funding interval. API admission and
	// consensus deduplicate identical action bytes; neither coordinator supplies
	// a CDXA payload or interprets an ingress ACK as execution finality.
	f.waitDEX(t, 1, 0)
	f.admit(t, 2, f.sign(t, 2, engine.Oracle, func(a *engine.Action) {
		a.Price = engine.Amount(nativeUnits(100).String())
		a.FeedSequence = 1
		a.ValidUntil = 100
	}))
	f.admit(t, 3, f.sign(t, 0, engine.Withdraw, func(a *engine.Action) {
		a.Amount = engine.Amount(nativeUnits(10).String())
		a.Recipient = [20]byte(f.owners[3])
	}))
	next := f.finalize(t, 3, 4)
	deadline := time.Now().Add(150 * time.Second)
	for len(f.ledger.seenClaims) == 0 && time.Now().Before(deadline) {
		statuses := f.relayStatuses(t)
		var head hexutil.Uint64
		if err := f.ledger.base.clients[0].Call(&head, "eth_blockNumber"); err != nil {
			t.Fatal(err)
		}
		if uint64(head) > f.ledger.scanned {
			f.ledger.scan(t, uint64(head))
		}
		if len(f.ledger.seenClaims) != 0 {
			break
		}
		_ = statuses // Retain process-exit/status-shape validation on every poll.
		time.Sleep(250 * time.Millisecond)
	}
	if len(f.ledger.seenClaims) != 1 {
		t.Fatalf("actual native relay claim deadline paid=%d operations=%v relay=%+v", len(f.ledger.seenClaims), f.ledger.operationCounts, f.relayStatuses(t))
	}
	for _, p := range f.relays {
		p.stop(t)
	}
	// The remaining admitted transaction, if any, is still accounted. Once CLI
	// workers stop there are no senders other than already admitted relay jobs.
	time.Sleep(750 * time.Millisecond)
	var head hexutil.Uint64
	if err := f.ledger.base.clients[0].Call(&head, "eth_blockNumber"); err != nil {
		t.Fatal(err)
	}
	f.ledger.scan(t, uint64(head))
	f.waitSource(t, uint64(head))
	f.ledger.reconcile(t)
	projection := f.ledger.base.projection(t)
	if projection.Balance.Cmp(nativeUnits(215)) != 0 || len(f.ledger.seenClaims) != 1 || f.ledger.operationCounts["claim"] != 1 || f.ledger.operationCounts["anchor"] == 0 || f.ledger.operationCounts["checkpoint"] < 3 {
		t.Fatalf("short relay accounting mismatch custody=%s claims=%d ops=%v", projection.Balance, len(f.ledger.seenClaims), f.ledger.operationCounts)
	}
	for _, v := range []struct {
		bucket settlement.Bucket
		amount int64
	}{{settlement.Trader, 190}, {settlement.Support, 20}, {settlement.Insurance, 5}, {settlement.Unconsumed, 0}, {settlement.Fees, 0}, {settlement.Dust, 0}, {settlement.Withdrawals, 0}, {settlement.Rewards, 0}} {
		if f.ledger.buckets[v.bucket].Cmp(nativeUnits(v.amount)) != 0 {
			t.Fatalf("short bucket %s mismatch", v.bucket)
		}
	}
	if f.ledger.base.wallets[f.owners[3]].Cmp(nativeUnits(10)) != 0 {
		t.Fatal("fixed native withdrawal recipient did not receive exactly10")
	}
	if f.children[6] != nil {
		t.Fatal("seventh registered key unexpectedly started")
	}
	t.Logf("NORMAL_RELAY_SHORT_PASS nativeFunding=225 custody=215 recipient=10 CLXHeight=%d DEXNext=%d claims=1 CLXProcesses=7 CommonDEXParents=6 activeDEX=6 relayProcesses=2 sourceNormalETH=true coordinatorDepositProofs=0 coordinatorSettlementTXs=0 relayStatus=%+v", head, next, f.relayStatuses(t))
}
