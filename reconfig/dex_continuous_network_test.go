package reconfig_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/settlement"
)

// This new config3 scenario is independent of the legacy fixed18-checkpoint
// regression. Its relay workers generate all proofs and native settlement TXs.
func TestFHSNativeContinuousOrdinaryCLI(t *testing.T) {
	f := newContinuousFixture(t)
	f.fund(t)
	f.startDEX(t, 6)
	deferred := []common.Address{f.owners[3]}
	f.startRelays(t, deferred)
	e := &continuousEconomy{fixture: f, certificates: map[uint64][]rewards.Certificate{}}
	e.cycle(t, 1, 0, 4, nil)
	f.waitSettled(t, 18)
	old := f.checkpoint(t, 14)
	if old.Checkpoint.WithdrawalTotal.Big().Cmp(nativeUnits(10)) != 0 {
		t.Fatal("old withdrawal checkpoint missing")
	}
	f.joinSeventh(t)
	f.pauseRelays(t, true)
	f.advanceCLX(t, 65, "second-deposit-boundary-relays-down")
	f.fundMore(t)
	f.resumeRelays(t, deferred)
	e.cycle(t, 2, 20, 6, nil)
	f.waitSettled(t, 38)
	_, finalized := f.minimumHeight(t)
	state, _ := f.financial(t, finalized)
	oldAnchor := state.RollingAnchor.Height
	stoppedWAL := f.pauseDEX(t)
	pausedHead := f.observeCLX(t).Header.Number.Uint64()
	target := pausedHead + 65
	if target < 129 {
		target = 129
	}
	f.advanceCLX(t, target, "all-DEX-cold-over-64")
	t.Logf("CONTINUOUS_DEX_ABSENCE persistedAnchor=%d stoppedCLXHead=%d resumedCLXHead=%d actualStoppedHeightDelta=%d", oldAnchor, pausedHead, f.ledger.scanned, f.ledger.scanned-pausedHead)
	f.fundMore(t)
	f.waitNormalKeyRenewal(t)
	f.resumeDEX(t, stoppedWAL)
	// Own safety is retained by restartFinancialCLI; the application/source must
	// authenticate multiple bounded rolling intervals after this long absence.
	e.flatCatchup(t)
	_, finalized = f.minimumHeight(t)
	state, _ = f.financial(t, finalized)
	if state.RollingAnchor == nil {
		t.Fatal("flat catch-up has no authenticated CLX anchor")
	}
	t.Logf("CONTINUOUS_DEX_ANCHOR phase=flat finalized=%d sourceHeight=%d version=%d cursor=8", finalized, state.RollingAnchor.Height, state.RollingAnchor.Version)
	// The separately specified early-final-deposit variant keeps the final40
	// native funding after actual CLX257, before older checkpoint draining can
	// lengthen the gap again. Only authenticated CDXA may credit it in cycle3.
	f.advanceCLX(t, 257, "final-deposit-after-flat-before-CP58")
	if !f.verifiedRenewalHint(t) {
		t.Fatal("verified source-v2 scheduling observation regressed before final funding")
	}
	f.fundMore(t)
	f.waitSettled(t, 58)
	e.cycle(t, 3, 60, 10, func(work func() uint64) { f.withCLXStopped(t, work) })
	_, finalized = f.minimumHeight(t)
	state, marketAfterRenewal := f.financial(t, finalized)
	if state.RollingAnchor == nil || state.RollingAnchor.Version != 2 || marketAfterRenewal.InboxCursor != 10 {
		t.Fatal("cycle3 did not finalize renewed-key CLX deposit evidence")
	}
	t.Logf("CONTINUOUS_DEX_RENEWED_ANCHOR phase=cycle3 finalized=%d sourceHeight=%d version=%d cursor=%d", finalized, state.RollingAnchor.Height, state.RollingAnchor.Version, marketAfterRenewal.InboxCursor)
	f.waitSettled(t, 78)
	e.cycle(t, 4, 80, 10, nil)
	for h := uint64(101); h <= 107; h++ {
		f.admit(t, h, f.sign(t, 2, engine.Noop, nil))
	}
	e.close(t, 108, 10)
	next := uint64(109)
	for next <= 110 {
		f.admit(t, next, f.sign(t, 2, engine.Noop, nil))
		next++
	}
	next = f.finalize(t, 108, next)
	_, finalized = f.minimumHeight(t)
	f.waitSettled(t, finalized)
	beforeRelease := f.observeCLX(t)
	if beforeRelease.Header.Number.Uint64() < 257 {
		t.Fatal("long scenario did not cross257 actual CLX blocks")
	}
	if paid := f.ledger.base.wallets[f.owners[3]]; paid != nil && paid.Sign() != 0 {
		t.Fatal("deferred old claim paid before explicit relay policy release")
	}
	// Same checkpoint/root/path remains valid after later reward periods and source updates;
	// only a local relay deferral is removed. No protocol recovery rule changes.
	f.pauseRelays(t, false)
	f.resumeRelays(t, nil)
	wantClaims := 72 // four withdrawals; periods1/2 six and periods3..10 seven recipients.
	watch := f.progressWatch(t, "final-native-payments")
	for {
		f.observeCLX(t)
		f.observeProgress(t, watch, "final-native-payments")
		f.relayStatuses(t) // detect child failure; status is not payment authority.
		if len(f.ledger.seenClaims) > wantClaims {
			t.Fatal("unexpected additional native claim")
		}
		if len(f.ledger.seenClaims) == wantClaims && watch.point.Sequence >= finalized {
			f.requireFinalFinancial(t, finalized, wantClaims)
			// Full accounting/proof work may not revive an expired payment clock.
			f.observeProgress(t, watch, "final-native-payments")
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Only after independently authenticated payments may local revalidation
	// progress drive a separate wait clock; the absolute parent bound is shared.
	f.waitRelayAudit(t, finalized)
	f.pauseRelays(t, false)
	final := f.requireFinalFinancial(t, finalized, wantClaims)
	f.requireNoHeavyCLX(t)
	f.checkParents(t, final.Header.Number.Uint64())
	continuousSyncOffCommon(t, f.network.Fixture, f.source, final.Header.Number.Uint64())
	t.Logf("NORMAL_CONTINUOUS_PASS fixture=extended10-early-final-deposit CLXHeight=%d DEXFinalized=%d CLXAccepted=%d nextUnusedDEXHeight=%d funding=345 custody=295 withdrawals=40 rewards=10 uniqueClaims=%d inbox=10 periods=10 lateOwnKeySnapshot=true coldDEXOver64=true CLXOutageDEXProgress=true relays=2 oldClaimSequence=14 oldClaimRoot=%x engine=0/0/0", final.Header.Number.Uint64(), finalized, final.Status.Sequence, next, len(f.ledger.seenClaims), old.Checkpoint.WithdrawalRoot)
}

// Both the payment-phase boundary and overall completion independently reconcile
// canonical receipts/balances/source proofs; relay status cannot replace this.
func (f *continuousFixture) requireFinalFinancial(t *testing.T, finalized uint64, wantClaims int) nativeProjection {
	t.Helper()
	final := f.observeCLX(t)
	f.waitSource(t, final.Header.Number.Uint64())
	f.ledger.reconcile(t)
	var golden struct {
		Inputs, Custody json.Number
		WithdrawalPaid  json.Number `json:"withdrawal_paid"`
		RewardPaid      json.Number `json:"reward_paid"`
		Buckets         map[settlement.Bucket]json.Number
		Accounts        map[string]json.Number
	}
	rawGolden, err := os.ReadFile("../dex/testdata/continuous-extended10-early-final-deposit.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(rawGolden, &golden); err != nil {
		t.Fatal(err)
	}
	if final.Balance.String() != golden.Custody.String() || len(f.ledger.seenClaims) != wantClaims || f.ledger.base.wallets[f.owners[3]].Cmp(nativeUnits(10)) != 0 {
		t.Fatalf("continuous final custody/oldclaim mismatch custody=%s claims=%d", final.Balance, len(f.ledger.seenClaims))
	}
	for bucket, want := range golden.Buckets {
		if f.ledger.buckets[bucket].String() != want.String() {
			t.Fatalf("continuous independent final bucket %s=%s want=%s", bucket, f.ledger.buckets[bucket], want)
		}
	}
	_, market := f.financial(t, finalized)
	if market.RewardPeriod != 10 || market.InboxCursor != 10 || market.Total != golden.Inputs.String() || market.WithdrawReserved != golden.WithdrawalPaid.String() || market.RewardReserved != golden.RewardPaid.String() {
		t.Fatal("continuous DEX financial total/cursor/reservation mismatch")
	}
	for who, want := range map[int]string{0: golden.Accounts["alice"].String(), 1: golden.Accounts["bob"].String()} {
		account := market.Accounts[fmt.Sprintf("%x", f.owners[who][:])]
		if account == nil || account.Cash != want {
			t.Fatal("continuous independent final trader accounting", who, account, want)
		}
	}
	return final
}
