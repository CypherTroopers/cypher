package settlement

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/dex/protocol"
)

// This combines paid-claim retention with a subsequent authenticated anchor
// update and a cold LevelDB reopen. The signed FHS/MPT evidence is real, but the
// context is a unit fixture, not ordinary transaction or process consensus.
func TestNativeRollingPaidClaimAdvanceColdReopenAndDifferentRelay(t *testing.T) {
	r := newRollingNativeFixture(t)
	custody := r.config.DEXDevnet.Custody
	path := t.TempDir()
	disk, err := rawdb.NewLevelDBDatabase(path, 16, 16, "rolling-paid-recovery")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if disk != nil {
			disk.Close()
		}
	}()
	// Move only this newly created fixture's already committed genesis/inbox
	// trie into the owned disk database before doing any rolling transitions.
	iter := r.state.Database().TrieDB().DiskDB().NewIterator(nil, nil)
	for iter.Next() {
		if err = disk.Put(iter.Key(), iter.Value()); err != nil {
			iter.Release()
			t.Fatal(err)
		}
	}
	err = iter.Error()
	iter.Release()
	if err != nil {
		t.Fatal(err)
	}
	r.state, err = state.New(r.state.IntermediateRoot(false), state.NewDatabase(disk), nil)
	if err != nil {
		t.Fatal(err)
	}
	base, err := r.verifier.BootstrapAnchor()
	if err != nil {
		t.Fatal(err)
	}
	a16, _ := r.update(t, base, 16, nil)
	a32, _ := r.update(t, a16, 32, nil)
	a48, _ := r.update(t, a32, 48, nil)
	a, err := openNative(r.state, r.config, r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.f.a = a
	inbox, err := protocol.InboxEntriesRoot(r.entries)
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.Claim{Domain: a.domain, Kind: protocol.Withdrawal, Sequence: 1, ID: protocol.Hash{91}, Owner: [20]byte(r.f.alice), Recipient: [20]byte(r.f.alice), Amount: coins(10)}
	summary := protocol.FinanceSummary{Version: 1, Domain: a.domain, Custody: [20]byte(custody), Sequence: 1, DepositTotal: coins(200), WithdrawalTotal: coins(10)}
	cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: a.domain.ChainID, Genesis: a.domain.Genesis, DEXID: a.domain.DEXID, Epoch: 1, Committee: a.domain.Committee, Sequence: 1, PreRoot: a.nativeRoot, PostRoot: protocol.Hash{92}, FirstBlock: 1, LastBlock: 1, CLXHeight: 16, CLXHash: protocol.Hash(r.blocks[15].Hash()), InboxEnd: 4, InboxRoot: inbox, DataRoot: protocol.Hash{93}, DataSchema: 4}
	cp.WithdrawalRoot, _ = manifest(t, []protocol.Claim{claim})
	bind(t, &cp, summary)
	cpRaw, err := protocol.EncodeNativeCheckpoint(cp, summary, r.f.proof(t, cp), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RunNative(r.state, r.config, r.ctx, cpRaw); err != nil {
		t.Fatal("accept checkpoint bound to retained old anchor", err)
	}
	claimRaw, err := protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstRelay := r.ctx
	firstRelay.Sender = r.f.bob
	paid, err := RunNative(r.state, r.config, firstRelay, claimRaw)
	if err != nil || len(paid) != 33 || paid[32] != 0 {
		t.Fatal("initial old claim payment", err, paid)
	}
	// Advance after payment, not merely before it; the old accepted root and
	// its paid nullifier must survive this ordinary authenticated update.
	a64, _ := r.update(t, a48, 64, nil)
	status, buckets, surplus, err := NativeStatus(r.state, custody)
	if err != nil {
		t.Fatal(err)
	}
	rolling, err := ReadNativeRollingStatus(r.state, custody)
	if err != nil || rolling != (RollingStatus{64, 64, 4}) {
		t.Fatal("advanced rolling state", rolling, err)
	}
	nullSlot, err := ClaimNullifierStorageKey(claim)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := claim.Hash()
	if err != nil || r.state.GetState(custody, nullSlot) != common.Hash(leaf) {
		t.Fatal("paid nullifier", err)
	}
	root, err := r.state.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.state.Database().TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	if err = disk.Close(); err != nil {
		t.Fatal(err)
	}
	disk = nil
	disk, err = rawdb.NewLevelDBDatabase(path, 16, 16, "rolling-paid-recovery")
	if err != nil {
		t.Fatal(err)
	}
	r.state, err = state.New(root, state.NewDatabase(disk), nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		gotStatus, gotBuckets, gotSurplus, err := NativeStatus(r.state, custody)
		if err != nil || gotStatus != status || !reflect.DeepEqual(gotBuckets, buckets) || gotSurplus != surplus {
			t.Fatal("cold replay changed native history/buckets", err)
		}
		gotRolling, err := ReadNativeRollingStatus(r.state, custody)
		if err != nil || gotRolling != rolling {
			t.Fatal("cold replay changed rolling history", err)
		}
		for _, anchor := range []struct {
			height uint64
			want   protocol.Hash
		}{{16, a16.BlockHash}, {64, a64.BlockHash}} {
			got, err := ReadNativeAnchor(r.state, custody, anchor.height)
			if err != nil || got.BlockHash != anchor.want {
				t.Fatal("old or new anchor lost", anchor.height, err)
			}
		}
		if r.state.GetBalance(custody).Cmp(clx(215)) != 0 || r.state.GetBalance(r.f.alice).Cmp(clx(10)) != 0 || r.state.GetBalance(r.f.bob).Sign() != 0 || r.state.GetBalance(r.f.sponsor).Sign() != 0 || r.state.GetState(custody, nullSlot) != common.Hash(leaf) || r.state.IntermediateRoot(false) != root {
			t.Fatal("paid balances/nullifier/root changed after advance and reopen")
		}
	}
	check()
	secondRelay := r.ctx
	secondRelay.Sender = r.f.sponsor
	replayed, err := RunNative(r.state, r.config, secondRelay, claimRaw)
	if err != nil || len(replayed) != 33 || replayed[32] != 1 || !bytes.Equal(replayed[:32], paid[:32]) {
		t.Fatal("different relay failed semantic exact replay", err, replayed)
	}
	check()
	for _, field := range []string{"owner", "recipient", "amount"} {
		altered := claim
		switch field {
		case "owner":
			altered.Owner = [20]byte(r.f.bob)
		case "recipient":
			altered.Recipient = [20]byte(r.f.bob)
		case "amount":
			altered.Amount = coins(11)
		}
		raw, err := protocol.EncodeNativeClaim(altered, 0, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		logs := len(r.state.Logs())
		if _, err = RunNative(r.state, r.config, secondRelay, raw); err == nil || len(r.state.Logs()) != logs {
			t.Fatal("same ID altered claim accepted or emitted log", field, err)
		}
		check()
	}
	t.Log("ROLLING_PAID_RECOVERY oldAnchor=16 paid=10 laterAnchor=64 coldLevelDB=true relayChanged=true custody=215 replayNoPayment=true alteredOwnerRecipientAmountRejected=true")
}
