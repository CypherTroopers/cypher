package reconfig_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/transport"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// exerciseDEXFinancialFaults only controls processes created by the enclosing
// isolated test. It never changes membership, quorum thresholds or vote rules.
// Callback actions are cached once before delivery to multiple public APIs.
func exerciseDEXFinancialFaults(t *testing.T, children []*dexFinancialChild, init testnet.Init, firstHeight uint64, action func(uint64) []byte) uint64 {
	t.Helper()
	if len(children) != 7 || firstHeight < 3 || init.MaxHeight > 128 || init.MaxHeight <= 24 || firstHeight > init.MaxHeight-24 || init.MaxHeight-24-firstHeight < 13 || action == nil {
		t.Fatal("financial fault fixture bounds")
	}
	// Keep an explicit suffix for the following economic scenarios. Additional
	// finality children consume this workload budget, never new voting rights.
	maxFaultHeight := init.MaxHeight - 24
	for i, c := range children {
		if c == nil || c.stopped || c.index != i {
			t.Fatalf("financial fault fixture node%d unavailable", i)
		}
	}
	all := []int{0, 1, 2, 3, 4, 5, 6}
	majority := []int{0, 1, 2, 3, 4}
	next := firstHeight
	cached := map[uint64][]byte{}
	put := func(indices []int, count int) uint64 {
		for i := 0; i < count; i++ {
			h := next
			if h > maxFaultHeight {
				t.Fatal("financial fault actions exhausted bounded horizon")
			}
			raw := cached[h]
			if raw == nil {
				raw = bytes.Clone(action(h))
				cached[h] = raw
			}
			if len(raw) == 0 {
				t.Fatal("empty fault action")
			}
			for _, index := range indices {
				children[index].ok(t, testnet.Request{Op: "action", Height: h, Raw: raw})
			}
			next++
		}
		return next - 1
	}
	waitCertified := func(indices []int, certified uint64) []testnet.Response {
		return waitDEXFinancial(t, children, func(statuses []testnet.Response) bool {
			for _, i := range indices {
				s := statuses[i].Status
				if s == nil || s.Error != "" || s.Certified < certified {
					return false
				}
			}
			return true
		})
	}
	// A QC after skipped leader views does not necessarily finalize its parent.
	// Supply real, signed Noop children until an authentic consecutive-view edge
	// closes the tail, instead of waiting forever with no remaining actions.
	wait := func(indices []int, certified uint64) uint64 {
		for extra := 0; extra <= len(children); extra++ {
			statuses := waitCertified(indices, certified)
			ready := true
			for _, i := range indices {
				ready = ready && statuses[i].Status.Finalized >= certified-1
			}
			if ready {
				return certified
			}
			if extra == len(children) {
				t.Fatalf("financial FHS tail did not finalize after %d authenticated child actions; certified=%d", extra, certified)
			}
			if next != certified+1 {
				t.Fatal("financial tail child is not the next unused action")
			}
			t.Logf("DEX_FINALITY_TAIL_CHILD certified=%d finalized=%d adding=%d active=%d extra=%d/7", certified, statuses[indices[0]].Status.Finalized, next, len(indices), extra+1)
			certified = put(indices, 1)
		}
		panic("unreachable bounded finality loop")
	}
	last := wait(all, firstHeight-1)
	baseline := children[0].ok(t, testnet.Request{Op: "checkpoint", Height: firstHeight - 2})
	economics := func(raw []byte) []byte {
		var f devnet.FinancialState
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		var s engine.State
		if err := json.Unmarshal(f.Engine, &s); err != nil {
			t.Fatal(err)
		}
		if s.Total != "225000000000000000000" {
			t.Fatal("financial fault fixture collateral changed", s.Total)
		}
		withdraw, ok := new(big.Int).SetString(s.WithdrawReserved, 10)
		if !ok {
			t.Fatal("invalid withdraw reserve")
		}
		reward, ok := new(big.Int).SetString(s.RewardReserved, 10)
		if !ok {
			t.Fatal("invalid reward reserve")
		}
		if withdraw.Add(withdraw, reward).String() != "11000000000000000000" {
			t.Fatal("financial fault fixture reserve changed")
		}
		oracle := s.Accounts[hex.EncodeToString(init.Market.Oracle[:])]
		if oracle == nil {
			t.Fatal("fault oracle missing")
		}
		oracle.Nonce = 0
		s.Height = 0
		encoded, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	initialEconomics := economics(baseline.State)
	check := func(indices []int, height uint64, label string) {
		var previous testnet.Response
		for count, index := range indices {
			r := children[index].ok(t, testnet.Request{Op: "checkpoint", Height: height})
			if r.Checkpoint == nil || r.Checkpoint.LastBlock != height || !bytes.Equal(economics(r.State), initialEconomics) {
				t.Fatalf("%s changed financial state node%d", label, index)
			}
			if count > 0 && (*previous.Checkpoint != *r.Checkpoint || !bytes.Equal(previous.State, r.State)) {
				t.Fatalf("%s financial root divergence node%d", label, index)
			}
			previous = r
		}
		t.Logf("DEX_FINANCIAL_FAULT stage=%s live=%d finalized=%d root=%x total=225CLX reserved=11CLX", label, len(indices), height, previous.Checkpoint.PostRoot)
	}

	// Six and then five live processes must produce fresh financial QCs.
	children[6].kill(t)
	wal6 := readFinancialWAL(t, children[6])
	last = put(all[:6], 3)
	last = wait(all[:6], last)
	check(all[:6], last-1, "one-stopped")
	children[5].kill(t)
	wal5 := readFinancialWAL(t, children[5])
	last = put(majority, 3)
	last = wait(majority, last)
	check(majority, last-1, "two-stopped")

	// Restart preserves the exact old WAL before any network activity. A public
	// identity/recipient substitution is rejected before consensus opens that WAL.
	restore := func(index int, old []byte) {
		before := children[index]
		var child *dexFinancialChild
		if before.cli != nil {
			child = restartFinancialCLI(t, before, init, old)
		} else {
			child = startDEXFinancialChild(t, before.dir, index)
		}
		if !reflect.DeepEqual(child.identity, before.identity) || child.cmd.Process.Pid == before.cmd.Process.Pid {
			t.Fatal("restart changed process-owned identity")
		}
		if child.cli == nil && !bytes.Equal(readFinancialWAL(t, child), old) {
			t.Fatal("restart changed unopened FHS WAL")
		}
		if child.cli == nil {
			bad := init
			bad.Peers = append([]transport.Peer(nil), init.Peers...)
			bad.Peers[index].RewardRecipient[0] ^= 1
			if r := child.call(t, testnet.Request{Op: "init", Init: &bad}); r.Error == "" {
				t.Fatal("restart accepted changed registered identity")
			}
			if !bytes.Equal(readFinancialWAL(t, child), old) {
				t.Fatal("rejected identity changed FHS WAL")
			}
			child.ok(t, testnet.Request{Op: "init", Init: &init})
		}
		previous, current := financialWALSafety(t, old), financialWALSafety(t, readFinancialWAL(t, child))
		if current.LastVote.ViewNumber < previous.LastVote.ViewNumber || current.LastTimeoutView < previous.LastTimeoutView || (current.LastVote.ViewNumber == previous.LastVote.ViewNumber && !reflect.DeepEqual(current.LastVote, previous.LastVote)) {
			t.Fatal("restart regressed or changed its own durable vote")
		}
		children[index] = child
	}
	restore(5, wal5)
	restore(6, wal6)
	heal := func() {
		for _, child := range children {
			child.ok(t, testnet.Request{Op: "partition", Allowed: []bool{true, true, true, true, true, true, true}})
		}
		for _, child := range children {
			child.ok(t, testnet.Request{Op: "repair"})
		}
	}
	heal()
	last = wait(all, last)
	check(all, last-1, "restart-repair")
	partition := func(split int) {
		for i, child := range children {
			allowed := make([]bool, 7)
			for j := range allowed {
				allowed[j] = (i < split) == (j < split)
			}
			child.ok(t, testnet.Request{Op: "partition", Allowed: allowed})
		}
	}
	partition(5)
	last = put(majority, 3)
	last = wait(majority, last)
	check(majority, last-1, "partition-5-2")
	heal()
	last = wait(all, last)
	check(all, last-1, "partition-5-2-healed")

	// No peer knew this action before all delivery gates partitioned the7-node
	// committee into4 and3. Old in-flight evidence therefore cannot certify it.
	partition(4)
	fresh := put(all, 1)
	if fresh != last+1 {
		t.Fatal("4/3 action was not fresh")
	}
	deadline := time.NewTimer(2*time.Duration(init.TimeoutMillis)*time.Millisecond + time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	blocked := false
	for !blocked {
		for i, child := range children {
			r := child.ok(t, testnet.Request{Op: "status"})
			if r.Status == nil || r.Status.Certified != last || r.Status.Finalized != last-1 {
				t.Fatalf("4/3 formed progress without quorum: node%d status=%+v fresh=%d", i, r.Status, fresh)
			}
		}
		select {
		case <-deadline.C:
			blocked = true
		case <-tick.C:
		}
	}
	deadline.Stop()
	tick.Stop()
	check(all, last-1, "partition-4-3-no-new-qc")
	heal()
	last = put(all, 3)
	last = wait(all, last)
	check(all, last-1, "partition-4-3-healed")
	return next
}

// readFinancialWAL reads only public proposal/vote safety data after an owned
// crash, never the process identity file containing its private keys.
func readFinancialWAL(t *testing.T, c *dexFinancialChild) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.dir, "fhs", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > 2*1024*1024 {
		t.Fatal("fault WAL byte bound")
	}
	if err := validateFinancialWALChecksum(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// This test-only envelope check identifies the persisted format before hashing.
// Application.Open still performs complete authenticated replay on restart.
func validateFinancialWALChecksum(raw []byte) error {
	var envelope struct {
		Payload  json.RawMessage
		Checksum protocol.Hash
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	var payload struct{ Version, ExecutionSchema uint16 }
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return err
	}
	domain := "common-dex/wal/v1"
	switch payload.Version {
	case 1:
	case 2:
		if payload.ExecutionSchema != 4 {
			return errors.New("fault compact WAL schema")
		}
		domain = "common-dex/wal/v2"
	case 3:
		if payload.ExecutionSchema != 4 {
			return errors.New("fault action dictionary WAL schema")
		}
		domain = "common-dex/wal/v3"
	default:
		return errors.New("fault WAL version")
	}
	if protocol.Digest(domain, envelope.Payload) != envelope.Checksum {
		return errors.New("fault WAL checksum")
	}
	return nil
}

func financialWALSafety(t *testing.T, raw []byte) *hotstuff.FHSSafetyState {
	t.Helper()
	var envelope struct{ Payload json.RawMessage }
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var payload struct{ Safety *hotstuff.FHSSafetyState }
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil || payload.Safety == nil || payload.Safety.LastVote == nil {
		t.Fatal("fault WAL safety missing", err)
	}
	return payload.Safety
}
