package reconfig_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
)

func (f *continuousFixture) observeCLX(t *testing.T) nativeProjection {
	t.Helper()
	var head hexutil.Uint64
	if err := f.ledger.base.clients[0].Call(&head, "eth_blockNumber"); err != nil {
		t.Fatal(err)
	}
	f.ledger.scan(t, uint64(head))
	return f.ledger.base.projection(t)
}

// Ordinary zero-value transfers create real signed/admitted work. Existing
// protocol empty descendants may also occur; height alone is never a deposit.
func (f *continuousFixture) advanceCLX(t *testing.T, target uint64, label string) {
	t.Helper()
	if target > 768 {
		t.Fatal("continuous test height budget")
	}
	before := f.observeCLX(t)
	deadline := time.Now().Add(8 * time.Minute)
	submitted := 0
	for f.ledger.scanned < target {
		if time.Now().After(deadline) {
			t.Fatal("ordinary CLX advance deadline", label)
		}
		f.send(t, 2, f.owners[2], new(big.Int), nil, 21000)
		submitted++
	}
	after := f.observeCLX(t)
	f.waitSource(t, after.Header.Number.Uint64())
	t.Logf("CONTINUOUS_INTERVAL label=%s before=%d after=%d ordinarySignedTransfers=%d custodyBefore=%s custodyAfter=%s", label, before.Header.Number.Uint64(), after.Header.Number.Uint64(), submitted, before.Balance, after.Balance)
}

func (f *continuousFixture) waitSettled(t *testing.T, sequence uint64) {
	t.Helper()
	label := fmt.Sprintf("settlement-%d", sequence)
	watch := f.progressWatch(t, label)
	var p nativeProjection
	for {
		p = f.observeCLX(t)
		f.observeProgress(t, watch, label)
		if watch.point.Sequence >= sequence {
			f.waitSource(t, p.Header.Number.Uint64())
			f.ledger.reconcile(t)
			t.Logf("CONTINUOUS_SETTLED DEXSequence=%d CLXAccepted=%d CLXHeight=%d root=%s custody=%s", sequence, p.Status.Sequence, p.Header.Number.Uint64(), p.Header.Root.Hex(), p.Balance)
			return
		}
		f.relayStatuses(t)
		time.Sleep(250 * time.Millisecond)
	}
}

func (f *continuousFixture) pauseRelays(t *testing.T, hard bool) []uint64 {
	t.Helper()
	heights := make([]uint64, len(f.relays))
	for i, p := range f.relays {
		s := p.status(t)
		heights[i] = s.Authenticated.SourceAnchor.Height
		if !p.stopped && hard {
			select {
			case <-p.done:
				p.stopped = true
			default:
				if err := p.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-p.done:
				case <-time.After(10 * time.Second):
					t.Fatal("owned relay SIGKILL deadline")
				}
				p.stopped = true
			}
		} else {
			p.stop(t)
		}
		t.Logf("CONTINUOUS_RELAY_PAUSE index=%d pid=%d hard=%v sourceAnchor=%d CLXAccepted=%d jobs=%d counts=%v", i, p.cmd.Process.Pid, hard, heights[i], s.Authenticated.CLXSequence, s.TotalJobs, s.Counts)
	}
	return heights
}
func (f *continuousFixture) resumeRelays(t *testing.T, deferred []common.Address) {
	t.Helper()
	for i, old := range f.relays {
		if !old.stopped {
			t.Fatal("relay must be stopped before same-store reopen")
		}
		args := append([]string(nil), old.cmd.Args[1:]...)
		configPath := ""
		for n := 0; n+1 < len(args); n++ {
			if args[n] == "--relay.config" {
				configPath = args[n+1]
			}
		}
		if configPath == "" {
			t.Fatal("owned relay config missing")
		}
		raw, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		var m continuousRelayManifest
		if err = json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m.SourceURL, m.SubmitURL = f.source.Stack.HTTPEndpoint(), f.source.Stack.HTTPEndpoint()
		m.DeferredRecipients = append([]common.Address(nil), deferred...)
		raw, err = json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(configPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(old.cmd.Path, args...)
		cmd.Env = append([]string(nil), old.cmd.Env...)
		p := &continuousRelay{cmd: cmd, done: make(chan error, 1), dir: old.dir, logPath: filepath.Join(filepath.Dir(old.logPath), fmt.Sprintf("relay-restart-%d.log", time.Now().UnixNano()))}
		log, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err = cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		done := p.done
		go func() { err := cmd.Wait(); log.Close(); done <- err; close(done) }()
		f.relays[i] = p
		t.Cleanup(func() { p.stop(t) })
		t.Logf("CONTINUOUS_RELAY_COLD_REOPEN index=%d oldPID=%d newPID=%d sameStore=%s deferredRecipients=%d", i, old.cmd.Process.Pid, cmd.Process.Pid, p.dir, len(deferred))
	}
}

// Only existing test-owned parents/sidecars stop. Their safety WAL bytes are
// preserved; a full process restart cannot reuse an in-memory anchor cache.
func (f *continuousFixture) pauseDEX(t *testing.T) map[int][]byte {
	t.Helper()
	wal := map[int][]byte{}
	for i, c := range f.children {
		if c == nil || c.stopped {
			continue
		}
		c.cli.stop(t)
		// Wait for the existing helper's sender to close its old channel before a
		// restart replaces the channel field used by that helper.
		select {
		case <-c.cli.done:
		case <-time.After(time.Second):
			t.Fatal("owned DEX parent did not close")
		}
		c.stopped = true
		wal[i] = readFinancialWAL(t, c)
		t.Logf("CONTINUOUS_DEX_COLD_PAUSE index=%d parentPID=%d walBytes=%d", i, c.cli.parent.Process.Pid, len(wal[i]))
	}
	return wal
}
func (f *continuousFixture) resumeDEX(t *testing.T, wal map[int][]byte) {
	t.Helper()
	for i := 0; i < len(f.children); i++ {
		original, ok := wal[i]
		if !ok {
			continue
		}
		c := f.children[i]
		if !bytes.Equal(readFinancialWAL(t, c), original) {
			t.Fatal("stopped DEX WAL changed")
		}
		f.children[i] = restartFinancialCLI(t, c, f.init, original)
		f.connectParent(t, f.children[i])
	}
}

// work advances DEX only and returns the financial checkpoint that must later
// settle. It must not invoke any CLX fixture/adapter while the committee is down.
func (f *continuousFixture) withCLXStopped(t *testing.T, work func() uint64) uint64 {
	t.Helper()
	before := f.observeCLX(t)
	oldPIDs := f.network.PIDs()
	f.network.Stop()
	target := work()
	statuses := f.statuses(t)
	for _, s := range statuses {
		if s.Finalized < target {
			t.Fatal("DEX did not finalize during CLX outage")
		}
	}
	sourceHead := f.source.Service.BlockChain().CurrentBlock()
	sourceState, err := f.source.Service.BlockChain().StateAt(sourceHead.Root())
	if err != nil {
		t.Fatal(err)
	}
	status, _, _, err := settlement.NativeStatus(sourceState, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	if status.Sequence >= target {
		t.Fatal("offline CLX magically accepted later DEX state")
	}
	for _, s := range f.relayStatuses(t) {
		if s.TotalJobs > 1280 || s.Authenticated.CLXSequence >= target {
			t.Fatal("relay outage state exceeds bound or falsely settled")
		}
	}
	t.Logf("CONTINUOUS_CLX_OUTAGE oldPIDs=%v beforeHeight=%d CLXAccepted=%d DEXFinalized=%d unsettled=%d sourceRoot=%s", oldPIDs, before.Header.Number.Uint64(), status.Sequence, target, target-status.Sequence, sourceHead.Root().Hex())
	f.network.Restart()
	f.ledger.base.connect(t)
	// A selected already canonical root/receipt/bucket state must survive. New
	// valid in-flight descendants may become canonical; they are separately scanned.
	var restored nativeProjection
	if err = f.ledger.base.clients[0].Call(&restored, "dexfixture_projection", hexutil.Uint64(before.Header.Number.Uint64())); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, restored) {
		t.Fatal("CLX restart changed prior canonical financial state")
	}
	t.Logf("CONTINUOUS_CLX_REOPEN oldPIDs=%v newPIDs=%v retainedHeight=%d retainedRoot=%s", oldPIDs, f.network.PIDs(), before.Header.Number.Uint64(), before.Header.Root.Hex())
	// This ordinary TX also proves Common admission/TxQUIC and ETH reconnect
	// automatically. No peer head is edited and no connection is forced to reset.
	f.send(t, 2, f.owners[2], new(big.Int), nil, 21000)
	f.waitSettled(t, target)
	return target
}

func (f *continuousFixture) requireNoHeavyCLX(t *testing.T) {
	t.Helper()
	if f.ledger.base.projection(t).Engine != (engine.ProcessMetrics{}) || engine.Metrics() != (engine.ProcessMetrics{}) {
		t.Fatal("CLX/source process executed DEX engine")
	}
}
