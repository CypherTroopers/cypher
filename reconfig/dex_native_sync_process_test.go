package reconfig_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/p2p/enode"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/rlp"
)

const offCommonPrefix = "DEX_OFF_COMMON "

// The child receives public bootstrap material only. No wallet, vote key,
// operator key, executed state, receipts or DEX state are supplied to it.
type offCommonCommand struct {
	Op, DataDir, Peer string
	Restart           bool
	Genesis           *core.Genesis
	KeyBlock          []byte
	Committee         []*common.Cnode
	Height            uint64
	Hash              common.Hash
	TD                *big.Int
}
type offCommonReport struct {
	PID         int
	Height      uint64
	HTTP, Enode string
	Blocks      [][]byte
	Receipts    []types.Receipts
	Status      settlement.Status
	Buckets     map[settlement.Bucket]protocol.Amount
	Surplus     protocol.Amount
	Balance     *big.Int
	Entries     []protocol.InboxEntry
	Engine      engine.ProcessMetrics
	Mining, CLX bool
	Accounts    int
}

func TestNativeDEXOffCommonProcess(t *testing.T) {
	if os.Getenv("CYPHER_NATIVE_OFF_COMMON_CHILD") != "1" {
		t.Skip("isolated ordinary Common child")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	var commonNode *nativeCommonNode
	reply := func(report offCommonReport) {
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw)+len(offCommonPrefix)+1 >= 16<<20 {
			t.Fatal("ordinary Common report exceeds 16 MiB IPC bound")
		}
		fmt.Fprintln(os.Stdout, offCommonPrefix+string(raw))
	}
	for scanner.Scan() {
		var command offCommonCommand
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			t.Fatal(err)
		}
		switch command.Op {
		case "init":
			if commonNode != nil || command.Genesis == nil || len(command.Committee) != 7 || command.DataDir == "" {
				t.Fatal("invalid Common bootstrap")
			}
			var key types.KeyBlock
			if err := rlp.DecodeBytes(command.KeyBlock, &key); err != nil {
				t.Fatal(err)
			}
			fixture := &reconfig.FHSRewardNetworkFixture{Genesis: command.Genesis, KeyBlock: &key, Committee: command.Committee}
			commonNode = startFHSRewardCommon(t, fixture, nativeCommonOptions{DataDir: command.DataDir, P2P: nativeSyncPeers(), Plain: true, Restart: command.Restart})
			reply(offCommonReport{PID: os.Getpid(), Height: commonNode.Service.BlockChain().CurrentBlock().NumberU64(), HTTP: commonNode.Stack.HTTPEndpoint(), Enode: commonNode.Stack.Server().Self().URLv4()})
		case "sync":
			if commonNode == nil {
				t.Fatal("Common not initialized")
			}
			peer, err := enode.ParseV4(command.Peer)
			if err != nil {
				t.Fatal(err)
			}
			commonNode.Stack.Server().AddPeer(peer)
			peerID := fmt.Sprintf("%x", peer.ID().Bytes()[:8])
			deadline := time.NewTimer(65 * time.Second)
			tick := time.NewTicker(100 * time.Millisecond)
			result := make(chan error, 1)
			active := false
			var lastErr error
			for commonNode.Service.BlockChain().CurrentBlock().NumberU64() < command.Height || active {
				select {
				case err := <-result:
					active = false
					lastErr = err
				case <-tick.C:
					if !active {
						active = true
						go func() {
							result <- commonNode.Service.Downloader().Synchronise(peerID, command.Hash, command.TD, downloader.FullSync)
						}()
					}
				case <-deadline.C:
					commonNode.Service.Downloader().Cancel()
					t.Fatalf("ordinary ETH sync timeout: head=%d peers=%+v last=%v", commonNode.Service.BlockChain().CurrentBlock().NumberU64(), commonNode.Stack.Server().PeersInfo(), lastErr)
				}
			}
			deadline.Stop()
			tick.Stop()
			reply(reportOffCommon(t, commonNode, command.Height))
		case "snapshot":
			if commonNode == nil {
				t.Fatal("Common not initialized")
			}
			reply(reportOffCommon(t, commonNode, command.Height))
		case "follow":
			if commonNode == nil {
				t.Fatal("Common not initialized")
			}
			followOffCommon(t, commonNode, command)
			reply(reportOffCommonLimit(t, commonNode, command.Height, 1024))
		case "snapshot_follow":
			if commonNode == nil {
				t.Fatal("Common not initialized")
			}
			reply(reportOffCommonLimit(t, commonNode, command.Height, 1024))
		case "close":
			if commonNode != nil {
				commonNode.Client.Close()
				if err := commonNode.Stack.Close(); err != nil {
					t.Fatal(err)
				}
			}
			reply(offCommonReport{PID: os.Getpid()})
			return
		default:
			t.Fatal("unknown Common child operation")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func reportOffCommon(t *testing.T, node *nativeCommonNode, height uint64) offCommonReport {
	t.Helper()
	return reportOffCommonLimit(t, node, height, 128)
}

func reportOffCommonLimit(t *testing.T, node *nativeCommonNode, height, limit uint64) offCommonReport {
	t.Helper()
	chain := node.Service.BlockChain()
	// This bounds the test's CLX sync report, independently of the unchanged
	// 64-ancestor finality evidence bound. Claims can follow the last anchor.
	if chain.CurrentBlock().NumberU64() != height || height > limit || limit > 1024 {
		t.Fatal("ordinary Common snapshot height/bound")
	}
	r := offCommonReport{PID: os.Getpid(), Height: height, Engine: engine.Metrics(), Mining: node.Service.IsMining(), CLX: node.Service.ServiceIsRunning(), Accounts: len(node.Stack.AccountManager().Accounts())}
	// Account for the actual JSON representations incrementally, so even a
	// height-bounded chain cannot accumulate an unbounded child IPC response.
	// One MiB is reserved for fixed metadata and array punctuation. The final
	// reply also checks its exact encoded length against the 16 MiB frame.
	reportBytes := 1 << 20
	charge := func(value interface{}) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > (16<<20)-reportBytes {
			t.Fatal("ordinary Common report exceeds 16 MiB IPC bound")
		}
		reportBytes += len(raw)
	}
	for i := uint64(0); i <= height; i++ {
		block := chain.GetBlockByNumber(i)
		if block == nil {
			t.Fatal("ordinary Common block missing")
		}
		raw := block.EncodeToBytes()
		receipts := chain.GetReceiptsByHash(block.Hash())
		charge(raw)
		charge(receipts)
		r.Blocks = append(r.Blocks, raw)
		r.Receipts = append(r.Receipts, receipts)
	}
	state, err := chain.StateAt(chain.CurrentBlock().Root())
	if err != nil {
		t.Fatal(err)
	}
	r.Status, r.Buckets, r.Surplus, err = settlement.NativeStatus(state, params.DEXSettlementAddress)
	if err != nil {
		t.Fatal(err)
	}
	r.Balance = new(big.Int).Set(state.GetBalance(params.DEXSettlementAddress))
	for i := uint64(0); i < r.Status.Deposits; i++ {
		entry, err := settlement.ReadNativeEntry(state, params.DEXSettlementAddress, i)
		if err != nil {
			t.Fatal(err)
		}
		charge(entry)
		r.Entries = append(r.Entries, entry)
	}
	return r
}

type offCommonChild struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	reports chan offCommonReport
	done    chan error
	log     *os.File
	stopped bool
}

func startOffCommonChild(t *testing.T, dir string) *offCommonChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestNativeDEXOffCommonProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "CYPHER_NATIVE_OFF_COMMON_CHILD=1")
	log, err := os.Create(filepath.Join(dir, fmt.Sprintf("off-common-%d.log", time.Now().UnixNano())))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = log
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &offCommonChild{cmd: cmd, input: input, reports: make(chan offCommonReport, 2), done: make(chan error, 1), log: log}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 16<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, offCommonPrefix) {
				var report offCommonReport
				if json.Unmarshal([]byte(strings.TrimPrefix(line, offCommonPrefix)), &report) == nil {
					c.reports <- report
				}
			} else {
				fmt.Fprintln(log, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(log, err)
		}
		close(c.reports)
		c.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		if !c.stopped {
			c.input.Close()
			c.cmd.Process.Kill()
			<-c.done
		}
		c.log.Close()
	})
	return c
}
func (c *offCommonChild) call(t *testing.T, command offCommonCommand) offCommonReport {
	t.Helper()
	raw, err := json.Marshal(command)
	if err != nil || len(raw)+1 >= 8<<20 {
		t.Fatalf("ordinary Common command exceeds 8 MiB IPC bound or cannot encode: %v", err)
	}
	if _, err := c.input.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case report, ok := <-c.reports:
		if ok {
			return report
		}
	case <-time.After(80 * time.Second):
		c.cmd.Process.Kill()
	}
	content, _ := os.ReadFile(c.log.Name())
	t.Fatalf("DEX OFF child failed (%s):\n%s", c.log.Name(), content)
	return offCommonReport{}
}
func (c *offCommonChild) stop(t *testing.T) {
	t.Helper()
	c.call(t, offCommonCommand{Op: "close"})
	c.input.Close()
	err := <-c.done
	c.stopped = true
	if err != nil {
		t.Fatal(err)
	}
}

func nativeSyncOffCommon(t *testing.T, fixture *reconfig.FHSRewardNetworkFixture, source *nativeCommonNode, target uint64) {
	t.Helper()
	if source.Stack.Server().NodeInfo().Ports.Listener == 0 {
		t.Fatal("source Common needs nativeSyncPeers before start")
	}
	head := source.Service.BlockChain().GetBlockByNumber(target)
	if head == nil || source.Service.BlockChain().CurrentBlock().NumberU64() != target {
		t.Fatal("source target mismatch")
	}
	key, err := rlp.EncodeToBytes(fixture.KeyBlock)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bootstrap := offCommonCommand{Op: "init", DataDir: filepath.Join(dir, "node"), Genesis: fixture.Genesis, KeyBlock: key, Committee: fixture.Committee}
	child := startOffCommonChild(t, dir)
	started := child.call(t, bootstrap)
	if started.PID == os.Getpid() || started.Height != 0 {
		t.Fatal("DEX OFF child is not independent/new")
	}
	check := func(r offCommonReport) {
		if r.Height != target || r.Engine != (engine.ProcessMetrics{}) || r.Mining || r.CLX || r.Accounts != 0 || len(r.Blocks) != int(target+1) || len(r.Receipts) != int(target+1) {
			t.Fatal("DEX OFF process role/execution evidence mismatch", r.PID, r.Engine, r.Mining, r.CLX, r.Accounts)
		}
		for height, raw := range r.Blocks {
			block := source.Service.BlockChain().GetBlockByNumber(uint64(height))
			if block == nil || !bytes.Equal(raw, block.EncodeToBytes()) {
				t.Fatalf("DEX OFF ETH full block/root/receipt-root/gas mismatch height=%d", height)
			}
			// JSON transport canonicalizes nil PostState to an empty byte slice.
			// Compare the complete receipt wire data, including derived gas/log
			// metadata, rather than Go slice allocation identity.
			got, gotErr := json.Marshal(r.Receipts[height])
			want, wantErr := json.Marshal(source.Service.BlockChain().GetReceiptsByHash(block.Hash()))
			if gotErr != nil || wantErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("DEX OFF ETH receipt data mismatch height=%d got=%s want=%s errors=%v/%v", height, got, want, gotErr, wantErr)
			}
		}
		state, err := source.Service.BlockChain().StateAt(head.Root())
		if err != nil {
			t.Fatal(err)
		}
		status, buckets, surplus, err := settlement.NativeStatus(state, params.DEXSettlementAddress)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != status || !reflect.DeepEqual(r.Buckets, buckets) || r.Surplus != surplus || r.Balance == nil || r.Balance.Cmp(state.GetBalance(params.DEXSettlementAddress)) != 0 || len(r.Entries) != int(status.Deposits) {
			t.Fatal("DEX OFF ETH native buckets/custody mismatch")
		}
		for i, e := range r.Entries {
			stored, err := settlement.ReadNativeEntry(state, params.DEXSettlementAddress, uint64(i))
			if err != nil || e != stored {
				t.Fatal("DEX OFF ETH native entry mismatch", err)
			}
		}
	}
	synced := child.call(t, offCommonCommand{Op: "sync", Peer: source.Stack.Server().Self().URLv4(), Height: target, Hash: head.Hash(), TD: source.Service.BlockChain().GetTd(head.Hash(), target)})
	check(synced)
	child.stop(t)
	restarted := startOffCommonChild(t, dir)
	bootstrap.Restart = true
	resumed := restarted.call(t, bootstrap)
	if resumed.PID == started.PID || resumed.PID == os.Getpid() || resumed.Height != target {
		t.Fatal("DEX OFF process restart identity/head")
	}
	check(restarted.call(t, offCommonCommand{Op: "snapshot", Height: target}))
	restarted.stop(t)
	t.Logf("DEX_OFF_PROCESS_FULLSYNC_RESTART pid=%d restartPid=%d height=%d root=%s receipts=%s gas=%d financialEngine=0/0/0", started.PID, resumed.PID, target, head.Root().Hex(), head.ReceiptHash().Hex(), head.GasUsed())
}
