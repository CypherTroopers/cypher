package reconfig

// These opt-in integration tests use the test binary as seven independent
// validators. Only a receive-side fault filter and a preprogrammed transaction
// client are test code: QUIC authentication, consensus, proposal construction,
// validation, DA repair, WAL writes, and finality are production paths.
//
// CYPHER_FHS_PROCESS_RECOVERY=1 go test ./reconfig -run '^TestFHSProcessRecovery' -count=1 -timeout=5m
// Each child owns its BLS secret and LevelDB directory. No existing node data
// or credentials are read. The deployed genesis forks/resource limits are kept;
// only endpoints, identities, funded accounts and genesis time are substituted.
// Each validator uses GOMAXPROCS=2 and a 16 MiB LevelDB cache/32 handles; consensus
// transaction/block limits and timeout parameters retain production values.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rnet/network"
)

const fhsProcessPrefix = "FHS_PROCESS "

type fhsProcessGate struct {
	// Split gates discard, never delay, messages. Dropped QUIC messages have
	// already left the sender's retry queue; healing cannot replay them.
	Split             bool
	TimeoutCollector  bool
	AcceptTC          bool
	DropManifest      bool
	FirstProposalOnly bool
	DropEverything    bool
	Healed            bool
}

type fhsProcessCommand struct {
	ID        uint64
	Op        string
	Genesis   json.RawMessage
	Committee []*common.Cnode
	SenderKey string
	Timestamp uint64
	Gate      fhsProcessGate
	Workload  bool
}

type fhsProcessReport struct {
	ID                uint64
	Error             string
	PID               int
	Address           string
	Public            string
	Genesis           common.Hash
	KeyHash           common.Hash
	CommitteeHash     common.Hash
	View              uint64
	TC                uint64
	Certified         uint64
	Height            uint64
	Canonical         []common.Hash
	NextLeader        string
	DroppedTC         uint64
	DroppedVotes      uint64
	DroppedOther      uint64
	DroppedDA         uint64
	DataTimeouts      uint64
	Manifests         uint64
	RepairData        uint64
	RepairTxs         uint64
	RepairDonors      []string
	FirstManifests    uint64
	FirstRepairTxs    uint64
	FirstRepairDonors []string
	FixtureFirstTx    common.Hash
	CanonicalFirstTx  common.Hash
	Healed            bool
	Submitted         uint64
	WorkError         string
}

type fhsRecoveryChild struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	replies chan fhsProcessReport
	done    chan error
	seq     uint64
	info    fhsProcessReport
	logPath string
	stopped bool
}

func startFHSRecoveryChild(t *testing.T, dir string) *fhsRecoveryChild {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestFHSRecoveryProcessHelper$", "-test.timeout=6m")
	cmd.Env = append(os.Environ(), "CYPHER_FHS_PROCESS_CHILD="+dir, "GOMAXPROCS=2")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "child.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = logFile
	c := &fhsRecoveryChild{cmd: cmd, input: input, replies: make(chan fhsProcessReport, 32), done: make(chan error, 1), logPath: logPath}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 4<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, fhsProcessPrefix) {
				var report fhsProcessReport
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, fhsProcessPrefix)), &report); err == nil {
					c.replies <- report
				}
			} else {
				fmt.Fprintln(logFile, line)
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		<-scanned
		logFile.Close()
		c.done <- err
	}()
	t.Cleanup(func() {
		if !c.stopped {
			_ = c.cmd.Process.Kill()
			<-c.done
			c.stopped = true
		}
		_ = c.input.Close()
		if t.Failed() {
			data, _ := os.ReadFile(c.logPath)
			if artifact, err := os.CreateTemp("", "fhs-process-failure-*.log"); err == nil {
				_, _ = artifact.Write(data)
				_ = artifact.Close()
				t.Logf("validator %d complete log: %s", c.info.PID, artifact.Name())
			}
			if len(data) > 24000 {
				data = data[len(data)-24000:]
			}
			t.Logf("validator %d log tail:\n%s", c.info.PID, data)
		}
	})
	select {
	case c.info = <-c.replies:
		if c.info.Error != "" {
			t.Fatal(c.info.Error)
		}
	case err := <-c.done:
		c.stopped = true
		t.Fatalf("child startup: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("child startup timed out")
	}
	return c
}

func (c *fhsRecoveryChild) call(t *testing.T, command fhsProcessCommand) fhsProcessReport {
	t.Helper()
	c.seq++
	command.ID = c.seq
	if err := json.NewEncoder(c.input).Encode(command); err != nil {
		t.Fatal(err)
	}
	timeout := 20 * time.Second
	if command.Op == "init" {
		// Genesis/state initialization is CPU intensive under the race detector.
		// Keep the ordinary command deadline strict once the node is initialized.
		timeout = time.Minute
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case report := <-c.replies:
		if report.ID != command.ID {
			t.Fatalf("child reply ID: have %d want %d", report.ID, command.ID)
		}
		if report.Error != "" {
			t.Fatalf("validator %d %s: %s", c.info.PID, command.Op, report.Error)
		}
		return report
	case err := <-c.done:
		c.stopped = true
		t.Fatalf("validator %d exited during %s: %v", c.info.PID, command.Op, err)
	case <-deadline.C:
		t.Fatalf("validator %d %s timed out", c.info.PID, command.Op)
	}
	return fhsProcessReport{}
}

func newFHSRecoveryProcesses(t *testing.T) ([]*fhsRecoveryChild, int) {
	t.Helper()
	if os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" {
		t.Skip("set CYPHER_FHS_PROCESS_RECOVERY=1 for isolated seven-process QUIC trials")
	}
	genesis, err := os.ReadFile(filepath.Join("..", "genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	timestamp := uint64(time.Now().Unix())
	children := make([]*fhsRecoveryChild, 7)
	committee := make([]*common.Cnode, 7)
	seenPID, seenPublic, seenAddress := make(map[int]bool), make(map[string]bool), make(map[string]bool)
	for i := range children {
		children[i] = startFHSRecoveryChild(t, t.TempDir())
		info := children[i].info
		if seenPID[info.PID] || seenPublic[info.Public] || seenAddress[info.Address] {
			t.Fatal("validators share a process, endpoint, or BLS identity")
		}
		seenPID[info.PID], seenPublic[info.Public] = true, true
		seenAddress[info.Address] = true
		committee[i] = &common.Cnode{Address: info.Address, Public: info.Public, CoinBase: common.BigToAddress(big.NewInt(int64(i + 1))).Hex()}
	}
	var rootGenesis core.Genesis
	if err := json.Unmarshal(genesis, &rootGenesis); err != nil {
		t.Fatal(err)
	}
	// Only fixture committee order is controlled; the root election seed and
	// native timeout settings remain unchanged. The killed proposer and the
	// DA-isolated laggard must not lead views 2..10 while the five available
	// voters build the historical repair frontier. Otherwise this phase tests
	// an intentionally unavailable leader's long production lease instead.
	order := []int{0, 1, 2, 3, 4, 5, 6}
	laggard := -1
	for attempt := 0; attempt < 5040; attempt++ {
		ordered := make([]*common.Cnode, len(committee))
		for i, original := range order {
			ordered[i] = committee[original]
		}
		hash := (&bftview.Committee{List: ordered}).RlpHash()
		originalLeader, err := fairHotstuffLeaderIndex(rootGenesis.Config.FairHotstuffSeed, rootGenesis.Config.ChainID.Uint64(), 1, hash, 7)
		if err != nil {
			t.Fatal(err)
		}
		used := map[int]bool{int(originalLeader): true}
		originalLeadsAgain := false
		for view := uint64(2); view <= 10; view++ {
			leader, err := fairHotstuffLeaderIndex(rootGenesis.Config.FairHotstuffSeed, rootGenesis.Config.ChainID.Uint64(), view, hash, 7)
			if err != nil {
				t.Fatal(err)
			}
			used[int(leader)] = true
			originalLeadsAgain = originalLeadsAgain || leader == originalLeader
		}
		if !originalLeadsAgain {
			for i := range children {
				if !used[i] {
					laggard = i
					break
				}
			}
		}
		if laggard >= 0 {
			reordered := make([]*fhsRecoveryChild, len(children))
			for i, original := range order {
				reordered[i] = children[original]
			}
			children, committee = reordered, ordered
			t.Logf("fixture committee permutation=%v; proposer=%d laggard=%d; both excluded from scheduled views2..10", order, originalLeader, laggard)
			break
		}
		// Enumerate all 7! permutations in a deterministic, bounded order.
		i := len(order) - 2
		for i >= 0 && order[i] >= order[i+1] {
			i--
		}
		if i < 0 {
			break
		}
		j := len(order) - 1
		for order[j] <= order[i] {
			j--
		}
		order[i], order[j] = order[j], order[i]
		for left, right := i+1, len(order)-1; left < right; left, right = left+1, right-1 {
			order[left], order[right] = order[right], order[left]
		}
	}
	if laggard < 0 {
		t.Fatal("no bounded generated committee permutation supplies the recovery leader schedule")
	}
	var genesisHash common.Hash
	for _, c := range children {
		status := c.call(t, fhsProcessCommand{Op: "init", Genesis: genesis, Committee: committee, SenderKey: hex.EncodeToString(crypto.FromECDSA(key)), Timestamp: timestamp})
		if genesisHash == (common.Hash{}) {
			genesisHash = status.Genesis
		}
		if status.Genesis != genesisHash {
			t.Fatal("independent validators derived different genesis commitments")
		}
		c.info = status
	}
	return children, laggard
}

func fhsProcessStatuses(t *testing.T, children []*fhsRecoveryChild) []fhsProcessReport {
	t.Helper()
	statuses := make([]fhsProcessReport, len(children))
	for i, c := range children {
		if !c.stopped {
			statuses[i] = c.call(t, fhsProcessCommand{Op: "status"})
		}
	}
	return statuses
}

func waitFHSProcesses(t *testing.T, children []*fhsRecoveryChild, timeout time.Duration, condition func([]fhsProcessReport) bool) []fhsProcessReport {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []fhsProcessReport
	for time.Now().Before(deadline) {
		last = fhsProcessStatuses(t, children)
		for _, s := range last {
			if s.WorkError != "" {
				t.Fatalf("fixture transaction client: %s", s.WorkError)
			}
		}
		if condition(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("recovery deadline exceeded; status=%+v", last)
	return nil
}

func requireFHSCanonicalAgreement(t *testing.T, children []*fhsRecoveryChild, statuses []fhsProcessReport, height uint64) {
	t.Helper()
	var expected common.Hash
	for i, s := range statuses {
		if children[i].stopped {
			continue
		}
		if s.Height < height || len(s.Canonical) <= int(height) {
			t.Fatalf("validator %d has no finalized height %d", i, height)
		}
		if expected == (common.Hash{}) {
			expected = s.Canonical[height]
		}
		if s.Canonical[height] == (common.Hash{}) || s.Canonical[height] != expected {
			t.Fatalf("canonical divergence at %d: %+v", height, statuses)
		}
	}
}

func TestFHSProcessRecoverySplitTC(t *testing.T) {
	children, _ := newFHSRecoveryProcesses(t)
	// Form exactly one TC at validator 0. Deliver it to four validators,
	// including the next proposer, leaving three unable to join that view.
	committeeHash := children[0].info.CommitteeHash
	var genesis core.Genesis
	raw, _ := os.ReadFile(filepath.Join("..", "genesis.json"))
	if err := json.Unmarshal(raw, &genesis); err != nil {
		t.Fatal(err)
	}
	leader, err := fairHotstuffLeaderIndex(genesis.Config.FairHotstuffSeed, genesis.Config.ChainID.Uint64(), 2, committeeHash, 7)
	if err != nil {
		t.Fatal(err)
	}
	advanced := map[int]bool{0: true, int(leader): true}
	for i := 0; len(advanced) < 4; i++ {
		advanced[i] = true
	}
	for i, c := range children {
		c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Split: true, TimeoutCollector: i == 0, AcceptTC: advanced[i]}})
		c.call(t, fhsProcessCommand{Op: "workload", Workload: true})
		c.call(t, fhsProcessCommand{Op: "start"})
	}
	for _, c := range children {
		c.call(t, fhsProcessCommand{Op: "timeout"})
	}
	split := waitFHSProcesses(t, children, 20*time.Second, func(s []fhsProcessReport) bool {
		for i, r := range s {
			if advanced[i] {
				if r.TC != 1 {
					return false
				}
			} else if r.TC != 0 || r.DroppedTC == 0 {
				return false
			}
		}
		return true
	})
	for _, s := range split {
		if s.Height != 0 {
			t.Fatal("fault phase unexpectedly finalized a block")
		}
	}
	// Receive filters have no delayed-message queue. Briefly discard all
	// packets while successful QUIC sends drain, then open fresh delivery.
	for _, c := range children {
		c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{DropEverything: true}})
	}
	time.Sleep(300 * time.Millisecond)
	for _, c := range children {
		c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
	}
	// No timeout, proposal, vote, QC, or block commands after this boundary.
	final := waitFHSProcesses(t, children, 70*time.Second, func(s []fhsProcessReport) bool {
		for _, r := range s {
			if !r.Healed || r.Height < 2 {
				return false
			}
		}
		return true
	})
	requireFHSCanonicalAgreement(t, children, final, 2)
	t.Logf("partial TC loss healed automatically over QUIC; before=%+v after=%+v", split, final)
}

func TestFHSProcessRecoveryOfflineProposer(t *testing.T) {
	children, laggard := newFHSRecoveryProcesses(t)
	original := -1
	for i, c := range children {
		if c.info.Address == children[0].info.NextLeader {
			original = i
		}
	}
	if original < 0 {
		t.Fatal("genesis proposal leader is unavailable")
	}
	for i, c := range children {
		c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{DropManifest: i == laggard, FirstProposalOnly: true}})
		c.call(t, fhsProcessCommand{Op: "workload", Workload: i != laggard})
		c.call(t, fhsProcessCommand{Op: "start"})
	}
	before := waitFHSProcesses(t, children, 30*time.Second, func(s []fhsProcessReport) bool {
		certified := 0
		for i, r := range s {
			if i != laggard && r.Certified == 1 {
				certified++
			}
		}
		return certified == 6 && s[laggard].Height == 0 && s[laggard].Submitted == 0 && s[laggard].DroppedDA > 0
	})
	if before[laggard].RepairTxs != 0 {
		t.Fatal("laggard obtained a transaction before its missing-data assertion")
	}
	// While its proposal data is unavailable at the laggard, partition the
	// timeout certificate for the next view into exactly four/three recipients.
	// All children already certified proposal 1 except the isolated laggard;
	// the scheduled fixture client withholds transaction 2 until delivery heals.
	var rootGenesis core.Genesis
	encoded, err := os.ReadFile(filepath.Join("..", "genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &rootGenesis); err != nil {
		t.Fatal(err)
	}
	nextLeader, err := fairHotstuffLeaderIndex(rootGenesis.Config.FairHotstuffSeed, rootGenesis.Config.ChainID.Uint64(), 3, before[0].CommitteeHash, 7)
	if err != nil {
		t.Fatal(err)
	}
	collector := (laggard + 1) % 7
	advanced := map[int]bool{collector: true, int(nextLeader): true}
	for i := 0; len(advanced) < 4; i++ {
		advanced[i] = true
	}
	for i, c := range children {
		c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Split: true, TimeoutCollector: i == collector, AcceptTC: advanced[i]}})
	}
	for _, c := range children {
		c.call(t, fhsProcessCommand{Op: "timeout"})
	}
	split := waitFHSProcesses(t, children, 20*time.Second, func(s []fhsProcessReport) bool {
		for i, r := range s {
			if advanced[i] {
				if r.TC != 2 {
					return false
				}
			} else if r.TC >= 2 || r.DroppedTC == 0 {
				return false
			}
		}
		if s[laggard].RepairTxs != 0 || s[laggard].Manifests != 0 || s[laggard].Submitted != 0 || s[laggard].Height != 0 {
			t.Fatal("laggard obtained proposal data during the combined fault phase")
		}
		return true
	})
	// This is an actual OS process crash, not an application flag. There are
	// six survivors, of which five already hold proposal data.
	if err := children[original].cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-children[original].done
	children[original].stopped = true
	for i, c := range children {
		if i != original {
			c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{DropEverything: true}})
		}
	}
	time.Sleep(300 * time.Millisecond)
	for i, c := range children {
		if i != original {
			c.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: i != laggard, DropManifest: i == laggard}})
		}
	}
	// Let all five available voters finalize past the missing first proposal.
	// This makes its eventual repair historical at every healthy donor and
	// forces the laggard to recover after its initial body wait has expired.
	advancedHeads := waitFHSProcesses(t, children, 90*time.Second, func(s []fhsProcessReport) bool {
		for i, r := range s {
			if i != original && i != laggard && r.Height < 5 {
				return false
			}
		}
		return true
	})
	time.Sleep(proposalBodyWaitBaseTimeout + time.Second)
	expired := waitFHSProcesses(t, children, 10*time.Second, func(s []fhsProcessReport) bool {
		return s[laggard].DataTimeouts > 0
	})
	delayed := expired[laggard]
	if delayed.Height != 0 || delayed.Manifests != 0 || delayed.RepairTxs != 0 || delayed.Submitted != 0 || delayed.Healed {
		t.Fatal("laggard escaped data isolation before the final communication restoration")
	}
	t.Logf("before final heal: laggard PID=%d height=%d bodyTimeouts=%d manifests=%d repairTXs=%d; all five healthy donors finalized height5", delayed.PID, delayed.Height, delayed.DataTimeouts, delayed.Manifests, delayed.RepairTxs)
	children[laggard].call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
	// All communication faults are now removed. No controller consensus or
	// workload commands follow this boundary: only status polling and assertions.
	final := waitFHSProcesses(t, children, 70*time.Second, func(s []fhsProcessReport) bool {
		for i, r := range s {
			if i != original && (!r.Healed || r.Height < 5) {
				return false
			}
		}
		return s[laggard].FirstRepairTxs > 0 && s[laggard].FirstManifests > 0
	})
	for _, donor := range final[laggard].FirstRepairDonors {
		if donor == children[original].info.Address {
			t.Fatal("stopped proposer counted as a recovery donor")
		}
	}
	if len(final[laggard].FirstRepairDonors) == 0 {
		t.Fatal("no actual nonleader donor retrieval observed")
	}
	if final[laggard].CanonicalFirstTx != children[laggard].info.FixtureFirstTx {
		t.Fatal("repaired proposal 1 did not finalize the initially missing fixture transaction")
	}
	requireFHSCanonicalAgreement(t, children, final, 5)
	for i, r := range final {
		if i != original && i != laggard && r.Certified != expired[i].Certified {
			t.Fatal("new donor QC obscures recovery from the timed-out retained HighQC")
		}
	}
	t.Logf("partial TC delivery=%+v; proposer PID %d killed; historical donor heads=%+v; laggard restored missing first-proposal data from %v; status=%+v", split, children[original].info.PID, advancedHeads, final[laggard].FirstRepairDonors, final)
}

type fhsRecoveryProcess struct {
	mu         sync.Mutex
	dir        string
	secret     bls.SecretKey
	address    string
	reserved   net.PacketConn
	service    *Service
	backend    *ReconfigBackend
	gate       fhsProcessGate
	stats      fhsProcessReport
	workload   atomic.Bool
	txs        []*types.Transaction
	admissions []*types.CommonTxAdmissionBatch
	quit       chan struct{}
}

func TestFHSRecoveryProcessHelper(t *testing.T) {
	dir := os.Getenv("CYPHER_FHS_PROCESS_CHILD")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	process := &fhsRecoveryProcess{dir: dir, quit: make(chan struct{})}
	log.Root().SetHandler(log.FilterHandler(func(record *log.Record) bool {
		if record.Msg == "FHS HighQC validation completion rejected" && strings.Contains(fmt.Sprint(record.Ctx...), "proposal body timeout") {
			process.mu.Lock()
			process.stats.DataTimeouts++
			process.mu.Unlock()
		}
		return record.Lvl <= log.LvlWarn || strings.Contains(record.Msg, "HOTSTUFF PROPOSAL") || strings.Contains(record.Msg, "HighQC")
	}, log.StreamHandler(os.Stderr, log.LogfmtFormat())))
	process.secret.SetByCSPRNG()
	if err := os.WriteFile(filepath.Join(dir, "test-bls.key"), []byte(process.secret.SerializeToHexStr()), 0600); err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	process.address = socket.LocalAddr().String()
	process.reserved = socket
	defer socket.Close()
	process.stats = fhsProcessReport{PID: os.Getpid(), Address: process.address, Public: process.secret.GetPublicKey().SerializeToHexStr()}
	fhsWriteProcessReport(process.stats)
	decoder := json.NewDecoder(os.Stdin)
	for {
		var command fhsProcessCommand
		if err := decoder.Decode(&command); err != nil {
			break
		}
		err = process.command(command)
		report := process.report()
		report.ID = command.ID
		if err != nil {
			report.Error = err.Error()
		}
		fhsWriteProcessReport(report)
	}
	if process.backend != nil {
		_ = process.backend.Stop()
	}
}

func fhsWriteProcessReport(report fhsProcessReport) {
	encoded, _ := json.Marshal(report)
	fmt.Println(fhsProcessPrefix + string(encoded))
}

func (p *fhsRecoveryProcess) command(command fhsProcessCommand) error {
	switch command.Op {
	case "init":
		return p.initialize(command)
	case "gate":
		p.mu.Lock()
		p.gate = command.Gate
		p.mu.Unlock()
	case "workload":
		p.workload.Store(command.Workload)
	case "start":
		var coinbase string
		for _, node := range p.service.chainConfig.GenCommittee {
			if node.Address == p.address {
				coinbase = node.CoinBase
			}
		}
		return p.service.start(&common.NodeConfig{Private: p.secret.SerializeToHexStr(), Public: p.secret.GetPublicKey().SerializeToHexStr(), Coinbase: coinbase})
	case "timeout":
		p.service.enqueueFHSTimeout()
	case "status":
	default:
		return fmt.Errorf("unknown process command %q", command.Op)
	}
	return nil
}

func (p *fhsRecoveryProcess) report() fhsProcessReport {
	p.mu.Lock()
	report := p.stats
	report.RepairDonors = append([]string(nil), p.stats.RepairDonors...)
	report.FirstRepairDonors = append([]string(nil), p.stats.FirstRepairDonors...)
	report.Healed = p.gate.Healed
	p.mu.Unlock()
	if p.service == nil {
		return report
	}
	s := p.service
	view := s.GetCurrentView()
	report.View = view.ViewNumber
	report.CommitteeHash = view.CommitteeHash
	report.KeyHash = view.KeyHash
	_, report.NextLeader, _ = s.CurrentState()
	if tc := s.HighestFHSTimeoutCertificate(); tc != nil {
		report.TC = tc.Statement.TimedOutView
	}
	if qc := s.HighestCertified(); qc != nil {
		report.Certified = qc.Number
	}
	report.Genesis = s.bc.Genesis().Hash()
	report.Height = s.bc.CurrentBlockN()
	if len(p.txs) > 0 {
		report.FixtureFirstTx = p.txs[0].Hash()
	}
	if report.Height > 0 {
		if first := s.bc.GetBlockByNumber(1); first != nil && len(first.Transactions()) > 0 {
			report.CanonicalFirstTx = first.Transactions()[0].Hash()
		}
	}
	for i := uint64(0); i <= report.Height; i++ {
		report.Canonical = append(report.Canonical, s.bc.GetCanonicalHash(i))
	}
	return report
}

func (p *fhsRecoveryProcess) initialize(command fhsProcessCommand) error {
	var genesis core.Genesis
	if err := json.Unmarshal(command.Genesis, &genesis); err != nil {
		return err
	}
	config := genesis.Config
	if config == nil || !config.FairHotstuff || !config.FixedCommittee || config.FixedLeader || len(command.Committee) != 7 || config.EffectiveRnetTransport() != "quic" || config.EffectiveRnetFallbackTransport() != "none" {
		return fmt.Errorf("fixture requires deployed seven-member fixed-committee FHS QUIC genesis")
	}
	config.GenCommittee = make(params.GenesisCommittee)
	committee := &bftview.Committee{List: command.Committee}
	for i, n := range command.Committee {
		config.GenCommittee[i] = *n
	}
	clientKey, err := crypto.HexToECDSA(command.SenderKey)
	if err != nil {
		return err
	}
	sender := crypto.PubkeyToAddress(clientKey.PublicKey)
	config.CommonRPCSigners = []common.Address{sender}
	genesis.Alloc = core.GenesisAlloc{sender: core.GenesisAccount{Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(27), nil)}}
	genesis.Timestamp = command.Timestamp
	genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(config)
	if err != nil {
		return err
	}
	store, err := leveldb.New(filepath.Join(p.dir, "chain"), 16, 32, "")
	if err != nil {
		return err
	}
	db := rawdb.NewDatabase(store)
	mux := new(event.TypeMux)
	engine := colossusX.NewFaker()
	backend := &ReconfigBackend{chainDb: db, eventMux: mux, engine: engine, pendingLogsFeed: new(event.Feed), calcGasLimitFunc: func(block *types.Block) uint64 { return block.GasLimit() }}
	backend.candidatePool = core.NewCandidatePool(backend, mux, db)
	key := types.NewKeyBlock(&types.KeyBlockHeader{Number: big.NewInt(0), Difficulty: big.NewInt(1), Time: command.Timestamp, CommitteeHash: committee.RlpHash()})
	rawdb.WriteKeyBlock(db, key)
	rawdb.WriteKeyBlockHash(db, key.Hash(), 0)
	rawdb.WriteHeadKeyBlockHash(db, key.Hash())
	rawdb.WriteHeadKeyHeaderHash(db, key.Hash())
	rawdb.WriteTd(db, key.Hash(), 0, key.Difficulty())
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(0, key.Hash(), committee) {
		return fmt.Errorf("persist independent genesis committee")
	}
	backend.keyBlockchain, err = core.NewKeyBlockChain(backend, db, nil, config, engine, mux)
	if err != nil {
		return err
	}
	genesisBlock, err := genesis.Commit(db)
	if err != nil {
		return err
	}
	backend.blockchain, err = core.NewBlockChain(db, nil, config, engine, vm.Config{}, nil, nil, backend.keyBlockchain)
	if err != nil {
		return err
	}
	poolConfig := core.DefaultTxPoolConfig
	poolConfig.Journal = ""
	backend.txPool = core.NewTxPool(poolConfig, config, backend.blockchain)
	core.SetCommonRPCAdmissionDatabase(db)
	core.SetCommonRPCAdmissionFinalizedLookup(backend.blockchain.IsFinalizedTransaction)
	// The fixture client signs ordinary EVM transfers and admission records
	// before faults begin. It never signs consensus messages or constructs QCs.
	for nonce := uint64(0); nonce < 5; nonce++ {
		tx, err := types.SignTx(types.NewTransaction(nonce, common.HexToAddress("0x1000"), big.NewInt(1), 21000, big.NewInt(params.FixedBaseFeePerGas*2), nil), types.NewEIP155Signer(config.ChainID), clientKey)
		if err != nil {
			return err
		}
		admission := &types.CommonTxAdmissionBatch{ChainID: config.ChainID, GenesisHash: genesisBlock.Hash(), Miner: sender, Timestamp: command.Timestamp, TxHashes: []common.Hash{tx.Hash()}}
		admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
		admission.AdmissionID = types.CommonTxAdmissionID(admission)
		admission.Signature, err = crypto.Sign(types.CommonTxAdmissionSigningHash(admission).Bytes(), clientKey)
		if err != nil {
			return err
		}
		p.txs = append(p.txs, tx)
		p.admissions = append(p.admissions, admission)
	}
	p.backend = backend
	if err := p.reserved.Close(); err != nil {
		return err
	}
	p.service = newService("fhsProcessRecovery", p.address, config, backend)
	backend.service = p.service
	// This registered processor replaces only fault delivery, delegating every
	// admitted envelope to the same production handler as a normal validator.
	p.service.netService.server.RegisterProcessorFunc(network.RegisterMessage(&networkMsg{}), p.receive)
	p.service.updateCurrentView(nil, nil, false)
	go p.transactionClient()
	return nil
}

func (p *fhsRecoveryProcess) receive(envelope *network.Envelope) {
	msg, ok := envelope.Msg.(*networkMsg)
	if !ok {
		return
	}
	p.mu.Lock()
	gate := p.gate
	drop := gate.DropEverything
	if h := msg.Hmsg; h != nil {
		// A leader may automatically pipeline an empty successor after QC1.
		// Freeze that successor's network quorum until the controlled TC2 split.
		if gate.FirstProposalOnly && h.Number > 1 {
			drop = true
			p.stats.DroppedOther++
		}
		if gate.Split {
			switch h.Code {
			case hotstuff.MsgTimeout:
				if !gate.TimeoutCollector {
					drop = true
					p.stats.DroppedVotes++
				}
			case hotstuff.MsgTimeoutQC:
				if !gate.AcceptTC {
					drop = true
					p.stats.DroppedTC++
				}
			default:
				drop = true
				p.stats.DroppedOther++
			}
		}
	}
	if body := msg.Pmsg; body != nil {
		if gate.Split || gate.DropManifest || (gate.FirstProposalOnly && body.Number > 1) {
			drop = true
			p.stats.DroppedDA++
		}
		if !drop {
			if body.Type == proposalBodyMsgManifest {
				p.stats.Manifests++
				if body.Number == 1 {
					p.stats.FirstManifests++
				}
			}
			if body.Type == proposalBodyMsgRepairData {
				p.stats.RepairData++
				p.stats.RepairTxs += uint64(len(body.TransactionBytes))
				found := false
				for _, donor := range p.stats.RepairDonors {
					if donor == body.From {
						found = true
					}
				}
				if !found {
					p.stats.RepairDonors = append(p.stats.RepairDonors, body.From)
				}
				if body.Number == 1 {
					p.stats.FirstRepairTxs += uint64(len(body.TransactionBytes))
					found = false
					for _, donor := range p.stats.FirstRepairDonors {
						if donor == body.From {
							found = true
						}
					}
					if !found {
						p.stats.FirstRepairDonors = append(p.stats.FirstRepairDonors, body.From)
					}
				}
			}
		}
	}
	p.mu.Unlock()
	if !drop {
		p.service.netService.handleNetworkMsgAck(envelope)
	}
}

func (p *fhsRecoveryProcess) transactionClient() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	next := 0
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
		}
		if !p.workload.Load() || !p.service.isRunning() || next >= len(p.txs) {
			continue
		}
		// One new transaction per certified parent keeps a real pipelined
		// workload available without manufacturing a second block after heal.
		if uint64(next) > p.service.GetCurrentView().TxNumber {
			continue
		}
		p.mu.Lock()
		healed := p.gate.Healed
		p.mu.Unlock()
		if next > 0 && !healed {
			continue
		}
		_, err := core.VerifyAndStoreCommonRPCAdmissionBatch(p.admissions[next], p.service.chainConfig.ChainID, p.service.bc.Genesis().Hash())
		if err == nil {
			err = p.service.txPool.AddLocal(p.txs[next])
		}
		if err != nil {
			p.mu.Lock()
			p.stats.WorkError = err.Error()
			p.mu.Unlock()
			return
		}
		next++
		p.mu.Lock()
		p.stats.Submitted = uint64(next)
		p.mu.Unlock()
	}
}
