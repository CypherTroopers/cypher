package reconfig

// This opt-in experiment combines actual CLX QUIC processes with actual DEX
// FHS/WAL processes. The DEX transport is a bounded parent-driven pipe bus, not
// a production network transport. See docs/dex/process-isolation-spec.md.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	dexconsensus "github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const (
	dexProcessPrefix       = "DEX_ISOLATION "
	dexProcessWireLimit    = 2 << 20
	dexProcessMessageLimit = 64 << 10
	dexProcessQueueLimit   = 4096
	dexProcessQueueBytes   = 16 << 20
)

type dexProcessEnvelope struct {
	To      string
	Message *hotstuff.HotstuffMessage
}

type dexProcessCommand struct {
	ID          uint64
	Op          string
	Domain      protocol.Domain
	Members     []*common.Cnode
	Index       int
	Anchor      checkpoint.FinalizedAnchor
	MaxHeight   uint64
	Message     *hotstuff.HotstuffMessage
	ProofHeight uint64
}

type dexProcessReport struct {
	ID                 uint64
	Error              string
	PID                int
	Address            string
	Public             string
	Height             uint64
	Certified          uint64
	FinalizedHash      protocol.Hash
	Advanced           bool
	ProtocolRejections uint64
	Messages           []dexProcessEnvelope
	Checkpoint         *protocol.Checkpoint
	Proof              []byte
}

func benignDEXProcessError(err error) bool {
	if err == nil {
		return true
	}
	for _, expected := range []error{hotstuff.ErrInsufficientQC, hotstuff.ErrProposalValidationPending, hotstuff.ErrUnhandledMsg, hotstuff.ErrOldState, hotstuff.ErrMissingView, hotstuff.ErrViewOldPhase, hotstuff.ErrFutureState} {
		if errors.Is(err, expected) {
			return true
		}
	}
	return strings.Contains(err.Error(), "counter fixture height limit")
}

func writeDEXProcessReport(report dexProcessReport) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(encoded) > dexProcessWireLimit {
		return errors.New("DEX process response size exceeded")
	}
	_, err = fmt.Fprintln(os.Stdout, dexProcessPrefix+string(encoded))
	return err
}

// TestDEXIsolationProcessHelper is invoked only in processes created by the
// parent experiment. It never opens an operational datadir or network socket.
func TestDEXIsolationProcessHelper(t *testing.T) {
	dir := os.Getenv("CYPHER_DEX_ISOLATION_CHILD")
	if dir == "" {
		t.Skip("isolated DEX subprocess helper")
	}
	if os.Getenv("CYPHER_DEX_PROCESS_DEVNET") != "1" {
		t.Fatal("DEX subprocess opt-in missing")
	}
	index, err := strconv.Atoi(os.Getenv("CYPHER_DEX_ISOLATION_INDEX"))
	if err != nil || index < 0 || index >= 7 {
		t.Fatal("invalid DEX process index")
	}
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlWarn, log.StreamHandler(os.Stderr, log.LogfmtFormat())))
	var secret bls.SecretKey
	keyPath := filepath.Join(dir, "fixture-bls.key")
	encodedKey, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		secret.SetByCSPRNG()
		keyFile, createErr := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, err := keyFile.WriteString(secret.SerializeToHexStr()); err != nil {
			keyFile.Close()
			t.Fatal(err)
		}
		if err := keyFile.Sync(); err != nil {
			keyFile.Close()
			t.Fatal(err)
		}
		if err := keyFile.Close(); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	} else if err := secret.DeserializeHexStr(string(encodedKey)); err != nil {
		t.Fatal(err)
	}
	base := dexProcessReport{PID: os.Getpid(), Address: fmt.Sprintf("127.0.0.1:%d", 31000+index), Public: secret.GetPublicKey().SerializeToHexStr()}
	if err := writeDEXProcessReport(base); err != nil {
		t.Fatal(err)
	}
	var app *dexconsensus.Application
	defer func() {
		if app != nil {
			_ = app.Close()
		}
	}()
	var outbox []dexProcessEnvelope
	var rejected uint64
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), dexProcessWireLimit)
	for scanner.Scan() {
		var command dexProcessCommand
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&command); err != nil {
			t.Fatal(err)
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			t.Fatal("trailing DEX process command")
		}
		outbox = nil
		report := base
		report.ID = command.ID
		var commandErr error
		if command.Op == "init" {
			if app != nil {
				commandErr = errors.New("DEX process already initialized")
			} else {
				app, commandErr = dexconsensus.Open(dexconsensus.Config{Domain: command.Domain, Members: command.Members, Index: command.Index, Secret: &secret, DataDir: filepath.Join(dir, "dex-state"), CLXHeight: command.Anchor.Height, CLXHash: command.Anchor.Hash, MaxHeight: command.MaxHeight})
				if commandErr == nil {
					app.SetTransport(func(to string, message *hotstuff.HotstuffMessage) error {
						encoded, err := rlp.EncodeToBytes(message)
						if err != nil {
							return err
						}
						if len(encoded) > dexProcessMessageLimit || len(outbox) >= 64 {
							return errors.New("DEX process outbound limit exceeded")
						}
						outbox = append(outbox, dexProcessEnvelope{to, message})
						return nil
					})
				}
			}
		} else if app == nil {
			commandErr = errors.New("DEX process not initialized")
		} else {
			switch command.Op {
			case "start":
				commandErr = app.Start()
			case "handle":
				encoded, err := rlp.EncodeToBytes(command.Message)
				if err != nil || command.Message == nil || len(encoded) > dexProcessMessageLimit {
					commandErr = errors.New("invalid bounded DEX process message")
				} else {
					commandErr = app.Handle(command.Message)
				}
			case "advance":
				report.Advanced, commandErr = app.Advance()
			case "timeout":
				commandErr = app.Timeout()
			case "status":
			case "proof":
				c, proof, err := app.FinalizedCheckpoint(command.ProofHeight)
				commandErr = err
				if err == nil {
					report.Checkpoint, report.Proof = &c, proof
				}
			default:
				commandErr = fmt.Errorf("unknown DEX process command %q", command.Op)
			}
		}
		if commandErr != nil {
			if (command.Op == "start" || command.Op == "handle" || command.Op == "advance" || command.Op == "timeout") && benignDEXProcessError(commandErr) {
				rejected++
			} else {
				report.Error = commandErr.Error()
			}
		}
		if app != nil {
			report.Height, report.Certified = app.FinalizedHeight(), app.CertifiedHeight()
			if report.Height > 0 {
				c, _, err := app.FinalizedCheckpoint(report.Height)
				if err != nil {
					report.Error = err.Error()
				} else {
					report.FinalizedHash, err = c.Hash()
					if err != nil {
						report.Error = err.Error()
					}
				}
			}
		}
		report.Messages, report.ProtocolRejections = outbox, rejected
		if err := writeDEXProcessReport(report); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

type dexIsolationChild struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	replies chan dexProcessReport
	done    chan error
	seq     uint64
	info    dexProcessReport
	dir     string
	index   int
	stopped bool
}

func startDEXIsolationChild(t *testing.T, dir string, index int) *dexIsolationChild {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestDEXIsolationProcessHelper$", "-test.timeout=8m")
	cmd.Env = append(os.Environ(), "CYPHER_DEX_ISOLATION_CHILD="+dir, fmt.Sprintf("CYPHER_DEX_ISOLATION_INDEX=%d", index), "GOMAXPROCS=2")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(dir, "process-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = logFile
	c := &dexIsolationChild{cmd: cmd, input: input, replies: make(chan dexProcessReport, 4), done: make(chan error, 1), dir: dir, index: index}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), dexProcessWireLimit+len(dexProcessPrefix)+1)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, dexProcessPrefix) {
				var report dexProcessReport
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, dexProcessPrefix)), &report); err != nil {
					c.replies <- dexProcessReport{Error: err.Error()}
				} else {
					c.replies <- report
				}
			} else {
				fmt.Fprintln(logFile, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(logFile, err)
		}
	}()
	go func() { err := cmd.Wait(); <-scanned; logFile.Close(); c.done <- err }()
	t.Cleanup(func() {
		if !c.stopped {
			_ = c.cmd.Process.Kill()
			<-c.done
			c.stopped = true
		}
		_ = c.input.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			if artifact, err := os.CreateTemp("", "dex-isolation-failure-*.log"); err == nil {
				_, _ = artifact.Write(data)
				_ = artifact.Close()
				t.Logf("DEX process %d full log: %s", c.info.PID, artifact.Name())
			}
			if len(data) > 16000 {
				data = data[len(data)-16000:]
			}
			t.Logf("DEX process %d log tail:\n%s", c.info.PID, data)
		}
	})
	select {
	case c.info = <-c.replies:
		if c.info.Error != "" {
			t.Fatal(c.info.Error)
		}
	case err := <-c.done:
		c.stopped = true
		t.Fatalf("DEX child startup failed: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("DEX child startup timed out")
	}
	return c
}

func (c *dexIsolationChild) call(t *testing.T, command dexProcessCommand) dexProcessReport {
	t.Helper()
	c.seq++
	command.ID = c.seq
	encoded, err := json.Marshal(command)
	if err != nil || len(encoded) > dexProcessWireLimit {
		t.Fatalf("DEX process command bound: %v", err)
	}
	if _, err := c.input.Write(append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-c.replies:
		if result.ID != command.ID || result.Error != "" {
			t.Fatalf("DEX process %d command %s: id=%d want=%d error=%s", c.info.PID, command.Op, result.ID, command.ID, result.Error)
		}
		c.info = result
		return result
	case err := <-c.done:
		c.stopped = true
		t.Fatalf("DEX child exited during %s: %v", command.Op, err)
	case <-time.After(20 * time.Second):
		t.Fatalf("DEX process %d command %s timed out", c.info.PID, command.Op)
	}
	return dexProcessReport{}
}

func (c *dexIsolationChild) kill(t *testing.T) {
	t.Helper()
	if c.stopped {
		t.Fatal("DEX process already stopped")
	}
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
		c.stopped = true
	case <-time.After(10 * time.Second):
		t.Fatal("owned DEX process did not exit")
	}
	_ = c.input.Close()
}

type dexIsolationBus struct {
	children   []*dexIsolationChild
	queue      []dexProcessEnvelope
	bytes      int
	deliveries int
}

func (b *dexIsolationBus) collect(t *testing.T, report dexProcessReport) {
	t.Helper()
	for _, message := range report.Messages {
		encoded, err := rlp.EncodeToBytes(message.Message)
		if err != nil || len(encoded) > dexProcessMessageLimit || len(b.queue) >= dexProcessQueueLimit || len(encoded) > dexProcessQueueBytes-b.bytes {
			t.Fatalf("DEX bounded bus overflow: messages=%d bytes=%d error=%v", len(b.queue), b.bytes, err)
		}
		b.queue = append(b.queue, message)
		b.bytes += len(encoded)
	}
}

func (b *dexIsolationBus) run(t *testing.T, height uint64) {
	t.Helper()
	for _, child := range b.children {
		b.collect(t, child.call(t, dexProcessCommand{Op: "start"}))
	}
	deadline := time.Now().Add(60 * time.Second)
	for step := 0; step < 20000 && time.Now().Before(deadline); step++ {
		progress := false
		for _, child := range b.children {
			report := child.call(t, dexProcessCommand{Op: "advance"})
			b.collect(t, report)
			progress = progress || report.Advanced
		}
		if len(b.queue) != 0 {
			envelope := b.queue[0]
			b.queue = b.queue[1:]
			encoded, _ := rlp.EncodeToBytes(envelope.Message)
			b.bytes -= len(encoded)
			found := false
			for _, child := range b.children {
				if child.info.Address == envelope.To {
					b.collect(t, child.call(t, dexProcessCommand{Op: "handle", Message: envelope.Message}))
					found = true
					break
				}
			}
			if !found {
				t.Fatal("DEX message to unregistered destination")
			}
			b.deliveries++
			progress = true
		}
		complete := true
		for _, child := range b.children {
			complete = complete && child.info.Height >= height
		}
		if complete && len(b.queue) == 0 && !progress {
			return
		}
		if !progress {
			t.Fatalf("DEX consensus quiesced below target %d; statuses=%+v", height, b.statuses())
		}
	}
	t.Fatalf("DEX process delivery/time budget exhausted: deliveries=%d statuses=%+v", b.deliveries, b.statuses())
}

func (b *dexIsolationBus) statuses() []dexProcessReport {
	result := make([]dexProcessReport, len(b.children))
	for i, child := range b.children {
		result[i] = child.info
		result[i].Messages = nil
	}
	return result
}

func TestDEXAndCLXProcessIsolation(t *testing.T) {
	if os.Getenv("CYPHER_DEX_PROCESS_DEVNET") != "1" || os.Getenv("CYPHER_FHS_PROCESS_RECOVERY") != "1" {
		t.Skip("set both isolated DEX/FHS process devnet opt-ins")
	}
	requireDEXProcessNetworkIsolation(t)
	clx, _, fixture := newFHSRecoveryProcessFixture(t, false, false)
	for _, child := range clx {
		child.call(t, fhsProcessCommand{Op: "start"})
		child.call(t, fhsProcessCommand{Op: "workload", Workload: true})
	}
	initial := waitFHSProcesses(t, clx, 90*time.Second, func(statuses []fhsProcessReport) bool {
		for _, status := range statuses {
			if status.Height < 1 {
				return false
			}
		}
		return true
	})
	requireFHSCanonicalAgreement(t, clx, initial, 1)
	anchor := checkpoint.FinalizedAnchor{Height: 1, Hash: protocol.Hash(initial[0].Canonical[1])}
	bus := &dexIsolationBus{}
	members := make([]*common.Cnode, 7)
	seenPID, seenPublic := make(map[int]bool), make(map[string]bool)
	for _, child := range clx {
		seenPID[child.info.PID], seenPublic[child.info.Public] = true, true
	}
	for i := range members {
		child := startDEXIsolationChild(t, t.TempDir(), i)
		if seenPID[child.info.PID] || seenPublic[child.info.Public] {
			t.Fatal("CLX and DEX share process or voting identity")
		}
		seenPID[child.info.PID], seenPublic[child.info.Public] = true, true
		bus.children = append(bus.children, child)
		members[i] = &common.Cnode{Address: child.info.Address, Public: child.info.Public, CoinBase: fmt.Sprintf("dex-fixture-recipient-%d", i)}
	}
	domain := protocol.Domain{Version: protocol.Version, ChainID: fixture.Genesis.Config.ChainID.Uint64(), Genesis: protocol.Hash(initial[0].Genesis), DEXID: protocol.Digest("fixture", []byte("separate-process-dex")), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	for i, child := range bus.children {
		child.call(t, dexProcessCommand{Op: "init", Domain: domain, Members: members, Index: i, Anchor: anchor, MaxHeight: 3})
	}
	bus.run(t, 2)
	beforeDEX := bus.statuses()
	var acceptedHash protocol.Hash
	epoch, err := checkpoint.NewEpoch(domain, 1, ^uint64(0), members)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range bus.children {
		report := child.call(t, dexProcessCommand{Op: "proof", ProofHeight: 2})
		if report.Checkpoint == nil {
			t.Fatal("finalized DEX checkpoint missing")
		}
		if _, err := epoch.Verify(*report.Checkpoint, report.Proof); err != nil {
			t.Fatal(err)
		}
		hash, _ := report.Checkpoint.Hash()
		if acceptedHash == (protocol.Hash{}) {
			acceptedHash = hash
		} else if hash != acceptedHash {
			t.Fatal("DEX processes finalized different checkpoints")
		}
	}
	beforeCLX := fhsProcessStatuses(t, clx)
	var target uint64 = 3
	for _, status := range beforeCLX {
		if status.Height >= target {
			target = status.Height + 1
		}
	}
	for _, child := range bus.children {
		child.kill(t)
	}
	for _, child := range clx {
		child.call(t, fhsProcessCommand{Op: "gate", Gate: fhsProcessGate{Healed: true}})
	}
	afterCLX := waitFHSProcesses(t, clx, 90*time.Second, func(statuses []fhsProcessReport) bool {
		for _, status := range statuses {
			if status.Height < target {
				return false
			}
		}
		return true
	})
	requireFHSCanonicalAgreement(t, clx, afterCLX, target)
	bus.queue, bus.bytes = nil, 0
	for i, old := range bus.children {
		child := startDEXIsolationChild(t, old.dir, old.index)
		if child.info.PID == old.info.PID || child.info.Public != old.info.Public {
			t.Fatal("DEX restart did not preserve independent key identity")
		}
		recovered := child.call(t, dexProcessCommand{Op: "init", Domain: domain, Members: members, Index: i, Anchor: anchor, MaxHeight: 5})
		if recovered.Height != beforeDEX[i].Height || recovered.FinalizedHash != beforeDEX[i].FinalizedHash {
			t.Fatalf("DEX WAL recovery mismatch: before=%+v after=%+v", beforeDEX[i], recovered)
		}
		bus.children[i] = child
	}
	bus.run(t, 4)
	var finalHash protocol.Hash
	for _, child := range bus.children {
		if child.info.Height != 4 {
			t.Fatalf("DEX resumed height=%d want 4", child.info.Height)
		}
		if finalHash == (protocol.Hash{}) {
			finalHash = child.info.FinalizedHash
		} else if finalHash != child.info.FinalizedHash {
			t.Fatal("DEX restart finality divergence")
		}
	}
	t.Logf("14 distinct CLX/DEX process identities; DEX pipe-network simulation deliveries=%d; all 7 DEX PIDs killed and restarted with WAL height 2 preserved then finalized 4; CLX advanced from heights %+v to canonical height %d while DEX was stopped; checkpoint signature verification only, no native settlement", bus.deliveries, dexProcessHeights(beforeCLX), target)
}

// Cross-user-namespace access to /proc/1/ns/net may return EACCES even when
// unshare created the required isolated namespace. Verify the network's actual
// reachable interfaces/routes instead. An optional parent namespace identity
// captured before unshare adds a stricter comparison; it never bypasses checks.
func requireDEXProcessNetworkIsolation(t *testing.T) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("inspect process-devnet interfaces: %v", err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatalf("process devnet requires exactly one active loopback interface and no external interfaces: %+v (use unshare -n and enable lo)", interfaces)
	}
	for _, path := range []string{"/proc/net/route", "/proc/net/ipv6_route"} {
		data, err := os.ReadFile(path)
		if err != nil {
			if path == "/proc/net/ipv6_route" && os.IsNotExist(err) {
				continue // IPv6 is disabled in this kernel/namespace.
			}
			t.Fatalf("inspect process-devnet route table %s: %v", path, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] == "Iface" {
				continue
			}
			iface := fields[0]
			if path == "/proc/net/ipv6_route" {
				iface = fields[len(fields)-1]
			}
			if iface != "lo" {
				t.Fatalf("process devnet has an external route in %s: %q", path, line)
			}
		}
	}
	currentNS, nsErr := os.Readlink("/proc/self/ns/net")
	parentNS := os.Getenv("CYPHER_DEX_PARENT_NETNS")
	if parentNS != "" && (nsErr != nil || currentNS == parentNS) {
		t.Fatalf("process-devnet namespace differs from captured parent only after unshare: current=%q parent=%q readlink_error=%v", currentNS, parentNS, nsErr)
	}
	t.Logf("process-devnet network verified: active loopback only, no external routes; namespace=%q namespace_read_error=%v captured_parent=%t", currentNS, nsErr, parentNS != "")
}

func dexProcessHeights(statuses []fhsProcessReport) []uint64 {
	heights := make([]uint64, len(statuses))
	for i, status := range statuses {
		heights[i] = status.Height
	}
	return heights
}
