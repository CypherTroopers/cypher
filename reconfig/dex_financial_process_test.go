package reconfig_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/devnet/testnet"
)

func TestDEXNativeFinancialChild(t *testing.T) {
	dir := os.Getenv("CYPHER_DEX_FINANCIAL_CHILD")
	if dir == "" {
		t.Skip("isolated financial child")
	}
	index, err := strconv.Atoi(os.Getenv("CYPHER_DEX_FINANCIAL_INDEX"))
	if err != nil {
		t.Fatal(err)
	}
	if err = testnet.Serve(os.Stdin, os.Stdout, dir, index); err != nil {
		t.Fatal(err)
	}
}

type dexFinancialChild struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	replies  chan testnet.Response
	done     chan error
	identity testnet.Identity
	dir      string
	index    int
	stopped  bool
	logPath  string
	cli      *financialCLI
}

func startDEXFinancialChild(t *testing.T, dir string, index int) *dexFinancialChild {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestDEXNativeFinancialChild$", "-test.timeout=12m")
	cmd.Env = append(os.Environ(), "CYPHER_DEX_FINANCIAL_CHILD="+dir, "CYPHER_DEX_FINANCIAL_INDEX="+strconv.Itoa(index), "GOMAXPROCS=2")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(filepath.Dir(dir), fmt.Sprintf("financial-child-%d-%d.log", index, time.Now().UnixNano()))
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = log
	c := &dexFinancialChild{cmd: cmd, input: in, replies: make(chan testnet.Response, 8), done: make(chan error, 1), dir: dir, index: index, logPath: logPath}
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 4096), testnet.MaxControlBytes+4096)
		for s.Scan() {
			line := s.Text()
			if strings.HasPrefix(line, testnet.OutputPrefix) {
				var r testnet.Response
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, testnet.OutputPrefix)), &r); err == nil {
					c.replies <- r
				} else {
					fmt.Fprintln(log, "control decode:", err)
				}
			} else {
				fmt.Fprintln(log, line)
			}
		}
	}()
	go func() { err := cmd.Wait(); <-scanned; log.Close(); c.done <- err }()
	t.Cleanup(func() {
		if !c.stopped {
			c.kill(t)
		}
		in.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(c.logPath)
			f, err := os.CreateTemp("", "dex-financial-failure-*.log")
			if err == nil {
				f.Write(raw)
				f.Close()
				t.Logf("DEX child%d full log %s", index, f.Name())
			}
			if len(raw) > 16000 {
				raw = raw[len(raw)-16000:]
			}
			t.Logf("DEX child%d log: %s", index, raw)
		}
	})
	select {
	case r := <-c.replies:
		if r.Error != "" || r.Identity == nil {
			t.Fatalf("financial child identity: %+v", r)
		}
		c.identity = *r.Identity
	case err := <-c.done:
		c.stopped = true
		t.Fatalf("financial child startup: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("financial child startup deadline")
	}
	return c
}
func (c *dexFinancialChild) call(t *testing.T, r testnet.Request) testnet.Response {
	t.Helper()
	if c.cli != nil {
		return c.cli.request(t, r)
	}
	if c.stopped {
		t.Fatal("request to stopped financial child")
	}
	if err := json.NewEncoder(c.input).Encode(r); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-c.replies:
		return result
	case err := <-c.done:
		c.stopped = true
		t.Fatalf("financial child%d exit op=%s: %v", c.index, r.Op, err)
	case <-time.After(20 * time.Second):
		t.Fatalf("financial child%d op=%s deadline", c.index, r.Op)
	}
	return testnet.Response{}
}
func (c *dexFinancialChild) ok(t *testing.T, r testnet.Request) testnet.Response {
	t.Helper()
	out := c.call(t, r)
	if out.Error != "" {
		t.Fatalf("financial child%d op=%s: %s", c.index, r.Op, out.Error)
	}
	return out
}
func (c *dexFinancialChild) kill(t *testing.T) {
	t.Helper()
	if c.cli != nil {
		c.cli.killSidecar(t)
		c.stopped = true
		return
	}
	if c.stopped {
		return
	}
	_ = c.cmd.Process.Kill()
	select {
	case <-c.done:
		c.stopped = true
	case <-time.After(10 * time.Second):
		t.Fatalf("owned DEX child%d did not exit", c.index)
	}
}
func waitDEXFinancial(t *testing.T, children []*dexFinancialChild, condition func([]testnet.Response) bool) []testnet.Response {
	t.Helper()
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var last []testnet.Response
	for {
		last = make([]testnet.Response, len(children))
		for i, c := range children {
			if c != nil && !c.stopped {
				last[i] = c.ok(t, testnet.Request{Op: "status"})
			}
		}
		if condition(last) {
			return last
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			for i, r := range last {
				t.Logf("DEX%d status=%+v certs=%d receiptErrors=%d", i, r.Status, len(r.Certificates), r.ReceiptErrors)
			}
			t.Fatal("financial DEX event deadline")
		}
	}
}
