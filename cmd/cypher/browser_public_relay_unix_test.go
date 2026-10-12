//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func publicRelayUnixTestStat(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	return stat
}

func publicRelayUnixAssertPreserved(t *testing.T, path string, before unix.Stat_t) {
	t.Helper()
	after := publicRelayUnixTestStat(t, path)
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Mode != before.Mode || after.Uid != before.Uid {
		t.Fatalf("path was changed: before=%+v after=%+v", before, after)
	}
}

func publicRelayUnixTestStaleSocket(t *testing.T, path string) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if stat := publicRelayUnixTestStat(t, path); stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		t.Fatal("fixture did not leave a Unix socket")
	}
}

func publicRelayUnixTestPrepare(t *testing.T, path string, dial func(string, string, time.Duration) (net.Conn, error)) error {
	t.Helper()
	dir, leaf, err := publicRelayParent(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	lock, err := lockPublicRelaySocket(dir, leaf)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	return preparePublicRelaySocketPath(dir, leaf, path, dial)
}

func TestPublicRelayUnixSocketReclaimsStaleAndRestarts(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%t", stale), func(t *testing.T) {
			path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
			if stale {
				publicRelayUnixTestStaleSocket(t, path)
			}
			listener, err := listenPublicRelaySocket(path)
			if err != nil {
				t.Fatal("could not create relay listener", err)
			}
			defer listener.Close()
			stat := publicRelayUnixTestStat(t, path)
			if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Mode&0777 != 0600 {
				t.Fatalf("new listener must be an owner-only socket: %+v", stat)
			}
			conn, err := net.DialTimeout("unix", path, time.Second)
			if err != nil {
				t.Fatal("created listener is not reachable", err)
			}
			conn.Close()
			lockBefore := publicRelayUnixTestStat(t, path+".lock")
			if lockBefore.Mode&unix.S_IFMT != unix.S_IFREG || lockBefore.Mode&0777 != 0600 {
				t.Fatalf("lock must be an owner-only regular file: %+v", lockBefore)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("owned socket remains after Close", err)
			}
			publicRelayUnixAssertPreserved(t, path+".lock", lockBefore)
			restarted, err := listenPublicRelaySocket(path)
			if err != nil {
				t.Fatal("Close did not release the socket-path lock", err)
			}
			if err := restarted.Close(); err != nil {
				t.Fatal(err)
			}
			publicRelayUnixAssertPreserved(t, path+".lock", lockBefore)
		})
	}
}

func TestPublicRelayUnixSocketProtectsLegacyListener(t *testing.T) {
	path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
	legacy, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	before := publicRelayUnixTestStat(t, path)
	if listener, err := listenPublicRelaySocket(path); err == nil {
		listener.Close()
		t.Fatal("accepted a live listener that does not hold the new startup lock")
	}
	publicRelayUnixAssertPreserved(t, path, before)
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal("legacy listener was disrupted", err)
	}
	conn.Close()
}

func TestPublicRelayUnixSocketProtectsNonSocketPaths(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "dangling-symlink", "foreign-owned-socket"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "dangling-symlink":
				target := path + ".target"
				if kind == "symlink" {
					publicRelayUnixTestStaleSocket(t, target)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "foreign-owned-socket":
				if os.Geteuid() != 0 {
					t.Skip("changing socket ownership requires root")
				}
				publicRelayUnixTestStaleSocket(t, path)
				if err := os.Chown(path, 65534, -1); err != nil {
					if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
						t.Skipf("environment cannot create a foreign-owned socket fixture: %v", err)
					}
					t.Fatal(err)
				}
			}
			before := publicRelayUnixTestStat(t, path)
			if listener, err := listenPublicRelaySocket(path); err == nil {
				listener.Close()
				t.Fatal("unsafe socket path was admitted")
			}
			publicRelayUnixAssertPreserved(t, path, before)
			if kind == "file" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "preserve" {
					t.Fatal("regular file content changed", err)
				}
			}
		})
	}
}

// A timeout remains inconclusive even if a wrapped error contains ECONNREFUSED.
type publicRelayUnixProbeTimeout struct{ cause error }

func (e publicRelayUnixProbeTimeout) Error() string   { return "fixture probe timeout" }
func (e publicRelayUnixProbeTimeout) Timeout() bool   { return true }
func (e publicRelayUnixProbeTimeout) Temporary() bool { return true }
func (e publicRelayUnixProbeTimeout) Unwrap() error   { return e.cause }

func TestPublicRelayUnixSocketProtectsInconclusiveProbe(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"permission", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", unix.EACCES)}},
		{"timeout", publicRelayUnixProbeTimeout{cause: unix.ETIMEDOUT}},
		{"timeout-wrapping-refused", publicRelayUnixProbeTimeout{cause: unix.ECONNREFUSED}},
		{"unknown", errors.New("unclassified connection failure")},
		{"not-found", &net.OpError{Op: "dial", Net: "unix", Err: unix.ENOENT}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
			publicRelayUnixTestStaleSocket(t, path)
			before := publicRelayUnixTestStat(t, path)
			called := false
			err := publicRelayUnixTestPrepare(t, path, func(network, address string, timeout time.Duration) (net.Conn, error) {
				called = true
				if network != "unix" || address != path || timeout <= 0 {
					t.Fatalf("invalid bounded probe: %q %q %v", network, address, timeout)
				}
				return nil, test.err
			})
			if err == nil || !called {
				t.Fatal("inconclusive probe must reject startup", err)
			}
			publicRelayUnixAssertPreserved(t, path, before)
		})
	}
}

func TestPublicRelayUnixSocketProtectsReplacementDuringProbe(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "socket"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
			publicRelayUnixTestStaleSocket(t, path)
			var replacement unix.Stat_t
			err := publicRelayUnixTestPrepare(t, path, func(_, _ string, _ time.Duration) (net.Conn, error) {
				// Retaining the old inode also prevents inode reuse from hiding a swap.
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "file":
					if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(path+".old", path); err != nil {
						t.Fatal(err)
					}
				case "socket":
					publicRelayUnixTestStaleSocket(t, path)
				}
				replacement = publicRelayUnixTestStat(t, path)
				return nil, &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", unix.ECONNREFUSED)}
			})
			if err == nil {
				t.Fatal("replacement during the probe was admitted")
			}
			publicRelayUnixAssertPreserved(t, path, replacement)
		})
	}
}

func TestPublicRelayUnixSocketProtectsUnsafeLockPaths(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "fifo", "socket", "group-readable", "hardlink", "foreign-owned"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
			lockPath := path + ".lock"
			switch kind {
			case "symlink":
				if err := os.WriteFile(lockPath+".target", []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(lockPath+".target", lockPath); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(lockPath, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(lockPath, 0600); err != nil {
					t.Fatal(err)
				}
			case "socket":
				publicRelayUnixTestStaleSocket(t, lockPath)
			default:
				if kind == "foreign-owned" && os.Geteuid() != 0 {
					t.Skip("changing lock ownership requires root")
				}
				if err := os.WriteFile(lockPath, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "group-readable" {
					if err := os.Chmod(lockPath, 0640); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "hardlink" {
					if err := os.Link(lockPath, lockPath+".alias"); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "foreign-owned" {
					if err := os.Chown(lockPath, 65534, -1); err != nil {
						if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
							t.Skipf("environment cannot create a foreign-owned lock fixture: %v", err)
						}
						t.Fatal(err)
					}
				}
			}
			before := publicRelayUnixTestStat(t, lockPath)
			if listener, err := listenPublicRelaySocket(path); err == nil {
				listener.Close()
				t.Fatal("unsafe startup lock was admitted")
			}
			publicRelayUnixAssertPreserved(t, lockPath, before)
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe lock created a socket", err)
			}
		})
	}
}

func TestPublicRelayUnixSocketConcurrentStartup(t *testing.T) {
	path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
	publicRelayUnixTestStaleSocket(t, path)
	type result struct {
		listener net.Listener
		err      error
	}
	const contenders = 12
	start := make(chan struct{})
	results := make(chan result, contenders)
	var ready sync.WaitGroup
	ready.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			ready.Done()
			<-start
			listener, err := listenPublicRelaySocket(path)
			results <- result{listener, err}
		}()
	}
	ready.Wait()
	close(start)
	var winners []net.Listener
	for i := 0; i < contenders; i++ {
		result := <-results
		if result.err == nil {
			winners = append(winners, result.listener)
			defer result.listener.Close()
		}
	}
	if len(winners) != 1 {
		t.Fatalf("expected one live listener, got %d", len(winners))
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal("losing startup removed the winning listener", err)
	}
	conn.Close()
}

func TestPublicRelayUnixSocketLockCoversCloseCleanup(t *testing.T) {
	path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
	listener, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Stop accepting without running the wrapper's inode check and cleanup.
	// The refused connection alone must not allow another startup to reclaim it.
	if err := listener.(*publicRelaySocket).UnixListener.Close(); err != nil {
		t.Fatal(err)
	}
	before := publicRelayUnixTestStat(t, path)
	if other, err := listenPublicRelaySocket(path); err == nil {
		other.Close()
		t.Fatal("startup reclaimed a socket before its owner completed Close")
	}
	publicRelayUnixAssertPreserved(t, path, before)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal("completed Close did not permit restart", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}

const publicRelayUnixProcessPathEnv = "CYPHER_TEST_PUBLIC_RELAY_SOCKET_PATH"

// The parent uses different working directories to model distinct datadirs.
// The listening child holds its socket until the parent closes its stdin.
func TestPublicRelayUnixSocketProcessChild(t *testing.T) {
	path := os.Getenv(publicRelayUnixProcessPathEnv)
	if path == "" {
		return
	}
	var start [1]byte
	if _, err := io.ReadFull(os.Stdin, start[:]); err != nil {
		t.Fatal(err)
	}
	listener, err := listenPublicRelaySocket(path)
	if err != nil {
		fmt.Println("rejected")
		return
	}
	defer listener.Close()
	fmt.Println("listening")
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicRelayUnixSocketConcurrentProcesses(t *testing.T) {
	dir := publicRelayTestDirectory(t)
	path := filepath.Join(dir, "common.sock")
	publicRelayUnixTestStaleSocket(t, path)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	type child struct {
		cmd       *exec.Cmd
		stdin     io.WriteCloser
		scanner   *bufio.Scanner
		stderr    bytes.Buffer
		listening bool
	}
	children := make([]*child, 2)
	for i := range children {
		child := &child{cmd: exec.CommandContext(ctx, executable, "-test.run=^TestPublicRelayUnixSocketProcessChild$")}
		children[i] = child
		child.cmd.Env = append(os.Environ(), publicRelayUnixProcessPathEnv+"="+path)
		child.cmd.Dir = filepath.Join(dir, fmt.Sprintf("node-%d", i))
		if err := os.Mkdir(child.cmd.Dir, 0700); err != nil {
			t.Fatal(err)
		}
		child.cmd.Stderr = &child.stderr
		child.stdin, err = child.cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := child.cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		child.scanner = bufio.NewScanner(stdout)
		if err := child.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			child.stdin.Close()
			if child.cmd.ProcessState == nil {
				child.cmd.Process.Kill()
				child.cmd.Wait()
			}
		})
	}
	for _, child := range children {
		if _, err := child.stdin.Write([]byte("S")); err != nil {
			t.Fatal(err)
		}
	}
	winners := 0
	for _, child := range children {
		if !child.scanner.Scan() {
			t.Fatal("child produced no startup result", child.scanner.Err())
		}
		switch child.scanner.Text() {
		case "listening":
			winners++
			child.listening = true
		case "rejected":
		default:
			t.Fatalf("unexpected child output: %q", child.scanner.Text())
		}
	}
	if winners != 1 {
		t.Fatalf("different datadirs sharing a socket must have one winner, got %d", winners)
	}
	before := publicRelayUnixTestStat(t, path)
	if listener, err := listenPublicRelaySocket(path); err == nil {
		listener.Close()
		t.Fatal("parent admitted a socket owned by the live child")
	}
	publicRelayUnixAssertPreserved(t, path, before)
	lockBefore := publicRelayUnixTestStat(t, path+".lock")
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal("losing process removed the winning socket", err)
	}
	conn.Close()
	for _, child := range children {
		if child.listening {
			// Kill only the test-owned listener, reproducing a crash rather than
			// allowing Close to unlink its socket and release its lock normally.
			if err := child.cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := child.cmd.Wait(); err == nil {
				t.Fatal("killed fixture child exited successfully")
			}
		} else {
			child.stdin.Close()
			if err := child.cmd.Wait(); err != nil {
				t.Fatalf("rejected child failed: %v\n%s", err, child.stderr.String())
			}
		}
	}
	publicRelayUnixAssertPreserved(t, path, before)
	publicRelayUnixAssertPreserved(t, path+".lock", lockBefore)
	restarted, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal("crashed process did not release the socket lock or stale socket could not be reclaimed", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicRelayUnixSocketCloseProtectsReplacementSocket(t *testing.T) {
	path := filepath.Join(publicRelayTestDirectory(t), "common.sock")
	listener, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	publicRelayUnixTestStaleSocket(t, path)
	before := publicRelayUnixTestStat(t, path)
	if err := listener.Close(); err == nil {
		t.Fatal("Close did not report the replacement socket")
	}
	publicRelayUnixAssertPreserved(t, path, before)
	// Releasing the old listener's lock allows a later legitimate stale recovery.
	restarted, err := listenPublicRelaySocket(path)
	if err != nil {
		t.Fatal("replacement report retained the old listener lock", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}
