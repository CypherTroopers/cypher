//go:build linux

package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type walCrashBootstrap struct {
	Domain    protocol.Domain
	Members   []*common.Cnode
	CLXHash   protocol.Hash
	CLXHeight uint64
}

// The child receives public unit-fixture metadata. Its vote secret is the
// deterministic test-only scalar already used by newConfiguredNetwork.
func TestWALOrphanSIGKILLChild(t *testing.T) {
	dir := os.Getenv("DEX_WAL_ORPHAN_CHILD_DIR")
	if dir == "" {
		t.Skip("owned SIGKILL child")
	}
	data, err := os.ReadFile(os.Getenv("DEX_WAL_ORPHAN_CHILD_BOOTSTRAP"))
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap walCrashBootstrap
	if err := json.Unmarshal(data, &bootstrap); err != nil {
		t.Fatal(err)
	}
	secret := new(bls.SecretKey)
	if err := secret.SetDecString("700"); err != nil {
		t.Fatal(err)
	}
	c := Config{Domain: bootstrap.Domain, Members: bootstrap.Members, Index: 0, Secret: secret,
		DataDir: dir, CLXHash: bootstrap.CLXHash, CLXHeight: bootstrap.CLXHeight,
		MaxHeight: 8, Execution: new(compactExecution)}
	a, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	a.wal.afterTemporaryChunk = func() error {
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			return err
		}
		select {}
	}
	statement := hotstuff.TimeoutStatement{Version: 3, ChainID: a.ChainID(), TimedOutView: 7,
		KeyNumber: c.Domain.Epoch, KeyHash: common.Hash(c.Domain.EpochKey()), CommitteeHash: common.Hash(c.Domain.Committee)}
	if err := a.PersistFHSTimeoutVote(&statement); err != nil {
		t.Fatal(err)
	}
	t.Fatal("partial-write SIGKILL boundary was not reached")
}

func TestWALOrphanActualSIGKILLRepeatedRecovery(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	first, _ := compactPendingRecords(t, n, 0)
	vote, err := decodeRecordVote(first)
	if err != nil {
		t.Fatal(err)
	}
	a := n.nodes[0]
	if err := a.PersistFHSVote(vote); err != nil {
		t.Fatal(err)
	}
	expected := hotstuff.CloneFHSSafetyState(a.disk.Safety)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	c := n.configs[0]
	bootstrap, err := json.Marshal(walCrashBootstrap{c.Domain, c.Members, c.CLXHash, c.CLXHeight})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := filepath.Join(t.TempDir(), "public-fixture.json")
	if err := os.WriteFile(bootstrapPath, bootstrap, 0600); err != nil {
		t.Fatal(err)
	}
	canonicalPath := filepath.Join(c.DataDir, "state.json")
	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWALOrphanSIGKILLChild$", "-test.v")
		command.Env = append(os.Environ(), "DEX_WAL_ORPHAN_CHILD_DIR="+c.DataDir, "DEX_WAL_ORPHAN_CHILD_BOOTSTRAP="+bootstrapPath)
		output, err := command.CombinedOutput()
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("iteration%d child did not receive SIGKILL: %v %s", i, err, output)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("iteration%d unexpected child exit: %v %s", i, err, output)
		}
		pending, err := os.ReadFile(filepath.Join(c.DataDir, walPendingName))
		if err != nil || len(pending) == 0 || len(pending) >= maxWALBytes || json.Valid(pending) {
			t.Fatal("actual crash must leave an incomplete bounded JSON generation", err)
		}
		before, err := os.ReadFile(canonicalPath)
		if err != nil || !bytes.Equal(before, canonical) {
			t.Fatal("crash changed the canonical WAL", err)
		}
		entries, err := os.ReadDir(c.DataDir)
		if err != nil || len(entries) != 4 {
			t.Fatal("a crash must leave exactly one pending generation", len(entries), err)
		}
		a, err = Open(c)
		if err != nil {
			t.Fatal("authenticated restart", err)
		}
		n.nodes[0] = a
		if !reflect.DeepEqual(expected, a.disk.Safety) || a.disk.Safety.LastTimeoutVote != nil || a.FinalizedHeight() != 5 || a.CurrentN() != 7 {
			t.Fatal("restart promoted the uncommitted timeout or changed vote/finality")
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(canonicalPath)
		if err != nil || !bytes.Equal(after, canonical) {
			t.Fatal("cleanup changed canonical state", err)
		}
		entries, err = os.ReadDir(c.DataDir)
		if err != nil || len(entries) != 3 {
			t.Fatal("repeated crash/recovery accumulated WAL generations", len(entries), err)
		}
	}
}

func orphanCopyConfig(t *testing.T, original Config, raw []byte) Config {
	t.Helper()
	c := original
	c.DataDir = filepath.Join(t.TempDir(), "wal")
	if err := os.Mkdir(c.DataDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"DEVNET": []byte(devnetMarker), "state.json": raw} {
		if err := os.WriteFile(filepath.Join(c.DataDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func orphanFile(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(f.Truncate(size), f.Close()); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWALOrphanLegacyCleanupPreservesUnknown(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	if err := n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	c := n.configs[0]
	canonical, err := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	orphanFile(t, c.DataDir, walPendingName, 100)
	orphanFile(t, c.DataDir, "state-legacy123.tmp", maxWALBytes)
	unknown := orphanFile(t, c.DataDir, "operator-note", 17)
	unknownLink := filepath.Join(c.DataDir, "unknown-link")
	if err := os.Symlink(unknown, unknownLink); err != nil {
		t.Fatal(err)
	}
	a, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	n.nodes[0] = a
	for _, name := range []string{walPendingName, "state-legacy123.tmp"} {
		if _, err := os.Lstat(filepath.Join(c.DataDir, name)); !os.IsNotExist(err) {
			t.Fatal("owned orphan was not reclaimed", name, err)
		}
	}
	if info, err := os.Lstat(unknown); err != nil || info.Size() != 17 {
		t.Fatal("unknown file changed", err)
	}
	if target, err := os.Readlink(unknownLink); err != nil || target != unknown {
		t.Fatal("unknown symlink changed", err)
	}
	after, err := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
	if err != nil || !bytes.Equal(after, canonical) {
		t.Fatal("legacy cleanup changed canonical bytes", err)
	}
}

func TestWALOrphanUnsafeOrUnverifiedRecoveryDeletesNothing(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	if err := n.nodes[0].Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(n.configs[0].DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*testing.T, *Config){
		"canonical-missing": func(t *testing.T, c *Config) {
			if err := os.Remove(filepath.Join(c.DataDir, "state.json")); err != nil {
				t.Fatal(err)
			}
		},
		"canonical-corrupt": func(t *testing.T, c *Config) {
			if err := os.WriteFile(filepath.Join(c.DataDir, "state.json"), []byte("{broken"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"checksum-valid-own-vote-corrupt": func(t *testing.T, c *Config) {
			path := filepath.Join(c.DataDir, "state.json")
			d := readCompact(t, path)
			d.Safety.LastVote.ProposalID[0] ^= 1
			writeCompact(t, path, d)
		},
		"external-vote-restore-failed": func(t *testing.T, c *Config) {
			c.RestoreVote = func(*hotstuff.PersistedVote) error { return errors.New("fixture collector unavailable") }
		},
		"finalized-callback-failed": func(t *testing.T, c *Config) {
			c.OnFinalizedExecution = func(uint64, []byte, []byte) error { return errors.New("fixture external reconciliation unavailable") }
		},
		"symlink": func(t *testing.T, c *Config) {
			if err := os.Symlink(filepath.Join(c.DataDir, "state.json"), filepath.Join(c.DataDir, walPendingName)); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, c *Config) {
			if err := os.Link(filepath.Join(c.DataDir, "state.json"), filepath.Join(c.DataDir, walPendingName)); err != nil {
				t.Fatal(err)
			}
		},
		"permissions": func(t *testing.T, c *Config) {
			path := orphanFile(t, c.DataDir, walPendingName, 1)
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, c *Config) {
			if err := os.Mkdir(filepath.Join(c.DataDir, walPendingName), 0700); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, c *Config) {
			if err := syscall.Mkfifo(filepath.Join(c.DataDir, walPendingName), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"foreign-owner": func(t *testing.T, c *Config) {
			if os.Geteuid() != 0 {
				t.Skip("owner mutation requires root test process")
			}
			path := orphanFile(t, c.DataDir, walPendingName, 1)
			if err := os.Chown(path, 65534, -1); err != nil {
				if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
					t.Skipf("test namespace does not permit a foreign UID: %v", err)
				}
				t.Fatal(err)
			}
		},
		"individual-byte-limit": func(t *testing.T, c *Config) { orphanFile(t, c.DataDir, walPendingName, maxWALBytes+1) },
		"aggregate-byte-limit": func(t *testing.T, c *Config) {
			for i := 0; i < 5; i++ {
				orphanFile(t, c.DataDir, fmt.Sprintf("state-%d.tmp", i), maxWALBytes)
			}
		},
		"orphan-count-limit": func(t *testing.T, c *Config) {
			for i := 0; i < maxWALOrphans; i++ {
				orphanFile(t, c.DataDir, fmt.Sprintf("state-%d.tmp", i), 1)
			}
		},
		"directory-entry-limit": func(t *testing.T, c *Config) {
			for i := 0; i < maxWALDirectoryEntries; i++ {
				orphanFile(t, c.DataDir, fmt.Sprintf("unknown-%d", i), 1)
			}
		},
		"directory-permissions": func(t *testing.T, c *Config) {
			if err := os.Chmod(c.DataDir, 0755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := orphanCopyConfig(t, n.configs[0], raw)
			safe := orphanFile(t, c.DataDir, "state-safe.tmp", 21)
			mutate(t, &c)
			canonical, err := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
			missingCanonical := os.IsNotExist(err)
			if err != nil && !missingCanonical {
				t.Fatal(err)
			}
			before, err := os.ReadDir(c.DataDir)
			if err != nil {
				t.Fatal(err)
			}
			a, err := Open(c)
			if err == nil {
				a.Close()
				t.Fatal("unsafe/unverified WAL recovery accepted")
			}
			if info, err := os.Lstat(safe); err != nil || info.Size() != 21 {
				t.Fatal("safe orphan deleted before complete validation", err)
			}
			for _, entry := range before {
				if _, err := os.Lstat(filepath.Join(c.DataDir, entry.Name())); err != nil {
					t.Fatal("failed recovery deleted an entry", entry.Name(), err)
				}
			}
			after, err := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
			if missingCanonical {
				if !os.IsNotExist(err) {
					t.Fatal("failed recovery recreated a missing canonical WAL", err)
				}
			} else if err != nil || !bytes.Equal(after, canonical) {
				t.Fatal("failed recovery changed canonical state", err)
			}
		})
	}
}

type orphanStatInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (s orphanStatInfo) Sys() interface{} { return &s.stat }

// Single-UID test namespaces cannot chown to an unmapped owner. Exercise the
// actual metadata predicate independently as well; the filesystem case above
// remains explicitly skipped when that namespace restriction applies.
func TestWALOrphanForeignOwnerMetadataRejected(t *testing.T) {
	path := orphanFile(t, t.TempDir(), "state-owner.tmp", 1)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !ownedWALTemporary(info) {
		t.Fatal("invalid local file metadata")
	}
	foreign := orphanStatInfo{FileInfo: info, stat: *stat}
	foreign.stat.Uid = uint32(os.Geteuid()) + 1
	if ownedWALTemporary(foreign) || ownedWALDirectory(foreign) {
		t.Fatal("foreign UID metadata accepted")
	}
	linked := orphanStatInfo{FileInfo: info, stat: *stat}
	linked.stat.Nlink = 2
	if ownedWALTemporary(linked) {
		t.Fatal("multiple-link metadata accepted")
	}
}

func TestWALOrphanActiveCollisionDisablesSigning(t *testing.T) {
	n := compactNetwork(t)
	n.start(t)
	first, _ := compactPendingRecords(t, n, 0)
	vote, err := decodeRecordVote(first)
	if err != nil {
		t.Fatal(err)
	}
	a := n.nodes[0]
	canonical, err := os.ReadFile(filepath.Join(a.wal.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	pendingPath := orphanFile(t, a.wal.dir, walPendingName, 19)
	if err := a.PersistFHSVote(vote); err == nil || a.fatal == nil {
		t.Fatal("fixed-name collision did not disable signing")
	}
	if err := a.PersistFHSVote(vote); err == nil {
		t.Fatal("failed persistence continued signing")
	}
	if info, err := os.Lstat(pendingPath); err != nil || info.Size() != 19 {
		t.Fatal("O_EXCL collision overwrote pending data", err)
	}
	after, err := os.ReadFile(filepath.Join(a.wal.dir, "state.json"))
	if err != nil || !bytes.Equal(after, canonical) {
		t.Fatal("collision changed canonical data", err)
	}
}
