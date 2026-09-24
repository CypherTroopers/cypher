package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/relay/source"
)

func TestObserverOnlyReadProofRequests(t *testing.T) {
	for _, raw := range []string{`{"Op":"eth_sendRawTransaction"}`, `{"Op":"anchor","Height":1}`, `{"Op":"current","Height":9223372036854775808}`, `{"Op":"current","Unknown":true}`, `{"Op":"current"} {}`} {
		if _, err := parse([]byte(raw)); err == nil {
			t.Fatal("accepted unbounded/mutation/unbound request", raw)
		}
	}
	for _, raw := range []string{`{"Op":"current"}`, `{"Op":"advance"}`, `{"Op":"anchor","Height":1,"Hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}`} {
		if _, err := parse([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourceHeightIsNotDEXSequenceCapacity(t *testing.T) {
	for _, height := range []uint64{4096, 4097, 32768, math.MaxInt64} {
		raw, err := json.Marshal(request{Op: "anchor", Height: height, Hash: common.Hash{31: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parse(raw); err != nil {
			t.Fatalf("source coordinate %d rejected: %v", height, err)
		}
	}
	// Raising an absolute coordinate must not raise any proof work/storage cap.
	if source.MaxSegmentHeaders != 32 || source.MaxSegments != 1024 || source.MaxWALBytes != 32*1024*1024 || clxevidence.MaxAccountStorageSlots != 32 {
		t.Fatal("source proof work/storage bounds changed")
	}
	raw, err := json.Marshal(request{Op: "account", Height: 4097, Hash: common.Hash{31: 1}, Address: common.Address{19: 1}, Keys: make([]common.Hash, 33)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(raw); err == nil {
		t.Fatal("higher source coordinate bypassed slot proof bound")
	}
}

func financeRun(t *testing.T) (string, string) {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "live-finance-observer-test")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(parent, "OWNER.json")
	if err := os.WriteFile(marker, []byte(`{"tool":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "source-observer"), marker
}

func TestObserverWorkspaceRunPath(t *testing.T) {
	stage, err := filepath.Abs(filepath.Join("..", "..", "build", "stage"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); os.IsNotExist(err) {
		t.Skip("optional workspace build/stage directory absent")
	}
	parent, err := os.MkdirTemp(stage, "live-finance-observer-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) }) // This test's exact owned directory.
	if err := os.WriteFile(filepath.Join(parent, "OWNER.json"), []byte(`{"tool":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRunOwner(filepath.Join(parent, "source-observer")); err != nil {
		t.Fatalf("normal owned workspace run path: %v", err)
	}
}

func TestObserverRunFilesystemOwnership(t *testing.T) {
	t.Run("new-and-existing-private", func(t *testing.T) {
		dir, marker := financeRun(t)
		want, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readRunOwner(dir)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("safe new directory: %v", err)
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := readRunOwner(dir); err != nil {
			t.Fatalf("safe existing directory: %v", err)
		}
	})
	cases := map[string]func(*testing.T, string, string) string{
		"ancestor-symlink": func(t *testing.T, dir, marker string) string {
			link := filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(filepath.Dir(filepath.Dir(dir)), link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, filepath.Base(filepath.Dir(dir)), filepath.Base(dir))
		},
		"run-public": func(t *testing.T, dir, marker string) string {
			if err := os.Chmod(filepath.Dir(dir), 0755); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"ancestor-writable": func(t *testing.T, dir, marker string) string {
			if err := os.Chmod(filepath.Dir(filepath.Dir(dir)), 0777); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"observer-public": func(t *testing.T, dir, marker string) string {
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"observer-symlink": func(t *testing.T, dir, marker string) string {
			if err := os.Symlink(t.TempDir(), dir); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"marker-public": func(t *testing.T, dir, marker string) string {
			if err := os.Chmod(marker, 0644); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"marker-symlink": func(t *testing.T, dir, marker string) string {
			target := marker + ".target"
			if err := os.Rename(marker, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, marker); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"marker-hardlink": func(t *testing.T, dir, marker string) string {
			if err := os.Link(marker, marker+".link"); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"marker-fifo": func(t *testing.T, dir, marker string) string {
			if err := os.Remove(marker); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(marker, 0600); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"marker-oversize": func(t *testing.T, dir, marker string) string {
			if err := os.WriteFile(marker, bytes.Repeat([]byte("x"), 8193), 0600); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"run-foreign-owner": func(t *testing.T, dir, marker string) string {
			if os.Geteuid() != 0 {
				t.Skip("chown ownership fault requires root; no privilege escalation")
			}
			if err := os.Chown(filepath.Dir(dir), 65534, -1); err != nil {
				if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
					t.Skipf("sandbox does not permit a foreign UID ownership fixture: %v", err)
				}
				t.Fatal(err)
			}
			return dir
		},
		"marker-foreign-owner": func(t *testing.T, dir, marker string) string {
			if os.Geteuid() != 0 {
				t.Skip("chown ownership fault requires root; no privilege escalation")
			}
			if err := os.Chown(marker, 65534, -1); err != nil {
				if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
					t.Skipf("sandbox does not permit a foreign UID ownership fixture: %v", err)
				}
				t.Fatal(err)
			}
			return dir
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir, marker := financeRun(t)
			dir = mutate(t, dir, marker)
			if _, err := readRunOwner(dir); err == nil {
				t.Fatal("unsafe observer storage accepted")
			}
		})
	}
}
