//go:build linux
// +build linux

package source

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
)

// The storage-only fixture has no remote source and no cryptographic verifier:
// its empty canonical WAL must restore exactly the immutable bootstrap. Actual
// signed-chain restore is covered separately by TestRelaySource tests.
func sourceStorageFixture(t *testing.T, dir string) *Client {
	t.Helper()
	s, err := openSourceStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := clxevidence.Anchor{Version: 1, ChainID: 99, Genesis: protocol.Hash{1}, DEXID: protocol.Hash{2}, Custody: [20]byte{3}, BlockHash: protocol.Hash{1}, StateRoot: protocol.Hash{4}, SourceKeyHash: protocol.Hash{5}, SourceCommittee: protocol.Hash{6}, SourceEpoch: 1}
	return &Client{store: s, bootstrap: a, current: a}
}

func TestSourcePartialWriteOrphanRestore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "source")
	c := sourceStorageFixture(t, dir)
	if err := c.restore(); err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile(filepath.Join(dir, "source-wal.json"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := c.current
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "operator-notes.tmp")
	if err = os.WriteFile(unrelated, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		// Inject the exact on-disk state of an interrupted partial write, without
		// executing deferred cleanup; this is not a physical power-loss test.
		if err = os.WriteFile(filepath.Join(dir, sourcePendingName), []byte(`{"payload":`), 0600); err != nil {
			t.Fatal(err)
		}
		legacy := filepath.Join(dir, "source-wal-"+strconv.Itoa(i)+".tmp")
		if err = os.WriteFile(legacy, []byte("incomplete legacy save"), 0600); err != nil {
			t.Fatal(err)
		}
		c = sourceStorageFixture(t, dir)
		if err = c.restore(); err != nil || c.current != anchor || len(c.segments) != 0 {
			t.Fatal("orphan affected canonical bootstrap", err)
		}
		for _, path := range []string{filepath.Join(dir, sourcePendingName), legacy} {
			if _, err = os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("orphan retained", path, err)
			}
		}
		if err = c.save(nil); err != nil {
			t.Fatal("fixed exclusive save did not recover", err)
		}
		if err = c.store.close(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "source-wal.json"))
		if err != nil || !bytes.Equal(got, canonical) {
			t.Fatal("canonical source WAL changed", err)
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 4 {
			t.Fatal("restarts accumulated temporary files", len(files), err)
		}
	}
	if got, err := os.ReadFile(unrelated); err != nil || string(got) != "retain" {
		t.Fatal("unrelated file modified", err)
	}
}

func TestSourceOrphanCleanupFailsClosed(t *testing.T) {
	for _, name := range []string{"invalid_canonical", "symlink", "mode", "hardlink", "oversized", "count"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "source")
			c := sourceStorageFixture(t, dir)
			if err := c.restore(); err != nil {
				t.Fatal(err)
			}
			c.store.close()
			good := filepath.Join(dir, "source-wal-valid.tmp")
			if err := os.WriteFile(good, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			bad := filepath.Join(dir, sourcePendingName)
			var err error
			switch name {
			case "invalid_canonical":
				err = os.WriteFile(filepath.Join(dir, "source-wal.json"), []byte("broken"), 0600)
			case "symlink":
				err = os.Symlink("source-wal.json", bad)
			case "mode":
				err = os.WriteFile(bad, []byte("partial"), 0644)
			case "hardlink":
				err = os.Link(good, bad)
			case "oversized":
				err = os.WriteFile(bad, nil, 0600)
				if err == nil {
					err = os.Truncate(bad, MaxWALBytes+1)
				}
			case "count":
				for i := 0; i < maxSourceOrphans; i++ {
					if err = os.WriteFile(filepath.Join(dir, "source-wal-"+strconv.Itoa(i)+".tmp"), nil, 0600); err != nil {
						break
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			c = sourceStorageFixture(t, dir)
			if err = c.restore(); err == nil {
				t.Fatal("unsafe orphan or broken canonical state accepted")
			}
			c.store.close()
			if _, err = os.Lstat(good); err != nil {
				t.Fatal("cleanup occurred before complete authentication and checks", err)
			}
		})
	}
}
