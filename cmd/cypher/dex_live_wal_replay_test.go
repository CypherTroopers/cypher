package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
)

// This opt-in test reads public signed WAL bytes and existing key files, but
// copies no keys and never starts an actor, listener or signing worker. Every
// writable path is a temporary clone; the live datadir is never opened writable.
func TestDEXCurrentPublicWALColdReplayOnTemporaryCopies(t *testing.T) {
	root := os.Getenv("CYPHER_DEX_PUBLIC_WAL_REPLAY_DIR")
	if root == "" {
		t.Skip("explicit current public WAL replay fixture required")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute prepared manifest root required")
	}
	for _, name := range []string{"cyphermine", "cypherdex1", "cypherdex2", "cypherdex3", "cypherdex4", "cypherdex5", "cypherdex6"} {
		t.Run(name, func(t *testing.T) {
			m, err := service.LoadManifest(filepath.Join(root, "manifests", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			original := m.DataDir
			m.DataDir = filepath.Join(t.TempDir(), "dex")
			if err = os.MkdirAll(filepath.Join(m.DataDir, "fhs"), 0700); err != nil {
				t.Fatal(err)
			}
			pointer, err := os.ReadFile(filepath.Join(original, "fhs", "CURRENT"))
			if err != nil {
				t.Fatal(err)
			}
			var current struct{ Payload struct{ Generation uint64 } }
			if err = json.Unmarshal(pointer, &current); err != nil || current.Payload.Generation != 0 {
				t.Fatal("this explicit failed-generation-zero fixture no longer applies", err)
			}
			stateName := fmt.Sprintf("state-%020d.json", current.Payload.Generation)
			var sourceState []byte
			originalHashes := map[string][32]byte{}
			pathsToCopy := []string{"DEX_SIDECAR", "fhs/DEVNET", "fhs/CURRENT", "fhs/" + stateName}
			// Own vote safety spans both FHS and its authenticated participation
			// records. Preserve those public signatures too; an empty collector
			// correctly refuses to restore a previously signed FHS vote.
			participation, err := os.ReadDir(filepath.Join(original, "participation"))
			if err != nil || len(participation) > 256 {
				t.Fatal("bounded participation fixture", err)
			}
			if err = os.Mkdir(filepath.Join(m.DataDir, "participation"), 0700); err != nil {
				t.Fatal(err)
			}
			for _, entry := range participation {
				n := entry.Name()
				if n == "OWNER" || n == "state.json" || strings.HasPrefix(n, "period-") && strings.HasSuffix(n, ".json") {
					pathsToCopy = append(pathsToCopy, filepath.Join("participation", n))
				}
			}
			for _, rel := range pathsToCopy {
				info, err := os.Lstat(filepath.Join(original, rel))
				if err != nil || !info.Mode().IsRegular() {
					t.Fatal("public fixture must be a regular file", rel, err)
				}
				src, err := os.ReadFile(filepath.Join(original, rel))
				if err != nil || len(src) > 2*1024*1024 {
					t.Fatal("public fixture read bound", err)
				}
				originalHashes[rel] = sha256.Sum256(src)
				if err = os.WriteFile(filepath.Join(m.DataDir, rel), src, 0600); err != nil {
					t.Fatal(err)
				}
				if rel == "fhs/"+stateName {
					sourceState = src
				}
			}
			var before, after struct {
				Payload struct {
					Safety, Outbox         json.RawMessage
					Generation, BaseHeight uint64
					Finalized              []json.RawMessage
				}
			}
			if err = json.Unmarshal(sourceState, &before); err != nil {
				t.Fatal(err)
			}
			// Financial Open performs complete authenticated replay then the
			// bounded archive cut. No Start call is made, so no vote is emitted.
			instance, err := finance.OpenManifest(m)
			if err != nil {
				t.Fatal("current financial replay", err)
			}
			if err = instance.Close(); err != nil {
				t.Fatal(err)
			}
			paths, err := filepath.Glob(filepath.Join(m.DataDir, "fhs", "state-*.json"))
			if err != nil || len(paths) != 1 {
				t.Fatal("single canonical generation expected", err)
			}
			recovered, err := os.ReadFile(paths[0])
			if err != nil || json.Unmarshal(recovered, &after) != nil {
				t.Fatal("recovered state", err)
			}
			if !bytes.Equal(before.Payload.Safety, after.Payload.Safety) || !bytes.Equal(before.Payload.Outbox, after.Payload.Outbox) || after.Payload.Generation != 1 || after.Payload.BaseHeight != uint64(len(before.Payload.Finalized)) || len(after.Payload.Finalized) != 0 || len(recovered) >= len(sourceState) {
				t.Fatal("cold byte cut lost safety/finality or failed to reclaim authenticated prefix")
			}
			// Repeat cold recovery of the new archive, independently of the
			// first Open's in-memory verifier/cache.
			instance, err = finance.OpenManifest(m)
			if err != nil {
				t.Fatal("archived financial cold replay", err)
			}
			if err = instance.Close(); err != nil {
				t.Fatal(err)
			}
			for rel, want := range originalHashes {
				raw, err := os.ReadFile(filepath.Join(original, rel))
				if err != nil || sha256.Sum256(raw) != want {
					t.Fatal("source changed during read-only replay; result cannot bind one snapshot", rel, err)
				}
			}
			t.Logf("public source sha256=%x bytes=%d -> %d cut=%d; exact safety/outbox, two authenticated financial Opens, no Start and original files unchanged", sha256.Sum256(sourceState), len(sourceState), len(recovered), after.Payload.BaseHeight)
		})
	}
}
