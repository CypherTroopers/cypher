package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/reconfig/hotstuff"
)

// These large, authenticated actions exercise the production byte watermark,
// not a reduced count threshold. Financial formulas are covered separately.
type byteGenerationExecution struct{ ancestryFixtureExecution }

func (*byteGenerationExecution) ID() string { return "fixture-byte-generation/v1" }
func (e *byteGenerationExecution) Execute(parent, action []byte, ctx ExecutionContext) (ExecutionResult, error) {
	if len(action) != 48*1024 || !bytes.Equal(action, bytes.Repeat([]byte{1}, len(action))) {
		return ExecutionResult{}, errors.New("invalid byte generation action")
	}
	return e.ancestryFixtureExecution.Execute(parent, []byte{1}, ctx)
}

func byteGenerationNetwork(t *testing.T, height uint64) *network {
	return newConfiguredNetwork(t, height, func(c *Config) {
		c.StorageGenerations = true
		c.Execution = new(byteGenerationExecution)
		c.Actions = func(uint64) ([]byte, error) { return bytes.Repeat([]byte{1}, 48*1024), nil }
	})
}

func TestGenerationByteWatermarkRealFHSTwoCutsAndColdRecovery(t *testing.T) {
	n := byteGenerationNetwork(t, 56)
	n.start(t)
	for i, a := range n.nodes {
		if a.disk.Generation < 2 || a.disk.BaseHeight == 0 || a.disk.BaseHeight >= StorageGenerationInterval || a.FinalizedHeight() != 55 || a.CertifiedHeight() != 56 {
			t.Fatalf("node%d byte cuts/finality %+v %d/%d", i, a.StorageStatus(), a.CertifiedHeight(), a.FinalizedHeight())
		}
		info, err := os.Stat(filepath.Join(a.wal.dir, generationStateName(a.disk.Generation)))
		if err != nil || info.Size() > maxWALBytes {
			t.Fatal("hot WAL byte bound", err)
		}
		safety, outbox := hotstuff.CloneFHSSafetyState(a.disk.Safety), hotstuff.CloneSignedState(a.disk.Outbox)
		generation, cut := a.disk.Generation, a.disk.BaseHeight
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		restored, err := Open(n.configs[i])
		if err != nil {
			t.Fatalf("node%d cold replay: %v", i, err)
		}
		n.nodes[i] = restored
		if !reflect.DeepEqual(restored.disk.Safety, safety) || !reflect.DeepEqual(restored.disk.Outbox, outbox) || restored.disk.Generation != generation || restored.disk.BaseHeight != cut {
			t.Fatal("byte cut lost durable safety or archive boundary")
		}
		for _, h := range []uint64{1, cut - 1, cut, 55} {
			raw, err := restored.FinalizedState(h)
			if err != nil || len(raw) != 8 || binary.BigEndian.Uint64(raw) != h {
				t.Fatal("old authenticated state unavailable", h, err)
			}
			cp, proof, err := restored.FinalizedCheckpoint(h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = restored.epoch.Verify(cp, proof); err != nil {
				t.Fatal("old claim/checkpoint proof lost", h, err)
			}
		}
		if i == 0 {
			t.Logf("production watermark: generations=%d cut=%d finalized55/certified56 hot=%d <= %d; old roots and exact vote/QC/outbox preserved", generation, cut, info.Size(), maxWALBytes)
		}
	}
}

func TestGenerationByteWatermarkCrashPublication(t *testing.T) {
	for _, stage := range []string{"archive-durable", "hot-durable", "current-durable"} {
		t.Run(stage, func(t *testing.T) {
			n := byteGenerationNetwork(t, 30)
			a := n.nodes[0]
			injected := errors.New("byte cut injected failure")
			a.wal.generationFault = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			for _, node := range n.nodes {
				if err := node.Start(); !benign(err) {
					t.Fatal(err)
				}
			}
			failed := false
			for step := 0; step < 20000 && !failed; step++ {
				for _, node := range n.nodes {
					_, err := node.Advance()
					if node == a && (errors.Is(err, injected) || errors.Is(a.fatal, injected)) {
						failed = true
						break
					}
					if !benign(err) {
						t.Fatal(err)
					}
				}
				if failed || len(n.queue) == 0 {
					continue
				}
				d := n.queue[0]
				n.queue = n.queue[1:]
				for _, node := range n.nodes {
					if node.Self() != d.to {
						continue
					}
					err := node.Handle(d.message)
					if node == a && (errors.Is(err, injected) || errors.Is(a.fatal, injected)) {
						failed = true
					} else if !benign(err) {
						t.Fatal(err)
					}
					break
				}
			}
			if !failed || a.fatal == nil || a.FinalizedHeight() >= StorageGenerationInterval {
				t.Fatal("actual early byte cut failure not reached")
			}
			// Read the last durable canonical state, not the failed in-memory
			// mutation. Open must authenticate it and may safely finish the cut.
			durable, err := a.wal.load(a.config.Domain, a.disk.VotePublic)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Close(); err != nil {
				t.Fatal(err)
			}
			restored, err := Open(n.configs[0])
			if err != nil {
				t.Fatal("byte cut restart", err)
			}
			n.nodes[0] = restored
			if !reflect.DeepEqual(restored.disk.Safety, durable.Safety) || !reflect.DeepEqual(restored.disk.Outbox, durable.Outbox) || restored.FinalizedHeight() != durable.BaseHeight+uint64(len(durable.Finalized)) {
				t.Fatal("failed byte cut lost last durable vote/QC/outbox/finality")
			}
			if stage == "current-durable" && restored.disk.Generation == 0 {
				t.Fatal("published byte cut rolled back")
			}
		})
	}
}
