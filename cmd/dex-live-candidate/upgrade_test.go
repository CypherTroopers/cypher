package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/params"
)

func currentV4Source(t *testing.T) (string, *core.Genesis) {
	t.Helper()
	dir := t.TempDir()
	i, err := generate(sourceGenesisFixture(), filepath.Join(dir, "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(i.GenesisFile)
	if err != nil {
		t.Fatal(err)
	}
	var g core.Genesis
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &g) != nil || json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture JSON")
	}
	g.Config.DEXDevnet.Version = 4
	g.Mixhash, err = params.FairHotstuffGenesisCommitment(g.Config)
	if err != nil {
		t.Fatal(err)
	}
	fields["config"], err = json.Marshal(g.Config)
	if err != nil {
		t.Fatal(err)
	}
	fields["mixHash"], err = json.Marshal(g.Mixhash)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "current-v4.json")
	if err = os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return source, &g
}

func TestCandidateUpgradesAuthenticatedCurrentV4WithoutChangingChainOrCLX(t *testing.T) {
	source, old := currentV4Source(t)
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	i, err := generate(source, filepath.Join(t.TempDir(), "new-v5"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("current source mutated", err)
	}
	raw, err := os.ReadFile(i.GenesisFile)
	if err != nil {
		t.Fatal(err)
	}
	var next core.Genesis
	if err = json.Unmarshal(raw, &next); err != nil {
		t.Fatal(err)
	}
	if next.Config.DEXDevnet.Version != 5 || next.Config.ChainID.Cmp(old.Config.ChainID) != 0 || next.Config.ChainID.Uint64() != oldChainID ||
		!reflect.DeepEqual(old.Alloc, next.Alloc) || !reflect.DeepEqual(old.Config.GenCommittee, next.Config.GenCommittee) {
		t.Fatal("upgrade changed CLX identity or allocations")
	}
	if i.OldGenesis != old.ToBlock(nil).Hash().Hex() || i.OldGenesis == i.Genesis || next.Config.DEXDevnet.DEXID == old.Config.DEXDevnet.DEXID {
		t.Fatal("upgrade source/new generation identities")
	}
	commitment, err := params.FairHotstuffGenesisCommitment(next.Config)
	if err != nil || commitment != next.Mixhash {
		t.Fatal("new v5 commitment", err)
	}
}

func TestCandidateRejectsUnsupportedOrUnboundSourceBeforeCreatingOutput(t *testing.T) {
	source, _ := currentV4Source(t)
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"v3", "v5", "future", "mixhash", "committee"} {
		t.Run(failure, func(t *testing.T) {
			var g core.Genesis
			if err := json.Unmarshal(original, &g); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "v3":
				g.Config.DEXDevnet.Version = 3
			case "v5":
				g.Config.DEXDevnet.Version = 5
			case "future":
				g.Config.DEXDevnet.Version = 99
			case "mixhash":
				g.Mixhash[0] ^= 1
			case "committee":
				g.Config.DEXDevnet.Committee[0].Public = "invalid"
			}
			dir := t.TempDir()
			p := filepath.Join(dir, "input.json")
			out := filepath.Join(dir, "out")
			raw, err := json.Marshal(g)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(p, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = generate(p, out); err == nil {
				t.Fatal("invalid source accepted")
			}
			if _, err = os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("invalid input created output", err)
			}
		})
	}
}
