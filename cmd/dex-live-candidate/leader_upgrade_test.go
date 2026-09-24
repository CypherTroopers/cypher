package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func oldLeaderPatchFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	inv, e := generate(sourceGenesisFixture(), candidate)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(candidate, "relays"), 0700); e != nil {
		t.Fatal(e)
	}
	// Convert only this newly-created unit fixture to the preceding two-relay
	// layout. No current candidate or runtime data is ever accessed by this test.
	var oldKeys []keyInfo
	for _, k := range inv.Keys {
		if strings.HasPrefix(k.Purpose, "submission-") {
			if e = os.Remove(k.KeyFile); e != nil {
				t.Fatal(e)
			}
		} else {
			oldKeys = append(oldKeys, k)
		}
	}
	inv.Keys = oldKeys
	inv.Funding = nil
	for n, path := range inv.LeaderSubmissionConfigs {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if n < 2 {
			var cfg relayManifest
			if json.Unmarshal(raw, &cfg) != nil {
				t.Fatal("fixture config")
			}
			cfg.Payers = nil
			cfg.DataDir = filepath.Join(candidate, "runtime", fmtIndex("relay-", n))
			cfg.AutoInbox = n == 0
			for _, lane := range []string{"anchor", "checkpoint", "claim"} {
				k, e := newAccount(candidate, fmtIndex("relay-", n)+"-"+lane+"-gas")
				if e != nil {
					t.Fatal(e)
				}
				inv.Keys = append(inv.Keys, k)
				// Existing identities must all survive preparation; key loading belongs
				// to the normal CLI's signer validator, not to this patch preparer.
			}
			old := filepath.Join(candidate, "relays", fmtIndex("relay-", n)+".json")
			if e = putJSON(old, cfg); e != nil {
				t.Fatal(e)
			}
			inv.RelayConfigs = append(inv.RelayConfigs, old)
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Remove(filepath.Join(candidate, "submissions")); e != nil {
		t.Fatal(e)
	}
	inv.LeaderSubmissionConfigs = nil
	for n, p := range inv.Participants {
		var m map[string]interface{}
		b, _ := os.ReadFile(p.Manifest)
		json.Unmarshal(b, &m)
		delete(m, "LeaderSubmission")
		b, _ = json.MarshalIndent(m, "", "  ")
		if e = os.WriteFile(p.Manifest, append(b, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
		inv.Participants[n].SubmissionConfig = ""
	}
	raw, _ := json.MarshalIndent(inv, "", "  ")
	raw = append(raw, '\n')
	if e = os.WriteFile(filepath.Join(candidate, "public", "inventory.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	participants := map[string]interface{}{}
	for _, p := range inv.Participants {
		b, _ := os.ReadFile(p.Manifest)
		participants[p.Name] = map[string]interface{}{"enabled": true, "manifest": p.Manifest, "sha256": digest(b)}
	}
	selection := map[string]interface{}{"version": 1, "chain_id": inv.ChainID, "dex_id": inv.DEXID, "genesis_sha256": inv.GenesisSHA256, "generation_inventory": filepath.Join(candidate, "public", "inventory.json"), "generation_inventory_sha256": digest(raw), "participants": participants}
	if e = putJSON(filepath.Join(candidate, "local-deployment.json"), selection); e != nil {
		t.Fatal(e)
	}
	active := filepath.Join(root, "live-deployment.json")
	if e = putJSON(active, selection); e != nil {
		t.Fatal(e)
	}
	genesis := filepath.Join(root, "genesis.json")
	b, _ := os.ReadFile(inv.GenesisFile)
	if e = put(genesis, b); e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Join(candidate, "runtime", "relay-0"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = put(filepath.Join(candidate, "runtime", "relay-0", "sent-nonce.wal"), []byte("already signed nonce; preserve")); e != nil {
		t.Fatal(e)
	}
	return candidate, genesis, active
}
func fmtIndex(prefix string, n int) string { return prefix + string(rune('0'+n)) }

func TestPrepareLeaderPatchPreservesGenerationKeysStateAndSelections(t *testing.T) {
	candidate, genesis, active := oldLeaderPatchFixture(t)
	// Hash every old file, including old secret identity files and runtime WAL.
	before := map[string]string{}
	filepath.Walk(candidate, func(path string, s os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if s.Mode().IsRegular() {
			b, _ := os.ReadFile(path)
			before[path] = digest(b)
		}
		return nil
	})
	for _, path := range []string{genesis, active} {
		b, _ := os.ReadFile(path)
		before[path] = digest(b)
	}
	out := filepath.Join(filepath.Dir(candidate), "prepared")
	plan, e := prepareLeaderSubmissionPatch(candidate, genesis, active, out)
	if e != nil {
		t.Fatal(e)
	}
	if plan.ChainID != oldChainID || len(plan.Changes) != 38 || len(plan.RequiresStopped) != 9 {
		t.Fatal("unexpected patch surface", len(plan.Changes))
	}
	for path, want := range before {
		b, e := os.ReadFile(path)
		if e != nil || digest(b) != want {
			t.Fatal("existing input mutated", path, e)
		}
	}
	var next inventory
	raw, e := os.ReadFile(filepath.Join(out, "public", "inventory.json"))
	if e != nil || json.Unmarshal(raw, &next) != nil {
		t.Fatal("prepared inventory", e)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	var retired []string
	json.Unmarshal(fields["RetiredRelayConfigs"], &retired)
	if len(next.RelayConfigs) != 0 || len(retired) != 2 || len(next.LeaderSubmissionConfigs) != 7 || len(next.Keys) != 45 {
		t.Fatal("key/config preservation and ownership", len(next.Keys))
	}
	for _, c := range plan.Changes {
		raw, e := os.ReadFile(c.Prepared)
		if e != nil || digest(raw) != c.SHA256 {
			t.Fatal("prepared hash", e)
		}
		s, e := os.Stat(c.Prepared)
		if e != nil || s.Mode().Perm() != 0600 {
			t.Fatal("private patch permissions", e)
		}
		if c.Target == genesis || strings.Contains(c.Target, "/runtime/") {
			t.Fatal("forbidden patch target", c.Target)
		}
		if c.BeforeSHA256 != "" && c.BeforeSHA256 != before[c.Target] {
			t.Fatal("incorrect precondition")
		}
	}
	for n, p := range next.Participants {
		var cfg relayManifest
		raw, _ := os.ReadFile(filepath.Join(out, "submissions", p.Name+".json"))
		if json.Unmarshal(raw, &cfg) != nil {
			t.Fatal("config")
		}
		if cfg.DataDir != filepath.Join(p.DEXDataDir, "submission") || cfg.DEXURL != "http://"+p.API || !cfg.AutoInbox || len(cfg.Payers) != 3 || p.SubmissionConfig != next.LeaderSubmissionConfigs[n] {
			t.Fatal("member-local submission")
		}
		for _, payer := range cfg.Payers {
			if payer.Purpose != "leader-submission-gas" || filepath.Dir(payer.KeyFile) != filepath.Join(candidate, "keys") {
				t.Fatal("dedicated gas identity")
			}
		}
	}
	if _, e = prepareLeaderSubmissionPatch(candidate, genesis, active, out); e == nil {
		t.Fatal("overwrote existing prepared patch")
	}
}
func TestPrepareLeaderPatchRejectsChangedSelectionOrGenesisBeforeOutput(t *testing.T) {
	for _, target := range []string{"genesis", "selection", "manifest", "nested"} {
		t.Run(target, func(t *testing.T) {
			candidate, genesis, active := oldLeaderPatchFixture(t)
			out := filepath.Join(filepath.Dir(candidate), "prepared")
			path := genesis
			switch target {
			case "selection":
				path = active
			case "manifest":
				path = filepath.Join(candidate, "manifests", "cyphermine.json")
			case "nested":
				out = filepath.Join(candidate, "public", "nested-patch")
			}
			if target != "nested" {
				b, _ := os.ReadFile(path)
				if target == "selection" {
					var value map[string]interface{}
					json.Unmarshal(b, &value)
					value["chain_id"] = oldChainID + 1
					b, _ = json.Marshal(value)
				} else {
					b = append(b, ' ')
				}
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := prepareLeaderSubmissionPatch(candidate, genesis, active, out); e == nil {
				t.Fatal("accepted changed input")
			}
			if _, e := os.Stat(out); !os.IsNotExist(e) {
				t.Fatal("invalid input created output", e)
			}
		})
	}
}
