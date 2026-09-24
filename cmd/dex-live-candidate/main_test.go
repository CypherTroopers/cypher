package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/service"
)

func sourceGenesisFixture() string { return filepath.Join("testdata", "source-genesis-10101919.json") }

func TestCandidateDerivesActualGenesisAndKeepsAllocAndChainID(t *testing.T) {
	source := sourceGenesisFixture()
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "candidate")
	i, err := generate(source, dir)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(source)
	if err != nil || string(before) != string(after) {
		t.Fatal("source genesis mutated", err)
	}
	if i.Status != "BLOCKED" || i.ResetAuthorized || i.Deployed || i.StorageGenerationReady || !i.AllocPreserved || !i.CLXCommitteePreserved || !i.ChainIDPreserved || i.OrdinaryCLXReplaySeparated || i.ChainID != oldChainID || i.Genesis == i.OldGenesis {
		t.Fatal("candidate gates or identity")
	}
	if len(i.Participants) != 7 || len(i.RelayConfigs) != 0 || len(i.LeaderSubmissionConfigs) != 7 || len(i.Keys) != 39 {
		t.Fatal("candidate identity cardinality", len(i.Keys))
	}
	var g core.Genesis
	raw, err := os.ReadFile(i.GenesisFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if i.ConfigurationVersion != 5 || g.Config.DEXDevnet == nil || g.Config.DEXDevnet.Version != 5 {
		t.Fatal("candidate must select explicit bounded-history finality configuration")
	}
	var beforeJSON, afterJSON map[string]interface{}
	if json.Unmarshal(before, &beforeJSON) != nil || json.Unmarshal(raw, &afterJSON) != nil {
		t.Fatal("genesis JSON")
	}
	beforeConfig := beforeJSON["config"].(map[string]interface{})
	afterConfig := afterJSON["config"].(map[string]interface{})
	if len(afterConfig) != len(beforeConfig)+1 || afterConfig["dexDevnet"] == nil {
		t.Fatal("only dexDevnet configuration may be added")
	}
	delete(afterConfig, "dexDevnet")
	delete(beforeJSON, "mixHash")
	delete(afterJSON, "mixHash")
	if !reflect.DeepEqual(beforeJSON, afterJSON) {
		t.Fatal("existing config/top-level JSON values changed")
	}
	if g.ToBlock(nil).Hash().Hex() != i.Genesis || g.ToBlock(nil).Root().Hex() != i.StateRoot {
		t.Fatal("not actual genesis hash/root")
	}
	if g.Config.ChainID.Uint64() != oldChainID || !strings.Contains(strings.Join(i.FinancialAssumptions, " "), "does not prevent ordinary CLX TX replay") {
		t.Fatal("same-chain authentication boundary is not explicit")
	}
	seen := map[string]bool{}
	for _, k := range i.Keys {
		if seen[k.Address] {
			t.Fatal("keys reused across purposes")
		}
		seen[k.Address] = true
		if _, ok := g.Alloc[common.HexToAddress(k.Address)]; ok {
			t.Fatal("new key was allocated genesis funds")
		}
		s, err := os.Stat(k.KeyFile)
		if err != nil || s.Mode().Perm() != 0600 {
			t.Fatal("secret permissions", err)
		}
	}
	for _, p := range i.Participants {
		if _, err = os.Stat(p.DEXDataDir); !os.IsNotExist(err) {
			t.Fatal("candidate created runtime state")
		}
		m, err := service.LoadManifest(p.Manifest)
		if err != nil || m.Domain.ChainID != oldChainID || m.Finance.CLX.ChainID != oldChainID || m.Domain.Genesis != protocol.Hash(g.ToBlock(nil).Hash()) || m.Finance.CLX.ChainConfig.DEXDevnet.Version != 5 || m.LeaderSubmission != p.SubmissionConfig {
			t.Fatal("DEX/source manifests not bound to preserved chain ID and new genesis", err)
		}
	}
	for n, path := range i.LeaderSubmissionConfigs {
		raw, err := os.ReadFile(path)
		var m relayManifest
		if err != nil || json.Unmarshal(raw, &m) != nil || m.Domain.ChainID != oldChainID || m.CLX.ChainID != oldChainID || m.Domain.Genesis != protocol.Hash(g.ToBlock(nil).Hash()) {
			t.Fatal("leader submission not bound to preserved chain ID and new genesis", err)
		}
		participant := i.Participants[n]
		if path != participant.SubmissionConfig || !m.AutoInbox || m.DEXURL != "http://"+participant.API || m.DataDir != filepath.Join(participant.DEXDataDir, "submission") || len(m.Payers) != 3 {
			t.Fatal("submission must belong to this DEX participant and restart with its Common")
		}
		for index, lane := range []string{"anchor", "checkpoint", "claim"} {
			payer := m.Payers[index]
			if payer.Lane != lane || payer.Address.Hex() == participant.RewardRecipient || payer.Address.Hex() == participant.CommonWallet || !seen[payer.Address.Hex()] {
				t.Fatal("submission payer is not a separately inventoried gas identity")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "relays")); !os.IsNotExist(err) {
		t.Fatal("default candidate must not create standalone relay node configuration")
	}
	if _, err = generate(source, dir); err == nil {
		t.Fatal("existing candidate overwritten")
	}
	pub, err := os.ReadFile(filepath.Join(dir, "public", "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventoryMap map[string]interface{}
	if err = json.Unmarshal(pub, &inventoryMap); err != nil {
		t.Fatal(err)
	}
	if _, ok := inventoryMap["Secret"]; ok {
		t.Fatal("private material in inventory")
	}
}

func TestCandidateReusesOnlySixCommonWalletsFromRenamedPrivateArchive(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "original")
	old, err := generate(sourceGenesisFixture(), first)
	if err != nil {
		t.Fatal(err)
	}
	archived := filepath.Join(root, "private-archive")
	if err = os.Rename(first, archived); err != nil {
		t.Fatal(err)
	}
	if _, err = generateWithCommonIdentities(sourceGenesisFixture(), filepath.Join(archived, "nested-output"), archived); err == nil {
		t.Fatal("new output may not mutate the archive")
	}
	next := filepath.Join(root, "new")
	current, err := generateWithCommonIdentities(sourceGenesisFixture(), next, archived)
	if err != nil {
		t.Fatal(err)
	}
	if !current.CommonIdentitiesReused || current.ReusedCommonIdentitySource != archived {
		t.Fatal("identity source not recorded")
	}
	oldAddresses := map[string]string{}
	for _, k := range old.Keys {
		oldAddresses[k.Purpose] = k.Address
	}
	for _, k := range current.Keys {
		reused := strings.HasPrefix(k.Purpose, "cypherdex") && strings.HasSuffix(k.Purpose, "-common-wallet")
		if (oldAddresses[k.Purpose] == k.Address) != reused {
			t.Fatal("wrong key-purpose reuse", k.Purpose)
		}
		if reused {
			a, e1 := os.ReadFile(filepath.Join(archived, "keys", k.Purpose+".key"))
			b, e2 := os.ReadFile(k.KeyFile)
			if e1 != nil || e2 != nil || string(a) != string(b) {
				t.Fatal("Common wallet not preserved")
			}
		}
	}
	for n := range current.Participants {
		if current.Participants[n].VotePublic == old.Participants[n].VotePublic {
			t.Fatal("DEX vote identity was reused")
		}
		if current.Participants[n].CommonWallet != old.Participants[n].CommonWallet {
			t.Fatal("Common wallet changed")
		}
	}
	if current.DEXID == old.DEXID || current.Genesis == old.Genesis {
		t.Fatal("DEX domain/generation was reused")
	}
	for _, base := range []string{archived, next} {
		if _, err = os.Stat(filepath.Join(base, "runtime")); !os.IsNotExist(err) {
			t.Fatal("identity preparation touched runtime")
		}
	}
}

func TestCandidateReuseRejectsUnownedLayoutAndFalseKeyAddressBeforeOutput(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	i, err := generate(sourceGenesisFixture(), original)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(original, "public", "inventory.json")
	good, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(original, "keys", "cypherdex1-common-wallet.key")
	keyBytes, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []string{"false-address", "external-key-metadata", "wrong-secret", "key-symlink", "public-key-permission", "root-symlink"} {
		t.Run(test, func(t *testing.T) {
			var changed inventory
			if err := json.Unmarshal(good, &changed); err != nil {
				t.Fatal(err)
			}
			identityRoot := original
			switch test {
			case "false-address":
				changed.Participants[1].CommonWallet = changed.Participants[2].CommonWallet
			case "external-key-metadata":
				changed.Participants[1].CommonKeyFile = filepath.Join(root, "outside.key")
			case "wrong-secret":
				if err := os.WriteFile(key, []byte(strings.Repeat("01", 32)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "key-symlink":
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(i.Participants[2].CommonKeyFile, key); err != nil {
					t.Fatal(err)
				}
			case "public-key-permission":
				if err := os.Chmod(key, 0644); err != nil {
					t.Fatal(err)
				}
			case "root-symlink":
				identityRoot = filepath.Join(root, "linked")
				if err := os.Symlink(original, identityRoot); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(changed)
			if err := os.WriteFile(pub, raw, 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(root, "refused-"+test)
			if _, err := generateWithCommonIdentities(sourceGenesisFixture(), out, identityRoot); err == nil {
				t.Fatal("unsafe identity source accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("failed identity validation created output")
			}
			if test == "key-symlink" {
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(key, keyBytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(key, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pub, good, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCandidateRejectsManifestIdentityTampering(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "candidate")
	i, err := generate(sourceGenesisFixture(), dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := service.LoadManifest(i.Participants[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := protocol.NativeMarketSeed(m.Finance.Market.Oracle)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*service.Manifest){
		"genesis":       func(m *service.Manifest) { m.Domain.Genesis[0] ^= 1 },
		"committee":     func(m *service.Manifest) { m.Members[0].Public = m.Members[1].Public },
		"domain":        func(m *service.Manifest) { m.Finance.CLX.DEXID[0] ^= 1 },
		"tls-pin":       func(m *service.Manifest) { m.Peers[0].CertSHA256[0] ^= 1 },
		"vote-key":      func(m *service.Manifest) { m.VoteKeyFile = filepath.Join(dir, "keys", "dex-1.vote.key") },
		"unknown-epoch": func(m *service.Manifest) { m.Domain.Epoch = 2 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy, err := service.LoadManifest(i.Participants[0].Manifest)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if err = validateManifest(copy, seed); err == nil {
				t.Fatal("tampered candidate accepted")
			}
		})
	}
	if err = os.Chmod(m.VoteKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err = validateManifest(m, seed); err == nil {
		t.Fatal("public vote key file accepted")
	}
}

func TestCandidateRejectsUnsafePathsAndWrongGeneration(t *testing.T) {
	root := t.TempDir()
	source := sourceGenesisFixture()
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(source, filepath.Join(link, "candidate")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]interface{}
	if err = json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	// The discarded candidate's different chain ID is a historical rejection
	// fixture, not the current deployment setting requested by the user.
	g["config"].(map[string]interface{})["chainId"] = 10101920
	raw, err = json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "wrong.json")
	if err = os.WriteFile(bad, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "untouched")
	if _, err = generate(bad, out); err == nil {
		t.Fatal("wrong source generation accepted")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed preflight created output")
	}
}
