package main

import (
	"encoding/json"
	"os"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
	"path/filepath"
	"testing"
)

// Validate the prepared private candidate through the actual normal relay CLI
// parser/signer. This does not start a relay or contact either network.
func TestDEXLiveCandidateRelayCLIValidation(t *testing.T) {
	root := os.Getenv("CYPHER_DEX_PRIVATE_CANDIDATE")
	if root == "" {
		t.Skip("explicit private candidate directory required")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute candidate path required")
	}
	seen := map[string]bool{}
	raw, err := os.ReadFile(filepath.Join(root, "public", "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		LeaderSubmissionConfigs []string
		RelayConfigs            []string
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	paths := inventory.LeaderSubmissionConfigs
	if len(paths) == 0 {
		// Historical candidates explicitly listed standalone relay fixtures.
		paths = inventory.RelayConfigs
		if len(paths) != 2 {
			t.Fatal("candidate has neither seven leader configs nor historical two relay configs")
		}
	} else if len(paths) != 7 || len(inventory.RelayConfigs) != 0 {
		t.Fatal("leader candidate must have seven submission configs and no standalone relay roles")
	}
	for _, name := range paths {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		m, err := loadRelayCLIManifest(path)
		if err != nil {
			t.Fatal(name, "manifest validation failed", err)
		}
		c, err := m.config()
		if err != nil {
			t.Fatal(name, "config validation failed", err)
		}
		signer, err := loadRelayLocalSigner(m, c)
		if err != nil {
			t.Fatal(name, "local signer validation failed", err)
		}
		defer signer.close()
		if len(signer.keys) != 3 {
			t.Fatal(name, "expected separate three gas lane identities")
		}
		for _, p := range m.Payers {
			if seen[p.Address.Hex()] {
				t.Fatal("relay identities overlap")
			}
			seen[p.Address.Hex()] = true
		}
	}
}

// Exercise the actual financial factory with the prepared registered identities,
// while every writable path belongs to this test. No Start, listener, network,
// vote or financial transaction is executed, and candidate/live WALs are untouched.
func TestDEXLiveCandidateFinancialFactoryV5(t *testing.T) {
	root := os.Getenv("CYPHER_DEX_PRIVATE_CANDIDATE")
	if root == "" {
		t.Skip("explicit private candidate directory required")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute candidate path required")
	}
	var firstRoot protocol.Hash
	seen := map[uint8]bool{}
	for _, name := range []string{"cyphermine", "cypherdex1", "cypherdex2", "cypherdex3", "cypherdex4", "cypherdex5", "cypherdex6"} {
		t.Run(name, func(t *testing.T) {
			m, err := service.LoadManifest(filepath.Join(root, "manifests", name+".json"))
			if err != nil {
				t.Fatal("manifest", err)
			}
			if m.Finance == nil || m.Finance.CLX.ChainConfig == nil || m.Finance.CLX.ChainConfig.DEXDevnet == nil || m.Finance.CLX.ChainConfig.DEXDevnet.Version != 5 {
				t.Fatal("requires prepared version5 financial manifest")
			}
			if seen[m.Index] {
				t.Fatal("duplicate registered participant")
			}
			seen[m.Index] = true
			original := m.DataDir
			m.DataDir = filepath.Join(t.TempDir(), "dex")
			if m.DataDir == original || m.BootstrapSnapshotFile != "" {
				t.Fatal("test must open a fresh isolated empty datadir")
			}
			expected, err := protocol.NativeGenesisRootV4(protocol.Hash(m.Finance.CLX.ChainConfig.DEXDevnet.GenesisSeed), m.Domain, m.Finance.Market.Custody)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				instance, err := finance.OpenManifest(m)
				if err != nil {
					t.Fatalf("factory open%d: %v", attempt, err)
				}
				if err = instance.Close(); err != nil {
					t.Fatal("factory close", err)
				}
				paths, err := filepath.Glob(filepath.Join(m.DataDir, "fhs", "state-*.json"))
				if err != nil || len(paths) != 1 {
					t.Fatal("expected exactly one fresh generation WAL", err)
				}
				raw, err := os.ReadFile(paths[0])
				if err != nil || len(raw) > 2*1024*1024 {
					t.Fatal("bounded generated WAL", err)
				}
				var env struct{ Payload json.RawMessage }
				if err = json.Unmarshal(raw, &env); err != nil {
					t.Fatal(err)
				}
				var state struct {
					Version         uint16
					Domain          protocol.Domain
					ExecutionID     string
					ExecutionSchema uint16
					GenesisState    []byte
					GenesisRoot     protocol.Hash
					Records         map[string]json.RawMessage
					Finalized       []json.RawMessage
					Safety          struct {
						LastVote        json.RawMessage
						HighestQC       json.RawMessage
						LastTimeoutVote json.RawMessage
						HighestTC       json.RawMessage
					}
				}
				if err = json.Unmarshal(env.Payload, &state); err != nil {
					t.Fatal(err)
				}
				if state.Version != 4 || state.Domain != m.Domain || state.ExecutionID != "BTC-CLX-native-finance-v6-history-v1" || state.ExecutionSchema != consensus.AncestryExecutionSchema || state.GenesisRoot != expected || len(state.Records) != 0 || len(state.Finalized) != 0 {
					t.Fatal("factory did not bind empty schema6/version5 financial state")
				}
				for _, safety := range []json.RawMessage{state.Safety.LastVote, state.Safety.HighestQC, state.Safety.LastTimeoutVote, state.Safety.HighestTC} {
					if len(safety) > 0 && string(safety) != "null" {
						t.Fatal("constructor unexpectedly signed or advanced consensus")
					}
				}
				var financial struct {
					Version uint16
					Engine  json.RawMessage
				}
				var engine struct {
					Height      uint64
					Total       string
					InboxCursor uint64
				}
				if json.Unmarshal(state.GenesisState, &financial) != nil || json.Unmarshal(financial.Engine, &engine) != nil || financial.Version != 6 || engine.Height != 0 || engine.Total != "0" || engine.InboxCursor != 0 {
					t.Fatal("constructor changed financial genesis")
				}
				if firstRoot == (protocol.Hash{}) {
					firstRoot = state.GenesisRoot
				} else if firstRoot != state.GenesisRoot {
					t.Fatal("registered participants disagree on genesis root")
				}
			}
			t.Logf("registered participant%d: factory open/close+cold reopen PASS; dataSchema6 financialState6; noStart/noVote/noNetwork/liveDatadirUntouched", m.Index)
		})
	}
	if len(seen) != 7 {
		t.Fatal("expected seven unique registered participants")
	}
}
