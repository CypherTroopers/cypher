package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/params"
)

// Every path belongs to this fixture. Enabled journals are disposable cache
// directories, never chaindata/keystore/the instance directory itself.
func TestG0CommonCLIJournalPathRestart(t *testing.T) {
	if os.Getenv("CYPHER_DEX_CLI_DEVNET") != "1" {
		t.Skip("opt-in isolated normal CLI namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("loopback-only namespace required", err)
	}
	for _, mode := range []string{"omitted", "empty", "relative", "absolute"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			raw, err := os.ReadFile("../../genesis.json")
			if err != nil {
				t.Fatal(err)
			}
			var genesis core.Genesis
			if err = json.Unmarshal(raw, &genesis); err != nil {
				t.Fatal(err)
			}
			_, rnet, _ := net.SplitHostPort(freeEndpoint(t))
			genesis.Config.RnetPort = rnet
			for i, member := range genesis.Config.GenCommittee {
				member.Address = fmt.Sprintf("127.0.0.1:%d", 29100+i)
				genesis.Config.GenCommittee[i] = member
			}
			genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(genesis.Config)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = json.Marshal(genesis)
			if err != nil {
				t.Fatal(err)
			}
			genesisPath := filepath.Join(root, "genesis.json")
			if err = os.WriteFile(genesisPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			datadir := filepath.Join(root, "common")
			startOwnedCLI(t, root, "--datadir", datadir, "init", genesisPath).wait(t)
			initial := readNativeCLIClosedGenesis(t, datadir, "journal-"+mode+"-initialized")
			if initial[0] == (common.Hash{}) || initial[1] == (common.Hash{}) {
				t.Fatal("missing initialized genesis")
			}
			instance := filepath.Join(datadir, "cypher")
			sentinel := filepath.Join(instance, "g0-sibling-sentinel")
			wantSentinel := []byte("owned sibling outside the replaceable cache directory")
			if err = os.WriteFile(sentinel, wantSentinel, 0600); err != nil {
				t.Fatal(err)
			}
			ipcDir, err := os.MkdirTemp("", "g0-journal-ipc-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(ipcDir) })
			ipc := filepath.Join(ipcDir, "node.ipc")
			args := []string{"--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", rnet, "--port", "0", "--nodiscover", "--maxpeers", "0", "--ipcpath", ipc, "--syncmode", "full", "--cache", "32"}
			journal := filepath.Join(instance, "triecache")
			switch mode {
			case "empty":
				args = append(args, "--cache.trie.journal", "")
			case "relative":
				journal = filepath.Join(instance, "g0-cache", "trie")
				args = append(args, "--cache.trie.journal", filepath.Join("g0-cache", "trie"))
			case "absolute":
				journal = filepath.Join(root, "owned-absolute-triecache")
				args = append(args, "--cache.trie.journal", journal)
			}
			for restart := 0; restart < 2; restart++ {
				parent := startOwnedCLI(t, root, args...)
				client := waitIPC(t, ipc, parent)
				var mining bool
				if err = client.Call(&mining, "eth_mining"); err != nil || mining {
					t.Fatal("unexpected PoW lifecycle", mining, err)
				}
				client.Close()
				parent.stop(t)
				if got := readNativeCLIClosedGenesis(t, datadir, fmt.Sprintf("journal-%s-closed-%d", mode, restart)); got != initial {
					t.Fatal("shutdown changed genesis mappings")
				}
				if got, err := os.ReadFile(sentinel); err != nil || !bytes.Equal(got, wantSentinel) {
					t.Fatal("shutdown replaced sibling data", err)
				}
				entries, err := os.ReadDir(journal)
				if mode == "empty" {
					if !os.IsNotExist(err) {
						t.Fatal("disabled journal created a cache directory", err)
					}
				} else if err != nil || len(entries) == 0 {
					t.Fatal("enabled journal not persisted at expected path", journal, err)
				}
			}
			t.Logf("JOURNAL_RESTART mode=%s expected=%s normal_starts=2 genesis_init=1 tx_key_genesis=preserved sibling=preserved normal_pow_nonce=NOT_RUN", mode, journal)
		})
	}
}
