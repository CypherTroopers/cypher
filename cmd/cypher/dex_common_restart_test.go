package main

import (
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

// An ordinary Common with DEX disabled must preserve its database across an
// explicitly disabled trie journal and a normal shutdown. This runs the actual
// CLI and does not reset or reinitialize genesis when it restarts.
func TestCommonCLIEmptyTrieJournalRestartDEXOff(t *testing.T) {
	if os.Getenv("CYPHER_DEX_CLI_DEVNET") != "1" {
		t.Skip("opt-in isolated CLI namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("loopback-only namespace required", err)
	}
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
	path := filepath.Join(root, "genesis.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	datadir := filepath.Join(root, "common")
	init := startOwnedCLI(t, root, "--datadir", datadir, "init", path)
	init.wait(t)
	initial := readNativeCLIClosedGenesis(t, datadir, "DEX-OFF-after-init")
	if initial[0] == (common.Hash{}) || initial[1] == (common.Hash{}) {
		t.Fatal("fixture genesis missing")
	}
	ipcDir, err := os.MkdirTemp("", "common-restart-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	ipc := filepath.Join(ipcDir, "node.ipc")
	args := []string{"--datadir", datadir, "--nat", "extip:127.0.0.1", "--rnetport", rnet, "--port", "0", "--nodiscover", "--maxpeers", "0", "--ipcpath", ipc, "--syncmode", "full", "--cache", "32", "--cache.trie.journal", ""}
	for n := 0; n < 2; n++ {
		parent := startOwnedCLI(t, root, args...)
		client := waitIPC(t, ipc, parent)
		var mining bool
		if err = client.Call(&mining, "eth_mining"); err != nil || mining {
			t.Fatal("unexpected mining", mining, err)
		}
		client.Close()
		parent.stop(t)
		if got := readNativeCLIClosedGenesis(t, datadir, fmt.Sprintf("DEX-OFF-closed-%d", n)); got != initial {
			t.Fatal("normal Common shutdown changed genesis mappings")
		}
	}
	t.Log("ordinary Common DEX OFF restarted without init; disabled trie journal preserved tx/key genesis and chaindata; no PoW nonce search")
}
