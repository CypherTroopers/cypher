package eth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/p2p"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rpc"
)

const rewardCrashChildDirectory = "CYPHER_TEST_REWARD_CRASH_DIRECTORY"
const rewardCrashChildPhase = "CYPHER_TEST_REWARD_CRASH_PHASE"

// The fixture contains public chain/account data and already user-signed TXs.
// The generated A key is kept only in the temporary encrypted keystore.
type rewardCrashFixture struct {
	Genesis     *core.Genesis  `json:"genesis"`
	Signer      common.Address `json:"signer"`
	Before      common.Address `json:"before"`
	After       common.Address `json:"after"`
	OldTX       hexutil.Bytes  `json:"oldTx"`
	NewTX       hexutil.Bytes  `json:"newTx"`
	IPCEndpoint string         `json:"ipcEndpoint"`
}

type rewardCrashCheckpoint struct {
	OldProof hexutil.Bytes `json:"oldProof"`
	NewProof hexutil.Bytes `json:"newProof,omitempty"`
	OldID    common.Hash   `json:"oldId"`
	NewID    common.Hash   `json:"newId,omitempty"`
}

func writeRewardCrashJSON(path string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// The first child is killed only after a successful public HTTP acceptance and
// a successful IPC B->C change. Process.Kill never runs node.Close or deferred
// WAL/outbox drains. A separate process must recover that exact on-disk state.
func TestCommonRPCRewardForcedCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	encoded, err := os.ReadFile("../genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture := rewardCrashFixture{Genesis: new(core.Genesis), Before: common.HexToAddress("0xb1"), After: common.HexToAddress("0xc1")}
	if err := json.Unmarshal(encoded, fixture.Genesis); err != nil {
		t.Fatal(err)
	}
	fixture.Genesis.Config.RnetPort = "0"
	fixture.Genesis.Config.EnabledTPS = DefaultConfig.EnableTPS
	fixture.Genesis.Mixhash, err = params.FairHotstuffGenesisCommitment(fixture.Genesis.Config)
	if err != nil {
		t.Fatal(err)
	}
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	fixture.Signer = crypto.PubkeyToAddress(signerKey.PublicKey)
	for _, address := range []common.Address{fixture.Signer, crypto.PubkeyToAddress(payerKey.PublicKey)} {
		fixture.Genesis.Alloc[address] = core.GenesisAccount{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))}
	}
	// Deliberately cheap test-only KDF; no real keys or passwords are used.
	store := keystore.NewKeyStore(filepath.Join(dir, "keystore"), 2, 1)
	if _, err := store.ImportECDSA(signerKey, "test password"); err != nil {
		t.Fatal(err)
	}
	for nonce, target := range []*hexutil.Bytes{&fixture.OldTX, &fixture.NewTX} {
		tx, err := types.SignTx(types.NewTransaction(uint64(nonce), common.Address{1}, big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil), types.NewEIP155Signer(fixture.Genesis.Config.ChainID), payerKey)
		if err != nil {
			t.Fatal(err)
		}
		*target, err = tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
	socketDir, err := os.MkdirTemp("", "reward-crash-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	fixture.IPCEndpoint = filepath.Join(socketDir, "rpc.ipc")
	if runtime.GOOS == "windows" {
		fixture.IPCEndpoint = `\\.\pipe\` + filepath.Base(socketDir)
	}
	if err := writeRewardCrashJSON(filepath.Join(dir, "fixture.json"), fixture); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runChild := func(phase string, kill bool) rewardCrashCheckpoint {
		t.Helper()
		logPath := filepath.Join(dir, phase+".log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer logFile.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCommonRPCRewardCrashChild$", "-test.timeout=85s", "-test.v")
		cmd.Env = append(os.Environ(), rewardCrashChildDirectory+"="+dir, rewardCrashChildPhase+"="+phase)
		cmd.Stdout, cmd.Stderr = logFile, logFile
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		waited := false
		defer func() {
			if !waited {
				cmd.Process.Kill()
				<-done
			}
		}()
		childOutput := func() string {
			data, _ := os.ReadFile(logPath)
			if len(data) > 8192 {
				data = data[len(data)-8192:]
			}
			return string(data)
		}
		checkpointPath := filepath.Join(dir, phase+".json")
		if kill {
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
		ready:
			for {
				select {
				case err := <-done:
					waited = true
					t.Fatalf("accepting child exited before durable readiness: %v\n%s", err, childOutput())
				case <-ticker.C:
					if _, err := os.Stat(checkpointPath); err == nil {
						break ready
					} else if !os.IsNotExist(err) {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("accepting child did not reach durable readiness before deadline")
				}
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waitErr := <-done
			waited = true
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) || exitErr.Success() {
				t.Fatalf("child did not terminate abruptly: %v", waitErr)
			}
			data, _ := os.ReadFile(logPath)
			if bytes.Contains(data, []byte("WARNING: DATA RACE")) {
				t.Fatalf("race detected in killed child:\n%s", childOutput())
			}
		} else {
			waitErr := <-done
			waited = true
			if waitErr != nil {
				t.Fatalf("recovery child failed: %v\n%s", waitErr, childOutput())
			}
		}
		data, err := os.ReadFile(checkpointPath)
		if err != nil {
			t.Fatal(err)
		}
		var checkpoint rewardCrashCheckpoint
		if err := json.Unmarshal(data, &checkpoint); err != nil {
			t.Fatal(err)
		}
		return checkpoint
	}
	before := runChild("accepted", true)
	after := runChild("recovered", false)
	if len(before.OldProof) == 0 || !bytes.Equal(before.OldProof, after.OldProof) || before.OldID != after.OldID {
		t.Fatal("forced crash/retry changed the original B certificate or Admission ID")
	}
	if len(after.NewProof) == 0 || after.NewID == after.OldID {
		t.Fatal("post-recovery new TX did not get its own C certificate")
	}
}

func TestCommonRPCRewardCrashChild(t *testing.T) {
	dir := os.Getenv(rewardCrashChildDirectory)
	if dir == "" {
		t.Skip("subprocess helper")
	}
	phase := os.Getenv(rewardCrashChildPhase)
	if phase != "accepted" && phase != "recovered" {
		t.Fatal("unknown crash-test phase")
	}
	data, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture rewardCrashFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	stack, err := node.New(&node.Config{
		Name: "reward-crash", DataDir: filepath.Join(dir, "node"), KeyStoreDir: filepath.Join(dir, "keystore"),
		IPCPath: fixture.IPCEndpoint, HTTPHost: "127.0.0.1", HTTPModules: []string{"eth", "personal"},
		HTTPVirtualHosts: []string{"localhost"}, NoUSB: true, UseLightweightKDF: true,
		P2P: p2p.Config{NoDiscovery: true, MaxPeers: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stack.Close(); err != nil {
			t.Error(err)
		}
	})
	config := DefaultConfig
	config.Genesis = fixture.Genesis
	config.GenesisKey = &core.GenesisKey{Config: fixture.Genesis.Config, Difficulty: big.NewInt(1)}
	config.NetworkId = fixture.Genesis.Config.ChainID.Uint64()
	config.Miner.Etherbase = fixture.Signer
	config.SyncMode, config.ExternalIp = downloader.FullSync, "127.0.0.1"
	config.RnetPort, config.EnableTPS = fixture.Genesis.Config.RnetPort, fixture.Genesis.Config.EnabledTPS
	config.DatabaseCache, config.DatabaseHandles = 16, 16
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 0, 0, 0
	config.TxQUIC = testTxQUICConfig()
	config.TxQUIC.BridgeEnabled = true
	config.TxQUIC.OutboxRetryMin, config.TxQUIC.OutboxRetryMax = time.Second, time.Second
	service, err := New(stack, &config)
	if err != nil {
		t.Fatal(err)
	}
	service.txQUICIngress.SetFHSRouteProvider(func() (TxQUICFHSRoute, error) {
		return TxQUICFHSRoute{}, errors.New("crash-test committee is offline")
	})
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	httpClient, err := rpc.DialHTTP(stack.HTTPEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(httpClient.Close)
	ipcClient, err := rpc.DialIPC(context.Background(), stack.IPCEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ipcClient.Close)
	store := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	if store.HasAddress(fixture.Before) || store.HasAddress(fixture.After) {
		t.Fatal("reward recipients must not have local keys")
	}
	account := accounts.Account{Address: fixture.Signer}
	if _, err := store.SignHash(account, make([]byte, 32)); !errors.Is(err, keystore.ErrLocked) {
		t.Fatalf("new process did not start with A locked: %v", err)
	}
	var oldTX, newTX types.Transaction
	if err := oldTX.UnmarshalBinary(fixture.OldTX); err != nil {
		t.Fatal(err)
	}
	if err := newTX.UnmarshalBinary(fixture.NewTX); err != nil {
		t.Fatal(err)
	}
	submit := func(raw hexutil.Bytes, tx *types.Transaction) error {
		var hash common.Hash
		err := httpClient.Call(&hash, "eth_sendRawTransaction", raw)
		if err == nil && hash != tx.Hash() {
			return errors.New("public acceptance returned a different TX hash")
		}
		return err
	}
	proof := func(tx *types.Transaction, recipient common.Address) (hexutil.Bytes, common.Hash) {
		t.Helper()
		admission, found, err := service.txQUICIngress.wal.localRPCAdmission(fixture.Signer, tx.Hash())
		if err != nil || !found || admission.Batch.Miner != fixture.Signer || admission.Batch.RewardRecipient != recipient || admission.Batch.Version != types.CommonRPCVersionV2 {
			t.Fatalf("durable admission identity mismatch: found=%v, %v", found, err)
		}
		if err := types.VerifyCommonTxAdmissionSignature(admission.Batch); err != nil {
			t.Fatal(err)
		}
		encoded, err := rlp.EncodeToBytes(admission.Batch)
		if err != nil {
			t.Fatal(err)
		}
		if service.txPool.Get(tx.Hash()) == nil {
			t.Fatal("durable accepted TX is missing from the restored pool")
		}
		return encoded, admission.Batch.AdmissionID
	}
	assertDurableRecords := func(want map[common.Hash]common.Address) {
		t.Helper()
		pending, _ := service.txQUICIngress.outbox.Pending()
		if pending != len(want) {
			t.Fatalf("active outbox contains %d records, want %d", pending, len(want))
		}
		seen := make(map[common.Hash]struct{})
		iterator := service.txOutboxDb.NewIterator(txOutboxRecordPrefix, nil)
		defer iterator.Release()
		for iterator.Next() {
			var record TxOutboxRecord
			if err := rlp.DecodeBytes(iterator.Value(), &record); err != nil {
				t.Fatal(err)
			}
			batch, _, err := decodeTxQUICBatch(record.Payload)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range batch.Items {
				hash := item.Tx.Hash()
				recipient, exists := want[hash]
				if _, duplicate := seen[hash]; duplicate || !exists || batch.Certificate.Miner != fixture.Signer || batch.Certificate.RewardRecipient != recipient {
					t.Fatal("outbox contains duplicate TXs or altered signed recipients")
				}
				seen[hash] = struct{}{}
			}
		}
		if iterator.Error() != nil || len(seen) != len(want) {
			t.Fatal("outbox omitted a successful HTTP admission")
		}
		// Retries legitimately append distinct operation events. Their immutable
		// proof identity per TX must remain singular, and event IDs stay unique.
		events, certificates := make(map[common.Hash]struct{}), make(map[common.Hash]common.Hash)
		if err := service.txQUICIngress.wal.Replay(func(frame *txIngressWALFrame) error {
			if _, duplicate := events[frame.EventID]; duplicate {
				return errors.New("duplicate canonical WAL event ID")
			}
			events[frame.EventID] = struct{}{}
			if frame.Kind != txIngressWALLocalIntent {
				return nil
			}
			batch, _, err := decodeTxQUICBatch(frame.Payload)
			if err != nil {
				return err
			}
			for _, item := range batch.Items {
				hash := item.Tx.Hash()
				if recipient, exists := want[hash]; !exists || batch.Certificate.Miner != fixture.Signer || batch.Certificate.RewardRecipient != recipient {
					return fmt.Errorf("WAL proof recipient differs for accepted TX %s", hash)
				}
				if id, exists := certificates[hash]; exists && id != batch.Certificate.AdmissionID {
					return errors.New("retry created a second certificate ID for the same TX")
				}
				certificates[hash] = batch.Certificate.AdmissionID
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(certificates) != len(want) {
			t.Fatal("WAL lost an accepted TX proof")
		}
	}
	unlock := func() {
		t.Helper()
		var success bool
		if err := ipcClient.Call(&success, "personal_unlockAccount", fixture.Signer, "test password", uint64(0)); err != nil || !success {
			t.Fatalf("IPC re-unlock failed: %v", err)
		}
	}
	var status commonrpcreward.Status
	checkpoint := rewardCrashCheckpoint{}
	if phase == "accepted" {
		if err := ipcClient.Call(&status, "personal_setCommonRPCRewardAddress", fixture.Signer, fixture.Before, "test password"); err != nil {
			t.Fatal(err)
		}
		unlock()
		if err := submit(fixture.OldTX, &oldTX); err != nil {
			t.Fatal(err)
		}
		checkpoint.OldProof, checkpoint.OldID = proof(&oldTX, fixture.Before)
		if err := ipcClient.Call(&status, "personal_setCommonRPCRewardAddress", fixture.Signer, fixture.After, "test password"); err != nil {
			t.Fatal(err)
		}
		assertDurableRecords(map[common.Hash]common.Address{oldTX.Hash(): fixture.Before})
		if err := writeRewardCrashJSON(filepath.Join(dir, phase+".json"), checkpoint); err != nil {
			t.Fatal(err)
		}
		// Parent Process.Kill is the only successful exit path for this phase.
		select {}
	}
	if err := ipcClient.Call(&status, "personal_getCommonRPCRewardAddress", fixture.Signer); err != nil || !status.Configured || status.RewardRecipient == nil || *status.RewardRecipient != fixture.After {
		t.Fatalf("successful IPC B->C setting did not survive Process.Kill: %+v, %v", status, err)
	}
	assertDurableRecords(map[common.Hash]common.Address{oldTX.Hash(): fixture.Before})
	for i := 0; i < 2; i++ {
		if err := submit(fixture.OldTX, &oldTX); err != nil {
			t.Fatalf("locked recovery could not reuse old B proof: %v", err)
		}
	}
	checkpoint.OldProof, checkpoint.OldID = proof(&oldTX, fixture.Before)
	if _, err := store.SignHash(account, make([]byte, 32)); !errors.Is(err, keystore.ErrLocked) {
		t.Fatal("retry implicitly unlocked A")
	}
	if err := submit(fixture.NewTX, &newTX); err == nil || !strings.Contains(err.Error(), "authentication needed") {
		t.Fatalf("locked recovery accepted a fresh TX: %v", err)
	}
	assertDurableRecords(map[common.Hash]common.Address{oldTX.Hash(): fixture.Before})
	unlock()
	if err := submit(fixture.NewTX, &newTX); err != nil {
		t.Fatalf("re-unlock did not resume fresh C admissions: %v", err)
	}
	checkpoint.NewProof, checkpoint.NewID = proof(&newTX, fixture.After)
	assertDurableRecords(map[common.Hash]common.Address{oldTX.Hash(): fixture.Before, newTX.Hash(): fixture.After})
	if err := writeRewardCrashJSON(filepath.Join(dir, phase+".json"), checkpoint); err != nil {
		t.Fatal(err)
	}
}
