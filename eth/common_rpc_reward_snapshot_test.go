package eth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/accounts/keystore"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/ethdb/memorydb"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

// Uses the existing real chain/WAL harness and real personal IPC API. Admission
// signing uses the same unlocked-wallet SignData operation as reconfig. No
// committee networking, transaction publication, or production keys are needed
// to exercise the configuration snapshot boundary.
func TestCommonRPCRewardConcurrentIPCSnapshots(t *testing.T) {
	previous := bftview.GetServerCoinBase()
	t.Cleanup(func() { bftview.SetServerCoinBase(previous) })
	chain := newSyncModeTestManager(t, true, downloader.FullSync, false).blockchain
	root := t.TempDir()
	ks := keystore.NewKeyStore(filepath.Join(root, "keys"), 2, 1)
	var signers [2]accounts.Account
	for i := range signers {
		account, err := ks.NewAccount("snapshot test password")
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.Unlock(account, "snapshot test password"); err != nil {
			t.Fatal(err)
		}
		signers[i] = account
		t.Cleanup(func() { ks.Lock(account.Address) })
	}
	am := accounts.NewManager(&accounts.Config{}, ks)
	t.Cleanup(func() { am.Close() })
	registry := commonrpcreward.Open(root, chain.Config().ChainID, chain.Genesis().Hash())
	config := testTxQUICConfig()
	config.ChainID, config.GenesisHash = chain.Config().ChainID.Uint64(), chain.Genesis().Hash()
	db := memorydb.New()
	t.Cleanup(func() { db.Close() })
	wal := newTxIngressWAL(db, config)
	if err := wal.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wal.Stop)
	service := &Ethereum{blockchain: chain, accountManager: am, commonRPCRewards: registry, txQUICIngress: &TxQUICIngress{wal: wal}}
	backend := &EthAPIBackend{eth: service, extRPCEnabled: true}
	api := ethapi.NewPrivateAccountAPI(backend, new(ethapi.AddrLocker))
	dir, err := os.MkdirTemp("", "snapshot-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "rpc.ipc")
	if runtime.GOOS == "windows" {
		endpoint = `\\.\pipe\` + filepath.Base(dir)
	}
	listener, server, err := rpc.StartIPCEndpoint(endpoint, []rpc.API{{Namespace: "personal", Service: api}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); server.Stop() })
	ipc, err := rpc.DialIPC(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ipc.Close)
	recipients := [2][2]common.Address{{common.HexToAddress("0xb1"), common.HexToAddress("0xb2")}, {common.HexToAddress("0xd1"), common.HexToAddress("0xd2")}}
	setRecipient := func(signer int, generation int) error {
		var status commonrpcreward.Status
		if err := ipc.Call(&status, "personal_setCommonRPCRewardAddress", signers[signer].Address, recipients[signer][generation], "snapshot test password"); err != nil {
			return err
		}
		if !status.Configured || status.Signer != signers[signer].Address || status.RewardRecipient == nil || *status.RewardRecipient != recipients[signer][generation] {
			return fmt.Errorf("IPC returned inconsistent preference")
		}
		return nil
	}
	for i := range signers {
		if err := setRecipient(i, 0); err != nil {
			t.Fatal(err)
		}
	}
	bftview.SetServerCoinBase(signers[0].Address)
	sign := func(batch *types.CommonTxAdmissionBatch) error {
		account := accounts.Account{Address: batch.Miner}
		wallet, err := am.Find(account)
		if err != nil {
			return err
		}
		signature, err := wallet.SignData(account, accounts.MimetypeDataWithValidator, types.CommonTxAdmissionSigningPayload(batch))
		batch.Signature = signature
		return err
	}
	core.SetCommonRPCAdmissionSigner(sign)
	t.Cleanup(func() { core.SetCommonRPCAdmissionSigner(nil) })
	admit := func(worker, iteration int) ([]core.CommonRPCAdmissionResult, error) {
		hashes := []common.Hash{crypto.Keccak256Hash([]byte(fmt.Sprintf("snapshot/%d/%d/0", worker, iteration))), crypto.Keccak256Hash([]byte(fmt.Sprintf("snapshot/%d/%d/1", worker, iteration)))}
		return backend.signOrReuseCommonRPCAdmissions(hashes, chain.Genesis().Hash(), 0, uint64(time.Now().Unix()))
	}
	validate := func(results []core.CommonRPCAdmissionResult) error {
		if len(results) != 2 || results[0].Batch == nil || results[0].Batch != results[1].Batch {
			return fmt.Errorf("one admission batch did not retain a single snapshot")
		}
		batch := results[0].Batch
		if batch.Version != types.CommonRPCVersionV2 || results[0].Item != 0 || results[1].Item != 1 {
			return fmt.Errorf("invalid version or aligned references")
		}
		if err := types.VerifyCommonTxAdmissionSignature(batch); err != nil {
			return err
		}
		for i, account := range signers {
			if batch.Miner == account.Address {
				if batch.RewardRecipient == recipients[i][0] || batch.RewardRecipient == recipients[i][1] {
					return nil
				}
				return fmt.Errorf("batch mixed signing account %s with another account's recipient %s", batch.Miner, batch.RewardRecipient)
			}
		}
		return fmt.Errorf("batch used an unknown signing account")
	}

	// Freeze the real signing callback after snapshot acquisition. Both IPC
	// preference and active identity change before signing resumes; this batch
	// must retain its captured A/B pair, and the next one must use D's setting.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	core.SetCommonRPCAdmissionSigner(func(batch *types.CommonTxAdmissionBatch) error {
		once.Do(func() { close(entered); <-release })
		return sign(batch)
	})
	type admissionResponse struct {
		results []core.CommonRPCAdmissionResult
		err     error
	}
	response := make(chan admissionResponse, 1)
	go func() { results, err := admit(-1, 0); response <- admissionResponse{results, err} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("signing callback did not begin")
	}
	if err := setRecipient(0, 1); err != nil {
		close(release)
		t.Fatal(err)
	}
	bftview.SetServerCoinBase(signers[1].Address)
	close(release)
	completed := <-response
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	if err := validate(completed.results); err != nil {
		t.Fatal(err)
	}
	if batch := completed.results[0].Batch; batch.Miner != signers[0].Address || batch.RewardRecipient != recipients[0][0] {
		t.Fatal("configuration changed an in-flight signed batch")
	}
	core.SetCommonRPCAdmissionSigner(sign)
	results, err := admit(-1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Batch.Miner != signers[1].Address || results[0].Batch.RewardRecipient != recipients[1][0] {
		t.Fatal("new batch did not use the newly selected account's preference")
	}

	// Bound the stress test: two IPC writers, one identity writer, four actual
	// admission workers. Each worker signs distinct TX hashes without a retry hit.
	start := make(chan struct{})
	errors := make(chan error, 8)
	var workers sync.WaitGroup
	for signer := range signers {
		workers.Add(1)
		go func(signer int) {
			defer workers.Done()
			<-start
			for i := 0; i < 12; i++ {
				if err := setRecipient(signer, i%2); err != nil {
					errors <- err
					return
				}
			}
		}(signer)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 96; i++ {
			bftview.SetServerCoinBase(signers[i%2].Address)
			runtime.Gosched()
		}
	}()
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-start
			for i := 0; i < 24; i++ {
				results, err := admit(worker, i)
				if err == nil {
					err = validate(results)
				}
				if err != nil {
					errors <- err
					return
				}
				runtime.Gosched()
			}
		}(worker)
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	for _, addresses := range recipients {
		for _, address := range addresses {
			if ks.HasAddress(address) {
				t.Fatal("recipient key was imported")
			}
		}
	}
	t.Run("transaction_and_receipt_fields", func(t *testing.T) {
		// The extraction paths must use the immutable certificate/reward, even
		// when the node's active signer and latest preference have changed.
		tx, err := ks.SignTx(signers[0], types.NewTransaction(0, common.HexToAddress("0x42"), big.NewInt(1), 21000, big.NewInt(1), nil), chain.Config().ChainID)
		if err != nil {
			t.Fatal(err)
		}
		wantRecipient := recipients[0][0]
		admissions, err := core.SignCommonRPCAdmissions([]common.Hash{tx.Hash()}, signers[0].Address, chain.Config().ChainID, chain.Genesis().Hash(), 0, uint64(time.Now().Unix()), wantRecipient)
		if err != nil {
			t.Fatal(err)
		}
		reward := &types.CommonTxReward{Version: types.CommonRPCVersionV2, TxHash: tx.Hash(), Approver: signers[0].Address, RewardRecipient: wantRecipient, ApproverReward: big.NewInt(7), Burn: big.NewInt(28)}
		block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1)}).WithBody([]*types.Transaction{tx}, nil)
		block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{admissions[0].Batch}, []types.CommonTxAdmissionRef{{Batch: 0, Item: 0}}, []*types.CommonTxReward{reward})
		receipt := make(map[string]interface{})
		addCommonRPCFields(receipt, block, tx.Hash())
		transaction := NewPublicEthereumAPI(service).rpcTransactionFields(tx, block, block.Hash(), 1, 0)
		for _, fields := range []map[string]interface{}{receipt, transaction} {
			encoded, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]interface{}
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if fields["commonTxApprover"] != signers[0].Address || fields["commonTxRewardRecipient"] != wantRecipient || decoded["commonTxApproverReward"] != "0x7" || decoded["commonTxBurn"] != "0x1c" {
				t.Fatalf("response conflated signer/recipient/amount: %s", encoded)
			}
		}
		for _, invalidRecipient := range []common.Address{{}, signers[0].Address} {
			if _, err := core.SignCommonRPCAdmissions([]common.Hash{tx.Hash()}, signers[0].Address, chain.Config().ChainID, chain.Genesis().Hash(), 0, uint64(time.Now().Unix()), invalidRecipient); err == nil {
				t.Fatal("missing or self-directed mandatory recipient was accepted")
			}
		}
	})
}

func TestCommonRPCRewardSnapshotExcludesIdentityWriter(t *testing.T) {
	previous := bftview.GetServerCoinBase()
	t.Cleanup(func() { bftview.SetServerCoinBase(previous) })
	a, d := common.HexToAddress("0xa1"), common.HexToAddress("0xd1")
	b, c := common.HexToAddress("0xb1"), common.HexToAddress("0xc1")
	registry := commonrpcreward.Open(t.TempDir(), big.NewInt(1337), common.HexToHash("0x01"))
	if _, err := registry.Set(a, b); err != nil {
		t.Fatal(err)
	}
	bftview.SetServerCoinBase(a)
	entered, readNow, readDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var gotSigner, gotRecipient common.Address
	var readErr error
	go func() {
		bftview.WithServerCoinBase(func(signer common.Address) {
			gotSigner = signer
			close(entered)
			<-readNow
			gotRecipient, readErr = registry.Recipient(signer)
		})
		close(readDone)
	}()
	<-entered
	writerStarted, writerDone := make(chan struct{}), make(chan struct{})
	go func() { close(writerStarted); bftview.SetServerCoinBase(d); close(writerDone) }()
	<-writerStarted
	// A's preference may change while its identity snapshot is held. D may not
	// become active until that lookup completes, so (A,C) really exists at lookup.
	if _, err := registry.Set(a, c); err != nil {
		close(readNow)
		<-readDone
		<-writerDone
		t.Fatal(err)
	}
	select {
	case <-writerDone:
		close(readNow)
		<-readDone
		t.Fatal("identity writer crossed an unfinished recipient snapshot")
	case <-time.After(50 * time.Millisecond):
	}
	close(readNow)
	<-readDone
	<-writerDone
	if readErr != nil || gotSigner != a || gotRecipient != c || bftview.GetServerCoinBase() != d {
		t.Fatalf("incoherent snapshot: signer=%s recipient=%s error=%v", gotSigner, gotRecipient, readErr)
	}
}
