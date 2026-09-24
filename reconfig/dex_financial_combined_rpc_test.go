package reconfig_test

// This fixture enables the existing RPC reward role on a normal Common which
// already supervises its native-finance DEX sidecar. No miner is started and no
// validator receives a transaction through a test-only injection path.
import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/commonrpcreward"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig"
	"github.com/cypherium/cypher/rpc"
)

func financialCombinedRPC(t *testing.T, child *dexFinancialChild, source *nativeCommonNode, fixture *reconfig.FHSRewardNetworkFixture, height uint64, finalityClient *rpc.Client) (func(*types.Transaction) error, common.Address) {
	t.Helper()
	if child == nil || child.cli == nil || source == nil || fixture == nil || fixture.OperatorKey == nil || finalityClient == nil || height == 0 || height > 128 {
		t.Fatal("combined RPC requires an owned normal Common and bounded native devnet fixture")
	}
	p := child.cli
	genesis := fixture.Genesis.ToBlock(nil).Hash()
	chain := source.Service.BlockChain()
	if chain.Genesis().Hash() != genesis || chain.CurrentBlock().NumberU64() != height {
		t.Fatal("combined RPC source must already have replayed the exact CLX height")
	}
	manifest, err := os.ReadFile(p.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ipc, err := rpc.DialIPC(ctx, filepath.Join(filepath.Dir(p.manifestPath), "common.ipc"))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ipc.Close)
	call := func(result interface{}, method string, args ...interface{}) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return ipc.CallContext(ctx, result, method, args...)
	}
	checkRoles := func() error {
		var mining bool
		if err := call(&mining, "eth_mining"); err != nil {
			return err
		}
		if mining {
			return fmt.Errorf("combined RPC unexpectedly started PoW")
		}
		var status service.Status
		if err := p.http("GET", "/v1/status", nil, &status); err != nil {
			return err
		}
		if status.State != "active" || status.Error != "" || status.Finalized == 0 {
			return fmt.Errorf("combined RPC DEX sidecar unavailable: state=%s finalized=%d error=%s", status.State, status.Finalized, status.Error)
		}
		current, err := os.ReadFile(p.manifestPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, manifest) {
			return fmt.Errorf("RPC role changed immutable DEX key/recipient/domain configuration")
		}
		return nil
	}
	if err := checkRoles(); err != nil {
		t.Fatal(err)
	}

	// The source uses normal InsertChain verification; this parent obtains the
	// same blocks through actual ETH P2P synchronization before local TX checks.
	var added bool
	if err := call(&added, "admin_addPeer", source.Stack.Server().Self().URLv4()); err != nil || !added {
		t.Fatal("combined RPC Common peer admission", err)
	}
	deadline := time.Now().Add(75 * time.Second)
	for {
		var current hexutil.Uint64
		if err := call(&current, "eth_blockNumber"); err != nil {
			t.Fatal(err)
		}
		if uint64(current) == height {
			break
		}
		if uint64(current) > height || time.Now().After(deadline) {
			t.Fatalf("combined RPC Common sync height=%d want=%d", current, height)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, h := range []uint64{0, height} {
		var got struct {
			Hash    common.Hash
			Root    common.Hash    `json:"stateRoot"`
			Receipt common.Hash    `json:"receiptsRoot"`
			Gas     hexutil.Uint64 `json:"gasUsed"`
		}
		if err := call(&got, "eth_getBlockByNumber", hexutil.EncodeUint64(h), false); err != nil {
			t.Fatal(err)
		}
		want := chain.GetBlockByNumber(h)
		if want == nil || got.Hash != want.Hash() || got.Root != want.Root() || got.Receipt != want.ReceiptHash() || uint64(got.Gas) != want.GasUsed() {
			t.Fatal("combined RPC Common CLX genesis/head/root/receipt/gas mismatch", h)
		}
	}
	var custody hexutil.Big
	if err := call(&custody, "eth_getBalance", params.DEXSettlementAddress, hexutil.EncodeUint64(height)); err != nil || (*big.Int)(&custody).Cmp(nativeUnits(225)) != 0 {
		t.Fatal("combined RPC requires authenticated pre-claim native custody225", err)
	}

	// A separately owned Common needs its own operator nonce stream. Copying the
	// source operator into a fresh outbox starts the same authenticated stream at
	// nonce 1, which the validators correctly reject against its existing replay
	// watermark. This new fixture key signs admission only and receives no funds.
	// Only this freshly generated fixture operator enters the owned keystore.
	// Neither the reward recipient's key nor any DEX vote/trader key is imported.
	operatorKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal("combined RPC fixture operator generation failed", err)
	}
	operator := crypto.PubkeyToAddress(operatorKey.PublicKey)
	if operator == crypto.PubkeyToAddress(fixture.OperatorKey.PublicKey) || operator == fixture.RewardRecipient {
		t.Fatal("combined RPC fixture operator must have an independent identity")
	}
	var operatorBalance hexutil.Big
	if err := call(&operatorBalance, "eth_getBalance", operator, hexutil.EncodeUint64(height)); err != nil || (*big.Int)(&operatorBalance).Sign() != 0 {
		t.Fatal("combined RPC fixture operator must be unfunded", err)
	}
	const password = "combined RPC isolated fixture"
	var imported common.Address
	if err := call(&imported, "personal_importRawKey", hex.EncodeToString(crypto.FromECDSA(operatorKey)), password); err != nil || imported != operator {
		t.Fatal("combined RPC fixture operator import failed", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		var accounts []common.Address
		if err := call(&accounts, "personal_listAccounts"); err != nil {
			t.Fatal(err)
		}
		if len(accounts) == 1 && accounts[0] == operator {
			break
		}
		if len(accounts) > 1 || time.Now().After(deadline) {
			t.Fatal("combined RPC Common operator wallet discovery mismatch")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var ok bool
	if err := call(&ok, "miner_setEtherbase", operator); err != nil || !ok {
		t.Fatal("combined RPC operator selection", err)
	}
	var registered commonrpcreward.Status
	if err := call(&registered, "personal_setCommonRPCRewardAddress", operator, fixture.RewardRecipient, password); err != nil {
		t.Fatal(err)
	}
	if !registered.Configured || registered.Signer != operator || registered.RewardRecipient == nil || *registered.RewardRecipient != fixture.RewardRecipient || registered.GenesisHash != genesis || registered.ChainID == nil || (*big.Int)(registered.ChainID).Cmp(fixture.Genesis.Config.ChainID) != 0 {
		t.Fatal("combined RPC recipient/domain registration mismatch")
	}
	if err := call(&ok, "personal_unlockAccount", operator, password, uint64(0)); err != nil || !ok {
		t.Fatal("combined RPC trusted IPC unlock", err)
	}
	httpStarted, cleaned := false, false
	cleanup := func() error {
		if cleaned {
			return nil
		}
		cleaned = true
		var first error
		if httpStarted {
			if err := call(&ok, "admin_stopRPC"); err != nil || !ok {
				first = fmt.Errorf("combined RPC HTTP stop: %v (ok=%t)", err, ok)
			}
		}
		if err := call(&ok, "personal_lockAccount", operator); err != nil || !ok {
			if first == nil {
				first = fmt.Errorf("combined RPC operator lock: %v (ok=%t)", err, ok)
			}
		}
		return first
	}
	t.Cleanup(func() {
		if !cleaned {
			_ = cleanup()
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	if err := call(&ok, "admin_startRPC", "127.0.0.1", port, "", "eth", "127.0.0.1"); err != nil || !ok {
		t.Fatal("combined RPC loopback HTTP start", err)
	}
	httpStarted = true
	client, err := rpc.DialHTTP(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var coinbase common.Address
	if err := client.Call(&coinbase, "eth_coinbase"); err != nil || coinbase != operator {
		t.Fatal("combined RPC public operator identity", err)
	}
	if err := client.Call(nil, "personal_listAccounts"); err == nil {
		t.Fatal("combined RPC private account API exposed over HTTP")
	}
	t.Logf("NORMAL_COMMON_RPC_DEX_READY index=%d CommonPID=%d DEXSidecarPID=%d height=%d custody=%s operator=%s recipient=%s pow=false rpcReward=true dex=true publicHTTP=eth-only", child.index, p.parent.Process.Pid, p.sidecar.Pid, height, (*big.Int)(&custody), operator.Hex(), fixture.RewardRecipient.Hex())
	used := false
	return func(tx *types.Transaction) (result error) {
		if used {
			return fmt.Errorf("combined RPC fixture permits exactly one relay")
		}
		used = true
		defer func() {
			if err := cleanup(); result == nil && err != nil {
				result = err
			}
		}()
		if err := checkRoles(); err != nil {
			return err
		}
		wire, err := tx.MarshalBinary()
		if err != nil {
			return err
		}
		var hash common.Hash
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = client.CallContext(ctx, &hash, "eth_sendRawTransaction", hexutil.Bytes(wire))
		cancel()
		if err != nil {
			return err
		}
		if hash != tx.Hash() {
			return fmt.Errorf("combined RPC transaction hash mismatch")
		}
		if err := checkRoles(); err != nil {
			return err
		}
		t.Logf("NORMAL_COMMON_RPC_DEX_RELAY index=%d tx=%s pow=false dex=active rpcReward=authenticated HTTP=accepted CLXFinality=checked-by-nativeLedger", child.index, hash.Hex())
		// HTTP acceptance durably owns the admission batch, but TxQUIC signs the
		// transport envelope asynchronously and may sign again for a retry. Keep
		// this fixture's operator unlocked until the separately observed CLX
		// receipt exists. This wait changes only this test coordinator wrapper;
		// the public HTTP API still reports ingress acceptance, not finality.
		receipt := nativeWaitReceipt(t, finalityClient, hash)
		if uint64(receipt.Status) != 1 || receipt.CommonTxApprover != operator || receipt.CommonTxRewardRecipient != fixture.RewardRecipient {
			return fmt.Errorf("combined RPC finalized receipt identity/status mismatch")
		}
		t.Logf("NORMAL_COMMON_RPC_DEX_CONFIRMED index=%d tx=%s CLXHeight=%d HTTP=previously-accepted CLXFinality=observed operatorCleanup=after-receipt", child.index, hash.Hex(), receipt.BlockNumber)
		return nil
	}, operator
}
