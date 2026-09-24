package reconfig_test

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rpc"
)

// The public RPC block is a projection, not the complete Header hash preimage.
// Compare its required fields with a separately authenticated canonical block;
// never use this observation as finality authority.
type continuousRPCBlock struct {
	Hash        *common.Hash    `json:"hash"`
	Number      *hexutil.Uint64 `json:"number"`
	ParentHash  *common.Hash    `json:"parentHash"`
	Root        *common.Hash    `json:"stateRoot"`
	TxRoot      *common.Hash    `json:"transactionsRoot"`
	ReceiptRoot *common.Hash    `json:"receiptsRoot"`
	GasUsed     *hexutil.Uint64 `json:"gasUsed"`
}

func (p *continuousRPCBlock) matchCanonical(want *types.Block) error {
	if p == nil || want == nil || p.Hash == nil || p.Number == nil || p.ParentHash == nil || p.Root == nil || p.TxRoot == nil || p.ReceiptRoot == nil || p.GasUsed == nil {
		return fmt.Errorf("missing/null canonical RPC projection field: got=%+v", p)
	}
	if *p.Hash != want.Hash() || uint64(*p.Number) != want.NumberU64() || *p.ParentHash != want.ParentHash() || *p.Root != want.Root() || *p.TxRoot != want.TxHash() || *p.ReceiptRoot != want.ReceiptHash() || uint64(*p.GasUsed) != want.GasUsed() {
		return fmt.Errorf("canonical RPC projection mismatch: got height=%d hash=%s parent=%s root=%s tx=%s receipts=%s gas=%d; want height=%d hash=%s parent=%s root=%s tx=%s receipts=%s gas=%d", uint64(*p.Number), p.Hash.Hex(), p.ParentHash.Hex(), p.Root.Hex(), p.TxRoot.Hex(), p.ReceiptRoot.Hex(), uint64(*p.GasUsed), want.NumberU64(), want.Hash().Hex(), want.ParentHash().Hex(), want.Root().Hex(), want.TxHash().Hex(), want.ReceiptHash().Hex(), want.GasUsed())
	}
	return nil
}

func checkContinuousRPCBlock(t *testing.T, client *rpc.Client, want *types.Block) {
	t.Helper()
	var got *continuousRPCBlock
	if err := client.Call(&got, "eth_getBlockByNumber", hexutil.Uint64(want.NumberU64()), false); err != nil {
		t.Fatal("ordinary parent block RPC", err)
	}
	if err := got.matchCanonical(want); err != nil {
		t.Fatal(err)
	}
}

func (f *continuousFixture) parentClient(t *testing.T, c *dexFinancialChild) *rpc.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := rpc.DialIPC(ctx, filepath.Join(filepath.Dir(c.cli.manifestPath), "common.ipc"))
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func (f *continuousFixture) connectParent(t *testing.T, c *dexFinancialChild) {
	t.Helper()
	client := f.parentClient(t, c)
	defer client.Close()
	var added bool
	if err := client.Call(&added, "admin_addPeer", f.source.Stack.Server().Self().URLv4()); err != nil || !added {
		t.Fatal("ordinary parent initial ETH peer", err)
	}
	t.Logf("CONTINUOUS_COMMON_PEER index=%d parentPID=%d initialConnection=true forcedHeadRefresh=false", c.index, c.cli.parent.Process.Pid)
}
func (f *continuousFixture) checkParents(t *testing.T, height uint64) {
	t.Helper()
	target := f.source.Service.BlockChain().GetBlockByNumber(height)
	if target == nil {
		t.Fatal("source lacks parent sync target")
	}
	for _, c := range f.children {
		if c == nil || c.stopped {
			continue
		}
		client := f.parentClient(t, c)
		deadline := time.Now().Add(75 * time.Second)
		var head hexutil.Uint64
		for time.Now().Before(deadline) {
			if err := client.Call(&head, "eth_blockNumber"); err != nil {
				client.Close()
				t.Fatal(err)
			}
			if uint64(head) >= height {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if uint64(head) < height {
			client.Close()
			t.Fatalf("ordinary parent automatic ETH follow deadline node=%d head=%d target=%d", c.index, head, height)
		}
		checkContinuousRPCBlock(t, client, target)
		for _, tx := range f.ledger.base.txs {
			if got, want := nativeWaitReceipt(t, client, tx.Hash()), nativeWaitReceipt(t, f.ledger.base.clients[0], tx.Hash()); !reflect.DeepEqual(got, want) {
				client.Close()
				t.Fatal("ordinary parent receipts mismatch", c.index)
			}
		}
		var mining bool
		if err := client.Call(&mining, "eth_mining"); err != nil || mining {
			client.Close()
			t.Fatal("normal parent unexpectedly mining", err)
		}
		client.Close()
		t.Logf("CONTINUOUS_COMMON_SYNC index=%d height=%d hash=%s root=%s receipts=%d automaticETH=true pow=false", c.index, height, target.Hash().Hex(), target.Root().Hex(), len(f.ledger.base.txs))
	}
}
