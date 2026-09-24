package relay

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

// This is a component integration: signatures, checkpoint proof verification,
// native balances/reservations/nullifier and durable per-member journals are
// real. The CLX source observations and transport are package-local fixtures,
// not ordinary CLX block execution, real leader elections, or a LIVE-network run.
func TestLeaderHandoffLostACKRealNativeClaimAndColdRecovery(t *testing.T) {
	c, _, _ := fixtureConfig(t)
	keys := make([]bls.SecretKey, 7)
	members := make([]*common.Cnode, 7)
	for i := range keys {
		if err := keys[i].SetDecString(fmt.Sprint(19500 + i)); err != nil {
			t.Fatal(err)
		}
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 35000+i), Public: keys[i].GetPublicKey().SerializeToHexStr(), CoinBase: common.Address{19: byte(i + 1)}.Hex()}
	}
	c.Domain.Committee = protocol.Hash((&bftview.Committee{List: members}).RlpHash())
	epoch, err := checkpoint.NewEpoch(c.Domain, 1, 101, members)
	if err != nil {
		t.Fatal(err)
	}
	diskPath := filepath.Join(t.TempDir(), "clx-native-state")
	disk, err := rawdb.NewLevelDBDatabase(diskPath, 16, 16, "leader-native")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if disk != nil {
			disk.Close()
		}
	}()
	db := state.NewDatabase(disk)
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, recipient := common.Address{21}, common.Address{22}
	st.AddBalance(owner, clxUnit(100))
	anchor := checkpoint.FinalizedAnchor{Height: 1, Hash: protocol.Hash{4}}
	adapterConfig := settlement.Config{Devnet: true, Domain: c.Domain, Custody: c.Custody, GenesisRoot: protocol.Hash{8}, Epochs: []*checkpoint.Epoch{epoch}, FinalizedAnchors: []checkpoint.FinalizedAnchor{anchor}, MaxCheckpoints: 100}
	a, err := settlement.NewDevnet(st, adapterConfig)
	if err != nil {
		t.Fatal(err)
	}
	deposit, _ := protocol.AmountFromBig(clxUnit(100))
	withdraw, _ := protocol.AmountFromBig(clxUnit(10))
	if _, err := a.Deposit(owner, deposit, anchor); err != nil {
		t.Fatal(err)
	}
	_, inbox, total, err := a.Inbox(0, 1, anchor)
	if err != nil {
		t.Fatal(err)
	}
	claim := protocol.Claim{Domain: c.Domain, Kind: protocol.Withdrawal, Sequence: 1, ID: protocol.Hash{19}, Owner: [20]byte(owner), Recipient: [20]byte(recipient), Amount: withdraw}
	leaf, _ := claim.Hash()
	claimRoot, _, err := protocol.BuildCountedTree([]protocol.Hash{leaf})
	if err != nil {
		t.Fatal(err)
	}
	finance := protocol.FinanceSummary{Version: 1, Domain: c.Domain, Custody: [20]byte(c.Custody), Sequence: 1, DepositTotal: total, WithdrawalTotal: withdraw}
	cp := protocol.Checkpoint{Version: 1, ProofMode: 1, ChainID: c.Domain.ChainID, Genesis: c.Domain.Genesis, DEXID: c.Domain.DEXID, Epoch: c.Domain.Epoch, Committee: c.Domain.Committee, Sequence: 1, PreRoot: adapterConfig.GenesisRoot, PostRoot: protocol.Hash{7}, FirstBlock: 1, LastBlock: 1, CLXHeight: anchor.Height, CLXHash: anchor.Hash, InboxEnd: 1, InboxRoot: inbox, WithdrawalRoot: claimRoot, WithdrawalTotal: withdraw, DataRoot: protocol.Hash{6}, DataSchema: 2}
	cp.FundingRef, _ = finance.Hash()
	bundleRaw := auditBundle(t, c.Domain, members, keys, cp, finance, claim)
	bundle, err := checkpoint.DecodeSettlementBundle(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Accept(cp, finance, bundle.Proof); err != nil {
		t.Fatal("real five-signer descendant finality proof rejected", err)
	}
	call, err := protocol.EncodeNativeClaim(claim, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	job := Job{Version: 1, Lane: Claim, ID: BusinessID(c.Domain, c.Custody, Claim, leaf), Payload: call, Authorization: bundleRaw, Owner: owner}
	active, view := 0, uint64(1)
	var nodes [2]*LeaderRelay
	var backends [2]*testBackend
	var signers [2]*testSigner
	var configs [2]Config
	var dirs [2]string
	var replay [2]bool
	for member := range nodes {
		config, b, s := fixtureConfig(t)
		config.Domain = c.Domain
		b.obs.anchor.SourceCommittee = protocol.Hash{7}
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		payer := crypto.PubkeyToAddress(key.PublicKey)
		s.keys = map[common.Address]*ecdsa.PrivateKey{payer: key}
		for _, lane := range []Lane{Anchor, Checkpoint, Claim} {
			config.Payers[lane] = payer
		}
		b.obs.nonce = uint64(20 + 30*member)
		b.onSend = func() error {
			var tx types.Transaction
			if err := rlp.DecodeBytes(b.sent[len(b.sent)-1], &tx); err != nil {
				return err
			}
			nativeCall, err := protocol.DecodeNativeCall(tx.Data())
			if err != nil {
				return err
			}
			claim, index, count, siblings, err := protocol.DecodeNativeClaim(nativeCall.Body)
			if err != nil {
				return err
			}
			replay[member], err = a.Claim(claim, index, count, siblings)
			if err != nil {
				return err
			}
			b.obs.nonce++
			if member == 0 {
				active, view = 1, 2
				return errors.New("transport fixture lost ACK after native payment")
			}
			return nil
		}
		dirs[member] = filepath.Join(t.TempDir(), "member")
		configs[member], backends[member], signers[member] = config, b, s
		nodes[member] = openLeaderFixture(t, config, b, s, dirs[member], func(context.Context) (Leadership, error) {
			return Leadership{View: view, Active: active == member}, nil
		})
		defer nodes[member].Close()
		if err := nodes[member].Enqueue(job); err != nil {
			t.Fatal(err)
		}
	}
	if err := leaderStepNow(nodes[0], false); err == nil {
		t.Fatal("missing injected ACK failure")
	}
	if replay[0] || nodes[0].Status()[0].Phase == "complete" {
		t.Fatal("first payment treated as replay or ACK loss locally completed")
	}
	// The successor's last authenticated observation precedes the first payment.
	// A concurrently submitted duplicate must be harmless in canonical accounting,
	// even though this node's local completion cache has not caught up yet.
	if err := leaderStepNow(nodes[1], false); err != nil {
		t.Fatal(err)
	}
	if !replay[1] || st.GetBalance(recipient).Cmp(clxUnit(10)) != 0 || st.GetBalance(c.Custody).Cmp(clxUnit(90)) != 0 {
		t.Fatal("different sender duplicated native payment")
	}
	for member := range nodes {
		backends[member].obs.completed = true
		if err := nodes[member].Close(); err != nil {
			t.Fatal(err)
		}
	}
	root, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TrieDB().Commit(root, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := disk.Close(); err != nil {
		t.Fatal(err)
	}
	disk = nil
	disk, err = rawdb.NewLevelDBDatabase(diskPath, 16, 16, "leader-native")
	if err != nil {
		t.Fatal(err)
	}
	st, err = state.New(root, state.NewDatabase(disk), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err = settlement.NewDevnet(st, adapterConfig)
	if err != nil {
		t.Fatal(err)
	}
	for member := range nodes {
		nodes[member] = openLeaderFixture(t, configs[member], backends[member], signers[member], dirs[member], func(context.Context) (Leadership, error) {
			return Leadership{View: view, Active: active == member}, nil
		})
		defer nodes[member].Close()
		if err := leaderStepNow(nodes[member], true); err != nil {
			t.Fatal(err)
		}
		if nodes[member].PendingWork() || nodes[member].Status()[0].Phase != "complete" {
			t.Fatal("cold authenticated business/nonce reconciliation failed")
		}
	}
	if duplicate, err := a.Claim(claim, 0, 1, nil); err != nil || !duplicate || st.IntermediateRoot(false) != root || st.GetBalance(recipient).Cmp(clxUnit(10)) != 0 {
		t.Fatal("cold native nullifier did not preserve exactly-once payment", err)
	}
	t.Log("HANDOFF_NATIVE component=true signerCount=5 threshold=5/7 memberPayers=2 payerNonces=20,50 recipientCLX=10 custodyCLX=90 duplicateNoPayment=true coldTrieAndJournals=true live=false")
}
