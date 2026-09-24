package clxevidence_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type financialFixture struct {
	execution  *devnet.Execution
	config     engine.Config
	clxConfig  clxevidence.Config
	evidence   clxevidence.RangeEvidence
	oracle     *ecdsa.PrivateKey
	members    []*common.Cnode
	recipients [][20]byte
}

func nativeFixture(t *testing.T) financialFixture {
	t.Helper()
	c, verifier, evidence := clxevidence.EvidenceFixtureForTest(t)
	members := make([]*common.Cnode, 7)
	recipients := make([][20]byte, 7)
	for i, n := range c.Epochs[0].Members {
		copyNode := *n
		recipients[i][19] = byte(i + 1)
		copyNode.CoinBase = common.Address(recipients[i]).Hex()
		members[i] = &copyNode
	}
	domain := protocol.Domain{Version: 1, ChainID: c.ChainID, Genesis: protocol.Hash(c.Genesis.Hash()), DEXID: c.DEXID, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	var raw [32]byte
	raw[31] = 41
	oracle, err := crypto.ToECDSA(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	config := engine.Config{Domain: domain, Oracle: [20]byte(crypto.PubkeyToAddress(oracle.PublicKey)), Custody: [20]byte(c.Custody), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true}
	market, err := engine.New(config)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := protocol.NativeMarketSeed(config.Oracle)
	if err != nil {
		t.Fatal(err)
	}
	x := &devnet.Execution{Market: market, Registry: registry, Native: &devnet.NativeContext{Seed: seed, Verifier: verifier}}
	return financialFixture{x, config, c, evidence, oracle, members, recipients}
}

func cloneEvidence(t *testing.T, e clxevidence.RangeEvidence) clxevidence.RangeEvidence {
	t.Helper()
	raw, err := clxevidence.EncodeRangeEvidence(e)
	if err != nil {
		t.Fatal(err)
	}
	e, err = clxevidence.DecodeRangeEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func signedOracle(t *testing.T, f financialFixture, kind uint8, nonce uint64) []byte {
	t.Helper()
	raw, err := engine.Sign(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Kind: kind, Owner: f.config.Oracle, Nonce: nonce}, f.oracle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// This joins the real CLX block/QC and StateDB proof codecs to financial credit.
// The evidence is unit-signed. The process-produced CLX TX/finality gate is
// deliberately separate and cannot be inferred from this test passing.
func TestNativeFinancialProofDrivenCredit(t *testing.T) {
	f := nativeFixture(t)
	x := f.execution
	parent, root, err := x.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	initial, market, err := x.Decode(parent)
	if err != nil || initial.Version != 2 || initial.Anchor != nil || market.Total != "0" || market.Support != "0" || market.Insurance != "0" || market.InboxCursor != 0 {
		t.Fatal("native genesis was not empty", err)
	}
	wantRoot, _ := protocol.NativeGenesisRoot(x.Native.Seed, f.config.Domain, f.config.Custody)
	if root != wantRoot || x.Schema() != 3 {
		t.Fatal("native genesis/schema mismatch")
	}
	ctx := consensus.ExecutionContext{Domain: f.config.Domain, Height: 1, ParentRoot: root}
	reject := func(t *testing.T, state, action []byte, context consensus.ExecutionContext) {
		t.Helper()
		before := append([]byte(nil), state...)
		if _, err := x.Execute(state, action, context); err == nil {
			t.Fatal("untrusted credit accepted")
		}
		if !bytes.Equal(state, before) {
			t.Fatal("rejected credit mutated its parent")
		}
	}
	t.Run("unproved_signed_credit", func(t *testing.T) { reject(t, parent, signedOracle(t, f, engine.Credit, 1), ctx) })
	t.Run("ordinary_action_before_authenticated_anchor", func(t *testing.T) { reject(t, parent, signedOracle(t, f, engine.Noop, 1), ctx) })
	t.Run("malformed", func(t *testing.T) { reject(t, parent, []byte("CDXI\xff"), ctx) })
	for _, name := range []string{"unfinalized", "same_hash_sign_info", "changed_amount", "changed_owner"} {
		t.Run(name, func(t *testing.T) {
			e := cloneEvidence(t, f.evidence)
			switch name {
			case "unfinalized":
				b := types.DecodeToBlock(e.Blocks[0])
				if err := b.SetFHSFinalityProof(nil); err != nil {
					t.Fatal(err)
				}
				e.Blocks[0] = b.EncodeToBytes()
			case "same_hash_sign_info":
				b := types.DecodeToBlock(e.Blocks[0])
				old := b.Hash()
				b.SignInfo().Signature[0] ^= 1
				if b.Hash() != old {
					t.Fatal("hash changed")
				}
				e.Blocks[0] = b.EncodeToBytes()
			case "changed_amount":
				e.Entries[0].Entry.Amount[31]++
			case "changed_owner":
				e.Entries[0].Entry.Owner[0]++
			}
			action, err := devnet.EncodeInboxAction(e)
			if err != nil {
				t.Fatal(err)
			}
			reject(t, parent, action, ctx)
		})
	}
	action, err := devnet.EncodeInboxAction(f.evidence)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), parent...)
	result, err := x.Execute(parent, action, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parent, before) {
		t.Fatal("successful credit changed parent")
	}
	state, market, err := x.Decode(result.State)
	if err != nil {
		t.Fatal(err)
	}
	owner := f.evidence.Entries[0].Entry.Owner
	trader := market.Accounts[hex.EncodeToString(owner[:])]
	if market.Total != "6" || market.Support != "2" || market.Insurance != "3" || trader == nil || trader.Cash != "1" || trader.Nonce != 0 || market.InboxCursor != 3 || state.Finance.DepositTotal.Big().String() != "1" {
		t.Fatal("bucket conservation/nonces", market, state.Finance)
	}
	anchor := types.DecodeToBlock(f.evidence.Blocks[0])
	if state.Anchor == nil || state.Anchor.Height != 1 || state.Anchor.Hash != protocol.Hash(anchor.Hash()) || result.CLXHash != state.Anchor.Hash || result.CLXHeight != 1 || result.InboxStart != 0 || result.InboxEnd != 3 {
		t.Fatal("authenticated anchor/range lost")
	}
	next := consensus.ExecutionContext{Domain: f.config.Domain, Height: 2, ParentRoot: result.PostRoot}
	t.Run("duplicate", func(t *testing.T) { reject(t, result.State, action, next) })
	ordinary, err := x.Execute(result.State, signedOracle(t, f, engine.Noop, 1), next)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.CLXHash != result.CLXHash || ordinary.CLXHeight != result.CLXHeight {
		t.Fatal("ordinary action replaced authenticated anchor")
	}
	empty := cloneEvidence(t, f.evidence)
	empty.Entries = nil
	emptyAction, err := devnet.EncodeInboxAction(empty)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := x.Execute(ordinary.State, emptyAction, consensus.ExecutionContext{Domain: f.config.Domain, Height: 3, ParentRoot: ordinary.PostRoot})
	if err != nil {
		t.Fatal(err)
	}
	rstate, refreshedMarket, err := x.Decode(refreshed.State)
	if err != nil || refreshedMarket.Total != "6" || refreshedMarket.InboxCursor != 3 || refreshed.InboxStart != 3 || refreshed.InboxEnd != 3 || rstate.Finance.DepositTotal != (protocol.Amount{}) || refreshed.CLXHash != result.CLXHash {
		t.Fatal("empty range changed funds/cursor", err)
	}
	if err := x.Finalized(3, emptyAction, refreshed.State); err != nil {
		t.Fatal(err)
	}
}

func TestNativeGenesisConfigurationAndCapabilityGuards(t *testing.T) {
	f := nativeFixture(t)
	x := f.execution
	bad := *x
	context := *x.Native
	context.Seed[0] ^= 1
	bad.Native = &context
	if _, _, err := bad.Genesis(); err == nil {
		t.Fatal("unbound native market seed")
	}
	changed := f.config
	changed.Oracle[0] ^= 1
	market, err := engine.New(changed)
	if err != nil {
		t.Fatal(err)
	}
	bad = *x
	bad.Market = market
	if _, _, err := bad.Genesis(); err == nil {
		t.Fatal("changed oracle reused genesis sentinel")
	}
	recipients := append([][20]byte(nil), f.recipients...)
	recipients[0][0] ^= 1
	registry, err := rewards.NewRegistry(f.config.Domain, f.members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	bad = *x
	bad.Registry = registry
	if _, _, err := bad.Genesis(); err == nil {
		t.Fatal("unbound native reward recipient")
	}
	legacy := f.config
	legacy.NativeInbox = false
	legacyEmpty, err := engine.New(legacy)
	if err != nil {
		t.Fatal(err)
	}
	bad = *x
	bad.Market = legacyEmpty
	if _, _, err := bad.Genesis(); err == nil {
		t.Fatal("native execution accepted legacy credit mode")
	}
	foreignDomain := f.config.Domain
	foreignDomain.DEXID[0] ^= 1
	foreignRegistry, err := rewards.NewRegistry(foreignDomain, f.members, f.recipients)
	if err != nil {
		t.Fatal(err)
	}
	bad = *x
	bad.Registry = foreignRegistry
	if _, _, err := bad.Genesis(); err == nil {
		t.Fatal("native execution accepted foreign reward domain")
	}
	legacy.Support = "2"
	legacy.Insurance = "3"
	legacyMarket, err := engine.New(legacy)
	if err != nil {
		t.Fatal(err)
	}
	old := devnet.Execution{Market: legacyMarket, Registry: registry}
	if _, _, err := old.Genesis(); err != nil || old.Schema() != 2 {
		t.Fatal("legacy fixture altered", err)
	}
	for _, funded := range []engine.Config{func() engine.Config { c := f.config; c.Support = "1"; return c }(), func() engine.Config { c := f.config; c.Insurance = "1"; return c }()} {
		if _, err := engine.New(funded); err == nil {
			t.Fatal("native genesis accepted fabricated funding")
		}
	}
	parent, err := x.Market.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range []*clxevidence.VerifiedRange{nil, new(clxevidence.VerifiedRange)} {
		if _, _, err := x.Market.ApplyInbox(parent, capability, 1); err == nil {
			t.Fatal("unverified capability")
		}
	}
	foreign := f.clxConfig
	foreign.DEXID[0] ^= 1
	v, err := clxevidence.New(foreign)
	if err != nil {
		t.Fatal(err)
	}
	empty := cloneEvidence(t, f.evidence)
	empty.Entries = nil
	verified, err := v.VerifyRange(0, empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.Market.ApplyInbox(parent, verified, 1); err == nil {
		t.Fatal("foreign empty evidence capability")
	}
	valid, err := x.Native.Verifier.VerifyRange(0, f.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.Market.ApplyInbox(nil, valid, 1); err == nil {
		t.Fatal("nil financial parent")
	}
	if _, _, err := x.Market.ApplyInbox(parent, valid, 2); err == nil {
		t.Fatal("skipped DEX height")
	}
}
