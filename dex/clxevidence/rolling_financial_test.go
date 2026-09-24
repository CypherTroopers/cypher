package clxevidence_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
)

func rollingFinancialFixture(t *testing.T, last uint64) (financialFixture, *clxevidence.RollingFinancialFixture) {
	t.Helper()
	chain := clxevidence.RollingFinancialFixtureForTest(t, last)
	return financialExecutionForRollingChain(t, chain), chain
}

func financialExecutionForRollingChain(t *testing.T, chain *clxevidence.RollingFinancialFixture) financialFixture {
	t.Helper()
	members := make([]*common.Cnode, 7)
	recipients := make([][20]byte, 7)
	for i, node := range chain.Config.ChainConfig.DEXDevnet.Committee {
		n := node
		members[i] = &n
		recipients[i] = [20]byte(common.HexToAddress(n.CoinBase))
	}
	domain := protocol.Domain{Version: 1, ChainID: chain.Config.ChainID, Genesis: protocol.Hash(chain.Config.Genesis.Hash()), DEXID: chain.Config.DEXID, Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	var key [32]byte
	key[31] = 41
	oracle, err := crypto.ToECDSA(key[:])
	if err != nil {
		t.Fatal(err)
	}
	config := engine.Config{Domain: domain, Oracle: [20]byte(crypto.PubkeyToAddress(oracle.PublicKey)), Custody: [20]byte(chain.Config.Custody), Support: "0", Insurance: "0", CLXHash: domain.Genesis, NativeInbox: true}
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
	x := &devnet.Execution{Market: market, Registry: registry, Native: &devnet.NativeContext{Seed: seed, Verifier: chain.Verifier, Rolling: true}}
	return financialFixture{execution: x, config: config, clxConfig: chain.Config, oracle: oracle, members: members, recipients: recipients}
}

func cloneRolling(t *testing.T, e clxevidence.RollingEvidence) clxevidence.RollingEvidence {
	t.Helper()
	raw, err := clxevidence.EncodeRollingEvidence(e)
	if err != nil {
		t.Fatal(err)
	}
	out, err := clxevidence.DecodeRollingEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// This test authenticates real codecs, 5/7 BLS signatures, child-QC finality and
// StateDB MPT paths. All keys and headers are unit fixtures, not live processes.
func TestRollingFinancialCreditBeyond257AndColdReplay(t *testing.T) {
	f, chain := rollingFinancialFixture(t, 258)
	x := f.execution
	parent, root, err := x.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	initial, m, err := x.Decode(parent)
	if err != nil || initial.Version != 5 || initial.Anchor != nil || initial.RollingAnchor == nil || initial.Participation == nil || initial.Participation.Version != 2 || len(initial.Participation.Entries) != 0 || m.Total != "0" || x.Schema() != 4 {
		t.Fatal("rolling genesis", err)
	}
	wantRoot, err := protocol.NativeGenesisRootV3(x.Native.Seed, f.config.Domain, f.config.Custody)
	if err != nil || root != wantRoot {
		t.Fatal("rolling genesis root", err)
	}
	oldRoot, _ := protocol.NativeGenesisRoot(x.Native.Seed, f.config.Domain, f.config.Custody)
	if root == oldRoot {
		t.Fatal("rolling genesis aliases legacy sentinel")
	}
	base := *initial.RollingAnchor
	height := uint64(1)
	var participation []byte
	var records []struct {
		Parent, Action, State []byte
		Context               consensus.ExecutionContext
		Root                  protocol.Hash
	}
	apply := func(action []byte) consensus.ExecutionResult {
		t.Helper()
		ctx := consensus.ExecutionContext{Domain: f.config.Domain, Height: height, ParentRoot: root}
		if err := x.AuthenticateAction(action); err != nil {
			t.Fatal("rolling action admission", err)
		}
		before := bytes.Clone(parent)
		result, err := x.Execute(parent, action, ctx)
		if err != nil {
			t.Fatal("rolling financial execute", height, err)
		}
		if !bytes.Equal(parent, before) {
			t.Fatal("financial parent mutated")
		}
		if err := x.Finalized(height, action, result.State); err != nil {
			t.Fatal("finalized replay metadata", err)
		}
		records = append(records, struct {
			Parent, Action, State []byte
			Context               consensus.ExecutionContext
			Root                  protocol.Hash
		}{before, bytes.Clone(action), bytes.Clone(result.State), ctx, result.PostRoot})
		parent, root = result.State, result.PostRoot
		height++
		return result
	}
	for _, target := range []uint64{1, 32, 64, 65, 96, 128, 130, 160, 192, 224, 256, 258, 258} {
		state, market, err := x.Decode(parent)
		if err != nil {
			t.Fatal(err)
		}
		base = *state.RollingAnchor
		include := target == 1 || target == 65 || target == 130 || (target == 258 && base.Height == 258)
		evidence := chain.Evidence(t, base, target, market.InboxCursor, include)
		if target == 65 {
			reject := func(t *testing.T, e clxevidence.RollingEvidence) {
				t.Helper()
				raw, err := devnet.EncodeRollingInboxAction(e)
				if err != nil {
					t.Fatal(err)
				}
				before := bytes.Clone(parent)
				if _, err := x.Execute(parent, raw, consensus.ExecutionContext{Domain: f.config.Domain, Height: height, ParentRoot: root}); err == nil {
					t.Fatal("invalid rolling evidence changed financial state")
				}
				if !bytes.Equal(before, parent) {
					t.Fatal("rejected rolling update mutated parent")
				}
			}
			for _, name := range []string{"base", "signature-same-hash", "unfinalized", "epoch", "account-proof", "count-proof", "amount", "owner", "duplicate-entry"} {
				t.Run(name, func(t *testing.T) {
					bad := cloneRolling(t, evidence)
					switch name {
					case "base":
						bad.Base[0] ^= 1
					case "account-proof":
						bad.AccountProof[0][0] ^= 1
					case "count-proof":
						bad.CountProof[0][0] ^= 1
					case "amount":
						bad.Entries[0].Entry.Amount[31]++
					case "owner":
						bad.Entries[0].Entry.Owner[0]++
					case "duplicate-entry":
						bad.Entries = append(bad.Entries, bad.Entries[0])
					default:
						var header types.Header
						if err := rlp.DecodeBytes(bad.Headers[0].Header, &header); err != nil {
							t.Fatal(err)
						}
						hash := header.Hash()
						if name == "signature-same-hash" {
							header.SignInfo.Signature[0] ^= 1
							if header.Hash() != hash {
								t.Fatal("signature changed header hash")
							}
						}
						if name == "unfinalized" {
							header.SignInfo.FHSFinalityProof = nil
						}
						if name == "epoch" {
							header.KeyHash[0] ^= 1
						}
						bad.Headers[0].Header, err = rlp.EncodeToBytes(&header)
						if err != nil {
							t.Fatal(err)
						}
					}
					reject(t, bad)
				})
			}
		}
		action, err := devnet.EncodeRollingInboxAction(evidence)
		if err != nil {
			t.Fatal("bounded action", target, err)
		}
		priorCursor, priorTotal := market.InboxCursor, market.Total
		result := apply(action)
		state, market, err = x.Decode(result.State)
		if err != nil {
			t.Fatal(err)
		}
		if state.Version != 5 || state.RollingAnchor.Height != target || result.CLXHeight != target || result.CLXHash != protocol.Hash(chain.Blocks[target-1].Hash()) || state.RollingAnchor.InboxCount != uint64(len(chain.Entries[target])) {
			t.Fatal("rolling authenticated anchor lost", target)
		}
		if !include && (market.InboxCursor != priorCursor || market.Total != priorTotal || result.InboxStart != priorCursor || result.InboxEnd != priorCursor || state.Finance.DepositTotal != (protocol.Amount{})) {
			t.Fatal("empty rolling update manufactured funds")
		}
		if len(participation) > 0 {
			got, _ := json.Marshal(state.Participation)
			if !bytes.Equal(got, participation) {
				t.Fatal("anchor update changed committed participation")
			}
		}
		t.Logf("ROLLING_FINANCIAL_UPDATE dexHeight=%d clxHeight=%d witnesses=%d bytes=%d cursor=%d total=%s", height-1, target, len(evidence.Headers), len(action), market.InboxCursor, market.Total)
		if target == 1 {
			oracleAction, err := engine.Sign(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: 1, Kind: engine.Oracle, Price: engine.Amount("1000000000000000000"), FeedSequence: 1, ValidUntil: 100}, f.oracle)
			if err != nil {
				t.Fatal(err)
			}
			apply(oracleAction)
			// Synthetic registered collector receipts are only used to ensure an
			// existing committed set survives inbox updates; no payout is inferred.
			duty := rewards.Duty{Version: 1, Domain: f.config.Domain, Period: 1, Height: 1, View: 1, ProposalID: protocol.Hash{12}, Participant: 0, Recipient: f.recipients[0]}
			var receipts []rewards.Receipt
			for i := 0; i < 5; i++ {
				var key bls.SecretKey
				if err := key.SetDecString(new(big.Int).SetUint64(uint64(1200 + i)).String()); err != nil {
					t.Fatal(err)
				}
				raw, _ := duty.Encode()
				raw = append(raw, byte(i))
				raw = append(raw, key.GetPublicKey().Serialize()...)
				h := protocol.Digest("common-dex/participation-receipt/v1", raw)
				receipt := rewards.Receipt{Duty: duty, Collector: uint8(i)}
				copy(receipt.Signature[:], key.SignHash(h[:]).Serialize())
				receipts = append(receipts, receipt)
			}
			certificate, err := x.Registry.Certificate(receipts)
			if err != nil {
				t.Fatal(err)
			}
			commit, err := devnet.EncodeParticipationAction(engine.Action{Version: 1, Epoch: f.config.Domain.EpochKey(), Owner: f.config.Oracle, Nonce: 2}, f.oracle, []rewards.Certificate{certificate})
			if err != nil {
				t.Fatal(err)
			}
			apply(commit)
			committed, _, err := x.Decode(parent)
			if err != nil {
				t.Fatal(err)
			}
			participation, _ = json.Marshal(committed.Participation)
		}
	}
	final, market, err := x.Decode(parent)
	if err != nil {
		t.Fatal(err)
	}
	trader := market.Accounts[hex.EncodeToString([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})]
	if final.RollingAnchor.Height != 258 || market.InboxCursor != 6 || market.Total != "21" || market.Support != "2" || market.Insurance != "3" || trader == nil || trader.Cash != "16" || market.RewardReserved != "0" {
		t.Fatal("rolling financial conservation", market)
	}
	path := filepath.Join(t.TempDir(), "financial-state.json")
	if err := os.WriteFile(path, parent, 0600); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	coldMarket, err := engine.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	coldRegistry, err := rewards.NewRegistry(f.config.Domain, f.members, f.recipients)
	if err != nil {
		t.Fatal(err)
	}
	coldVerifier, err := clxevidence.New(f.clxConfig)
	if err != nil {
		t.Fatal(err)
	}
	cold := &devnet.Execution{Market: coldMarket, Registry: coldRegistry, Native: &devnet.NativeContext{Seed: x.Native.Seed, Verifier: coldVerifier, Rolling: true}}
	if state, _, err := cold.Decode(stored); err != nil || !reflect.DeepEqual(state, final) {
		t.Fatal("cold financial decode", err)
	}
	for _, record := range records {
		result, err := cold.Execute(record.Parent, record.Action, record.Context)
		if err != nil || result.PostRoot != record.Root || !bytes.Equal(result.State, record.State) {
			t.Fatal("cold deterministic replay", record.Context.Height, err)
		}
	}
	// The already consumed proof cannot authorize a duplicate credit or rollback
	// the anchor, even though all of its original signatures remain valid.
	if _, err := cold.Execute(parent, records[0].Action, consensus.ExecutionContext{Domain: f.config.Domain, Height: height, ParentRoot: root}); err == nil {
		t.Fatal("old rolling proof replayed against new base")
	}
}

func TestRollingFinancialVersionAndActionSeparation(t *testing.T) {
	f, chain := rollingFinancialFixture(t, 1)
	rolling := f.execution
	raw, root, err := rolling.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := rolling.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	evidence := chain.Evidence(t, *state.RollingAnchor, 1, 0, true)
	action, err := devnet.EncodeRollingInboxAction(evidence)
	if err != nil {
		t.Fatal(err)
	}
	old := nativeFixture(t)
	oldRaw, oldRoot, err := old.execution.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	legacyAction, err := devnet.EncodeInboxAction(old.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if old.execution.Schema() != 3 || rolling.Schema() != 4 || old.execution.ID() == rolling.ID() {
		t.Fatal("financial protocol identities collide")
	}
	if _, _, err := old.execution.Decode(raw); err == nil {
		t.Fatal("legacy decoder accepted state5")
	}
	if _, _, err := rolling.Decode(oldRaw); err == nil {
		t.Fatal("rolling decoder accepted legacy state2")
	}
	if err := old.execution.AuthenticateAction(action); err == nil {
		t.Fatal("legacy admission accepted CDXA")
	}
	if err := rolling.AuthenticateAction(legacyAction); err == nil {
		t.Fatal("rolling admission accepted CDXI")
	}
	if _, err := old.execution.Execute(oldRaw, action, consensus.ExecutionContext{Domain: old.config.Domain, Height: 1, ParentRoot: oldRoot}); err == nil {
		t.Fatal("legacy execution accepted CDXA")
	}
	if _, err := rolling.Execute(raw, legacyAction, consensus.ExecutionContext{Domain: f.config.Domain, Height: 1, ParentRoot: root}); err == nil {
		t.Fatal("rolling execution accepted CDXI")
	}
	for _, version := range []uint16{1, 2, 3, 4} {
		changed := *state
		changed.Version = version
		encoded, err := changed.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rolling.Decode(encoded); err == nil {
			t.Fatal("legacy state version reinterpreted", version)
		}
		h, _ := changed.Root()
		newHash, _ := state.Root()
		if h == newHash {
			t.Fatal("state root version domains collided", version)
		}
	}
	for _, mutate := range []func(*clxevidence.Anchor){func(a *clxevidence.Anchor) { a.SourceEpoch++ }, func(a *clxevidence.Anchor) { a.SourceCommittee[0] ^= 1 }, func(a *clxevidence.Anchor) { a.Custody[0] ^= 1 }, func(a *clxevidence.Anchor) { a.Genesis[0] ^= 1 }} {
		changed := *state
		anchor := *state.RollingAnchor
		mutate(&anchor)
		changed.RollingAnchor = &anchor
		encoded, err := changed.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rolling.Decode(encoded); err == nil {
			t.Fatal("cold decoder accepted foreign anchor identity")
		}
	}
}
