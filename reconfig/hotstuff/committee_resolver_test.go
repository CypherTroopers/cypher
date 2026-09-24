package hotstuff

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
)

type resolverTestApp struct {
	*fhsFutureJumpApp
	committee  *bftview.Committee
	resolveErr error
	returnNil  bool
}

func (a *resolverTestApp) ResolveHotstuffCommittee(number uint64, hash common.Hash, _ bool) (*bftview.Committee, error) {
	if a.resolveErr != nil {
		return nil, a.resolveErr
	}
	if a.returnNil {
		return nil, nil
	}
	if number != a.keyNumber || hash != a.keyHash {
		return nil, errors.New("unknown application epoch")
	}
	return a.committee, nil
}

type resolverFixture struct {
	app     *resolverTestApp
	manager *HotstuffProtocolManager
	secrets []bls.SecretKey
	keys    []*bls.PublicKey
	context FHSViewContext
}

func newResolverFixture(t *testing.T, domain int) *resolverFixture {
	t.Helper()
	secrets := make([]bls.SecretKey, 7)
	keys := make([]*bls.PublicKey, 7)
	committee := &bftview.Committee{List: make([]*common.Cnode, 7)}
	for i := range secrets {
		if err := secrets[i].SetDecString(fmt.Sprint(1000 + domain*10 + i)); err != nil {
			t.Fatal(err)
		}
		keys[i] = secrets[i].GetPublicKey()
		committee.List[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 17000+domain*10+i), Public: keys[i].SerializeToHexStr(), CoinBase: fmt.Sprintf("devnet-recipient-%d-%d", domain, i)}
	}
	keyHash := hotstuffDigestHash([]byte(fmt.Sprintf("isolated-domain-%d-epoch-1", domain)))
	app := &resolverTestApp{
		fhsFutureJumpApp: &fhsFutureJumpApp{
			recoveryTestApp: &recoveryTestApp{self: committee.List[0].Address, fhs: true, publicKeysByHash: map[common.Hash][]*bls.PublicKey{keyHash: keys}},
			current:         7, keyNumber: 1, keyHash: keyHash, committeeHash: committee.RlpHash(), leaderID: committee.List[0].Address,
		},
		committee: committee,
	}
	ctx := FHSViewContext{Version: fhsWireVersion, ChainID: app.ChainID(), TargetView: 8, KeyNumber: 1, KeyHash: keyHash, CommitteeHash: committee.RlpHash(), LeaderID: app.leaderID, EntryKind: FHSViewFromQC}
	return &resolverFixture{app: app, manager: NewHotstuffProtocolManager(app, &secrets[0], keys[0]), secrets: secrets, keys: keys, context: ctx}
}

func installResolverGlobalFixture(t *testing.T, fixture *resolverFixture) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	bftview.SetCommitteeConfig(db, nil, nil)
	if !bftview.WriteCommittee(fixture.app.keyNumber, fixture.app.keyHash, fixture.app.committee) {
		t.Fatal("write global CLX fixture")
	}
	oldAddress, oldPublic, oldCoinbase := bftview.GetServerAddress(), bftview.GetServerInfo(bftview.PublicKey), bftview.GetServerCoinBase()
	bftview.SetServerInfo("clx-global-identity", "clx-global-public")
	bftview.SetServerCoinBase(common.HexToAddress("0xc1"))
	t.Cleanup(func() {
		bftview.SetServerInfo(oldAddress, oldPublic)
		bftview.SetServerCoinBase(oldCoinbase)
		bftview.SetCommitteeConfig(nil, nil, nil)
		db.Close()
	})
}

func resolverQC(t *testing.T, f *resolverFixture) *SignedState {
	t.Helper()
	viewID := hotstuffDigestHash([]byte("resolver-qc-view"), f.app.keyHash[:])
	ref := &types.HotstuffProposalRef{
		Version: types.HotstuffProposalRefVersion, ChainID: f.app.ChainID(), Number: 4,
		ViewNumber: 7, ViewID: viewID, LeaderID: f.app.leaderID, KeyHash: f.app.keyHash,
		BlockHash: hotstuffDigestHash([]byte("block"), f.app.keyHash[:]), ParentHash: common.HexToHash("0x123"),
		BodyHash: common.HexToHash("0x456"), BodySize: 1, ExtraHash: types.HotstuffProposalExtraHash(nil),
	}
	state := ref.EncodeToBytes()
	return &SignedState{State: state, Sign: aggregateContextSignatures(t, f.secrets, []int{0, 1, 2, 3, 4}, f.app.ChainID(), MsgVotePrepare, viewID, f.app.leaderID, state), Mask: []byte{0x1f}, ViewID: viewID, LeaderID: f.app.leaderID, Number: 7}
}

func TestInstanceCommitteeResolverSeparatesTwoDEXAndCLX(t *testing.T) {
	clx, a, b := newResolverFixture(t, 1), newResolverFixture(t, 2), newResolverFixture(t, 3)
	installResolverGlobalFixture(t, clx)
	legacy := NewHotstuffProtocolManager(clx.app.recoveryTestApp, &clx.secrets[0], clx.keys[0])
	before := bftview.LoadMember(clx.app.keyNumber, clx.app.keyHash, true).RlpHash()
	for _, f := range []*resolverFixture{a, b} {
		committee, keys, err := f.manager.fhsCommittee(&f.context, true)
		if err != nil || committee.RlpHash() != f.context.CommitteeHash || len(keys) != 7 {
			t.Fatalf("own committee rejected: %v", err)
		}
		// Both returned nodes and BLS key objects must be private snapshots.
		committee.List[0].Address = "mutated-result"
		if err := keys[0].Deserialize(clx.keys[0].Serialize()); err != nil {
			t.Fatal(err)
		}
		again, againKeys, err := f.manager.fhsCommittee(&f.context, true)
		if err != nil || again.List[0].Address != f.app.leaderID || !bytes.Equal(againKeys[0].Serialize(), f.keys[0].Serialize()) {
			t.Fatalf("resolver snapshot aliases app state: %v", err)
		}
		state, _, _ := f.app.CurrentState()
		if _, err := f.manager.createFHSView(false, PhasePrepare, &f.context, state); err != nil {
			t.Fatalf("independent view initialization: %v", err)
		}
		if err := f.manager.verifyFHSParentQC(resolverQC(t, f), 8); err != nil {
			t.Fatalf("own parent QC rejected: %v", err)
		}
	}
	for _, pair := range [][2]*resolverFixture{{a, b}, {b, a}, {a, clx}, {b, clx}} {
		if _, _, err := pair[0].manager.fhsCommittee(&pair[1].context, true); err == nil {
			t.Fatal("foreign domain committee accepted")
		}
		if err := pair[0].manager.verifyFHSParentQC(resolverQC(t, pair[1]), 8); err == nil {
			t.Fatal("foreign domain QC accepted")
		}
	}
	if _, _, err := legacy.fhsCommittee(&clx.context, true); err != nil {
		t.Fatalf("legacy CLX fallback changed: %v", err)
	}
	for _, foreign := range []*resolverFixture{a, b} {
		if err := legacy.verifyFHSParentQC(resolverQC(t, foreign), 8); err == nil {
			t.Fatal("DEX QC accepted by CLX app")
		}
	}
	if bftview.GetServerAddress() != "clx-global-identity" || bftview.GetServerInfo(bftview.PublicKey) != "clx-global-public" || bftview.GetServerCoinBase() != common.HexToAddress("0xc1") || bftview.LoadMember(clx.app.keyNumber, clx.app.keyHash, true).RlpHash() != before {
		t.Fatal("DEX changed global CLX committee/identity/coinbase")
	}
}

func TestInstanceCommitteeResolverNeverFallsBack(t *testing.T) {
	clx := newResolverFixture(t, 4)
	installResolverGlobalFixture(t, clx)
	for _, mode := range []string{"error", "nil", "unknown-epoch"} {
		t.Run(mode, func(t *testing.T) {
			app := *clx.app
			switch mode {
			case "error":
				app.resolveErr = errors.New("registry unavailable")
			case "nil":
				app.returnNil = true
			case "unknown-epoch":
				base := *app.fhsFutureJumpApp
				base.keyNumber++
				app.fhsFutureJumpApp = &base
			}
			manager := NewHotstuffProtocolManager(&app, &clx.secrets[0], clx.keys[0])
			if _, _, err := manager.fhsCommittee(&clx.context, true); err == nil {
				t.Fatal("provider failure fell back to valid global entry")
			}
			view := &View{currentState: (&bftview.View{KeyNumber: clx.app.keyNumber, KeyHash: clx.app.keyHash, CommitteeHash: clx.context.CommitteeHash}).EncodeConsensusToBytes()}
			if err := manager.initViewCommittee(view); err == nil {
				t.Fatal("view initialization bypassed resolver failure")
			}
		})
	}
}

func TestInstanceCommitteeResolverRejectsMalformedRegistry(t *testing.T) {
	mutations := map[string]func(*resolverFixture){
		"bad-commitment": func(f *resolverFixture) { f.context.CommitteeHash[0] ^= 1 },
		"nil-member":     func(f *resolverFixture) { f.app.committee.List[1] = nil },
		"nil-key":        func(f *resolverFixture) { f.keys[1] = nil },
		"short-keys":     func(f *resolverFixture) { f.app.publicKeysByHash[f.app.keyHash] = f.keys[:6] },
		"invalid-size":   func(f *resolverFixture) { f.app.committee.List = f.app.committee.List[:6] },
		"reordered-keys": func(f *resolverFixture) { f.keys[0], f.keys[1] = f.keys[1], f.keys[0] },
		"duplicate-id":   func(f *resolverFixture) { f.app.committee.List[1].Address = f.app.committee.List[0].Address },
		"empty-id":       func(f *resolverFixture) { f.app.committee.List[1].Address = "" },
		"bad-key-hex":    func(f *resolverFixture) { f.app.committee.List[1].Public = "not-hex" },
		"empty-key":      func(f *resolverFixture) { f.app.committee.List[1].Public = "" },
		"duplicate-key": func(f *resolverFixture) {
			f.keys[1] = f.keys[0]
			f.app.committee.List[1].Public = f.app.committee.List[0].Public
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newResolverFixture(t, 5)
			mutate(f)
			if _, _, err := f.manager.fhsCommittee(&f.context, true); err == nil {
				t.Fatal("malformed registry accepted")
			}
		})
	}
}

func TestInstanceCommitteeResolverBindsQCAndTimeoutDomains(t *testing.T) {
	f := newResolverFixture(t, 6)
	qc := resolverQC(t, f)
	for _, field := range []string{"chain", "epoch", "view", "payload", "signature"} {
		t.Run(field, func(t *testing.T) {
			bad := CloneSignedState(qc)
			ref, err := types.DecodeHotstuffProposalRef(bad.State)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "chain":
				ref.ChainID++
			case "epoch":
				ref.KeyHash[0] ^= 1
			case "view":
				ref.ViewID[0] ^= 1
			case "payload":
				ref.StateRoot[0] ^= 1
			case "signature":
				bad.Sign[0] ^= 1
			}
			bad.State = ref.EncodeToBytes()
			if err := f.manager.verifyFHSParentQC(bad, 8); err == nil {
				t.Fatal("altered QC accepted")
			}
		})
	}
	statement := &TimeoutStatement{Version: fhsWireVersion, ChainID: f.app.ChainID(), TimedOutView: 8, KeyNumber: 1, KeyHash: f.app.keyHash, CommitteeHash: f.context.CommitteeHash}
	digest, err := TimeoutStatementDigest(statement)
	if err != nil {
		t.Fatal(err)
	}
	votes := make(map[int]*bls.Sign)
	for i := 0; i < 5; i++ {
		votes[i] = signFHSAugmented(t, &f.secrets[i], f.keys[i], digest)
	}
	tc, err := buildTimeoutCertificate(statement, votes, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeoutCertificate(tc, f.keys, 5); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TimeoutStatement){
		func(s *TimeoutStatement) { s.ChainID++ },
		func(s *TimeoutStatement) { s.KeyHash[0] ^= 1 },
		func(s *TimeoutStatement) { s.KeyNumber++ },
		func(s *TimeoutStatement) { s.CommitteeHash[0] ^= 1 },
		func(s *TimeoutStatement) { s.TimedOutView++ },
	} {
		bad := CloneTimeoutCertificate(tc)
		mutate(&bad.Statement)
		if err := VerifyTimeoutCertificate(bad, f.keys, 5); err == nil {
			t.Fatal("timeout replay across context accepted")
		}
	}
}
