package devnet

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

func benign(err error) bool {
	if err == nil {
		return true
	}
	for _, e := range []error{hotstuff.ErrInsufficientQC, hotstuff.ErrProposalValidationPending, hotstuff.ErrUnhandledMsg, hotstuff.ErrOldState, hotstuff.ErrMissingView, hotstuff.ErrViewOldPhase, hotstuff.ErrFutureState} {
		if errors.Is(err, e) {
			return true
		}
	}
	return strings.Contains(err.Error(), "fixture height limit") || strings.Contains(err.Error(), "participation commit data pending")
}
func TestNativeCLXFinancialFHSScenario(t *testing.T) {
	// All native balances are allocated by a new in-memory devnet genesis. No
	// operational wallet, genesis, node or transaction endpoint is consulted.
	var userKeys [4]*ecdsa.PrivateKey
	var owners [4][20]byte
	for i := range userKeys {
		raw := make([]byte, 32)
		raw[31] = byte(41 + i)
		var err error
		userKeys[i], err = crypto.ToECDSA(raw)
		if err != nil {
			t.Fatal(err)
		}
		owners[i] = [20]byte(crypto.PubkeyToAddress(userKeys[i].PublicKey))
	}
	var voteKeys [7]bls.SecretKey
	members := make([]*common.Cnode, 7)
	recipients := make([][20]byte, 7)
	for i := range voteKeys {
		if err := voteKeys[i].SetDecString(fmt.Sprint(500 + i)); err != nil {
			t.Fatal(err)
		}
		recipients[i][19] = byte(100 + i)
		members[i] = &common.Cnode{Address: fmt.Sprintf("127.0.0.1:%d", 31000+i), CoinBase: common.Address(recipients[i]).Hex(), Public: voteKeys[i].GetPublicKey().SerializeToHexStr()}
	}
	nativeDB := rawdb.NewMemoryDatabase()
	defer nativeDB.Close()
	chainConfig := *params.AllcolossusXProtocolChanges
	chainConfig.ChainID = big.NewInt(10101919)
	g := core.Genesis{Config: &chainConfig, Alloc: core.GenesisAlloc{common.Address(owners[1]): {Balance: engine.Amount("100000000000000000000").Big()}, common.Address(owners[2]): {Balance: engine.Amount("100000000000000000000").Big()}, common.Address(owners[0]): {Balance: engine.Amount("25000000000000000000").Big()}}}
	genesis := g.ToBlock(nativeDB)
	st, err := state.New(genesis.Root(), state.NewDatabase(nativeDB), nil)
	if err != nil {
		t.Fatal(err)
	}
	domain := protocol.Domain{Version: 1, ChainID: 10101919, Genesis: protocol.Hash(genesis.Hash()), DEXID: protocol.Digest("isolated-devnet", []byte(t.Name())), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: members}).RlpHash())}
	anchor := checkpoint.FinalizedAnchor{Height: 0, Hash: domain.Genesis}
	custody := common.Address{19: 240}
	expectedDeposits := []protocol.Deposit{{Version: 1, Domain: domain, Custody: [20]byte(custody), ID: 0, Owner: owners[1], Amount: engine.Amount("100000000000000000000"), CLXHash: anchor.Hash}, {Version: 1, Domain: domain, Custody: [20]byte(custody), ID: 1, Owner: owners[2], Amount: engine.Amount("100000000000000000000"), CLXHash: anchor.Hash}}
	market, err := engine.New(engine.Config{Domain: domain, Custody: [20]byte(custody), Oracle: owners[0], Deposits: expectedDeposits, Support: "20000000000000000000", Insurance: "5000000000000000000", CLXHash: anchor.Hash})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := rewards.NewRegistry(domain, members, recipients)
	if err != nil {
		t.Fatal(err)
	}
	base := &Execution{Market: market, Registry: registry}
	_, root, err := base.Genesis()
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := checkpoint.NewEpoch(domain, 1, 128, members)
	if err != nil {
		t.Fatal(err)
	}
	nativeConfig := settlement.Config{Devnet: true, Custody: custody, Domain: domain, GenesisRoot: root, Epochs: []*checkpoint.Epoch{epoch}, FinalizedAnchors: []checkpoint.FinalizedAnchor{anchor}, MaxCheckpoints: 127}
	native, err := settlement.NewDevnet(st, nativeConfig)
	if err != nil {
		t.Fatal(err)
	}
	for i, dep := range expectedDeposits {
		actual, err := native.Deposit(common.Address(owners[i+1]), dep.Amount, anchor)
		if err != nil || actual != dep {
			t.Fatalf("native deposit %d mismatch: %v", i, err)
		}
	}
	if err := native.FundPool(settlement.Support, common.Address(owners[0]), engine.Amount("20000000000000000000")); err != nil {
		t.Fatal(err)
	}
	if err := native.FundPool(settlement.Insurance, common.Address(owners[0]), engine.Amount("5000000000000000000")); err != nil {
		t.Fatal(err)
	}
	verifiedDeposits, _, _, err := native.Inbox(0, 2, anchor)
	if err != nil || len(verifiedDeposits) != 2 {
		t.Fatalf("authenticated inbox: %v", err)
	}
	for i := range expectedDeposits {
		if expectedDeposits[i] != verifiedDeposits[i] {
			t.Fatal("fixture expectation differs from native finalized inbox")
		}
	}
	if st.GetBalance(custody).Cmp(engine.Amount("225000000000000000000").Big()) != 0 || st.GetBalance(common.Address(owners[1])).Sign() != 0 {
		t.Fatal("native custody double spend")
	}

	rootDir := t.TempDir()
	apps := make([]*consensus.Application, 7)
	collectors := make([]*rewards.Collector, 7)
	executions := make([]*Execution, 7)
	configs := make([]consensus.Config, 7)
	type envelope struct {
		to      string
		message *hotstuff.HotstuffMessage
	}
	var queue []envelope
	type observed struct {
		ref  []byte
		vote *hotstuff.HotstuffMessage
	}
	pending := map[int]observed{}
	certificates := map[int]rewards.Certificate{}
	cleanup := func() {
		for _, a := range apps {
			if a != nil {
				_ = a.Close()
			}
		}
		for _, c := range collectors {
			if c != nil {
				_ = c.Shutdown()
			}
		}
	}
	defer cleanup()
	actions := map[uint64][]byte{}
	nonces := [4]uint64{}
	buildAction := func(height uint64, who int, kind uint8, modify func(*engine.Action)) {
		nonces[who]++
		a := engine.Action{Version: 1, Epoch: domain.EpochKey(), Kind: kind, Owner: owners[who], Nonce: nonces[who]}
		if modify != nil {
			modify(&a)
		}
		raw, err := engine.Sign(a, userKeys[who])
		if err != nil {
			t.Fatal(err)
		}
		actions[height] = raw
	}
	buildAction(1, 1, engine.Credit, func(a *engine.Action) { a.DepositID = 0 })
	buildAction(2, 2, engine.Credit, func(a *engine.Action) { a.DepositID = 1 })
	buildAction(3, 0, engine.Oracle, func(a *engine.Action) {
		a.Price = engine.Amount("100000000000000000000")
		a.FeedSequence = 1
		a.FundingRate = 100
		a.ValidUntil = 100
	})
	order := func(oid uint64, side int8, p string) func(*engine.Action) {
		return func(a *engine.Action) {
			a.OrderID = oid
			a.Side = side
			a.Price = engine.Amount(p)
			a.Quantity = 100000000
		}
	}
	buildAction(4, 2, engine.Place, order(1, -1, "100000000000000000000"))
	buildAction(5, 1, engine.Place, order(1, 1, "100000000000000000000"))
	for h := uint64(6); h <= 9; h++ {
		buildAction(h, 0, engine.Noop, nil)
	}
	buildAction(10, 0, engine.Funding, nil)
	buildAction(11, 0, engine.Oracle, func(a *engine.Action) {
		a.Price = engine.Amount("110000000000000000000")
		a.FeedSequence = 2
		a.FundingRate = 100
		a.ValidUntil = 100
	})
	buildAction(12, 1, engine.Place, order(2, -1, "110000000000000000000"))
	buildAction(13, 2, engine.Place, order(2, 1, "110000000000000000000"))
	buildAction(14, 1, engine.Withdraw, func(a *engine.Action) { a.Amount = engine.Amount("10000000000000000000"); a.Recipient = owners[3] })
	for h := uint64(15); h <= 17; h++ {
		buildAction(h, 0, engine.Noop, nil)
	}
	closeNonce := nonces[0] + 1
	nonces[0]++
	buildAction(19, 0, engine.Noop, nil)
	source := func(height uint64) ([]byte, error) {
		if height == 6 && !bytes.HasPrefix(actions[height], []byte("CDXP")) {
			if len(certificates) != 7 {
				return nil, errors.New("participation commit data pending")
			}
			command, err := engine.Decode(actions[height])
			if err != nil {
				return nil, err
			}
			var set []rewards.Certificate
			for i := 0; i < 7; i++ {
				set = append(set, certificates[i])
			}
			actions[height], err = EncodeParticipationAction(command, userKeys[0], set)
			if err != nil {
				return nil, err
			}
		}
		if raw, ok := actions[height]; ok {
			return append([]byte(nil), raw...), nil
		}
		if height != 18 {
			return nil, errors.New("unknown financial action")
		}
		if len(certificates) != 7 {
			return nil, fmt.Errorf("expected 7 independently receipted participants, got %d", len(certificates))
		}
		pkg := rewards.ClosePackage{Period: 1}
		for h := uint64(1); h <= 14; h++ {
			if h > 10 && h != 14 {
				continue
			}
			var cp protocol.Checkpoint
			var proof []byte
			var err error
			for _, app := range apps {
				if app != nil && app.FinalizedHeight() >= h {
					cp, proof, err = app.FinalizedCheckpoint(h)
					break
				}
			}
			if err != nil || len(proof) == 0 {
				return nil, fmt.Errorf("missing finalized reward witness %d", h)
			}
			pkg.Blocks = append(pkg.Blocks, rewards.FinalizedBlock{Checkpoint: cp, Proof: proof})
		}
		for i := 0; i < 7; i++ {
			pkg.Certificates = append(pkg.Certificates, certificates[i])
		}
		command := engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: owners[0], Nonce: closeNonce}
		raw, err := EncodeRewardAction(command, userKeys[0], pkg)
		if err != nil {
			return nil, err
		}
		actions[height] = raw
		return append([]byte(nil), raw...), nil
	}
	for i := range apps {
		collector, err := rewards.OpenCollector(filepath.Join(rootDir, fmt.Sprint("participation-", i)), registry, uint8(i), &voteKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		collectors[i] = collector
		executions[i] = &Execution{Market: market, Registry: registry, Collector: collector}
		index := i
		configs[i] = consensus.Config{Domain: domain, Members: members, Index: i, Secret: &voteKeys[i], DataDir: filepath.Join(rootDir, fmt.Sprint("fhs-", i)), CLXHash: anchor.Hash, MaxHeight: 19, Execution: executions[i], Actions: source, OnFinalizedExecution: executions[i].Finalized, BeforeVote: collector.BeforeVote, RestoreVote: collector.CheckFHSWatermark, ObserveVote: func(ref []byte, v *hotstuff.HotstuffMessage) error {
			r, err := types.DecodeHotstuffProposalRef(ref)
			if err != nil {
				return err
			}
			if r.Number == 5 {
				copyVote := *v
				copyVote.DataC = append([]byte(nil), v.DataC...)
				pending[index] = observed{append([]byte(nil), ref...), &copyVote}
			}
			return nil
		}}
		apps[i], err = consensus.Open(configs[i])
		if err != nil {
			t.Fatal(err)
		}
		apps[i].SetTransport(func(to string, m *hotstuff.HotstuffMessage) error {
			if len(queue) >= 4096 {
				return errors.New("financial transport saturation")
			}
			queue = append(queue, envelope{to, m})
			return nil
		})
	}
	collect := func() {
		for participant, v := range pending {
			if _, ok := certificates[participant]; ok {
				continue
			}
			var receipts []rewards.Receipt
			for _, c := range collectors {
				receipt, err := c.Issue(v.ref, v.vote)
				if errors.Is(err, rewards.ErrUnvalidatedTarget) {
					continue
				}
				if err != nil {
					t.Fatalf("participation issue %d: %v", participant, err)
				}
				receipts = append(receipts, receipt)
			}
			if len(receipts) >= 5 {
				certificate, err := registry.Certificate(receipts)
				if err != nil {
					t.Fatal(err)
				}
				certificates[participant] = certificate
				for _, c := range collectors {
					if err := c.RememberCertificate(certificate); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	for _, app := range apps {
		if err := app.Start(); !benign(err) {
			t.Fatal(err)
		}
	}
	for step := 0; step < 100000; step++ {
		progress := false
		for _, app := range apps {
			did, err := app.Advance()
			if !benign(err) {
				t.Fatalf("advance: %v", err)
			}
			progress = progress || did
			collect()
		}
		if len(queue) > 0 {
			item := queue[0]
			queue = queue[1:]
			for _, app := range apps {
				if app.Self() == item.to {
					if err := app.Handle(item.message); !benign(err) {
						t.Fatalf("wire: %v", err)
					}
					break
				}
			}
			progress = true
			collect()
		}
		if !progress {
			break
		}
		if step == 99999 {
			t.Fatal("financial network did not quiesce")
		}
	}
	var canonical []byte
	for i, app := range apps {
		if app.FinalizedHeight() != 18 {
			t.Fatalf("validator %d finalized %d", i, app.FinalizedHeight())
		}
		data, err := app.FinalizedState(18)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			canonical = data
		} else if !bytes.Equal(canonical, data) {
			t.Fatal("financial state disagreement")
		}
	}
	final, marketState, err := base.Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Rewards) != 7 || marketState.RewardReserved != "1000000000000000000" {
		t.Fatal("authenticated reward reservation")
	}
	t.Run("participation_commit_envelope_and_version", func(t *testing.T) {
		parent, err := apps[0].FinalizedState(5)
		if err != nil {
			t.Fatal(err)
		}
		cp, _, err := apps[0].FinalizedCheckpoint(5)
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(parent)
		context := consensus.ExecutionContext{Domain: domain, Height: 6, CLXHash: anchor.Hash, ParentRoot: cp.PostRoot}
		if err := base.AuthenticateAction(actions[6]); err != nil {
			t.Fatal("commit authentication", err)
		}
		result, err := base.Execute(parent, actions[6], context)
		if err != nil {
			t.Fatal(err)
		}
		financial, market, err := base.Decode(result.State)
		if err != nil || financial.Version != 3 || financial.Participation == nil || len(financial.Participation.Entries) != 7 || market.RewardReserved != "0" || result.RewardTotal != (protocol.Amount{}) {
			t.Fatal("commit reserved rewards or missed explicit version transition", err)
		}
		for name, mutate := range map[string]func([]byte){"close-domain": func(raw []byte) { copy(raw[:4], "CDXR") }, "signature": func(raw []byte) { raw[4+engine.ActionSize] ^= 1 }, "payload": func(raw []byte) { raw[len(raw)-1] ^= 1 }} {
			t.Run(name, func(t *testing.T) {
				raw := bytes.Clone(actions[6])
				mutate(raw)
				if err := base.AuthenticateAction(raw); err == nil {
					t.Fatal("tampered commit admitted")
				}
				if _, err := base.Execute(parent, raw, context); err == nil {
					t.Fatal("tampered commit executed")
				}
			})
		}
		if !bytes.Equal(parent, before) {
			t.Fatal("commit or rejection mutated parent")
		}
	})
	t.Run("reward_execution_independent_of_local_certificate_delivery", func(t *testing.T) {
		parent, err := apps[0].FinalizedState(17)
		if err != nil {
			t.Fatal(err)
		}
		cp, _, err := apps[0].FinalizedCheckpoint(17)
		if err != nil {
			t.Fatal(err)
		}
		_, pkg, err := decodeAction(actions[18])
		if err != nil {
			t.Fatal(err)
		}
		omitted := pkg.Certificates[len(pkg.Certificates)-1]
		pkg.Certificates = pkg.Certificates[:len(pkg.Certificates)-1]
		command := engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: owners[0], Nonce: closeNonce}
		action, err := EncodeRewardAction(command, userKeys[0], *pkg)
		if err != nil {
			t.Fatal(err)
		}
		var results [2]consensus.ExecutionResult
		var errs [2]error
		for i := 0; i < 2; i++ {
			dir := filepath.Join(rootDir, fmt.Sprintf("different-delivery-%d", i))
			collector, err := rewards.OpenCollector(dir, registry, uint8(i), &voteKeys[i])
			if err != nil {
				t.Fatal(err)
			}
			defer collector.Shutdown()
			if i == 1 {
				if err := collector.RememberCertificate(omitted); err != nil {
					t.Fatal(err)
				}
			}
			execution := &Execution{Market: market, Registry: registry, Collector: collector}
			results[i], errs[i] = execution.Execute(parent, action, consensus.ExecutionContext{Domain: domain, Height: 18, CLXHash: anchor.Hash, ParentRoot: cp.PostRoot})
			if i == 0 {
				// Old local-only policy can have pinned another candidate. Such a
				// diagnostic WAL is not authority over committed financial replay.
				if _, err := collector.Close(1, pkg.Blocks, pkg.Certificates); err != nil {
					t.Fatal(err)
				}
			}
			if err := execution.Finalized(18, actions[18], canonical); err != nil {
				t.Fatal("local delivery changed finalized callback", err)
			}
			if err := collector.Shutdown(); err != nil {
				t.Fatal(err)
			}
			restored, err := rewards.OpenCollector(dir, registry, uint8(i), &voteKeys[i])
			if err != nil {
				t.Fatal(err)
			}
			execution.Collector = restored
			if err := execution.Finalized(18, actions[18], canonical); err != nil {
				t.Fatal("collector restart changed finalized callback", err)
			}
			replayed, replayErr := execution.Execute(parent, action, consensus.ExecutionContext{Domain: domain, Height: 18, CLXHash: anchor.Hash, ParentRoot: cp.PostRoot})
			if !errors.Is(replayErr, rewards.ErrCommittedOmission) || !bytes.Equal(replayed.State, results[i].State) {
				t.Fatal("collector restart changed reward execution", replayErr)
			}
			if err := restored.Shutdown(); err != nil {
				t.Fatal(err)
			}
		}
		if (errs[0] == nil) != (errs[1] == nil) || errs[0] != nil && errs[0].Error() != errs[1].Error() || results[0].PostRoot != results[1].PostRoot || !bytes.Equal(results[0].State, results[1].State) {
			t.Fatalf("identical committed parent/proposal diverged by local delivery: absent=%v present=%v root0=%x root1=%x", errs[0], errs[1], results[0].PostRoot, results[1].PostRoot)
		}
	})
	t.Run("speculative_reward_proposal_does_not_pin_period", func(t *testing.T) {
		collector, err := rewards.OpenCollector(filepath.Join(rootDir, "uncommitted-close"), registry, 0, &voteKeys[0])
		if err != nil {
			t.Fatal(err)
		}
		defer collector.Shutdown()
		execution := &Execution{Market: market, Registry: registry, Collector: collector}
		parent, err := apps[0].FinalizedState(17)
		if err != nil {
			t.Fatal(err)
		}
		cp, _, err := apps[0].FinalizedCheckpoint(17)
		if err != nil {
			t.Fatal(err)
		}
		_, pkg, err := decodeAction(actions[18])
		if err != nil {
			t.Fatal(err)
		}
		omitted := pkg.Certificates[len(pkg.Certificates)-1]
		pkg.Certificates = pkg.Certificates[:len(pkg.Certificates)-1]
		cmd := engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: owners[0], Nonce: closeNonce}
		incomplete, err := EncodeRewardAction(cmd, userKeys[0], *pkg)
		if err != nil {
			t.Fatal(err)
		}
		ctx := consensus.ExecutionContext{Domain: domain, Height: 18, CLXHash: anchor.Hash, ParentRoot: cp.PostRoot}
		if _, err := execution.Execute(parent, incomplete, ctx); !errors.Is(err, rewards.ErrCommittedOmission) {
			t.Fatal("committed omission must fail without local delivery", err)
		}
		if err := collector.RememberCertificate(omitted); err != nil {
			t.Fatal(err)
		}
		if _, err := execution.Execute(parent, actions[18], ctx); err != nil {
			t.Fatalf("uncommitted proposal poisoned retry: %v", err)
		}
		if _, err := execution.Execute(parent, incomplete, ctx); !errors.Is(err, rewards.ErrCommittedOmission) {
			t.Fatalf("known omitted certificate accepted: %v", err)
		}
		// An unclosable reward period must not force a market-wide halt. The
		// same authenticated parent/nonce can execute ordinary authorized work.
		beforeParent := bytes.Clone(parent)
		_, priorMarket, err := execution.Decode(parent)
		if err != nil {
			t.Fatal(err)
		}
		noop, err := engine.Sign(engine.Action{Version: 1, Epoch: domain.EpochKey(), Owner: owners[0], Nonce: closeNonce, Kind: engine.Noop}, userKeys[0])
		if err != nil {
			t.Fatal(err)
		}
		result, err := execution.Execute(parent, noop, ctx)
		if err != nil {
			t.Fatalf("reward omission blocked ordinary market action: %v", err)
		}
		wrapper, ordinaryMarket, err := execution.Decode(result.State)
		if err != nil || ordinaryMarket.RewardReserved != priorMarket.RewardReserved || ordinaryMarket.RewardPeriod != priorMarket.RewardPeriod || len(wrapper.Rewards) != 0 || result.RewardTotal != (protocol.Amount{}) || result.RewardPeriod != 0 || !bytes.Equal(parent, beforeParent) {
			t.Fatal("ordinary action reserved a rejected reward or mutated parent", err)
		}
		if _, err := execution.Execute(parent, actions[18], ctx); err != nil {
			t.Fatalf("ordinary speculative action consumed reward retry nonce: %v", err)
		}
	})
	t.Run("oversized_financial_snapshot_rejected_before_arithmetic", func(t *testing.T) {
		f, _, err := base.Decode(canonical)
		if err != nil {
			t.Fatal(err)
		}
		f.Fees[0][0] = 1
		raw, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := base.Decode(raw); err == nil {
			t.Fatal("oversized fee accepted")
		}
	})
	// Settlement was idle while the DEX progressed. Submission now uses only
	// the CLX authenticated inbox, FHS proofs and fixed finance summaries.
	for h := uint64(1); h <= 18; h++ {
		cp, proof, err := apps[0].FinalizedCheckpoint(h)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := apps[0].FinalizedState(h)
		if err != nil {
			t.Fatal(err)
		}
		f, _, err := base.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		result, err := native.Accept(cp, *f.Finance, proof)
		if err != nil {
			t.Fatalf("native checkpoint %d: %v", h, err)
		}
		if result.Verification.SignatureChecks < 2 {
			t.Fatal("single QC accepted")
		}
		replay, err := native.Accept(cp, *f.Finance, proof)
		if err != nil || !replay.Replay {
			t.Fatal("checkpoint idempotence")
		}
	}
	withdrawState, _ := apps[0].FinalizedState(14)
	withdraw, _, err := base.Decode(withdrawState)
	if err != nil {
		t.Fatal(err)
	}
	claimAll := func(claims []protocol.Claim) {
		leaves := make([]protocol.Hash, len(claims))
		for i, c := range claims {
			leaves[i], err = c.Hash()
			if err != nil {
				t.Fatal(err)
			}
		}
		_, proofs, err := protocol.BuildCountedTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range claims {
			if replay, err := native.Claim(c, uint32(i), uint32(len(claims)), proofs[i]); err != nil || replay {
				t.Fatalf("native claim %v %v", replay, err)
			}
			if replay, err := native.Claim(c, uint32(i), uint32(len(claims)), proofs[i]); err != nil || !replay {
				t.Fatalf("native duplicate %v %v", replay, err)
			}
		}
	}
	claimAll(withdraw.Withdrawals)
	claimAll(final.Rewards)
	if st.GetBalance(custody).Cmp(engine.Amount("214000000000000000000").Big()) != 0 || st.GetBalance(common.Address(owners[3])).Cmp(engine.Amount("10000000000000000000").Big()) != 0 {
		t.Fatal("native custody/payment result")
	}
	var rewardTotal big.Int
	for _, recipient := range recipients {
		rewardTotal.Add(&rewardTotal, st.GetBalance(common.Address(recipient)))
	}
	if rewardTotal.Cmp(engine.Amount("1000000000000000000").Big()) != 0 {
		t.Fatal("native operator rewards")
	}
	// Restart both domains from their persisted state. FHS re-executes every
	// financial parent; the CLX trie retains native reserves and nullifiers.
	cleanup()
	for i := range apps {
		apps[i] = nil
		collectors[i] = nil
	}
	for i := range configs {
		collector, err := rewards.OpenCollector(filepath.Join(rootDir, fmt.Sprint("participation-", i)), registry, uint8(i), &voteKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		collectors[i] = collector
		executions[i].Collector = collector
		configs[i].BeforeVote = collector.BeforeVote
		configs[i].RestoreVote = collector.CheckFHSWatermark
		apps[i], err = consensus.Open(configs[i])
		if err != nil {
			t.Fatalf("financial restart %d: %v", i, err)
		}
		raw, err := apps[i].FinalizedState(18)
		if err != nil || !bytes.Equal(raw, canonical) {
			t.Fatal("restart financial replay mismatch")
		}
	}
	stateRoot, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Database().TrieDB().Commit(stateRoot, false, nil); err != nil {
		t.Fatal(err)
	}
	st, err = state.New(stateRoot, state.NewDatabase(nativeDB), nil)
	if err != nil {
		t.Fatal(err)
	}
	native, err = settlement.NewDevnet(st, nativeConfig)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]protocol.Hash, len(final.Rewards))
	for i, c := range final.Rewards {
		leaves[i], _ = c.Hash()
	}
	_, paths, err := protocol.BuildCountedTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range final.Rewards {
		replay, err := native.Claim(c, uint32(i), uint32(len(leaves)), paths[i])
		if err != nil || !replay {
			t.Fatalf("restart nullifier: %v %v", replay, err)
		}
	}
	if native.Status().Sequence != 18 || st.GetBalance(custody).Cmp(engine.Amount("214000000000000000000").Big()) != 0 {
		t.Fatal("native restart balance/history")
	}
	balances, err := native.Balances()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("7 FHS validators finalized 18 financial blocks; real native fixture custody225 -> withdraw10 + reward1 ->214 CLX; pools F=%s S=%s I=%s; 7 participant certificates from actual votes; all DEX WALs and CLX StateDB restarted", balances[settlement.Fees].Big(), balances[settlement.Support].Big(), balances[settlement.Insurance].Big())
	t.Log("CLX transaction-handler registration, finalized CLX financial transactions, live-network financial workload and real funds NOT_RUN; native calls use trusted devnet execution context")
}
