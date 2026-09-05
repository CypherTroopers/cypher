package reconfig

import (
	"bytes"
	"math/big"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusX"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/trie"
)

type ownedParentFixture struct {
	chain    *core.BlockChain
	service  *Service
	parent   *core.VerifiedProposal
	child    *types.Block
	sender   common.Address
	contract common.Address
}

// Use real EVM execution with code, storage and logs for the ownership tests.
// The live FHS scheduler/epoch checks are exercised separately below; this
// chain omits FHS admission proofs to isolate state ownership from their crypto.
func newOwnedParentFixture(t *testing.T) *ownedParentFixture {
	t.Helper()
	config := *params.TestChainConfig
	config.ChainID = big.NewInt(73901)
	config.SetModernForkConfig(&params.ModernForkConfig{BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0)})
	t.Cleanup(func() { config.SetModernForkConfig(nil) })
	key, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	contract := common.HexToAddress("0x739010")
	// Store calldata word at slot zero, then emit its 32 bytes with LOG0.
	code := common.FromHex("0x6000358060005560005260206000a000")
	db := rawdb.NewMemoryDatabase()
	genesis := (&core.Genesis{Config: &config, Difficulty: big.NewInt(1), GasLimit: params.GenesisGasLimit, Timestamp: 1,
		Alloc: core.GenesisAlloc{
			sender:   {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
			contract: {Nonce: 1, Code: code, Balance: big.NewInt(0)},
		}}).MustCommit(db)
	engine := colossusX.NewFaker()
	chain, err := core.NewBlockChain(db, nil, &config, engine, vm.Config{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { chain.Stop(); engine.Close(); db.Close() })
	makeBlock := func(parent *types.Block, parentState *state.StateDB, nonce, value uint64) *types.Block {
		input := common.BigToHash(new(big.Int).SetUint64(value))
		tx, err := types.SignTx(types.NewTransaction(nonce, contract, big.NewInt(0), 100_000, big.NewInt(1_000_000_000), input[:]), types.LatestSignerForChainID(config.ChainID), key)
		if err != nil {
			t.Fatal(err)
		}
		header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)),
			Difficulty: big.NewInt(1), GasLimit: parent.GasLimit(), BaseFee: big.NewInt(params.FixedBaseFeePerGas),
			Time: parent.Time() + 1, BlockType: types.SlowTx_Block}
		block := types.NewBlock(header, []*types.Transaction{tx}, nil, nil, new(trie.Trie))
		execution := parentState.Copy()
		receipts, _, gas, err := core.NewStateProcessor(&config, chain, engine).Process(block, execution, vm.Config{})
		if err != nil {
			t.Fatal(err)
		}
		header.Root, header.GasUsed = execution.IntermediateRoot(true), gas
		return types.NewBlock(header, []*types.Transaction{tx}, nil, receipts, new(trie.Trie))
	}
	genesisState, err := chain.StateAt(genesis.Root())
	if err != nil {
		t.Fatal(err)
	}
	parentBlock := makeBlock(genesis, genesisState, 0, 1)
	parent, err := chain.ValidateBlockForHotstuff(common.HexToHash("0x739001"), 1, common.HexToHash("0x739011"), "parent", parentBlock)
	if err != nil {
		t.Fatal(err)
	}
	parentView := parent.StateDB.Copy()
	if nonce, slot := parentView.GetNonce(sender), parentView.GetState(contract, common.Hash{}); nonce != 1 || slot != common.HexToHash("0x01") {
		t.Fatalf("parent fixture state: nonce=%d slot=%x", nonce, slot[:])
	}
	child := makeBlock(parentBlock, parent.StateDB, 1, 2)
	service := &Service{fhsCertifiedByHash: map[common.Hash]*fhsCertifiedProposal{parentBlock.Hash(): {verified: parent}}}
	return &ownedParentFixture{chain: chain, service: service, parent: parent, child: child, sender: sender, contract: contract}
}

func (f *ownedParentFixture) validate(snapshot *core.VerifiedProposal, block *types.Block) (*core.VerifiedProposal, error) {
	return f.chain.ValidateBlockForHotstuffWithOwnedParent(common.HexToHash("0x739002"), 2, common.HexToHash("0x739022"), "child", block, snapshot)
}

func (f *ownedParentFixture) checkParent(t *testing.T) {
	t.Helper()
	// Observe the same speculative trie view passed to a child, independent
	// of the original StateDB's separate canonical snapshot read cache.
	parentView := f.parent.StateDB.Copy()
	if nonce, slot := parentView.GetNonce(f.sender), parentView.GetState(f.contract, common.Hash{}); nonce != 1 || slot != common.HexToHash("0x01") {
		t.Fatalf("child execution mutated the shared parent nonce/storage: nonce=%d slot=%x", nonce, slot[:])
	}
	if root := parentView.IntermediateRoot(true); root != f.parent.Block.Root() {
		t.Fatal("child execution changed the shared parent's speculative root")
	}
}

func TestFHSOwnedParentSnapshotExecutesWithoutSecondCopy(t *testing.T) {
	f := newOwnedParentFixture(t)
	snapshot := f.service.snapshotFHSCertifiedVerified(f.parent.BlockHash())
	sibling := f.service.snapshotFHSCertifiedVerified(f.parent.BlockHash())
	ownedState := snapshot.StateDB
	if ownedState == f.parent.StateDB || sibling.StateDB == ownedState {
		t.Fatal("scheduler did not isolate private parent snapshots")
	}
	verified, err := f.validate(snapshot, f.child)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.StateDB != nil || verified.StateDB != ownedState {
		t.Fatal("execution did not consume the private snapshot without another copy")
	}
	f.checkParent(t)
	if sibling.StateDB.GetNonce(f.sender) != 1 || sibling.StateDB.GetState(f.contract, common.Hash{}) != common.HexToHash("0x01") {
		t.Fatal("execution changed a sibling snapshot")
	}
	if verified.StateDB.GetNonce(f.sender) != 2 || verified.StateDB.GetState(f.contract, common.Hash{}) != common.HexToHash("0x02") {
		t.Fatal("child state transition was not executed")
	}
	if len(verified.Receipts) != 1 || verified.Receipts[0].Status != types.ReceiptStatusSuccessful || len(verified.Logs) != 1 ||
		!bytes.Equal(verified.Logs[0].Data, common.HexToHash("0x02").Bytes()) || verified.UsedGas != f.child.GasUsed() {
		t.Fatal("child receipts, gas or contract log differ from execution")
	}
	reference, err := f.chain.ValidateBlockForHotstuffWithParent(verified.ProposalID, verified.ViewNumber, verified.ViewID, verified.LeaderID, f.child, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	if reference.StateDB == f.parent.StateDB || !reflect.DeepEqual(reference.Receipts, verified.Receipts) || !reflect.DeepEqual(reference.Logs, verified.Logs) ||
		reference.StateDB.IntermediateRoot(true) != verified.StateDB.IntermediateRoot(true) || !bytes.Equal(reference.StateDB.GetCode(f.contract), verified.StateDB.GetCode(f.contract)) {
		t.Fatal("owned and shared-parent validation paths differ")
	}
	if _, err := f.validate(snapshot, f.child); err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("consumed snapshot was reusable: %v", err)
	}
}

func TestFHSOwnedParentSnapshotFailureIsDiscarded(t *testing.T) {
	for _, failure := range []string{"before-execution", "after-execution"} {
		t.Run(failure, func(t *testing.T) {
			f := newOwnedParentFixture(t)
			snapshot := f.service.snapshotFHSCertifiedVerified(f.parent.BlockHash())
			ownedState := snapshot.StateDB
			block := f.child
			if failure == "before-execution" {
				block = nil
			} else {
				header := block.Header()
				header.Root = common.HexToHash("0xbad")
				block = block.WithSeal(header)
			}
			if verified, err := f.validate(snapshot, block); err == nil || verified != nil {
				t.Fatalf("invalid child produced an execution artifact: %v", err)
			}
			if snapshot.StateDB != nil {
				t.Fatal("failed execution retained a reusable snapshot")
			}
			if failure == "after-execution" && ownedState.GetNonce(f.sender) != 2 {
				t.Fatal("late failure did not exercise a partially consumed execution state")
			}
			f.checkParent(t)
			if _, err := f.validate(snapshot, f.child); err == nil || !strings.Contains(err.Error(), "consumed") {
				t.Fatalf("failed snapshot was reusable: %v", err)
			}
			if _, err := f.validate(f.service.snapshotFHSCertifiedVerified(f.parent.BlockHash()), f.child); err != nil {
				t.Fatalf("failure poisoned a fresh sibling execution: %v", err)
			}
		})
	}
}

func TestFHSOwnedParentSnapshotSurvivesConcurrentParentCommit(t *testing.T) {
	f := newOwnedParentFixture(t)
	snapshot := f.service.snapshotFHSCertifiedVerified(f.parent.BlockHash())
	start := make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		<-start
		_, err := f.chain.CommitVerifiedProposal(f.parent, false)
		committed <- err
	}()
	close(start)
	verified, validationErr := f.validate(snapshot, f.child)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if validationErr != nil {
		t.Fatal(validationErr)
	}
	if status, err := f.chain.CommitVerifiedProposal(verified, false); err != nil || status != core.CanonStatTy {
		t.Fatalf("commit child after concurrent parent consumption: status=%v err=%v", status, err)
	}
	reopened, err := f.chain.StateAt(f.child.Root())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.GetNonce(f.sender) != 2 || reopened.GetState(f.contract, common.Hash{}) != common.HexToHash("0x02") || len(reopened.GetCode(f.contract)) == 0 {
		t.Fatal("committed child lost state/code after parent consumption")
	}
}

func TestFHSOwnedParentEarlyRefFailureConsumesSnapshot(t *testing.T) {
	f := newOwnedParentFixture(t)
	snapshot := f.service.snapshotFHSCertifiedVerified(f.parent.BlockHash())
	service := new(txService)
	if _, err := service.verifyHotstuffProposalWithOwnedParent(nil, f.child, nil, snapshot); err == nil {
		t.Fatal("nil proposal reference accepted")
	}
	if snapshot.StateDB != nil {
		t.Fatal("early tx-service failure retained ownership")
	}
	f.checkParent(t)
}

func TestFHSPrepareWorkerConsumesSnapshotAndRetainsGenerationGate(t *testing.T) {
	for _, missingState := range []bool{false, true} {
		name := "private-state"
		if missingState {
			name = "empty-parent-without-state"
		}
		t.Run(name, func(t *testing.T) { testFHSPrepareWorkerOwnedParent(t, missingState) })
	}
}

func testFHSPrepareWorkerOwnedParent(t *testing.T, missingState bool) {
	f := newConvergenceFixture(t)
	s := f.replicas[0]
	parent := f.proposal(t, nil, 10, 'p')
	child := f.proposal(t, parent, 11, 'c')
	if err := s.adoptFHSHighQC(parent.qc, false, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectFHSProposalParent(parent.qc); err != nil {
		t.Fatal(err)
	}
	if missingState {
		// Empty parents with a persisted root may omit StateDB. This remains
		// a valid input to the legacy copying verifier's StateAt fallback.
		s.getFHSCertifiedVerified(parent.ref.BlockHash).StateDB = nil
	}
	atomic.StoreInt32(&s.runningState, 1)
	t.Cleanup(func() { atomic.StoreInt32(&s.runningState, 0) })
	atomic.StoreUint64(&s.proposalValidationGeneration, 1)
	s.proposalValidationJobs = make(chan *proposalValidationJob, 1)
	s.proposalValidationResults = make(chan *hotstuff.FHSProposalValidationResult, 1)
	s.activeProposalValidations = make(map[common.Hash]*proposalValidationControl)
	request := &hotstuff.FHSProposalValidationRequest{Key: hotstuff.FHSProposalValidationKey{RequestID: 1,
		ViewNumber: child.ref.ViewNumber, ViewID: child.ref.ViewID, LeaderID: child.ref.LeaderID, ProposalID: child.ref.ProposalID()},
		ProposalRef: child.ref.EncodeToBytes(), ParentQC: parent.qc}
	if err := s.ScheduleFHSProposalValidation(request); err != nil {
		t.Fatal(err)
	}
	job := <-s.proposalValidationJobs
	t.Cleanup(job.cancel)
	snapshotState := job.parentVerified.StateDB
	s.proposalValidationJobs <- job
	close(s.proposalValidationJobs)
	s.proposalValidationWorker()
	var result *hotstuff.FHSProposalValidationResult
	select {
	case result = <-s.proposalValidationResults:
	default:
		t.Fatal("active Prepare worker did not publish its result")
	}
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	output := result.ApplicationData.(*proposalValidationOutput)
	if missingState {
		if snapshotState != nil || output.verified.StateDB == nil {
			t.Fatal("empty parent did not preserve the private StateAt fallback")
		}
	} else {
		if job.parentVerified.StateDB != nil || output.verified.StateDB != snapshotState || snapshotState == s.getFHSCertifiedVerified(parent.ref.BlockHash).StateDB {
			t.Fatal("Prepare worker did not exclusively consume its scheduler snapshot")
		}
	}
	atomic.AddUint64(&s.proposalValidationGeneration, 1)
	if err := s.installHotstuffProposalValidation(output); err != hotstuff.ErrOldState {
		t.Fatalf("consumed state bypassed obsolete generation rejection: %v", err)
	}
	atomic.StoreUint64(&s.proposalValidationGeneration, output.serviceGeneration)
	atomic.StoreInt32(&s.fhsEpochTransition, 1)
	if err := s.installHotstuffProposalValidation(output); err != hotstuff.ErrOldState {
		t.Fatalf("consumed state bypassed key-epoch transition rejection: %v", err)
	}
}
