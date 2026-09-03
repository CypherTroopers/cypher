package core

import (
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/trie"
)

func fhsSidecarHandoffFixture(t *testing.T) (*params.ChainConfig, *types.Block, fhsSidecarValidationContext, *validatedFHSSidecars) {
	t.Helper()
	config := modernTestConfig(true, true, true)
	config.FairHotstuff = true
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	miner := crypto.PubkeyToAddress(key.PublicKey)
	config.CommonRPCSigners = []common.Address{miner}
	genesisHash := common.HexToHash("0xf001")
	context := fhsSidecarValidationContext{genesisHash: genesisHash, keyBlockNumber: 7}
	tx := types.NewTransaction(0, common.HexToAddress("0x2001"), big.NewInt(1), params.TxGas, big.NewInt(params.FixedTransferGasPricePerGas), nil)
	txs := types.Transactions{tx}
	batch := stateProcessorTestAdmissionBatch(t, key, config.ChainID, genesisHash, context.keyBlockNumber, 100, []common.Hash{tx.Hash()})
	reward := &types.CommonTxReward{
		TxHash: tx.Hash(), Approver: miner,
		ApproverReward: big.NewInt(1), Burn: big.NewInt(2),
	}
	header := &types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		BlockType:  types.FastTx_Block,
		Time:       100,
		KeyHash:    common.HexToHash("0xa007"),
		TxHash:     types.DeriveSha(txs, new(trie.Trie)),
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)
	block.AttachCommonTxData([]*types.CommonTxAdmissionBatch{batch}, []types.CommonTxAdmissionRef{{}}, []*types.CommonTxReward{reward})
	if err := validateFHSCommonRPCSidecarCardinality(config, block); err != nil {
		t.Fatal(err)
	}
	if err := validateCommonTxSidecarRoots(block); err != nil {
		t.Fatal(err)
	}
	validated, err := buildValidatedFHSSidecarLayout(config, block, context)
	if err != nil {
		t.Fatal(err)
	}
	return config, block, context, validated
}

func TestFHSSidecarHandoffConcurrentTakeHasSingleOwner(t *testing.T) {
	config, block, context, validated := fhsSidecarHandoffFixture(t)
	handoff := newFHSSidecarHandoff()
	if !handoff.publish(config, block, context, validated) {
		t.Fatal("validated sidecars were not published")
	}

	const consumers = 64
	start := make(chan struct{})
	var group sync.WaitGroup
	var owners atomic.Int32
	group.Add(consumers)
	for index := 0; index < consumers; index++ {
		go func() {
			defer group.Done()
			<-start
			if got := handoff.take(config, block, context); got != nil {
				if got != validated {
					t.Errorf("consumer received unexpected sidecars %p", got)
				}
				owners.Add(1)
			}
		}()
	}
	close(start)
	group.Wait()
	if got := owners.Load(); got != 1 {
		t.Fatalf("sidecar owners = %d, want 1", got)
	}
}

func TestFHSSidecarHandoffBindsConsensusIdentity(t *testing.T) {
	config, block, context, validated := fhsSidecarHandoffFixture(t)
	handoff := newFHSSidecarHandoff()
	if !handoff.publish(config, block, context, validated) {
		t.Fatal("validated sidecars were not published")
	}

	changedContext := context
	changedContext.genesisHash[0] ^= 1
	if got := handoff.take(config, block, changedContext); got != nil {
		t.Fatal("sidecars were reused under another genesis")
	}
	changedContext = context
	changedContext.keyBlockNumber++
	if got := handoff.take(config, block, changedContext); got != nil {
		t.Fatal("sidecars were reused under another key epoch")
	}

	originalTime := block.Header0().Time
	block.Header0().Time++
	if got := handoff.take(config, block, context); got != nil {
		t.Fatal("sidecars were reused under another block time")
	}
	block.Header0().Time = originalTime
	originalKeyHash := block.Header0().KeyHash
	block.Header0().KeyHash[0] ^= 1
	if got := handoff.take(config, block, context); got != nil {
		t.Fatal("sidecars were reused under another key hash")
	}
	block.Header0().KeyHash = originalKeyHash

	changedConfig := *config
	changedConfig.CommonRPCSigners = append([]common.Address(nil), config.CommonRPCSigners...)
	changedConfig.CommonRPCSigners[0][0] ^= 1
	if got := handoff.take(&changedConfig, block, context); got != nil {
		t.Fatal("sidecars were reused under another consensus config")
	}
	if got := handoff.take(config, block, context); got != validated {
		t.Fatalf("original identity returned %p, want %p", got, validated)
	}
}

func TestFHSSidecarHandoffFallbackValidatesAndReuseConsumes(t *testing.T) {
	config, block, context, validated := fhsSidecarHandoffFixture(t)
	handoff := newFHSSidecarHandoff()

	fallback, err := takeOrValidateFHSSidecars(config, block, context, handoff)
	if err != nil {
		t.Fatalf("cache-miss validation: %v", err)
	}
	if fallback == nil || len(fallback.approvers) != 1 || fallback.approvers[0] != config.CommonRPCSigners[0] {
		t.Fatalf("fallback approvers = %#v", fallback)
	}
	if reward, ok := fallback.rewardForTransaction(block.Body(), 0); !ok || reward.TxHash != block.Transactions()[0].Hash() {
		t.Fatalf("fallback reward = %#v, found=%t", reward, ok)
	}

	if !handoff.publish(config, block, context, validated) {
		t.Fatal("validated sidecars were not published")
	}
	reused, err := takeOrValidateFHSSidecars(config, block, context, handoff)
	if err != nil {
		t.Fatalf("cache-hit validation: %v", err)
	}
	if reused != validated {
		t.Fatal("StateProcessor seam rebuilt instead of consuming validated sidecars")
	}
	if len(handoff.entries) != 0 || handoff.retained != 0 {
		t.Fatal("consumed sidecars remained retained")
	}
	secondFallback, err := takeOrValidateFHSSidecars(config, block, context, handoff)
	if err != nil {
		t.Fatalf("post-consume fallback: %v", err)
	}
	if secondFallback == reused {
		t.Fatal("consume-once handoff returned the same artifact twice")
	}
}

func TestFHSSidecarHandoffBoundsRetainedArtifacts(t *testing.T) {
	config, block, context, _ := fhsSidecarHandoffFixture(t)
	// Reuse backing in this accounting test: every independently keyed entry
	// must still be charged as if it exclusively retains its artifact.
	const transactionCount = 320 * 1024
	block = types.NewBlockWithHeader(block.Header()).WithBody(make(types.Transactions, transactionCount), nil)
	validated := &validatedFHSSidecars{
		approvers:       make([]common.Address, transactionCount),
		rewardPositions: make([]uint32, transactionCount),
	}
	handoff := newFHSSidecarHandoff()
	for index := 0; index < fhsSidecarHandoffMaxEntries*2; index++ {
		block.Header0().Number.SetUint64(uint64(index + 1))
		block.Header0().Time = uint64(index + 1)
		if !handoff.publish(config, block, context, validated) {
			t.Fatalf("publish %d failed", index)
		}
	}
	if len(handoff.entries) >= fhsSidecarHandoffMaxEntries {
		t.Fatalf("byte budget did not evict entries: retained %d", len(handoff.entries))
	}
	if handoff.retained > fhsSidecarHandoffMaxBytes {
		t.Fatalf("retained bytes = %d, maximum %d", handoff.retained, fhsSidecarHandoffMaxBytes)
	}
}

func TestFHSSidecarHandoffInvalidSignatureCannotPublish(t *testing.T) {
	config, block, context, _ := fhsSidecarHandoffFixture(t)
	body := block.Body()
	body.CommonTxAdmissionBatches[0].Signature[0] ^= 1
	block.AttachCommonTxData(body.CommonTxAdmissionBatches, body.CommonTxAdmissionRefs, body.CommonTxRewards)
	validated, err := buildValidatedFHSSidecarLayout(config, block, context)
	if err != nil {
		t.Fatalf("tampered signature should pass pre-crypto layout: %v", err)
	}
	handoff := newFHSSidecarHandoff()
	if err := verifyAndPublishValidatedFHSSidecars(config, block, context, validated, handoff); err == nil {
		t.Fatal("tampered admission signature was accepted")
	}
	if len(handoff.entries) != 0 || handoff.retained != 0 {
		t.Fatal("invalid sidecars entered the handoff")
	}
}
