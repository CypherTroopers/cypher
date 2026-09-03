package reconfig

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet/network"
	"github.com/cypherium/cypher/trie"
)

func testSignedProposalRepairTransaction(t *testing.T) *types.Transaction {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(
		types.NewTransaction(7, common.HexToAddress("0x1234"), big.NewInt(5), 21_000, big.NewInt(3), []byte("repair")),
		types.NewEIP155Signer(big.NewInt(99)),
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func testProposalRepairWireBody(t *testing.T) (*proposalBodyMsg, *types.Transaction) {
	t.Helper()
	tx := testSignedProposalRepairTransaction(t)
	encodedTransaction, err := encodeProposalRepairTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	body := &proposalBodyMsg{
		Type:             proposalBodyMsgRepairData,
		ProposalID:       common.HexToHash("0x01"),
		BodyHash:         common.HexToHash("0x02"),
		BodySize:         1,
		Number:           1,
		ViewNumber:       1,
		ViewID:           common.HexToHash("0x03"),
		LeaderID:         "leader",
		From:             "member-0",
		ProposalKeyHash:  common.HexToHash("0x04"),
		SenderKeyHash:    common.HexToHash("0x04"),
		MissingTxHashes:  []common.Hash{tx.Hash()},
		TransactionBytes: [][]byte{encodedTransaction},
		AuthSig:          []byte{1},
	}
	return body, tx
}

func TestProposalRepairNetworkRoundTrip(t *testing.T) {
	body, tx := testProposalRepairWireBody(t)
	if err := validateProposalBodyWireShape(body); err != nil {
		t.Fatalf("valid repair payload rejected before network encoding: %v", err)
	}
	network.RegisterMessage(&networkMsg{})
	encoded, err := network.Marshal(&networkMsg{Pmsg: body})
	if err != nil {
		t.Fatalf("marshal repair message with a signed transaction: %v", err)
	}
	_, decodedMessage, err := network.Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := decodedMessage.(*networkMsg)
	if !ok || decoded.Pmsg == nil {
		t.Fatalf("repair transaction did not survive network round trip: %#v", decodedMessage)
	}
	if err := validateProposalBodyWireShape(decoded.Pmsg); err != nil {
		t.Fatalf("network-decoded repair payload rejected: %v", err)
	}
	if len(decoded.Pmsg.TransactionBytes) != 1 || !bytes.Equal(decoded.Pmsg.TransactionBytes[0], body.TransactionBytes[0]) {
		t.Fatalf("network round trip changed canonical transaction bytes")
	}
	decodedTransactions, err := decodeProposalRepairTransactions(decoded.Pmsg.MissingTxHashes, decoded.Pmsg.TransactionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedTransactions) != 1 || decodedTransactions[0].Hash() != tx.Hash() {
		t.Fatalf("network round trip changed repair transaction hash")
	}
	signer := types.NewEIP155Signer(big.NewInt(99))
	wantSender, err := types.Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	gotSender, err := types.Sender(signer, decodedTransactions[0])
	if err != nil {
		t.Fatalf("network round trip lost the transaction signature: %v", err)
	}
	if gotSender != wantSender {
		t.Fatalf("network round trip changed signed sender: have %s want %s", gotSender, wantSender)
	}
}

func TestProposalRepairWireValidationRejectsMalformedTransactions(t *testing.T) {
	valid, tx := testProposalRepairWireBody(t)
	other := testSignedProposalRepairTransaction(t)
	tests := map[string]func(*proposalBodyMsg){
		"count mismatch": func(body *proposalBodyMsg) {
			body.MissingTxHashes = append(body.MissingTxHashes, other.Hash())
		},
		"count limit": func(body *proposalBodyMsg) {
			body.MissingTxHashes = make([]common.Hash, proposalRepairMaxHashes+1)
			body.TransactionBytes = make([][]byte, proposalRepairMaxHashes+1)
			for index := range body.MissingTxHashes {
				body.MissingTxHashes[index] = common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
			}
		},
		"empty hash": func(body *proposalBodyMsg) {
			body.MissingTxHashes[0] = common.Hash{}
		},
		"hash mismatch": func(body *proposalBodyMsg) {
			body.MissingTxHashes[0] = other.Hash()
		},
		"duplicate hash": func(body *proposalBodyMsg) {
			body.MissingTxHashes = append(body.MissingTxHashes, tx.Hash())
			body.TransactionBytes = append(body.TransactionBytes, append([]byte(nil), body.TransactionBytes[0]...))
		},
		"invalid encoding": func(body *proposalBodyMsg) {
			body.TransactionBytes[0] = []byte{types.AccessListTxType}
		},
		"oversized total": func(body *proposalBodyMsg) {
			body.TransactionBytes[0] = make([]byte, proposalBodySidecarMaxBytes)
		},
		"noncanonical encoding": func(body *proposalBodyMsg) {
			body.TransactionBytes[0] = append(body.TransactionBytes[0], 0)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			body := cloneProposalBodyMsg(valid)
			mutate(body)
			if err := validateProposalBodyWireShape(body); err == nil {
				t.Fatal("malformed repair transaction payload was accepted")
			}
		})
	}
}

func TestProposalRepairEncodingRejectsUninitializedTransaction(t *testing.T) {
	if _, err := encodeProposalRepairTransaction(new(types.Transaction)); err == nil {
		t.Fatal("uninitialized transaction was encoded for proposal repair")
	}
}

func TestProposalRepairResponseRejectsUninitializedResolvedTransaction(t *testing.T) {
	service, body := testProposalSidecar(t)
	requested := testSignedProposalRepairTransaction(t)
	block := types.NewBlock(&types.Header{
		Number:     big.NewInt(1),
		Difficulty: big.NewInt(1),
		GasLimit:   30_000_000,
	}, types.Transactions{requested}, nil, nil, new(trie.Trie))
	block.SetCommonTxData(nil, []types.CommonTxAdmissionRef{{}}, nil)
	manifest, err := encodeProposalDataManifest(block)
	if err != nil {
		t.Fatal(err)
	}
	body.EncodedBlock = nil
	body.Manifest = manifest
	service.resolveTxQUICTransaction = func(common.Hash) (*types.Transaction, error) {
		return new(types.Transaction), nil
	}
	if _, _, err := service.proposalRepairTransactions(body, []common.Hash{requested.Hash()}); err == nil {
		t.Fatal("uninitialized resolved transaction was emitted in a repair response")
	}
}

func TestProposalRepairRequestTrackerCoversMaxCountWithDelayedResponses(t *testing.T) {
	transactionLimit := int(params.FairHotstuffWorkLimits().Transactions)
	missing := make([]common.Hash, transactionLimit)
	for index := range missing {
		missing[index] = common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
	}

	// Keep the complete missing set unchanged to model responses arriving only
	// after every first-pass request has already been sent.
	tracker := new(proposalRepairRequestTracker)
	seen := make(map[common.Hash]struct{}, transactionLimit)
	windowCount := (transactionLimit + proposalRepairMaxHashes - 1) / proposalRepairMaxHashes
	for windowIndex := 0; windowIndex < windowCount; windowIndex++ {
		window := tracker.nextWindow(missing)
		wantSize := proposalRepairMaxHashes
		if remaining := transactionLimit - windowIndex*proposalRepairMaxHashes; remaining < wantSize {
			wantSize = remaining
		}
		if len(window) != wantSize {
			t.Fatalf("repair window %d size = %d, want %d", windowIndex, len(window), wantSize)
		}
		for _, hash := range window {
			if _, duplicate := seen[hash]; duplicate {
				t.Fatalf("repair window %d repeated %s before covering the manifest", windowIndex, hash)
			}
			seen[hash] = struct{}{}
		}
	}
	if len(seen) != transactionLimit {
		t.Fatalf("first repair pass covered %d transactions, want %d", len(seen), transactionLimit)
	}

	rotated := tracker.nextWindow(missing)
	wantRotated := transactionLimit
	if wantRotated > proposalRepairMaxHashes {
		wantRotated = proposalRepairMaxHashes
	}
	if len(rotated) != wantRotated {
		t.Fatalf("rotated repair window size = %d, want %d", len(rotated), wantRotated)
	}
	for index := range rotated {
		if rotated[index] != missing[index] {
			t.Fatalf("rotated repair window[%d] = %s, want %s", index, rotated[index], missing[index])
		}
	}
}

func TestProposalRepairRequestTrackerRequeuesPartialResponseRemainder(t *testing.T) {
	missing := make([]common.Hash, 2*proposalRepairMaxHashes)
	for index := range missing {
		missing[index] = common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
	}

	tracker := new(proposalRepairRequestTracker)
	first := tracker.nextWindow(missing)
	if len(first) != proposalRepairMaxHashes {
		t.Fatalf("first repair window size = %d, want %d", len(first), proposalRepairMaxHashes)
	}

	// Model a byte-capped response which can return only the first transaction
	// from a full hash window. The rest of that same request must become eligible
	// immediately instead of waiting for a pass over every later manifest hash.
	remaining := append([]common.Hash(nil), missing[1:]...)
	second := tracker.nextWindow(remaining)
	if len(second) != proposalRepairMaxHashes {
		t.Fatalf("second repair window size = %d, want %d", len(second), proposalRepairMaxHashes)
	}
	for index := 0; index < proposalRepairMaxHashes-1; index++ {
		if second[index] != missing[index+1] {
			t.Fatalf("second repair window[%d] = %s, want partial remainder %s", index, second[index], missing[index+1])
		}
	}
	if second[len(second)-1] != missing[proposalRepairMaxHashes] {
		t.Fatalf("second repair window tail = %s, want next unrequested hash %s", second[len(second)-1], missing[proposalRepairMaxHashes])
	}
}

func TestProposalRepairAssemblyTrackerPipelinesDisjointWindows(t *testing.T) {
	transactionLimit := proposalRepairNativeRequestBurst*proposalRepairMaxHashes + 1
	hashes := make([]common.Hash, transactionLimit)
	for index := range hashes {
		hashes[index] = common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
	}
	state := &proposalAssemblyState{
		manifest:     &proposalDataManifest{TransactionHashes: hashes},
		positions:    make(map[common.Hash]int, len(hashes)),
		transactions: make(types.Transactions, len(hashes)),
		missingCount: len(hashes),
	}
	for index, hash := range hashes {
		state.positions[hash] = index
	}
	tracker := new(proposalRepairRequestTracker)
	seen := make(map[common.Hash]struct{}, proposalRepairNativeRequestBurst*proposalRepairMaxHashes)
	for request := 0; request < proposalRepairNativeRequestBurst; request++ {
		window := tracker.nextAssemblyWindow(state)
		if len(window) != proposalRepairMaxHashes {
			t.Fatalf("window %d size = %d, want %d", request, len(window), proposalRepairMaxHashes)
		}
		for _, hash := range window {
			if _, duplicate := seen[hash]; duplicate {
				t.Fatalf("window %d repeated in-flight hash %s", request, hash)
			}
			seen[hash] = struct{}{}
		}
	}
	if len(seen) != proposalRepairNativeRequestBurst*proposalRepairMaxHashes {
		t.Fatalf("pipelined windows covered %d hashes", len(seen))
	}
	if got := proposalRepairRequestBurstForConfig(nativeProposalLimitTestConfig()); got != proposalRepairNativeRequestBurst {
		t.Fatalf("native request burst = %d, want %d", got, proposalRepairNativeRequestBurst)
	}
	if got := proposalRepairRequestBurstForConfig(nil); got != 1 {
		t.Fatalf("legacy request burst = %d, want 1", got)
	}
}

func TestProposalRepairAssemblyTrackerImmediatelyRetriesPartialWindow(t *testing.T) {
	hashes := make([]common.Hash, 2*proposalRepairMaxHashes)
	state := &proposalAssemblyState{
		manifest:     &proposalDataManifest{TransactionHashes: hashes},
		positions:    make(map[common.Hash]int, len(hashes)),
		transactions: make(types.Transactions, len(hashes)),
		missingCount: len(hashes),
	}
	for index := range hashes {
		hashes[index] = common.BigToHash(new(big.Int).SetUint64(uint64(index + 1)))
		state.positions[hashes[index]] = index
	}
	tracker := new(proposalRepairRequestTracker)
	first := tracker.nextAssemblyWindow(state)
	if len(first) != proposalRepairMaxHashes {
		t.Fatalf("first window size = %d", len(first))
	}
	state.transactions[0] = testSignedProposalRepairTransaction(t)
	state.missingCount--
	state.resolved = append(state.resolved, hashes[0])
	second := tracker.nextAssemblyWindow(state)
	if len(second) != proposalRepairMaxHashes {
		t.Fatalf("retry window size = %d", len(second))
	}
	for index := 0; index < proposalRepairMaxHashes-1; index++ {
		if second[index] != hashes[index+1] {
			t.Fatalf("retry[%d] = %s, want %s", index, second[index], hashes[index+1])
		}
	}
	if second[len(second)-1] != hashes[proposalRepairMaxHashes] {
		t.Fatalf("retry tail = %s, want %s", second[len(second)-1], hashes[proposalRepairMaxHashes])
	}
}

func TestMergeProposalRepairRejectsOutsideHashAtomically(t *testing.T) {
	valid := testSignedProposalRepairTransaction(t)
	outside := testSignedProposalRepairTransaction(t)
	validBytes, err := encodeProposalRepairTransaction(valid)
	if err != nil {
		t.Fatal(err)
	}
	outsideBytes, err := encodeProposalRepairTransaction(outside)
	if err != nil {
		t.Fatal(err)
	}
	proposalID := common.HexToHash("0x101")
	bodyHash := common.HexToHash("0x102")
	viewID := common.HexToHash("0x103")
	service := &Service{
		chainConfig: &params.ChainConfig{ChainID: big.NewInt(99)},
		proposalBodies: map[common.Hash]*proposalBodyMsg{proposalID: {
			ProposalID: proposalID, BodyHash: bodyHash, BodySize: 1, Number: 1,
			ViewNumber: 1, ViewID: viewID, LeaderID: "leader", Manifest: []byte{1},
		}},
		proposalAssemblies: map[common.Hash]*proposalAssemblyState{proposalID: {
			manifest:     &proposalDataManifest{TransactionHashes: []common.Hash{valid.Hash()}},
			positions:    map[common.Hash]int{valid.Hash(): 0},
			transactions: make(types.Transactions, 1),
			missingCount: 1,
		}},
	}
	_, err = service.mergeProposalRepair(&proposalBodyMsg{
		Type: proposalBodyMsgRepairData, ProposalID: proposalID, BodyHash: bodyHash,
		BodySize: 1, Number: 1, ViewNumber: 1, ViewID: viewID, LeaderID: "leader",
		MissingTxHashes:  []common.Hash{valid.Hash(), outside.Hash()},
		TransactionBytes: [][]byte{validBytes, outsideBytes},
	})
	if err == nil {
		t.Fatal("repair containing an out-of-manifest hash was accepted")
	}
	state := service.proposalAssemblies[proposalID]
	if state.missingCount != 1 || state.transactions[0] != nil || len(service.proposalBodies[proposalID].TransactionBytes) != 0 {
		t.Fatal("rejected repair partially mutated the proposal assembly")
	}
}

func TestProposalRepairWaitTimeoutCoversMaxCountRequestSchedule(t *testing.T) {
	transactionLimit := int(params.FairHotstuffWorkLimits().Transactions)
	windowCount := (transactionLimit + proposalRepairMaxHashes - 1) / proposalRepairMaxHashes
	want := proposalBodyRequestAfter + time.Duration(windowCount-1)*proposalBodyRequestInterval + proposalRepairNetworkMargin
	if got := proposalRepairWaitTimeout(transactionLimit); got != want {
		t.Fatalf("max-count repair timeout = %s, want %s", got, want)
	}
	if want > proposalBodyWaitMaxTimeout {
		t.Fatalf("max-count repair timeout %s exceeds bounded wait %s", want, proposalBodyWaitMaxTimeout)
	}
	if got := proposalRepairWaitTimeout(transactionLimit + 1); got != want {
		t.Fatalf("over-limit repair timeout = %s, want bounded consensus maximum %s", got, want)
	}
}

func TestDecodeProposalDataManifestAppliesConsensusCountLimitsFirst(t *testing.T) {
	limits := params.FairHotstuffWorkLimits()
	tests := []struct {
		name   string
		want   string
		mutate func(*proposalDataManifest)
	}{
		{
			name: "transactions",
			want: "transaction count",
			mutate: func(manifest *proposalDataManifest) {
				manifest.TransactionHashes = make([]common.Hash, int(limits.Transactions)+1)
			},
		},
		{
			name: "admission batches",
			want: "admission batch count",
			mutate: func(manifest *proposalDataManifest) {
				batch := &types.CommonTxAdmissionBatch{ChainID: big.NewInt(1)}
				manifest.CommonTxAdmissionBatches = make([]*types.CommonTxAdmissionBatch, int(limits.CommonTxAdmissionBatches)+1)
				for index := range manifest.CommonTxAdmissionBatches {
					manifest.CommonTxAdmissionBatches[index] = batch
				}
			},
		},
		{
			name: "admission references",
			want: "admission reference count",
			mutate: func(manifest *proposalDataManifest) {
				manifest.CommonTxAdmissionRefs = make([]types.CommonTxAdmissionRef, int(limits.CommonTxAdmissionRefs)+1)
			},
		},
		{
			name: "rewards",
			want: "reward count",
			mutate: func(manifest *proposalDataManifest) {
				reward := &types.CommonTxReward{ApproverReward: new(big.Int), Burn: new(big.Int)}
				manifest.CommonTxRewards = make([]*types.CommonTxReward, int(limits.CommonTxRewards)+1)
				for index := range manifest.CommonTxRewards {
					manifest.CommonTxRewards[index] = reward
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := &proposalDataManifest{Header: &types.Header{
				Number:     big.NewInt(1),
				Difficulty: big.NewInt(1),
			}}
			test.mutate(manifest)
			encoded, err := rlp.EncodeToBytes(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeProposalDataManifest(encoded); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("oversized %s error = %v, want %q limit rejection", test.name, err, test.want)
			}
		})
	}
}
