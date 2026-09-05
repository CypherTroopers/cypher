package reconfig

import (
	"bytes"
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/trie"
)

// The suffix is longer than the body cache but shorter than the independent
// finality-proof limit. Its last two views are the first consecutive pair.
func TestFHSBodyCacheDoesNotBoundCertifiedSuffix(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "live"
		if restart {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			f := newConvergenceFixture(t)
			f.replicas = f.replicas[:1]
			s := f.replicas[0]
			const count = 70
			var tip *fhsCertifiedProposal
			for i := 0; i < count; i++ {
				tip = f.proposal(t, tip, uint64(2*i+1), byte(i))
			}
			if err := s.adoptFHSHighQC(tip.qc, false, false); err != nil {
				t.Fatalf("adopt gapped suffix: %v", err)
			}
			if err := s.commitFHS2ChainForCertified(tip.qc); err != nil {
				t.Fatal(err)
			}
			if s.bc.CurrentBlockN() != 0 {
				t.Fatal("nonconsecutive QCs finalized a block")
			}
			if restart {
				resetBranchSafetyRuntime(s)
				s.proposalAssemblies = nil
				if err := s.loadFHSWAL(); err != nil {
					t.Fatalf("restore suffix beyond body cache capacity: %v", err)
				}
			}
			if len(s.fhsCertifiedByID) != count {
				t.Fatalf("retained certificates = %d, want %d", len(s.fhsCertifiedByID), count)
			}
			child := f.proposal(t, tip, tip.qc.Number+1, 0xff)
			if err := s.AdoptFHSHighQC(child.qc); err != nil {
				t.Fatalf("consecutive child cannot finalize retained suffix: %v", err)
			}
			if s.bc.CurrentBlockN() != count || s.bc.CurrentBlock().Hash() != tip.ref.BlockHash {
				t.Fatalf("final head = %d/%s, want %d/%s", s.bc.CurrentBlockN(), s.bc.CurrentBlock().Hash(), count, tip.ref.BlockHash)
			}
			first := s.bc.GetBlockByNumber(1)
			proof, present, err := core.DecodeFHSCommitProof(first)
			if err != nil || !present || len(proof.QCs) != count {
				t.Fatalf("first ancestor lost its complete proof: present=%t err=%v", present, err)
			}
			if err := s.bc.VerifyFHSCommitProof(first, proof); err != nil {
				t.Fatalf("persisted ancestor proof is invalid: %v", err)
			}
			s.muProposalBody.RLock()
			entries, used := s.proposalBodyCacheUsageLocked()
			s.muProposalBody.RUnlock()
			if entries > proposalBodyCacheMaxEntries || used > proposalBodyCacheLimitForConfig(s.chainConfig) {
				t.Fatalf("body cache exceeded its budget: entries=%d bytes=%d", entries, used)
			}
		})
	}
}

func TestFHSBodyCacheEvictionRetainsRepairableCertifiedProposal(t *testing.T) {
	f := newConvergenceFixture(t)
	f.replicas = f.replicas[:1]
	s := f.replicas[0]
	parent := f.proposal(t, nil, 1, 'p')
	child := f.proposal(t, parent, 3, 'c')
	original := s.getProposalBody(child.ref.ProposalID())
	if err := s.adoptFHSHighQC(child.qc, false, false); err != nil {
		t.Fatal(err)
	}
	// A QC is synchronous, while the content writer may not have completed.
	if err := rawdb.DeleteFHSProposal(s.fhsStore.db, child.ref.ProposalID()); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.DeleteFHSBody(s.fhsStore.db, child.ref.BodyHash); err != nil {
		t.Fatal(err)
	}
	s.muProposalBody.Lock()
	for s.proposalBodies[child.ref.ProposalID()] != nil {
		if !s.evictOldestProposalBodyLocked() {
			s.muProposalBody.Unlock()
			t.Fatal("certified body cannot be evicted")
		}
	}
	s.muProposalBody.Unlock()
	if s.getVerifiedProposal(child.ref.ProposalID()) == nil || s.fhsCertifiedByID[child.ref.ProposalID()] == nil {
		t.Fatal("body eviction discarded certified execution or QC")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := s.proposalBodyForHighQCStage(ctx, child.ref, 0)
	if err != nil || body == nil {
		t.Fatalf("recover certified body without durable content: %v", err)
	}
	if !bytes.Equal(body.EncodedBlock, original.EncodedBlock) || !bytes.Equal(body.ParentQC, original.ParentQC) {
		t.Fatal("reconstruction changed signed body or parent proof")
	}
	request := cloneProposalBodyEnvelope(original)
	request.Type = proposalBodyMsgRepairRequest
	repaired, _, err := s.proposalBodyForRepairRequest(request)
	if err != nil || repaired == nil || !bytes.Equal(repaired.EncodedBlock, original.EncodedBlock) {
		t.Fatalf("evicted certified body is not a repair donor: %v", err)
	}
	request.BodyHash = common.HexToHash("0xbad")
	if _, _, err := s.proposalBodyForRepairRequest(request); err == nil {
		t.Fatal("repair accepted mismatched commitment")
	}
	if s.getProposalBody(child.ref.ProposalID()) != nil {
		t.Fatal("repair repopulated the contested body cache")
	}
}

func TestFHSBodyCacheRepairSurvivesIndexEviction(t *testing.T) {
	s, body := testProposalSidecar(t)
	tx := testSignedProposalRepairTransaction(t)
	header := types.DecodeToBlock(body.EncodedBlock).Header()
	header.GasLimit = 30_000_000
	block := types.NewBlock(header, types.Transactions{tx}, nil, nil, new(trie.Trie))
	reward := &types.CommonTxReward{TxHash: tx.Hash(), Approver: common.HexToAddress("0x42"), ApproverReward: big.NewInt(1), Burn: new(big.Int)}
	block.SetCommonTxData(nil, nil, []*types.CommonTxReward{reward})
	body.EncodedBlock = block.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithProof(99, body.ViewNumber, body.ViewID, body.LeaderID, block, body.EncodedBlock, body.Extra, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	body.ProposalID, body.BodyHash, body.BodySize = ref.ProposalID(), ref.BodyHash, ref.BodySize
	body.KeyActivationProof = []byte("retained-activation-proof")
	if err := s.storeProposalBody(body); err != nil {
		t.Fatal(err)
	}
	// This fixture starts at the already-executed artifact boundary; the suffix
	// tests above exercise real signed-QC adoption and durable recovery.
	s.fhsCertifiedByID[body.ProposalID] = &fhsCertifiedProposal{ref: ref,
		verified: &core.VerifiedProposal{Block: block}, envelope: cloneProposalBodyEnvelope(body), originalHeader: block.Header()}
	request := cloneProposalBodyEnvelope(body)
	selected, _, err := s.proposalBodyForRepairRequest(request)
	if err != nil || selected == nil || len(selected.EncodedBlock) != 0 {
		t.Fatalf("select indexed repair donor: %v", err)
	}
	s.muProposalBody.Lock()
	s.evictProposalBodyLocked(body.ProposalID)
	s.muProposalBody.Unlock()
	// Finality mutates the live block header after certification. Rebuilding the
	// original body must use the retained original header, including on donors.
	block.SetFHSSignature([]byte{1}, []byte{1}, ref.ViewID, ref.LeaderID, ref.ViewNumber, ref.ExtraHash, ref.ParentQCID)
	hashes, transactions, err := s.proposalRepairTransactions(selected, []common.Hash{tx.Hash(), common.HexToHash("0xdead")})
	if err != nil || len(hashes) != 1 || hashes[0] != tx.Hash() || len(transactions) != 1 {
		t.Fatalf("transaction repair after index eviction: hashes=%v err=%v", hashes, err)
	}
	manifest, err := s.proposalManifestForRepair(body.ProposalID, selected)
	if err != nil {
		t.Fatalf("manifest repair after index eviction: %v", err)
	}
	expectedManifest, err := encodeProposalDataManifestForConfig(s.chainConfig, types.DecodeToBlock(body.EncodedBlock))
	if err != nil || !bytes.Equal(manifest, expectedManifest) {
		t.Fatalf("repaired manifest lost the original header or sidecars: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	recovered, err := s.waitProposalBodyForValidation(ctx, ref, 0)
	if err != nil || recovered == nil || !bytes.Equal(recovered.EncodedBlock, body.EncodedBlock) ||
		!bytes.Equal(recovered.Extra, body.Extra) || !bytes.Equal(recovered.KeyActivationProof, body.KeyActivationProof) {
		t.Fatalf("validation lost certified payload or proof metadata after eviction: %v", err)
	}
}

func TestFHSBodyCachePreservesOriginalHeaderMetadata(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "live"
		if restart {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			f := newConvergenceFixture(t)
			f.replicas = f.replicas[:1]
			s := f.replicas[0]
			seed := f.proposal(t, nil, 1, 'm')
			body := s.getProposalBody(seed.ref.ProposalID())
			block := types.DecodeToBlock(body.EncodedBlock)
			// The accepted body format permits existing header metadata, and
			// BodyHash commits these exact bytes even when QC installation later
			// replaces them on the executed block.
			block.SetFHSSignature([]byte{0x42}, []byte{1}, seed.ref.ViewID, seed.ref.LeaderID, 1, seed.ref.ExtraHash, seed.ref.ParentQCID)
			body.EncodedBlock = block.EncodeToBytes()
			ref, err := types.NewHotstuffProposalRefWithProof(s.ChainID(), 1, seed.ref.ViewID, seed.ref.LeaderID, block, body.EncodedBlock, body.Extra, seed.ref.ParentQCID)
			if err != nil {
				t.Fatal(err)
			}
			body.ProposalID, body.BodyHash, body.BodySize = ref.ProposalID(), ref.BodyHash, ref.BodySize
			if err := s.storeProposalBody(body); err != nil {
				t.Fatal(err)
			}
			qc := signFHSEpochProposalQC(t, &fhsEpochTestFixture{service: s, keys: f.keys, public: f.public}, ref)
			if err := s.adoptFHSHighQC(qc, false, false); err != nil {
				t.Fatalf("adopt accepted metadata-bearing proposal: %v", err)
			}
			if restart {
				resetBranchSafetyRuntime(s)
				s.proposalAssemblies = nil
				if err := s.loadFHSWAL(); err != nil {
					t.Fatal(err)
				}
			}
			s.muProposalBody.Lock()
			s.evictProposalBodyLocked(body.ProposalID)
			s.muProposalBody.Unlock()
			recovered, found, err := s.reconstructFHSCertifiedBody(body.ProposalID)
			if err != nil || !found || recovered == nil || !bytes.Equal(recovered.EncodedBlock, body.EncodedBlock) {
				t.Fatalf("certified reconstruction changed original header bytes: found=%t err=%v", found, err)
			}
		})
	}
}
