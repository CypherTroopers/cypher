package reconfig

import (
	"bytes"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb/leveldb"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet/network"
	"github.com/cypherium/cypher/trie"
)

type manifestRelayFixture struct {
	leader, donor, receiver *Service
	wire                    *proposalBodyMsg
	encoded                 []byte
}

func newManifestRelayFixture(t *testing.T) *manifestRelayFixture {
	t.Helper()
	f := newFHSEpochTestFixture(t)
	services := make([]*Service, 3)
	for i := range services {
		db := rawdb.NewMemoryDatabase()
		t.Cleanup(func() { db.Close() })
		secret := new(bls.SecretKey)
		if err := secret.Deserialize(f.keys[i].Serialize()); err != nil {
			t.Fatal(err)
		}
		address := f.committee.List[i].Address
		services[i] = &Service{
			chainConfig: f.service.chainConfig, kbc: f.service.kbc, currentView: f.service.currentView,
			netService:         &netService{serverID: address, serverAddress: address},
			proposalBodySecret: secret, consensusPublic: f.public[i],
			fhsStore:             newFHSSafetyStore(db, f.service.ChainID(), f.genesisHash),
			proposalBodies:       make(map[common.Hash]*proposalBodyMsg),
			verifiedProposalByID: make(map[common.Hash]*core.VerifiedProposal),
			fhsCertifiedByID:     make(map[common.Hash]*fhsCertifiedProposal),
		}
	}
	tx := testSignedProposalRepairTransaction(t)
	block := types.NewBlock(&types.Header{
		ParentHash: common.HexToHash("0x01"), Number: big.NewInt(1), Difficulty: big.NewInt(1),
		GasLimit: 30_000_000, KeyHash: f.current.Hash(),
	}, types.Transactions{tx}, nil, nil, new(trie.Trie))
	admission := &types.CommonTxAdmissionBatch{
		ChainID: f.service.chainConfig.ChainID, GenesisHash: f.genesisHash,
		Miner: common.HexToAddress("0x42"), Timestamp: 1,
		TxHashes: []common.Hash{tx.Hash()}, Signature: make([]byte, 65),
	}
	admission.TxRoot = types.DeriveCommonTxAdmissionTxRoot(admission.TxHashes)
	admission.AdmissionID = types.CommonTxAdmissionID(admission)
	reward := &types.CommonTxReward{TxHash: tx.Hash(), Approver: admission.Miner, ApproverReward: new(big.Int), Burn: new(big.Int)}
	block.SetCommonTxData([]*types.CommonTxAdmissionBatch{admission}, []types.CommonTxAdmissionRef{{}}, []*types.CommonTxReward{reward})
	encoded := block.EncodeToBytes()
	ref, err := types.NewHotstuffProposalRefWithProof(f.service.ChainID(), 21, common.HexToHash("0x21"), services[0].Self(), block, encoded, nil, common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := encodeProposalDataManifestForConfig(f.service.chainConfig, block)
	if err != nil {
		t.Fatal(err)
	}
	wire := &proposalBodyMsg{
		Type: proposalBodyMsgManifest, ProposalID: ref.ProposalID(), BodyHash: ref.BodyHash, BodySize: ref.BodySize,
		Number: ref.Number, ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
		ProposalKeyHash: ref.KeyHash, Manifest: manifest,
	}
	for _, s := range services {
		s.activeHighQCValidation = &highQCValidationControl{authorized: map[common.Hash]proposalBodyAuthority{
			ref.ProposalID(): {key: hotstuff.FHSProposalValidationKey{
				ProposalID: ref.ProposalID(), ViewNumber: ref.ViewNumber, ViewID: ref.ViewID, LeaderID: ref.LeaderID,
			}, keyHash: ref.KeyHash},
		}}
	}
	services[1].resolveTxQUICTransaction = func(hash common.Hash) (*types.Transaction, error) {
		if hash == tx.Hash() {
			return tx, nil
		}
		return nil, nil
	}
	if err := services[0].sealProposalBody(wire); err != nil {
		t.Fatal(err)
	}
	services[1].handleProposalBodyMsg(&network.ServerIdentity{Address: network.Address(wire.From)}, wire)
	if body := services[1].getProposalBody(ref.ProposalID()); body == nil || !bytes.Equal(body.EncodedBlock, encoded) {
		t.Fatal("healthy donor did not reconstruct the leader's authenticated proposal")
	}
	return &manifestRelayFixture{leader: services[0], donor: services[1], receiver: services[2], wire: wire, encoded: encoded}
}

func (f *manifestRelayFixture) relay(t *testing.T, body *proposalBodyMsg) *proposalBodyMsg {
	t.Helper()
	manifest, err := f.donor.proposalManifestForRepair(body.ProposalID, body)
	if err != nil {
		t.Fatal(err)
	}
	relay := cloneProposalBodyEnvelope(body)
	relay.Type, relay.Manifest = proposalBodyMsgManifest, manifest
	if err := f.donor.sealProposalBody(relay); err != nil {
		t.Fatal(err)
	}
	return relay
}

func TestFHSManifestRelayRepairsMissingTransactionWithoutLeader(t *testing.T) {
	f := newManifestRelayFixture(t)
	body := f.donor.getProposalBody(f.wire.ProposalID)
	relay := f.relay(t, body)
	peer := &network.ServerIdentity{Address: network.Address(f.donor.Self())}
	if err := f.receiver.verifyProposalBodySender(peer, relay); err != nil {
		t.Fatal(err)
	}
	if err := f.receiver.verifyProposalManifestAuthority(relay); err != nil {
		t.Fatal(err)
	}
	// The original proposer takes no further part. Only the healthy donor's
	// messages pass through the actual authenticated network-message handler.
	f.receiver.handleProposalBodyMsg(peer, relay)
	snapshot := f.receiver.proposalBodySnapshotForWait(relay.ProposalID)
	if !snapshot.hasManifest || snapshot.missingCount != 1 {
		t.Fatal("relay discarded the manifest needed to request the missing transaction")
	}
	missing := f.receiver.proposalMissingHashes(relay.ProposalID)
	hashes, transactions, err := f.donor.proposalRepairTransactions(body, missing)
	if err != nil {
		t.Fatal(err)
	}
	response := cloneProposalBodyEnvelope(body)
	response.Type = proposalBodyMsgRepairData
	response.MissingTxHashes, response.TransactionBytes = hashes, transactions
	if err := f.donor.sealProposalBody(response); err != nil {
		t.Fatal(err)
	}
	f.receiver.handleProposalBodyMsg(peer, response)
	got := f.receiver.getProposalBody(relay.ProposalID)
	if got == nil || !bytes.Equal(got.EncodedBlock, f.encoded) {
		t.Fatal("donor repair did not recover the exact leader proposal")
	}
}

func TestFHSManifestRelayRepairsFromDonorAheadOfReceiver(t *testing.T) {
	f := newManifestRelayFixture(t)
	queue := newPeerQueues()
	t.Cleanup(queue.close)
	donorNet := f.donor.netService
	donorNet.chainConfig = f.donor.chainConfig
	donorNet.backend = f.donor
	donorNet.curBlockN = f.wire.Number + 5
	donorNet.ackMap = make(map[string]*ackInfo)
	donorNet.idQueues = map[string]*peerQueues{f.receiver.Self(): queue}
	request := cloneProposalBodyEnvelope(f.wire)
	request.Type = proposalBodyMsgRepairRequest
	for _, phase := range []string{"manifest", "transactions"} {
		if phase == "transactions" {
			request.MissingTxHashes = f.receiver.proposalMissingHashes(request.ProposalID)
			if len(request.MissingTxHashes) != 1 {
				t.Fatal("historical relay did not retain the missing-TX manifest")
			}
		}
		if err := f.receiver.sealProposalBody(request); err != nil {
			t.Fatal(err)
		}
		message := &networkMsg{Pmsg: request}
		if donorNet.IgnoreMsg(message) {
			t.Fatalf("donor ahead of the receiver discarded historical %s request", phase)
		}
		// Exercise the real inbound height filter, authentication, durable/cache
		// lookup and response queue. The same filter guards the outbound lane.
		donorNet.handleNetworkMsgAck(&network.Envelope{
			ServerIdentity: &network.ServerIdentity{Address: network.Address(f.receiver.Self())}, Msg: message,
		})
		var response *networkMsg
		select {
		case response = <-queue.nextBulk:
		case response = <-queue.nextMetadata:
		case <-time.After(time.Second):
			t.Fatalf("historical %s request produced no response", phase)
		}
		queue.release(response)
		if donorNet.IgnoreMsg(response) {
			t.Fatalf("donor's outbound filter discarded historical %s response", phase)
		}
		f.receiver.handleProposalBodyMsg(&network.ServerIdentity{Address: network.Address(f.donor.Self())}, response.Pmsg)
	}
	if body := f.receiver.getProposalBody(f.wire.ProposalID); body == nil || !bytes.Equal(body.EncodedBlock, f.encoded) {
		t.Fatal("historical donor repair did not reconstruct the original proposal")
	}
}

func TestFHSManifestRelayRejectsDonorTamperingBeforeCachePublication(t *testing.T) {
	f := newManifestRelayFixture(t)
	valid := f.relay(t, f.donor.getProposalBody(f.wire.ProposalID))
	peer := &network.ServerIdentity{Address: network.Address(f.donor.Self())}
	for _, attack := range []string{"manifest", "missing leader signature", "donor signature"} {
		t.Run(attack, func(t *testing.T) {
			bad := cloneProposalBodyMsg(valid)
			switch attack {
			case "manifest":
				manifest, err := decodeProposalDataManifestForConfig(f.receiver.chainConfig, bad.Manifest)
				if err != nil {
					t.Fatal(err)
				}
				manifest.Header.Extra = []byte("poisoned by repair donor")
				bad.Manifest, err = rlp.EncodeToBytes(manifest)
				if err != nil {
					t.Fatal(err)
				}
			case "missing leader signature":
				bad.ManifestAuthSig = nil
			case "donor signature":
				if err := signProposalManifest(f.donor.ChainID(), bad, f.donor.proposalBodySecret); err != nil {
					t.Fatal(err)
				}
			}
			// The donor is an authorized committee member and can sign its own
			// valid transport envelope, but cannot replace the leader's proof.
			if err := f.donor.sealProposalBody(bad); err != nil {
				t.Fatal(err)
			}
			if err := f.receiver.verifyProposalBodySender(peer, bad); err != nil {
				t.Fatal(err)
			}
			if err := f.receiver.verifyProposalManifestSignature(bad); err == nil {
				t.Fatal("authorized donor replaced the leader's manifest")
			}
			f.receiver.handleProposalBodyMsg(peer, bad)
			if f.receiver.getProposalBody(valid.ProposalID) != nil {
				t.Fatal("tampered relay poisoned the proposal cache")
			}
		})
	}
	f.receiver.handleProposalBodyMsg(peer, valid)
	if snapshot := f.receiver.proposalBodySnapshotForWait(valid.ProposalID); !snapshot.hasManifest || snapshot.missingCount != 1 {
		t.Fatal("rejected donor messages prevented subsequent valid repair")
	}
}

func TestFHSManifestRelayLeaderSignatureSurvivesDonorRestart(t *testing.T) {
	f := newManifestRelayFixture(t)
	body := f.donor.getProposalBody(f.wire.ProposalID)
	path := filepath.Join(t.TempDir(), "donor-content")
	disk, err := leveldb.New(path, 1, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disk.Close() })
	f.donor.fhsStore = newFHSSafetyStore(disk, f.donor.ChainID(), common.HexToHash("0xf105"))
	// Store the body through its ordinary validation/persistence entry point.
	if err := f.donor.storeProposalBody(body); err != nil {
		t.Fatal(err)
	}
	if err := disk.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err = leveldb.New(path, 1, 8, "")
	if err != nil {
		t.Fatal(err)
	}
	f.donor.fhsStore = newFHSSafetyStore(disk, f.donor.ChainID(), common.HexToHash("0xf105"))
	f.donor.proposalBodies = make(map[common.Hash]*proposalBodyMsg)
	f.donor.proposalAssemblies = nil
	f.donor.resolveTxQUICTransaction = nil
	restored, durable, err := f.donor.proposalBodyForRepairRequest(f.wire)
	if err != nil || !durable || restored == nil {
		t.Fatalf("restarted donor could not load durable body: durable=%t err=%v", durable, err)
	}
	if !bytes.Equal(restored.ManifestAuthSig, body.ManifestAuthSig) || len(restored.ManifestAuthSig) == 0 {
		t.Fatal("restart lost the original leader's manifest signature")
	}
	relay := f.relay(t, restored)
	f.receiver.handleProposalBodyMsg(&network.ServerIdentity{Address: network.Address(f.donor.Self())}, relay)
	if snapshot := f.receiver.proposalBodySnapshotForWait(relay.ProposalID); !snapshot.hasManifest || snapshot.missingCount != 1 {
		t.Fatal("restarted donor could not initiate missing-transaction repair")
	}
}

func TestFHSManifestRelaySignatureBindsProposalAndProofContext(t *testing.T) {
	f := newManifestRelayFixture(t)
	valid := f.relay(t, f.donor.getProposalBody(f.wire.ProposalID))
	for _, mutate := range []struct {
		name  string
		apply func(*proposalBodyMsg)
	}{
		{"proposal", func(b *proposalBodyMsg) { b.ProposalID[0] ^= 1 }},
		{"body", func(b *proposalBodyMsg) { b.BodyHash[0] ^= 1 }},
		{"size", func(b *proposalBodyMsg) { b.BodySize++ }},
		{"number", func(b *proposalBodyMsg) { b.Number++ }},
		{"view", func(b *proposalBodyMsg) { b.ViewNumber++ }},
		{"view identity", func(b *proposalBodyMsg) { b.ViewID[0] ^= 1 }},
		{"leader", func(b *proposalBodyMsg) { b.LeaderID = f.donor.Self() }},
		{"committee", func(b *proposalBodyMsg) { b.ProposalKeyHash[0] ^= 1 }},
		{"extra", func(b *proposalBodyMsg) { b.Extra = []byte{1} }},
		{"parent proof", func(b *proposalBodyMsg) { b.ParentQC = []byte{1} }},
		{"activation proof", func(b *proposalBodyMsg) { b.KeyActivationProof = []byte{1} }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			bad := cloneProposalBodyMsg(valid)
			mutate.apply(bad)
			if err := f.receiver.verifyProposalManifestSignature(bad); err == nil {
				t.Fatal("leader signature accepted a changed proposal or proof")
			}
		})
	}
}
