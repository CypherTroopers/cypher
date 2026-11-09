package reconfig

import (
	"bytes"
	"fmt"
	"net"
	"strconv"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

// tallyLeaderFaults counts one fault for the deterministic leader of each
// timeout certificate. Proofs must belong to the parent key block and be
// ordered by timed-out view.
func tallyLeaderFaults(config *params.ChainConfig, committeeSize int, parentHash, committeeHash common.Hash, proofs []*hotstuff.TimeoutCertificate) ([]uint32, error) {
	if config == nil || config.ChainID == nil || !config.FairHotstuff {
		return nil, fmt.Errorf("permissionless faults require Fair HotStuff")
	}
	if committeeSize <= 0 {
		return nil, fmt.Errorf("empty committee")
	}
	faults := make([]uint32, committeeSize)
	var previous uint64
	for i, proof := range proofs {
		if proof == nil {
			return nil, fmt.Errorf("nil timeout proof %d", i)
		}
		statement := proof.Statement
		if statement.KeyHash != parentHash || statement.CommitteeHash != committeeHash {
			return nil, fmt.Errorf("timeout proof %d belongs to a different committee", i)
		}
		if statement.ChainID != config.ChainID.Uint64() {
			return nil, fmt.Errorf("timeout proof %d chain mismatch", i)
		}
		if i > 0 && statement.TimedOutView <= previous {
			return nil, fmt.Errorf("timeout proofs are not strictly increasing")
		}
		previous = statement.TimedOutView
		leader, err := fairHotstuffLeaderIndex(config.FairHotstuffSeed, statement.ChainID, statement.TimedOutView, committeeHash, committeeSize)
		if err != nil {
			return nil, err
		}
		faults[leader]++
	}
	return faults, nil
}

// evictIndex returns the seat replaced by the next external PoW winner.
// Certified leader faults win. With none, the seat is a deterministic
// function of the parent key hash so a healthy committee still opens a seat.
func evictIndex(config *params.ChainConfig, committee *bftview.Committee, parentHash, committeeHash common.Hash, faults []uint32) (int, error) {
	if committee == nil || len(committee.List) == 0 {
		return 0, fmt.Errorf("empty committee")
	}
	if len(faults) != len(committee.List) {
		return 0, fmt.Errorf("fault vector length %d does not match committee %d", len(faults), len(committee.List))
	}
	maxFault := uint32(0)
	for _, count := range faults {
		if count > maxFault {
			maxFault = count
		}
	}
	if maxFault == 0 {
		if config == nil || config.ChainID == nil {
			return 0, fmt.Errorf("missing chain id for seat rotation")
		}
		index, err := fairHotstuffLeaderIndex(parentHash, config.ChainID.Uint64(), 1, committeeHash, len(committee.List))
		if err != nil {
			return 0, err
		}
		return int(index), nil
	}
	chosen := -1
	var chosenKey []byte
	for index, count := range faults {
		member := committee.List[index]
		if count != maxFault || member == nil || member.Public == "" {
			continue
		}
		key := common.FromHex(member.Public)
		if len(key) == 0 {
			key = []byte(member.Public)
		}
		if chosen < 0 || bytes.Compare(key, chosenKey) < 0 {
			chosen = index
			chosenKey = key
		}
	}
	if chosen < 0 {
		return 0, fmt.Errorf("no committee seat matches the fault tally")
	}
	return chosen, nil
}

func decodeTimeoutProofs(raw [][]byte) ([]*hotstuff.TimeoutCertificate, error) {
	proofs := make([]*hotstuff.TimeoutCertificate, len(raw))
	for i, item := range raw {
		proof, err := hotstuff.DecodeTimeoutCertificate(item)
		if err != nil {
			return nil, fmt.Errorf("timeout proof %d: %w", i, err)
		}
		proofs[i] = proof
	}
	return proofs, nil
}

func encodeTimeoutProofs(proofs []*hotstuff.TimeoutCertificate) ([][]byte, error) {
	raw := make([][]byte, len(proofs))
	for i, proof := range proofs {
		encoded, err := hotstuff.EncodeTimeoutCertificate(proof)
		if err != nil {
			return nil, err
		}
		raw[i] = encoded
	}
	return raw, nil
}

func committeeNodeFromCandidate(candidate *types.Candidate) (*common.Cnode, error) {
	if candidate == nil || candidate.PubKey == "" || candidate.Coinbase == "" || candidate.KeyCandidate == nil {
		return nil, fmt.Errorf("permissionless candidate is incomplete")
	}
	if candidate.Port <= 0 {
		return nil, fmt.Errorf("permissionless candidate has no committee port")
	}
	return &common.Cnode{
		Address:  net.JoinHostPort(net.IP(candidate.IP).String(), strconv.Itoa(candidate.Port)),
		CoinBase: candidate.Coinbase,
		Public:   candidate.PubKey,
	}, nil
}

func verifyTimeoutProofs(committee *bftview.Committee, committeeHash common.Hash, proofs []*hotstuff.TimeoutCertificate) error {
	if len(proofs) == 0 {
		return nil
	}
	keys := committee.ToBlsPublicKeys(committeeHash)
	if len(keys) != len(committee.List) {
		return fmt.Errorf("committee public keys are incomplete")
	}
	for _, key := range keys {
		if key == nil {
			return fmt.Errorf("committee public key is invalid")
		}
	}
	threshold := hotstuff.CalcThreshold(len(keys))
	for i, proof := range proofs {
		if err := hotstuff.VerifyTimeoutCertificate(proof, keys, threshold); err != nil {
			return fmt.Errorf("timeout proof %d: %w", i, err)
		}
	}
	return nil
}

// applyPermissionlessSeat copies the parent committee and replaces the evicted
// seat with the external candidate. The returned committee shares no slice
// with the parent.
func applyPermissionlessSeat(config *params.ChainConfig, parent *bftview.Committee, parentHash, committeeHash common.Hash, candidate *types.Candidate, proofs []*hotstuff.TimeoutCertificate) (*bftview.Committee, *common.Cnode, int, error) {
	if err := verifyTimeoutProofs(parent, committeeHash, proofs); err != nil {
		return nil, nil, 0, err
	}
	faults, err := tallyLeaderFaults(config, len(parent.List), parentHash, committeeHash, proofs)
	if err != nil {
		return nil, nil, 0, err
	}
	index, err := evictIndex(config, parent, parentHash, committeeHash, faults)
	if err != nil {
		return nil, nil, 0, err
	}
	incoming, err := committeeNodeFromCandidate(candidate)
	if err != nil {
		return nil, nil, 0, err
	}
	next := parent.Copy()
	evicted, err := next.Replace(index, incoming)
	if err != nil {
		return nil, nil, 0, err
	}
	return next, evicted, index, nil
}

// checkPermissionlessKeyblock accepts a key block whose seat replacement
// recomputes to the same committee, incoming member, and outgoing member.
func checkPermissionlessKeyblock(config *params.ChainConfig, parent *bftview.Committee, parentBlock, keyblock *types.KeyBlock, candidate *types.Candidate, proposalView uint64) (*bftview.Committee, *common.Cnode, error) {
	if parent == nil || parentBlock == nil || keyblock == nil || !keyblock.PermissionlessSeat() {
		return nil, nil, fmt.Errorf("permissionless key block is incomplete")
	}
	if parent.RlpHash() != parentBlock.CommitteeHash() {
		return nil, nil, fmt.Errorf("parent committee hash mismatch")
	}
	proofs, err := decodeTimeoutProofs(keyblock.FaultProofBytes())
	if err != nil {
		return nil, nil, err
	}
	next, evicted, _, err := applyPermissionlessSeat(config, parent, parentBlock.Hash(), parentBlock.CommitteeHash(), candidate, proofs)
	if err != nil {
		return nil, nil, err
	}
	if next.RlpHash() != keyblock.CommitteeHash() {
		return nil, nil, fmt.Errorf("permissionless committee hash mismatch")
	}
	if evicted.Public != keyblock.OutPubKey() || evicted.CoinBase != trimBadMarker(keyblock.OutAddress(0)) {
		return nil, nil, fmt.Errorf("permissionless outgoing member mismatch")
	}
	incomingIndex := indexOfPublic(next, candidate.PubKey)
	if incomingIndex < 0 {
		return nil, nil, fmt.Errorf("permissionless incoming member is missing")
	}
	incoming := next.List[incomingIndex]
	if incoming.Public != keyblock.InPubKey() || incoming.CoinBase != keyblock.InAddress() {
		return nil, nil, fmt.Errorf("permissionless incoming member mismatch")
	}
	// The proposal view is still elected from the parent committee. The seat
	// replacement takes effect for views after this key block.
	leaderIndex, err := fairHotstuffLeaderIndex(config.FairHotstuffSeed, config.ChainID.Uint64(), proposalView, parentBlock.CommitteeHash(), len(parent.List))
	if err != nil {
		return nil, nil, err
	}
	leader := parent.List[leaderIndex]
	if leader == nil || leader.Public != keyblock.LeaderPubKey() || leader.CoinBase != keyblock.LeaderAddress() {
		return nil, nil, fmt.Errorf("permissionless leader mismatch")
	}
	return next, evicted, nil
}

func trimBadMarker(address string) string {
	if len(address) > 0 && address[0] == '*' {
		return address[1:]
	}
	return address
}

func indexOfPublic(committee *bftview.Committee, public string) int {
	if committee == nil {
		return -1
	}
	for index, member := range committee.List {
		if member != nil && member.Public == public {
			return index
		}
	}
	return -1
}

func candidateIsMember(committee *bftview.Committee, candidate *types.Candidate) bool {
	return candidate != nil && indexOfPublic(committee, candidate.PubKey) >= 0
}

// selectExternalCandidate returns the lowest-nonce candidate for this key
// number and parent whose public key is not already on the committee.
func selectExternalCandidate(candidates []*types.Candidate, committee *bftview.Committee, keyNumber uint64, parentHash common.Hash) *types.Candidate {
	var best *types.Candidate
	for _, candidate := range candidates {
		if candidate == nil || candidate.KeyCandidate == nil || candidate.PubKey == "" {
			continue
		}
		if candidate.KeyCandidate.Number == nil || candidate.KeyCandidate.Number.Uint64() != keyNumber {
			continue
		}
		if candidate.KeyCandidate.ParentHash != parentHash {
			continue
		}
		if candidateIsMember(committee, candidate) {
			continue
		}
		if best == nil || candidate.KeyCandidate.Nonce.Uint64() < best.KeyCandidate.Nonce.Uint64() {
			best = candidate
		}
	}
	return best
}

func missingLocalTimeout(local, embedded []*hotstuff.TimeoutCertificate) error {
	have := make(map[uint64]struct{}, len(embedded))
	for _, proof := range embedded {
		if proof == nil {
			continue
		}
		have[proof.Statement.TimedOutView] = struct{}{}
	}
	for _, proof := range local {
		if proof == nil {
			continue
		}
		if _, ok := have[proof.Statement.TimedOutView]; !ok {
			return fmt.Errorf("key block omits timeout view %d", proof.Statement.TimedOutView)
		}
	}
	return nil
}

func (keyS *keyService) verifyPermissionlessKeyBlock(keyblock *types.KeyBlock, candidate *types.Candidate, proposalView uint64) error {
	if keyblock == nil || !keyblock.PermissionlessSeat() {
		return fmt.Errorf("permissionless key block is incomplete")
	}
	if !keyS.permissionlessEnabled() {
		return fmt.Errorf("permissionless key block requires Fair HotStuff without a fixed committee")
	}
	parentBlock := keyS.kbc.GetBlockByHash(keyblock.ParentHash())
	if parentBlock == nil {
		return fmt.Errorf("permissionless parent key block is missing")
	}
	parent := bftview.LoadMember(parentBlock.NumberU64(), parentBlock.Hash(), true)
	if parent == nil {
		return fmt.Errorf("permissionless parent committee is missing")
	}
	var next *bftview.Committee
	if keyblock.HasNewNode() {
		if candidate == nil || candidate.KeyCandidate == nil {
			return fmt.Errorf("permissionless pow reconfig requires its candidate")
		}
		if keyS.engine != nil {
			checked := types.DecodeToCandidate(candidate.EncodeToBytes())
			if checked == nil || checked.KeyCandidate == nil {
				return fmt.Errorf("invalid permissionless candidate encoding")
			}
			checked.KeyCandidate.BlockType = keyblock.BlockType()
			if err := keyS.engine.VerifyCandidate(keyS.kbc, checked); err != nil {
				return err
			}
			candidate = checked
		}
		embedded, err := decodeTimeoutProofs(keyblock.FaultProofBytes())
		if err != nil {
			return err
		}
		if service, ok := keyS.s.(*Service); ok {
			if err := missingLocalTimeout(service.epochTimeoutProofs(parentBlock.Hash()), embedded); err != nil {
				return err
			}
		}
		rebuilt, _, err := checkPermissionlessKeyblock(keyS.config, parent, parentBlock, keyblock, candidate, proposalView)
		if err != nil {
			return err
		}
		next = rebuilt
	} else {
		if len(keyblock.FaultProofBytes()) != 0 {
			return fmt.Errorf("permissionless time reconfig carries fault proofs")
		}
		if keyblock.CommitteeHash() != parent.RlpHash() {
			return fmt.Errorf("permissionless time reconfig changed the committee")
		}
		leaderIndex, err := fairHotstuffLeaderIndex(keyS.config.FairHotstuffSeed, keyS.config.ChainID.Uint64(), proposalView, parent.RlpHash(), len(parent.List))
		if err != nil {
			return err
		}
		leader := parent.List[leaderIndex]
		if leader == nil || leader.Public != keyblock.LeaderPubKey() || leader.CoinBase != keyblock.LeaderAddress() {
			return fmt.Errorf("permissionless time reconfig leader mismatch")
		}
		next = parent.Copy()
	}
	if bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true) == nil {
		if !next.Store(keyblock) {
			return fmt.Errorf("permissionless key block failed to store its committee")
		}
	}
	keyS.s.syncCommittee(next, keyblock)
	return nil
}

func (keyS *keyService) buildPermissionlessKeyBlock(parent *bftview.Committee, leaderIndex uint, txParentNumber uint64, header *types.KeyBlockHeader) (*types.KeyBlock, *bftview.Committee, *types.Candidate, error) {
	if parent == nil || header == nil || int(leaderIndex) >= len(parent.List) || parent.List[leaderIndex] == nil {
		return nil, nil, nil, fmt.Errorf("permissionless leader index %d is outside the committee", leaderIndex)
	}
	leader := parent.List[leaderIndex]
	var listed []*types.Candidate
	if keyS.candidatepool != nil {
		listed = keyS.candidatepool.Content()
	}
	best := selectExternalCandidate(listed, parent, header.Number.Uint64(), header.ParentHash)
	var proofs []*hotstuff.TimeoutCertificate
	if service, ok := keyS.s.(*Service); ok {
		proofs = service.epochTimeoutProofs(header.ParentHash)
	}
	header.T_Number = txParentNumber
	if best == nil {
		header.BlockType = types.TimeReconfig
		header.CommitteeHash = parent.RlpHash()
		keyblock := types.NewKeyBlock(header).WithBody(parent.In().Public, parent.In().CoinBase, "", "", leader.Public, leader.CoinBase)
		keyblock.SetPermissionlessFaults(nil)
		return keyblock, parent.Copy(), nil, nil
	}
	next, evicted, _, err := applyPermissionlessSeat(keyS.config, parent, header.ParentHash, parent.RlpHash(), best, proofs)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err := encodeTimeoutProofs(proofs)
	if err != nil {
		return nil, nil, nil, err
	}
	candidateHeader := best.KeyCandidate
	header.BlockType = types.PowReconfig
	header.Time, header.Difficulty = candidateHeader.Time, candidateHeader.Difficulty
	header.MixDigest, header.Nonce = candidateHeader.MixDigest, candidateHeader.Nonce
	header.CommitteeHash = next.RlpHash()
	keyblock := types.NewKeyBlock(header).WithBody(best.PubKey, best.Coinbase, evicted.Public, evicted.CoinBase, leader.Public, leader.CoinBase)
	keyblock.SetPermissionlessFaults(raw)
	return keyblock, next, best, nil
}

type persistedEpochTimeouts struct {
	KeyHash common.Hash
	Proofs  [][]byte
}

func (s *Service) loadEpochTimeouts() {
	if s == nil || s.epochTimeoutReady {
		return
	}
	s.epochTimeoutReady = true
	if s.epochTimeouts == nil {
		s.epochTimeouts = make(map[uint64]*hotstuff.TimeoutCertificate)
	}
	if s.fhsStore == nil || s.fhsStore.db == nil {
		return
	}
	blob, err := rawdb.ReadFHSEpochTimeouts(s.fhsStore.db)
	if err != nil || len(blob) == 0 {
		return
	}
	var stored persistedEpochTimeouts
	if err := rlp.DecodeBytes(blob, &stored); err != nil {
		return
	}
	s.epochTimeoutKey = stored.KeyHash
	for _, raw := range stored.Proofs {
		proof, err := hotstuff.DecodeTimeoutCertificate(raw)
		if err != nil || proof == nil {
			continue
		}
		s.epochTimeouts[proof.Statement.TimedOutView] = proof
	}
}

func (s *Service) persistEpochTimeouts() {
	if s == nil || s.fhsStore == nil || s.fhsStore.db == nil {
		return
	}
	proofs := make([]*hotstuff.TimeoutCertificate, 0, len(s.epochTimeouts))
	for _, proof := range s.epochTimeouts {
		proofs = append(proofs, proof)
	}
	sortTimeoutProofs(proofs)
	raw, err := encodeTimeoutProofs(proofs)
	if err != nil {
		return
	}
	blob, err := rlp.EncodeToBytes(&persistedEpochTimeouts{KeyHash: s.epochTimeoutKey, Proofs: raw})
	if err != nil {
		return
	}
	_ = rawdb.WriteFHSEpochTimeouts(s.fhsStore.db, blob)
}

func sortTimeoutProofs(proofs []*hotstuff.TimeoutCertificate) {
	for i := 1; i < len(proofs); i++ {
		item := proofs[i]
		j := i
		for j > 0 && (proofs[j-1] == nil || item != nil && proofs[j-1].Statement.TimedOutView > item.Statement.TimedOutView) {
			proofs[j] = proofs[j-1]
			j--
		}
		proofs[j] = item
	}
}

func (s *Service) recordEpochTimeout(tc *hotstuff.TimeoutCertificate) {
	if s == nil || tc == nil {
		return
	}
	s.muEpochTimeout.Lock()
	defer s.muEpochTimeout.Unlock()
	s.loadEpochTimeouts()
	if s.epochTimeoutKey != tc.Statement.KeyHash {
		s.epochTimeoutKey = tc.Statement.KeyHash
		s.epochTimeouts = make(map[uint64]*hotstuff.TimeoutCertificate)
	}
	s.epochTimeouts[tc.Statement.TimedOutView] = hotstuff.CloneTimeoutCertificate(tc)
	s.persistEpochTimeouts()
}

func (s *Service) epochTimeoutProofs(keyHash common.Hash) []*hotstuff.TimeoutCertificate {
	if s == nil {
		return nil
	}
	s.muEpochTimeout.Lock()
	defer s.muEpochTimeout.Unlock()
	s.loadEpochTimeouts()
	if s.epochTimeoutKey != keyHash {
		return nil
	}
	proofs := make([]*hotstuff.TimeoutCertificate, 0, len(s.epochTimeouts))
	for _, proof := range s.epochTimeouts {
		proofs = append(proofs, hotstuff.CloneTimeoutCertificate(proof))
	}
	sortTimeoutProofs(proofs)
	return proofs
}

func (s *Service) resetEpochTimeouts() {
	if s == nil {
		return
	}
	s.muEpochTimeout.Lock()
	defer s.muEpochTimeout.Unlock()
	s.clearEpochTimeoutsLocked()
}

// discardClosedEpochTimeouts drops durable timeout proofs for a parent key that
// already has a child key on the local chain. KeyBlockDone clears them live; this
// covers restart after a crash between commit and that clear.
func (s *Service) discardClosedEpochTimeouts() {
	if s == nil || s.kbc == nil {
		return
	}
	s.muEpochTimeout.Lock()
	defer s.muEpochTimeout.Unlock()
	s.loadEpochTimeouts()
	if s.epochTimeoutKey == (common.Hash{}) {
		return
	}
	for block := s.kbc.CurrentBlock(); block != nil; {
		if block.ParentHash() == s.epochTimeoutKey {
			s.clearEpochTimeoutsLocked()
			return
		}
		if block.NumberU64() == 0 || block.ParentHash() == (common.Hash{}) {
			return
		}
		parent := s.kbc.GetBlockByHash(block.ParentHash())
		if parent == nil || parent.Hash() == block.Hash() {
			return
		}
		block = parent
	}
}

func (s *Service) clearEpochTimeoutsLocked() {
	s.epochTimeoutReady = true
	s.epochTimeoutKey = common.Hash{}
	s.epochTimeouts = make(map[uint64]*hotstuff.TimeoutCertificate)
	if s.fhsStore != nil && s.fhsStore.db != nil {
		_ = rawdb.DeleteFHSEpochTimeouts(s.fhsStore.db)
	}
}

func (s *Service) applyPermissionlessMembership(committee *bftview.Committee) {
	if s == nil || committee == nil || !s.fairHotstuffEnabled() || s.keyService == nil || !s.keyService.permissionlessEnabled() {
		return
	}
	if bftview.IamMember() < 0 {
		if s.isRunning() {
			log.Info("permissionless committee seat ended; consensus service stopping")
			s.setRunState(0)
			if s.pacetMakerTimer != nil {
				s.pacetMakerTimer.stop()
			}
			if s.netService != nil {
				s.netService.StartStop(false)
			}
		}
		return
	}
	if s.isRunning() {
		return
	}
	s.muConsensusIdentity.RLock()
	secret := s.proposalBodySecret
	public := s.consensusPublic
	s.muConsensusIdentity.RUnlock()
	if secret == nil || public == nil || s.netService == nil || s.netService.server == nil {
		log.Info("permissionless seat is waiting for a configured consensus identity")
		return
	}
	peers, err := s.fhsPeerAuthorizationWithCertifiedCarriers(committee)
	if err != nil {
		log.Error("permissionless membership peer list failed", "err", err)
		return
	}
	if err := s.netService.server.ConfigurePeerAuthentication(s.ChainID(), s.netService.serverAddress, secret.SerializeToHexStr(), public.SerializeToHexStr(), peers); err != nil {
		log.Error("permissionless membership authentication failed", "err", err)
		return
	}
	s.netService.setAuthenticatedPeerKeys(peers)
	s.setRunState(1)
	s.netService.StartStop(true)
	if s.pacetMakerTimer != nil {
		_ = s.pacetMakerTimer.start()
	}
	log.Info("permissionless committee seat started consensus")
}
