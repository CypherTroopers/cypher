// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

// Package reconfig implements Cypherium reconfiguration.
package reconfig

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type keyService struct {
	s               serviceI
	muBestCandidate sync.Mutex
	muLeaderState   sync.Mutex
	bestCandidate   *types.Candidate
	candidatepool   *core.CandidatePool
	bc              *core.BlockChain
	kbc             *core.KeyBlockChain
	engine          consensus.Engine
	config          *params.ChainConfig
	primaryLeader   uint
	primaryLeaderPK string
	activeLeader    uint
}

func newKeyService(s serviceI, backend *ReconfigBackend, config *params.ChainConfig) *keyService {
	keyS := new(keyService)
	keyS.s = s
	keyS.candidatepool = backend.CandidatePool()
	keyS.bc = backend.BlockChain()
	keyS.kbc = backend.KeyBlockChain()
	keyS.engine = backend.Engine()
	keyS.config = config
	keyS.primaryLeader = 0
	keyS.activeLeader = 0
	if config != nil {
		if n, ok := config.GenCommittee[0]; ok && n.Public != "" {
			keyS.primaryLeaderPK = n.Public
		}
	}
	if keyS.primaryLeaderPK == "" && keyS.kbc != nil {
		if cm := keyS.kbc.CurrentCommittee(); len(cm) > 0 {
			keyS.primaryLeaderPK = cm[0].Public
		}
	}
	return keyS
}

func (keyS *keyService) fixedModeEnabled() bool {
	return keyS.config != nil && (keyS.config.FixedLeader || keyS.config.FixedCommittee)
}

func (keyS *keyService) fixedLeaderModeEnabled() bool {
	return keyS.config != nil && keyS.config.FixedLeader && !keyS.config.FairHotstuff
}

func (keyS *keyService) promoteFallbackLeader(current uint) {
	if !keyS.fixedLeaderModeEnabled() {
		return
	}
	mb := bftview.GetCurrentMember()
	if mb == nil || len(mb.List) == 0 {
		return
	}

	keyS.muLeaderState.Lock()
	defer keyS.muLeaderState.Unlock()

	keyS.syncPrimaryLeaderLocked(mb)
	size := uint(len(mb.List))
	if size == 0 {
		return
	}
	primary := keyS.primaryLeader % size
	next := primary
	if size > 1 {
		next = primary + 1
		if next >= size {
			next = 0
		}
	}
	keyS.activeLeader = next
	log.Warn("fixed-mode leader fallback activated", "primary", keyS.primaryLeader, "active", keyS.activeLeader, "committeeSize", len(mb.List), "oldCurrent", current)
}

func (keyS *keyService) restorePrimaryLeader() {
	if !keyS.fixedLeaderModeEnabled() {
		return
	}
	keyS.muLeaderState.Lock()
	defer keyS.muLeaderState.Unlock()
	if keyS.activeLeader != keyS.primaryLeader {
		log.Info("fixed-mode leader restored", "from", keyS.activeLeader, "to", keyS.primaryLeader)
	}
	keyS.activeLeader = keyS.primaryLeader
}

func (keyS *keyService) getPrimaryLeaderIndex() uint {
	keyS.muLeaderState.Lock()
	defer keyS.muLeaderState.Unlock()
	mb := bftview.GetCurrentMember()
	keyS.syncPrimaryLeaderLocked(mb)
	return keyS.primaryLeader
}

func (keyS *keyService) setActiveLeader(index uint) {
	if !keyS.fixedLeaderModeEnabled() {
		return
	}
	mb := bftview.GetCurrentMember()

	keyS.muLeaderState.Lock()
	defer keyS.muLeaderState.Unlock()

	keyS.syncPrimaryLeaderLocked(mb)
	if mb != nil && len(mb.List) > 0 {
		if index >= uint(len(mb.List)) {
			index = keyS.primaryLeader % uint(len(mb.List))
		}
	}
	if keyS.activeLeader != index {
		log.Info("fixed-mode active leader updated", "from", keyS.activeLeader, "to", index, "primary", keyS.primaryLeader)
	}
	keyS.activeLeader = index
}

func (keyS *keyService) getFallbackLeaderIndex(primary uint) uint {
	mb := bftview.GetCurrentMember()

	keyS.muLeaderState.Lock()
	defer keyS.muLeaderState.Unlock()

	keyS.syncPrimaryLeaderLocked(mb)
	if mb == nil || len(mb.List) == 0 {
		return primary
	}

	size := uint(len(mb.List))
	if primary >= size {
		primary = keyS.primaryLeader % size
	}
	if size <= 1 {
		return primary
	}

	next := primary + 1
	if next >= size {
		next = 0
	}
	return next
}

func (keyS *keyService) syncPrimaryLeaderLocked(mb *bftview.Committee) {
	if mb == nil || len(mb.List) == 0 {
		return
	}
	if keyS.primaryLeaderPK == "" {
		keyS.primaryLeaderPK = mb.List[0].Public
	}
	for i, node := range mb.List {
		if node.Public == keyS.primaryLeaderPK {
			keyS.primaryLeader = uint(i)
			return
		}
	}
	if keyS.primaryLeader >= uint(len(mb.List)) {
		keyS.primaryLeader = 0
	}
}

func verifyKeyBlockLegacyFutureAt(keyblock *types.KeyBlock, now time.Time) error {
	if keyblock == nil {
		return fmt.Errorf("verifyKeyBlock,nil key block in future timestamp validation")
	}
	if !params.LegacyKeyTimestampWithinFutureLimit(keyblock.Time(), now) {
		return fmt.Errorf("verifyKeyBlock,timestamp too far in future, got:%d", keyblock.Time())
	}
	return nil
}

func verifyCandidateLegacyFutureAt(candidate *types.Candidate, now time.Time) error {
	if candidate == nil || candidate.KeyCandidate == nil {
		return fmt.Errorf("verifyKeyBlock,nil candidate in future timestamp validation")
	}
	if !params.LegacyKeyTimestampWithinFutureLimit(candidate.KeyCandidate.Time, now) {
		return fmt.Errorf("verifyKeyBlock,candidate timestamp too far in future, got:%d", candidate.KeyCandidate.Time)
	}
	return nil
}

func verifyKeyBlockMinInterval(keyblock, curKeyblock *types.KeyBlock) error {
	if keyblock == nil || curKeyblock == nil {
		return fmt.Errorf("verifyKeyBlock,nil key block in minimum-interval validation")
	}
	interval := uint64(params.KeyBlockMinInterval / time.Second)
	if curKeyblock.Time() > ^uint64(0)-interval {
		return fmt.Errorf("verifyKeyBlock,parent timestamp overflows minimum interval")
	}
	minNextKeyTime := curKeyblock.Time() + interval
	if keyblock.Time() < minNextKeyTime {
		return fmt.Errorf("verifyKeyBlock,timestamp too early, min:%d, got:%d", minNextKeyTime, keyblock.Time())
	}
	return nil
}

// Verify keyblock
func verifyKeyBlockCarrierParent(keyblock *types.KeyBlock, txParentNumber uint64) error {
	if keyblock == nil {
		return fmt.Errorf("nil key block")
	}
	if keyblock.T_Number() != txParentNumber {
		return fmt.Errorf("key block transaction parent mismatch: keyTNumber=%d proposalParent=%d", keyblock.T_Number(), txParentNumber)
	}
	return nil
}

// verifyKeyBlockCandidateBinding defines the legacy relationship between the
// key-block body, its difficulty and the optional PoW candidate. In fixed mode
// Time/Pace blocks may carry a candidate solely to reward its submitter; in
// dynamic mode a candidate necessarily implies a Pow/PacePow reconfiguration.
// Keeping this shape exact prevents an unproven OutAddress from minting the
// common-miner reward and prevents no-candidate blocks from rewriting work.
func verifyKeyBlockCandidateBinding(keyblock, parent *types.KeyBlock, candidate *types.Candidate, fixedMode bool) error {
	if err := keyblock.ValidateBasic(); err != nil {
		return err
	}
	if err := parent.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid parent key block: %w", err)
	}
	hasOutPublic := keyblock.OutPubKey() != ""
	hasOutAddress := keyblock.OutAddress(0) != ""
	if hasOutPublic != hasOutAddress {
		return fmt.Errorf("keyblock reward identity is incomplete")
	}

	bindCandidate := func(useRewardIdentity bool) error {
		if candidate == nil || candidate.KeyCandidate == nil {
			return fmt.Errorf("keyblock candidate is missing")
		}
		candidateHeader := types.CopyKeyBlockHeader(candidate.KeyCandidate)
		candidateHeader.BlockType = keyblock.BlockType()
		if keyblock.Header().HashWithCandi() != candidateHeader.HashWithCandi() {
			return fmt.Errorf("keyblock candidate header mismatch")
		}
		if useRewardIdentity {
			if keyblock.OutPubKey() != candidate.PubKey || keyblock.OutAddress(0) != candidate.Coinbase {
				return fmt.Errorf("keyblock reward submitter mismatch")
			}
		} else if keyblock.InPubKey() != candidate.PubKey || keyblock.InAddress() != candidate.Coinbase {
			return fmt.Errorf("keyblock admitted candidate mismatch")
		}
		return nil
	}

	switch keyblock.BlockType() {
	case types.PowReconfig, types.PacePowReconfig:
		if fixedMode {
			return fmt.Errorf("pow reconfiguration is disabled in fixed mode")
		}
		if !hasOutPublic {
			return fmt.Errorf("pow reconfiguration outer identity is missing")
		}
		return bindCandidate(false)
	case types.TimeReconfig, types.PaceReconfig:
		if fixedMode && hasOutPublic {
			return bindCandidate(true)
		}
		if candidate != nil {
			return fmt.Errorf("unexpected candidate on non-reward key block")
		}
		if hasOutPublic {
			return fmt.Errorf("unproven reward identity on key block")
		}
		if keyblock.Difficulty().Cmp(parent.Difficulty()) != 0 {
			return fmt.Errorf("no-candidate key block changed parent difficulty")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key block type %d", keyblock.BlockType())
	}
}

func keyBlockBodiesEqual(left, right *types.KeyBlock) bool {
	if left == nil || right == nil {
		return false
	}
	leftBody, rightBody := left.Body(), right.Body()
	return leftBody != nil && rightBody != nil && *leftBody == *rightBody
}

func (keyS *keyService) verifyKeyBlock(keyblock *types.KeyBlock, bestCandi *types.Candidate, txParentNumber uint64) error { //
	if err := keyblock.ValidateBasic(); err != nil {
		return fmt.Errorf("verifyKeyBlock: malformed key block: %w", err)
	}
	log.Info("@verifyKeyBlock", "number", keyblock.NumberU64())
	kbc := keyS.kbc
	if kbc == nil {
		return fmt.Errorf("verifyKeyBlock:nil key block chain")
	}
	curKeyblock := kbc.CurrentBlock()
	if curKeyblock == nil {
		return types.ErrUnknownAncestor
	}
	now := time.Now()
	// This check deliberately precedes both the self-leader and known-block
	// shortcuts. Neither local authorship nor prior storage may bypass the
	// versioned legacy wall-clock policy.
	if err := verifyKeyBlockLegacyFutureAt(keyblock, now); err != nil {
		return err
	}
	var candidatePublicKey []byte
	if bestCandi != nil {
		publicKey, err := core.ValidateLegacyCandidate(bestCandi)
		if err != nil {
			return fmt.Errorf("verifyKeyBlock: invalid candidate: %w", err)
		}
		if err := verifyCandidateLegacyFutureAt(bestCandi, now); err != nil {
			return err
		}
		candidatePublicKey = publicKey
	}
	knownBlock := kbc.HasBlock(keyblock.Hash(), keyblock.NumberU64())
	// A candidate accepted into this known key block can already be present in
	// the current committee. Apply the decoded-byte duplication rule only while
	// admitting a new block, never while recovering an already stored block.
	if len(candidatePublicKey) > 0 && !knownBlock && core.LegacyCandidatePublicKeyInCommittee(candidatePublicKey, kbc.GetCommitteeByHash(curKeyblock.Hash())) {
		return fmt.Errorf("verifyKeyBlock: %w", core.ErrCandidateIsMember)
	}
	if keyblock.HasNewNode() && bestCandi == nil {
		return fmt.Errorf("keyblock verify failed, pow reconfig need the best candidate")
	}
	if err := verifyKeyBlockCarrierParent(keyblock, txParentNumber); err != nil {
		return fmt.Errorf("verifyKeyBlock: %w", err)
	}

	if knownBlock { //First come from p2p
		log.Info("verifyKeyBlock exist!", "number", keyblock.NumberU64())
		stored := kbc.GetBlock(keyblock.Hash(), keyblock.NumberU64())
		if stored == nil {
			return fmt.Errorf("keyblock verify failed, known key block body is unavailable")
		}
		// KeyBlock.Hash commits only the header. A different body under the same
		// header hash must never be used to reconstruct or synchronize committee
		// state.
		if !keyBlockBodiesEqual(stored, keyblock) {
			return fmt.Errorf("keyblock verify failed, known key block body mismatch")
		}
		keyblock = stored
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb == nil {
			// Dynamic admission includes the miner endpoint only in Candidate Extra;
			// neither the key-block hash nor committee hash commits IP/port. Once the
			// original committee record is missing, an untrusted replay cannot safely
			// reconstruct that endpoint. Require restore/resync from an authoritative
			// snapshot instead of persisting attacker-selected network identity.
			if keyblock.HasNewNode() {
				return fmt.Errorf("keyblock verify failed, cannot reconstruct known dynamic committee without committed endpoint evidence")
			}
			mb, _ = bftview.GetCommittee(nil, keyblock, true)
			if mb == nil {
				return fmt.Errorf("keyblock verify failed, can't recover committee for known key block %d/%s", keyblock.NumberU64(), keyblock.Hash())
			}
			if !mb.Store(keyblock) {
				return fmt.Errorf("keyblock verify failed, can't persist committee for known key block %d/%s", keyblock.NumberU64(), keyblock.Hash())
			}
		}

		if mb != nil {
			keyS.s.syncCommittee(mb, keyblock)
		}

		return nil
	}
	var newNode *common.Cnode
	if keyblock.HasNewNode() {
		newNode = &common.Cnode{
			Address:  net.JoinHostPort(net.IP(bestCandi.IP).String(), strconv.Itoa(bestCandi.Port)),
			CoinBase: keyblock.InAddress(),
			Public:   keyblock.InPubKey(),
		}
	}
	if keyblock.NumberU64() != curKeyblock.NumberU64()+1 {
		return fmt.Errorf("verifyKeyBlock,number is not %d", curKeyblock.NumberU64()+1)
	}
	if keyblock.ParentHash() != curKeyblock.Hash() {
		//log.Error("verifyKeyBlock", "Non contiguous consensus prevhash", keyblock.ParentHash(), "currenthash", curKeyblock.Hash())
		return fmt.Errorf("verifyKeyBlock,Non contiguous key block's hash")
	}
	if err := verifyKeyBlockMinInterval(keyblock, curKeyblock); err != nil {
		return err
	}
	viewleaderIndex := keyS.s.GetCurrentView().LeaderIndex
	index := bftview.GetMemberIndex(keyblock.LeaderPubKey())
	if index != int(viewleaderIndex) {
		return fmt.Errorf("verifyKeyBlock,leaderindex(%d) error, nowIndex:%d", viewleaderIndex, index)
	}
	if keyblock.InAddress() == "" || keyblock.InPubKey() == "" || keyblock.LeaderPubKey() == "" || keyblock.LeaderAddress() == "" {
		return fmt.Errorf("verifyKeyBlock,in or leader public key is empty")
	}

	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}

	keyType := keyblock.BlockType()
	if err := verifyKeyBlockCandidateBinding(keyblock, curKeyblock, bestCandi, keyS.fixedModeEnabled()); err != nil {
		return fmt.Errorf("keyblock verify failed, candidate binding: %w", err)
	}

	if keyType == types.PowReconfig || keyType == types.PacePowReconfig {
		best := keyS.getBestCandidate(false)
		if best != nil && best.KeyCandidate.Nonce.Uint64() < bestCandi.KeyCandidate.Nonce.Uint64() { //compare best with local
			return fmt.Errorf("keyblock verify failed, not the best, my nonce is less than leader")
		}
	}

	mb, outer := bftview.GetCommittee(newNode, keyblock, true)
	if mb == nil {
		return fmt.Errorf("keyblock verify failed, can't get new committee")
	}
	if keyblock.CommitteeHash() != mb.RlpHash() {
		return fmt.Errorf("keyblock verify failed, chash:%x, block hash:%x", mb.RlpHash(), keyblock.CommitteeHash())
	}

	if keyType == types.PowReconfig || keyType == types.PacePowReconfig {
		if outer == nil {
			return fmt.Errorf("keyblock verify failed, PowReconfig or PacePowReconfig should has outer")
		}
		outAddress := keyblock.OutAddress(0)
		if outAddress == "" || keyblock.OutPubKey() == "" {
			return fmt.Errorf("keyblock verify failed, pow reconfig outer identity is empty")
		}
		isBadAddress := false
		if outAddress[0] == '*' {
			outAddress = outAddress[1:]
			isBadAddress = true
		}
		if outAddress == "" {
			return fmt.Errorf("keyblock verify failed, pow reconfig outer address is empty")
		}
		if outer.CoinBase != outAddress || outer.Public != keyblock.OutPubKey() {
			return fmt.Errorf("keyblock verify failed, outer is not correct,outer=%s,my outer=%s", outAddress, outer.CoinBase)
		}
		if isBadAddress {
			badAddress := keyS.getBadAddress()
			if outAddress != badAddress {
				return fmt.Errorf("keyblock verify failed, outer is not correct,outer =%s, badAddress=%s", outAddress, badAddress)
			}
		}
	}

	if mb.Leader().CoinBase != keyblock.LeaderAddress() || mb.Leader().Public != keyblock.LeaderPubKey() {
		return fmt.Errorf("keyblock verify failed, leader is not correct")
	}
	if mb.In().CoinBase != keyblock.InAddress() || mb.In().Public != keyblock.InPubKey() {
		return fmt.Errorf("keyblock verify failed, in is not correct")
	}
	if bestCandi != nil {
		if keyS.candidatepool == nil {
			return fmt.Errorf("verifyKeyBlock: candidate pool unavailable for final candidate validation")
		}
		// Proposal Extra is supplied directly by the leader and can bypass every
		// CandidateMsg/KCP/NewView admission path. All cheap keyblock, binding and
		// committee checks above run first; now recompute canonical difficulty on
		// a detached header and perform the one expensive PoW verification before
		// any persistent committee or rescue-mode side effect.
		if err := keyS.candidatepool.ValidateCandidate(bestCandi); err != nil {
			return fmt.Errorf("verifyKeyBlock: invalid final candidate: %w", err)
		}
	}
	latestKeyblock := kbc.CurrentBlock()
	if latestKeyblock == nil || latestKeyblock.NumberU64() != curKeyblock.NumberU64() || latestKeyblock.Hash() != curKeyblock.Hash() {
		return fmt.Errorf("verifyKeyBlock: canonical key head changed during validation")
	}
	if bftview.InRescueMode(keyblock.NumberU64(), keyblock.Hash()) {
		bftview.ClearRescueMode()
		log.Info("Rescue mode cleared after processing block",
			"number", keyblock.NumberU64())
	}
	if bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true) == nil {
		if !mb.Store(keyblock) {
			return fmt.Errorf("keyblock verify failed, can't persist committee for key block %d/%s", keyblock.NumberU64(), keyblock.Hash())
		}
	}
	keyS.s.syncCommittee(mb, keyblock)

	return nil
}

// Try to change committee and proposal a new keyblock
func (keyS *keyService) tryProposalChangeCommittee(leaderIndex uint, isDone bool, txParentNumber uint64) (*types.KeyBlock, *bftview.Committee, *types.Candidate, error) {
	log.Info("tryProposalChangeCommittee", "canonical tx number", keyS.bc.CurrentBlockN(), "proposal parent", txParentNumber, "isDone", isDone, "leaderIndex", leaderIndex)
	curKeyBlock := keyS.kbc.CurrentBlock()
	curKNumber := curKeyBlock.Number()
	curKHash := curKeyBlock.Hash()
	mb := bftview.GetCurrentMember()
	if mb == nil {
		return nil, nil, nil, fmt.Errorf("not found committee in keyblock number=%d", curKNumber)
	}
	mb = mb.Copy()
	header := &types.KeyBlockHeader{
		Number:     curKNumber.Add(curKNumber, common.Big1),
		ParentHash: curKHash,
		Difficulty: curKeyBlock.Difficulty(),
		Time:       uint64(time.Now().Unix()),
	}

	var outerPublic, outerCoinBase string
	best := keyS.getBestCandidate(keyS.fixedModeEnabled())
	powSubmitter := best
	log.Info("fixed-mode candidate lookup for reward",
		"fixedMode", keyS.fixedModeEnabled(),
		"hasBest", best != nil,
		"currentKeyNumber", keyS.kbc.CurrentBlockN(),
		"expectedCandidateNumber", keyS.kbc.CurrentBlockN()+1)
	if keyS.config != nil && (keyS.config.FixedLeader || keyS.config.FixedCommittee) {
		best = nil
	}

	var reconfigType uint8
	if isDone {
		if best != nil {
			reconfigType = types.PowReconfig
		} else {
			reconfigType = types.TimeReconfig
		}
	} else {
		if best != nil {
			reconfigType = types.PacePowReconfig
		} else {
			reconfigType = types.PaceReconfig
		}
	}
	header.BlockType = reconfigType

	if reconfigType == types.PowReconfig || reconfigType == types.PacePowReconfig {
		ck := best.KeyCandidate
		header.Time, header.Difficulty, header.MixDigest, header.Nonce = ck.Time, ck.Difficulty, ck.MixDigest, ck.Nonce
		newNode := &common.Cnode{
			Address:  net.JoinHostPort(net.IP(best.IP).String(), strconv.Itoa(best.Port)),
			CoinBase: best.Coinbase,
			Public:   best.PubKey,
		}

		badAddress := keyS.getBadAddress()
		outer := mb.Add(newNode, int(leaderIndex), badAddress)
		if outer == nil { //not new add
			return nil, nil, nil, fmt.Errorf("not new best candidate")
		}
		outerPublic, outerCoinBase = outer.Public, outer.CoinBase
		if badAddress != "" && outerCoinBase == badAddress {
			outerCoinBase = "*" + outerCoinBase
		}

	} else { //exchange in internal
		if keyS.fixedModeEnabled() && powSubmitter != nil {
			ck := powSubmitter.KeyCandidate
			header.Time, header.Difficulty, header.MixDigest, header.Nonce = ck.Time, ck.Difficulty, ck.MixDigest, ck.Nonce
			outerPublic, outerCoinBase = powSubmitter.PubKey, powSubmitter.Coinbase
		}
		mb.Add(nil, int(leaderIndex), "")
	}

	header.CommitteeHash = mb.RlpHash()
	// T_Number identifies the transaction block immediately preceding the
	// carrier block. In two-chain HotStuff that parent may be certified but not
	// canonical yet, so the canonical head is not a valid source here.
	header.T_Number = txParentNumber
	log.Info("fixed-mode pow submitter status",
		"fixedMode", keyS.fixedModeEnabled(),
		"hasPowSubmitter", powSubmitter != nil,
		"outerCoinBase", outerCoinBase)

	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)
	if !mb.Store(keyblock) {
		return nil, nil, nil, fmt.Errorf("failed to persist proposed committee for key block %d/%s", keyblock.NumberU64(), keyblock.Hash())
	}
	if keyS.fixedModeEnabled() {
		return keyblock, mb, powSubmitter, nil
	}
	return keyblock, mb, best, nil
}

func (keyS *keyService) getNextLeaderIndex(leaderIndex uint) uint {
	if keyS.fixedLeaderModeEnabled() {
		mb := bftview.GetCurrentMember()
		keyS.muLeaderState.Lock()
		defer keyS.muLeaderState.Unlock()
		keyS.syncPrimaryLeaderLocked(mb)
		if mb != nil && len(mb.List) > 0 {
			if keyS.activeLeader >= uint(len(mb.List)) {
				keyS.activeLeader = keyS.primaryLeader % uint(len(mb.List))
			}
		}
		return keyS.activeLeader
	}

	mb := bftview.GetCurrentMember()
	if mb == nil {
		return 1
	}

	committeeSize := len(mb.List)
	leaderIndex++
	if leaderIndex >= uint(committeeSize) {
		leaderIndex = 0
	}
	kbc := keyS.kbc
	curblock := kbc.CurrentBlock()
	curNumber := curblock.NumberU64()
	if curNumber == 0 {
		return leaderIndex
	}

	badNodes := make(map[string]bool)
	badAddr := keyS.getBadAddress()
	if badAddr != "" {
		badNodes[badAddr] = true
	}

	for loopi := 0; loopi < 3; loopi++ {
		if curblock.BlockType() == types.PaceReconfig || curblock.BlockType() == types.PacePowReconfig {
			curblock := kbc.GetBlockByHash(curblock.ParentHash())
			if curblock != nil {
				badNodes[curblock.LeaderAddress()] = true
			}
		}
	}

	if len(badNodes) > 0 {
		curNodes := kbc.GetCommitteeByNumber(curNumber)
		for i, r := range curNodes {
			if leaderIndex == uint(i) {
				if badNodes[r.CoinBase] {
					leaderIndex = uint(i) + 1
					if leaderIndex == uint(committeeSize) {
						leaderIndex = 0
					}

				}
			}
		}
	}
	return leaderIndex
}

func (keyS *keyService) getBadAddress() string {
	mb := bftview.GetCurrentMember()
	if mb == nil {
		return ""
	}
	cmLen := len(mb.List)
	exps := make(map[int]int)

	fromN := keyS.kbc.CurrentBlock().T_Number() + 1
	ToN := keyS.bc.CurrentBlockN()
	if fromN > ToN {
		return ""
	}

	for i := fromN; i <= ToN; i++ {
		block := keyS.bc.GetBlockByNumber(uint64(i))
		if block == nil {
			return ""
		}
		si := block.SignInfo()
		indexs := hotstuff.MaskToExceptionIndexs(si.Exceptions, cmLen)
		if len(indexs) > 0 {
			for j := 0; j < len(indexs); j++ {
				exps[indexs[j]]++
			}
		}
	}

	genesisCm := keyS.config.GenCommittee
	isGenesis := func(addr string) bool {
		for _, r := range genesisCm {
			if r.CoinBase == addr {
				return true
			}
		}
		return false
	}

	ii := 0
	maxV := 0
	for i := 0; i < cmLen; i++ {
		v, ok := exps[i]
		if !ok {
			continue
		}

		if ToN-fromN < 10 && isGenesis(mb.List[i].CoinBase) {
			v = v - 1
		}

		if v > maxV {
			maxV = v
			ii = i
		}
	}
	return mb.List[ii].CoinBase
}

// Clear candidate in cache
func (keyS *keyService) clearCandidate(keyblock *types.KeyBlock) {
	keyS.muBestCandidate.Lock()
	defer keyS.muBestCandidate.Unlock()
	keyS.candidatepool.ClearObsolete(keyblock.Number())
	keyS.bestCandidate = nil
}

// Get the best candidate by lowest nonce
func (keyS *keyService) getBestCandidate(refresh bool) *types.Candidate {
	keyS.muBestCandidate.Lock()
	defer keyS.muBestCandidate.Unlock()
	if keyS.kbc == nil || keyS.candidatepool == nil {
		keyS.bestCandidate = nil
		return nil
	}
	currentKeyBlock := keyS.kbc.CurrentBlock()
	if currentKeyBlock == nil {
		keyS.bestCandidate = nil
		return nil
	}
	expectedNumber := currentKeyBlock.NumberU64() + 1
	if keyS.bestCandidate != nil {
		if err := keyS.candidatepool.ValidateRemoteCandidatePreflight(keyS.bestCandidate, time.Now()); err != nil {
			log.Debug("Cleared context-invalid cached best candidate", "err", err)
			keyS.bestCandidate = nil
		}
	}

	if refresh {
		// Preserve a still-valid winner learned through NewView even when this node
		// never received it through CandidateMsg/KCP. The preflight above has
		// already cleared any winner invalidated by a tx rewind or key-head change;
		// filtered pool candidates can now compete against the surviving cache.
		kNumber := expectedNumber
		contents := keyS.candidatepool.Content()
		if len(contents) > 0 {
			found := false

			for _, cand := range contents {
				if cand == nil || cand.KeyCandidate == nil {
					continue
				}

				if cand.KeyCandidate.Number.Uint64() != kNumber {
					log.Warn("getBestCandidate skip unmatched candidate",
						"currentKeyNumber", keyS.kbc.CurrentBlockN(),
						"expectedCandidateNumber", kNumber,
						"candidateNumber", cand.KeyCandidate.Number.Uint64(),
						"nonce", cand.KeyCandidate.Nonce.Uint64(),
						"pubkey", cand.PubKey,
					)
					continue
				}

				found = true
				if keyS.bestCandidate == nil ||
					cand.KeyCandidate.Nonce.Uint64() < keyS.bestCandidate.KeyCandidate.Nonce.Uint64() {
					keyS.bestCandidate = cand
				}
			}

			if !found {
				log.Warn("getBestCandidate no candidate for expected key number",
					"currentKeyNumber", keyS.kbc.CurrentBlockN(),
					"expectedCandidateNumber", kNumber,
					"candidateCount", len(contents),
				)
			}
		}
	} //end if refresh
	if keyS.bestCandidate != nil {
		if err := keyS.candidatepool.ValidateRemoteCandidatePreflight(keyS.bestCandidate, time.Now()); err != nil {
			log.Debug("Discarded best candidate invalidated during selection", "err", err)
			keyS.bestCandidate = nil
			return nil
		}
	}
	return keyS.bestCandidate
}

// Set the best candidate by pow
func (keyS *keyService) setBestCandidate(bestCandidates []*types.Candidate) {
	bestNonce := uint64(math.MaxUint64)
	best := keyS.getBestCandidate(true)
	if best != nil {
		bestNonce = best.KeyCandidate.Nonce.Uint64()
	}
	keyNumber := keyS.kbc.CurrentBlockN() + 1
	for _, cand := range bestCandidates {
		if cand == nil || keyS.candidatepool == nil {
			continue
		}
		// NewView extra is authenticated as committee transport data, but a
		// Byzantine member can still supply malformed or invalid PoW. Validate
		// the complete candidate before any dereference or winner-cache write.
		if err := keyS.candidatepool.ValidateCandidate(cand); err != nil {
			log.Warn("setBestCandidate rejected NewView candidate", "err", err)
			continue
		}
		ck := cand.KeyCandidate
		if ck.Number.Uint64() == keyNumber && ck.Nonce.Uint64() < bestNonce && bftview.GetMemberIndex(cand.PubKey) < 0 {
			bestNonce = ck.Nonce.Uint64()
			keyS.muBestCandidate.Lock()
			keyS.bestCandidate = cand
			keyS.muBestCandidate.Unlock()
		}
	}
}
