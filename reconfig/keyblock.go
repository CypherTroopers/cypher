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
	"sync/atomic"
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

func scheduledKeyBlockTimestamp(parentTime uint64) uint64 {
	return parentTime + uint64(params.KeyBlockMinInterval/time.Second)
}

// fixedKeyBlockCadenceApplies leaves a zero-timestamp genesis key block as a
// one-time bootstrap anchor. Deriving its child from parent+600 would otherwise
// start the fixed cadence in 1970 and make a freshly reset devnet catch up
// millions of already elapsed slots. An explicit non-zero genesis timestamp is
// treated as the configured cadence anchor.
func fixedKeyBlockCadenceApplies(parent *types.KeyBlock, fixedMode bool) bool {
	if !fixedMode || parent == nil {
		return false
	}
	return !parent.IsZeroTimeGenesis()
}

func keyBlockProposalTimestamp(parentTime, proposalTime uint64, exactCadence bool) uint64 {
	if exactCadence {
		return scheduledKeyBlockTimestamp(parentTime)
	}
	return proposalTime
}

const (
	fixedKeyBlockFutureClockSkew       = 30 * time.Second
	fixedModeKeyblockWakeupInterval    = 2 * time.Second
	fixedModeKeyblockWatchdogInterval  = 250 * time.Millisecond
	fixedModeKeyblockViewRoundDuration = 2 * params.CollectVoteInfoTimeout
)

func verifyKeyBlockInterval(keyblock, curKeyblock *types.KeyBlock, fixedMode bool) error {
	return verifyKeyBlockIntervalAt(keyblock, curKeyblock, fixedMode, time.Now())
}

func verifyKeyBlockIntervalAt(keyblock, curKeyblock *types.KeyBlock, fixedMode bool, now time.Time) error {
	if fixedMode {
		latestAccepted := uint64(now.Add(fixedKeyBlockFutureClockSkew).Unix())
		if keyblock.Time() > latestAccepted {
			return fmt.Errorf("verifyKeyBlock,fixed cadence timestamp too far in future, max:%d, got:%d", latestAccepted, keyblock.Time())
		}
	}
	nextKeyTime := scheduledKeyBlockTimestamp(curKeyblock.Time())
	if fixedKeyBlockCadenceApplies(curKeyblock, fixedMode) {
		if keyblock.Time() != nextKeyTime {
			return fmt.Errorf("verifyKeyBlock,fixed cadence timestamp mismatch, want:%d, got:%d", nextKeyTime, keyblock.Time())
		}
		return nil
	}
	if keyblock.Time() < nextKeyTime {
		return fmt.Errorf("verifyKeyBlock,timestamp too early, min:%d, got:%d", nextKeyTime, keyblock.Time())
	}
	return nil
}

func fixedModeRewardCandidateForSlot(candidate *types.Candidate, slot uint64) *types.Candidate {
	if candidate == nil || candidate.KeyCandidate == nil || candidate.KeyCandidate.Time != slot {
		return nil
	}
	return candidate
}

func bestFixedModeRewardCandidateForSlot(candidates []*types.Candidate, parentHash common.Hash, number, slot uint64) *types.Candidate {
	var best *types.Candidate
	for _, candidate := range candidates {
		candidate = fixedModeRewardCandidateForSlot(candidate, slot)
		if candidate == nil || candidate.KeyCandidate.ParentHash != parentHash || candidate.KeyCandidate.Number == nil || candidate.KeyCandidate.Number.Uint64() != number {
			continue
		}
		if best == nil || candidate.KeyCandidate.Nonce.Uint64() < best.KeyCandidate.Nonce.Uint64() {
			best = candidate
		}
	}
	return best
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

// verifyCertifiedFHSKeyBlock replays a QC-authenticated carrier against its
// immutable signing epoch. A later local view, best candidate, or reputation
// estimate cannot invalidate a proposal already certified by that committee.
// The live proposal verifier below retains those admission checks.
func (keyS *keyService) verifyCertifiedFHSKeyBlock(ref *types.HotstuffProposalRef, keyblock *types.KeyBlock, candidate *types.Candidate) error {
	if keyS == nil || keyS.kbc == nil || keyS.config == nil || !keyS.config.FairHotstuff ||
		ref == nil || ref.Number == 0 || ref.BlockType != types.Key_Block || keyblock == nil {
		return fmt.Errorf("incomplete certified FHS key carrier")
	}
	if keyS.config.ChainID == nil || ref.ChainID != keyS.config.ChainID.Uint64() {
		return fmt.Errorf("certified FHS key carrier chain mismatch")
	}
	if err := verifyKeyBlockCarrierParent(keyblock, ref.Number-1); err != nil {
		return err
	}
	if ref.KeyHash != keyblock.ParentHash() {
		return fmt.Errorf("certified FHS key carrier signing parent mismatch")
	}
	parent := keyS.kbc.GetBlockByHash(ref.KeyHash)
	if parent == nil || parent.NumberU64() == ^uint64(0) || keyblock.NumberU64() != parent.NumberU64()+1 {
		return fmt.Errorf("certified FHS key carrier has an invalid parent epoch")
	}
	canonicalParent := keyS.kbc.GetBlockByNumber(parent.NumberU64())
	if canonicalParent == nil || canonicalParent.Hash() != parent.Hash() {
		return fmt.Errorf("certified FHS key carrier parent epoch is not canonical")
	}
	if err := verifyKeyBlockInterval(keyblock, parent, keyS.fixedModeEnabled()); err != nil {
		return err
	}
	committee := bftview.LoadMember(parent.NumberU64(), parent.Hash(), true)
	if committee == nil || len(committee.List) < 2 || committee.RlpHash() != parent.CommitteeHash() {
		return fmt.Errorf("certified FHS key carrier signing committee is unavailable")
	}
	leaderIndex, err := fairHotstuffLeaderIndex(keyS.config.FairHotstuffSeed, ref.ChainID, ref.ViewNumber, parent.CommitteeHash(), len(committee.List))
	if err != nil {
		return err
	}
	leader := committee.List[leaderIndex]
	if leader == nil || ref.LeaderID != leader.Address || keyblock.LeaderPubKey() != leader.Public || keyblock.LeaderAddress() != leader.CoinBase {
		return fmt.Errorf("certified FHS key carrier leader differs from its authenticated view")
	}
	if keyblock.InAddress() == "" || keyblock.InPubKey() == "" || keyblock.LeaderAddress() == "" || !keyblock.TypeCheck(parent.T_Number()) {
		return fmt.Errorf("invalid certified FHS key carrier membership")
	}
	keyType := keyblock.BlockType()
	powChange := keyType == types.PowReconfig || keyType == types.PacePowReconfig
	if powChange && keyS.fixedModeEnabled() {
		return fmt.Errorf("certified FHS pow reconfiguration is disabled in fixed mode")
	}
	if !powChange && keyType != types.TimeReconfig && keyType != types.PaceReconfig {
		return fmt.Errorf("invalid certified FHS key carrier type %d", keyType)
	}
	rewardCandidate := keyS.fixedModeEnabled() && !powChange && keyblock.OutPubKey() != "" && keyblock.OutAddress(0) != ""
	var newNode *common.Cnode
	if powChange || rewardCandidate {
		if candidate == nil || candidate.KeyCandidate == nil || keyS.engine == nil {
			return fmt.Errorf("certified FHS key carrier requires its PoW candidate")
		}
		// Candidate verification may normalize BlockType. Keep the sidecar
		// immutable while retaining the exact candidate proof checks.
		candidate = types.DecodeToCandidate(candidate.EncodeToBytes())
		if candidate == nil || candidate.KeyCandidate == nil {
			return fmt.Errorf("invalid certified FHS key carrier candidate encoding")
		}
		candidate.KeyCandidate.BlockType = keyType
		if keyblock.Header().HashWithCandi() != candidate.KeyCandidate.HashWithCandi() {
			return fmt.Errorf("certified FHS key carrier candidate commitment mismatch")
		}
		if powChange {
			if keyblock.InPubKey() != candidate.PubKey || keyblock.InAddress() != candidate.Coinbase {
				return fmt.Errorf("certified FHS key carrier incoming candidate mismatch")
			}
			newNode = &common.Cnode{Address: net.JoinHostPort(net.IP(candidate.IP).String(), strconv.Itoa(candidate.Port)), CoinBase: candidate.Coinbase, Public: candidate.PubKey}
		} else if keyblock.OutPubKey() != candidate.PubKey || keyblock.OutAddress(0) != candidate.Coinbase {
			return fmt.Errorf("certified FHS key carrier reward candidate mismatch")
		}
		if err := keyS.engine.VerifyCandidate(keyS.kbc, candidate); err != nil {
			return err
		}
	}
	next := committee.Copy()
	outer := next.Add(newNode, int(leaderIndex), keyblock.OutAddress(1))
	if next.RlpHash() != keyblock.CommitteeHash() || next.Leader().CoinBase != keyblock.LeaderAddress() ||
		next.Leader().Public != keyblock.LeaderPubKey() || next.In().CoinBase != keyblock.InAddress() || next.In().Public != keyblock.InPubKey() {
		return fmt.Errorf("certified FHS key carrier committee commitment mismatch")
	}
	if powChange {
		outAddress := keyblock.OutAddress(0)
		if len(outAddress) > 0 && outAddress[0] == '*' {
			outAddress = outAddress[1:]
		}
		if outer == nil || outer.CoinBase != outAddress || outer.Public != keyblock.OutPubKey() {
			return fmt.Errorf("certified FHS key carrier outgoing member mismatch")
		}
	}
	// Persist only immutable committee material, with no network callback,
	// rescue-mode change, or modification of the live pacemaker context.
	if !next.StoreWithoutCallback(keyblock) {
		return fmt.Errorf("cannot store certified FHS key carrier committee")
	}
	return nil
}

func (keyS *keyService) verifyKeyBlock(keyblock *types.KeyBlock, bestCandi *types.Candidate, txParentNumber uint64) error { //
	log.Info("@verifyKeyBlock", "number", keyblock.NumberU64())
	if err := verifyKeyBlockCarrierParent(keyblock, txParentNumber); err != nil {
		return fmt.Errorf("verifyKeyBlock: %w", err)
	}
	kbc := keyS.kbc
	if keyblock.LeaderPubKey() == bftview.GetServerInfo(bftview.PublicKey) {
		curKeyblock := kbc.CurrentBlock()
		if keyblock.NumberU64() != curKeyblock.NumberU64()+1 {
			return fmt.Errorf("verifyKeyBlock,number is not %d", curKeyblock.NumberU64()+1)
		}
		if keyblock.ParentHash() != curKeyblock.Hash() {
			//log.Error("verifyKeyBlock", "Non contiguous consensus prevhash", keyblock.ParentHash(), "currenthash", curKeyblock.Hash())
			return fmt.Errorf("verifyKeyBlock,Non contiguous key block's hash")
		}
		if err := verifyKeyBlockInterval(keyblock, curKeyblock, keyS.fixedModeEnabled()); err != nil {
			return err
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

	if kbc.HasBlock(keyblock.Hash(), keyblock.NumberU64()) { //First come from p2p
		log.Info("verifyKeyBlock exist!", "number", keyblock.NumberU64())
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb == nil {
			mb, _ = bftview.GetCommittee(newNode, keyblock, true)
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
	curKeyblock := keyS.kbc.CurrentBlock()
	if keyblock.NumberU64() != curKeyblock.NumberU64()+1 {
		return fmt.Errorf("verifyKeyBlock,number is not %d", curKeyblock.NumberU64()+1)
	}
	if keyblock.ParentHash() != curKeyblock.Hash() {
		//log.Error("verifyKeyBlock", "Non contiguous consensus prevhash", keyblock.ParentHash(), "currenthash", curKeyblock.Hash())
		return fmt.Errorf("verifyKeyBlock,Non contiguous key block's hash")
	}
	if err := verifyKeyBlockInterval(keyblock, curKeyblock, keyS.fixedModeEnabled()); err != nil {
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
	if keyS.config != nil && (keyS.config.FixedLeader || keyS.config.FixedCommittee) &&
		(keyType == types.PowReconfig || keyType == types.PacePowReconfig) {
		return fmt.Errorf("keyblock verify failed, pow reconfig is disabled when fixedLeader/fixedCommittee is enabled")
	}

	if keyType == types.PowReconfig || keyType == types.PacePowReconfig {
		if bestCandi == nil {
			return fmt.Errorf("keyblock verify failed, pow reconfig need the best candidate")
		}
		bestCandi.KeyCandidate.BlockType = keyType
		//log.Info("keyblock verify", "keyblock.Header", keyblock.Header(), "bestCandi.Header", bestCandi.KeyCandidate)
		if keyblock.Header().HashWithCandi() != bestCandi.KeyCandidate.HashWithCandi() {
			return fmt.Errorf("keyblock verify failed,best candidate's hash is not equal me")
		}
		if keyblock.InPubKey() != bestCandi.PubKey || keyblock.InAddress() != bestCandi.Coinbase {
			return fmt.Errorf("keyblock verify failed, best candidate in info is not correct")
		}

		best := keyS.getBestCandidate(false)
		if best != nil && best.KeyCandidate.Nonce.Uint64() < bestCandi.KeyCandidate.Nonce.Uint64() { //compare best with local
			return fmt.Errorf("keyblock verify failed, not the best, my nonce is less than leader")
		}
		//verify bestCandi's MixDigest,Nonce with ip
		err := keyS.engine.VerifyCandidate(keyS.kbc, bestCandi)
		if err != nil {
			return err //fmt.Errorf("keyblock verify failed,candidate pow verification failed!")
		}
	} else if keyS.fixedModeEnabled() && (keyType == types.TimeReconfig || keyType == types.PaceReconfig) &&
		keyblock.OutPubKey() != "" && keyblock.OutAddress(0) != "" {
		if bestCandi == nil {
			return fmt.Errorf("keyblock verify failed, fixed mode pow reward requires candidate")
		}
		bestCandi.KeyCandidate.BlockType = keyType
		if keyblock.Header().HashWithCandi() != bestCandi.KeyCandidate.HashWithCandi() {
			return fmt.Errorf("keyblock verify failed, fixed mode candidate hash mismatch")
		}
		if keyblock.OutPubKey() != bestCandi.PubKey || keyblock.OutAddress(0) != bestCandi.Coinbase {
			return fmt.Errorf("keyblock verify failed, fixed mode candidate submitter mismatch")
		}
		if err := keyS.engine.VerifyCandidate(keyS.kbc, bestCandi); err != nil {
			return err
		}
	} else if keyType == types.TimeReconfig {
		//
	} else if keyType == types.PaceReconfig {
		//
	} else {
		return fmt.Errorf("verifyKeyBlock,error BlockType:%d", keyblock.BlockType())
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
		isBadAddress := false
		if outAddress[0] == '*' {
			outAddress = outAddress[1:]
			isBadAddress = true
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
	fixedMode := keyS.fixedModeEnabled()
	fixedCadence := fixedKeyBlockCadenceApplies(curKeyBlock, fixedMode)
	header := &types.KeyBlockHeader{
		Number:     curKNumber.Add(curKNumber, common.Big1),
		ParentHash: curKHash,
		Difficulty: curKeyBlock.Difficulty(),
		Time:       keyBlockProposalTimestamp(curKeyBlock.Time(), uint64(time.Now().Unix()), fixedCadence),
	}

	var outerPublic, outerCoinBase string
	best := keyS.getBestCandidate(false)
	if fixedMode {
		best = bestFixedModeRewardCandidateForSlot(
			keyS.candidatepool.Content(), curKHash, header.Number.Uint64(), header.Time,
		)
	}
	powSubmitter := best
	log.Info("fixed-mode candidate lookup for reward",
		"fixedMode", fixedMode,
		"hasBest", best != nil,
		"currentKeyNumber", keyS.kbc.CurrentBlockN(),
		"expectedCandidateNumber", keyS.kbc.CurrentBlockN()+1)
	if fixedMode {
		best = nil
		if powSubmitter != nil && fixedModeRewardCandidateForSlot(powSubmitter, header.Time) == nil {
			candidateTime := uint64(0)
			if powSubmitter.KeyCandidate != nil {
				candidateTime = powSubmitter.KeyCandidate.Time
			}
			log.Warn("fixed-mode reward candidate omitted for wrong cadence slot",
				"candidateTime", candidateTime,
				"slot", header.Time,
				"currentKeyNumber", keyS.kbc.CurrentBlockN())
			powSubmitter = nil
		}
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
		if fixedMode && powSubmitter != nil {
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
		"fixedMode", fixedMode,
		"hasPowSubmitter", powSubmitter != nil,
		"outerCoinBase", outerCoinBase)

	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)
	if fixedMode {
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

	if refresh {
		kNumber := keyS.kbc.CurrentBlockN() + 1
		if keyS.bestCandidate != nil && keyS.bestCandidate.KeyCandidate.Number.Uint64() != kNumber {
			keyS.bestCandidate = nil
		}
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
		if bftview.GetMemberIndex(keyS.bestCandidate.PubKey) >= 0 {
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
		ck := cand.KeyCandidate
		if ck.Number.Uint64() == keyNumber && ck.Nonce.Uint64() < bestNonce && bftview.GetMemberIndex(cand.PubKey) < 0 {
			bestNonce = ck.Nonce.Uint64()
			keyS.muBestCandidate.Lock()
			keyS.bestCandidate = cand
			keyS.muBestCandidate.Unlock()
		}
	}
}

// GetExtra call by hotstuff
func (s *Service) GetExtra() []byte {
	best := s.keyService.getBestCandidate(true)
	if best == nil {
		return nil
	}
	return best.EncodeToBytes()
}

// keyProposalPlan derives proposal eligibility from the canonical key-block interval.
// Fixed mode deliberately ignores NoDone: it is local recovery state and may be
// reset by an otherwise valid TC/QC transition while the key-block slot is due.
func keyProposalPlan(fixedMode bool, leaderIndex uint, noDone, intervalElapsed bool) (attempt, isDone bool) {
	if fixedMode {
		return intervalElapsed, true
	}
	return leaderIndex > 0 && intervalElapsed, !noDone
}

func (s *Service) abortFixedModeKeyProposal(reason string, err error) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if s.keyService == nil || !s.keyService.fixedModeEnabled() || s.currentView.NoDone {
		return
	}
	log.Warn("fixed-mode keyblock proposal aborted; returning to tx proposal view",
		"reason", reason,
		"err", err,
		"txNumber", s.currentView.TxNumber,
		"keyNumber", s.currentView.KeyNumber,
		"leaderIndex", s.currentView.LeaderIndex)
	s.currentView.NoDone = true
	// A failed fixed-mode keyblock proposal should not leave the service waiting
	// for a keyblock that was never committed. Reset the waiting watermark so the
	// next successful tx/key block can advance the view normally.
	s.waittingView.TxNumber = s.currentView.TxNumber
	s.waittingView.KeyNumber = s.currentView.KeyNumber
}

func (s *Service) fixedModeKeyblockIntervalElapsed(now time.Time) bool {
	if s.keyService == nil || !s.keyService.fixedModeEnabled() {
		return false
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return false
	}
	lastKeyTime := time.Unix(int64(curKeyBlock.Time()), 0)
	return now.Sub(lastKeyTime) >= params.KeyBlockMinInterval
}

func (s *Service) fixedModeCandidateRewardReady(now time.Time) bool {
	if s.keyService == nil || !s.keyService.fixedModeEnabled() {
		return false
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return false
	}

	lastKeyTime := time.Unix(int64(curKeyBlock.Time()), 0)
	elapsed := now.Sub(lastKeyTime)
	if elapsed < params.KeyBlockMinInterval {
		return false
	}

	// handleHotStuffMsg wakes every 1ms. Refreshing CandidatePool on every idle
	// loop floods logs and can burn CPU while the keyblock view is waiting.
	if !s.lastCandidateRewardCheck.IsZero() && now.Sub(s.lastCandidateRewardCheck) < 2*time.Second {
		return s.lastCandidateRewardReady
	}

	s.lastCandidateRewardCheck = now
	s.lastCandidateRewardReady = s.getBestCandidate(true) != nil
	return s.lastCandidateRewardReady
}

func (s *Service) repairFixedModeTxProposalViewIfPending(pendingTotal int) {
	if pendingTotal <= 0 || s.keyService == nil || !s.keyService.fixedModeEnabled() {
		return
	}
	curKeyBlock := s.kbc.CurrentBlock()
	if curKeyBlock == nil {
		return
	}

	now := time.Now()
	lastKeyTime := time.Unix(int64(curKeyBlock.Time()), 0)
	elapsed := now.Sub(lastKeyTime)

	// If keyblock interval has elapsed, do not interfere with normal keyblock proposal.
	if elapsed >= params.KeyBlockMinInterval {
		return
	}

	// Do not repair immediately after a tx block proposal was generated.
	// The proposal may still be in HotStuff consensus. Touching currentView /
	// waittingView while a tx block is in-flight can make the next view wait
	// for the wrong watermark.
	s.muProposalCadence.RLock()
	lastTxProposal := s.lastFastBlockTime
	if s.lastSlowBlockTime.After(lastTxProposal) {
		lastTxProposal = s.lastSlowBlockTime
	}
	s.muProposalCadence.RUnlock()
	if !lastTxProposal.IsZero() && now.Sub(lastTxProposal) < 2*time.Second {
		s.muCurrentView.Lock()
		txNumber := s.currentView.TxNumber
		keyNumber := s.currentView.KeyNumber
		leaderIndex := s.currentView.LeaderIndex
		noDone := s.currentView.NoDone
		s.muCurrentView.Unlock()

		log.Debug("skip fixed-mode tx proposal view repair; recent tx proposal in flight",
			"pendingTotal", pendingTotal,
			"sinceLastTxProposal", now.Sub(lastTxProposal),
			"elapsed", elapsed,
			"minimum", params.KeyBlockMinInterval,
			"txNumber", txNumber,
			"keyNumber", keyNumber,
			"leaderIndex", leaderIndex,
			"noDone", noDone)

		return
	}

	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if !s.currentView.NoDone {
		leaderIndex := s.keyService.getPrimaryLeaderIndex()
		if s.fairHotstuffEnabled() {
			leaderIndex = s.fairHotstuffLeaderIndexForCurrentLocked()
		}
		if mb := bftview.GetCurrentMember(); mb != nil && len(mb.List) > 0 && leaderIndex >= uint(len(mb.List)) {
			leaderIndex = 0
		}

		log.Warn("fixed-mode pending txs while keyblock interval not elapsed; forcing tx proposal view",
			"pendingTotal", pendingTotal,
			"elapsed", elapsed,
			"minimum", params.KeyBlockMinInterval,
			"txNumber", s.currentView.TxNumber,
			"keyNumber", s.currentView.KeyNumber,
			"oldLeaderIndex", s.currentView.LeaderIndex,
			"newLeaderIndex", leaderIndex)

		s.currentView.NoDone = true
		s.currentView.LeaderIndex = leaderIndex
		s.waittingView.TxNumber = s.currentView.TxNumber
		s.waittingView.KeyNumber = s.currentView.KeyNumber
	}
}

func (s *Service) resetFixedModeKeyblockViewLocked() {
	s.fixedKeyViewStartedAt = time.Time{}
	s.fixedKeyViewTxNumber = 0
	s.fixedKeyViewKeyNumber = 0
	s.fixedKeyViewTxHash = common.Hash{}
	s.fixedKeyViewKeyHash = common.Hash{}
}

func (s *Service) fixedModeKeyblockViewStateChangedLocked() bool {
	return s.fixedKeyViewStartedAt.IsZero() ||
		s.fixedKeyViewTxNumber != s.currentView.TxNumber ||
		s.fixedKeyViewKeyNumber != s.currentView.KeyNumber ||
		s.fixedKeyViewTxHash != s.currentView.TxHash ||
		s.fixedKeyViewKeyHash != s.currentView.KeyHash
}

func (s *Service) fixedModeKeyblockViewStart(now time.Time) time.Time {
	start := now
	if block := s.bc.CurrentBlock(); block != nil {
		start = time.Unix(int64(block.Time()), 0)
	}
	return fixedModeKeyblockViewStartFromHeads(now, start, s.kbc.CurrentBlock())
}

func fixedModeKeyblockViewStartFromHeads(now, start time.Time, keyBlock *types.KeyBlock) time.Time {
	if keyBlock != nil {
		if keyBlock.IsZeroTimeGenesis() {
			return now
		}
		keyReadyAt := time.Unix(int64(keyBlock.Time()), 0).Add(params.KeyBlockMinInterval)
		if keyReadyAt.After(start) {
			start = keyReadyAt
		}
	}
	if start.After(now) {
		return now
	}
	return start
}

func (s *Service) prepareFixedModeKeyblockView(now time.Time) (oldView bftview.View, curView bftview.View, viewAge time.Duration) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	oldView = s.currentView

	primary := uint(0)
	if s.fairHotstuffEnabled() {
		primary = s.fairHotstuffLeaderIndexForCurrentLocked()
	} else if s.keyService != nil {
		primary = s.keyService.getPrimaryLeaderIndex()
	}
	primary = s.normalizeLeaderIndex(primary)

	if s.fixedModeKeyblockViewStateChangedLocked() {
		// Derive the timeout origin from committed chain data. Local ACK times and
		// process start times are not consensus state and previously split nodes
		// between the primary and fallback leaders for the same view.
		s.fixedKeyViewStartedAt = s.fixedModeKeyblockViewStart(now)
		s.fixedKeyViewTxNumber = s.currentView.TxNumber
		s.fixedKeyViewKeyNumber = s.currentView.KeyNumber
		s.fixedKeyViewTxHash = s.currentView.TxHash
		s.fixedKeyViewKeyHash = s.currentView.KeyHash
	}

	viewAge = now.Sub(s.fixedKeyViewStartedAt)
	if viewAge < 0 {
		viewAge = 0
	}
	nextRound := uint64(viewAge / fixedModeKeyblockViewRoundDuration)
	// Local heartbeat/ACK observations are not consensus state. Using them to
	// select a fallback split healthy nodes across different LeaderIndex values.
	// With protocol-level retransmission, a live primary self-recovers without a
	// leader change. A future down-node fallback must be quorum-certified.
	if s.keyService != nil {
		s.keyService.setActiveLeader(primary)
	}

	s.currentView.LeaderIndex = primary
	s.currentView.NoDone = false
	if s.currentView.Round != nextRound {
		log.Warn("fixed-mode keyblock advancing recovery round",
			"oldRound", s.currentView.Round,
			"round", nextRound,
			"viewAge", viewAge,
			"roundDuration", fixedModeKeyblockViewRoundDuration,
			"currentBlock", s.bc.CurrentBlockN(),
			"currentKey", s.kbc.CurrentBlockN())
		s.currentView.Round = nextRound
	}
	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1

	curView = s.currentView
	return oldView, curView, viewAge
}

func (s *Service) wakeFixedModeKeyblock(now time.Time, reason string, candidateRewardReady bool, pendingTotal, fastPending, slowPending int) bool {
	if atomic.LoadInt32(&s.runningState) != 1 || bftview.IamMember() < 0 {
		return false
	}
	if !s.fixedModeKeyblockIntervalElapsed(now) {
		return false
	}
	s.clearProposalNoWork()

	s.muCurrentView.Lock()
	if !s.lastFixedKeyNewViewWakeup.IsZero() && now.Sub(s.lastFixedKeyNewViewWakeup) < fixedModeKeyblockWakeupInterval {
		s.muCurrentView.Unlock()
		return true
	}
	s.lastFixedKeyNewViewWakeup = now
	s.muCurrentView.Unlock()

	oldView, curView, viewAge := s.prepareFixedModeKeyblockView(now)
	log.Warn("fixed-mode keyblock start-new-view wakeup",
		"reason", reason,
		"currentBlock", s.bc.CurrentBlockN(),
		"currentKey", s.kbc.CurrentBlockN(),
		"oldLeaderIndex", oldView.LeaderIndex,
		"oldNoDone", oldView.NoDone,
		"leaderIndex", curView.LeaderIndex,
		"noDone", curView.NoDone,
		"round", curView.Round,
		"viewAge", viewAge,
		"isLeader", bftview.IamLeader(curView.LeaderIndex),
		"candidateReady", candidateRewardReady,
		"pendingTotal", pendingTotal,
		"fastPending", fastPending,
		"slowPending", slowPending)

	curN := s.bc.CurrentBlockN()
	s.sendNewViewMsg(curN)
	s.enqueueTimerPriority(curN)
	return true
}

func (s *Service) keyblockLivenessLoop() {
	ticker := time.NewTicker(fixedModeKeyblockWatchdogInterval)
	defer ticker.Stop()
	for now := range ticker.C {
		if atomic.LoadInt32(&s.runningState) != 1 || bftview.IamMember() < 0 {
			continue
		}
		if !s.fixedModeKeyblockIntervalElapsed(now) {
			continue
		}
		if s.proposalNoWorkUnchanged(now) {
			continue
		}
		fastPending, slowPending := s.lanePendingCounts()
		pendingTotal := 0
		if s.txPool != nil {
			pendingTotal, _ = s.txPool.Stats()
		}
		s.purgeExpiredProposalCaches(now)
		s.wakeFixedModeKeyblock(now, "watchdog", false, pendingTotal, fastPending, slowPending)
	}
}

// Save committee by keyblock
func (s *Service) saveCommittee(curKeyBlock *types.KeyBlock) {
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), false)
	if mb != nil {
		return
	}

	var newNode *common.Cnode
	if curKeyBlock.BlockType() == types.PowReconfig || curKeyBlock.BlockType() == types.PacePowReconfig {
		newNode = &common.Cnode{
			CoinBase: curKeyBlock.InAddress(),
			Public:   curKeyBlock.InPubKey(),
		}
	}

	mb, _ = bftview.GetCommittee(newNode, curKeyBlock, false)
	mb.StoreWithoutCallback(curKeyBlock)
}

// Update committee by keyblock
func (s *Service) updateCommittee(keyBlock *types.KeyBlock) bool {
	bStore := false
	curKeyBlock := keyBlock
	if bftview.IamMember() < 0 {
		return false
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), true)
	if mb != nil {
		return bStore
	}

	s.muCommitteeInfo.Lock()
	ac, ok := s.lastCmInfoMap[curKeyBlock.Hash()]
	if ok {
		if ac.committee != nil {
			mb = ac.committee
		} else if ac.node != nil {
			mb, _ = bftview.GetCommittee(ac.node, curKeyBlock, true)
		}
	}
	s.muCommitteeInfo.Unlock()

	if mb == nil && !curKeyBlock.HasNewNode() {
		mb, _ = bftview.GetCommittee(nil, curKeyBlock, true)
	}

	if mb != nil {
		bStore = mb.Store(curKeyBlock)
	} else {
		log.Info("updateCommittee can't found committee", "txNumber", s.bc.CurrentBlockN(), "keyNumber", curKeyBlock.NumberU64())
	}
	return bStore
}

func (s *Service) Committee_OnStored(keyblock *types.KeyBlock, mb *bftview.Committee) {
	log.Debug("store committee", "keyNumber", keyblock.NumberU64(), "ip0", mb.List[0].Address, "ipn", mb.List[len(mb.List)-1].Address)
	if keyblock.HasNewNode() && keyblock.NumberU64() == s.kbc.CurrentBlockN() {
		s.netService.AdjustConnect(keyblock.OutAddress(1))
	}
}

// Request committee for keyblock
func (s *Service) Committee_Request(kNumber uint64, hash common.Hash) {
	if kNumber <= s.lastReqCmNumber || !bftview.IamMemberByNumber(kNumber, hash) {
		return
	}

	log.Debug("Committee_Request", "keynumber", kNumber)

	var parentMb *bftview.Committee
	for i := 1; i < 10; i++ {
		keyblock := s.kbc.GetBlockByNumber(kNumber - uint64(i))
		if keyblock == nil {
			return
		}
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb != nil {
			parentMb = mb
			break
		}
	}
	if parentMb == nil {
		return
	}

	for _, node := range parentMb.List {
		if IsSelf(node.Address) {
			continue
		}
		s.netService.SendRawData(node.Address, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: hash, KeyNumber: kNumber}})
	}
	s.lastReqCmNumber = kNumber
}

func (s *Service) getBestCandidate(refresh bool) *types.Candidate {
	return s.keyService.getBestCandidate(refresh)
}
