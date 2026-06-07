package types

// AttachCommonTxData attaches common RPC admission/reward data and commits their
// BLAKE3 Merkle roots into the header. It is intended for block construction
// before any hash/size cache is used.
func (b *Block) AttachCommonTxData(admissions []*CommonTxAdmission, rewards []*CommonTxReward) {
	b.commonTxAdmissions = copyCommonTxAdmissions(admissions)
	b.commonTxRewards = copyCommonTxRewards(rewards)
	b.header.CommonTxAdmissionRoot = DeriveCommonTxAdmissionRoot(b.commonTxAdmissions)
	b.header.CommonTxRewardRoot = DeriveCommonTxRewardRoot(b.commonTxRewards)
}
