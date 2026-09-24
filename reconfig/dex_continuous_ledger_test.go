package reconfig_test

// This observer reconciles every canonical TX, including independent relay
// senders. It does not submit checkpoints or patch a node's synchronization.
import (
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

type continuousLedger struct {
	base                                                  *nativeLedger
	scanned                                               uint64
	seenClaims                                            map[protocol.Hash]bool
	accepted                                              map[uint64]protocol.Hash
	buckets                                               map[settlement.Bucket]*big.Int
	operationCounts                                       map[string]uint64
	anchorProgressHeight                                  uint64
	maxCalldata, maxHeaders, maxProofNodes, maxProofBytes int
}

func newContinuousLedger(t *testing.T, base *nativeLedger) *continuousLedger {
	t.Helper()
	if len(base.txs) != 0 || base.height != 0 {
		t.Fatal("continuous observer must start at genesis")
	}
	b := map[settlement.Bucket]*big.Int{}
	for _, k := range []settlement.Bucket{settlement.Unconsumed, settlement.Trader, settlement.Fees, settlement.Support, settlement.Insurance, settlement.Dust, settlement.Withdrawals, settlement.Rewards} {
		b[k] = new(big.Int)
	}
	return &continuousLedger{base: base, seenClaims: map[protocol.Hash]bool{}, accepted: map[uint64]protocol.Hash{}, buckets: b, operationCounts: map[string]uint64{}}
}
func (l *continuousLedger) scan(t *testing.T, height uint64) {
	t.Helper()
	l.base.network.WaitFinalized(height)
	for h := l.scanned + 1; h <= height; h++ {
		var raw hexutil.Bytes
		if err := l.base.clients[0].Call(&raw, "dexfixture_block", hexutil.Uint64(h)); err != nil {
			t.Fatal(err)
		}
		var block types.Block
		if err := rlp.DecodeBytes(raw, &block); err != nil || block.NumberU64() != h {
			t.Fatal("canonical accounting block", err)
		}
		var blockGas uint64
		for _, tx := range block.Transactions() {
			r := nativeWaitReceipt(t, l.base.clients[0], tx.Hash())
			if r.BlockHash != block.Hash() || uint64(r.BlockNumber) != h {
				t.Fatal("receipt not bound to accounting block")
			}
			for _, c := range l.base.clients[1:] {
				if other := nativeWaitReceipt(t, c, tx.Hash()); !reflect.DeepEqual(r, other) {
					t.Fatal("relay receipt differs across CLX committee")
				}
			}
			payer, err := types.Sender(types.NewEIP155Signer(l.base.network.Fixture.Genesis.Config.ChainID), tx)
			if err != nil {
				t.Fatal(err)
			}
			if tx.Nonce() != l.base.nonces[payer] {
				t.Fatalf("canonical sender nonce gap payer=%s got=%d want=%d", payer.Hex(), tx.Nonce(), l.base.nonces[payer])
			}
			l.base.nonces[payer]++
			if r.EffectiveGasPrice == nil || (*big.Int)(r.EffectiveGasPrice).Cmp(tx.GasPrice()) != 0 {
				t.Fatal("legacy fixture effective gas mismatch")
			}
			gas := new(big.Int).Mul(new(big.Int).SetUint64(uint64(r.GasUsed)), tx.GasPrice())
			commonShare := new(big.Int).Quo(new(big.Int).Set(gas), big.NewInt(5))
			if r.CommonTxRewardRecipient != l.base.network.Fixture.RewardRecipient || r.CommonTxApproverReward == nil || (*big.Int)(r.CommonTxApproverReward).Cmp(commonShare) != 0 {
				t.Fatal("continuous Common reward mismatch")
			}
			l.base.add(payer, new(big.Int).Neg(gas))
			l.base.add(r.CommonTxRewardRecipient, commonShare)
			l.base.gas.Add(l.base.gas, gas)
			l.base.reward.Add(l.base.reward, commonShare)
			l.base.burn.Add(l.base.burn, new(big.Int).Sub(gas, commonShare))
			blockGas += uint64(r.GasUsed)
			operation := "transfer"
			if tx.To() == nil {
				t.Fatal("continuous ledger fixture does not authorize contract creation")
			}
			if uint64(r.Status) == types.ReceiptStatusSuccessful {
				l.base.add(payer, new(big.Int).Neg(tx.Value()))
				l.base.add(*tx.To(), tx.Value())
				if *tx.To() == params.DEXSettlementAddress {
					operation = l.native(t, tx, r)
				} else if len(tx.Data()) > 0 {
					t.Fatal("unknown non-native execution in accounting fixture")
				}
			} else {
				operation = "reverted"
				if len(r.Logs) != 0 {
					t.Fatal("reverted native logs survived")
				}
			}
			l.operationCounts[operation]++
			l.base.txs = append(l.base.txs, tx)
			t.Logf("CONTINUOUS_TX height=%d block=%s tx=%s payer=%s nonce=%d op=%s status=%d gas=%d gasAtoms=%s commonAtoms=%s calldata=%d", h, block.Hash().Hex(), tx.Hash().Hex(), payer.Hex(), tx.Nonce(), operation, r.Status, r.GasUsed, gas, commonShare, len(tx.Data()))
		}
		if blockGas != block.GasUsed() {
			t.Fatal("continuous receipts gas differs from header")
		}
		l.scanned = h
		l.base.height = h
	}
}
func (l *continuousLedger) native(t *testing.T, tx *types.Transaction, r nativeReceipt) string {
	t.Helper()
	call, err := protocol.DecodeNativeCall(tx.Data())
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Data()) > l.maxCalldata {
		l.maxCalldata = len(tx.Data())
	}
	switch call.Operation {
	case protocol.NativeDeposit, protocol.NativeSupport, protocol.NativeInsurance:
		bucket := settlement.Unconsumed
		if call.Operation == protocol.NativeSupport {
			bucket = settlement.Support
		}
		if call.Operation == protocol.NativeInsurance {
			bucket = settlement.Insurance
		}
		l.buckets[bucket].Add(l.buckets[bucket], tx.Value())
		return fmt.Sprintf("funding-%d", call.Operation)
	case protocol.NativeAnchorUpdate:
		evidence, continuation, err := settlement.DecodeAnchorUpdate(call.Body)
		if err != nil {
			t.Fatal(err)
		}
		// Only a new canonical storage effect may count as watchdog progress.
		// Exact anchor replays intentionally emit no NativeAnchorTopic event.
		for _, event := range r.Logs {
			if event.Address == params.DEXSettlementAddress && len(event.Topics) == 1 && event.Topics[0] == settlement.NativeAnchorTopic {
				var target types.Header
				if len(event.Data) != 40 || len(evidence.Headers) == 0 || rlp.DecodeBytes(evidence.Headers[len(evidence.Headers)-1].Header, &target) != nil || target.Number == nil || !target.Number.IsUint64() {
					t.Fatal("canonical anchor progress event malformed")
				}
				if target.Number.Uint64() > l.anchorProgressHeight {
					l.anchorProgressHeight = target.Number.Uint64()
				}
			}
		}
		headers := len(evidence.Headers) + len(continuation)
		nodes, proofBytes := len(evidence.AccountProof)+len(evidence.CountProof), 0
		for _, list := range [][][]byte{evidence.AccountProof, evidence.CountProof} {
			for _, v := range list {
				proofBytes += len(v)
			}
		}
		for _, entry := range evidence.Entries {
			nodes += len(entry.Proof)
			for _, v := range entry.Proof {
				proofBytes += len(v)
			}
		}
		if headers > clxevidence.MaxAncestryBlocks || len(tx.Data()) > protocol.MaxNativeCallBytes {
			t.Fatal("continuous proof bounds expanded")
		}
		if headers > l.maxHeaders {
			l.maxHeaders = headers
		}
		if nodes > l.maxProofNodes {
			l.maxProofNodes = nodes
		}
		if proofBytes > l.maxProofBytes {
			l.maxProofBytes = proofBytes
		}
		t.Logf("CONTINUOUS_ANCHOR_COST tx=%s calldata=%d headers=%d mptNodes=%d mptBytes=%d gas=%d", tx.Hash().Hex(), len(tx.Data()), headers, nodes, proofBytes, r.GasUsed)
		return "anchor"
	case protocol.NativeCheckpoint:
		cp, f, _, _, err := protocol.DecodeNativeCheckpoint(call.Body)
		if err != nil {
			t.Fatal(err)
		}
		hash, _ := cp.Hash()
		if old, ok := l.accepted[cp.Sequence]; ok {
			if old != hash {
				t.Fatal("conflicting canonical checkpoint")
			}
			return "checkpoint-replay"
		}
		l.accepted[cp.Sequence] = hash
		moves := []struct {
			from, to settlement.Bucket
			amount   protocol.Amount
		}{
			{settlement.Unconsumed, settlement.Trader, f.DepositTotal}, {settlement.Insurance, settlement.Trader, f.InsuranceUsed},
			{settlement.Trader, settlement.Fees, f.CollectedFees}, {settlement.Trader, settlement.Dust, f.FundingDust},
			{settlement.Trader, settlement.Withdrawals, f.WithdrawalTotal}, {settlement.Fees, settlement.Rewards, f.RewardFromFees}, {settlement.Support, settlement.Rewards, f.RewardFromSupport},
		}
		for _, m := range moves {
			l.buckets[m.from].Sub(l.buckets[m.from], m.amount.Big())
			l.buckets[m.to].Add(l.buckets[m.to], m.amount.Big())
		}
		t.Logf("CONTINUOUS_CHECKPOINT sequence=%d hash=%x anchor=%d/%x inbox=%d..%d fee=%s rewardFee=%s rewardSupport=%s", cp.Sequence, hash, cp.CLXHeight, cp.CLXHash, cp.InboxStart, cp.InboxEnd, f.CollectedFees.Big(), f.RewardFromFees.Big(), f.RewardFromSupport.Big())
		return "checkpoint"
	case protocol.NativeClaim:
		claim, _, _, _, err := protocol.DecodeNativeClaim(call.Body)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := claim.Hash()
		already := l.seenClaims[leaf]
		found := false
		for _, log := range r.Logs {
			if log.Address == params.DEXSettlementAddress && len(log.Topics) == 1 && log.Topics[0] == settlement.NativeClaimTopic {
				if len(log.Data) != 33 || common.BytesToHash(log.Data[:32]) != common.Hash(leaf) || (log.Data[32] == 1) != already {
					t.Fatal("claim replay event/accounting mismatch")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("successful claim event absent")
		}
		if already {
			return "claim-replay"
		}
		l.seenClaims[leaf] = true
		bucket := settlement.Withdrawals
		if claim.Kind == protocol.Reward {
			bucket = settlement.Rewards
		}
		amount := claim.Amount.Big()
		l.buckets[bucket].Sub(l.buckets[bucket], amount)
		l.base.add(params.DEXSettlementAddress, new(big.Int).Neg(amount))
		l.base.add(common.Address(claim.Recipient), amount)
		t.Logf("CONTINUOUS_CLAIM id=%x seq=%d recipient=%x amount=%s kind=%d", leaf, claim.Sequence, claim.Recipient, amount, claim.Kind)
		return "claim"
	default:
		t.Fatal("unknown successful native operation")
	}
	return "unknown"
}
func (l *continuousLedger) reconcile(t *testing.T) {
	t.Helper()
	l.base.reconcile(t)
	p := l.base.projection(t)
	sum := new(big.Int)
	keys := make([]string, 0, len(l.buckets))
	for k := range l.buckets {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	for _, name := range keys {
		key := settlement.Bucket(name)
		want := l.buckets[key]
		got := p.Buckets[key].Big()
		if want.Sign() < 0 || got.Cmp(want) != 0 {
			t.Fatalf("continuous bucket %s got=%s want=%s", key, got, want)
		}
		sum.Add(sum, want)
		t.Logf("CONTINUOUS_BUCKET key=%s atoms=%s", key, want)
	}
	if new(big.Int).Add(sum, p.Surplus.Big()).Cmp(p.Balance) != 0 {
		t.Fatal("continuous custody conservation")
	}
	t.Logf("CONTINUOUS_LIMITS maxCalldata=%d maxHeaders=%d maxMPTNodes=%d maxMPTBytes=%d operationCounts=%v", l.maxCalldata, l.maxHeaders, l.maxProofNodes, l.maxProofBytes, l.operationCounts)
}
