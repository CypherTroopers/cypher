// Package settlement implements native StateDB accounting for isolated devnets.
// Schema 3 is dispatched by ordinary CLX transactions only when authenticated
// genesis configuration enables it; schema 2 remains a component fixture.
// Committee-certified accounting does not prove DEX execution validity.
package settlement

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
)

const MaxDeposits = 4096
const PeriodLength = uint64(10)

type Bucket string

const (
	Unconsumed  Bucket = "U"
	Trader      Bucket = "T"
	Fees        Bucket = "F"
	Support     Bucket = "S"
	Insurance   Bucket = "I"
	Dust        Bucket = "Z"
	Withdrawals Bucket = "W"
	Rewards     Bucket = "R"
)

var bucketNames = []Bucket{Unconsumed, Trader, Fees, Support, Insurance, Dust, Withdrawals, Rewards}

type Config struct {
	Devnet           bool
	Custody          common.Address
	Domain           protocol.Domain
	GenesisRoot      protocol.Hash
	Epochs           []*checkpoint.Epoch
	FinalizedAnchors []checkpoint.FinalizedAnchor
	MaxCheckpoints   int
}

type Adapter struct {
	st            *state.StateDB // Legacy fixture handle; execution always uses db.
	db            nativeState
	custody       common.Address
	domain        protocol.Domain
	epochs        []*checkpoint.Epoch
	limit         uint64
	configHash    common.Hash
	nativeV2      bool
	nativeVersion uint16
	nativeRoot    protocol.Hash
	nativeGenesis common.Hash
	nativeSurplus common.Hash
}
type Status struct {
	Sequence, LastBlock, InboxCursor, Deposits, RewardPeriod uint64
	Hash, Summary, Root                                      protocol.Hash
}
type Acceptance struct {
	Sequence         uint64
	Hash             protocol.Hash
	Replay           bool
	Verification     checkpoint.VerifyStats
	DataAvailability string
}

func key(name string, n uint64, index uint32) common.Hash {
	var b bytes.Buffer
	b.WriteString(name)
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, n)
	_ = binary.Write(&b, binary.BigEndian, index)
	return common.Hash(protocol.Digest("common-dex/settlement/storage/v1", b.Bytes()))
}
func (a *Adapter) get(name string, n uint64) common.Hash {
	return a.db.GetState(a.custody, key(name, n, 0))
}
func (a *Adapter) set(name string, n uint64, value common.Hash) {
	a.db.SetState(a.custody, key(name, n, 0), value)
}
func (a *Adapter) number(name string) uint64 {
	h := a.get(name, 0)
	return binary.BigEndian.Uint64(h[24:])
}
func (a *Adapter) setNumber(name string, n uint64) {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], n)
	a.set(name, 0, h)
}
func (a *Adapter) readBlob(name string, n uint64, size int) []byte {
	raw := make([]byte, size)
	for offset := 0; offset < size; offset += 32 {
		h := a.db.GetState(a.custody, key(name, n, uint32(offset/32)))
		copy(raw[offset:], h[:])
	}
	return raw
}
func (a *Adapter) writeBlob(name string, n uint64, raw []byte) {
	for offset := 0; offset < len(raw); offset += 32 {
		var h common.Hash
		copy(h[:], raw[offset:])
		a.db.SetState(a.custody, key(name, n, uint32(offset/32)), h)
	}
}
func sameDomain(a, b protocol.Domain) bool {
	return a.Version == b.Version && a.ChainID == b.ChainID && a.Genesis == b.Genesis && a.DEXID == b.DEXID
}

func NewDevnet(st *state.StateDB, c Config) (*Adapter, error) {
	if !c.Devnet || st == nil || c.Custody == (common.Address{}) || !c.Domain.Valid() || c.GenesisRoot == (protocol.Hash{}) || len(c.Epochs) == 0 || len(c.Epochs) > 64 || len(c.FinalizedAnchors) == 0 || len(c.FinalizedAnchors) > 4096 || c.MaxCheckpoints < 1 || c.MaxCheckpoints > 4096 {
		return nil, errors.New("explicit isolated devnet configuration required")
	}
	a := &Adapter{st: st, db: st, custody: c.Custody, domain: c.Domain, epochs: append([]*checkpoint.Epoch(nil), c.Epochs...), limit: uint64(c.MaxCheckpoints)}
	var manifest bytes.Buffer
	_ = binary.Write(&manifest, binary.BigEndian, c.Domain)
	manifest.Write(c.Custody[:])
	manifest.Write(c.GenesisRoot[:])
	_ = binary.Write(&manifest, binary.BigEndian, uint64(c.MaxCheckpoints))
	_ = binary.Write(&manifest, binary.BigEndian, uint16(len(a.epochs)))
	for i, e := range a.epochs {
		if e == nil || !sameDomain(e.Domain(), c.Domain) {
			return nil, errors.New("invalid epoch registry")
		}
		first, end := e.Bounds()
		if i == 0 {
			if first != 1 || e.Domain() != c.Domain {
				return nil, errors.New("invalid first epoch")
			}
		} else {
			_, previousEnd := a.epochs[i-1].Bounds()
			if first != previousEnd || e.Domain().Epoch != a.epochs[i-1].Domain().Epoch+1 {
				return nil, errors.New("noncontiguous epoch registry")
			}
		}
		if end <= first {
			return nil, errors.New("invalid epoch bounds")
		}
		h := e.RegistryCommitment()
		manifest.Write(h[:])
	}
	anchors := append([]checkpoint.FinalizedAnchor(nil), c.FinalizedAnchors...)
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].Height < anchors[j].Height })
	_ = binary.Write(&manifest, binary.BigEndian, uint16(len(anchors)))
	for i, anchor := range anchors {
		if anchor.Hash == (protocol.Hash{}) || (i > 0 && anchors[i-1].Height == anchor.Height) {
			return nil, errors.New("invalid finalized anchor registry")
		}
		_ = binary.Write(&manifest, binary.BigEndian, anchor.Height)
		manifest.Write(anchor.Hash[:])
	}
	configHash := common.Hash(protocol.Digest("common-dex/settlement/config/v1", manifest.Bytes()))
	a.configHash = configHash
	existing := a.get("config", 0)
	if existing != (common.Hash{}) {
		if existing != configHash {
			return nil, errors.New("settlement config/registry mismatch")
		}
		if err := a.checkCustody(); err != nil {
			return nil, err
		}
		return a, nil
	}
	if st.GetBalance(c.Custody).Sign() != 0 || st.Exist(c.Custody) {
		return nil, errors.New("custody address must be unused at devnet initialization")
	}
	snapshot := st.Snapshot()
	// EIP-161 considers balance/nonce/code, not storage. Keep the reserved
	// custody account alive even before funding or after the final payment.
	st.SetNonce(c.Custody, 1)
	a.set("config", 0, configHash)
	a.set("root", 0, common.Hash(c.GenesisRoot))

	for _, anchor := range anchors {
		a.set("anchor", anchor.Height, common.Hash(anchor.Hash))
	}
	if err := st.Error(); err != nil {
		st.RevertToSnapshot(snapshot)
		return nil, err
	}
	return a, nil
}

func (a *Adapter) Status() Status {
	return Status{a.number("sequence"), a.number("last-block"), a.number("cursor"), a.number("deposits"), a.number("period"), protocol.Hash(a.get("accepted-hash", 0)), protocol.Hash(a.get("summary", 0)), protocol.Hash(a.get("root", 0))}
}
func (a *Adapter) Balances() (map[Bucket]protocol.Amount, error) {
	out := make(map[Bucket]protocol.Amount, len(bucketNames))
	for _, name := range bucketNames {
		value := protocol.Amount(a.get("bucket/"+string(name), 0))
		if !value.Valid() {
			return nil, errors.New("stored bucket exceeds u128")
		}
		out[name] = value
	}
	return out, a.db.Error()
}
func (a *Adapter) checkCustody() error {
	if a.get("config", 0) != a.configHash {
		return errors.New("settlement configuration absent or reverted")
	}
	values, err := a.Balances()
	if err != nil {
		return err
	}
	sum := new(big.Int)
	for _, v := range values {
		sum.Add(sum, v.Big())
	}
	if a.nativeV2 {
		sum.Add(sum, new(big.Int).SetBytes(a.get("native-surplus", 0).Bytes()))
	}
	maxBits := 128
	if a.nativeV2 {
		maxBits = 256
	}
	if sum.BitLen() > maxBits || sum.Cmp(a.db.GetBalance(a.custody)) != 0 {
		return errors.New("native custody/bucket mismatch")
	}
	return a.db.Error()
}
func (a *Adapter) writeBalances(values map[Bucket]*big.Int) error {
	for _, name := range bucketNames {
		amount, err := protocol.AmountFromBig(values[name])
		if err != nil {
			return err
		}
		a.set("bucket/"+string(name), 0, common.Hash(amount))
	}
	return nil
}
func (a *Adapter) mutableBalances() (map[Bucket]*big.Int, error) {
	values, err := a.Balances()
	if err != nil {
		return nil, err
	}
	out := make(map[Bucket]*big.Int, len(values))
	for name, v := range values {
		out[name] = v.Big()
	}
	return out, nil
}
func (a *Adapter) atomic(fn func() error) error {
	snapshot := a.db.Snapshot()
	if err := fn(); err != nil {
		a.db.RevertToSnapshot(snapshot)
		return err
	}
	if err := a.checkCustody(); err != nil {
		a.db.RevertToSnapshot(snapshot)
		return err
	}
	return nil
}
func (a *Adapter) transfer(from, to common.Address, amount *big.Int) error {
	if from == to || amount.Sign() <= 0 || a.db.GetBalance(from).Cmp(amount) < 0 {
		return errors.New("invalid or unfunded native transfer")
	}
	if new(big.Int).Add(a.db.GetBalance(to), amount).BitLen() > 256 {
		return errors.New("native recipient overflow")
	}
	a.db.SubBalance(from, new(big.Int).Set(amount))
	a.db.AddBalance(to, new(big.Int).Set(amount))
	return a.db.Error()
}

// Deposit receives an authenticated CLX transaction sender. Do not expose this
// signature directly as an RPC permitting callers to choose another sender.
func (a *Adapter) Deposit(sender common.Address, amount protocol.Amount, inclusion checkpoint.FinalizedAnchor) (protocol.Deposit, error) {
	if sender == (common.Address{}) || sender == a.custody || !amount.Valid() || amount == (protocol.Amount{}) || inclusion.Hash == (protocol.Hash{}) {
		return protocol.Deposit{}, errors.New("invalid native deposit")
	}
	if err := a.checkCustody(); err != nil {
		return protocol.Deposit{}, err
	}
	id := a.number("deposits")
	if id >= MaxDeposits {
		return protocol.Deposit{}, errors.New("deposit capacity")
	}
	d := protocol.Deposit{Version: 1, Domain: a.domain, Custody: [20]byte(a.custody), ID: id, Owner: [20]byte(sender), Amount: amount, CLXHeight: inclusion.Height, CLXHash: inclusion.Hash}
	raw, err := d.Encode()
	if err != nil {
		return protocol.Deposit{}, err
	}
	err = a.atomic(func() error {
		values, err := a.mutableBalances()
		if err != nil {
			return err
		}
		values[Unconsumed].Add(values[Unconsumed], amount.Big())
		if err = a.writeBalances(values); err != nil {
			return err
		}
		if err = a.transfer(sender, a.custody, amount.Big()); err != nil {
			return err
		}
		a.writeBlob("deposit", id, raw)
		a.setNumber("deposits", id+1)
		return nil
	})
	if err != nil {
		return protocol.Deposit{}, err
	}
	return d, nil
}
func (a *Adapter) FundPool(pool Bucket, sender common.Address, amount protocol.Amount) error {
	if pool != Support && pool != Insurance {
		return errors.New("only prepaid support/insurance funding is allowed")
	}
	if sender == (common.Address{}) || sender == a.custody || !amount.Valid() || amount == (protocol.Amount{}) {
		return errors.New("invalid pool funding")
	}
	if err := a.checkCustody(); err != nil {
		return err
	}
	return a.atomic(func() error {
		values, err := a.mutableBalances()
		if err != nil {
			return err
		}
		values[pool].Add(values[pool], amount.Big())
		if err = a.writeBalances(values); err != nil {
			return err
		}
		return a.transfer(sender, a.custody, amount.Big())
	})
}
func (a *Adapter) GetDeposit(id uint64) (protocol.Deposit, error) {
	if id >= a.number("deposits") {
		return protocol.Deposit{}, errors.New("unknown deposit")
	}
	d, err := protocol.DecodeDeposit(a.readBlob("deposit", id, protocol.DepositSize))
	if err != nil {
		return d, err
	}
	if d.ID != id || d.Custody != [20]byte(a.custody) || !sameDomain(d.Domain, a.domain) {
		return protocol.Deposit{}, errors.New("deposit storage identity mismatch")
	}
	return d, a.db.Error()
}
func (a *Adapter) Inbox(start, end uint64, anchor checkpoint.FinalizedAnchor) ([]protocol.Deposit, protocol.Hash, protocol.Amount, error) {
	if end < start || end-start > protocol.MaxDepositsPerCheckpoint || end > a.number("deposits") || a.get("anchor", anchor.Height) != common.Hash(anchor.Hash) || anchor.Hash == (protocol.Hash{}) {
		return nil, protocol.Hash{}, protocol.Amount{}, errors.New("invalid or unfinalized deposit range")
	}
	deposits := make([]protocol.Deposit, 0, end-start)
	sum := new(big.Int)
	for id := start; id < end; id++ {
		d, err := a.GetDeposit(id)
		if err != nil {
			return nil, protocol.Hash{}, protocol.Amount{}, err
		}
		if d.CLXHeight > anchor.Height || a.get("anchor", d.CLXHeight) != common.Hash(d.CLXHash) {
			return nil, protocol.Hash{}, protocol.Amount{}, errors.New("deposit inclusion is not finalized")
		}
		deposits = append(deposits, d)
		sum.Add(sum, d.Amount.Big())
	}
	root, err := protocol.DepositInboxRoot(deposits)
	if err != nil {
		return nil, protocol.Hash{}, protocol.Amount{}, err
	}
	total, err := protocol.AmountFromBig(sum)
	return deposits, root, total, err
}

func (a *Adapter) Accept(c protocol.Checkpoint, f protocol.FinanceSummary, proof []byte) (Acceptance, error) {
	return a.acceptVerified(c, f, proof, nil)
}

type verifiedInbox struct {
	root  protocol.Hash
	total protocol.Amount
}

func (a *Adapter) acceptVerified(c protocol.Checkpoint, f protocol.FinanceSummary, proof []byte, verified *verifiedInbox) (Acceptance, error) {
	result := Acceptance{Sequence: c.Sequence, DataAvailability: checkpoint.DataAvailabilityNotVerified}
	if err := a.checkCustody(); err != nil {
		return result, err
	}
	nativeSchema := uint16(3)
	if a.nativeVersion == 3 {
		nativeSchema = 4
	}
	if a.nativeVersion == 4 {
		nativeSchema = 5
	}
	if a.nativeVersion == 5 {
		nativeSchema = 6
	}
	if (verified == nil && c.DataSchema != 2) || (verified != nil && c.DataSchema != nativeSchema) {
		return result, errors.New("financial checkpoint schema differs from authenticated configuration")
	}
	hash, err := c.Hash()
	if err != nil {
		return result, err
	}
	result.Hash = hash
	if previous := a.get("history", c.Sequence); previous != (common.Hash{}) {
		if previous != common.Hash(hash) {
			return result, checkpoint.ErrCheckpointConflict
		}
		fh, err := f.Hash()
		if err != nil || fh != c.FundingRef {
			return result, errors.New("replay summary mismatch")
		}
		result.Replay = true
		return result, nil
	}
	s := a.Status()
	if c.Sequence == 0 || c.Sequence > a.limit || c.Sequence != s.Sequence+1 || c.Previous != s.Hash || c.PreRoot != s.Root || c.FirstBlock != s.LastBlock+1 || c.LastBlock < c.FirstBlock || c.LastBlock-c.FirstBlock >= 1024 || !sameDomain(c.Domain(), a.domain) {
		return result, checkpoint.ErrCheckpointConnection
	}
	if f.Custody != [20]byte(a.custody) || f.Domain != c.Domain() || f.Sequence != c.Sequence || f.Previous != s.Summary {
		return result, errors.New("finance summary connection mismatch")
	}
	summaryHash, err := f.Hash()
	if err != nil {
		return result, err
	}
	if summaryHash != c.FundingRef {
		return result, errors.New("finance commitment mismatch")
	}
	anchor := checkpoint.FinalizedAnchor{Height: c.CLXHeight, Hash: c.CLXHash}
	if c.CLXHeight < a.number("clx-height") || c.InboxStart != s.InboxCursor {
		return result, errors.New("anchor/inbox regression")
	}
	var root protocol.Hash
	var depositTotal protocol.Amount
	if verified == nil {
		_, root, depositTotal, err = a.Inbox(c.InboxStart, c.InboxEnd, anchor)
		if err != nil {
			return result, err
		}
	} else {
		root, depositTotal = verified.root, verified.total
	}
	if root != c.InboxRoot || depositTotal != f.DepositTotal {
		return result, errors.New("authenticated deposit total/root mismatch")
	}
	reward := new(big.Int).Add(f.RewardFromFees.Big(), f.RewardFromSupport.Big())
	rewardAmount, err := protocol.AmountFromBig(reward)
	if err != nil {
		return result, err
	}
	if f.WithdrawalTotal != c.WithdrawalTotal || rewardAmount != c.RewardTotal || f.RewardPeriod != c.RewardPeriod {
		return result, errors.New("checkpoint reservation mismatch")
	}
	if (c.WithdrawalTotal == (protocol.Amount{})) != (c.WithdrawalRoot == (protocol.Hash{})) || (c.RewardTotal == (protocol.Amount{})) != (c.RewardRoot == (protocol.Hash{})) {
		return result, errors.New("noncanonical empty reserve root")
	}
	values, err := a.mutableBalances()
	if err != nil {
		return result, err
	}
	if f.RewardPeriod != 0 {
		if f.RewardPeriod != s.RewardPeriod+1 || f.RewardPeriod > a.limit/PeriodLength || f.FeePeriodFirst != (f.RewardPeriod-1)*PeriodLength+1 || f.FeePeriodLast != f.RewardPeriod*PeriodLength || c.Sequence < f.FeePeriodLast+4 {
			return result, errors.New("reward period replay/gap/prefinality close")
		}
		periodFees := new(big.Int)
		for sequence := f.FeePeriodFirst; sequence <= f.FeePeriodLast; sequence++ {
			if a.get("history", sequence) == (common.Hash{}) {
				return result, errors.New("reward fee range not accepted")
			}
			periodFees.Add(periodFees, new(big.Int).SetBytes(a.get("collected-fees", sequence).Bytes()))
		}
		if periodFees.BitLen() > 128 {
			return result, errors.New("period fees overflow")
		}
		feeShare := new(big.Int).Quo(periodFees, big.NewInt(2))
		supportAllowance := min(values[Support], clx(2))
		budget := min(new(big.Int).Add(feeShare, supportAllowance), clx(1))
		if reward.Cmp(budget) > 0 || f.RewardFromFees.Big().Cmp(min(feeShare, reward)) != 0 || f.RewardFromSupport.Big().Cmp(supportAllowance) > 0 {
			return result, errors.New("unfunded/excess reward budget")
		}
	}
	values[Unconsumed].Sub(values[Unconsumed], depositTotal.Big())
	values[Trader].Add(values[Trader], depositTotal.Big())
	values[Trader].Add(values[Trader], f.InsuranceUsed.Big())
	values[Trader].Sub(values[Trader], f.CollectedFees.Big())
	values[Trader].Sub(values[Trader], f.FundingDust.Big())
	values[Trader].Sub(values[Trader], f.WithdrawalTotal.Big())
	values[Fees].Add(values[Fees], f.CollectedFees.Big())
	values[Fees].Sub(values[Fees], f.RewardFromFees.Big())
	values[Support].Sub(values[Support], f.RewardFromSupport.Big())
	values[Insurance].Sub(values[Insurance], f.InsuranceUsed.Big())
	values[Dust].Add(values[Dust], f.FundingDust.Big())
	values[Withdrawals].Add(values[Withdrawals], f.WithdrawalTotal.Big())
	values[Rewards].Add(values[Rewards], reward)
	for _, value := range values {
		if _, err := protocol.AmountFromBig(value); err != nil {
			return result, fmt.Errorf("bucket source/limit: %w", err)
		}
	}
	var epoch *checkpoint.Epoch
	for _, e := range a.epochs {
		first, end := e.Bounds()
		if c.Sequence >= first && c.Sequence < end && c.Domain() == e.Domain() {
			epoch = e
			break
		}
	}
	if epoch == nil {
		return result, checkpoint.ErrUnauthorizedEpoch
	}
	result.Verification, err = epoch.Verify(c, proof)
	if err != nil {
		return result, err
	}
	cpraw, _ := c.Encode()
	fraw, _ := f.Encode()
	err = a.atomic(func() error {
		if err := a.writeBalances(values); err != nil {
			return err
		}
		a.writeBlob("checkpoint", c.Sequence, cpraw)
		a.writeBlob("finance", c.Sequence, fraw)
		a.set("history", c.Sequence, common.Hash(hash))
		a.set("accepted-hash", 0, common.Hash(hash))
		a.set("summary", 0, common.Hash(summaryHash))
		a.set("root", 0, common.Hash(c.PostRoot))
		a.setNumber("sequence", c.Sequence)
		a.setNumber("last-block", c.LastBlock)
		a.setNumber("cursor", c.InboxEnd)
		a.setNumber("clx-height", c.CLXHeight)
		if f.RewardPeriod != 0 {
			a.setNumber("period", f.RewardPeriod)

		}
		a.set("collected-fees", c.Sequence, common.Hash(f.CollectedFees))
		return nil
	})
	return result, err
}
func min(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}
func clx(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
}

// Claim pays only the fixed authenticated recipient. A valid duplicate is a no-op.
func (a *Adapter) Claim(c protocol.Claim, index, count uint32, siblings []protocol.Hash) (bool, error) {
	if err := a.checkCustody(); err != nil {
		return false, err
	}
	if err := c.Validate(); err != nil {
		return false, err
	}
	if !c.Amount.Valid() || common.Address(c.Recipient) == a.custody {
		return false, errors.New("invalid devnet claim amount/recipient")
	}
	if a.get("history", c.Sequence) == (common.Hash{}) {
		return false, errors.New("checkpoint not accepted")
	}
	cp, err := protocol.DecodeCheckpoint(a.readBlob("checkpoint", c.Sequence, protocol.CheckpointSize))
	if err != nil {
		return false, err
	}
	if c.Domain != cp.Domain() {
		return false, errors.New("claim domain mismatch")
	}
	root, reserve, bucket, paidName := cp.WithdrawalRoot, cp.WithdrawalTotal, Withdrawals, "withdrawal-paid"
	if c.Kind == protocol.Reward {
		if c.Period != cp.RewardPeriod {
			return false, errors.New("claim reward period mismatch")
		}
		root, reserve, bucket, paidName = cp.RewardRoot, cp.RewardTotal, Rewards, "reward-paid"
	}
	leaf, err := c.Hash()
	if err != nil {
		return false, err
	}
	if err = protocol.VerifyCountedInclusion(root, leaf, index, count, siblings); err != nil {
		return false, err
	}
	nullifier, _ := c.Nullifier()
	nullSlot := common.Hash(protocol.Digest("common-dex/settlement/nullifier/v1", nullifier[:]))
	if existing := a.db.GetState(a.custody, nullSlot); existing != (common.Hash{}) {
		if existing == common.Hash(leaf) {
			return true, nil
		}
		return false, errors.New("claim ID already used by another leaf")
	}
	paid := new(big.Int).SetBytes(a.get(paidName, c.Sequence).Bytes())
	paid.Add(paid, c.Amount.Big())
	if paid.Cmp(reserve.Big()) > 0 {
		return false, errors.New("checkpoint reserve exhausted")
	}
	values, err := a.mutableBalances()
	if err != nil {
		return false, err
	}
	values[bucket].Sub(values[bucket], c.Amount.Big())
	if values[bucket].Sign() < 0 {
		return false, errors.New("global reserve exhausted")
	}
	err = a.atomic(func() error {
		if err := a.writeBalances(values); err != nil {
			return err
		}
		if err := a.transfer(a.custody, common.Address(c.Recipient), c.Amount.Big()); err != nil {
			return err
		}
		paidAmount, err := protocol.AmountFromBig(paid)
		if err != nil {
			return err
		}
		a.set(paidName, c.Sequence, common.Hash(paidAmount))
		a.db.SetState(a.custody, nullSlot, common.Hash(leaf))
		return nil
	})
	return false, err
}
