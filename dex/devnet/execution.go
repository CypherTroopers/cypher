// Package devnet composes the explicitly isolated financial experiment. CLX
// settlement never imports this package or the Common-side execution engine.
package devnet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/dex/accounting"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
)

type FinancialState struct {
	Version              uint16
	Registry             protocol.Hash
	Engine               json.RawMessage
	Finance              *protocol.FinanceSummary
	Fees                 []protocol.Amount
	Withdrawals, Rewards []protocol.Claim
	Anchor               *NativeAnchor           `json:",omitempty"`
	Participation        *rewards.CommittedState `json:",omitempty"`
	RollingAnchor        *clxevidence.Anchor     `json:",omitempty"`
	FeeHistory           *FeeHistory             `json:",omitempty"`
}

func (s *FinancialState) Encode() ([]byte, error) {
	b, err := json.Marshal(s)
	if len(b) > consensus.MaxStateBytes {
		return nil, errors.New("financial state bound")
	}
	return b, err
}
func (s *FinancialState) Root() (protocol.Hash, error) {
	b, err := s.Encode()
	if err != nil {
		return protocol.Hash{}, err
	}
	if s.Version == 2 {
		return protocol.Digest("common-dex/financial-state/v2", b), nil
	}
	if s.Version == 3 {
		return protocol.Digest("common-dex/financial-state/v3", b), nil
	}
	if s.Version == 4 {
		return protocol.Digest("common-dex/financial-state/v4", b), nil
	}
	if s.Version == 5 {
		return protocol.Digest("common-dex/financial-state/v5", b), nil
	}
	if s.Version == 6 {
		return protocol.Digest("common-dex/financial-state/v6", b), nil
	}
	return protocol.Digest("common-dex/financial-state/v1", b), nil
}

type Execution struct {
	Market    *engine.Engine
	Registry  *rewards.Registry
	Collector *rewards.Collector
	Native    *NativeContext
}

type NativeAnchor struct {
	Height uint64
	Hash   protocol.Hash
}
type NativeContext struct {
	Seed     protocol.Hash
	Verifier *clxevidence.Verifier
	// Rolling is selected only from the authenticated isolated genesis version3.
	Rolling bool
	// Continuous requires the authenticated v4 genesis and rolling evidence.
	Continuous bool
	// Ancestry selects schema6 from authenticated devnet configuration v5.
	// Financial state and arithmetic remain version6.
	Ancestry bool
}

func (e *Execution) ID() string {
	if e.Native != nil && e.Native.Ancestry {
		return "BTC-CLX-native-finance-v6-history-v1"
	}
	if e.continuous() {
		return "BTC-CLX-native-finance-v6"
	}
	if e.rolling() {
		return "BTC-CLX-native-finance-v5"
	}
	if e.Native != nil {
		return "BTC-CLX-native-finance-v4"
	}
	return "BTC-CLX-isolated-finance-v3"
}
func (e *Execution) Schema() uint16 {
	if e.Native != nil && e.Native.Ancestry {
		return consensus.AncestryExecutionSchema
	}
	if e.continuous() {
		return consensus.ContinuousExecutionSchema
	}
	if e.rolling() {
		return consensus.RollingExecutionSchema
	}
	if e.Native != nil {
		return consensus.NativeExecutionSchema
	}
	return consensus.ExecutionSchema
}

func (e *Execution) Genesis() ([]byte, protocol.Hash, error) {
	if e.Native != nil && e.Native.Ancestry && !e.continuous() {
		return nil, protocol.Hash{}, errors.New("ancestry finance requires continuous storage and rolling evidence")
	}
	if e.Native != nil && e.Native.Continuous && !e.rolling() {
		return nil, protocol.Hash{}, errors.New("continuous finance requires rolling evidence")
	}
	if e.Registry == nil {
		return nil, protocol.Hash{}, errors.New("authenticated reward registry required")
	}
	s, err := e.Market.Genesis()
	if err != nil {
		return nil, protocol.Hash{}, err
	}
	raw, err := s.Encode()
	if err != nil {
		return nil, protocol.Hash{}, err
	}
	f := FinancialState{Version: 1, Registry: e.Registry.Commitment(), Engine: raw, Fees: []protocol.Amount{}, Withdrawals: []protocol.Claim{}, Rewards: []protocol.Claim{}}
	if e.Native != nil {
		seed, seedErr := protocol.NativeMarketSeed(e.Market.Oracle())
		if seedErr != nil || seed != e.Native.Seed || !e.Market.NativeInboxEnabled() || e.Registry.Domain() != e.Market.Domain() || !e.Registry.NativeRecipientsBound() || e.Native.Verifier == nil || s.Total != "0" || s.InboxCursor != 0 {
			return nil, protocol.Hash{}, errors.New("native empty genesis required")
		}
		f.Version = 2
		if e.rolling() {
			anchor, err := e.Native.Verifier.BootstrapAnchor()
			if err != nil {
				return nil, protocol.Hash{}, err
			}
			f.Version, f.RollingAnchor, f.Participation = 5, &anchor, &rewards.CommittedState{Version: 2, Entries: []rewards.CommittedEntry{}}
			if e.continuous() {
				f.Version, f.FeeHistory = 6, newFeeHistory()
			}
		}
	}
	b, err := f.Encode()
	if err != nil {
		return nil, protocol.Hash{}, err
	}
	if e.Native != nil {
		if e.continuous() {
			h, err := protocol.NativeGenesisRootV4(e.Native.Seed, e.Market.Domain(), e.Market.Custody())
			return b, h, err
		}
		if e.rolling() {
			h, err := protocol.NativeGenesisRootV3(e.Native.Seed, e.Market.Domain(), e.Market.Custody())
			return b, h, err
		}
		h, err := protocol.NativeGenesisRoot(e.Native.Seed, e.Market.Domain(), e.Market.Custody())
		return b, h, err
	}
	h, err := f.Root()
	return b, h, err
}
func (e *Execution) Decode(raw []byte) (*FinancialState, *engine.State, error) {
	if len(raw) == 0 || len(raw) > consensus.MaxStateBytes {
		return nil, nil, errors.New("financial state bound")
	}
	var s FinancialState
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return nil, nil, err
	}
	canonical, err := s.Encode()
	validVersion := s.Version == e.version() || (!e.rolling() && s.Version == e.version()+2)
	if err != nil || !bytes.Equal(raw, canonical) || !validVersion || (e.Native == nil && s.Anchor != nil) || e.Registry == nil || s.Registry != e.Registry.Commitment() {
		return nil, nil, errors.New("noncanonical financial state")
	}
	if e.rolling() {
		if s.Anchor != nil || s.RollingAnchor == nil || e.validateRollingAnchor(*s.RollingAnchor) != nil {
			return nil, nil, errors.New("rolling financial anchor identity")
		}
	} else if s.RollingAnchor != nil {
		return nil, nil, errors.New("rolling anchor in legacy financial state")
	}
	market, err := e.Market.Decode(s.Engine)
	if err != nil {
		return nil, nil, err
	}
	if (s.Version >= 3) != (s.Participation != nil) {
		return nil, nil, errors.New("participation state version")
	}
	if s.Participation != nil {
		if err := e.Registry.ValidateCommitted(s.Participation, market.RewardPeriod, market.Height); err != nil {
			return nil, nil, err
		}
	}
	if len(s.Withdrawals) > 1 || len(s.Rewards) > 7 {
		return nil, nil, errors.New("financial history bound")
	}
	if e.continuous() {
		if len(s.Fees) != 0 || s.Fees == nil || s.FeeHistory == nil {
			return nil, nil, errors.New("continuous fee history required")
		}
		if err := s.FeeHistory.validate(market.Height, market.RewardPeriod, market.PeriodFees); err != nil {
			return nil, nil, err
		}
	} else if s.FeeHistory != nil || uint64(len(s.Fees)) != market.Height || len(s.Fees) > consensus.MaxRecords {
		return nil, nil, errors.New("legacy financial history bound")
	}
	periodSum := new(big.Int)
	for i, fee := range s.Fees {
		if !fee.Valid() {
			return nil, nil, errors.New("financial fee bound")
		}
		periodSum.Add(periodSum, fee.Big())
		if periodSum.BitLen() > 128 {
			return nil, nil, errors.New("financial period fee bound")
		}
		if (i+1)%10 == 0 {
			periodSum.SetInt64(0)
		}
	}
	if market.Height == 0 {
		if s.Finance != nil {
			return nil, nil, errors.New("unexpected genesis summary")
		}
	} else if s.Finance == nil || s.Finance.Sequence != market.Height || s.Finance.Domain != e.Market.Domain() {
		return nil, nil, errors.New("financial summary mismatch")
	}
	if s.Finance != nil {
		if err := s.Finance.Validate(); err != nil {
			return nil, nil, err
		}
		lastFee := protocol.Amount{}
		if e.continuous() {
			lastFee = s.FeeHistory.LastFee
		} else {
			lastFee = s.Fees[len(s.Fees)-1]
		}
		if s.Finance.Custody != e.Market.Custody() || lastFee != s.Finance.CollectedFees {
			return nil, nil, errors.New("financial custody/fee mismatch")
		}
		for _, set := range []struct {
			claims []protocol.Claim
			kind   uint8
			total  *big.Int
		}{{s.Withdrawals, protocol.Withdrawal, s.Finance.WithdrawalTotal.Big()}, {s.Rewards, protocol.Reward, new(big.Int).Add(s.Finance.RewardFromFees.Big(), s.Finance.RewardFromSupport.Big())}} {
			total := new(big.Int)
			var last protocol.Hash
			for i, c := range set.claims {
				if err := c.Validate(); err != nil {
					return nil, nil, err
				}
				if !c.Amount.Valid() || c.Domain != e.Market.Domain() || c.Sequence != market.Height || c.Kind != set.kind || (i > 0 && bytes.Compare(last[:], c.ID[:]) >= 0) || (c.Kind == protocol.Reward && c.Period != s.Finance.RewardPeriod) {
					return nil, nil, errors.New("financial claim mismatch")
				}
				last = c.ID
				total.Add(total, c.Amount.Big())
			}
			if total.Cmp(set.total) != 0 {
				return nil, nil, errors.New("financial claim total mismatch")
			}
		}
	} else if len(s.Withdrawals) != 0 || len(s.Rewards) != 0 {
		return nil, nil, errors.New("genesis claims")
	}
	return &s, market, nil
}
func makeAmount(v string) protocol.Amount {
	n, ok := new(big.Int).SetString(v, 10)
	if !ok {
		panic("internal finance amount")
	}
	a, err := protocol.AmountFromBig(n)
	if err != nil {
		panic(err)
	}
	return a
}
func add(a, b string) string {
	return new(big.Int).Add(makeAmount(a).Big(), makeAmount(b).Big()).String()
}
func subtract(a, b string) (string, error) {
	n := new(big.Int).Sub(makeAmount(a).Big(), makeAmount(b).Big())
	v, err := protocol.AmountFromBig(n)
	if err != nil {
		return "", err
	}
	return v.Big().String(), nil
}

func EncodeRewardAction(command engine.Action, key *ecdsa.PrivateKey, pkg rewards.ClosePackage) ([]byte, error) {
	b, err := pkg.Encode()
	if err != nil {
		return nil, err
	}
	h := protocol.Digest("common-dex/reward-close-action/v1", b)
	command.Kind = engine.RewardClose
	copy(command.Target[:], h[:20])
	signed, err := engine.Sign(command, key)
	if err != nil {
		return nil, err
	}
	out := append([]byte("CDXR"), signed...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	out = append(out, n[:]...)
	out = append(out, b...)
	if len(out) > consensus.MaxActionBytes {
		return nil, errors.New("reward action byte bound")
	}
	return out, nil
}
func decodeAction(raw []byte) ([]byte, *rewards.ClosePackage, error) {
	if len(raw) == engine.SignedActionSize {
		return raw, nil, nil
	}
	if len(raw) < 4+engine.SignedActionSize+4 || len(raw) > consensus.MaxActionBytes || !bytes.Equal(raw[:4], []byte("CDXR")) {
		return nil, nil, errors.New("financial action envelope")
	}
	signed := raw[4 : 4+engine.SignedActionSize]
	tail := raw[4+engine.SignedActionSize:]
	if uint64(binary.BigEndian.Uint32(tail[:4])) != uint64(len(tail)-4) {
		return nil, nil, errors.New("close payload length")
	}
	command, err := engine.Decode(signed)
	if err != nil {
		return nil, nil, err
	}
	h := protocol.Digest("common-dex/reward-close-action/v1", tail[4:])
	var target [20]byte
	copy(target[:], h[:20])
	if command.Kind != engine.RewardClose || command.Target != target {
		return nil, nil, errors.New("close payload signature binding")
	}
	pkg, err := rewards.DecodeClosePackage(tail[4:])
	if err != nil {
		return nil, nil, err
	}
	return signed, &pkg, nil
}
func (e *Execution) Execute(parent, action []byte, ctx consensus.ExecutionContext) (consensus.ExecutionResult, error) {
	f, s, err := e.Decode(parent)
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	root, err := e.parentRoot(parent, f, s)
	if err != nil || root != ctx.ParentRoot || ctx.Domain != e.Market.Domain() {
		return consensus.ExecutionResult{}, errors.New("execution parent/domain")
	}

	var pkg *rewards.ClosePackage
	var commitBatch *rewards.CommitBatch
	var points rewards.Points
	var delta engine.Delta
	if bytes.HasPrefix(action, []byte("CDXA")) {
		if !e.rolling() || f.RollingAnchor == nil {
			return consensus.ExecutionResult{}, errors.New("rolling inbox mode required")
		}
		proof, err := clxevidence.DecodeRollingEvidence(action[4:])
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		verified, anchor, err := e.Native.Verifier.VerifyRolling(*f.RollingAnchor, s.InboxCursor, proof)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		s, delta, err = e.Market.ApplyInbox(s, verified, ctx.Height)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		f.RollingAnchor = &anchor
	} else if bytes.HasPrefix(action, []byte("CDXI")) {
		if e.Native == nil || e.Native.Verifier == nil || e.rolling() {
			return consensus.ExecutionResult{}, errors.New("native inbox mode required")
		}
		proof, err := clxevidence.DecodeRangeEvidence(action[4:])
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		verified, err := e.Native.Verifier.VerifyRange(s.InboxCursor, proof)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		header := verified.Header()
		if f.Anchor != nil && (header.Number.Uint64() < f.Anchor.Height || (header.Number.Uint64() == f.Anchor.Height && protocol.Hash(header.Hash()) != f.Anchor.Hash)) {
			return consensus.ExecutionResult{}, errors.New("native anchor regression/conflict")
		}
		s, delta, err = e.Market.ApplyInbox(s, verified, ctx.Height)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		f.Anchor = &NativeAnchor{Height: header.Number.Uint64(), Hash: protocol.Hash(header.Hash())}
	} else {
		if e.Native != nil && ((!e.rolling() && f.Anchor == nil) || (e.rolling() && (f.RollingAnchor == nil || f.RollingAnchor.Height == 0))) {
			return consensus.ExecutionResult{}, errors.New("native finalized inbox anchor required")
		}
		var signed []byte
		if bytes.HasPrefix(action, []byte("CDXP")) {
			signed, commitBatch, err = decodeCommitAction(action)
		} else {
			signed, pkg, err = decodeAction(action)
		}
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		command, err := engine.Decode(signed)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		if (command.Kind == engine.RewardClose) != (pkg != nil || commitBatch != nil) {
			return consensus.ExecutionResult{}, errors.New("unbound reward action")
		}
		if commitBatch != nil {
			f.Participation, err = e.Registry.Commit(f.Participation, s.RewardPeriod, ctx.Height, *commitBatch)
			if err != nil {
				return consensus.ExecutionResult{}, err
			}
			if f.Version < 3 {
				f.Version += 2
			}
		}
		if pkg != nil {
			if e.Registry == nil || pkg.Period != s.RewardPeriod+1 || pkg.Period > (^uint64(0)-4)/10 || ctx.Height < pkg.Period*10+4 {
				return consensus.ExecutionResult{}, errors.New("reward period boundary")
			}
			points, f.Participation, err = e.Registry.CheckCommittedClose(f.Participation, s.RewardPeriod, ctx.Height, *pkg)
			if err != nil {
				return consensus.ExecutionResult{}, err
			}
		}
		s, delta, err = e.Market.Apply(s, signed, ctx.Height)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
	}
	d := delta
	finance := protocol.FinanceSummary{Version: 1, Domain: ctx.Domain, Custody: e.Market.Custody(), Sequence: ctx.Height, DepositTotal: makeAmount(d.DepositTotal), CollectedFees: makeAmount(d.Fees), FundingDust: makeAmount(d.Dust), InsuranceUsed: makeAmount(d.InsuranceUsed)}
	if f.Finance != nil {
		finance.Previous, err = f.Finance.Hash()
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
	}
	if e.continuous() {
		if err := f.FeeHistory.append(ctx.Height, finance.CollectedFees); err != nil {
			return consensus.ExecutionResult{}, err
		}
	} else {
		f.Fees = append(f.Fees, finance.CollectedFees)
	}
	f.Withdrawals = d.Withdrawals
	f.Rewards = []protocol.Claim{}
	for _, claim := range f.Withdrawals {
		finance.WithdrawalTotal = makeAmount(add(finance.WithdrawalTotal.Big().String(), claim.Amount.Big().String()))
	}
	if pkg != nil {
		periodFees := "0"
		first, last := (pkg.Period-1)*10+1, pkg.Period*10
		if e.continuous() {
			periodFees = f.FeeHistory.period(pkg.Period).Big().String()
		} else {
			if last > uint64(len(f.Fees)) {
				return consensus.ExecutionResult{}, errors.New("reward fee history unavailable")
			}
			for i := first; i <= last; i++ {
				periodFees = add(periodFees, f.Fees[i-1].Big().String())
			}
		}
		scores := map[string]string{}
		for _, entry := range points.Entries {
			scores[hex.EncodeToString([]byte{entry.Participant})] = new(big.Int).SetUint64(uint64(entry.Points)).String()
		}
		allocation, err := accounting.Reward(accounting.RewardInput{Fees: periodFees, Support: s.Support, Allowance: "2000000000000000000", Cap: "1000000000000000000", Points: scores})
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		s.Fees, err = subtract(s.Fees, allocation.FromFees)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		s.Support, err = subtract(s.Support, allocation.FromSupport)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		s.RewardReserved = add(s.RewardReserved, allocation.Budget)
		s.RewardPeriod = pkg.Period
		s.PeriodFees, err = subtract(s.PeriodFees, periodFees)
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		if e.continuous() {
			if err := f.FeeHistory.close(pkg.Period); err != nil {
				return consensus.ExecutionResult{}, err
			}
		}
		finance.RewardPeriod = pkg.Period
		finance.FeePeriodFirst = first
		finance.FeePeriodLast = last
		finance.RewardFromFees = makeAmount(allocation.FromFees)
		finance.RewardFromSupport = makeAmount(allocation.FromSupport)
		finance.ParticipationRoot, err = points.Root()
		if err != nil {
			return consensus.ExecutionResult{}, err
		}
		for _, entry := range points.Entries {
			value := allocation.Allocations[hex.EncodeToString([]byte{entry.Participant})]
			if value == "0" {
				continue
			}
			var key [9]byte
			binary.BigEndian.PutUint64(key[:8], pkg.Period)
			key[8] = entry.Participant
			f.Rewards = append(f.Rewards, protocol.Claim{Domain: ctx.Domain, Sequence: ctx.Height, Kind: protocol.Reward, ID: protocol.Digest("common-dex/reward-id/v1", key[:]), Owner: entry.Recipient, Recipient: entry.Recipient, Amount: makeAmount(value), Period: pkg.Period})
		}
	}
	if err := e.Market.Validate(s); err != nil {
		return consensus.ExecutionResult{}, err
	}
	f.Engine, err = s.Encode()
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	f.Finance = &finance
	wRoot, err := claimRoot(f.Withdrawals)
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	rRoot, err := claimRoot(f.Rewards)
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	state, err := f.Encode()
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	post, err := f.Root()
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	funding, err := finance.Hash()
	if err != nil {
		return consensus.ExecutionResult{}, err
	}
	anchor := NativeAnchor{}
	if f.Anchor != nil {
		anchor = *f.Anchor
	}
	if f.RollingAnchor != nil {
		anchor.Height, anchor.Hash = f.RollingAnchor.Height, f.RollingAnchor.BlockHash
	}
	return consensus.ExecutionResult{CLXHeight: anchor.Height, CLXHash: anchor.Hash, State: state, PostRoot: post, InboxStart: d.InboxStart, InboxEnd: d.InboxEnd, InboxRoot: d.InboxRoot, WithdrawalRoot: wRoot, WithdrawalTotal: finance.WithdrawalTotal, RewardPeriod: finance.RewardPeriod, RewardRoot: rRoot, RewardTotal: makeAmount(add(finance.RewardFromFees.Big().String(), finance.RewardFromSupport.Big().String())), FundingRef: funding}, nil
}

// Finalized validates only committed financial metadata. Local collector
// delivery/close state must not alter replay of an already finalized proposal.
func (e *Execution) Finalized(height uint64, action, rawState []byte) error {
	if (e.Native != nil && (bytes.HasPrefix(action, []byte("CDXI")) || bytes.HasPrefix(action, []byte("CDXA")))) || bytes.HasPrefix(action, []byte("CDXP")) {
		_, _, err := e.Decode(rawState)
		return err
	}
	_, pkg, err := decodeAction(action)
	if err != nil {
		return err
	}
	if pkg == nil {
		return nil
	}
	f, s, err := e.Decode(rawState)
	if err != nil {
		return err
	}
	if s.Height != height || f.Finance == nil || f.Finance.RewardPeriod != pkg.Period {
		return errors.New("finalized participation state mismatch")
	}
	points, err := e.Registry.ComputePoints(pkg.Period, pkg.Blocks, pkg.Certificates)
	if err != nil {
		return err
	}
	root, err := points.Root()
	if err != nil || root != f.Finance.ParticipationRoot {
		return errors.New("finalized participation commitment mismatch")
	}
	return nil
}
func claimRoot(claims []protocol.Claim) (protocol.Hash, error) {
	sort.Slice(claims, func(i, j int) bool { return bytes.Compare(claims[i].ID[:], claims[j].ID[:]) < 0 })
	leaves := make([]protocol.Hash, len(claims))
	for i, c := range claims {
		h, err := c.Hash()
		if err != nil {
			return protocol.Hash{}, err
		}
		leaves[i] = h
	}
	root, _, err := protocol.BuildCountedTree(leaves)
	return root, err
}

func (e *Execution) version() uint16 {
	if e.continuous() {
		return 6
	}
	if e.rolling() {
		return 5
	}
	if e.Native != nil {
		return 2
	}
	return 1
}
func (e *Execution) parentRoot(raw []byte, f *FinancialState, s *engine.State) (protocol.Hash, error) {
	if e.Native != nil && s.Height == 0 {
		canonical, root, err := e.Genesis()
		if err != nil || !bytes.Equal(raw, canonical) {
			return protocol.Hash{}, errors.New("native genesis state mismatch")
		}
		return root, nil
	}
	if e.Native != nil && ((!e.rolling() && (f.Anchor == nil || f.Anchor.Hash == (protocol.Hash{}))) || (e.rolling() && (f.RollingAnchor == nil || f.RollingAnchor.BlockHash == (protocol.Hash{})))) {
		return protocol.Hash{}, errors.New("native authenticated anchor missing")
	}
	return f.Root()
}
func EncodeInboxAction(evidence clxevidence.RangeEvidence) ([]byte, error) {
	raw, err := clxevidence.EncodeRangeEvidence(evidence)
	if err != nil {
		return nil, err
	}
	if len(raw)+4 > consensus.MaxActionBytes {
		return nil, errors.New("inbox evidence action bound")
	}
	return append([]byte("CDXI"), raw...), nil
}
