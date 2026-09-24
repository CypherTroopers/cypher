package settlement

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

// NativeContext comes exclusively from authenticated EVM transaction/block
// execution. Value has already been transferred by EVM.Call.
type NativeContext struct {
	Sender             common.Address
	Nonce, BlockNumber uint64
	Value              *big.Int
	Genesis            *types.Header
	GenesisKeyHash     common.Hash
	GetHash            func(uint64) common.Hash
}

var NativeFundingTopic = common.Hash(protocol.Digest("common-dex/native-funding-event/v2", nil))
var NativeCheckpointTopic = common.Hash(protocol.Digest("common-dex/native-checkpoint-event/v2", nil))
var NativeClaimTopic = common.Hash(protocol.Digest("common-dex/native-claim-event/v2", nil))
var NativeAnchorTopic = common.Hash(protocol.Digest("common-dex/native-anchor-event/v1", nil))

// RequiredNativeGas charges worst-case bounded cryptography/ancestry for
// checkpoint admission. The separate EVM intrinsic calldata charge also applies.
func RequiredNativeGas(input []byte) uint64 {
	base := uint64(250000)
	if len(input) > 6 && (input[6] == protocol.NativeCheckpoint || input[6] == protocol.NativeAnchorUpdate) {
		base = 12000000
	}
	if len(input) > 6 && input[6] == protocol.NativeClaim {
		base = 350000
	}
	if len(input) > protocol.MaxNativeCallBytes {
		return ^uint64(0)
	}
	return base + uint64(len(input))*40
}

func openNative(st NativeState, config *params.ChainConfig, ctx NativeContext) (*Adapter, error) {
	return loadNative(st, config, ctx, false)
}

// readOnly permits exact anchor evidence replay without even reconciling newly
// forced surplus into storage. A new update materializes the same initialization
// only after proof and branch validation, inside RunNative's outer snapshot.
func loadNative(st NativeState, config *params.ChainConfig, ctx NativeContext, readOnly bool) (*Adapter, error) {
	if config == nil || config.DEXDevnet == nil || !config.DEXDevnetActive(new(big.Int).SetUint64(ctx.BlockNumber)) {
		return nil, errors.New("DEX native settlement inactive")
	}
	if err := config.ValidateDEXDevnet(); err != nil {
		return nil, err
	}
	if st == nil || ctx.Genesis == nil || ctx.Genesis.Number == nil || ctx.Genesis.Number.Sign() != 0 || ctx.Sender == (common.Address{}) || ctx.Sender == params.DEXSettlementAddress || ctx.Value == nil || ctx.Value.Sign() < 0 || ctx.Value.BitLen() > 128 || ctx.GetHash == nil {
		return nil, errors.New("invalid native execution context")
	}
	commitment, err := params.FairHotstuffGenesisCommitment(config)
	if err != nil || commitment != ctx.Genesis.MixDigest {
		return nil, errors.New("native execution genesis/config mismatch")
	}
	d := config.DEXDevnet
	nodes := make([]*common.Cnode, len(d.Committee))
	for i, n := range d.Committee {
		n := n
		nodes[i] = &n
	}
	domain := protocol.Domain{Version: 1, ChainID: config.ChainID.Uint64(), Genesis: protocol.Hash(ctx.Genesis.Hash()), DEXID: protocol.Hash(d.DEXID), Epoch: 1, Committee: protocol.Hash((&bftview.Committee{List: nodes}).RlpHash())}
	epoch, err := checkpoint.NewEpoch(domain, 1, d.MaxCheckpoints+1, nodes)
	if err != nil {
		return nil, err
	}
	root, err := protocol.NativeGenesisRoot(protocol.Hash(d.GenesisSeed), domain, [20]byte(d.Custody))
	if d.Version == 3 {
		root, err = protocol.NativeGenesisRootV3(protocol.Hash(d.GenesisSeed), domain, [20]byte(d.Custody))
	}
	if d.ContinuousStorage() {
		root, err = protocol.NativeGenesisRootV4(protocol.Hash(d.GenesisSeed), domain, [20]byte(d.Custody))
	}
	if err != nil {
		return nil, err
	}
	var configBytes bytes.Buffer
	configBytes.Write(commitment[:])
	genesisHash := ctx.Genesis.Hash()
	configBytes.Write(genesisHash[:])
	configBytes.Write(root[:])
	configLabel := "common-dex/native-config/v2"
	if d.Version == 3 {
		configLabel = "common-dex/native-config/v3"
	}
	if d.Version == 4 {
		configLabel = "common-dex/native-config/v4"
	}
	if d.AncestryProofs() {
		configLabel = "common-dex/native-config/v5"
	}
	a := &Adapter{db: stateWithError{st}, custody: d.Custody, domain: domain, epochs: []*checkpoint.Epoch{epoch}, limit: d.MaxCheckpoints, configHash: common.Hash(protocol.Digest(configLabel, configBytes.Bytes())), nativeV2: true, nativeVersion: d.Version, nativeRoot: root, nativeGenesis: genesisHash}
	if st.GetNonce(d.Custody) != 1 || len(st.GetCode(d.Custody)) != 0 {
		return nil, errors.New("reserved custody account shape")
	}
	stored := a.get("config", 0)
	if stored != (common.Hash{}) && stored != a.configHash {
		return nil, errors.New("native registry/config changed")
	}
	values, err := a.Balances()
	if err != nil {
		return nil, err
	}
	sum := new(big.Int).Set(ctx.Value)
	for _, v := range values {
		sum.Add(sum, v.Big())
	}
	surplus := new(big.Int).Sub(st.GetBalance(d.Custody), sum)
	if surplus.Sign() < 0 || surplus.BitLen() > 256 || surplus.Cmp(new(big.Int).SetBytes(a.get("native-surplus", 0).Bytes())) < 0 {
		return nil, errors.New("native backing deficit")
	}
	a.nativeSurplus = common.BigToHash(surplus)
	if !readOnly {
		a.materializeNative()
	}
	return a, a.db.Error()
}

func (a *Adapter) materializeNative() {
	if a.get("config", 0) == (common.Hash{}) {
		a.set("config", 0, a.configHash)
		a.set("root", 0, common.Hash(a.nativeRoot))
		if a.nativeVersion == 2 {
			a.set("native-anchor", 0, a.nativeGenesis)
		}
	}
	if a.get("native-surplus", 0) != a.nativeSurplus {
		a.set("native-surplus", 0, a.nativeSurplus)
	}
}

// RunNative must be invoked through EVM.Call, which owns transfer and gas.
// It returns bounded semantic errors; the VM maps them to execution revert.
func RunNative(st NativeState, config *params.ChainConfig, ctx NativeContext, input []byte) (out []byte, err error) {
	if st == nil {
		return nil, errors.New("native state unavailable")
	}
	snapshot := st.Snapshot()
	defer func() {
		if err != nil {
			st.RevertToSnapshot(snapshot)
		}
	}()
	call, err := protocol.DecodeNativeCall(input)
	if err != nil {
		return nil, err
	}
	if ctx.Value == nil {
		return nil, errors.New("missing native value")
	}
	if (call.Operation <= protocol.NativeInsurance) != (ctx.Value.Sign() > 0) {
		return nil, errors.New("native operation/value mismatch")
	}
	// Check operation-specific canonical lengths before loading/parsing the
	// trusted committee. Signature work remains inside the bounded verifiers.
	if call.Operation == protocol.NativeCheckpoint {
		if _, _, _, _, err = protocol.DecodeNativeCheckpoint(call.Body); err != nil {
			return nil, err
		}
	}
	if call.Operation == protocol.NativeClaim {
		if _, _, _, _, err = protocol.DecodeNativeClaim(call.Body); err != nil {
			return nil, err
		}
	}
	if call.Operation == protocol.NativeAnchorUpdate {
		if config == nil || !config.DEXDevnet.RollingAnchors() {
			return nil, errors.New("rolling anchors require supported native config 3, 4 or 5")
		}
		evidence, continuation, err := DecodeAnchorUpdate(call.Body)
		if err != nil || len(evidence.Entries) != 0 {
			return nil, errors.New("native anchor requires bounded empty-entry evidence")
		}
		a, err := loadNative(st, config, ctx, true)
		if err != nil {
			return nil, err
		}
		return a.nativeAnchorUpdate(config, ctx, evidence, continuation, call.Body)
	}
	a, err := openNative(st, config, ctx)
	if err != nil {
		return nil, err
	}
	switch call.Operation {
	case protocol.NativeDeposit, protocol.NativeSupport, protocol.NativeInsurance:
		return a.nativeFunding(ctx, call.Operation, input)
	case protocol.NativeCheckpoint:
		c, f, proof, evidence, e := protocol.DecodeNativeCheckpoint(call.Body)
		if e != nil {
			return nil, e
		}
		accepted, e := a.nativeAccept(config, ctx, c, f, proof, evidence)
		if e != nil {
			return nil, e
		}
		st.AddLog(&types.Log{Address: a.custody, Topics: []common.Hash{NativeCheckpointTopic}, Data: append([]byte(nil), accepted.Hash[:]...)})
		return append([]byte(nil), accepted.Hash[:]...), a.db.Error()
	case protocol.NativeClaim:
		claim, index, count, siblings, e := protocol.DecodeNativeClaim(call.Body)
		if e != nil {
			return nil, e
		}
		replay, e := a.Claim(claim, index, count, siblings)
		if e != nil {
			return nil, e
		}
		leaf, e := claim.Hash()
		if e != nil {
			return nil, e
		}
		data := append([]byte(nil), leaf[:]...)
		if replay {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
		st.AddLog(&types.Log{Address: a.custody, Topics: []common.Hash{NativeClaimTopic}, Data: data})
		return data, a.db.Error()
	}
	return nil, errors.New("native operation unavailable")
}

func (a *Adapter) nativeFunding(ctx NativeContext, kind uint8, input []byte) ([]byte, error) {
	amount, err := protocol.AmountFromBig(ctx.Value)
	if err != nil {
		return nil, err
	}
	index := a.number("deposits")
	if index >= MaxDeposits {
		return nil, errors.New("native inbox capacity")
	}
	payloadHash, err := protocol.NativeFundingPayloadHash([20]byte(ctx.Sender), [20]byte(ctx.Sender), amount, 0, kind, input)
	if err != nil {
		return nil, err
	}
	entry := protocol.InboxEntry{Version: 2, ChainID: a.domain.ChainID, Genesis: a.domain.Genesis, DEXID: a.domain.DEXID, Custody: [20]byte(a.custody), Sender: [20]byte(ctx.Sender), Nonce: ctx.Nonce, ActionIndex: 0, PayloadHash: payloadHash, Index: index, Owner: [20]byte(ctx.Sender), Amount: amount, Bucket: kind, Asset: 0}
	raw, err := entry.Encode()
	if err != nil {
		return nil, err
	}
	hash, err := entry.Hash()
	if err != nil {
		return nil, err
	}
	values, err := a.mutableBalances()
	if err != nil {
		return nil, err
	}
	bucket := Unconsumed
	if kind == protocol.NativeSupport {
		bucket = Support
	}
	if kind == protocol.NativeInsurance {
		bucket = Insurance
	}
	values[bucket].Add(values[bucket], ctx.Value)
	if err = a.writeBalances(values); err != nil {
		return nil, err
	}
	a.writeBlob("native-entry", index, raw)
	a.set("native-entry-height", index, common.BigToHash(new(big.Int).SetUint64(ctx.BlockNumber)))
	a.setNumber("deposits", index+1)
	a.db.SetState(a.custody, common.Hash(protocol.InboxCountStorageKey()), common.BigToHash(new(big.Int).SetUint64(index+1)))
	a.db.SetState(a.custody, common.Hash(protocol.InboxEntryStorageKey(index)), common.Hash(hash))
	if err = a.checkCustody(); err != nil {
		return nil, err
	}
	a.db.AddLog(&types.Log{Address: a.custody, Topics: []common.Hash{NativeFundingTopic}, Data: append([]byte(nil), raw...)})
	return raw, a.db.Error()
}

// ReadNativeEntry returns a persisted stable entry for proof/data serving only.
func ReadNativeEntry(st NativeState, custody common.Address, index uint64) (protocol.InboxEntry, error) {
	if st == nil {
		return protocol.InboxEntry{}, errors.New("native state unavailable")
	}
	a := Adapter{db: stateWithError{st}, custody: custody}
	if index >= a.number("deposits") {
		return protocol.InboxEntry{}, errors.New("unknown native entry")
	}
	entry, err := protocol.DecodeInboxEntry(a.readBlob("native-entry", index, protocol.InboxEntrySize))
	if err != nil {
		return entry, err
	}
	return entry, a.db.Error()
}

// NativeStatus is a read-only storage projection used by isolated tests/servers.
func NativeStatus(st NativeState, custody common.Address) (Status, map[Bucket]protocol.Amount, protocol.Amount, error) {
	if st == nil {
		return Status{}, nil, protocol.Amount{}, errors.New("native state unavailable")
	}
	a := Adapter{db: stateWithError{st}, custody: custody}
	b, err := a.Balances()
	return a.Status(), b, protocol.Amount(a.get("native-surplus", 0)), err
}
