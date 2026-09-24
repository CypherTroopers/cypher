// dex-live-finance is a bounded offline codec/signing/verifying helper for the
// PM2 development-network runner. It never contacts RPC, opens a chain DB,
// changes native state, or submits transactions. Signatures use purpose-specific
// candidate test keys; committee/reward-recipient private keys are not loaded.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rlp"
)

const maxRequest = 3 * 1024 * 1024

type keyInfo struct{ Purpose, Address, KeyFile string }
type inventory struct {
	ChainID              uint64
	Genesis, DEXID       string
	GenesisSHA256        string
	ConfigurationVersion uint16
	Keys                 []keyInfo
	Participants         []struct{ Manifest string }
}
type helper struct {
	root      string
	inventory inventory
	manifest  service.Manifest
	execution *devnet.Execution
	epoch     *checkpoint.Epoch
	keys      []*bls.PublicKey
}
type request struct {
	Op, Purpose, Kind, To, Value, GasPrice, Data            string
	Nonce, Gas, OrderID, Quantity, FeedSequence, ValidUntil uint64
	Side                                                    int8
	FundingRate                                             int64
	Price, Amount, Recipient                                string
	Flags                                                   uint8
	Record                                                  *consensus.Record
	Checkpoint                                              *protocol.Checkpoint
	Proof, State                                            []byte
	Certificates                                            []rewards.Certificate
	Close                                                   *rewards.ClosePackage
	Slots                                                   map[common.Hash]common.Hash
	Balance                                                 string
	Period                                                  uint64
}

func parse(raw []byte, out interface{}) error {
	if len(raw) == 0 || len(raw) > maxRequest {
		return errors.New("helper input byte bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("helper input codec")
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return errors.New("helper trailing input")
	}
	return nil
}

func validateGenesis(raw []byte, inv inventory) error {
	var g struct {
		Config *params.ChainConfig `json:"config"`
	}
	if len(raw) == 0 || len(raw) > 4<<20 || json.Unmarshal(raw, &g) != nil || g.Config == nil || g.Config.ChainID == nil || !g.Config.ChainID.IsUint64() || g.Config.ChainID.Sign() <= 0 || g.Config.ChainID.Uint64() != inv.ChainID || g.Config.DEXDevnet == nil || !g.Config.DEXDevnet.ContinuousStorage() || g.Config.DEXDevnet.Version != inv.ConfigurationVersion || fmt.Sprintf("%x", sha256.Sum256(raw)) != inv.GenesisSHA256 {
		return errors.New("candidate approved genesis/config/hash mismatch")
	}
	return nil
}

func load(root string) (*helper, error) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute candidate directory required")
	}
	raw, err := os.ReadFile(filepath.Join(root, "public/inventory.json"))
	if err != nil {
		return nil, err
	}
	var inv inventory
	if len(raw) > 1<<20 || json.Unmarshal(raw, &inv) != nil || inv.ChainID == 0 || (inv.ConfigurationVersion != 4 && inv.ConfigurationVersion != 5) || len(inv.Participants) != 7 {
		return nil, errors.New("candidate generation identity")
	}
	genesis, err := os.ReadFile(filepath.Join(root, "genesis.json"))
	if err != nil {
		return nil, errors.New("candidate approved genesis unavailable")
	}
	if err := validateGenesis(genesis, inv); err != nil {
		return nil, err
	}
	m, err := service.LoadManifest(inv.Participants[0].Manifest)
	if err != nil {
		return nil, err
	}
	if common.Hash(m.Domain.Genesis).Hex() != inv.Genesis || m.Domain.ChainID != inv.ChainID || common.Hash(m.Domain.DEXID).Hex() != inv.DEXID || m.Version != 2 {
		return nil, errors.New("candidate manifest identity")
	}
	seed, err := protocol.NativeMarketSeed(m.Finance.Market.Oracle)
	if err != nil {
		return nil, err
	}
	if err = finance.ValidateRegistration(m, seed); err != nil {
		return nil, err
	}
	market, err := engine.New(m.Finance.Market)
	if err != nil {
		return nil, err
	}
	recipients := make([][20]byte, 7)
	keys := make([]*bls.PublicKey, 7)
	for i, p := range m.Peers {
		recipients[i] = p.RewardRecipient
		keys[i] = new(bls.PublicKey)
		if err = keys[i].DeserializeHexStr(p.BLSPublic); err != nil {
			return nil, err
		}
	}
	registry, err := rewards.NewRegistry(m.Domain, m.Members, recipients)
	if err != nil {
		return nil, err
	}
	v, err := clxevidence.New(m.Finance.CLX)
	if err != nil {
		return nil, err
	}
	epoch, err := checkpoint.NewEpoch(m.Domain, 1, m.MaxHeight+1, m.Members)
	if err != nil {
		return nil, err
	}
	x := &devnet.Execution{Market: market, Registry: registry, Native: &devnet.NativeContext{Seed: seed, Verifier: v, Rolling: true, Continuous: true, Ancestry: inv.ConfigurationVersion == 5}}
	if _, _, err = x.Genesis(); err != nil {
		return nil, err
	}
	return &helper{root, inv, m, x, epoch, keys}, nil
}

func (h *helper) key(purpose string) (*ecdsa.PrivateKey, error) {
	switch purpose {
	case "trader-a", "trader-b", "synthetic-oracle", "insurance-owner", "support-owner":
	default:
		return nil, errors.New("key purpose not authorized for finance helper")
	}
	for _, item := range h.inventory.Keys {
		if item.Purpose != purpose {
			continue
		}
		path := filepath.Clean(item.KeyFile)
		if filepath.Dir(path) != filepath.Join(h.root, "keys") {
			return nil, errors.New("key outside candidate")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
			return nil, errors.New("private key file shape")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.New("private key unavailable")
		}
		key, err := crypto.HexToECDSA(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, errors.New("private key codec")
		}
		if crypto.PubkeyToAddress(key.PublicKey) != common.HexToAddress(item.Address) {
			return nil, errors.New("key address mismatch")
		}
		return key, nil
	}
	return nil, errors.New("purpose not found")
}

func amount(s string) (*big.Int, error) {
	if s == "" {
		s = "0"
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 || v.BitLen() > 128 || v.String() != s {
		return nil, errors.New("canonical amount outside u128")
	}
	return v, nil
}
func hashHex(h protocol.Hash) string { return common.Hash(h).Hex() }
func (h *helper) certified(r *consensus.Record) (*devnet.FinancialState, *engine.State, error) {
	if r == nil || r.QC == nil || r.Checkpoint.Domain() != h.manifest.Domain || r.Checkpoint.DataSchema != h.execution.Schema() || len(r.State) == 0 || len(r.State) > consensus.MaxStateBytes {
		return nil, nil, errors.New("certified record identity/bound")
	}
	ref, err := types.DecodeHotstuffProposalRef(r.Ref)
	if err != nil {
		return nil, nil, err
	}
	cpHash, err := r.Checkpoint.Hash()
	if err != nil {
		return nil, nil, err
	}
	q := r.QC
	if ref.ViewNumber == 0 || ref.Number != r.Checkpoint.Sequence || ref.Number > h.manifest.MaxHeight || ref.ChainID != h.manifest.Domain.ChainID || ref.KeyHash != common.Hash(h.manifest.Domain.EpochKey()) || ref.LeaderID != h.manifest.Members[(ref.ViewNumber-1)%7].Address || ref.BlockHash != common.Hash(cpHash) || ref.StateRoot != common.Hash(r.Checkpoint.PostRoot) || ref.BodyHash != common.Hash(r.Checkpoint.DataRoot) || !bytes.Equal(q.State, r.Ref) || q.Number != ref.ViewNumber || q.ViewID != ref.ViewID || q.LeaderID != ref.LeaderID {
		return nil, nil, errors.New("certified QC/ref/checkpoint binding")
	}
	dataRoot, err := consensus.ComputeExecutionDataRoot(r.Actions)
	if err == nil && h.execution.Schema() == consensus.AncestryExecutionSchema {
		if r.History == nil || r.History.Count+1 != ref.Number {
			return nil, nil, errors.New("certified ancestry count")
		}
		var historyRoot protocol.Hash
		historyRoot, err = r.History.Root()
		if err == nil {
			dataRoot, err = protocol.HistoryDataRoot(dataRoot, historyRoot, r.History.Count)
		}
	} else if r.History != nil {
		return nil, nil, errors.New("ancestry in legacy certified record")
	}
	if err != nil || dataRoot != r.Checkpoint.DataRoot {
		return nil, nil, errors.New("certified body commitment")
	}
	if !hotstuff.VerifyFHSSignatureWithContext(q.Sign, q.Mask, q.State, h.keys, 5, ref.ChainID, hotstuff.MsgVotePrepare, q.ViewID, q.LeaderID) {
		return nil, nil, errors.New("certified quorum signature")
	}
	if err = h.execution.ValidateSnapshot(r.State, ref.Number, r.Checkpoint.PostRoot); err != nil {
		return nil, nil, err
	}
	return h.execution.Decode(r.State)
}

func sortCloseCertificates(result []rewards.Certificate) {
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Duty, result[j].Duty
		if a.Height != b.Height {
			return a.Height < b.Height
		}
		return a.Participant < b.Participant
	})
}

func (h *helper) process(r request) (interface{}, error) {
	switch r.Op {
	case "identity":
		return map[string]interface{}{"chain_id": h.inventory.ChainID, "genesis": h.inventory.Genesis, "dex_id": h.inventory.DEXID, "custody": params.DEXSettlementAddress.Hex(), "schema": h.execution.Schema(), "financial_version": 6, "signing": false}, nil
	case "native-call":
		op := map[string]uint8{"deposit": protocol.NativeDeposit, "support": protocol.NativeSupport, "insurance": protocol.NativeInsurance}[r.Kind]
		if op == 0 {
			return nil, errors.New("unknown funding kind")
		}
		raw, err := (protocol.NativeCall{Operation: op}).Encode()
		return map[string]string{"data": "0x" + hex.EncodeToString(raw)}, err
	case "verify-tx":
		if len(r.Data) > 2+2*protocol.MaxNativeCallBytes {
			return nil, errors.New("signed TX bound")
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(r.Data, "0x"))
		if err != nil {
			return nil, err
		}
		var tx types.Transaction
		if err = rlp.DecodeBytes(raw, &tx); err != nil {
			return nil, err
		}
		if tx.ChainId().Cmp(new(big.Int).SetUint64(h.inventory.ChainID)) != 0 || tx.To() == nil {
			return nil, errors.New("signed TX chain/to")
		}
		sender, err := types.Sender(types.NewEIP155Signer(new(big.Int).SetUint64(h.inventory.ChainID)), &tx)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"hash": tx.Hash().Hex(), "sender": sender.Hex(), "to": tx.To().Hex(), "value": tx.Value().String(), "gas": tx.Gas(), "gas_price": tx.GasPrice().String(), "nonce": tx.Nonce(), "data": "0x" + hex.EncodeToString(tx.Data())}, nil
	case "sign-tx":
		key, err := h.key(r.Purpose)
		if err != nil {
			return nil, err
		}
		value, err := amount(r.Value)
		if err != nil {
			return nil, err
		}
		gasPrice, err := amount(r.GasPrice)
		if err != nil {
			return nil, err
		}
		if !common.IsHexAddress(r.To) || r.Gas == 0 || r.Gas > 1000000 || gasPrice.Sign() == 0 || len(r.Data) > 2+2*protocol.MaxNativeCallBytes {
			return nil, errors.New("transaction work bound")
		}
		data, err := hex.DecodeString(strings.TrimPrefix(r.Data, "0x"))
		if err != nil {
			return nil, errors.New("transaction calldata")
		}
		if len(data) > 0 {
			call, err := protocol.DecodeNativeCall(data)
			if err != nil || call.Operation > protocol.NativeInsurance || common.HexToAddress(r.To) != params.DEXSettlementAddress {
				return nil, errors.New("helper only signs native funding or plain transfer")
			}
		}
		tx, err := types.SignTx(types.NewTransaction(r.Nonce, common.HexToAddress(r.To), value, r.Gas, gasPrice, data), types.NewEIP155Signer(new(big.Int).SetUint64(h.inventory.ChainID)), key)
		if err != nil {
			return nil, err
		}
		raw, err := rlp.EncodeToBytes(tx)
		return map[string]string{"raw": "0x" + hex.EncodeToString(raw), "hash": tx.Hash().Hex(), "sender": crypto.PubkeyToAddress(key.PublicKey).Hex()}, err
	case "verify-certified":
		f, s, err := h.certified(r.Record)
		if err != nil {
			return nil, err
		}
		cpHash, _ := r.Record.Checkpoint.Hash()
		ref, _ := types.DecodeHotstuffProposalRef(r.Record.Ref)
		return map[string]interface{}{"stage": "certified_not_finalized", "height": s.Height, "checkpoint_hash": hashHex(cpHash), "root": hashHex(r.Record.Checkpoint.PostRoot), "proposal_id": ref.ProposalID().Hex(), "view": ref.ViewNumber, "financial": f, "market": s}, nil
	case "committed-certificates":
		f, _, err := h.certified(r.Record)
		if err != nil {
			return nil, err
		}
		result := []rewards.Certificate{}
		for _, entry := range f.Participation.Entries {
			c, err := rewards.DecodeCertificate(entry.Certificate)
			if err != nil {
				return nil, err
			}
			if c.Duty.Period == r.Period {
				result = append(result, c)
			}
		}
		sortCloseCertificates(result)
		return result, nil
	case "eligible-committed-certificates":
		f, state, err := h.certified(r.Record)
		if err != nil {
			return nil, err
		}
		if r.Close == nil || len(r.Close.Blocks) != int(rewards.PeriodBlocks)+1 || len(r.Close.Certificates) != 0 {
			return nil, errors.New("close witness request bound")
		}
		canonical := map[uint64]*types.HotstuffProposalRef{}
		for i, block := range r.Close.Blocks {
			if _, err := h.epoch.Verify(block.Checkpoint, block.Proof); err != nil {
				return nil, err
			}
			if i == int(rewards.PeriodBlocks) {
				continue
			}
			proof, err := checkpoint.DecodeProof(block.Proof)
			if err != nil {
				return nil, err
			}
			ref, err := types.DecodeHotstuffProposalRef(proof.Target.State)
			if err != nil {
				return nil, err
			}
			canonical[ref.Number] = ref
		}
		result := []rewards.Certificate{}
		for _, entry := range f.Participation.Entries {
			certificate, err := rewards.DecodeCertificate(entry.Certificate)
			if err != nil {
				return nil, err
			}
			d := certificate.Duty
			ref := canonical[d.Height]
			if d.Period == r.Close.Period && ref != nil && d.View == ref.ViewNumber && d.ProposalID == protocol.Hash(ref.ProposalID()) {
				result = append(result, certificate)
			}
		}
		sortCloseCertificates(result)
		pkg := *r.Close
		pkg.Certificates = result
		// The formal registry verifies exact witnesses, continuity, deadline,
		// canonical target and complete committed set again. Local collection
		// cannot independently turn an orphan vote into an eligible payment.
		if _, _, err := h.execution.Registry.CheckCommittedClose(f.Participation, state.RewardPeriod, state.Height+1, pkg); err != nil {
			return nil, err
		}
		return result, nil
	case "select-certificates":
		if _, _, err := h.certified(r.Record); err != nil {
			return nil, err
		}
		if len(r.Certificates) > rewards.MaxPeriodCertificates {
			return nil, errors.New("certificate count")
		}
		ref, _ := types.DecodeHotstuffProposalRef(r.Record.Ref)
		result := []rewards.Certificate{}
		seen := map[uint8]bool{}
		for _, c := range r.Certificates {
			if err := h.execution.Registry.VerifyCertificate(c); err != nil {
				return nil, err
			}
			d := c.Duty
			if d.Height != ref.Number || d.Period != (ref.Number-1)/10+1 {
				return nil, errors.New("foreign certificate height")
			}
			if d.View != ref.ViewNumber || d.ProposalID != protocol.Hash(ref.ProposalID()) {
				continue
			}
			if seen[d.Participant] {
				return nil, errors.New("duplicate certificate participant")
			}
			seen[d.Participant] = true
			result = append(result, c)
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Duty.Participant < result[j].Duty.Participant })
		return result, nil
	case "verify-finalized":
		if r.Checkpoint == nil || r.Checkpoint.Domain() != h.manifest.Domain || r.Checkpoint.DataSchema != h.execution.Schema() || len(r.State) == 0 || len(r.State) > consensus.MaxStateBytes {
			return nil, errors.New("finalized checkpoint identity/schema/state bound")
		}
		if _, err := h.epoch.Verify(*r.Checkpoint, r.Proof); err != nil {
			return nil, err
		}
		if err := h.execution.ValidateSnapshot(r.State, r.Checkpoint.Sequence, r.Checkpoint.PostRoot); err != nil {
			return nil, err
		}
		f, s, err := h.execution.Decode(r.State)
		cpHash, _ := r.Checkpoint.Hash()
		return map[string]interface{}{"stage": "dex_finalized_not_clx_accepted", "height": s.Height, "checkpoint_hash": hashHex(cpHash), "root": hashHex(r.Checkpoint.PostRoot), "financial": f, "market": s}, err
	case "sign-action", "commit-participation", "reward-close":
		return h.action(r)
	case "execute-signed":
		_, state, err := h.certified(r.Record)
		if err != nil {
			return nil, err
		}
		if len(r.Data) > 2+2*consensus.MaxActionBytes {
			return nil, errors.New("signed action bound")
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(r.Data, "0x"))
		if err != nil {
			return nil, err
		}
		result, err := h.execution.Execute(r.Record.State, raw, consensus.ExecutionContext{Domain: h.manifest.Domain, Height: state.Height + 1, ParentRoot: r.Record.Checkpoint.PostRoot})
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"height": state.Height + 1, "root": hashHex(result.PostRoot)}, nil
	case "decode-native":
		return decodeNative(r.Data)
	case "projection-keys", "projection":
		return project(r)
	default:
		return nil, errors.New("unsupported helper operation")
	}
}

func (h *helper) action(r request) (interface{}, error) {
	_, state, err := h.certified(r.Record)
	if err != nil {
		return nil, err
	}
	key, err := h.key(r.Purpose)
	if err != nil {
		return nil, err
	}
	owner := crypto.PubkeyToAddress(key.PublicKey)
	account := state.Accounts[hex.EncodeToString(owner[:])]
	if account == nil || account.Nonce == ^uint64(0) {
		return nil, errors.New("action owner or nonce unavailable")
	}
	a := engine.Action{Version: 1, Epoch: h.manifest.Domain.EpochKey(), Owner: [20]byte(owner), Nonce: account.Nonce + 1, OrderID: r.OrderID, Quantity: r.Quantity, Side: r.Side, FeedSequence: r.FeedSequence, ValidUntil: r.ValidUntil, FundingRate: r.FundingRate, Flags: r.Flags}
	price, err := amount(r.Price)
	if err != nil {
		return nil, err
	}
	a.Price, err = protocol.AmountFromBig(price)
	if err != nil {
		return nil, err
	}
	v, err := amount(r.Amount)
	if err != nil {
		return nil, err
	}
	a.Amount, err = protocol.AmountFromBig(v)
	if err != nil {
		return nil, err
	}
	if r.Recipient != "" {
		if !common.IsHexAddress(r.Recipient) {
			return nil, errors.New("recipient")
		}
		a.Recipient = [20]byte(common.HexToAddress(r.Recipient))
	}
	var raw []byte
	switch r.Op {
	case "sign-action":
		kind, ok := map[string]uint8{"noop": engine.Noop, "oracle": engine.Oracle, "place": engine.Place, "cancel": engine.Cancel, "amend": engine.Amend, "withdraw": engine.Withdraw, "funding": engine.Funding}[r.Kind]
		if !ok {
			return nil, errors.New("unsupported runner action")
		}
		a.Kind = kind
		raw, err = engine.Sign(a, key)
	case "commit-participation":
		if len(r.Certificates) == 0 || len(r.Certificates) > rewards.MaxPeriodCertificates {
			return nil, errors.New("participation count")
		}
		for _, c := range r.Certificates {
			if err = h.execution.Registry.VerifyCertificate(c); err != nil {
				return nil, err
			}
		}
		raw, err = devnet.EncodeParticipationAction(a, key, r.Certificates)
	case "reward-close":
		if r.Close == nil {
			return nil, errors.New("reward package required")
		}
		raw, err = devnet.EncodeRewardAction(a, key, *r.Close)
	}
	if err != nil {
		return nil, err
	}
	// The same authenticated parent is dry-executed before submission. This is
	// a Common-side client helper, never part of CLX settlement execution.
	result, err := h.execution.Execute(r.Record.State, raw, consensus.ExecutionContext{Domain: h.manifest.Domain, Height: state.Height + 1, ParentRoot: r.Record.Checkpoint.PostRoot})
	if err != nil {
		return nil, err
	}
	id := protocol.Digest("common-dex/ingress-action/v1", raw)
	return map[string]interface{}{"raw": "0x" + hex.EncodeToString(raw), "id": hex.EncodeToString(id[:]), "owner": owner.Hex(), "nonce": a.Nonce, "parent_height": state.Height, "predicted_height": state.Height + 1, "predicted_root": hashHex(result.PostRoot), "finality": "not_submitted"}, nil
}

func main() {
	root := flag.String("candidate", "", "private candidate directory, read-only")
	flag.Parse()
	h, err := load(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "candidate helper initialization rejected")
		os.Exit(2)
	}
	s := bufio.NewScanner(io.LimitReader(os.Stdin, 64<<20))
	s.Buffer(make([]byte, 65536), maxRequest)
	encoder := json.NewEncoder(os.Stdout)
	count := 0
	for s.Scan() {
		count++
		if count > 10000 {
			fmt.Fprintln(os.Stderr, "request count bound")
			os.Exit(2)
		}
		var r request
		var result interface{}
		err = parse(s.Bytes(), &r)
		if err == nil {
			result, err = h.process(r)
		}
		if err != nil {
			_ = encoder.Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		} else {
			_ = encoder.Encode(map[string]interface{}{"ok": true, "result": result})
		}
	}
	if s.Err() != nil {
		fmt.Fprintln(os.Stderr, "bounded helper input failed")
		os.Exit(2)
	}
}
