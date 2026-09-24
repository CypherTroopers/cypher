package main

import (
	"encoding/hex"
	"errors"
	"math/big"
	"sort"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/settlement"
	"github.com/cypherium/cypher/params"
)

func decodeNative(text string) (interface{}, error) {
	if len(text) > 2+2*protocol.MaxNativeCallBytes {
		return nil, errors.New("native input size")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(text, "0x"))
	if err != nil {
		return nil, err
	}
	c, err := protocol.DecodeNativeCall(raw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{"operation": c.Operation, "calldata_bytes": len(raw)}
	switch c.Operation {
	case protocol.NativeDeposit, protocol.NativeSupport, protocol.NativeInsurance:
		out["kind"] = map[uint8]string{1: "deposit", 2: "support", 3: "insurance"}[c.Operation]
	case protocol.NativeCheckpoint:
		cp, f, proof, source, err := protocol.DecodeNativeCheckpoint(c.Body)
		if err != nil {
			return nil, err
		}
		id, _ := cp.Hash()
		out["kind"] = "checkpoint"
		out["checkpoint"] = cp
		out["finance"] = f
		out["checkpoint_hash"] = hashHex(id)
		out["dex_proof_bytes"] = len(proof)
		out["clx_evidence_bytes"] = len(source)
	case protocol.NativeClaim:
		claim, index, count, siblings, err := protocol.DecodeNativeClaim(c.Body)
		if err != nil {
			return nil, err
		}
		id, _ := claim.Hash()
		slot, err := settlement.ClaimNullifierStorageKey(claim)
		if err != nil {
			return nil, err
		}
		out["kind"] = "claim"
		out["claim"] = claim
		out["claim_hash"] = hashHex(id)
		out["nullifier_slot"] = slot.Hex()
		out["index"] = index
		out["count"] = count
		out["depth"] = len(siblings)
		out["event_topic"] = settlement.NativeClaimTopic.Hex()
	case protocol.NativeAnchorUpdate:
		e, continuation, err := settlement.DecodeAnchorUpdate(c.Body)
		if err != nil {
			return nil, err
		}
		out["kind"] = "anchor"
		out["headers"] = len(e.Headers) + len(continuation)
		out["mpt_nodes"] = len(e.AccountProof) + len(e.CountProof)
		bytes, nodes := 0, len(e.AccountProof)+len(e.CountProof)
		for _, p := range e.AccountProof {
			bytes += len(p)
		}
		for _, p := range e.CountProof {
			bytes += len(p)
		}
		for _, entry := range e.Entries {
			nodes += len(entry.Proof)
			for _, p := range entry.Proof {
				bytes += len(p)
			}
		}
		if len(e.Headers)+len(continuation) > clxevidence.MaxAncestryBlocks {
			return nil, errors.New("anchor ancestry bound")
		}
		out["mpt_nodes"] = nodes
		out["mpt_bytes"] = bytes
	}
	return out, nil
}

// This implements only read projection. Every mutation method panics; no
// StateDB handle exists in this tool. Keys are discovered from NativeStatus
// itself so the runner does not duplicate the private settlement storage codec.
type projection struct {
	slots   map[common.Hash]common.Hash
	seen    map[common.Hash]bool
	balance *big.Int
}

func (s *projection) GetState(a common.Address, k common.Hash) common.Hash {
	if a != params.DEXSettlementAddress {
		panic("foreign projection account")
	}
	s.seen[k] = true
	return s.slots[k]
}
func (s *projection) GetBalance(common.Address) *big.Int              { return new(big.Int).Set(s.balance) }
func (*projection) GetNonce(common.Address) uint64                    { return 1 }
func (*projection) GetCode(common.Address) []byte                     { return nil }
func (*projection) Exist(common.Address) bool                         { return true }
func (*projection) SetState(common.Address, common.Hash, common.Hash) { panic("read-only projection") }
func (*projection) SubBalance(common.Address, *big.Int)               { panic("read-only projection") }
func (*projection) AddBalance(common.Address, *big.Int)               { panic("read-only projection") }
func (*projection) SetNonce(common.Address, uint64)                   { panic("read-only projection") }
func (*projection) Snapshot() int                                     { panic("read-only projection") }
func (*projection) RevertToSnapshot(int)                              { panic("read-only projection") }
func (*projection) AddLog(*types.Log)                                 { panic("read-only projection") }

func project(r request) (interface{}, error) {
	if len(r.Slots) > 128 {
		return nil, errors.New("projection slot bound")
	}
	b, err := amount(r.Balance)
	if err != nil {
		return nil, err
	}
	s := &projection{slots: r.Slots, seen: map[common.Hash]bool{}, balance: b}
	status, buckets, surplus, err := settlement.NativeStatus(s, params.DEXSettlementAddress)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for k := range s.seen {
		keys = append(keys, k.Hex())
	}
	sort.Strings(keys)
	if r.Op == "projection-keys" {
		return map[string]interface{}{"custody": params.DEXSettlementAddress.Hex(), "slots": keys, "scope": "read-only canonical projection; independent CLX finality authentication separate"}, nil
	}
	for k := range s.seen {
		if _, ok := r.Slots[k]; !ok {
			return nil, errors.New("projection missing required storage value")
		}
	}
	total := new(big.Int).Set(surplus.Big())
	values := map[string]string{}
	for k, v := range buckets {
		values[string(k)] = v.Big().String()
		total.Add(total, v.Big())
	}
	if total.Cmp(b) != 0 {
		return nil, errors.New("custody bucket/surplus conservation")
	}
	return map[string]interface{}{"status": status, "buckets": values, "surplus": surplus.Big().String(), "balance": b.String()}, nil
}
