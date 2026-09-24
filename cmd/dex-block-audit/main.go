// dex-block-audit extracts native issuance from bounded, locally observed block
// RLP. It neither contacts a node nor authenticates FHS finality. In particular,
// header hash equality does not authenticate SignInfo, which the hash excludes.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

// These are local audit limits, not changes to consensus or wire rules.
const (
	maxBlockBytes   = 4 << 20
	maxLineBytes    = 2*maxBlockBytes + 1024
	maxInputBytes   = 128 << 20
	maxBlocks       = 4096
	maxTransactions = 65536
	maxUncles       = 64
	maxKeyInfoBytes = 256 << 10
	trustScope      = "local canonical observation accounting only; FHS finality, SignInfo, execution and state root are NOT independently authenticated"
)

type auditInput struct {
	RLP            string
	ExpectedHash   common.Hash
	ExpectedNumber uint64
}

type reward struct {
	Kind      string `json:"kind"`
	Recipient string `json:"recipient"`
	Atoms     string `json:"atoms"`
	Basis     string `json:"basis"`
}

type recipientTotal struct {
	Recipient string `json:"recipient"`
	Atoms     string `json:"atoms"`
}

type auditResult struct {
	Scope           string           `json:"scope"`
	ActualHash      common.Hash      `json:"actual_hash"`
	Number          uint64           `json:"number"`
	ParentHash      common.Hash      `json:"parent_hash"`
	StateRoot       common.Hash      `json:"state_root"`
	Coinbase        common.Address   `json:"coinbase"`
	BlockType       uint8            `json:"block_type"`
	BlockTypeName   string           `json:"block_type_name"`
	TransactionHash []common.Hash    `json:"transaction_hashes"`
	RLPBytes        int              `json:"rlp_bytes"`
	StaticRule      string           `json:"static_rule"`
	Rewards         []reward         `json:"issuance_components"`
	Recipients      []recipientTotal `json:"issuance_by_recipient"`
	TotalAtoms      string           `json:"issuance_total_atoms"`
	Excluded        []string         `json:"excluded"`
}

// Parse every key explicitly so duplicate keys cannot silently replace the
// expected hash/height guards. JSON uint64 decoding rejects fractional,
// negative, exponential and overflowing input numbers.
func parseInput(line []byte) (auditInput, error) {
	var in auditInput
	d := json.NewDecoder(bytes.NewReader(line))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return in, errors.New("expected one JSON object")
	}
	seen := make(map[string]bool)
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return in, errors.New("invalid JSON key")
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return in, errors.New("duplicate or invalid JSON key")
		}
		seen[key] = true
		switch key {
		case "rlp":
			err = d.Decode(&in.RLP)
		case "expected_hash":
			var h string
			if err = d.Decode(&h); err == nil {
				var raw []byte
				if len(h) != 66 || !strings.HasPrefix(h, "0x") {
					err = errors.New("expected_hash must be a 0x-prefixed 32-byte hash")
				} else if raw, err = hex.DecodeString(h[2:]); err == nil {
					copy(in.ExpectedHash[:], raw)
				}
			}
		case "expected_number":
			var raw json.RawMessage
			if err = d.Decode(&raw); err == nil {
				if bytes.Equal(raw, []byte("null")) {
					err = errors.New("expected_number must be uint64")
				} else {
					err = json.Unmarshal(raw, &in.ExpectedNumber)
				}
			}
		default:
			return in, errors.New("unknown input field")
		}
		if err != nil {
			return in, fmt.Errorf("invalid %s", key)
		}
	}
	if _, err = d.Token(); err != nil {
		return in, errors.New("incomplete JSON object")
	}
	if len(seen) != 3 || !seen["rlp"] || !seen["expected_hash"] || !seen["expected_number"] {
		return in, errors.New("rlp, expected_hash and expected_number are required")
	}
	if _, err = d.Token(); err != io.EOF {
		return in, errors.New("trailing JSON data")
	}
	return in, nil
}

func validateHeader(h *types.Header) error {
	if h == nil || h.Number == nil || !h.Number.IsUint64() || h.Difficulty == nil || h.Difficulty.Sign() < 0 {
		return errors.New("missing or invalid header integer")
	}
	if h.BlockType > types.SlowTx_Block || h.GasUsed > h.GasLimit || len(h.KeyInfo) > maxKeyInfoBytes {
		return errors.New("unsupported block type, gas or KeyInfo limit")
	}
	return h.SanityCheck()
}

// Split into bounded zero-copy views before generic decoding can allocate a
// slice proportional to an attacker-provided list count.
func boundedList(raw []byte, limit int, retain bool) ([][]byte, error) {
	content, rest, err := rlp.SplitList(raw)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid RLP list")
	}
	var fields [][]byte
	count := 0
	for len(content) > 0 {
		count++
		if count > limit {
			return nil, errors.New("RLP list count exceeds audit limit")
		}
		_, _, rest, err := rlp.Split(content)
		if err != nil {
			return nil, errors.New("invalid RLP list item")
		}
		if retain {
			fields = append(fields, content[:len(content)-len(rest)])
		}
		content = rest
	}
	return fields, nil
}

func audit(in auditInput) (auditResult, error) {
	var result auditResult
	h := strings.TrimPrefix(in.RLP, "0x")
	if len(h) == 0 || len(h)%2 != 0 || len(h) > 2*maxBlockBytes {
		return result, errors.New("invalid or oversized block hex")
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return result, errors.New("invalid block hex")
	}
	// Preflight the header before Block.Header (which copies and assumes a
	// nonnil header). DecodeBytes also rejects trailing RLP and noncanonical ints.
	fields, err := boundedList(raw, 7, true)
	if err != nil || len(fields) != 7 {
		return result, errors.New("invalid current block RLP structure")
	}
	for i := 1; i < len(fields); i++ {
		limit := maxTransactions
		if i == 3 {
			limit = maxUncles
		}
		if _, err := boundedList(fields[i], limit, false); err != nil {
			return result, fmt.Errorf("block list %d: %w", i, err)
		}
	}
	var header types.Header
	if err := rlp.DecodeBytes(fields[0], &header); err != nil {
		return result, errors.New("invalid header RLP")
	}
	if err := validateHeader(&header); err != nil {
		return result, err
	}
	var block types.Block
	if err := rlp.DecodeBytes(raw, &block); err != nil {
		return result, errors.New("invalid block RLP")
	}
	if block.Hash() != in.ExpectedHash || header.Number.Uint64() != in.ExpectedNumber {
		return result, errors.New("expected hash or number mismatch")
	}
	txs, uncles := block.Transactions(), block.Uncles()
	if len(txs) > maxTransactions || len(uncles) > maxUncles {
		return result, errors.New("transaction or uncle count exceeds audit limit")
	}
	if types.CalcUncleHash(uncles) != header.UncleHash {
		return result, errors.New("uncle body commitment mismatch")
	}
	for _, uncle := range uncles {
		if err := validateHeader(uncle); err != nil {
			return result, errors.New("invalid uncle header")
		}
		// Avoid uint subtraction and negative issuance on unauthenticated input.
		gap := new(big.Int).Sub(header.Number, uncle.Number)
		if gap.Sign() <= 0 || gap.Cmp(big.NewInt(7)) > 0 {
			return result, errors.New("uncle height outside positive reward range")
		}
	}
	result = auditResult{
		Scope: trustScope, ActualHash: block.Hash(), Number: header.Number.Uint64(),
		ParentHash: header.ParentHash, StateRoot: header.Root, Coinbase: header.Coinbase,
		BlockType: header.BlockType, BlockTypeName: []string{"FastTx", "Key", "SlowTx"}[header.BlockType],
		TransactionHash: make([]common.Hash, len(txs)), RLPBytes: len(raw),
		Rewards: []reward{}, Recipients: []recipientTotal{},
		Excluded: []string{"transaction transfers", "gas fees/Common RPC rewards/burn", "DEX accounting", "genesis allocations"},
	}
	for i, tx := range txs {
		if tx == nil {
			return auditResult{}, errors.New("nil transaction")
		}
		result.TransactionHash[i] = tx.Hash()
	}
	if types.DeriveSha(types.Transactions(txs), new(trie.Trie)) != header.TxHash {
		return auditResult{}, errors.New("transaction body commitment mismatch")
	}
	// Independent integer formulas; do not call consensus reward code/StateDB.
	unit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	base := new(big.Int).Mul(big.NewInt(100000), unit)
	totals := make(map[string]*big.Int)
	total := new(big.Int)
	add := func(kind string, to common.Address, atoms *big.Int, basis string) {
		addr := to.Hex()
		result.Rewards = append(result.Rewards, reward{kind, addr, atoms.String(), basis})
		if totals[addr] == nil {
			totals[addr] = new(big.Int)
		}
		totals[addr].Add(totals[addr], atoms)
		total.Add(total, atoms)
	}
	switch {
	case result.Number == 0:
		result.StaticRule = "genesis allocation is not block-finalization issuance"
	case len(txs) == 0 && (header.BlockType == types.FastTx_Block || header.BlockType == types.SlowTx_Block):
		result.StaticRule = "empty FastTx/SlowTx: no static or uncle reward"
	default:
		result.StaticRule = "Frontier constant 100000 * 10^18 atoms; Key carrier retains static issuance"
		add("block", header.Coinbase, base, "100000 * 10^18; actual RLP Header.Coinbase")
		for i, uncle := range uncles {
			factor := new(big.Int).Sub(new(big.Int).Add(uncle.Number, big.NewInt(8)), header.Number)
			amount := new(big.Int).Div(new(big.Int).Mul(factor, base), big.NewInt(8))
			add("uncle", uncle.Coinbase, amount, fmt.Sprintf("uncle[%d]: (uncleNumber + 8 - blockNumber) * base / 8", i))
			add("uncle_inclusion", header.Coinbase, new(big.Int).Div(new(big.Int).Set(base), big.NewInt(32)), fmt.Sprintf("uncle[%d]: base / 32", i))
		}
	}
	if result.Number != 0 && header.BlockType == types.Key_Block && len(header.KeyInfo) != 0 {
		keyFields, err := boundedList(header.KeyInfo, 7, true)
		if err != nil || len(keyFields) != 7 {
			return auditResult{}, errors.New("invalid KeyInfo structure")
		}
		var kh types.KeyBlockHeader
		if err := rlp.DecodeBytes(keyFields[0], &kh); err != nil || kh.Number == nil || !kh.Number.IsUint64() || kh.Difficulty == nil || kh.Difficulty.Sign() < 0 || kh.Difficulty.BitLen() > 80 {
			return auditResult{}, errors.New("invalid KeyInfo header")
		}
		var key types.KeyBlock
		if err := rlp.DecodeBytes(header.KeyInfo, &key); err != nil || key.ParentHash() != header.KeyHash {
			return auditResult{}, errors.New("KeyInfo decode or carrier KeyHash/parent mismatch")
		}
		// Match the production rule's single leading '*' removal. An empty
		// outAddress has no bonus; OutAddress(1)'s leader fallback is NOT used.
		out := strings.TrimPrefix(key.OutAddress(0), "*")
		if out != "" {
			if !common.IsHexAddress(out) {
				return auditResult{}, errors.New("invalid KeyInfo outAddress")
			}
			add("key_pow_bonus", common.HexToAddress(out), new(big.Int).Set(base), "100000 * 10^18; KeyInfo.OutAddress(0) after one leading '*' removal")
		}
	}
	for addr := range totals {
		result.Recipients = append(result.Recipients, recipientTotal{addr, totals[addr].String()})
	}
	sort.Slice(result.Recipients, func(i, j int) bool { return result.Recipients[i].Recipient < result.Recipients[j].Recipient })
	result.TotalAtoms = total.String()
	return result, nil
}

func run(input io.Reader, output io.Writer) error {
	limited := &io.LimitedReader{R: input, N: maxInputBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	enc := json.NewEncoder(output)
	count := 0
	for scanner.Scan() {
		count++
		if count > maxBlocks || limited.N == 0 {
			return errors.New("input exceeds audit byte or block limit")
		}
		in, err := parseInput(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("line %d: %w", count, err)
		}
		result, err := audit(in)
		if err != nil {
			return fmt.Errorf("line %d: %w", count, err)
		}
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("output line %d: %w", count, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("input read/line limit failure: %w", err)
	}
	if limited.N == 0 || count == 0 {
		return errors.New("empty or oversized input")
	}
	return nil
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dex-block-audit < bounded-blocks.ndjson > audit.ndjson")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout); err != nil {
		// Never echo input RLP or arbitrary JSON strings into error logs.
		fmt.Fprintln(os.Stderr, "dex-block-audit:", err)
		os.Exit(1)
	}
}
