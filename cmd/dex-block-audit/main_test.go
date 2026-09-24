package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/trie"
)

var (
	miner = common.HexToAddress("0x1111111111111111111111111111111111111111")
	other = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

func testHeader(number uint64, kind uint8) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), GasLimit: 100000,
		BlockType: kind, Coinbase: miner, Root: common.HexToHash("0x1234")}
}

func testBlock(h *types.Header, tx bool, uncles []*types.Header) *types.Block {
	var txs []*types.Transaction
	if tx {
		txs = []*types.Transaction{types.NewTransaction(1, other, big.NewInt(10), 21000, big.NewInt(1), nil)}
	}
	return types.NewBlock(h, txs, uncles, nil, new(trie.Trie))
}

func inputFor(t testing.TB, block *types.Block) auditInput {
	t.Helper()
	b, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	return auditInput{hex.EncodeToString(b), block.Hash(), block.NumberU64()}
}

func lineFor(t testing.TB, in auditInput) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"rlp": in.RLP, "expected_hash": in.ExpectedHash.Hex(), "expected_number": in.ExpectedNumber})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestStaticIssuanceGolden(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   uint8
		tx     bool
		number uint64
		want   string
	}{
		{"empty_fast", types.FastTx_Block, false, 10, "0"},
		{"empty_slow", types.SlowTx_Block, false, 10, "0"},
		{"nonempty_fast", types.FastTx_Block, true, 10, "100000000000000000000000"},
		{"nonempty_slow", types.SlowTx_Block, true, 10, "100000000000000000000000"},
		{"empty_key", types.Key_Block, false, 10, "100000000000000000000000"},
		{"genesis", types.Key_Block, false, 0, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := testBlock(testHeader(tc.number, tc.kind), tc.tx, nil)
			in := inputFor(t, block)
			result, err := audit(in)
			if err != nil || result.TotalAtoms != tc.want {
				t.Fatalf("issuance %s want %s, err=%v", result.TotalAtoms, tc.want, err)
			}
			if result.ActualHash != block.Hash() || result.StateRoot != block.Root() || result.Coinbase != miner || result.Scope != trustScope {
				t.Fatal("incorrect observation identity/scope")
			}
			if tc.tx && (len(result.TransactionHash) != 1 || result.TransactionHash[0] != block.Transactions()[0].Hash()) {
				t.Fatal("transaction hashes not extracted")
			}
			in.RLP = "0x" + in.RLP
			prefixed, err := audit(in)
			if err != nil || prefixed.TotalAtoms != result.TotalAtoms {
				t.Fatal("0x prefix changed result", err)
			}
		})
	}
}

func TestUncleIssuanceGoldenAndRecipientAggregation(t *testing.T) {
	uncle := testHeader(9, types.FastTx_Block)
	uncle.Coinbase = other
	result, err := audit(inputFor(t, testBlock(testHeader(10, types.FastTx_Block), true, []*types.Header{uncle})))
	if err != nil || result.TotalAtoms != "190625000000000000000000" || len(result.Rewards) != 3 {
		t.Fatalf("uncle result %+v err=%v", result, err)
	}
	want := map[string]string{miner.Hex(): "103125000000000000000000", other.Hex(): "87500000000000000000000"}
	for _, v := range result.Recipients {
		if want[v.Recipient] != v.Atoms {
			t.Fatalf("recipient %+v", v)
		}
	}
	for _, n := range []uint64{1, 10, 11} {
		uncle.Number.SetUint64(n)
		if _, err := audit(inputFor(t, testBlock(testHeader(10, types.FastTx_Block), true, []*types.Header{uncle}))); err == nil {
			t.Fatalf("accepted unsafe uncle reward height %d", n)
		}
	}
}

func keyCarrier(t testing.TB, out string) *types.Block {
	t.Helper()
	key := types.NewKeyBlock(&types.KeyBlockHeader{Number: big.NewInt(3), ParentHash: common.HexToHash("0x9876"), Difficulty: big.NewInt(1), BlockType: types.TimeReconfig}).WithBody("", "", "", out, "", other.Hex())
	b, err := rlp.EncodeToBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	h := testHeader(10, types.Key_Block)
	h.KeyInfo, h.KeyHash = b, key.ParentHash()
	return testBlock(h, false, nil)
}

func TestKeyCarrierBonusGoldenNoLeaderFallback(t *testing.T) {
	for _, tc := range []struct {
		out, want string
		count     int
	}{
		{"", "100000000000000000000000", 1},
		{"*", "100000000000000000000000", 1},
		{other.Hex(), "200000000000000000000000", 2},
		{"*" + other.Hex(), "200000000000000000000000", 2},
		{miner.Hex(), "200000000000000000000000", 1},
	} {
		r, err := audit(inputFor(t, keyCarrier(t, tc.out)))
		if err != nil || r.TotalAtoms != tc.want || len(r.Recipients) != tc.count {
			t.Fatalf("out=%q result=%+v err=%v", tc.out, r, err)
		}
	}
	if _, err := audit(inputFor(t, keyCarrier(t, "not-an-address"))); err == nil {
		t.Fatal("accepted bad key recipient")
	}
	key := keyCarrier(t, other.Hex())
	h := key.Header()
	h.KeyHash = common.Hash{}
	if _, err := audit(inputFor(t, key.WithSeal(h))); err == nil {
		t.Fatal("accepted KeyHash mismatch")
	}
}

func TestInputGuards(t *testing.T) {
	good := lineFor(t, inputFor(t, testBlock(testHeader(10, types.FastTx_Block), true, nil)))
	for _, bad := range []string{
		`{}`, `[]`, good + ` {}`, strings.Replace(good, `"expected_number":10`, `"expected_number":null`, 1),
		strings.Replace(good, `"expected_number":10`, `"expected_number":-1`, 1),
		strings.Replace(good, `"expected_number":10`, `"expected_number":1.5`, 1),
		strings.Replace(good, `"expected_number":10`, `"expected_number":1e1`, 1),
		strings.Replace(good, `"expected_number":10`, `"expected_number":18446744073709551616`, 1),
		strings.Replace(good, `"expected_number":10`, `"expected_number":10,"expected_number":10`, 1),
		strings.Replace(good, `"expected_hash":`, `"unknown":`, 1),
		strings.Replace(good, `"expected_hash":"0x`, `"expected_hash":"`, 1),
	} {
		if _, err := parseInput([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid input %s", bad[:min(len(bad), 120)])
		}
	}
	for _, n := range []uint64{0, ^uint64(0)} {
		s := strings.Replace(good, `"expected_number":10`, fmt.Sprintf(`"expected_number":%d`, n), 1)
		v, err := parseInput([]byte(s))
		if err != nil || v.ExpectedNumber != n {
			t.Fatal("uint64 round trip", err)
		}
	}
}

func TestMalformedRLPBoundsAndHashNumberGuards(t *testing.T) {
	in := inputFor(t, testBlock(testHeader(10, types.FastTx_Block), true, nil))
	for _, h := range []string{"", "0x", "0", "gg", "c0", in.RLP + "00", strings.Repeat("00", maxBlockBytes+1)} {
		bad := in
		bad.RLP = h
		if _, err := audit(bad); err == nil {
			t.Fatal("accepted malformed/bounded RLP")
		}
	}
	bad := in
	bad.ExpectedNumber++
	if _, err := audit(bad); err == nil {
		t.Fatal("number guard missing")
	}
	bad = in
	bad.ExpectedHash[0] ^= 1
	if _, err := audit(bad); err == nil {
		t.Fatal("hash guard missing")
	}
	h := testHeader(10, types.FastTx_Block)
	h.Number.Lsh(big.NewInt(1), 64)
	if _, err := audit(inputFor(t, testBlock(h, true, nil))); err == nil {
		t.Fatal("wrapped block height")
	}
	h = testHeader(10, 255)
	if _, err := audit(inputFor(t, testBlock(h, true, nil))); err == nil {
		t.Fatal("unknown block type")
	}
	h = testHeader(10, types.Key_Block)
	h.KeyInfo = []byte{0xc0}
	if _, err := audit(inputFor(t, testBlock(h, false, nil))); err == nil {
		t.Fatal("invalid KeyInfo")
	}
}

func TestBodyMutationCannotChangeIssuanceUnderSameHeader(t *testing.T) {
	block := testBlock(testHeader(10, types.FastTx_Block), true, nil)
	in := inputFor(t, block)
	raw, _ := hex.DecodeString(in.RLP)
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields[1] = rlp.RawValue{0xc0}
	raw, _ = rlp.EncodeToBytes(fields)
	in.RLP = hex.EncodeToString(raw)
	if _, err := audit(in); err == nil {
		t.Fatal("same-header removed TX body accepted")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestNDJSONAndFailureExitBoundary(t *testing.T) {
	line := lineFor(t, inputFor(t, testBlock(testHeader(10, types.FastTx_Block), true, nil)))
	var out bytes.Buffer
	if err := run(strings.NewReader(line+"\n"+line+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(out.Bytes(), []byte("\n")) != 2 {
		t.Fatal("not one result per block")
	}
	for _, bad := range []string{"", "\n", line + "\n{}\n", strings.Repeat(" ", maxLineBytes+1)} {
		if err := run(strings.NewReader(bad), new(bytes.Buffer)); err == nil {
			t.Fatal("accepted bad NDJSON")
		}
	}
	if err := run(strings.NewReader(line), brokenWriter{}); err == nil {
		t.Fatal("ignored output failure")
	}
}

func FuzzInputAndRLP(f *testing.F) {
	f.Add([]byte(`{"rlp":"c0","expected_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","expected_number":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(lineFor(f, inputFor(f, testBlock(testHeader(10, types.FastTx_Block), true, nil)))))
	f.Add([]byte(lineFor(f, inputFor(f, keyCarrier(f, other.Hex())))))
	f.Add([]byte(lineFor(f, inputFor(f, testBlock(testHeader(10, types.FastTx_Block), true, []*types.Header{testHeader(9, types.FastTx_Block)})))))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxLineBytes {
			return
		}
		in, err := parseInput(b)
		if err == nil {
			_, _ = audit(in)
		}
	})
}

func TestPredecodeListLimit(t *testing.T) {
	values := make([]rlp.RawValue, maxTransactions+1)
	for i := range values {
		values[i] = rlp.RawValue{0xc0}
	}
	encoded, err := rlp.EncodeToBytes(values)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := boundedList(encoded, maxTransactions, false); err == nil {
		t.Fatal("unbounded list count")
	}
	if _, err := boundedList(encoded, 7, true); err == nil {
		t.Fatal("outer list count")
	}
}
