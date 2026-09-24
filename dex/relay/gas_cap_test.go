package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

// Install an exact V1 journal as written before protocol-cap clamping. This is
// test setup, not a live StateDB/nonce edit; restart uses the ordinary Open path.
func legacyOversizeAttempt(t *testing.T, dir string) (Config, *testBackend, *testSigner, Attempt) {
	t.Helper()
	c, b, s := fixtureConfig(t)
	c.GasLimits[Anchor] = 20000000
	b.obs.nonce, b.obs.requiredGas = 7, 13800000
	r := openFixture(t, c, b, s, dir)
	j := fixtureJob(Anchor, 1)
	if err := r.Enqueue(j); err != nil {
		t.Fatal(err)
	}
	price, _ := protocol.AmountFromBig(c.GasPrice)
	old := Attempt{Nonce: 7, GasLimit: 20000000, GasPrice: price, Sends: 1}
	tx := types.NewTransaction(old.Nonce, c.Custody, new(big.Int), old.GasLimit, c.GasPrice, j.Payload)
	signed, err := types.SignTx(tx, types.NewEIP155Signer(new(big.Int).SetUint64(c.Domain.ChainID)), s.keys[c.Payers[Anchor]])
	if err != nil {
		t.Fatal(err)
	}
	old.Raw, _ = rlp.EncodeToBytes(signed)
	old.Hash = signed.Hash()
	record := r.Status()[0]
	record.Attempt, record.Phase = old, "submitted"
	if err := r.update(0, record); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.bin"))
	if binary.BigEndian.Uint16(raw[4:6]) != 1 {
		t.Fatal("legacy setup changed envelope")
	}
	r.Close()
	return c, b, s, old
}

func TestRelayGasCapCorrectionRetainsV1AttemptAcrossCrash(t *testing.T) {
	for _, boundary := range []string{"before_gas_replacement", "after_gas_replacement", "after_signed", "before_send", "after_send"} {
		t.Run(boundary, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "relay")
			c, b, s, old := legacyOversizeAttempt(t, dir)
			binding, _ := c.hash()
			c.Hook = func(stage string) error {
				if stage == boundary {
					return errors.New("injected process interruption")
				}
				return nil
			}
			r := openFixture(t, c, b, s, dir)
			if err := stepNow(r); !errors.Is(err, ErrStore) {
				t.Fatal("boundary not reached", err)
			}
			r.Close()
			c.Hook = nil
			r = openFixture(t, c, b, s, dir)
			defer r.Close()
			if err := stepNow(r); err != nil {
				t.Fatal("cold correction", err)
			}
			record := r.Status()[0]
			if r.state.Binding != binding || r.state.Version != 2 || record.Attempt.Nonce != old.Nonce || record.Attempt.GasLimit != params.MaxTxGas || record.Attempt.GasPrice != old.GasPrice || len(record.PriorAttempts) != 1 {
				t.Fatal("replacement reservation or binding", record)
			}
			prior := record.PriorAttempts[0]
			if !bytes.Equal(prior.Raw, old.Raw) || prior.Hash != old.Hash || prior.Sends != old.Sends || prior.ACK != old.ACK || prior.Nonce != old.Nonce {
				t.Fatal("old signed evidence changed")
			}
			if record.Attempt.Hash == old.Hash {
				t.Fatal("gas cap did not change transaction")
			}
			for _, raw := range b.sent {
				if !bytes.Equal(raw, record.Attempt.Raw) {
					t.Fatal("obsolete raw sent or replacement bytes changed")
				}
			}
			if len(b.sent) == 0 {
				t.Fatal("replacement not sent")
			}
			r.Close()
			r = openFixture(t, c, b, s, dir)
			defer r.Close()
			b.obs.nonce, b.obs.completed = old.Nonce+1, true
			before := len(b.sent)
			if err := stepNow(r); err != nil {
				t.Fatal(err)
			}
			record = r.Status()[0]
			if record.Phase != "complete" || len(record.PriorAttempts) != 1 || len(b.sent) != before || !bytes.Equal(record.PriorAttempts[0].Raw, old.Raw) {
				t.Fatal("consumed nonce/completed business lost history or resent")
			}
		})
	}
}

func TestRelayGasCapRequiresAuthenticatedUnconsumedNonceAndLease(t *testing.T) {
	for _, scenario := range []string{"unverified", "nonce_consumed", "nonce_regressed", "standby", "demoted", "budget"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "relay")
			c, b, s, old := legacyOversizeAttempt(t, dir)
			at := Leadership{View: 4, Active: true}
			switch scenario {
			case "unverified":
				b.obs.verified = false
			case "nonce_consumed":
				b.obs.nonce++
			case "nonce_regressed":
				b.obs.nonce--
			case "standby":
				at.Active = false
			case "demoted":
				c.Hook = func(stage string) error {
					if stage == "after_gas_replacement" {
						at.View++
					}
					return nil
				}
			case "budget":
				b.obs.requiredGas = params.MaxTxGas + 1
			}
			l := openLeaderFixture(t, c, b, s, dir, func(context.Context) (Leadership, error) { return at, nil })
			defer l.Close()
			_ = leaderStepNow(l, scenario == "standby")
			record := l.Status()[0]
			if len(b.sent) != 0 || s.calls != 0 {
				t.Fatal("unauthorized replacement signed/sent")
			}
			if scenario == "demoted" {
				if len(record.PriorAttempts) != 1 || !bytes.Equal(record.PriorAttempts[0].Raw, old.Raw) || record.Attempt.Nonce != old.Nonce {
					t.Fatal("demotion lost old intent")
				}
			} else if !bytes.Equal(record.Attempt.Raw, old.Raw) || len(record.PriorAttempts) != 0 {
				t.Fatal("nonce/proof/budget failure rewrote old attempt")
			}
		})
	}
}

func TestRelayGasCapNewTemplatesAndHistoryBounds(t *testing.T) {
	c, b, s := fixtureConfig(t)
	c.GasLimits[Anchor] = 20000000
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	defer r.Close()
	j := fixtureJob(Anchor, 1)
	if err := r.Enqueue(j); err != nil {
		t.Fatal(err)
	}
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	if r.Status()[0].Attempt.GasLimit != params.MaxTxGas || c.GasLimits[Anchor] != 20000000 || len(r.Status()[0].PriorAttempts) != 0 {
		t.Fatal("new template clamp changed config or invented history")
	}
	oldDir := filepath.Join(t.TempDir(), "old")
	oc, ob, osign, old := legacyOversizeAttempt(t, oldDir)
	or := openFixture(t, oc, ob, osign, oldDir)
	defer or.Close()
	if err := stepNow(or); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*diskState){
		func(d *diskState) { d.Records[0].PriorAttempts = append(d.Records[0].PriorAttempts, old) },
		func(d *diskState) { d.Records[0].PriorAttempts[0].Nonce++ },
		func(d *diskState) { d.Records[0].PriorAttempts[0].Raw[10] ^= 1 },
		func(d *diskState) { d.Records[0].Attempt.GasLimit-- },
		func(d *diskState) { d.Version = 1 },
	} {
		d := cloneState(or.state)
		mutate(&d)
		if validateState(d, oc, or.state.Binding) == nil {
			t.Fatal("invalid replacement history accepted")
		}
		if len(d.Records[0].PriorAttempts) > 1 {
			raw, err := encodeState(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeState(raw); err == nil {
				t.Fatal("history count not rejected before signature validation")
			}
		}
	}
}
