package reconfig_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypher/dex/devnet"
	"github.com/cypherium/cypher/dex/devnet/testnet"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
)

// exerciseDEXRewardOmission uses only the normal CLI's public HTTP API. command
// is a value with the next expected oracle nonce; caller nonce/pkg stay intact
// for the subsequent complete-package action in the ordinary financial trace.
func exerciseDEXRewardOmission(t *testing.T, children []*dexFinancialChild, execution *devnet.Execution, pkg rewards.ClosePackage, command engine.Action, key *ecdsa.PrivateKey) {
	t.Helper()
	if len(children) != 7 || len(pkg.Certificates) != 7 || execution == nil || command.Nonce == 0 {
		t.Fatal("reward omission requires the seven-certificate financial fixture")
	}
	omitted := pkg.Certificates[len(pkg.Certificates)-1]
	omittedID, err := omitted.Duty.Hash()
	if err != nil {
		t.Fatal(err)
	}
	before := make([]testnet.Response, len(children))
	heights := make([]uint64, len(children))
	certified := make([]uint64, len(children))
	for i, c := range children {
		if c.cli == nil {
			t.Fatal("reward omission helper requires ordinary CLI processes")
		}
		s := c.ok(t, testnet.Request{Op: "status"})
		if s.Status == nil || s.Status.Finalized == 0 {
			t.Fatal("reward omission fixture has no finalized parent")
		}
		known := false
		for _, cert := range s.Certificates {
			id, e := cert.Duty.Hash()
			known = known || (e == nil && id == omittedID)
		}
		if !known {
			t.Fatalf("participant %d has not durably received the omitted certificate", i)
		}
		heights[i] = s.Status.Finalized
		certified[i] = s.Status.Certified
		before[i] = c.ok(t, testnet.Request{Op: "checkpoint", Height: heights[i]})
		financial, market, err := execution.Decode(before[i].State)
		if err != nil || market.RewardPeriod != 0 || market.RewardReserved != "0" {
			t.Fatal("reward omission prerequisite already reserved funds", err)
		}
		committed := false
		if financial.Participation != nil {
			for _, entry := range financial.Participation.Entries {
				cert, e := rewards.DecodeCertificate(entry.Certificate)
				if e != nil {
					t.Fatal(e)
				}
				id, e := cert.Duty.Hash()
				committed = committed || (e == nil && id == omittedID)
			}
		}
		if !committed {
			t.Fatal("reward omission evidence is not in finalized financial state", i)
		}
	}
	partial := pkg
	partial.Certificates = append([]rewards.Certificate(nil), pkg.Certificates[:len(pkg.Certificates)-1]...)
	raw, err := devnet.EncodeRewardAction(command, key, partial)
	if err != nil {
		t.Fatal(err)
	}
	wantID := protocol.Digest("common-dex/ingress-action/v1", raw)
	wantHex := hex.EncodeToString(wantID[:])
	var ack map[string]string
	if err = children[0].cli.http("POST", "/v1/actions", raw, &ack); err != nil {
		t.Fatal("correctly signed reward candidate was not admitted", err)
	}
	if ack["id"] != wantHex {
		t.Fatal("reward candidate admission identity mismatch", ack)
	}
	deadline := time.Now().Add(30 * time.Second)
	rejected := -1
	for time.Now().Before(deadline) && rejected < 0 {
		for i, c := range children {
			var status map[string]string
			if err = c.cli.http("GET", "/v1/action-status?id="+wantHex, nil, &status); err != nil {
				t.Fatal(err)
			}
			if status["stage"] == "dex_finalized" {
				t.Fatal("known certificate omission was finalized")
			}
			if status["stage"] == "rejected" {
				if !strings.Contains(status["reason"], rewards.ErrCommittedOmission.Error()) {
					t.Fatal("reward rejected for a different cause", status)
				}
				rejected = i
				break
			}
		}
		if rejected < 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if rejected < 0 {
		t.Fatal("reward omission action did not reach an explicit rejection")
	}
	for i, c := range children {
		s := c.ok(t, testnet.Request{Op: "status"})
		if s.Status == nil || s.Status.Finalized != heights[i] || s.Status.Certified != certified[i] {
			t.Fatal("rejected reward candidate advanced certification/finality", i, s.Status)
		}
		after := c.ok(t, testnet.Request{Op: "checkpoint", Height: heights[i]})
		if before[i].Checkpoint == nil || after.Checkpoint == nil || *before[i].Checkpoint != *after.Checkpoint || !bytes.Equal(before[i].State, after.State) {
			t.Fatal("rejected reward candidate changed finalized root/reserves", i)
		}
	}
	t.Logf("REWARD_OMISSION_REJECTED candidate=%s omittedDuty=%x participant=%d rejects=%d nextNonce=%d rewardReserve=0; complete package retry retains same nonce", wantHex, omittedID, omitted.Duty.Participant, rejected, command.Nonce)
}
