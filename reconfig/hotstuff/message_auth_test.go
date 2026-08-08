package hotstuff

import (
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto/bls"
)

type authTestApp struct{ *recoveryTestApp }

func (*authTestApp) RequireMessageAuth() bool { return true }

func authenticatedTestMessage(t *testing.T) (*HotstuffProtocolManager, *HotstuffMessage, *bls.PublicKey) {
	t.Helper()
	var secret bls.SecretKey
	secret.SetByCSPRNG()
	public := secret.GetPublicKey()
	app := &authTestApp{recoveryTestApp: &recoveryTestApp{self: "127.0.0.1:7100"}}
	manager := NewHotstuffProtocolManager(app, &secret, public)
	msg := manager.newMsg(MsgPrepare, 8, common.HexToHash("0x8888"), []byte("a"), []byte("b"), []byte("c"))
	msg.DataD = []byte("d")
	msg.DataE = []byte("e")
	msg.DataF = []byte("f")
	msg.DataG = []byte("g")
	if err := manager.sealMessage(msg); err != nil {
		t.Fatal(err)
	}
	return manager, msg, public
}

func cloneHotstuffMessageForAuth(t *testing.T, msg *HotstuffMessage) *HotstuffMessage {
	t.Helper()
	out := *msg
	out.PubKey = append([]byte(nil), msg.PubKey...)
	out.DataA = append([]byte(nil), msg.DataA...)
	out.DataB = append([]byte(nil), msg.DataB...)
	out.DataC = append([]byte(nil), msg.DataC...)
	out.DataD = append([]byte(nil), msg.DataD...)
	out.DataE = append([]byte(nil), msg.DataE...)
	out.DataF = append([]byte(nil), msg.DataF...)
	out.DataG = append([]byte(nil), msg.DataG...)
	out.AuthSig = append([]byte(nil), msg.AuthSig...)
	return &out
}

func TestMessageAuthenticationCoversEnvelope(t *testing.T) {
	manager, msg, public := authenticatedTestMessage(t)
	if err := VerifyMessageAuth(manager.app.ChainID(), msg, msg.Id, public); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	mutations := []func(*HotstuffMessage){
		func(m *HotstuffMessage) { m.Number++ },
		func(m *HotstuffMessage) { m.ViewId[0] ^= 1 },
		func(m *HotstuffMessage) { m.Id += "-spoofed" },
		func(m *HotstuffMessage) { m.PubKey[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataA[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataB[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataC[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataD[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataE[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataF[0] ^= 1 },
		func(m *HotstuffMessage) { m.DataG[0] ^= 1 },
	}
	for i, mutate := range mutations {
		tampered := cloneHotstuffMessageForAuth(t, msg)
		mutate(tampered)
		if err := VerifyMessageAuth(manager.app.ChainID(), tampered, msg.Id, public); err == nil {
			t.Fatalf("tampered envelope mutation %d was accepted", i)
		}
	}
}

func TestMessageAuthenticationRejectsWrongCommitteeKey(t *testing.T) {
	manager, msg, _ := authenticatedTestMessage(t)
	var attacker bls.SecretKey
	attacker.SetByCSPRNG()
	if err := VerifyMessageAuth(manager.app.ChainID(), msg, msg.Id, attacker.GetPublicKey()); err == nil {
		t.Fatal("message accepted under a different committee public key")
	}
}

func TestValidateHotstuffWireMessageRejectsOversizedControlPayload(t *testing.T) {
	_, msg, _ := authenticatedTestMessage(t)
	if err := ValidateHotstuffWireMessage(msg); err != nil {
		t.Fatalf("valid control message rejected: %v", err)
	}
	msg.DataG = make([]byte, MaxHotstuffControlBytes)
	if err := ValidateHotstuffWireMessage(msg); err == nil {
		t.Fatal("oversized control message was accepted")
	}
}

func TestValidateHotstuffWireMessageRejectsInactiveCode(t *testing.T) {
	_, msg, _ := authenticatedTestMessage(t)
	msg.Code = MsgCommit
	if err := ValidateHotstuffWireMessage(msg); err == nil {
		t.Fatal("inactive HotStuff code was accepted as a wire message")
	}
}
