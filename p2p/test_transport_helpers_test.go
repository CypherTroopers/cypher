package p2p

import (
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"net"

	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/p2p/enode"
	"golang.org/x/crypto/sha3"
)

// These helpers historically lived in the removed server_test.go. Peer tests
// still exercise the same in-memory authenticated frame transport, so keep the
// minimal shared fixture here instead of leaving the p2p test package
// uncompilable.
type testTransport struct {
	rpub *ecdsa.PublicKey
	*rlpx
	closeErr error
}

func newTestTransport(rpub *ecdsa.PublicKey, fd net.Conn) transport {
	wrapped := newRLPX(fd).(*rlpx)
	wrapped.rw = newRLPXFrameRW(fd, secrets{
		MAC:        zero16,
		AES:        zero16,
		IngressMAC: sha3.NewLegacyKeccak256(),
		EgressMAC:  sha3.NewLegacyKeccak256(),
	})
	return &testTransport{rpub: rpub, rlpx: wrapped}
}

func (transport *testTransport) doEncHandshake(*ecdsa.PrivateKey, *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	return transport.rpub, nil
}

func (transport *testTransport) doProtoHandshake(*protoHandshake) (*protoHandshake, error) {
	return &protoHandshake{ID: crypto.FromECDSAPub(transport.rpub)[1:], Name: "test"}, nil
}

func (transport *testTransport) close(err error) {
	_ = transport.rlpx.fd.Close()
	transport.closeErr = err
}

func newkey() *ecdsa.PrivateKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key
}

func randomID() (id enode.ID) {
	if _, err := cryptorand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}
