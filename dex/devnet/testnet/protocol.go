// Package testnet is an isolated process-test utility, not a public bootstrap API.
package testnet

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/engine"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/rewards"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/transport"
)

const OutputPrefix = "DEXCTL "
const MaxControlBytes = 2 * 1024 * 1024
const extensionHeader = "CDXEXT01"
const (
	extensionVote byte = iota + 1
	extensionReceipt
	extensionCertificate
	extensionRequest
	extensionRecord
)

type Identity struct {
	Peer                                 transport.Peer
	Member                               *common.Cnode
	API                                  string
	VoteKeyFile, TLSCertFile, TLSKeyFile string
}
type Init struct {
	Domain              protocol.Domain
	Members             []*common.Cnode
	Peers               []transport.Peer
	Market              engine.Config
	CLX                 clxevidence.Config
	MaxHeight           uint64
	ParticipationHeight uint64
	TimeoutMillis       uint64
}
type Request struct {
	Op      string
	Init    *Init  `json:",omitempty"`
	Height  uint64 `json:",omitempty"`
	Raw     []byte `json:",omitempty"`
	Allowed []bool `json:",omitempty"`
}
type Response struct {
	Error         string                `json:",omitempty"`
	Identity      *Identity             `json:",omitempty"`
	Status        *service.Status       `json:",omitempty"`
	Checkpoint    *protocol.Checkpoint  `json:",omitempty"`
	Proof         []byte                `json:",omitempty"`
	State         []byte                `json:",omitempty"`
	Certificates  []rewards.Certificate `json:",omitempty"`
	ReceiptErrors uint64                `json:",omitempty"`
}

func extension(kind byte, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body)+9 > transport.MaxPayload {
		return nil, errors.New("extension byte bound")
	}
	b := append([]byte(extensionHeader), kind)
	return append(b, body...), nil
}
func decodeExtension(raw []byte) (byte, []byte, error) {
	if len(raw) <= 9 || len(raw) > transport.MaxPayload || string(raw[:8]) != extensionHeader || raw[8] < extensionVote || raw[8] > extensionRecord {
		return 0, nil, errors.New("extension envelope")
	}
	return raw[8], raw[9:], nil
}
func encodeVote(ref, raw []byte) ([]byte, error) {
	if len(ref) == 0 || len(ref) > 2048 || len(raw) == 0 || len(raw) > 8192 {
		return nil, errors.New("vote extension bound")
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(len(ref)))
	b.Write(ref)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(raw)))
	b.Write(raw)
	return extension(extensionVote, b.Bytes())
}
func decodeVote(b []byte) ([]byte, []byte, error) {
	if len(b) < 7 {
		return nil, nil, errors.New("short vote extension")
	}
	n := int(binary.BigEndian.Uint16(b))
	if n == 0 || n > 2048 || len(b) < 2+n+4 {
		return nil, nil, errors.New("vote reference bound")
	}
	m := int(binary.BigEndian.Uint32(b[2+n:]))
	if m == 0 || m > 8192 || len(b) != 2+n+4+m {
		return nil, nil, errors.New("vote message bound")
	}
	return b[2 : 2+n], b[2+n+4:], nil
}
func requestData(after uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], after)
	out, _ := extension(extensionRequest, b[:])
	return out
}
