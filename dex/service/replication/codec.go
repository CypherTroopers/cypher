// Package replication authenticates devnet participation and certified-data
// delivery on the same actor that owns the DEX FHS application.
package replication

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cypherium/cypher/dex/transport"
)

const header = "CDXEXT01"
const (
	voteKind byte = iota + 1
	receiptKind
	certificateKind
	requestKind
	recordKind
)

func encode(kind byte, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body)+9 > transport.MaxPayload {
		return nil, errors.New("replication byte bound")
	}
	return append(append([]byte(header), kind), body...), nil
}
func decode(raw []byte) (byte, []byte, error) {
	if len(raw) <= 9 || len(raw) > transport.MaxPayload || string(raw[:8]) != header || raw[8] < voteKind || raw[8] > recordKind {
		return 0, nil, errors.New("replication envelope")
	}
	return raw[8], raw[9:], nil
}
func encodeVote(ref, raw []byte) ([]byte, error) {
	if len(ref) == 0 || len(ref) > 2048 || len(raw) == 0 || len(raw) > 8192 {
		return nil, errors.New("replication vote bound")
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(len(ref)))
	b.Write(ref)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(raw)))
	b.Write(raw)
	return encode(voteKind, b.Bytes())
}
func decodeVote(b []byte) ([]byte, []byte, error) {
	if len(b) < 7 {
		return nil, nil, errors.New("replication vote length")
	}
	n := int(binary.BigEndian.Uint16(b))
	if n == 0 || n > 2048 || len(b) < 2+n+4 {
		return nil, nil, errors.New("replication reference bound")
	}
	m := int(binary.BigEndian.Uint32(b[2+n:]))
	if m == 0 || m > 8192 || len(b) != 2+n+4+m {
		return nil, nil, errors.New("replication message bound")
	}
	return b[2 : 2+n], b[2+n+4:], nil
}
func request(after uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], after)
	raw, _ := encode(requestKind, b[:])
	return raw
}
