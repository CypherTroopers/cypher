// Package transport supplies bounded mutually pinned TLS for isolated DEX peers.
// It does not authenticate DEX execution or replace the FHS message signatures.
package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cypherium/cypher/dex/protocol"
)

const (
	MaxPayload    = 128 * 1024
	HeaderSize    = 75
	MaxFrame      = HeaderSize + MaxPayload
	KindConsensus = uint8(1)
	KindAction    = uint8(2)
	KindExtension = uint8(3)
)

var ErrBusy = errors.New("DEX transport temporarily busy")
var ErrCapacity = errors.New("DEX transport outbox capacity")

type Frame struct {
	Epoch, Registry           protocol.Hash
	Source, Destination, Kind uint8
	Payload                   []byte
}

func (f Frame) Encode() ([]byte, error) {
	if f.Epoch == (protocol.Hash{}) || f.Registry == (protocol.Hash{}) || f.Source >= 7 || f.Destination >= 7 || f.Kind < 1 || f.Kind > 3 || len(f.Payload) == 0 || len(f.Payload) > MaxPayload {
		return nil, errors.New("invalid bounded DEX frame")
	}
	b := make([]byte, 4+HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	copy(b[4:], "CDXNET01")
	copy(b[12:], f.Epoch[:])
	copy(b[44:], f.Registry[:])
	b[76], b[77], b[78] = f.Source, f.Destination, f.Kind
	copy(b[79:], f.Payload)
	return b, nil
}
func Decode(b []byte) (Frame, error) {
	var f Frame
	if len(b) < 4+HeaderSize+1 || len(b) > 4+MaxFrame || binary.BigEndian.Uint32(b[:4]) != uint32(len(b)-4) || string(b[4:12]) != "CDXNET01" {
		return f, errors.New("noncanonical DEX frame")
	}
	copy(f.Epoch[:], b[12:44])
	copy(f.Registry[:], b[44:76])
	f.Source, f.Destination, f.Kind = b[76], b[77], b[78]
	f.Payload = bytes.Clone(b[79:])
	if _, err := f.Encode(); err != nil {
		return Frame{}, err
	}
	return f, nil
}
func Read(r io.Reader) (Frame, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < HeaderSize+1 || n > MaxFrame {
		return Frame{}, nil, errors.New("DEX frame length bound")
	}
	b := make([]byte, 4+int(n))
	copy(b, header[:])
	if _, err := io.ReadFull(r, b[4:]); err != nil {
		return Frame{}, nil, err
	}
	f, err := Decode(b)
	return f, b, err
}
func ID(encoded []byte) protocol.Hash {
	if len(encoded) < 4 {
		return protocol.Hash{}
	}
	return protocol.Digest("common-dex/socket-frame/v1", encoded[4:])
}
