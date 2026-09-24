package settlement

import (
	"bytes"
	"errors"

	"github.com/cypherium/cypher/dex/clxevidence"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/rlp"
)

type anchorUpdateEnvelope struct {
	Version      uint16
	Evidence     []byte
	Continuation []clxevidence.HeaderWitness
}

// EncodeAnchorUpdate encodes the opcode6 body, not the outer native call.
func EncodeAnchorUpdate(e clxevidence.RollingEvidence, continuation []clxevidence.HeaderWitness) ([]byte, error) {
	raw, err := clxevidence.EncodeRollingEvidence(e)
	if err != nil {
		return nil, err
	}
	out, err := rlp.EncodeToBytes(anchorUpdateEnvelope{1, raw, continuation})
	if err != nil {
		return nil, err
	}
	if _, _, err = DecodeAnchorUpdate(out); err != nil {
		return nil, err
	}
	return out, nil
}

func EncodeNativeAnchorUpdate(e clxevidence.RollingEvidence, continuation []clxevidence.HeaderWitness) ([]byte, error) {
	body, err := EncodeAnchorUpdate(e, continuation)
	if err != nil {
		return nil, err
	}
	return (protocol.NativeCall{Operation: protocol.NativeAnchorUpdate, Body: body}).Encode()
}

func anchorList(raw []byte, max int) ([][]byte, error) {
	list, tail, err := rlp.SplitList(raw)
	if err != nil || len(tail) != 0 {
		return nil, errors.New("anchor RLP list")
	}
	var out [][]byte
	for len(list) != 0 {
		if len(out) >= max {
			return nil, errors.New("anchor RLP count")
		}
		_, _, next, err := rlp.Split(list)
		if err != nil {
			return nil, err
		}
		out = append(out, list[:len(list)-len(next)])
		list = next
	}
	return out, nil
}

func DecodeAnchorUpdate(raw []byte) (clxevidence.RollingEvidence, []clxevidence.HeaderWitness, error) {
	var empty clxevidence.RollingEvidence
	if len(raw) == 0 || len(raw) > protocol.MaxNativeCallBytes-protocol.NativeCallHeaderSize {
		return empty, nil, errors.New("anchor update byte bound")
	}
	fields, err := anchorList(raw, 3)
	if err != nil || len(fields) != 3 {
		return empty, nil, errors.New("anchor update field count")
	}
	encoded, tail, err := rlp.SplitString(fields[1])
	if err != nil || len(tail) != 0 {
		return empty, nil, errors.New("anchor evidence string")
	}
	e, err := clxevidence.DecodeRollingEvidence(encoded)
	if err != nil {
		return empty, nil, err
	}
	if len(e.Entries) != 0 || len(e.Headers) == 0 {
		return empty, nil, errors.New("anchor evidence requires headers and no entries")
	}
	list, err := anchorList(fields[2], clxevidence.MaxAncestryBlocks-len(e.Headers))
	if err != nil {
		return empty, nil, err
	}
	for _, item := range list {
		parts, err := anchorList(item, 2)
		if err != nil || len(parts) != 2 {
			return empty, nil, errors.New("anchor continuation fields")
		}
		size := 0
		for i, part := range parts {
			b, _, err := rlp.SplitString(part)
			if err != nil || len(b) == 0 || (i == 1 && len(b) > clxevidence.MaxRefBytes) {
				return empty, nil, errors.New("anchor continuation field bytes")
			}
			size += len(b)
		}
		if size > clxevidence.MaxHeaderWitnessBytes {
			return empty, nil, errors.New("anchor continuation byte bound")
		}
	}
	var envelope anchorUpdateEnvelope
	if err := rlp.DecodeBytes(raw, &envelope); err != nil || envelope.Version != 1 {
		return empty, nil, errors.New("anchor update version/codec")
	}
	canonical, err := rlp.EncodeToBytes(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return empty, nil, errors.New("anchor update noncanonical")
	}
	return e, envelope.Continuation, nil
}
