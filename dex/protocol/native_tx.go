package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const NativeCallHeaderSize = 12
const MaxNativeCallBytes = 64 * 1024
const NativeDeposit = uint8(1)
const NativeSupport = uint8(2)
const NativeInsurance = uint8(3)
const NativeCheckpoint = uint8(4)
const NativeClaim = uint8(5)
const NativeAnchorUpdate = uint8(6)

type NativeCall struct {
	Operation uint8
	Body      []byte
}

func NativeGenesisRoot(seed Hash, domain Domain, custody [20]byte) (Hash, error) {
	return nativeGenesisRoot("common-dex/native-genesis/v2", seed, domain, custody)
}

func NativeGenesisRootV3(seed Hash, domain Domain, custody [20]byte) (Hash, error) {
	return nativeGenesisRoot("common-dex/native-genesis/v3", seed, domain, custody)
}

func NativeGenesisRootV4(seed Hash, domain Domain, custody [20]byte) (Hash, error) {
	return nativeGenesisRoot("common-dex/native-genesis/v4", seed, domain, custody)
}

func nativeGenesisRoot(label string, seed Hash, domain Domain, custody [20]byte) (Hash, error) {
	if seed == (Hash{}) || !domain.Valid() || custody == ([20]byte{}) {
		return Hash{}, errors.New("invalid native genesis domain")
	}
	var b bytes.Buffer
	b.Write(seed[:])
	_ = binary.Write(&b, binary.BigEndian, domain)
	b.Write(custody[:])
	return Digest(label, b.Bytes()), nil
}

func (c NativeCall) Encode() ([]byte, error) {
	if len(c.Body) > MaxNativeCallBytes-NativeCallHeaderSize || c.Operation < NativeDeposit || c.Operation > NativeAnchorUpdate {
		return nil, errors.New("native call bounds/opcode")
	}
	if c.Operation <= NativeInsurance && len(c.Body) != 0 {
		return nil, errors.New("funding call has no body")
	}
	b := make([]byte, NativeCallHeaderSize+len(c.Body))
	copy(b, "CDXN")
	binary.BigEndian.PutUint16(b[4:6], 2)
	b[6] = c.Operation
	binary.BigEndian.PutUint32(b[8:12], uint32(len(c.Body)))
	copy(b[12:], c.Body)
	return b, nil
}

func DecodeNativeCall(b []byte) (NativeCall, error) {
	if len(b) < NativeCallHeaderSize || len(b) > MaxNativeCallBytes || string(b[:4]) != "CDXN" || binary.BigEndian.Uint16(b[4:6]) != 2 || b[7] != 0 || uint64(binary.BigEndian.Uint32(b[8:12])) != uint64(len(b)-12) {
		return NativeCall{}, errors.New("noncanonical native call")
	}
	c := NativeCall{Operation: b[6], Body: append([]byte(nil), b[12:]...)}
	if _, err := c.Encode(); err != nil {
		return NativeCall{}, err
	}
	return c, nil
}

func NativePayloadHash(raw []byte) Hash { return Digest("common-dex/native-call/v2", raw) }

// NativeFundingPayloadHash binds authenticated transaction economics, including
// the native value which is deliberately absent from the empty call body. It
// forms the funding InboxEntry.PayloadHash, hence also its stable SourceID.
func NativeFundingPayloadHash(sender, owner [20]byte, amount Amount, asset uint32, bucket uint8, raw []byte) (Hash, error) {
	if sender == ([20]byte{}) || owner == ([20]byte{}) || !amount.Valid() || amount == (Amount{}) || asset != 0 || bucket < NativeDeposit || bucket > NativeInsurance {
		return Hash{}, errors.New("invalid native funding payload")
	}
	call, err := DecodeNativeCall(raw)
	if err != nil || len(raw) != NativeCallHeaderSize || call.Operation != bucket {
		return Hash{}, errors.New("native funding payload call/bucket mismatch")
	}
	var encoded [91]byte
	binary.BigEndian.PutUint16(encoded[:2], 2)
	copy(encoded[2:22], sender[:])
	copy(encoded[22:42], owner[:])
	copy(encoded[42:74], amount[:])
	binary.BigEndian.PutUint32(encoded[74:78], asset)
	encoded[78] = bucket
	copy(encoded[79:], raw)
	return Digest("common-dex/native-funding-payload/v2", encoded[:]), nil
}

func EncodeNativeCheckpoint(c Checkpoint, f FinanceSummary, dexProof, clxEvidence []byte) ([]byte, error) {
	cb, err := c.Encode()
	if err != nil {
		return nil, err
	}
	fb, err := f.Encode()
	if err != nil {
		return nil, err
	}
	if len(dexProof) > 16*1024 || len(clxEvidence) > MaxNativeCallBytes {
		return nil, errors.New("native proof bounds")
	}
	var b bytes.Buffer
	b.Write(cb)
	b.Write(fb)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(dexProof)))
	b.Write(dexProof)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(clxEvidence)))
	b.Write(clxEvidence)
	return (NativeCall{NativeCheckpoint, b.Bytes()}).Encode()
}

func DecodeNativeCheckpoint(body []byte) (Checkpoint, FinanceSummary, []byte, []byte, error) {
	var c Checkpoint
	var f FinanceSummary
	const fixed = CheckpointSize + FinanceSummarySize
	if len(body) < fixed+8 || len(body) > MaxNativeCallBytes-NativeCallHeaderSize {
		return c, f, nil, nil, errors.New("native checkpoint shape")
	}
	var err error
	c, err = DecodeCheckpoint(body[:CheckpointSize])
	if err != nil {
		return c, f, nil, nil, err
	}
	f, err = DecodeFinanceSummary(body[CheckpointSize:fixed])
	if err != nil {
		return c, f, nil, nil, err
	}
	n := uint64(binary.BigEndian.Uint32(body[fixed : fixed+4]))
	if n > 16*1024 || n > uint64(len(body)-fixed-8) {
		return c, f, nil, nil, errors.New("native DEX proof bounds")
	}
	off := fixed + 4 + int(n)
	m := uint64(binary.BigEndian.Uint32(body[off : off+4]))
	if m != uint64(len(body)-off-4) {
		return c, f, nil, nil, errors.New("native CLX proof bounds")
	}
	return c, f, append([]byte(nil), body[fixed+4:off]...), append([]byte(nil), body[off+4:]...), nil
}

func EncodeNativeClaim(c Claim, index, count uint32, siblings []Hash) ([]byte, error) {
	raw, err := c.Encode()
	if err != nil {
		return nil, err
	}
	if len(siblings) > 10 {
		return nil, errors.New("native claim bound")
	}
	var b bytes.Buffer
	b.Write(raw)
	_ = binary.Write(&b, binary.BigEndian, index)
	_ = binary.Write(&b, binary.BigEndian, count)
	b.WriteByte(byte(len(siblings)))
	for _, h := range siblings {
		b.Write(h[:])
	}
	return (NativeCall{NativeClaim, b.Bytes()}).Encode()
}
func DecodeNativeClaim(body []byte) (Claim, uint32, uint32, []Hash, error) {
	var c Claim
	if len(body) < ClaimSize+9 || len(body) > ClaimSize+9+320 {
		return c, 0, 0, nil, errors.New("native claim shape")
	}
	depth := int(body[ClaimSize+8])
	if depth > 10 || len(body) != ClaimSize+9+32*depth {
		return c, 0, 0, nil, errors.New("native claim depth")
	}
	var err error
	c, err = DecodeClaim(body[:ClaimSize])
	if err != nil {
		return c, 0, 0, nil, err
	}
	s := make([]Hash, depth)
	for i := range s {
		copy(s[i][:], body[ClaimSize+9+i*32:ClaimSize+9+(i+1)*32])
	}
	return c, binary.BigEndian.Uint32(body[ClaimSize : ClaimSize+4]), binary.BigEndian.Uint32(body[ClaimSize+4 : ClaimSize+8]), s, nil
}
