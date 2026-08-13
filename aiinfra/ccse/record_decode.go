// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package ccse

import (
	"bytes"
	"encoding/binary"
)

// ParseRecordPreimage performs the inverse of Record.Preimage for immutable
// evidence restored after a restart. It does not verify authorization or the
// signature; callers must re-resolve the authoritative key and verify it. The
// exact input is re-encoded before return, so noncanonical inner projections,
// trailing data and ambiguous lengths are rejected.
func ParseRecordPreimage(preimage, signature []byte, limits Limits) (Record, error) {
	limits, err := normalizeLimits(limits)
	if err != nil || len(preimage) == 0 || len(signature) == 0 || len(signature) > limits.MaxSignatureBytes {
		return Record{}, ErrInvalidRecord
	}
	reader := recordPreimageReader{input: preimage}
	preamble, err := reader.take(len(ccseV1Preamble))
	if err != nil || string(preamble) != ccseV1Preamble {
		return Record{}, ErrInvalidRecord
	}
	messageType, err := reader.uint32()
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	major, err := reader.uint32()
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	minor, err := reader.uint32()
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	domainLength, err := reader.uint32()
	if err != nil || uint64(domainLength) > uint64(limits.MaxDomainBytes) {
		return Record{}, ErrInvalidRecord
	}
	domainBytes, err := reader.take(int(domainLength))
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	envelopeLength, err := reader.uint64()
	if err != nil || envelopeLength > uint64(limits.MaxEnvelopeBytes) {
		return Record{}, ErrInvalidRecord
	}
	envelopeBytes, err := reader.takeUint64(envelopeLength)
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	payloadLength, err := reader.uint64()
	if err != nil || payloadLength > uint64(limits.MaxPayloadBytes) {
		return Record{}, ErrInvalidRecord
	}
	payload, err := reader.takeUint64(payloadLength)
	if err != nil || reader.offset != len(reader.input) {
		return Record{}, ErrInvalidRecord
	}
	domain, err := decodeRecordDomain(domainBytes, limits.MaxDomainBytes)
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	envelope, err := decodeRecordEnvelope(envelopeBytes, limits.MaxEnvelopeBytes)
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	record := Record{MessageTypeID: messageType, SchemaVersion: Version{Major: major, Minor: minor},
		Domain: domain, Envelope: envelope, Payload: append([]byte(nil), payload...),
		Signature: append([]byte(nil), signature...)}
	reencoded, err := record.Preimage(limits)
	if err != nil || !bytes.Equal(reencoded, preimage) {
		return Record{}, ErrInvalidRecord
	}
	return record, nil
}

type recordPreimageReader struct {
	input  []byte
	offset int
}

func (r *recordPreimageReader) take(size int) ([]byte, error) {
	if size < 0 || r.offset > len(r.input) || size > len(r.input)-r.offset {
		return nil, ErrInvalidRecord
	}
	value := r.input[r.offset : r.offset+size]
	r.offset += size
	return value, nil
}
func (r *recordPreimageReader) takeUint64(size uint64) ([]byte, error) {
	if size > uint64(len(r.input)) {
		return nil, ErrInvalidRecord
	}
	return r.take(int(size))
}
func (r *recordPreimageReader) uint32() (uint32, error) {
	value, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}
func (r *recordPreimageReader) uint64() (uint64, error) {
	value, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}

func decodeRecordDomain(input []byte, maximum int) (Domain, error) {
	var value Domain
	err := Unmarshal(input, maximum, func(in *Decoder) error {
		var err error
		if value.Purpose, err = in.String(maximum); err != nil {
			return err
		}
		if value.SenderIdentity, err = in.String(maximum); err != nil {
			return err
		}
		if value.Audience, err = in.StringSet(maxAudience, maximum); err != nil {
			return err
		}
		if value.TenantOrganization.Present, value.TenantOrganization.Value, err = in.OptionalString(maximum); err != nil {
			return err
		}
		if value.ProviderOrganization.Present, value.ProviderOrganization.Value, err = in.OptionalString(maximum); err != nil {
			return err
		}
		fixed, err := in.FixedBytes(32)
		if err != nil {
			return err
		}
		copy(value.ChainID[:], fixed)
		fixed, err = in.FixedBytes(DigestSize)
		if err != nil {
			return err
		}
		copy(value.GenesisHash[:], fixed)
		if value.Environment, err = in.String(maximum); err != nil {
			return err
		}
		if value.ProtocolVersion.Major, err = in.Uint32(); err != nil {
			return err
		}
		if value.ProtocolVersion.Minor, err = in.Uint32(); err != nil {
			return err
		}
		if value.SchemaVersion.Major, err = in.Uint32(); err != nil {
			return err
		}
		if value.SchemaVersion.Minor, err = in.Uint32(); err != nil {
			return err
		}
		algorithm, err := in.Uint32()
		if err != nil {
			return err
		}
		value.SignatureAlgorithm = SignatureAlgorithmID(algorithm)
		if value.SignatureKeyID, err = in.String(maximum); err != nil {
			return err
		}
		if value.IssuedAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		if value.ExpiresAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		counterKind, err := in.Uint32()
		if err != nil {
			return err
		}
		value.CounterKind = CounterKind(counterKind)
		if value.Counter, err = in.Uint64(); err != nil {
			return err
		}
		value.ReplayDomainID, err = in.String(maximum)
		return err
	})
	if err != nil || value.validate() != nil {
		return Domain{}, ErrInvalidRecord
	}
	reencoded, err := value.canonicalBytes(maximum)
	if err != nil || !bytes.Equal(reencoded, input) {
		return Domain{}, ErrInvalidRecord
	}
	return value, nil
}

func decodeRecordEnvelope(input []byte, maximum int) (Envelope, error) {
	var value Envelope
	err := Unmarshal(input, maximum, func(in *Decoder) error {
		var err error
		if value.ProtocolVersion.Major, err = in.Uint32(); err != nil {
			return err
		}
		if value.ProtocolVersion.Minor, err = in.Uint32(); err != nil {
			return err
		}
		if value.SchemaVersion.Major, err = in.Uint32(); err != nil {
			return err
		}
		if value.SchemaVersion.Minor, err = in.Uint32(); err != nil {
			return err
		}
		fixed, err := in.FixedBytes(MessageIDSize)
		if err != nil {
			return err
		}
		copy(value.MessageID[:], fixed)
		fixed, err = in.FixedBytes(MessageIDSize)
		if err != nil {
			return err
		}
		copy(value.CorrelationID[:], fixed)
		if value.CausationID.Present, err = in.Bool(); err != nil {
			return err
		}
		if value.CausationID.Present {
			fixed, err = in.FixedBytes(MessageIDSize)
			if err != nil {
				return err
			}
			copy(value.CausationID.Value[:], fixed)
		}
		if value.SenderIdentity, err = in.String(maximum); err != nil {
			return err
		}
		fixed, err = in.FixedBytes(32)
		if err != nil {
			return err
		}
		copy(value.ChainID[:], fixed)
		if value.Environment, err = in.String(maximum); err != nil {
			return err
		}
		if value.IssuedAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		if value.ExpiresAtUnixNano, err = in.Int64(); err != nil {
			return err
		}
		counterKind, err := in.Uint32()
		if err != nil {
			return err
		}
		value.CounterKind = CounterKind(counterKind)
		if value.Counter, err = in.Uint64(); err != nil {
			return err
		}
		fixed, err = in.FixedBytes(DigestSize)
		if err != nil {
			return err
		}
		copy(value.PayloadDigest[:], fixed)
		algorithm, err := in.Uint32()
		if err != nil {
			return err
		}
		value.SignatureAlgorithm = SignatureAlgorithmID(algorithm)
		if value.SignatureKeyID, err = in.String(maximum); err != nil {
			return err
		}
		return in.ValidatedList(maxExtensions, maximum, func(_ int, child *Decoder) error {
			var extension Extension
			if extension.ID, err = child.Uint32(); err != nil {
				return err
			}
			if extension.Critical, err = child.Bool(); err != nil {
				return err
			}
			if extension.Value, err = child.Bytes(maximum); err != nil {
				return err
			}
			value.Extensions = append(value.Extensions, extension)
			return nil
		})
	})
	if err != nil || value.validate() != nil {
		return Envelope{}, ErrInvalidRecord
	}
	reencoded, err := value.canonicalBytes(maximum)
	if err != nil || !bytes.Equal(reencoded, input) {
		return Envelope{}, ErrInvalidRecord
	}
	return value, nil
}
