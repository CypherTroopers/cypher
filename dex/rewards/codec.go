// Package rewards authenticates bounded devnet participation records. Points
// are not funding, computation validity, or proof of a particular CPU's work.
package rewards

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"github.com/cypherium/cypher/dex/protocol"
)

const (
	PeriodBlocks          = uint64(10)
	GraceBlocks           = uint64(4)
	DutySize              = 193
	ReceiptSize           = 226
	MaxCertificateSize    = 425
	MaxPeriodCertificates = 70
)

type Duty struct {
	Version     uint16
	Domain      protocol.Domain
	Period      uint64
	Height      uint64
	View        uint64
	ProposalID  protocol.Hash
	Participant uint8
	Recipient   [20]byte
}

func (d Duty) Validate() error {
	if d.Version != 1 || !d.Domain.Valid() || d.Height == 0 || d.Height > math.MaxUint64-GraceBlocks || d.Period != (d.Height-1)/PeriodBlocks+1 || d.View == 0 || d.ProposalID == (protocol.Hash{}) || d.Participant >= 7 || d.Recipient == ([20]byte{}) {
		return errors.New("invalid participation duty")
	}
	return nil
}

func (d Duty) Encode() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, d)
	return b.Bytes(), err
}

func DecodeDuty(data []byte) (Duty, error) {
	var d Duty
	if len(data) != DutySize {
		return d, errors.New("noncanonical duty length")
	}
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &d); err != nil {
		return d, err
	}
	return d, d.Validate()
}

func (d Duty) Hash() (protocol.Hash, error) {
	b, err := d.Encode()
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.Digest("common-dex/participation-duty/v1", b), nil
}

type Receipt struct {
	Duty      Duty
	Collector uint8
	Signature [32]byte
}

func receiptDigest(d Duty, collector uint8, public []byte) (protocol.Hash, error) {
	b, err := d.Encode()
	if err != nil {
		return protocol.Hash{}, err
	}
	if collector >= 7 || len(public) != 64 {
		return protocol.Hash{}, errors.New("invalid receipt collector")
	}
	b = append(b, collector)
	b = append(b, public...)
	return protocol.Digest("common-dex/participation-receipt/v1", b), nil
}

func (r Receipt) Encode() ([]byte, error) {
	b, err := r.Duty.Encode()
	if err != nil {
		return nil, err
	}
	if r.Collector >= 7 {
		return nil, errors.New("invalid receipt collector")
	}
	b = append(b, r.Collector)
	return append(b, r.Signature[:]...), nil
}

func DecodeReceipt(data []byte) (Receipt, error) {
	var r Receipt
	if len(data) != ReceiptSize {
		return r, errors.New("noncanonical receipt length")
	}
	d, err := DecodeDuty(data[:DutySize])
	if err != nil {
		return r, err
	}
	r.Duty, r.Collector = d, data[DutySize]
	copy(r.Signature[:], data[DutySize+1:])
	if r.Collector >= 7 {
		return Receipt{}, errors.New("invalid receipt collector")
	}
	return r, nil
}

type CollectorSignature struct {
	Collector uint8
	Signature [32]byte
}

type Certificate struct {
	Duty       Duty
	Signatures []CollectorSignature
}

func (c Certificate) Encode() ([]byte, error) {
	b, err := c.Duty.Encode()
	if err != nil {
		return nil, err
	}
	if len(c.Signatures) < 5 || len(c.Signatures) > 7 {
		return nil, errors.New("participation requires 5/7 collector receipts")
	}
	b = append(b, byte(len(c.Signatures)))
	for i, s := range c.Signatures {
		if s.Collector >= 7 || i > 0 && s.Collector <= c.Signatures[i-1].Collector {
			return nil, errors.New("noncanonical receipt collector order")
		}
		b = append(b, s.Collector)
		b = append(b, s.Signature[:]...)
	}
	return b, nil
}

func DecodeCertificate(data []byte) (Certificate, error) {
	var c Certificate
	if len(data) < DutySize+1 || len(data) > MaxCertificateSize {
		return c, errors.New("certificate byte limit")
	}
	d, err := DecodeDuty(data[:DutySize])
	if err != nil {
		return c, err
	}
	n := int(data[DutySize])
	if n < 5 || n > 7 || len(data) != DutySize+1+33*n {
		return c, errors.New("noncanonical certificate count or length")
	}
	c.Duty = d
	for i := 0; i < n; i++ {
		offset := DutySize + 1 + 33*i
		var s CollectorSignature
		s.Collector = data[offset]
		copy(s.Signature[:], data[offset+1:offset+33])
		c.Signatures = append(c.Signatures, s)
	}
	if _, err := c.Encode(); err != nil {
		return Certificate{}, err
	}
	return c, nil
}

type Point struct {
	Participant uint8
	Recipient   [20]byte
	Points      uint8
}
type Points struct {
	Domain  protocol.Domain
	Period  uint64
	Entries [7]Point
}

func (p Points) Encode() ([]byte, error) {
	if !p.Domain.Valid() || p.Period == 0 || p.Period > (math.MaxUint64-GraceBlocks)/PeriodBlocks {
		return nil, errors.New("invalid points period")
	}
	for i, e := range p.Entries {
		if e.Participant != uint8(i) || e.Recipient == ([20]byte{}) || e.Points > uint8(PeriodBlocks) {
			return nil, errors.New("invalid bounded participation points")
		}
	}
	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, p)
	return b.Bytes(), err
}
func (p Points) Root() (protocol.Hash, error) {
	b, err := p.Encode()
	if err != nil {
		return protocol.Hash{}, err
	}
	return protocol.Digest("common-dex/participation-points/v1", b), nil
}
