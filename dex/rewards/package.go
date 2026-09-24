package rewards

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/dex/protocol"
)

const MaxClosePackageBytes = 65536
const ClosePackageMarker = "CDXPRW01"

type ClosePackage struct {
	Period       uint64
	Blocks       []FinalizedBlock
	Certificates []Certificate
}

func (p ClosePackage) shape() error {
	if p.Period == 0 || p.Period > (math.MaxUint64-GraceBlocks)/PeriodBlocks || len(p.Blocks) != int(PeriodBlocks)+1 || len(p.Certificates) > MaxPeriodCertificates {
		return errors.New("close package bounds")
	}
	domain := p.Blocks[0].Checkpoint.Domain()
	for i, b := range p.Blocks {
		height := (p.Period-1)*PeriodBlocks + 1 + uint64(i)
		if i == int(PeriodBlocks) {
			height = p.Period*PeriodBlocks + GraceBlocks
		}
		if b.Checkpoint.FirstBlock != height || b.Checkpoint.LastBlock != height || b.Checkpoint.Domain() != domain || len(b.Proof) == 0 || len(b.Proof) > checkpoint.MaxProofBytes {
			return errors.New("close package witness order/domain/bound")
		}
	}
	for i, c := range p.Certificates {
		if c.Duty.Domain != domain || c.Duty.Period != p.Period {
			return errors.New("close package certificate domain/period")
		}
		if i > 0 {
			old := p.Certificates[i-1].Duty
			if c.Duty.Height < old.Height || c.Duty.Height == old.Height && c.Duty.Participant <= old.Participant {
				return errors.New("noncanonical close certificate order")
			}
		}
	}
	return nil
}

func (p ClosePackage) Encode() ([]byte, error) {
	if err := p.shape(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(ClosePackageMarker)
	_ = binary.Write(&b, binary.BigEndian, p.Period)
	b.WriteByte(byte(len(p.Blocks)))
	for _, w := range p.Blocks {
		cp, err := w.Checkpoint.Encode()
		if err != nil {
			return nil, err
		}
		b.Write(cp)
		_ = binary.Write(&b, binary.BigEndian, uint16(len(w.Proof)))
		b.Write(w.Proof)
		if b.Len() > MaxClosePackageBytes {
			return nil, errors.New("close package aggregate byte bound")
		}
	}
	b.WriteByte(byte(len(p.Certificates)))
	for _, c := range p.Certificates {
		encoded, err := c.Encode()
		if err != nil {
			return nil, err
		}
		_ = binary.Write(&b, binary.BigEndian, uint16(len(encoded)))
		b.Write(encoded)
		if b.Len() > MaxClosePackageBytes {
			return nil, errors.New("close package aggregate byte bound")
		}
	}
	if b.Len() > MaxClosePackageBytes {
		return nil, errors.New("close package aggregate byte bound")
	}
	return b.Bytes(), nil
}

func DecodeClosePackage(data []byte) (ClosePackage, error) {
	var p ClosePackage
	if len(data) < 18 || len(data) > MaxClosePackageBytes || string(data[:8]) != ClosePackageMarker {
		return p, errors.New("close package marker/byte bound")
	}
	p.Period = binary.BigEndian.Uint64(data[8:16])
	n := int(data[16])
	offset := 17
	if n != int(PeriodBlocks)+1 {
		return ClosePackage{}, errors.New("close package witness count")
	}
	for i := 0; i < n; i++ {
		if len(data)-offset < protocol.CheckpointSize+2 {
			return ClosePackage{}, errors.New("truncated close checkpoint")
		}
		cp, err := protocol.DecodeCheckpoint(data[offset : offset+protocol.CheckpointSize])
		if err != nil {
			return ClosePackage{}, err
		}
		offset += protocol.CheckpointSize
		count := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if count == 0 || count > checkpoint.MaxProofBytes || count > len(data)-offset {
			return ClosePackage{}, errors.New("close proof byte bound")
		}
		p.Blocks = append(p.Blocks, FinalizedBlock{cp, bytes.Clone(data[offset : offset+count])})
		offset += count
	}
	if offset == len(data) {
		return ClosePackage{}, errors.New("missing close certificate count")
	}
	count := int(data[offset])
	offset++
	if count > MaxPeriodCertificates {
		return ClosePackage{}, errors.New("close certificate count bound")
	}
	for i := 0; i < count; i++ {
		if len(data)-offset < 2 {
			return ClosePackage{}, errors.New("truncated close certificate length")
		}
		n := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if n > MaxCertificateSize || n > len(data)-offset {
			return ClosePackage{}, errors.New("close certificate byte bound")
		}
		c, err := DecodeCertificate(data[offset : offset+n])
		if err != nil {
			return ClosePackage{}, err
		}
		p.Certificates = append(p.Certificates, c)
		offset += n
	}
	if offset != len(data) {
		return ClosePackage{}, errors.New("trailing close package bytes")
	}
	if err := p.shape(); err != nil {
		return ClosePackage{}, err
	}
	return p, nil
}
