package rewards

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"

	"github.com/cypherium/cypher/dex/protocol"
)

const CommitMarker = "CDXPCB02"
const MaxCommitBytes = 12 + MaxPeriodCertificates*(2+MaxCertificateSize)
const MaxPendingCertificates = 2 * MaxPeriodCertificates

var ErrUncommittedPeriod = errors.New("reward period has no committed participation")
var ErrCommittedOmission = errors.New("reward close differs from committed participation set")

type CommitBatch struct{ Certificates []Certificate }

func (b CommitBatch) Encode() ([]byte, error) {
	if len(b.Certificates) == 0 || len(b.Certificates) > MaxPeriodCertificates {
		return nil, errors.New("participation commit count")
	}
	var out bytes.Buffer
	out.WriteString(CommitMarker)
	_ = binary.Write(&out, binary.BigEndian, uint16(2))
	_ = binary.Write(&out, binary.BigEndian, uint16(len(b.Certificates)))
	var previous protocol.Hash
	for i, cert := range b.Certificates {
		h, err := cert.Duty.Hash()
		if err != nil {
			return nil, err
		}
		if i > 0 && bytes.Compare(previous[:], h[:]) >= 0 {
			return nil, errors.New("participation commit order")
		}
		previous = h
		raw, err := cert.Encode()
		if err != nil {
			return nil, err
		}
		_ = binary.Write(&out, binary.BigEndian, uint16(len(raw)))
		out.Write(raw)
	}
	return out.Bytes(), nil
}

func DecodeCommitBatch(raw []byte) (CommitBatch, error) {
	var b CommitBatch
	if len(raw) < 12 || len(raw) > MaxCommitBytes || string(raw[:8]) != CommitMarker || binary.BigEndian.Uint16(raw[8:10]) != 2 {
		return b, errors.New("participation commit envelope")
	}
	count := int(binary.BigEndian.Uint16(raw[10:12]))
	if count == 0 || count > MaxPeriodCertificates {
		return b, errors.New("participation commit count")
	}
	offset := 12
	for i := 0; i < count; i++ {
		if len(raw)-offset < 2 {
			return CommitBatch{}, errors.New("participation commit truncated length")
		}
		n := int(binary.BigEndian.Uint16(raw[offset:]))
		offset += 2
		if n > MaxCertificateSize || n > len(raw)-offset {
			return CommitBatch{}, errors.New("participation commit certificate bound")
		}
		cert, err := DecodeCertificate(raw[offset : offset+n])
		if err != nil {
			return CommitBatch{}, err
		}
		b.Certificates = append(b.Certificates, cert)
		offset += n
	}
	encoded, err := b.Encode()
	if err != nil || offset != len(raw) || !bytes.Equal(encoded, raw) {
		return CommitBatch{}, errors.New("noncanonical participation commit")
	}
	return b, nil
}

func SortedCommitBatch(certificates []Certificate) (CommitBatch, error) {
	b := CommitBatch{Certificates: append([]Certificate(nil), certificates...)}
	for _, c := range b.Certificates {
		if _, err := c.Encode(); err != nil {
			return CommitBatch{}, err
		}
	}
	sort.Slice(b.Certificates, func(i, j int) bool {
		a, _ := b.Certificates[i].Duty.Hash()
		z, _ := b.Certificates[j].Duty.Hash()
		return bytes.Compare(a[:], z[:]) < 0
	})
	_, err := b.Encode()
	return b, err
}

type CommittedEntry struct {
	CommittedAt uint64
	Certificate []byte
}
type CommittedState struct {
	Version uint16
	Entries []CommittedEntry
}

func (r *Registry) ValidateCommitted(s *CommittedState, closed, height uint64) error {
	if s == nil || s.Version != 2 || s.Entries == nil || len(s.Entries) > MaxPendingCertificates {
		return errors.New("committed participation state bound")
	}
	var previous protocol.Hash
	counts := map[uint64]int{}
	for i, entry := range s.Entries {
		if len(entry.Certificate) > MaxCertificateSize {
			return errors.New("committed certificate byte bound")
		}
		c, err := DecodeCertificate(entry.Certificate)
		if err != nil {
			return err
		}
		h, _ := c.Duty.Hash()
		if i > 0 && bytes.Compare(previous[:], h[:]) >= 0 {
			return errors.New("committed participation state order")
		}
		previous = h
		period := c.Duty.Period
		if period <= closed || period-closed > 2 || period > (math.MaxUint64-GraceBlocks)/PeriodBlocks || entry.CommittedAt <= c.Duty.Height || entry.CommittedAt > height || entry.CommittedAt > period*PeriodBlocks+GraceBlocks {
			return errors.New("committed participation period/deadline")
		}
		counts[period]++
		if counts[period] > MaxPeriodCertificates {
			return errors.New("committed participation period capacity")
		}
	}
	// Check every structural/order/deadline bound before any BLS work.
	for _, entry := range s.Entries {
		c, _ := DecodeCertificate(entry.Certificate)
		if err := r.VerifyCertificate(c); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) Commit(s *CommittedState, closed, height uint64, batch CommitBatch) (*CommittedState, error) {
	if _, err := batch.Encode(); err != nil {
		return nil, err
	}
	if s == nil {
		s = &CommittedState{Version: 2, Entries: []CommittedEntry{}}
	}
	if err := r.ValidateCommitted(s, closed, height); err != nil {
		return nil, err
	}
	next := &CommittedState{Version: 2, Entries: make([]CommittedEntry, 0, len(s.Entries)+len(batch.Certificates))}
	seen := map[protocol.Hash]bool{}
	for _, entry := range s.Entries {
		c, _ := DecodeCertificate(entry.Certificate)
		h, _ := c.Duty.Hash()
		seen[h] = true
		next.Entries = append(next.Entries, CommittedEntry{entry.CommittedAt, bytes.Clone(entry.Certificate)})
	}
	for _, c := range batch.Certificates {
		if err := r.VerifyCertificate(c); err != nil {
			return nil, err
		}
		h, _ := c.Duty.Hash()
		if seen[h] {
			continue
		}
		seen[h] = true
		raw, _ := c.Encode()
		next.Entries = append(next.Entries, CommittedEntry{height, raw})
	}
	sort.Slice(next.Entries, func(i, j int) bool {
		a, _ := DecodeCertificate(next.Entries[i].Certificate)
		b, _ := DecodeCertificate(next.Entries[j].Certificate)
		x, _ := a.Duty.Hash()
		y, _ := b.Duty.Hash()
		return bytes.Compare(x[:], y[:]) < 0
	})
	if err := r.ValidateCommitted(next, closed, height); err != nil {
		return nil, err
	}
	return next, nil
}

// CheckCommittedClose depends only on the authenticated parent state and action.
// Local receipt delivery is deliberately not an input to consensus execution.
func (r *Registry) CheckCommittedClose(s *CommittedState, closed, height uint64, pkg ClosePackage) (Points, *CommittedState, error) {
	if s == nil {
		return Points{}, nil, ErrUncommittedPeriod
	}
	if pkg.Period != closed+1 || closed == math.MaxUint64 || pkg.Period > (math.MaxUint64-GraceBlocks)/PeriodBlocks || height < pkg.Period*PeriodBlocks+GraceBlocks {
		return Points{}, nil, errors.New("committed close period")
	}
	if err := r.ValidateCommitted(s, closed, height); err != nil {
		return Points{}, nil, err
	}
	if _, err := pkg.Encode(); err != nil {
		return Points{}, nil, err
	}
	_, canonical, err := r.compute(pkg.Period, pkg.Blocks, nil)
	if err != nil {
		return Points{}, nil, err
	}
	eligible := map[protocol.Hash]bool{}
	present := false
	next := &CommittedState{Version: 2, Entries: []CommittedEntry{}}
	for _, entry := range s.Entries {
		cert, _ := DecodeCertificate(entry.Certificate)
		if cert.Duty.Period != pkg.Period {
			next.Entries = append(next.Entries, CommittedEntry{entry.CommittedAt, bytes.Clone(entry.Certificate)})
			continue
		}
		present = true
		target, ok := canonical[cert.Duty.Height]
		if ok && target.proposal == cert.Duty.ProposalID && target.view == cert.Duty.View {
			h, _ := cert.Duty.Hash()
			eligible[h] = true
		}
	}
	if !present {
		return Points{}, nil, ErrUncommittedPeriod
	}
	if len(eligible) != len(pkg.Certificates) {
		return Points{}, nil, ErrCommittedOmission
	}
	for _, cert := range pkg.Certificates {
		h, err := cert.Duty.Hash()
		if err != nil || !eligible[h] {
			return Points{}, nil, ErrCommittedOmission
		}
		delete(eligible, h)
	}
	if len(eligible) != 0 {
		return Points{}, nil, ErrCommittedOmission
	}
	points, err := r.ComputePoints(pkg.Period, pkg.Blocks, pkg.Certificates)
	if err != nil {
		return Points{}, nil, err
	}
	return points, next, nil
}
