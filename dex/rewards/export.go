package rewards

import (
	"bytes"
	"sort"
)

// Certificates returns owned canonical copies of durably acknowledged records.
// Height zero selects all retained certificates, within the collector WAL bound.
// It does not turn a receipt, current membership or wall-clock time into points.
func (c *Collector) Certificates(height uint64) ([]Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return nil, err
	}
	var out []Certificate
	for _, raw := range c.disk.Certificates {
		cert, err := DecodeCertificate(raw)
		if err != nil {
			return nil, err
		}
		if height == 0 || cert.Duty.Height == height {
			out = append(out, cert)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Duty, out[j].Duty
		if a.Height != b.Height {
			return a.Height < b.Height
		}
		if a.Participant != b.Participant {
			return a.Participant < b.Participant
		}
		if a.View != b.View {
			return a.View < b.View
		}
		return bytes.Compare(a.ProposalID[:], b.ProposalID[:]) < 0
	})
	return out, nil
}
