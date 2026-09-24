package consensus

import (
	"errors"
	"math"

	"github.com/cypherium/cypher/dex/checkpoint"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

const MaxWireBytes = 128 * 1024

func certificateShape(sign, mask []byte) error {
	if len(sign) == 0 || len(sign) > 128 {
		return errors.New("invalid DEX certificate signature size")
	}
	return hotstuff.ValidateCanonicalSignerMask(mask, 7, 5)
}
func qcShape(q *hotstuff.SignedState) error {
	if q == nil {
		return nil
	}
	if len(q.State) == 0 || len(q.State) > checkpoint.MaxRefBytes || q.Number == 0 || q.Number == math.MaxUint64 || len(q.LeaderID) == 0 || len(q.LeaderID) > 128 {
		return errors.New("invalid DEX QC shape")
	}
	return certificateShape(q.Sign, q.Mask)
}
func timeoutShape(t *hotstuff.TimeoutCertificate) error {
	if t == nil {
		return nil
	}
	if err := certificateShape(t.Sign, t.Mask); err != nil {
		return err
	}
	_, err := hotstuff.TimeoutStatementDigest(&t.Statement)
	return err
}

// DEX ingress rejects missing C-library inputs and oversized nested collections
// before the legacy FHS manager can enter cryptography. No network peer may send
// an internal timer/timeout/build control message through this entry point.
func validateDEXWire(m *hotstuff.HotstuffMessage) error {
	if err := hotstuff.ValidateHotstuffWireMessage(m); err != nil {
		return err
	}
	if len(m.Id) > 128 || len(m.AuthSig) == 0 || len(m.AuthSig) > 128 {
		return errors.New("invalid DEX wire authentication shape")
	}
	total := len(m.Id) + len(m.AuthSig) + len(m.PubKey)
	for _, b := range [][]byte{m.DataA, m.DataB, m.DataC, m.DataD, m.DataE, m.DataF, m.DataG} {
		total += len(b)
	}
	if total > MaxWireBytes {
		return errors.New("DEX wire byte limit")
	}
	switch m.Code {
	case hotstuff.MsgDecide:
		return errors.New("legacy Decide is disabled in the DEX FHS domain")
	case hotstuff.MsgVotePrepare:
		if len(m.DataB) != 0 || len(m.DataC) == 0 || len(m.DataC) > 128 {
			return errors.New("invalid DEX prepare-vote signature shape")
		}
	case hotstuff.MsgNewView:
		if len(m.DataB) == 0 || len(m.DataB) > 128 {
			return errors.New("invalid NewView signature size")
		}
		r, err := hotstuff.DecodeNewViewReport(m.DataA)
		if err != nil {
			return err
		}
		if err = qcShape(r.HighQC); err != nil {
			return err
		}
		t, err := hotstuff.DecodeTimeoutCertificate(m.DataD)
		if err != nil {
			return err
		}
		return timeoutShape(t)
	case hotstuff.MsgPrepare:
		a, err := hotstuff.DecodeAggregateQC(m.DataC)
		if err != nil {
			return err
		}
		if len(a.Reports) < 5 || len(a.Reports) > 7 {
			return errors.New("DEX NewView report bound")
		}
		if err = certificateShape(a.Sign, a.Mask); err != nil {
			return err
		}
		for _, r := range a.Reports {
			if err = qcShape(r.HighQC); err != nil {
				return err
			}
		}
		t, err := hotstuff.DecodeTimeoutCertificate(m.DataD)
		if err != nil {
			return err
		}
		if err = timeoutShape(t); err != nil {
			return err
		}
		q, err := hotstuff.DecodeSignedState(m.DataG)
		if err != nil {
			return err
		}
		return qcShape(q)
	case hotstuff.MsgTimeout:
		if len(m.DataB) == 0 || len(m.DataB) > 128 {
			return errors.New("invalid timeout vote signature size")
		}
	case hotstuff.MsgTimeoutQC, hotstuff.MsgQCBroadcast:
		return certificateShape(m.DataB, m.DataC)
	}
	return nil
}
