package reconfig_test

import (
	"errors"
	"math/big"
	"testing"
	"time"
)

const continuousRenewalSpacing = 2 * time.Minute
const continuousRenewalLimit = 14 * time.Minute
const continuousRenewalCarriers = 7

type continuousRenewalSchedule struct {
	hard, next, observed time.Time
	carriers             int
}

func (s *continuousRenewalSchedule) observe(now time.Time, bothVerifiedV2 bool) (send, done bool, err error) {
	if now.Before(s.observed) {
		return false, false, errors.New("renewal scheduling clock regression")
	}
	if !now.Before(s.hard) {
		return false, false, errors.New("normal CLX key-renewal scheduling deadline")
	}
	s.observed = now
	if bothVerifiedV2 {
		return false, true, nil
	}
	if s.carriers < continuousRenewalCarriers && !now.Before(s.next) {
		s.carriers++
		s.next = now.Add(continuousRenewalSpacing)
		return true, false, nil
	}
	return false, false, nil
}

// The relay's verified-source projection schedules inputs only. It is never
// installed in DEX/CLX state; CDXA must verify actual evidence independently.
func (f *continuousFixture) verifiedRenewalHint(t *testing.T) bool {
	t.Helper()
	statuses := f.relayStatuses(t)
	if len(statuses) != 2 {
		t.Fatal("renewal fixture requires two independent relay observers")
	}
	ready := true
	for _, s := range statuses {
		if s.Version == 0 { // no persisted observation yet; not an authenticated hint
			ready = false
			continue
		}
		a := s.Authenticated.SourceAnchor
		if s.Version != 1 || !s.Devnet || a.Validate() != nil || a.ChainID != f.init.Domain.ChainID || a.Genesis != f.init.Domain.Genesis || a.DEXID != f.init.Domain.DEXID || a.Custody != f.init.Market.Custody || a.SourceEpoch != 1 {
			t.Fatal("renewal scheduling source identity/shape mismatch")
		}
		ready = ready && a.Version == 2
	}
	return ready
}

func (f *continuousFixture) waitNormalKeyRenewal(t *testing.T) {
	t.Helper()
	now := time.Now()
	hard := now.Add(continuousRenewalLimit)
	if parent := continuousParentBound(t); parent.Before(hard) {
		hard = parent
	}
	s := continuousRenewalSchedule{hard: hard, next: now, observed: now}
	before := f.observeCLX(t).Header.Number.Uint64()
	t.Logf("CONTINUOUS_RENEWAL_SCHEDULE_START CLX=%d maxCarriers=%d spacing=%s hard=%s hintNotAuthority=true normalKeyClockUnchanged=true", before, continuousRenewalCarriers, continuousRenewalSpacing, hard.UTC().Format(time.RFC3339Nano))
	for {
		hint := f.verifiedRenewalHint(t)
		send, done, err := s.observe(time.Now(), hint)
		if err != nil {
			t.Fatalf("%s carriers=%d CLX=%d hintNotAuthority=true", err, s.carriers, f.ledger.scanned)
		}
		if done {
			after := f.observeCLX(t).Header.Number.Uint64()
			t.Logf("CONTINUOUS_RENEWAL_SCHEDULE_DONE before=%d after=%d carriers=%d elapsed=%s verifiedRelaySourcesV2=true hintNotAuthority=true", before, after, s.carriers, time.Since(now))
			return
		}
		if send {
			f.send(t, 2, f.owners[2], new(big.Int), nil, 21000)
			t.Logf("CONTINUOUS_RENEWAL_CARRIER number=%d CLX=%d maximum=%d", s.carriers, f.ledger.scanned, continuousRenewalCarriers)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestContinuousNormalRenewalSchedule(t *testing.T) {
	start := time.Unix(1000, 0)
	newSchedule := func() continuousRenewalSchedule {
		return continuousRenewalSchedule{hard: start.Add(continuousRenewalLimit), next: start, observed: start}
	}
	t.Run("missing_hint_spacing_and_seven_carrier_cap", func(t *testing.T) {
		s := newSchedule()
		count := 0
		for seconds := 0; seconds < 14*60; seconds++ {
			send, done, err := s.observe(start.Add(time.Duration(seconds)*time.Second), false)
			if err != nil || done {
				t.Fatal(done, err)
			}
			if send {
				if seconds != count*120 {
					t.Fatal("carrier spacing", seconds)
				}
				count++
			}
		}
		if count != 7 {
			t.Fatal(count)
		}
		if _, done, err := s.observe(s.hard, true); err == nil || done {
			t.Fatal("late hint revived expired schedule")
		}
	})
	t.Run("both_verified_sources_skip_unneeded_carriers", func(t *testing.T) {
		s := newSchedule()
		if send, done, err := s.observe(start, true); err != nil || send || !done || s.carriers != 0 {
			t.Fatal(send, done, err)
		}
	})
	t.Run("delayed_poll_does_not_burst_catchup_transfers", func(t *testing.T) {
		s := newSchedule()
		if send, _, err := s.observe(start.Add(5*time.Minute), false); !send || err != nil {
			t.Fatal(send, err)
		}
		if send, _, err := s.observe(start.Add(5*time.Minute), false); send || err != nil || s.carriers != 1 {
			t.Fatal(send, err)
		}
	})
	t.Run("earlier_parent_hard_bound", func(t *testing.T) {
		s := newSchedule()
		s.hard = start.Add(time.Minute)
		if _, done, err := s.observe(s.hard, true); err == nil || done {
			t.Fatal("parent deadline ignored")
		}
	})
	t.Run("clock_regression", func(t *testing.T) {
		s := newSchedule()
		if _, _, err := s.observe(start.Add(-time.Second), false); err == nil {
			t.Fatal("clock regression accepted")
		}
	})
}
