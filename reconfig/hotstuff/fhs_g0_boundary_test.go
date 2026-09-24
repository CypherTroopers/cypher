package hotstuff

import (
	"errors"
	"testing"
	"time"
)

// Manager-boundary test: content validation is represented by its existing
// asynchronous result interface. Actual body reconstruction/tampering checks
// remain covered by reconfig proposal repair tests and the seven-process test.
func TestG0EarlyQCContentFailureBoundaries(t *testing.T) {
	for _, mode := range []string{"missing-body-retry", "invalid-body"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newFHSAsyncValidationFixture(t)
			app := &earlyQCApplication{fhsAsyncValidationApp: fixture.async, leaderKey: fixture.keys[3]}
			fixture.manager.app = app
			if err := fixture.manager.newFHSNewView(); err != nil {
				t.Fatal(err)
			}
			ref, _ := fixture.prepare(t)
			state := ref.EncodeToBytes()
			msg := &HotstuffMessage{Code: MsgQCBroadcast, Number: ref.ViewNumber, ViewId: ref.ViewID,
				DataB: aggregateContextSignatures(t, fixture.secrets, []int{0, 1, 2}, app.ChainID(), MsgVotePrepare, ref.ViewID, ref.LeaderID, state),
				DataC: []byte{7}, DataD: state}
			fixture.authenticate(t, 3, msg)
			certified := 0
			app.onCertified = func(*SignedState) error { certified++; return nil }
			for i := 0; i < 16; i++ {
				if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
					t.Fatal("early duplicate QC result", err)
				}
			}
			if len(app.highScheduled) != 1 || len(app.highApplied) != 0 || certified != 0 || len(app.persisted) != 0 || fixture.manager.pendingHighQC == nil || len(fixture.manager.pendingHighQC.messages) != 1 {
				t.Fatal("duplicate QC bypassed/coarsened content validation or expanded worker queue")
			}
			first := app.highScheduled[0].Key
			bodyErr := ErrProposalDataUnavailable
			if mode == "invalid-body" {
				bodyErr = errors.New("G0 validated body hash/state mismatch")
			}
			if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: first, Err: bodyErr}); !errors.Is(err, bodyErr) {
				t.Fatal("body validation error not preserved", err)
			}
			if len(app.highApplied) != 0 || certified != 0 || len(app.persisted) != 0 {
				t.Fatal("failed content was applied/certified/voted")
			}
			if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: first}); !errors.Is(err, ErrOldState) {
				t.Fatal("stale completion after failed body accepted", err)
			}
			tick := &HotstuffMessage{Code: MsgTimer, Number: app.current}
			if mode == "invalid-body" {
				if fixture.manager.pendingHighQC != nil {
					t.Fatal("hard-invalid body retained retry")
				}
				if err := fixture.manager.HandleMessage(tick); err != nil {
					t.Fatal(err)
				}
				if len(app.highScheduled) != 1 || len(app.highApplied) != 0 || certified != 0 {
					t.Fatal("timer retried or certified hard-invalid content")
				}
				return
			}
			if fixture.manager.pendingHighQC == nil {
				t.Fatal("missing data discarded authenticated QC")
			}
			fixture.manager.pendingHighQC.retryAt = time.Now().Add(-time.Second)
			if err := fixture.manager.HandleMessage(tick); err != nil {
				t.Fatal(err)
			}
			if len(app.highScheduled) != 2 || app.highScheduled[1].Key == first {
				t.Fatal("retry did not allocate one new validation attempt")
			}
			second := app.highScheduled[1].Key
			if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: second}); err != nil {
				t.Fatal(err)
			}
			if len(app.highApplied) != 1 || certified != 1 || len(app.persisted) != 0 || fixture.manager.pendingHighQC != nil {
				t.Fatal("healed content did not certify once without local vote")
			}
			if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: second}); !errors.Is(err, ErrOldState) {
				t.Fatal("duplicate content completion accepted", err)
			}
			if len(app.highApplied) != 1 || certified != 1 {
				t.Fatal("duplicate completion repeated effects")
			}
		})
	}
}
