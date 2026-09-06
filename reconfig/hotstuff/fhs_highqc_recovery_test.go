package hotstuff

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
)

func TestFHSHighQCDataTimeoutRetainsAuthenticatedContinuation(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	msg := fixture.newViewMessage(t, 12, nil, qc)
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView result = %v", err)
	}
	request := fixture.async.highScheduled[0]
	dataErr := fmt.Errorf("proposal body timeout: %w", ErrProposalDataUnavailable)
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key, Err: dataErr}); !errors.Is(err, ErrProposalDataUnavailable) {
		t.Fatalf("body timeout result = %v", err)
	}
	pending := fixture.manager.pendingHighQC
	if pending == nil || !SignedStateSemanticEqual(pending.qc, qc) || len(pending.messages) != 1 || !sameFHSPrepare(pending.messages[0], msg) {
		t.Fatalf("body timeout discarded verified QC or authenticated continuation: pending=%#v", pending)
	}
	if len(fixture.async.highApplied) != 0 || len(fixture.async.highScheduled) != 1 {
		t.Fatalf("body timeout applied or immediately retried validation: applied=%d scheduled=%d", len(fixture.async.highApplied), len(fixture.async.highScheduled))
	}
	tick := &HotstuffMessage{Code: MsgTimer, Number: fixture.async.current}
	if err := fixture.manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	if len(fixture.async.highScheduled) != 1 {
		t.Fatal("timer retried before the recovery interval")
	}
	// Even a duplicate successful completion cannot install the timed-out job.
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); !errors.Is(err, ErrOldState) {
		t.Fatalf("late timed-out completion = %v", err)
	}
	pending.retryAt = time.Now().Add(-time.Second)
	if err := fixture.manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	if len(fixture.async.highScheduled) != 2 {
		t.Fatalf("timer schedules = %d, want 2 without another network QC", len(fixture.async.highScheduled))
	}
	retry := fixture.async.highScheduled[1]
	if retry.Key == request.Key || retry.Key.QCID != request.Key.QCID || retry.Key.TargetView != request.Key.TargetView || !SignedStateSemanticEqual(retry.QC, qc) {
		t.Fatalf("retry changed the certificate or reused the old attempt: first=%#v retry=%#v", request, retry)
	}
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("duplicate authenticated NewView = %v", err)
	}
	if err := fixture.manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	if len(fixture.async.highScheduled) != 2 || len(fixture.manager.pendingHighQC.messages) != 1 {
		t.Fatal("active retry did not coalesce duplicate continuations or timer ticks")
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: request.Key}); !errors.Is(err, ErrOldState) {
		t.Fatalf("superseded attempt completion = %v", err)
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: retry.Key}); err != nil {
		t.Fatalf("healed data retry = %v", err)
	}
	view := fixture.manager.views[msg.ViewId]
	if view == nil || len(view.fhsReports) != 1 || view.fhsReports[0] == nil || fixture.manager.pendingHighQC != nil {
		t.Fatalf("healed retry did not resume authenticated NewView: view=%#v pending=%#v", view, fixture.manager.pendingHighQC)
	}
}

func newFHSDataTimeoutFixture(t *testing.T) (*fhsAsyncValidationFixture, *HotstuffMessage, FHSHighQCValidationKey) {
	t.Helper()
	fixture := newFHSAsyncValidationFixture(t)
	msg := fixture.newViewMessage(t, 12, nil, fixture.parentQC(t, 11, true))
	if err := fixture.manager.HandleMessage(msg); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial NewView = %v", err)
	}
	key := fixture.async.highScheduled[0].Key
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: key, Err: ErrProposalDataUnavailable}); !errors.Is(err, ErrProposalDataUnavailable) {
		t.Fatalf("data timeout = %v", err)
	}
	if fixture.manager.pendingHighQC == nil {
		t.Fatal("data timeout discarded pending validation")
	}
	fixture.manager.pendingHighQC.retryAt = time.Now().Add(-time.Second)
	return fixture, msg, key
}

func TestFHSHighQCDataRetrySchedulerBackpressureIsBounded(t *testing.T) {
	for _, schedulerErr := range []error{ErrOldState, ErrProposalValidationPending, ErrProposalDataUnavailable} {
		t.Run(schedulerErr.Error(), func(t *testing.T) {
			fixture, msg, original := newFHSDataTimeoutFixture(t)
			fixture.async.highScheduleErr = schedulerErr
			tick := &HotstuffMessage{Code: MsgTimer, Number: fixture.async.current}
			if err := fixture.manager.HandleMessage(tick); !errors.Is(err, schedulerErr) {
				t.Fatalf("backpressured timer = %v", err)
			}
			pending := fixture.manager.pendingHighQC
			if pending == nil || pending.key != original || len(pending.messages) != 1 || !sameFHSPrepare(pending.messages[0], msg) || !pending.retryAt.After(time.Now()) {
				t.Fatalf("backpressure lost or immediately rearmed pending validation: %#v", pending)
			}
			sequence := fixture.manager.validationSequence
			if err := fixture.manager.HandleMessage(tick); err != nil || fixture.manager.validationSequence != sequence {
				t.Fatalf("immediate timer retried scheduler: err=%v sequence=%d", err, fixture.manager.validationSequence)
			}
			fixture.async.highScheduleErr = nil
			pending.retryAt = time.Now().Add(-time.Second)
			if err := fixture.manager.HandleMessage(tick); err != nil || len(fixture.async.highScheduled) != 2 {
				t.Fatalf("scheduler recovery = %v, jobs=%d", err, len(fixture.async.highScheduled))
			}
		})
	}
}

func TestFHSHighQCDataRetryDuringDeferredStartup(t *testing.T) {
	fixture := newFHSAsyncValidationFixture(t)
	qc := fixture.parentQC(t, 11, true)
	if err := fixture.manager.RecoverFHSHighQC(qc, 12); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("initial startup recovery = %v", err)
	}
	first := fixture.async.highScheduled[0]
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: first.Key, Err: ErrProposalDataUnavailable}); !errors.Is(err, ErrProposalDataUnavailable) {
		t.Fatalf("startup data timeout = %v", err)
	}
	// Deferred startup suppresses MsgTimer. Its recovery wake must remain
	// armed until a worker is active, without retrying before the interval.
	if err := fixture.manager.RecoverFHSHighQC(qc, 12); !errors.Is(err, ErrProposalDataUnavailable) {
		t.Fatalf("dormant startup recovery = %v, want retryable data error", err)
	}
	if len(fixture.async.highScheduled) != 1 {
		t.Fatal("startup wake retried before the recovery interval")
	}
	fixture.manager.pendingHighQC.retryAt = time.Now().Add(-time.Second)
	fixture.async.highScheduleErr = ErrProposalValidationPending
	if err := fixture.manager.RecoverFHSHighQC(qc, 12); !errors.Is(err, ErrProposalDataUnavailable) {
		t.Fatalf("backpressured startup recovery = %v, want retryable data error", err)
	}
	fixture.async.highScheduleErr = nil
	fixture.manager.pendingHighQC.retryAt = time.Now().Add(-time.Second)
	if err := fixture.manager.RecoverFHSHighQC(qc, 12); !errors.Is(err, ErrProposalValidationPending) {
		t.Fatalf("due startup recovery = %v", err)
	}
	if len(fixture.async.highScheduled) != 2 || fixture.async.highScheduled[1].Key == first.Key || !SignedStateSemanticEqual(fixture.async.highScheduled[1].QC, qc) {
		t.Fatal("startup wake did not reschedule the exact certificate with a fresh attempt")
	}
	if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: fixture.async.highScheduled[1].Key}); err != nil {
		t.Fatalf("healed startup recovery = %v", err)
	}
	if fixture.manager.pendingHighQC != nil || !SignedStateSemanticEqual(fixture.async.highest, qc) {
		t.Fatal("startup retry did not install the durable certificate")
	}
}

func TestFHSHighQCDataRetryDoesNotCrossEpochOrSupersession(t *testing.T) {
	t.Run("epoch", func(t *testing.T) {
		fixture, _, oldKey := newFHSDataTimeoutFixture(t)
		fixture.manager.ScheduleFHSEpochReset()
		if err := fixture.manager.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: fixture.async.current}); err != nil {
			t.Fatal(err)
		}
		if fixture.manager.pendingHighQC != nil || len(fixture.async.highScheduled) != 1 {
			t.Fatal("timer retried a previous epoch's certificate")
		}
		if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: oldKey}); !errors.Is(err, ErrOldState) || len(fixture.async.highApplied) != 0 {
			t.Fatalf("old epoch completion applied: %v", err)
		}
	})
	t.Run("higher QC", func(t *testing.T) {
		fixture, msg, oldKey := newFHSDataTimeoutFixture(t)
		newQC := fixture.parentQC(t, 12, true)
		if err := fixture.manager.scheduleFHSHighQCCatchup(newQC, 13, nil, common.Hash{}); !errors.Is(err, ErrProposalValidationPending) {
			t.Fatalf("higher QC = %v", err)
		}
		pending := fixture.manager.pendingHighQC
		if pending == nil || pending.key == oldKey || !pending.retryAt.IsZero() || len(pending.messages) != 1 || !sameFHSPrepare(pending.messages[0], msg) {
			t.Fatalf("newer QC did not supersede delayed work and retain continuation: %#v", pending)
		}
		if err := fixture.manager.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: fixture.async.current}); err != nil || len(fixture.async.highScheduled) != 2 {
			t.Fatalf("timer revived superseded QC: err=%v jobs=%d", err, len(fixture.async.highScheduled))
		}
		if err := fixture.manager.HandleFHSHighQCValidationResult(&FHSHighQCValidationResult{Key: oldKey}); !errors.Is(err, ErrOldState) || len(fixture.async.highApplied) != 0 {
			t.Fatalf("superseded completion applied: %v", err)
		}
	})
}

func TestFHSHighQCDataRetryPermanentFailureStopsTimerRetries(t *testing.T) {
	for _, stage := range []string{"worker", "scheduler", "apply"} {
		t.Run(stage, func(t *testing.T) {
			fixture, _, _ := newFHSDataTimeoutFixture(t)
			permanentErr := errors.New("invalid proposal proof")
			tick := &HotstuffMessage{Code: MsgTimer, Number: fixture.async.current}
			if stage == "scheduler" {
				fixture.async.highScheduleErr = permanentErr
				if err := fixture.manager.HandleMessage(tick); !errors.Is(err, permanentErr) {
					t.Fatalf("permanent scheduler error = %v", err)
				}
			} else {
				if err := fixture.manager.HandleMessage(tick); err != nil {
					t.Fatal(err)
				}
				result := &FHSHighQCValidationResult{Key: fixture.async.highScheduled[1].Key}
				wantErr := permanentErr
				if stage == "worker" {
					result.Err = permanentErr
				} else {
					fixture.async.highApplyErr = permanentErr
					wantErr = ErrInvalidHighQC
				}
				if err := fixture.manager.HandleFHSHighQCValidationResult(result); !errors.Is(err, wantErr) {
					t.Fatalf("permanent completion error = %v", err)
				}
			}
			jobs := len(fixture.async.highScheduled)
			if fixture.manager.pendingHighQC != nil {
				t.Fatal("permanent error retained retry work")
			}
			if err := fixture.manager.HandleMessage(tick); err != nil || len(fixture.async.highScheduled) != jobs {
				t.Fatalf("permanent error retried: err=%v jobs=%d", err, len(fixture.async.highScheduled))
			}
		})
	}
}
