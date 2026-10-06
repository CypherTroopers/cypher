package reconfig

import (
	"testing"
	"time"
)

func TestNativeExecutionLeaseCoversCriticalAndAggregateCompute(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	// The Solana-scale envelope has a 64-second critical path, but its total
	// compute divided over the protocol's 64 reference workers takes 256
	// seconds and must therefore determine the deadline.
	if got, want := nativeExecutionLeaseForConfig(config), 256*time.Second; got != want {
		t.Fatalf("native execution lease = %s, want %s", got, want)
	}

	config.NativeParallel.MaxCriticalPathCompute = 300 * nativeValidationComputePerSecond
	if got, want := nativeExecutionLeaseForConfig(config), 300*time.Second; got != want {
		t.Fatalf("critical-path execution lease = %s, want %s", got, want)
	}
	config.NativeParallel.MaxCriticalPathCompute = 1
	config.NativeParallel.MaxComputePerBlock = 1
	if got := nativeExecutionLeaseForConfig(config); got != nativePaceMakerExecutionMinimum {
		t.Fatalf("minimum execution lease = %s, want %s", got, nativePaceMakerExecutionMinimum)
	}
}

func TestNativePaceMakerTimeoutIncludesExecutionEnvelope(t *testing.T) {
	config := nativeProposalLimitTestConfig()
	want := addDurationSaturating(
		proposalBodyWaitTimeoutForConfig(config, config.EffectiveMaxBlockBytes()),
		proposalRepairWaitTimeoutForConfig(config, int(config.NativeParallel.MaxTransactionsPerBlock)),
	)
	want = addDurationSaturating(want, nativeExecutionLeaseForConfig(config))
	if got := paceMakerTimeoutForConfig(config); got != want {
		t.Fatalf("native pacemaker timeout = %s, want complete body+repair+execution %s", got, want)
	}
}
