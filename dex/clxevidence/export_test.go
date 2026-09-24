package clxevidence

import "testing"

// EvidenceFixtureForTest exposes only unit-generated signed evidence to the
// external integration test; it is not part of the shipped evidence API.
func EvidenceFixtureForTest(t *testing.T) (Config, *Verifier, RangeEvidence) {
	f := testFixture(t)
	return f.config, f.v, clonedEvidence(t, f.evidence)
}
