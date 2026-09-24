package main

import (
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/dex/service"
)

func TestLeaderSubmissionBindsOwnManifestAndSeparateGasKeys(t *testing.T) {
	r, root := relayCLIFixture(t)
	m := service.Manifest{Mode: "native-finance", Domain: r.Domain, DataDir: filepath.Join(root, "dex"), APIListen: "127.0.0.1:9999", MaxHeight: r.MaxHeight, LeaderSubmission: filepath.Join(root, "submission.json"), Finance: &service.NativeConfig{CLX: r.CLX}}
	r.DataDir, r.DEXURL = filepath.Join(m.DataDir, "submission"), "http://"+m.APIListen
	for i := range r.Payers {
		r.Payers[i].Purpose = "leader-submission-gas"
	}
	if _, err := r.config(); err != nil {
		t.Fatal(err)
	}
	if err := validateLeaderSubmission(m, r); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*relayCLIManifest)
	}{
		{"foreign-domain", func(v *relayCLIManifest) { v.Domain.DEXID[0] ^= 1 }},
		{"shared-journal", func(v *relayCLIManifest) { v.DataDir = filepath.Join(root, "shared") }},
		{"foreign-node-api", func(v *relayCLIManifest) { v.DEXURL = "http://127.0.0.1:9998" }},
		{"different-height-cap", func(v *relayCLIManifest) { v.MaxHeight-- }},
		{"self-declared-source", func(v *relayCLIManifest) { v.CLX.Seed[0] ^= 1 }},
		{"legacy-relay-key-purpose", func(v *relayCLIManifest) { v.Payers[0].Purpose = "relay-gas" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := r
			bad.Payers = append([]relayCLIPayer(nil), r.Payers...)
			tc.edit(&bad)
			if err := validateLeaderSubmission(m, bad); err == nil {
				t.Fatal("unsafe submission configuration accepted")
			}
		})
	}
}
