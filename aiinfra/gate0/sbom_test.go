// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package gate0

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSPDXGenerationIsDeterministicAndClosed(t *testing.T) {
	input := SBOMInput{Name: "cypher-gate0", DocumentNamespace: "https://cypherium.io/spdx/gate0/0123456789abcdef",
		CreatedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), Creator: "Tool:cph-gate0-sbom-v1",
		Components: []SBOMComponent{
			{SPDXID: "SPDXRef-Package-z", Name: "z", Version: "v1.0.0", DownloadLocation: "NOASSERTION", SHA256: strings.Repeat("22", 32)},
			{SPDXID: "SPDXRef-Package-a", Name: "a", Version: "v2.0.0", DownloadLocation: "NOASSERTION", SHA256: strings.Repeat("11", 32)},
		}}
	first, err := GenerateSPDX(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Components[0], input.Components[1] = input.Components[1], input.Components[0]
	second, err := GenerateSPDX(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("component permutation changed deterministic SPDX")
	}
	document, err := VerifySPDX(first, input.DocumentNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Packages) != 2 || document.Packages[0].SPDXID != "SPDXRef-Package-a" {
		t.Fatalf("unexpected SPDX packages: %+v", document.Packages)
	}
	tampered := bytes.Replace(first, []byte(strings.Repeat("11", 32)), []byte(strings.Repeat("gg", 32)), 1)
	if _, err := VerifySPDX(tampered, input.DocumentNamespace); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("tampered SPDX error=%v", err)
	}
	withUnknown := append(first[:len(first)-1], []byte(`,"unknown":true}`)...)
	if _, err := VerifySPDX(withUnknown, input.DocumentNamespace); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("unknown SPDX field error=%v", err)
	}
}
