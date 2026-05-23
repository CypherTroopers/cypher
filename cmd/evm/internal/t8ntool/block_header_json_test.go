package t8ntool

import (
	"encoding/json"
	"testing"
)

func TestParseB11RUint64AcceptsHexString(t *testing.T) {
	got, err := parseB11RUint64(json.RawMessage(`"0x5208"`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0x5208 {
		t.Fatalf("got %d", got)
	}
}

func TestParseB11RUint64AcceptsJSONNumber(t *testing.T) {
	got, err := parseB11RUint64(json.RawMessage(`21000`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 21000 {
		t.Fatalf("got %d", got)
	}
}

func TestB11RToBlockRejectsMissingHeader(t *testing.T) {
	if _, err := (&bbInput{}).ToBlock(); err == nil {
		t.Fatalf("expected missing header error")
	}
}
