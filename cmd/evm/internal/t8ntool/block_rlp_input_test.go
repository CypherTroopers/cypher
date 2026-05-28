package t8ntool

import (
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestB11RReadRLPHexFileAcceptsJSONString(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "txs.rlp")
	if err := ioutil.WriteFile(file, []byte(`"0xc0"`), 0644); err != nil {
		t.Fatalf("failed to write txs file: %v", err)
	}
	got, err := readRLPHexFile(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "0xc0" {
		t.Fatalf("got %q", got)
	}
}

func TestB11RReadRLPHexFileAcceptsRawHex(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "txs.rlp")
	if err := ioutil.WriteFile(file, []byte("0xc0\n"), 0644); err != nil {
		t.Fatalf("failed to write txs file: %v", err)
	}
	got, err := readRLPHexFile(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "0xc0" {
		t.Fatalf("got %q", got)
	}
}

func TestB11RReadRLPHexFileRejectsMissingPrefix(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "txs.rlp")
	if err := ioutil.WriteFile(file, []byte("c0"), 0644); err != nil {
		t.Fatalf("failed to write txs file: %v", err)
	}
	if _, err := readRLPHexFile(file); err == nil {
		t.Fatalf("expected missing 0x prefix error")
	}
}
