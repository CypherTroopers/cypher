package data

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cypherium/cypher/dex/protocol"
)

func TestRetainRestartMissingCorruptAndBounds(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dex-only")
	s, err := Open(root, 2, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("canonical replay data fixture")
	id, err := s.Put(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.Put(raw); err != nil || again != id {
		t.Fatal("idempotent put", err)
	}
	s, err = Open(root, 2, 64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(id)
	if err != nil || string(got) != string(raw) {
		t.Fatal("restart retrieval", err)
	}
	if _, err := s.Get(protocol.Hash{9}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing root is not availability", err)
	}
	if _, err := s.Put(make([]byte, MaxItemBytes+1)); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if _, err := s.Put(make([]byte, 65)); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if _, err := s.Put([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put([]byte("third")); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%x", id)), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrMismatch) {
		t.Fatal("corrupt data accepted", err)
	}
}

func TestRefuseExistingOperationalDirectoryAndSymlinks(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root, 2, 64); err == nil {
		t.Fatal("unmarked directory adopted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, 2, 64); err == nil {
		t.Fatal("symlink directory accepted")
	}
}
