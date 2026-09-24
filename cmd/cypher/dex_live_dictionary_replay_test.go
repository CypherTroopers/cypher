package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
)

// Independent semantic decoder for test comparison only. Production Open still
// verifies checksums, certificates, execution, archived finality and own votes.
func publicGenerationSemantics(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var env struct{ Payload map[string]interface{} }
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	s := env.Payload
	version, ok := s["Version"].(float64)
	if !ok || version != 4 && version != 5 {
		t.Fatal("public generation encoding version")
	}
	if version == 5 {
		records := s["Records"].(map[string]interface{})
		for _, pair := range [][3]string{{"Actions", "ActionDictionary", "ActionRefs"}, {"State", "StateDictionary", "StateRefs"}} {
			dictionary := s[pair[1]].([]interface{})
			refs := s[pair[2]].(map[string]interface{})
			for key, value := range records {
				i, present := refs[key].(float64)
				if !present || i != float64(int(i)) || i < 0 || int(i) >= len(dictionary) {
					t.Fatal("test semantic dictionary reference")
				}
				value.(map[string]interface{})[pair[0]] = dictionary[int(i)]
			}
			delete(s, pair[1])
			delete(s, pair[2])
		}
		s["Version"] = float64(4)
	}
	return s
}

func TestDEXCurrentPublicGenerationDictionaryColdReplayCopies(t *testing.T) {
	root := os.Getenv("CYPHER_DEX_PUBLIC_DICTIONARY_REPLAY_DIR")
	if root == "" {
		t.Skip("explicit current public WAL copy replay required")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute manifest root required")
	}
	for _, name := range []string{"cyphermine", "cypherdex1", "cypherdex2", "cypherdex3", "cypherdex4", "cypherdex5", "cypherdex6"} {
		t.Run(name, func(t *testing.T) {
			m, err := service.LoadManifest(filepath.Join(root, "manifests", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			original := m.DataDir
			m.DataDir = filepath.Join(t.TempDir(), "dex")
			for _, dir := range []string{"fhs/history", "participation"} {
				if err := os.MkdirAll(filepath.Join(m.DataDir, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			pointer, err := os.ReadFile(filepath.Join(original, "fhs/CURRENT"))
			if err != nil {
				t.Fatal(err)
			}
			var current struct{ Payload struct{ Generation uint64 } }
			if err = json.Unmarshal(pointer, &current); err != nil {
				t.Fatal(err)
			}
			stateName := fmt.Sprintf("state-%020d.json", current.Payload.Generation)
			paths := []string{"DEX_SIDECAR", "fhs/DEVNET", "fhs/CURRENT", "fhs/" + stateName}
			for _, dir := range []string{"participation", "fhs/history"} {
				entries, err := os.ReadDir(filepath.Join(original, dir))
				if err != nil || len(entries) > 4096 {
					t.Fatal("bounded public directory", dir, err)
				}
				for _, entry := range entries {
					n := entry.Name()
					if dir == "participation" && (n == "OWNER" || n == "state.json" || strings.HasPrefix(n, "period-") && strings.HasSuffix(n, ".json")) || dir == "fhs/history" && strings.HasPrefix(n, "archive-") && strings.HasSuffix(n, ".json") {
						paths = append(paths, filepath.Join(dir, n))
					}
				}
			}
			var source []byte
			var total int
			hashes := map[string][32]byte{}
			for _, rel := range paths {
				path := filepath.Join(original, rel)
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
					t.Fatal("bounded regular public file", rel, err)
				}
				raw, err := os.ReadFile(path)
				if err != nil || len(raw) > 2<<20 {
					t.Fatal("bounded public read", rel, err)
				}
				total += len(raw)
				if total > 256<<20 {
					t.Fatal("public copy total budget")
				}
				hashes[rel] = sha256.Sum256(raw)
				if err = os.WriteFile(filepath.Join(m.DataDir, rel), raw, 0600); err != nil {
					t.Fatal(err)
				}
				if rel == "fhs/"+stateName {
					source = raw
				}
			}
			// Capture a coherent public snapshot without stopping or opening any
			// live DB writable. Root controls all live lifecycle operations.
			for rel, want := range hashes {
				raw, err := os.ReadFile(filepath.Join(original, rel))
				if err != nil || sha256.Sum256(raw) != want {
					t.Fatal("public files changed during copy", rel, err)
				}
			}
			before := publicGenerationSemantics(t, source)
			var recovered []byte
			for cold := 0; cold < 2; cold++ {
				instance, err := finance.OpenManifest(m)
				if err != nil {
					t.Fatal("authenticated current financial Open", cold, err)
				}
				if err = instance.Close(); err != nil {
					t.Fatal(err)
				} // Deliberately never Start.
				recovered, err = os.ReadFile(filepath.Join(m.DataDir, "fhs", stateName))
				if err != nil {
					t.Fatal(err)
				}
				if len(recovered) > 2<<20 || !reflect.DeepEqual(before, publicGenerationSemantics(t, recovered)) {
					t.Fatal("loss of records, state, safety, outbox or archive metadata")
				}
				gotPointer, err := os.ReadFile(filepath.Join(m.DataDir, "fhs/CURRENT"))
				if err != nil || !bytes.Equal(pointer, gotPointer) {
					t.Fatal("same-generation rewrite changed CURRENT", err)
				}
			}
			if len(recovered) >= len(source) {
				t.Fatal("current duplicate-state encoding did not reduce hot bytes")
			}
			t.Logf("source sha256=%x generation=%d bytes=%d -> %d; all semantic fields identical; two full financial cold Opens, no Start/signing/network/live writes", sha256.Sum256(source), current.Payload.Generation, len(source), len(recovered))
		})
	}
}
