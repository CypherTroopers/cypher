package lightnode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLightnodeCommonRoleIsDistinctFromFiniteHTTP3ProofRole(t *testing.T) {
	if err := (CommonRole{FairHotstuff: true}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, role := range []CommonRole{{}, {FairHotstuff: true, Ingress: true}, {FairHotstuff: true, Mining: true}, {FairHotstuff: true, Unlock: true}} {
		if role.Validate() == nil {
			t.Fatalf("unsafe Common role admitted: %+v", role)
		}
	}
}

func TestLightnodeOwnerConfigRejectsAliasesExtraFieldsDuplicatePinsAndLargeInput(t *testing.T) {
	good := `{"enabled":true,"listenAddr":"127.0.0.1:18083","allowedPageOrigin":"http://127.0.0.1:18081","network":{"chainId":10101919,"genesisHash":"0x` + strings.Repeat("1", 64) + `"}}`
	path := filepath.Join(t.TempDir(), "public.json")
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicConfiguration(path); err != nil {
		t.Fatal(err)
	}
	selectedOrigin := "https://ai-test.make-cph-great-again.community"
	public := strings.Replace(good, "http://127.0.0.1:18081", selectedOrigin, 1)
	if err := os.WriteFile(path, []byte(public), 0600); err != nil {
		t.Fatal(err)
	}
	if config, err := LoadPublicConfiguration(path); err != nil || config.AllowedPageOrigin != selectedOrigin || config.Network.ChainID != 10101919 {
		t.Fatalf("exact selected HTTPS owner config rejected: %v", err)
	}
	bad := []string{
		strings.Replace(good, "127.0.0.1:18083", "0.0.0.0:18083", 1),
		strings.Replace(good, "127.0.0.1:18083", "localhost:18083", 1),
		strings.Replace(good, "http://127.0.0.1:18081", "https://evil.example", 1),
		strings.Replace(public, selectedOrigin, selectedOrigin+":443", 1),
		strings.Replace(public, selectedOrigin, selectedOrigin+"/", 1),
		strings.Replace(public, selectedOrigin, "https://AI-TEST.make-cph-great-again.community", 1),
		strings.Replace(public, `"allowedPageOrigin":"`+selectedOrigin+`"`, `"allowedPageOrigin":["`+selectedOrigin+`","http://127.0.0.1:18081"]`, 1),
		strings.Replace(good, `"enabled":true`, `"enabled":true,"enabled":true`, 1),
		strings.Replace(good, `"chainId":10101919`, `"chainId":10101919,"chainId":10101919`, 1),
		strings.Replace(good, `"enabled":true`, `"enabled":false`, 1),
		strings.Replace(good, `"enabled":true`, `"enabled":true,"prompt":"private"`, 1),
		strings.Replace(good, `"allowedPageOrigin":"http://127.0.0.1:18081",`, "", 1),
		strings.Replace(good, `"chainId"`, `"CHAINID"`, 1),
		good + "{}", good + strings.Repeat(" ", 4096),
	}
	for i, raw := range bad {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPublicConfiguration(path); err == nil {
			t.Fatalf("invalid config %d admitted", i)
		}
	}
	if _, err := LoadPublicConfiguration("relative.json"); err == nil {
		t.Fatal("relative config admitted")
	}
}

func TestLightnodeOwnerConfigRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "public.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := LoadPublicConfiguration(link); err == nil {
		t.Fatal("symlink admitted")
	}
}
