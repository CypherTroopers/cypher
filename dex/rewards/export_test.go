package rewards

import (
	"path/filepath"
	"testing"
)

func TestDurableCertificateExportOwnedAndRestarted(t *testing.T) {
	f := newRewardFixture(t)
	collectors := f.five(t)
	cert := f.certificate(t, collectors, 1, 6)
	dir := filepath.Join(t.TempDir(), "export")
	c := f.collector(t, 0, dir)
	if err := c.RememberCertificate(cert); err != nil {
		t.Fatal(err)
	}
	exported, err := c.Certificates(1)
	if err != nil || len(exported) != 1 {
		t.Fatal("export", err)
	}
	exported[0].Signatures[0].Signature[0] ^= 1
	fresh, err := c.Certificates(1)
	if err != nil || f.registry.VerifyCertificate(fresh[0]) != nil {
		t.Fatal("export aliases durable signature", err)
	}
	c.Shutdown()
	c = f.collector(t, 0, dir)
	fresh, err = c.Certificates(0)
	if err != nil || len(fresh) != 1 || f.registry.VerifyCertificate(fresh[0]) != nil {
		t.Fatal("restored export", err)
	}
	empty, err := c.Certificates(2)
	if err != nil || len(empty) != 0 {
		t.Fatal("wrong height exported", err)
	}
}
