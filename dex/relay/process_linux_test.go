//go:build linux

package relay

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This is an actual SIGKILL/reopen persistence test, with a fake proof backend.
// It does not substitute for the separate real Common/CLX/DEX network gate.
func TestRelaySIGKILLChild(t *testing.T) {
	stage := os.Getenv("DEX_RELAY_UNIT_KILL_STAGE")
	if stage == "" {
		t.Skip("child helper")
	}
	dir := os.Getenv("DEX_RELAY_UNIT_KILL_DIR")
	c, b, s := fixtureConfig(t)
	armed := stage != "after_completion"
	c.Hook = func(at string) error {
		if armed && at == stage {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	b.onSend = func() error {
		raw := b.sent[len(b.sent)-1]
		f, err := os.OpenFile(filepath.Join(dir, "unit-broadcast.bin"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write(raw); err != nil {
			f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	r := openFixture(t, c, b, s, dir)
	if stage == "mid_store" {
		r.store.afterTemporaryWrite = func() error { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL); select {} }
	}
	if err := r.Enqueue(fixtureJob(Checkpoint, 1)); err != nil {
		t.Fatal(err)
	}
	if err := stepNow(r); err != nil {
		t.Fatal(err)
	}
	if stage == "after_completion" {
		b.obs.completed = true
		b.obs.nonce = 1
		armed = true
		if err := stepNow(r); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("SIGKILL hook was not reached")
}

func TestRelayActualSIGKILLAndRestartBoundaries(t *testing.T) {
	for _, stage := range []string{"after_intent", "after_prepared", "after_signed", "before_send", "after_send", "after_proof", "after_completion"} {
		t.Run(stage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "relay")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRelaySIGKILLChild$")
			cmd.Env = append(os.Environ(), "DEX_RELAY_UNIT_KILL_STAGE="+stage, "DEX_RELAY_UNIT_KILL_DIR="+dir)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("child survived", string(out))
			}
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("unexpected child failure", err, string(out))
			}
			c, b, s := fixtureConfig(t)
			r := openFixture(t, c, b, s, dir)
			defer r.Close()
			if len(r.Status()) != 1 {
				t.Fatal("durable intent lost")
			}
			broadcast, readErr := os.ReadFile(filepath.Join(dir, "unit-broadcast.bin"))
			if stage == "after_send" || stage == "after_completion" {
				if readErr != nil || !bytes.Equal(broadcast, r.Status()[0].Attempt.Raw) {
					t.Fatal("broadcast raw not durable", readErr)
				}
			} else if readErr == nil {
				t.Fatal("broadcast before boundary", stage)
			}
			if stage == "after_completion" {
				b.obs.completed = true
				b.obs.nonce = 1
				if r.Status()[0].Phase != "revalidation_wait" {
					t.Fatal("completion bypassed revalidation")
				}
			}
			if err := stepNow(r); err != nil {
				t.Fatal("restart", err)
			}
			if stage != "after_completion" {
				b.obs.completed = true
				b.obs.nonce = 1
				if err := stepNow(r); err != nil {
					t.Fatal(err)
				}
			}
			if r.Status()[0].Phase != "complete" {
				t.Fatal("not completed")
			}
		})
	}
}

func TestRelayActualSIGKILLDuringTemporaryWrite(t *testing.T) {
	c, b, s := fixtureConfig(t)
	dir := filepath.Join(t.TempDir(), "relay")
	r := openFixture(t, c, b, s, dir)
	r.Close()
	canonical, err := os.ReadFile(filepath.Join(dir, "state.bin"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRelaySIGKILLChild$")
		cmd.Env = append(os.Environ(), "DEX_RELAY_UNIT_KILL_STAGE=mid_store", "DEX_RELAY_UNIT_KILL_DIR="+dir)
		out, err := cmd.CombinedOutput()
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal("expected SIGKILL", err, string(out))
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("wrong child exit", err, string(out))
		}
		if _, err = os.Stat(filepath.Join(dir, "state.next")); err != nil {
			t.Fatal("no orphan at actual pre-fsync kill", err)
		}
		r = openFixture(t, c, b, s, dir)
		if len(r.Status()) != 0 {
			t.Fatal("uncommitted intent promoted")
		}
		r.Close()
		after, err := os.ReadFile(filepath.Join(dir, "state.bin"))
		if err != nil || !bytes.Equal(after, canonical) {
			t.Fatal("canonical changed on orphan restore", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 3 {
			t.Fatal("orphan disk accumulation", len(entries), err)
		}
	}
}
