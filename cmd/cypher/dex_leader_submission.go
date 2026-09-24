package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/relay"
	"github.com/cypherium/cypher/dex/relay/source"
	"github.com/cypherium/cypher/dex/service"
)

// relaySession reuses the durable transaction machinery for both the integrated
// DEX leader and the explicitly invoked legacy test command. Its gas keys,
// verifier objects and network clients are worker-owned, never shared with the
// FHS actor. No subprocess or additional node role is created here.
type relaySession struct {
	signer  *relayLocalSigner
	lock    *os.File
	network *relay.Network
	core    *relay.Relay
	leader  *relay.LeaderRelay
}

func openRelaySession(m relayCLIManifest, check func(context.Context) (relay.Leadership, error)) (_ *relaySession, err error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	x := new(relaySession)
	defer func() {
		if err != nil {
			x.Close()
		}
	}()
	if x.signer, err = loadRelayLocalSigner(m, cfg); err != nil {
		return nil, err
	}
	if x.lock, err = prepareRelayCLIRoot(m.DataDir); err != nil {
		return nil, err
	}
	x.network, err = relay.OpenNetwork(relay.NetworkConfig{Relay: cfg, Source: source.Config{Endpoint: m.SourceURL, Dir: filepath.Join(m.DataDir, "source"), CLX: m.CLX}, SubmitURL: m.SubmitURL, DEXURL: m.DEXURL, MaxHeight: m.MaxHeight, AutoInbox: m.AutoInbox, CertifiedInboxPlanning: check != nil, DeferredRecipients: append([]common.Address(nil), m.DeferredRecipients...)})
	if err != nil {
		return nil, err
	}
	if check != nil {
		x.leader, err = relay.OpenLeader(filepath.Join(m.DataDir, "core"), cfg, x.network, x.signer, check)
		if err == nil {
			x.core = x.leader.Journal()
		}
	} else {
		x.core, err = relay.Open(filepath.Join(m.DataDir, "core"), cfg, x.network, x.signer)
	}
	if err != nil {
		return nil, err
	}
	return x, nil
}

func (x *relaySession) Close() error {
	var err error
	if x.core != nil {
		err = x.core.Close()
	}
	if x.network != nil {
		err = errors.Join(err, x.network.Close())
	}
	if x.signer != nil {
		x.signer.close()
	}
	if x.lock != nil {
		err = errors.Join(err, x.lock.Close())
	}
	return err
}

func validateLeaderSubmission(m service.Manifest, r relayCLIManifest) error {
	if m.Mode != "native-finance" || m.Finance == nil || m.LeaderSubmission == "" || m.APIListen == "" || r.Domain != m.Domain || r.MaxHeight != m.MaxHeight || filepath.Clean(r.DataDir) != filepath.Join(m.DataDir, "submission") || strings.TrimSuffix(r.DEXURL, "/") != "http://"+m.APIListen {
		return errors.New("leader submission must bind its own DEX manifest, API and private child datadir")
	}
	// Domain alone does not authenticate a self-declared source committee. Both
	// source verifiers must use the same explicit genesis and historical registry.
	a, err := json.Marshal(m.Finance.CLX)
	if err != nil {
		return err
	}
	b, err := json.Marshal(r.CLX)
	if err != nil || !bytes.Equal(a, b) {
		return errors.New("leader submission source differs from DEX authenticated CLX configuration")
	}
	for _, p := range r.Payers {
		if p.Purpose != "leader-submission-gas" {
			return errors.New("leader submission requires dedicated submission gas keys")
		}
	}
	return nil
}

type leaderSubmissionLoop struct {
	service *service.Service
	session *relaySession
	root    string
	last    consensus.Leadership
}

func openLeaderSubmission(s *service.Service, m service.Manifest) (*leaderSubmissionLoop, time.Duration, error) {
	r, err := loadRelayCLIManifest(m.LeaderSubmission)
	if err != nil {
		return nil, 0, err
	}
	if err = validateLeaderSubmission(m, r); err != nil {
		return nil, 0, err
	}
	x := &leaderSubmissionLoop{service: s, root: r.DataDir}
	x.session, err = openRelaySession(r, func(ctx context.Context) (relay.Leadership, error) {
		state, done, err := s.LeadershipLease(ctx)
		x.last = state // only this serial worker invokes the callback
		return relay.Leadership{View: state.View, Active: state.Active, Done: done}, err
	})
	if err != nil {
		return nil, 0, err
	}
	return x, time.Duration(r.PollMillis) * time.Millisecond, nil
}

func (l *leaderSubmissionLoop) Discover(ctx context.Context) error {
	defer func() { l.service.SetSubmissionPending(l.session.leader.PendingWork()) }()
	// Followers authenticate and persist observations too. This is read-only on
	// CLX/DEX and allows takeover to reconstruct unfinished business without
	// copying the previous leader's private key, nonce or local memory.
	return l.session.network.Discover(ctx, l.session.core)
}

func (l *leaderSubmissionLoop) Step(ctx context.Context) error {
	defer func() { l.service.SetSubmissionPending(l.session.leader.PendingWork()) }()
	state, err := l.service.Leadership(ctx)
	if err != nil {
		return err
	}
	l.last = state
	if !state.Active {
		return l.session.leader.Reconcile(ctx)
	}
	// Step already authenticates the selected job before signing/sending.
	// Repeating that work first could consume the bounded request deadline and
	// indefinitely prevent an otherwise healthy leader from ever submitting.
	err = l.session.leader.Step(ctx)
	if errors.Is(err, relay.ErrNotLeader) {
		return nil // explicit standby, not a consensus or economic failure
	}
	return err
}

func (l *leaderSubmissionLoop) WriteStatus(discovery, step error) error {
	return relayStatusWithLeader(l.root, l.session.network.AuthenticatedStatus(), l.session.core.Status(), discovery, step, &l.last)
}

func (l *leaderSubmissionLoop) Close() error {
	l.service.SetSubmissionPending(false)
	return l.session.Close()
}
