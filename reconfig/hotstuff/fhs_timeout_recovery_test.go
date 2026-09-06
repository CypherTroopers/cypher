package hotstuff

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/reconfig/bftview"
)

// The boundary application retains the durable certificate across manager
// restarts. All network envelopes, votes, TC aggregation and NewView quorum
// processing use the real protocol managers and seven distinct signing keys.
type timeoutRecoveryApp struct {
	*fhsAsyncValidationApp
	lastTimeout       *TimeoutStatement
	timeoutReads      int
	timeoutReadErr    error
	timeoutPersists   int
	timeoutPersistErr error
}

func (a *timeoutRecoveryApp) CurrentN() uint64 { return a.current + 1 }

func (a *timeoutRecoveryApp) PersistFHSTimeoutVote(statement *TimeoutStatement) error {
	a.timeoutPersists++
	if a.timeoutPersistErr != nil {
		return a.timeoutPersistErr
	}
	if statement.TimedOutView != a.CurrentN() {
		return ErrOldState
	}
	copy := *statement
	a.lastTimeout = &copy
	return nil
}

func (a *timeoutRecoveryApp) PendingFHSTimeoutVote() (*TimeoutStatement, error) {
	a.timeoutReads++
	if a.timeoutReadErr != nil {
		return nil, a.timeoutReadErr
	}
	if a.lastTimeout == nil {
		return nil, nil
	}
	copy := *a.lastTimeout
	return &copy, nil
}

func (a *timeoutRecoveryApp) AcceptFHSTimeoutCertificate(tc *TimeoutCertificate) error {
	if tc.Statement.ChainID != a.ChainID() || tc.Statement.KeyNumber != a.keyNumber ||
		tc.Statement.KeyHash != a.keyHash || tc.Statement.CommitteeHash != a.committeeHash {
		return ErrInvalidHighQC
	}
	if tc.Statement.TimedOutView <= a.current {
		return nil
	}
	return a.fhsFutureJumpApp.AcceptFHSTimeoutCertificate(tc)
}

type timeoutRecoveryNetwork struct {
	apps     []*timeoutRecoveryApp
	managers []*HotstuffProtocolManager
	secrets  []bls.SecretKey
	keys     []*bls.PublicKey
}

func newTimeoutRecoveryNetwork(t *testing.T) *timeoutRecoveryNetwork {
	t.Helper()
	secrets, keys := makeTestCommittee(t, 7)
	committee := &bftview.Committee{List: make([]*common.Cnode, len(keys))}
	for index, key := range keys {
		committee.List[index] = &common.Cnode{
			Address:  fmt.Sprintf("127.0.0.1:%d", 7200+index),
			CoinBase: fmt.Sprintf("timeout-recovery-%d", index), Public: key.SerializeToHexStr(),
		}
	}
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	bftview.SetCommitteeConfig(db, nil, nil)
	keyHash := common.HexToHash("0xf002")
	if !bftview.WriteCommittee(3, keyHash, committee) {
		t.Fatal("write timeout recovery committee")
	}
	network := &timeoutRecoveryNetwork{secrets: secrets, keys: keys}
	for index := range keys {
		app := &timeoutRecoveryApp{fhsAsyncValidationApp: &fhsAsyncValidationApp{
			fhsFutureJumpApp: &fhsFutureJumpApp{
				recoveryTestApp: &recoveryTestApp{
					self: committee.List[index].Address, fhs: true,
					publicKeysByHash: map[common.Hash][]*bls.PublicKey{keyHash: keys},
				},
				current: 10, keyNumber: 3, keyHash: keyHash,
				committeeHash: committee.RlpHash(), leaderID: committee.List[0].Address,
			},
		}}
		network.apps = append(network.apps, app)
		network.managers = append(network.managers, NewHotstuffProtocolManager(app, &secrets[index], keys[index]))
	}
	return network
}

func timeoutRecoveryMessages(messages []*HotstuffMessage, code uint32) []*HotstuffMessage {
	var selected []*HotstuffMessage
	for _, msg := range messages {
		if msg.Code == code {
			selected = append(selected, msg)
		}
	}
	return selected
}

func (network *timeoutRecoveryNetwork) formPartialTC(t *testing.T) *HotstuffMessage {
	t.Helper()
	// Only replica 0 receives five timeout votes before the partition. The
	// certificate then reaches replicas 0..3, including the next leader.
	for index, manager := range network.managers {
		if err := manager.LocalTimeout(); err != nil {
			t.Fatalf("replica %d local timeout: %v", index, err)
		}
	}
	for index := 0; index < 5; index++ {
		vote := timeoutRecoveryMessages(network.apps[index].broadcasts, MsgTimeout)[0]
		if err := network.managers[0].HandleMessage(vote); err != nil && !errors.Is(err, ErrInsufficientQC) {
			t.Fatalf("collect replica %d timeout: %v", index, err)
		}
	}
	tc := timeoutRecoveryMessages(network.apps[0].broadcasts, MsgTimeoutQC)[0]
	for index := 1; index < 4; index++ {
		if err := network.managers[index].HandleMessage(tc); err != nil {
			t.Fatalf("deliver partial TC to replica %d: %v", index, err)
		}
	}
	for index, app := range network.apps {
		want := uint64(10)
		if index < 4 {
			want++
		}
		if app.current != want {
			t.Fatalf("replica %d base view = %d, want %d", index, app.current, want)
		}
	}
	return tc
}

func TestFHSTimeoutVoteRecoveryHealsPreCertificateSplitDespiteDuplicates(t *testing.T) {
	network := newTimeoutRecoveryNetwork(t)
	votes := make([]*HotstuffMessage, len(network.apps))
	for index, manager := range network.managers {
		if err := manager.LocalTimeout(); err != nil {
			t.Fatal(err)
		}
		votes[index] = timeoutRecoveryMessages(network.apps[index].broadcasts, MsgTimeout)[0]
	}
	// The timeout vote from replica 3 is Byzantine but correctly signed. Before
	// healing, each collector receives only its partition's four or three votes.
	for receiver, manager := range network.managers {
		for sender, vote := range votes {
			if (receiver < 4) != (sender < 4) {
				continue
			}
			if err := manager.HandleMessage(vote); !errors.Is(err, ErrInsufficientQC) {
				t.Fatalf("partition timeout %d -> %d: %v", sender, receiver, err)
			}
		}
		network.apps[receiver].broadcasts = nil // Initial outbound queues are gone.
	}
	// A received duplicate must not extend the local send deadline. Wait for
	// exactly one physical resend interval, not the old two-minute cache TTL.
	time.Sleep(hotstuffRecoveryInterval + 10*time.Millisecond)
	for receiver, manager := range network.managers {
		if receiver == 3 {
			continue // This replica contributes no recovery work.
		}
		if err := manager.HandleMessage(votes[3]); !errors.Is(err, ErrInsufficientQC) {
			t.Fatalf("duplicate timeout -> %d: %v", receiver, err)
		}
		if err := manager.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: network.apps[receiver].current}); err != nil {
			t.Fatalf("healed timer %d: %v", receiver, err)
		}
		replays := timeoutRecoveryMessages(network.apps[receiver].broadcasts, MsgTimeout)
		if len(replays) != 1 {
			t.Fatalf("replica %d replayed %d durable timeout votes after duplicate reception, want 1", receiver, len(replays))
		}
		if err := VerifyMessageAuth(network.apps[receiver].ChainID(), replays[0], network.apps[receiver].Self(), network.keys[receiver]); err != nil {
			t.Fatalf("replica %d replay authentication: %v", receiver, err)
		}
	}
	for sender, app := range network.apps {
		if sender == 3 {
			continue
		}
		for _, vote := range timeoutRecoveryMessages(app.broadcasts, MsgTimeout) {
			if err := network.managers[0].HandleMessage(vote); err != nil && !errors.Is(err, ErrInsufficientQC) && !errors.Is(err, ErrViewIdNotMatch) {
				t.Fatalf("healed timeout %d -> 0: %v", sender, err)
			}
		}
	}
	tcs := timeoutRecoveryMessages(network.apps[0].broadcasts, MsgTimeoutQC)
	if len(tcs) != 1 {
		t.Fatalf("healed collector formed %d timeout certificates, want 1", len(tcs))
	}
	for index, manager := range network.managers {
		if index == 3 {
			continue
		}
		if err := manager.HandleMessage(tcs[0]); err != nil && !errors.Is(err, ErrOldState) {
			t.Fatalf("healed certificate -> %d: %v", index, err)
		}
		if network.apps[index].current != 11 {
			t.Fatalf("replica %d did not advance after communication healed", index)
		}
	}
}

func TestFHSTimeoutVoteRecoveryRestartReplaysDurableStatement(t *testing.T) {
	network := newTimeoutRecoveryNetwork(t)
	app := network.apps[2]
	if err := network.managers[2].LocalTimeout(); err != nil {
		t.Fatal(err)
	}
	original := timeoutRecoveryMessages(app.broadcasts, MsgTimeout)[0]
	durable := *app.lastTimeout
	app.broadcasts = nil
	manager := NewHotstuffProtocolManager(app, &network.secrets[2], network.keys[2])
	tick := &HotstuffMessage{Code: MsgTimer, Number: app.current}
	if err := manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	replays := timeoutRecoveryMessages(app.broadcasts, MsgTimeout)
	if len(replays) != 1 || replays[0] == original || *app.lastTimeout != durable {
		t.Fatal("restart did not re-envelope the exact durable timeout vote")
	}
	if err := VerifyMessageAuth(app.ChainID(), replays[0], app.Self(), network.keys[2]); err != nil {
		t.Fatal(err)
	}
	if err := network.managers[6].HandleMessage(replays[0]); !errors.Is(err, ErrInsufficientQC) {
		t.Fatalf("restarted vote was not accepted by its peer: %v", err)
	}
	if err := manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	if err := manager.LocalTimeout(); err != nil {
		t.Fatal(err)
	}
	if len(timeoutRecoveryMessages(app.broadcasts, MsgTimeout)) != 1 || app.timeoutReads != 1 {
		t.Fatal("timer or local timeout repeated durable work within the resend interval")
	}
}

func TestFHSTimeoutVoteRecoveryBroadcastFailureRemainsBoundedAndRetryable(t *testing.T) {
	network := newTimeoutRecoveryNetwork(t)
	app, manager := network.apps[0], network.managers[0]
	failure := errors.New("timeout vote delivery failed")
	app.broadcastErrors = []error{failure}
	if err := manager.LocalTimeout(); !errors.Is(err, failure) {
		t.Fatalf("initial timeout delivery = %v, want failure", err)
	}
	if app.lastTimeout == nil {
		t.Fatal("failed send lost its durable vote")
	}
	tick := &HotstuffMessage{Code: MsgTimer, Number: app.current}
	if err := manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	if len(timeoutRecoveryMessages(app.broadcasts, MsgTimeout)) != 1 {
		t.Fatal("failed initial send retried inside its interval")
	}
	manager.timeoutVoteRetryAt = time.Time{}
	if err := manager.HandleMessage(tick); !errors.Is(err, failure) {
		t.Fatalf("retry delivery = %v, want failure", err)
	}
	if err := manager.LocalTimeout(); err != nil {
		t.Fatal(err)
	}
	if len(timeoutRecoveryMessages(app.broadcasts, MsgTimeout)) != 2 {
		t.Fatal("failed recovery send was not rate limited")
	}
	app.broadcastErrors = nil
	manager.timeoutVoteRetryAt = time.Time{}
	if err := manager.HandleMessage(tick); err != nil {
		t.Fatal(err)
	}
	replays := timeoutRecoveryMessages(app.broadcasts, MsgTimeout)
	if len(replays) != 3 || replays[1] == replays[2] {
		t.Fatal("restored transport did not receive a fresh timeout envelope")
	}
	if err := network.managers[6].HandleMessage(replays[2]); !errors.Is(err, ErrInsufficientQC) {
		t.Fatalf("retried timeout vote was not accepted: %v", err)
	}
}

func TestFHSTimeoutVoteRecoveryStorageFailuresDoNotSend(t *testing.T) {
	for _, stage := range []string{"read", "persist"} {
		t.Run(stage, func(t *testing.T) {
			network := newTimeoutRecoveryNetwork(t)
			app, manager := network.apps[0], network.managers[0]
			if err := manager.LocalTimeout(); err != nil {
				t.Fatal(err)
			}
			app.broadcasts = nil
			failure := errors.New("timeout safety store failure")
			if stage == "read" {
				app.timeoutReadErr = failure
			} else {
				app.timeoutPersistErr = failure
			}
			manager.timeoutVoteRetryAt = time.Time{}
			tick := &HotstuffMessage{Code: MsgTimer, Number: app.current}
			if err := manager.HandleMessage(tick); !errors.Is(err, failure) {
				t.Fatalf("storage failure = %v, want failure", err)
			}
			reads, persists := app.timeoutReads, app.timeoutPersists
			if err := manager.HandleMessage(tick); err != nil {
				t.Fatal(err)
			}
			if len(app.broadcasts) != 0 || app.timeoutReads != reads || app.timeoutPersists != persists {
				t.Fatal("storage failure sent a vote or retried inside its interval")
			}
			app.timeoutReadErr, app.timeoutPersistErr = nil, nil
			manager.timeoutVoteRetryAt = time.Time{}
			if err := manager.HandleMessage(tick); err != nil || len(timeoutRecoveryMessages(app.broadcasts, MsgTimeout)) != 1 {
				t.Fatalf("storage recovery did not replay durable vote: %v", err)
			}
		})
	}
}

func TestFHSTimeoutVoteRecoveryRejectsObsoleteOrForeignStatement(t *testing.T) {
	for _, name := range []string{"absent", "stale view", "superseded by QC", "superseded by TC", "future view", "foreign chain", "foreign epoch", "foreign committee", "invalid version", "wrong member key"} {
		t.Run(name, func(t *testing.T) {
			network := newTimeoutRecoveryNetwork(t)
			app, manager := network.apps[0], network.managers[0]
			if err := manager.LocalTimeout(); err != nil {
				t.Fatal(err)
			}
			quiet := false
			switch name {
			case "absent":
				app.lastTimeout, quiet = nil, true
			case "stale view":
				app.current++
				quiet = true
			case "superseded by QC":
				app.highest = &SignedState{Number: app.lastTimeout.TimedOutView}
				quiet = true
			case "superseded by TC":
				app.highestTC = &TimeoutCertificate{Statement: *app.lastTimeout}
				quiet = true
			case "future view":
				app.lastTimeout.TimedOutView++
			case "foreign chain":
				app.lastTimeout.ChainID++
			case "foreign epoch":
				app.lastTimeout.KeyHash = common.HexToHash("0xdead")
			case "foreign committee":
				app.lastTimeout.CommitteeHash = common.HexToHash("0xbeef")
			case "invalid version":
				app.lastTimeout.Version++
			case "wrong member key":
				manager.publicKey = network.keys[1]
			}
			app.broadcasts = nil
			persists, current := app.timeoutPersists, app.current
			manager.timeoutVoteRetryAt = time.Time{}
			err := manager.replayFHSTimeoutVote(time.Now())
			if quiet && err != nil {
				t.Fatalf("obsolete vote should be a quiet no-op: %v", err)
			}
			if !quiet && err == nil {
				t.Fatal("invalid durable timeout vote was not rejected")
			}
			if len(app.broadcasts) != 0 || app.timeoutPersists != persists || app.current != current {
				t.Fatal("rejected durable vote changed consensus state or was broadcast")
			}
		})
	}
}

func TestFHSTimeoutRecoveryHealsPartialCertificateAfterQueuesExpire(t *testing.T) {
	network := newTimeoutRecoveryNetwork(t)
	network.formPartialTC(t)
	// No old outbound envelope survives the outage. Expire the volatile vote
	// and TC caches too: durable HighestTC must be sufficient for recovery.
	for index, manager := range network.managers {
		network.apps[index].broadcasts = nil
		for id := range manager.timeoutSeen {
			manager.timeoutSeen[id] = time.Now().Add(-pendingMessageTTL - time.Second)
		}
		manager.pruneTimeoutState(network.apps[index].CurrentN())
		if err := manager.LocalTimeout(); err != nil {
			t.Fatalf("replica %d timeout after outage: %v", index, err)
		}
	}
	// Restored communication alone cannot combine the four view-12 votes and
	// three view-11 votes. Exercise the exact-view rejection and echo paths.
	for sender, app := range network.apps {
		for _, vote := range timeoutRecoveryMessages(app.broadcasts, MsgTimeout) {
			for receiver, manager := range network.managers {
				if err := manager.HandleMessage(vote); err != nil && !errors.Is(err, ErrInsufficientQC) && !errors.Is(err, ErrViewIdNotMatch) {
					t.Fatalf("post-outage timeout %d -> %d: %v", sender, receiver, err)
				}
			}
		}
	}
	for index, manager := range network.managers {
		if got := len(timeoutRecoveryMessages(network.apps[index].broadcasts, MsgTimeoutQC)); got != 0 {
			t.Fatalf("replica %d unexpectedly formed %d TCs from a split quorum", index, got)
		}
		manager.timeoutCertificateRetryAt = time.Time{} // The outage exceeded the replay interval too.
		if err := manager.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: network.apps[index].current}); err != nil {
			t.Fatalf("replica %d recovery tick: %v", index, err)
		}
	}
	for sender := 0; sender < 4; sender++ {
		replays := timeoutRecoveryMessages(network.apps[sender].broadcasts, MsgTimeoutQC)
		if len(replays) != 1 {
			t.Fatalf("replica %d durable TC replays = %d, want 1 after the 4/3 split", sender, len(replays))
		}
		msg := replays[0]
		if err := VerifyMessageAuth(network.apps[sender].ChainID(), msg, network.apps[sender].Self(), network.keys[sender]); err != nil {
			t.Fatalf("replica %d did not authenticate its own TC replay: %v", sender, err)
		}
		for receiver, manager := range network.managers {
			if err := manager.HandleMessage(msg); err != nil && !errors.Is(err, ErrOldState) {
				t.Fatalf("replay %d -> %d: %v", sender, receiver, err)
			}
		}
	}
	for index, app := range network.apps {
		if app.current != 11 {
			t.Fatalf("replica %d remained in base view %d after reconnection", index, app.current)
		}
	}
	// Four replicas already timed out view 12 during the partition. Once all
	// seven share that view, their real timeout votes can now produce its TC
	// and enter a fresh view where a proposal can receive a quorum of votes.
	for index, manager := range network.managers {
		if err := manager.LocalTimeout(); err != nil {
			t.Fatalf("replica %d converged timeout: %v", index, err)
		}
	}
	for sender, app := range network.apps {
		for _, vote := range timeoutRecoveryMessages(app.broadcasts, MsgTimeout) {
			if vote.Number != 12 {
				continue
			}
			if err := network.managers[0].HandleMessage(vote); err != nil && !errors.Is(err, ErrInsufficientQC) && !errors.Is(err, ErrViewIdNotMatch) {
				t.Fatalf("converged timeout %d -> 0: %v", sender, err)
			}
		}
	}
	certificates := timeoutRecoveryMessages(network.apps[0].broadcasts, MsgTimeoutQC)
	nextTC := certificates[len(certificates)-1]
	if nextTC.Number != 12 {
		t.Fatal("healed network could not form its next timeout certificate")
	}
	for index := 1; index < len(network.managers); index++ {
		if err := network.managers[index].HandleMessage(nextTC); err != nil {
			t.Fatalf("next TC -> %d: %v", index, err)
		}
	}
	for index, app := range network.apps {
		if app.current != 12 {
			t.Fatalf("replica %d did not enter the fresh proposal view", index)
		}
		for _, msg := range app.writes {
			if msg.Number != 13 {
				continue
			}
			if err := network.managers[0].HandleMessage(msg); err != nil && !errors.Is(err, ErrInsufficientQC) && !errors.Is(err, ErrProposalValidationPending) {
				t.Fatalf("NewView %d -> leader: %v", index, err)
			}
		}
	}
	if len(network.apps[0].buildScheduled) != 1 {
		t.Fatalf("healed leader scheduled %d proposals, want 1 from a verified NewView quorum", len(network.apps[0].buildScheduled))
	}
}

func TestFHSTimeoutRecoveryRestartUsesDurableCertificate(t *testing.T) {
	network := newTimeoutRecoveryNetwork(t)
	original := network.formPartialTC(t)
	// Replica 2 only received the TC; it never aggregated or broadcast one.
	app := network.apps[2]
	app.broadcasts = nil
	manager := NewHotstuffProtocolManager(app, &network.secrets[2], network.keys[2])
	if err := manager.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: app.current}); err != nil {
		t.Fatal(err)
	}
	replays := timeoutRecoveryMessages(app.broadcasts, MsgTimeoutQC)
	if len(replays) != 1 {
		t.Fatalf("restarted receiver replayed %d TCs, want 1", len(replays))
	}
	msg := replays[0]
	if msg.ViewId != original.ViewId || msg.Id == original.Id {
		t.Fatal("restart did not retain the proof and replace the original sender")
	}
	if err := VerifyMessageAuth(app.ChainID(), msg, app.Self(), network.keys[2]); err != nil {
		t.Fatalf("restart TC envelope is not signed by replica 2: %v", err)
	}
	if err := network.managers[6].HandleMessage(msg); err != nil || network.apps[6].current != 11 {
		t.Fatalf("restart replay did not recover lagging replica: view=%d err=%v", network.apps[6].current, err)
	}
}

func TestFHSTimeoutRecoveryBroadcastFailureIsBoundedAndRetryable(t *testing.T) {
	network := newTimeoutRecoveryNetwork(t)
	network.formPartialTC(t)
	app, manager := network.apps[0], network.managers[0]
	failure := errors.New("injected timeout-certificate delivery failure")
	app.broadcastErrors = []error{failure}
	beforeWrites := len(app.writes)
	if err := manager.broadcastTimeoutCertificate(app.highestTC); !errors.Is(err, failure) {
		t.Fatalf("initial TC broadcast error = %v, want delivery failure", err)
	}
	if len(app.writes) != beforeWrites+1 {
		t.Fatal("failed TC delivery prevented the local NewView")
	}
	app.broadcasts = nil
	manager.timeoutCertificateRetryAt = time.Time{}
	tick := &HotstuffMessage{Code: MsgTimer, Number: app.current}
	if err := manager.HandleMessage(tick); !errors.Is(err, failure) {
		t.Fatalf("periodic TC replay error = %v, want delivery failure", err)
	}
	if err := manager.HandleMessage(tick); err != nil {
		t.Fatalf("bounded retry tick: %v", err)
	}
	if got := len(timeoutRecoveryMessages(app.broadcasts, MsgTimeoutQC)); got != 1 {
		t.Fatalf("failed replay retried inside its interval: %d attempts", got)
	}
	app.broadcastErrors = nil
	manager.timeoutCertificateRetryAt = time.Time{}
	if err := manager.HandleMessage(tick); err != nil {
		t.Fatalf("recovered delivery: %v", err)
	}
	replays := timeoutRecoveryMessages(app.broadcasts, MsgTimeoutQC)
	if len(replays) != 2 || replays[0] == replays[1] {
		t.Fatal("delivery recovery did not create a fresh TC envelope")
	}
	if err := network.managers[6].HandleMessage(replays[1]); err != nil || network.apps[6].current != 11 {
		t.Fatalf("retried TC did not recover lagging replica: view=%d err=%v", network.apps[6].current, err)
	}
}

func TestFHSTimeoutRecoveryRejectsObsoleteOrInvalidDurableProof(t *testing.T) {
	for _, name := range []string{"stale view", "superseded by QC", "future view", "invalid signature", "foreign chain", "foreign epoch", "foreign committee"} {
		t.Run(name, func(t *testing.T) {
			network := newTimeoutRecoveryNetwork(t)
			network.formPartialTC(t)
			app := network.apps[2]
			switch name {
			case "stale view":
				app.current++
			case "superseded by QC":
				app.highest = &SignedState{Number: app.highestTC.Statement.TimedOutView}
			case "future view":
				app.highestTC.Statement.TimedOutView++
			case "invalid signature":
				app.highestTC.Sign[0] ^= 0xff
			case "foreign chain":
				app.highestTC.Statement.ChainID++
			case "foreign epoch":
				app.highestTC.Statement.KeyHash = common.HexToHash("0xdead")
			case "foreign committee":
				app.highestTC.Statement.CommitteeHash = common.HexToHash("0xbeef")
			}
			app.broadcasts = nil
			beforeTC, beforeView, beforeAccepts := CloneTimeoutCertificate(app.highestTC), app.current, app.acceptCalls
			manager := NewHotstuffProtocolManager(app, &network.secrets[2], network.keys[2])
			err := manager.HandleMessage(&HotstuffMessage{Code: MsgTimer, Number: app.current})
			if name == "stale view" || name == "superseded by QC" {
				if err != nil {
					t.Fatalf("obsolete proof must be a quiet no-op: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid retained certificate was not rejected")
			}
			if len(app.broadcasts) != 0 || app.current != beforeView || app.acceptCalls != beforeAccepts ||
				!reflect.DeepEqual(app.highestTC, beforeTC) || len(manager.timeoutQC) != 0 || len(manager.timeoutVotes) != 0 {
				t.Fatal("rejected replay changed consensus state or emitted a message")
			}
		})
	}
}
