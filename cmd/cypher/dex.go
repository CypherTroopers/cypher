package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cypherium/cypher/cmd/utils"
	"github.com/cypherium/cypher/dex/instrumentation"
	"github.com/cypherium/cypher/dex/protocol"
	"github.com/cypherium/cypher/dex/service"
	"github.com/cypherium/cypher/dex/service/finance"
	"github.com/cypherium/cypher/internal/ethapi"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/rpc"
	cli "gopkg.in/urfave/cli.v1"
)

var dexValidatorCommand = cli.Command{Name: "dex-validator", Usage: "Run the isolated registered DEX sidecar", Flags: []cli.Flag{utils.DEXConfigFlag}, Action: utils.MigrateFlags(runDEXValidator)}

func runDEXValidator(ctx *cli.Context) error {
	if ctx.NArg() != 0 {
		return errors.New("DEX sidecar accepts only an explicit manifest")
	}
	m, err := service.LoadManifest(ctx.GlobalString(utils.DEXConfigFlag.Name))
	if err != nil {
		return err
	}
	var s *service.Service
	if m.Mode == "native-finance" {
		s, err = finance.OpenManifest(m)
	} else {
		s, err = service.OpenManifest(m)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.Start(); err != nil {
		return err
	}
	log.Info("DEX sidecar active", "index", m.Index, "mode", m.Mode, "datadir", m.DataDir)
	ctxStop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if m.LeaderSubmission != "" {
		worker, interval, err := openLeaderSubmission(s, m)
		if err != nil {
			return err
		}
		defer worker.Close()
		finished := make(chan error, 1)
		go func() { finished <- relayCLILoop(ctxStop, interval, false, worker) }()
		log.Info("DEX leader submission worker active", "index", m.Index)
		select {
		case err := <-finished:
			return err
		case <-ctxStop.Done():
			return <-finished // join worker before closing its journals and keys
		}
	}
	<-ctxStop.Done()
	return nil
}

// A DEX crash never requests CLX/miner/RPC shutdown. This object owns only the
// newly started child handle; it never discovers or signals an existing PID.
type dexSidecar struct {
	mu      sync.Mutex
	config  utils.DEXConfig
	backend ethapi.Backend
	child   *exec.Cmd
	done    chan struct{}
	stopped bool
}

func registerDEXSidecar(stack *node.Node, backend ethapi.Backend, cfg utils.DEXConfig) {
	// This observation is available even when the local DEX role is OFF. It
	// creates no engine/worker and never reads or mutates CLX settlement state.
	stack.RegisterAPIs([]rpc.API{{Namespace: "debug", Version: "1.0", Service: dexExecutionAPI{}, Public: false}})
	if !cfg.Validator {
		return
	}
	stack.RegisterLifecycle(&dexSidecar{config: cfg, backend: backend})
}

type dexExecutionAPI struct{}

func (dexExecutionAPI) DexExecutionStats() instrumentation.ExecutionStats {
	return instrumentation.Execution()
}
func (s *dexSidecar) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	if err := s.start(); err != nil {
		log.Error("DEX sidecar unavailable; Common continues", "err", err)
	}
	return nil
}
func (s *dexSidecar) start() error {
	m, err := service.LoadManifest(s.config.Config)
	if err != nil {
		return err
	}
	chain := s.backend.ChainConfig().ChainID
	if chain == nil || !chain.IsUint64() || chain.Uint64() != m.Domain.ChainID {
		return errors.New("DEX manifest differs from Common CLX chain ID")
	}
	header, err := s.backend.HeaderByNumber(context.Background(), rpc.BlockNumber(0))
	if err != nil || header == nil {
		return errors.New("Common genesis unavailable for DEX binding")
	}
	if protocol.Hash(header.Hash()) != m.Domain.Genesis {
		return errors.New("DEX manifest differs from Common CLX genesis")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.Command(binary, "dex-validator", "--dex.config", s.config.Config)
	// Preserve the CLI entry identity (also used by the repository's reexec test
	// harness); the executable path still comes only from os.Executable.
	child.Args[0] = os.Args[0]
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err = child.Start(); err != nil {
		return err
	}
	s.child = child
	s.done = make(chan struct{})
	go func() {
		err := child.Wait()
		close(s.done)
		s.mu.Lock()
		stopping := s.stopped
		s.mu.Unlock()
		if !stopping {
			log.Error("DEX sidecar exited; Common continues", "err", err)
		}
	}()
	return nil
}
func (s *dexSidecar) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	child, done := s.child, s.done
	s.mu.Unlock()
	if child == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	default:
	}
	_ = child.Process.Signal(os.Interrupt)
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		_ = child.Process.Kill()
		<-done
		return nil
	}
}
