package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/transport"
)

type apiServer struct {
	server   *http.Server
	listener net.Listener
}

func startAPI(s *Service, addr string) (*apiServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		status, err := s.Status(ctx)
		if err != nil {
			http.Error(w, "DEX unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("/v1/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, consensus.MaxActionBytes)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "action size", 413)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		id, err := s.Submit(ctx, b)
		if err != nil {
			code := 400
			if errors.Is(err, transport.ErrBusy) || errors.Is(err, context.DeadlineExceeded) {
				code = 503
			}
			http.Error(w, "action rejected", code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		stage, reason, finality := "ingress_admitted", "", "pending"
		if s.config.IngressStage != nil {
			if err := s.Do(ctx, func(*consensus.Application) error { stage, reason = s.config.IngressStage(id); return nil }); err != nil {
				http.Error(w, "admission status unavailable", http.StatusServiceUnavailable)
				return
			}
			if stage == "dex_finalized" {
				finality = "finalized"
			}
			if stage == "rejected" {
				finality = "rejected"
			}
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"stage": stage, "reason": reason, "id": hex.EncodeToString(id[:]), "dex_finality": finality, "clx_settlement": "separate"})
	})
	for _, path := range []string{"/v1/checkpoint", "/v1/certified", "/v1/participation", "/v1/action-status", "/v1/settlement", "/v1/snapshot"} {
		path := path
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || s.config.Query == nil {
				http.Error(w, "unavailable", http.StatusNotFound)
				return
			}
			if len(r.URL.RawQuery) > 1024 {
				http.Error(w, "query bound", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			var value interface{}
			err := s.Do(ctx, func(a *consensus.Application) error {
				var e error
				value, e = s.config.Query(a, path, r.URL.Query())
				return e
			})
			if err != nil {
				http.Error(w, "data unavailable", http.StatusServiceUnavailable)
				return
			}
			raw, err := json.Marshal(value)
			if err != nil || len(raw) > 3*1024*1024 {
				http.Error(w, "response bound", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(raw)
		})
	}
	api := &apiServer{server: &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 4 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}, listener: &limitedListener{Listener: listener, slots: make(chan struct{}, 16)}}
	go api.server.Serve(api.listener)
	return api, nil
}
func (a *apiServer) close() { a.server.Close() }

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once  sync.Once
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, slots: l.slots}, nil
		default:
			c.Close()
		}
	}
}
func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
