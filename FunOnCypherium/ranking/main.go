package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	ipcPath, ipcSource := resolveIPCPath()
	if ipcPath == "" {
		log.Fatalf("[IPC] no socket path could be resolved; set CYPHER_IPC_PATH or CYPHER_DATA_DIR")
	}
	if ipcSource != "env" {
		if err := os.Setenv("CYPHER_IPC_PATH", ipcPath); err != nil {
			log.Printf("[IPC] warning: unable to export resolved path: %v", err)
		}
	}
	log.Printf("[IPC] using %s (source=%s)", ipcPath, ipcSource)

	basePath := os.Getenv("BASE_PATH")
	if basePath == "" {
		basePath = defaultBasePath
	}

	port := defaultPort
	if raw := os.Getenv("PORT"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			port = parsed
		}
	}

	srv, err := newRankingServer(ipcPath, normalizeBasePath(basePath), port)
	if err != nil {
		log.Fatalf("[IPC] Failed to connect to %s: %v", ipcPath, err)
	}
	defer srv.close()

	if err := srv.bootstrap(context.Background()); err != nil {
		log.Fatalf("[INIT] bootstrap failed: %v", err)
	}

	mux := srv.buildMux()
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: loggingMiddleware(mux),
	}

	log.Printf("Server running at http://localhost:%d", port)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[FATAL] http server: %v", err)
	}
}
