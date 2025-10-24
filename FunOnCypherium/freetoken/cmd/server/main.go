package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const defaultPort = "4200"

func main() {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = defaultPort
	}

	assetRoot, err := resolveAssetRoot()
	if err != nil {
		log.Fatalf("unable to determine asset root: %v", err)
	}

	sharedDir := filepath.Clean(filepath.Join(assetRoot, "..", "shared"))
	if _, err := os.Stat(sharedDir); err != nil {
		log.Printf("warning: shared assets directory %q unavailable: %v", sharedDir, err)
	} else {
		http.Handle("/shared/", http.StripPrefix("/shared/", http.FileServer(http.Dir(sharedDir))))
	}

	staticServer := http.FileServer(http.Dir(assetRoot))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			serveFile(filepath.Join(assetRoot, "index.html"), w, r)
		case "/abi":
			serveFile(filepath.Join(assetRoot, "build", "CRC20.abi"), w, r)
		case "/bytecode":
			serveFile(filepath.Join(assetRoot, "build", "CRC20.bin"), w, r)
		default:
			staticServer.ServeHTTP(w, r)
		}
	})

	address := fmt.Sprintf(":%s", port)
	log.Printf("FunOnCypherium freetoken server listening on http://localhost:%s (serving assets from %s)", port, assetRoot)
	if err := http.ListenAndServe(address, nil); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func serveFile(path string, w http.ResponseWriter, r *http.Request) {
	if err := verifyPath(path); err != nil {
		log.Printf("refusing to serve %q: %v", path, err)
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}

func verifyPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("path %q is a directory", path)
	}
	return nil
}

func resolveAssetRoot() (string, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	candidates := []string{
		filepath.Join(workDir, "freetoken"),
		filepath.Join(workDir, "FunOnCypherium", "freetoken"),
		workDir,
	}

	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if hasFile(candidate, "index.html") {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not locate freetoken assets relative to %q", workDir)
}

func hasFile(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return false
	}
	return !info.IsDir()
}
