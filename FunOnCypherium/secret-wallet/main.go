package main

import (
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	defaultPort   = 4400
	maxPortTrials = 5
)

func main() {
	publicDir := resolvePublicDir()
	sharedDir := filepath.Clean(filepath.Join(publicDir, "..", "shared"))

	if err := ensureDirectory(publicDir); err != nil {
		log.Fatalf("unable to locate public directory: %v", err)
	}
	if err := ensureDirectory(sharedDir); err != nil {
		log.Fatalf("unable to locate shared directory: %v", err)
	}

	mux := http.NewServeMux()

	mux.Handle("/shared/", http.StripPrefix("/shared/", http.FileServer(http.Dir(sharedDir))))
	mux.Handle("/", newSPAHandler(publicDir, "index.html"))

	startPort := resolvePort()
	if err := startServer(mux, startPort); err != nil {
		log.Fatalf("failed to start Secret wallet server: %v", err)
	}
}

func resolvePublicDir() string {
	var candidates []string

	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exePath))
	}

	if _, filename, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Dir(filename))
	}

	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, dir := range candidates {
		dir = filepath.Clean(dir)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}

		if _, err := os.Stat(filepath.Join(dir, "index.html")); err == nil {
			return dir
		}
	}

	log.Fatal("unable to determine working directory for static assets")
	return ""
}

func ensureDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func resolvePort() int {
	raw := strings.TrimSpace(os.Getenv("PORT"))
	if raw == "" {
		return defaultPort
	}

	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		log.Printf("invalid PORT value %q, falling back to default %d", raw, defaultPort)
		return defaultPort
	}
	return port
}

func startServer(handler http.Handler, startPort int) error {
	for attempt := 0; attempt < maxPortTrials; attempt++ {
		port := startPort + attempt
		address := fmt.Sprintf(":%d", port)

		listener, err := net.Listen("tcp", address)
		if err != nil {
			if isAddrInUse(err) && attempt < maxPortTrials-1 {
				log.Printf("Port %d is already in use. Retrying with port %d (%d attempts left).", port, port+1, maxPortTrials-attempt-1)
				continue
			}
			return err
		}

		log.Printf("Secret wallet running at http://localhost:%d", port)
		if err := http.Serve(listener, withContentType(handler)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	return fmt.Errorf("could not bind to any port starting at %d", startPort)
}

func isAddrInUse(err error) bool {
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		if syscallErr, ok := netErr.Err.(*os.SyscallError); ok {
			return errors.Is(syscallErr, syscall.EADDRINUSE)
		}
	}
	return errors.Is(err, syscall.EADDRINUSE)
}

func newSPAHandler(rootDir, indexFile string) http.Handler {
	fileServer := http.FileServer(http.Dir(rootDir))
	indexPath := filepath.Join(rootDir, indexFile)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := path.Clean("/" + r.URL.Path)
		requestPath = strings.TrimPrefix(requestPath, "/")
		fsPath := filepath.Join(rootDir, filepath.FromSlash(requestPath))
		if info, err := os.Stat(fsPath); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}

		http.ServeFile(w, r, indexPath)
	})
}

func withContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extend the default MIME types for known static assets that might be missing.
		if ext := filepath.Ext(r.URL.Path); ext != "" {
			if mime.TypeByExtension(ext) == "" {
				switch strings.ToLower(ext) {
				case ".js":
					mime.AddExtensionType(".js", "application/javascript")
				case ".css":
					mime.AddExtensionType(".css", "text/css")
				case ".svg":
					mime.AddExtensionType(".svg", "image/svg+xml")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
