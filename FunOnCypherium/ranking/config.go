package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIPCPath             = "/root/go/src/github.com/cypherium/cypher/chaindbname/cypher.ipc"
	defaultBasePath            = "/ranking"
	defaultPort                = 4300
	flowCacheTTL               = time.Hour
	defaultAccountScanPageSize = 256
	defaultAccountScanPages    = 40
	defaultRPCRetryAttempts    = 3
	defaultRPCRetryBackoff     = 200 * time.Millisecond
)

var (
	defaultTrackedAddresses = []string{
		"0x559b817584e2e6d3be422e4e2478565eb467d99e",
	}
)

func normalizeBasePath(raw string) string {
	if raw == "" || raw == "/" {
		return ""
	}
	if strings.HasSuffix(raw, "/") {
		return strings.TrimRight(raw, "/")
	}
	return raw
}

func getEnvInt(key string, min int, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("[CONFIG] invalid %s=%q, using %d", key, raw, fallback)
		return fallback
	}
	if value < min {
		log.Printf("[CONFIG] %s=%d below minimum %d, using %d", key, value, min, fallback)
		return fallback
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("[CONFIG] invalid duration %s=%q, using %s", key, raw, fallback)
		return fallback
	}
	if value <= 0 {
		log.Printf("[CONFIG] non-positive duration %s=%s, using %s", key, value, fallback)
		return fallback
	}
	return value
}

func parseAddressList(raw string, fallback []string) []string {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		trimmed := strings.ToLower(strings.TrimSpace(part))
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}

func resolveIPCPath() (path string, source string) {
	if raw, ok := lookupEnvTrim("CYPHER_IPC_PATH"); ok {
		return raw, "env"
	}
	if raw, ok := lookupEnvTrim("CYPHER_DATA_DIR"); ok {
		return filepath.Join(raw, "cypher.ipc"), "data-dir"
	}
	return defaultIPCPath, "default"
}

func lookupEnvTrim(key string) (string, bool) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}
