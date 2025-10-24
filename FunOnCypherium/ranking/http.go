package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *rankingServer) staticDirectories() (string, string) {
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}

	var callerDir string
	if _, filename, _, ok := runtime.Caller(0); ok {
		callerDir = filepath.Dir(filename)
	}

	publicCandidates := []string{
		filepath.Join(wd, "public"),
		filepath.Join(wd, "ranking", "public"),
	}
	sharedCandidates := []string{
		filepath.Join(wd, "shared"),
		filepath.Join(wd, "..", "shared"),
	}

	if callerDir != "" {
		publicCandidates = append(publicCandidates,
			filepath.Join(callerDir, "public"),
			filepath.Join(filepath.Dir(callerDir), "public"),
		)
		sharedCandidates = append(sharedCandidates,
			filepath.Join(filepath.Dir(callerDir), "shared"),
			filepath.Join(filepath.Dir(filepath.Dir(callerDir)), "shared"),
		)
	}

	publicDir := firstExistingDir(publicCandidates...)
	sharedDir := firstExistingDir(sharedCandidates...)

	return publicDir, sharedDir
}

func firstExistingDir(paths ...string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	if len(paths) > 0 {
		return paths[len(paths)-1]
	}
	return "."
}

func (s *rankingServer) buildMux() http.Handler {
	publicDir, sharedDir := s.staticDirectories()
	apiHandler := s.withCORS(s.apiHandler())

	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", apiHandler))
	mux.Handle("/shared/", http.StripPrefix("/shared", http.FileServer(http.Dir(sharedDir))))
	mux.HandleFunc("/admin/backfill/7d", s.handleAdminBackfill)

	spa := spaHandler{publicDir: publicDir}
	mux.Handle("/", spa)

	if s.basePath != "" {
		apiPrefix := s.basePath + "/api"
		sharedPrefix := s.basePath + "/shared"
		mux.Handle(apiPrefix+"/", http.StripPrefix(apiPrefix, apiHandler))
		mux.Handle(sharedPrefix+"/", http.StripPrefix(sharedPrefix, http.FileServer(http.Dir(sharedDir))))
		mux.HandleFunc(s.basePath+"/admin/backfill/7d", s.handleAdminBackfill)
		mux.Handle(s.basePath, spa)
		mux.Handle(s.basePath+"/", http.StripPrefix(s.basePath, spa))
	}

	return mux
}

type spaHandler struct {
	publicDir string
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := filepath.Clean(r.URL.Path)
	if strings.HasPrefix(path, "../") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	candidate := filepath.Join(h.publicDir, path)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		http.ServeFile(w, r, candidate)
		return
	}

	indexPath := filepath.Join(h.publicDir, "index.html")
	http.ServeFile(w, r, indexPath)
}

func (s *rankingServer) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *rankingServer) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/wallet/", s.handleWallet)
	mux.HandleFunc("/ranking", s.handleRanking)
	mux.HandleFunc("/total-wallets", s.handleTotalWallets)
	mux.HandleFunc("/total-supply", s.handleTotalSupply)
	mux.HandleFunc("/latest-block", s.handleLatestBlock)
	mux.HandleFunc("/metrics", s.handleMetrics)
	return mux
}

func (s *rankingServer) handleWallet(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/wallet/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "address required", http.StatusBadRequest)
		return
	}

	address := strings.ToLower(parts[0])
	if len(parts) > 1 {
		switch parts[1] {
		case "flows":
			s.handleWalletFlows(w, r, address)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	wallet := s.walletStore.get(address)
	if wallet == nil {
		balance, err := s.fetchBalance(ctx, address)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		wallet = s.walletStore.upsert(address, balance)
	}

	if wallet == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"address": wallet.Address,
		"balance": wallet.Balance.String(),
	})
}

func (s *rankingServer) handleWalletFlows(w http.ResponseWriter, r *http.Request, address string) {
	if nocache := r.URL.Query().Get("nocache"); nocache == "1" {
		s.flowCacheMu.Lock()
		delete(s.flowCache, address)
		s.flowCacheMu.Unlock()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	summary, err := s.getFlowSummary(ctx, address)
	if err != nil {
		log.Printf("[API] flow summary error for %s: %v", address, err)
		http.Error(w, "Unable to compute wallet flows", http.StatusInternalServerError)
		return
	}

	payload := map[string]interface{}{
		"address":         address,
		"generatedAt":     summary.GeneratedAt.Format(time.RFC3339),
		"generatedAtUnix": summary.GeneratedAtUnix,
		"generatedAtUtc":  summary.GeneratedAtUTC,
		"flows":           summary.Flows,
	}

	respondJSON(w, http.StatusOK, payload)
}

func (s *rankingServer) handleRanking(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 10
	}

	wallets := s.walletStore.nonZero()
	sort.Slice(wallets, func(i, j int) bool {
		diff := new(big.Int).Sub(wallets[j].Balance, wallets[i].Balance)
		if diff.Sign() != 0 {
			return diff.Sign() < 0
		}
		return wallets[i].Address < wallets[j].Address
	})

	total := len(wallets)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	selected := wallets[start:end]
	response := make([]map[string]string, 0, len(selected))
	for _, wlt := range selected {
		response = append(response, map[string]string{
			"address": wlt.Address,
			"balance": wlt.Balance.String(),
		})

		s.queueAddressBackfill(wlt.Address)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"wallets":    response,
		"totalPages": pages(total, limit),
	})
}

func (s *rankingServer) handleTotalWallets(w http.ResponseWriter, _ *http.Request) {
	writePlain(w, http.StatusOK, strconv.Itoa(s.walletStore.countNonZero()))
}

func (s *rankingServer) handleTotalSupply(w http.ResponseWriter, _ *http.Request) {
	total := s.walletStore.totalBalance()
	writePlain(w, http.StatusOK, formatWei(total, 4))
}

func (s *rankingServer) handleLatestBlock(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	blockNumber, err := s.getBlockNumber(ctx)
	if err != nil {
		http.Error(w, "failed to fetch block", http.StatusInternalServerError)
		return
	}
	writePlain(w, http.StatusOK, blockNumber.String())
}

func (s *rankingServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.metrics.snapshot()
	scanSnapshot := s.accountScan.snapshot()
	snapshot.AccountScanCursor = scanSnapshot.Cursor
	snapshot.AccountScanCycleStartedAt = scanSnapshot.CycleStartedAt
	respondJSON(w, http.StatusOK, snapshot)
}

func pages(total, limit int) int {
	if limit <= 0 {
		return 0
	}
	if total == 0 {
		return 0
	}
	return (total + limit - 1) / limit
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[HTTP] failed to encode response: %v", err)
	}
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		log.Printf("[HTTP] failed to write response: %v", err)
	}
}

func durationToMillis(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return d.Milliseconds()
}

func formatWei(value *big.Int, decimals int) string {
	if value == nil {
		return "0"
	}

	sign := ""
	abs := new(big.Int).Set(value)
	if abs.Sign() < 0 {
		sign = "-"
		abs.Neg(abs)
	}

	base := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(18), nil)
	intPart := big.NewInt(0).Quo(abs, base)
	if decimals <= 0 {
		return sign + intPart.String()
	}

	remainder := big.NewInt(0).Mod(abs, base)
	scale := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(int64(decimals+1)), nil)
	scaled := big.NewInt(0).Mul(remainder, scale)
	scaled.Quo(scaled, base)

	roundDigit := new(big.Int).Mod(scaled, big.NewInt(10))
	scaled.Quo(scaled, big.NewInt(10))
	if roundDigit.Cmp(big.NewInt(5)) >= 0 {
		scaled.Add(scaled, big.NewInt(1))
	}

	limit := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	if scaled.Cmp(limit) >= 0 {
		intPart.Add(intPart, big.NewInt(1))
		scaled.Sub(scaled, limit)
	}

	decimalStr := fmt.Sprintf("%0*d", decimals, scaled)
	return fmt.Sprintf("%s%s.%s", sign, intPart.String(), decimalStr)
}

func weiToCphString(value *big.Int) string {
	if value == nil {
		return "0"
	}
	sign := ""
	abs := new(big.Int).Set(value)
	if abs.Sign() < 0 {
		sign = "-"
		abs.Neg(abs)
	}

	base := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(18), nil)
	intPart := big.NewInt(0).Quo(abs, base)
	remainder := big.NewInt(0).Mod(abs, base)
	if remainder.Sign() == 0 {
		return sign + intPart.String()
	}

	decimal := fmt.Sprintf("%018s", remainder.String())
	decimal = strings.TrimRight(decimal, "0")
	if decimal == "" {
		return sign + intPart.String()
	}
	return fmt.Sprintf("%s%s.%s", sign, intPart.String(), decimal)
}

func (s *rankingServer) handleAdminBackfill(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	if err := s.backfillLastNDays(ctx, 7); err != nil {
		log.Printf("[ADMIN] backfill 7d failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
