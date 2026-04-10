package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type rpcReq struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int64         `json:"id"`
}

type rpcResp struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcErr         `json:"error"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	var (
		rpcURL   = flag.String("rpc", "http://127.0.0.1:8545", "HTTP RPC endpoint")
		txFile   = flag.String("tx-file", "", "file containing 0x-prefixed signed raw tx per line")
		workers  = flag.Int("workers", 32, "parallel workers")
		duration = flag.Duration("duration", 30*time.Second, "test duration")
		rate     = flag.Int("rate", 0, "global request rate limit (tx/s), 0 = unlimited")
		timeout  = flag.Duration("timeout", 10*time.Second, "HTTP timeout")
	)
	flag.Parse()

	if *txFile == "" {
		fmt.Fprintln(os.Stderr, "-tx-file is required")
		os.Exit(2)
	}
	if *workers <= 0 {
		fmt.Fprintln(os.Stderr, "-workers must be > 0")
		os.Exit(2)
	}

	txs, err := readTxs(*txFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read tx file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d tx(s) from %s\n", len(txs), *txFile)
	fmt.Printf("RPC=%s workers=%d duration=%s rate=%d tx/s\n", *rpcURL, *workers, *duration, *rate)

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	client := &http.Client{Timeout: *timeout}

	var idx uint64
	var reqID int64
	var sent, httpErrs, rpcAccepted, rpcRejected uint64

	var wg sync.WaitGroup
	start := time.Now()

	var limiter <-chan time.Time
	if *rate > 0 {
		interval := time.Second / time.Duration(*rate)
		if interval < time.Microsecond {
			interval = time.Microsecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		limiter = ticker.C
	}

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if limiter != nil {
					select {
					case <-ctx.Done():
						return
					case <-limiter:
					}
				}

				myIdx := atomic.AddUint64(&idx, 1) - 1
				txHex := txs[int(myIdx%uint64(len(txs)))]
				id := atomic.AddInt64(&reqID, 1)

				reqBody := rpcReq{JSONRPC: "2.0", Method: "eth_sendRawTransaction", Params: []interface{}{txHex}, ID: id}
				payload, _ := json.Marshal(reqBody)
				hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, *rpcURL, bytes.NewReader(payload))
				hreq.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(hreq)
				atomic.AddUint64(&sent, 1)
				if err != nil {
					atomic.AddUint64(&httpErrs, 1)
					continue
				}

				var rr rpcResp
				decodeErr := json.NewDecoder(resp.Body).Decode(&rr)
				resp.Body.Close()
				if decodeErr != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
					atomic.AddUint64(&httpErrs, 1)
					continue
				}

				if rr.Error != nil {
					atomic.AddUint64(&rpcRejected, 1)
				} else {
					atomic.AddUint64(&rpcAccepted, 1)
				}
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if elapsed == 0 {
		elapsed = 1
	}

	fmt.Println("---- RESULT ----")
	fmt.Printf("elapsed_sec=%.3f\n", elapsed)
	fmt.Printf("requests=%d (%.2f req/s)\n", sent, float64(sent)/elapsed)
	fmt.Printf("rpc_accepted=%d (%.2f tx/s)\n", rpcAccepted, float64(rpcAccepted)/elapsed)
	fmt.Printf("rpc_rejected=%d\n", rpcRejected)
	fmt.Printf("http_errors=%d\n", httpErrs)
}

func readTxs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var txs []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "0x") {
			return nil, fmt.Errorf("invalid tx line (must start with 0x): %s", line)
		}
		txs = append(txs, line)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(txs) == 0 {
		return nil, fmt.Errorf("no tx found in file")
	}
	return txs, nil
}
