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
	"sort"
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
		rpcURL       = flag.String("rpc", "http://127.0.0.1:8545", "HTTP RPC endpoint")
		txFile       = flag.String("tx-file", "", "file containing 0x-prefixed signed raw tx per line")
		workers      = flag.Int("workers", 32, "parallel workers")
		duration     = flag.Duration("duration", 30*time.Second, "test duration")
		rate         = flag.Int("rate", 0, "global request rate limit (tx/s), 0 = unlimited")
		timeout      = flag.Duration("timeout", 10*time.Second, "HTTP timeout")
		showTop      = flag.Int("show-top", 10, "show top N reject reasons / HTTP statuses")
		noReuse      = flag.Bool("no-reuse", false, "send each tx at most once; stop after tx-file is exhausted")
		stopOnAccept = flag.Bool("stop-on-accept-exhaust", false, "with -no-reuse, stop the whole run once all txs have been attempted")
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
	fmt.Printf("RPC=%s workers=%d duration=%s rate=%d tx/s no_reuse=%v\n", *rpcURL, *workers, *duration, *rate, *noReuse)

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

	var errMu sync.Mutex
	rejectReasons := make(map[string]uint64)
	httpStatusCounts := make(map[int]uint64)
	httpErrorTexts := make(map[string]uint64)

	recordReject := func(msg string) {
		msg = normalizeReject(msg)
		errMu.Lock()
		rejectReasons[msg]++
		errMu.Unlock()
	}

	recordHTTPStatus := func(code int) {
		errMu.Lock()
		httpStatusCounts[code]++
		errMu.Unlock()
	}

	recordHTTPErrorText := func(msg string) {
		msg = strings.TrimSpace(msg)
		if msg == "" {
			msg = "(empty error)"
		}
		errMu.Lock()
		httpErrorTexts[msg]++
		errMu.Unlock()
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
				if *noReuse && myIdx >= uint64(len(txs)) {
					if *stopOnAccept {
						cancel()
					}
					return
				}

				txHex := txs[int(myIdx%uint64(len(txs)))]
				id := atomic.AddInt64(&reqID, 1)

				reqBody := rpcReq{
					JSONRPC: "2.0",
					Method:  "eth_sendRawTransaction",
					Params:  []interface{}{txHex},
					ID:      id,
				}

				payload, err := json.Marshal(reqBody)
				if err != nil {
					atomic.AddUint64(&httpErrs, 1)
					recordHTTPErrorText("marshal rpc request failed: " + err.Error())
					continue
				}

				hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, *rpcURL, bytes.NewReader(payload))
				if err != nil {
					atomic.AddUint64(&httpErrs, 1)
					recordHTTPErrorText("build http request failed: " + err.Error())
					continue
				}
				hreq.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(hreq)
				atomic.AddUint64(&sent, 1)

				if err != nil {
					atomic.AddUint64(&httpErrs, 1)
					recordHTTPErrorText(err.Error())
					continue
				}

				var rr rpcResp
				decodeErr := json.NewDecoder(resp.Body).Decode(&rr)
				resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					atomic.AddUint64(&httpErrs, 1)
					recordHTTPStatus(resp.StatusCode)
					continue
				}

				if decodeErr != nil {
					atomic.AddUint64(&httpErrs, 1)
					recordHTTPErrorText("decode response failed: " + decodeErr.Error())
					continue
				}

				if rr.Error != nil {
					atomic.AddUint64(&rpcRejected, 1)
					recordReject(rr.Error.Message)
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

	printTopRejects("Top RPC reject reasons", rejectReasons, *showTop)
	printTopStatus("Top HTTP status codes", httpStatusCounts, *showTop)
	printTopRejects("Top HTTP/client errors", httpErrorTexts, *showTop)
}

func readTxs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var txs []string
	s := bufio.NewScanner(f)

	// Allow long raw transaction lines.
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 4*1024*1024)

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

func normalizeReject(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "(empty rpc error)"
	}

	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "already known"):
		return "already known"
	case strings.Contains(lower, "nonce too low"):
		return "nonce too low"
	case strings.Contains(lower, "replacement transaction underpriced"):
		return "replacement transaction underpriced"
	case strings.Contains(lower, "underpriced"):
		return "underpriced"
	case strings.Contains(lower, "insufficient funds"):
		return "insufficient funds"
	case strings.Contains(lower, "invalid sender"):
		return "invalid sender"
	case strings.Contains(lower, "intrinsic gas too low"):
		return "intrinsic gas too low"
	case strings.Contains(lower, "txpool is full"):
		return "txpool is full"
	case strings.Contains(lower, "rlp:"):
		return msg
	default:
		return msg
	}
}

func printTopRejects(title string, m map[string]uint64, topN int) {
	fmt.Println("---- " + title + " ----")
	if len(m) == 0 {
		fmt.Println("(none)")
		return
	}

	type kv struct {
		Key string
		Val uint64
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{Key: k, Val: v})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Val == items[j].Val {
			return items[i].Key < items[j].Key
		}
		return items[i].Val > items[j].Val
	})

	if topN <= 0 || topN > len(items) {
		topN = len(items)
	}
	for i := 0; i < topN; i++ {
		fmt.Printf("%d\t%s\n", items[i].Val, items[i].Key)
	}
}

func printTopStatus(title string, m map[int]uint64, topN int) {
	fmt.Println("---- " + title + " ----")
	if len(m) == 0 {
		fmt.Println("(none)")
		return
	}

	type kv struct {
		Key int
		Val uint64
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{Key: k, Val: v})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Val == items[j].Val {
			return items[i].Key < items[j].Key
		}
		return items[i].Val > items[j].Val
	})

	if topN <= 0 || topN > len(items) {
		topN = len(items)
	}
	for i := 0; i < topN; i++ {
		fmt.Printf("%d\tHTTP %d\n", items[i].Val, items[i].Key)
	}
}
