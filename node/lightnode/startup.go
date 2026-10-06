package lightnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PublicConfiguration enables only the fixed recent-header communication scope.
// It is not a credential and contains no RPC URL, private key or signing role.
type PublicConfiguration struct {
	Enabled           bool    `json:"enabled"`
	ListenAddr        string  `json:"listenAddr"`
	AllowedPageOrigin string  `json:"allowedPageOrigin"`
	Network           Network `json:"network"`
}

type CommonRole struct {
	Ingress, FairHotstuff, Mining, Unlock bool
}

func (r CommonRole) Validate() error {
	// This read-only owned-header overlay does not use TxQUIC transaction
	// forwarding or HTTP/3. Ordinary Common nodes need not enable that bridge.
	if r.Ingress || !r.FairHotstuff || r.Mining || r.Unlock {
		return errors.New("recent-header communication requires a locked, non-mining FairHotstuff Common without TxQUIC ingress")
	}
	return nil
}

// LoadPublicConfiguration performs only a bounded local regular-file read.
// The disabled CLI path must not call it. Links and duplicate JSON keys fail shut.
func LoadPublicConfiguration(path string) (PublicConfiguration, error) {
	var result PublicConfiguration
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return result, errors.New("an absolute canonical public configuration path is required")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return result, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return result, errors.New("linked public configuration path")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if !before.Mode().IsRegular() || before.Size() > 4096 {
		return result, errors.New("public configuration must be a regular file of at most 4096 bytes")
	}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return result, errors.New("public configuration changed before opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return result, errors.New("public configuration exceeds its budget")
	}
	if err := rejectDuplicateJSON(raw); err != nil {
		return result, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 || fields["enabled"] == nil || fields["listenAddr"] == nil || fields["allowedPageOrigin"] == nil || fields["network"] == nil {
		return result, errors.New("exact public configuration keys required")
	}
	var networkFields map[string]json.RawMessage
	if json.Unmarshal(fields["network"], &networkFields) != nil || len(networkFields) != 2 || networkFields["chainId"] == nil || networkFields["genesisHash"] == nil {
		return result, errors.New("exact public network keys required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("trailing public configuration data")
	}
	if !result.Enabled || strings.TrimSpace(result.ListenAddr) != result.ListenAddr || result.ListenAddr == "" || result.AllowedPageOrigin == "" {
		return result, errors.New("explicit enabled public configuration required")
	}
	// New validates the literal loopback address, origin and network without I/O.
	checked, err := New(Config{Enabled: true, ListenAddr: result.ListenAddr,
		AllowedPageOrigin: result.AllowedPageOrigin, ExpectedNetwork: result.Network,
		Factory: func(_ context.Context) (View, error) { return nil, errors.New("configuration validation only") }})
	if err != nil {
		return result, err
	}
	if err := checked.Close(); err != nil {
		return result, err
	}
	return result, nil
}

func rejectDuplicateJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("public configuration nesting exceeds its budget")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate public configuration key")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			return errors.New("public configuration arrays are unsupported")
		default:
			return fmt.Errorf("unexpected public configuration delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing public configuration data")
	}
	return nil
}
