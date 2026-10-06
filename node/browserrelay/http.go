// SPDX-License-Identifier: LGPL-3.0-or-later
package browserrelay

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// NewHandler serves already materialized public objects to a local gateway.
// The owner must bind it to the private Unix socket: this is not the public
// browser session/signaling server. Requests never open a database snapshot.
func NewHandler(source *Exporter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		write := func(status int, value any) {
			raw, err := json.Marshal(value)
			if err != nil || len(raw)+1 > MaxEnvelopeBytes {
				status, raw = http.StatusInternalServerError, []byte(`{"error":"encoding_failed"}`)
			}
			w.WriteHeader(status)
			if r.Method != http.MethodHead {
				_, _ = w.Write(append(raw, '\n'))
			}
		}
		fail := func(status int, code string) {
			write(status, struct {
				Error string `json:"error"`
			}{code})
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
			fail(http.StatusBadRequest, "invalid_request")
			return
		}
		if source == nil {
			fail(http.StatusServiceUnavailable, "source_unavailable")
			return
		}
		switch {
		case r.URL.Path == "/relay/v1/source-config":
			write(http.StatusOK, source.SourceConfiguration())
		case r.URL.Path == "/relay/v1/source-status":
			write(http.StatusOK, source.Status())
		case r.URL.Path == "/relay/v1/head":
			envelope, err := source.Head()
			if err != nil {
				w.Header().Set("Retry-After", "2")
				fail(http.StatusServiceUnavailable, "source_unavailable")
				return
			}
			write(http.StatusOK, envelope)
		case strings.HasPrefix(r.URL.Path, "/relay/v1/headers/"):
			digest := strings.TrimPrefix(r.URL.Path, "/relay/v1/headers/")
			if len(digest) != 64 || strings.IndexFunc(digest, func(r rune) bool {
				return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
			}) >= 0 {
				fail(http.StatusBadRequest, "invalid_digest")
				return
			}
			packet, err := source.Header(digest)
			if err != nil {
				if errors.Is(err, ErrNotInWindow) {
					fail(http.StatusNotFound, "not_in_window")
				} else {
					w.Header().Set("Retry-After", "2")
					fail(http.StatusServiceUnavailable, "source_unavailable")
				}
				return
			}
			write(http.StatusOK, packet)
		default:
			fail(http.StatusNotFound, "not_found")
		}
	})
}
