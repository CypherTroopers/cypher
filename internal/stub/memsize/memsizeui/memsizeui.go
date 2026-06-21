package memsizeui

import "net/http"

// Handler is a no-op replacement for github.com/fjl/memsize/memsizeui.Handler.
// The original package uses runtime internals and does not link on newer Go versions.
type Handler struct{}

// Add keeps compatibility with the original memsizeui.Handler API.
// It intentionally does nothing.
func (h Handler) Add(name string, v interface{}) {}

// ServeHTTP keeps compatibility with http.Handler.
// The memsize debug UI is disabled in this build.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "memsize debug UI is disabled in this build", http.StatusNotImplemented)
}
