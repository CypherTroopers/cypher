package finance

import (
	"errors"
	"net/url"
	"testing"

	"github.com/cypherium/cypher/dex/consensus"
	"github.com/cypherium/cypher/dex/service"
)

func TestCertifiedQueryExplicitSelectedAncestry(t *testing.T) {
	for _, tc := range []struct {
		query             string
		selected, invalid bool
	}{
		{"height=54", false, false},
		{"height=54&selected=false", false, false},
		{"height=54&selected=true", true, false},
		{"height=54&selected=true&selected=false", false, true},
		{"height=54&selected=true&selected=true", false, true},
		{"height=54&selected=1", false, true},
		{"height=54&selected=True", false, true},
		{"height=54&selected=", false, true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			values, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			got, err := selectedCertifiedQuery(values)
			if (err != nil) != tc.invalid || got != tc.selected {
				t.Fatalf("selection %v error %v", got, err)
			}
		})
	}
}

func TestFinancialFactoryFullQueryAllowsSelectedOnlyForCertified(t *testing.T) {
	var cfg service.Config
	configureFinancialQuery(&cfg, 105, nil, nil, nil, nil, nil)
	// No certified body exists in this read-only actor. Reaching the ordinary
	// unavailable response (and certified response envelope) proves the full
	// factory route passed its outer keys guard and called the consensus read.
	actor := new(consensus.Application)
	for _, query := range []string{"height=84", "height=84&selected=false", "height=84&selected=true"} {
		values, _ := url.ParseQuery(query)
		response, err := cfg.Query(actor, "/v1/certified", values)
		if !errors.Is(err, consensus.ErrUnavailable) || response == nil {
			t.Fatalf("full certified route %q rejected before data lookup: %v", query, err)
		}
	}
	for _, tc := range []struct{ path, query string }{
		{"/v1/certified", "height=84&selected=true&other=1"},
		{"/v1/certified", "height=84&other=true"},
		{"/v1/certified", "height=84&selected=true&selected=false"},
		{"/v1/certified", "height=84&selected=1"},
		{"/v1/settlement", "height=84&selected=true"},
		{"/v1/checkpoint", "height=84&selected=true"},
		{"/v1/snapshot", "height=84&selected=true"},
		{"/v1/participation", "height=84&selected=true"},
		{"/v1/action-status", "id=01&selected=true"},
	} {
		values, _ := url.ParseQuery(tc.query)
		response, err := cfg.Query(actor, tc.path, values)
		if err == nil || errors.Is(err, consensus.ErrUnavailable) || response != nil {
			t.Fatalf("noncanonical query passed guard: %s %s response=%v error=%v", tc.path, tc.query, response, err)
		}
	}
}
