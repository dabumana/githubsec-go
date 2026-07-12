package githubsec

import (
	"os"
	"testing"
	"net/http"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestNewClient_Defaults(t *testing.T) {
	t.Parallel()

	c := NewClient()
	if c == nil {
		t.Fatal("nil client")
	}
	if c.baseURL != DefaultBaseURL {
		t.Fatalf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c.httpClient == nil {
		t.Fatal("nil httpClient")
	}
}

func TestWithHTTPClient_Option(t *testing.T) {
	t.Parallel()

	hc := &http.Client{}
	c := NewClient(WithHTTPClient(hc))
	if c.httpClient != hc {
		t.Fatal("WithHTTPClient not applied")
	}
}

func TestWithBaseURL_Option(t *testing.T) {
	t.Parallel()

	want := "https://example.com"
	c := NewClient(WithBaseURL(want))
	if c.baseURL != want {
		t.Fatalf("baseURL = %q, want %q", c.baseURL, want)
	}
}

func TestListGlobalAdvisories(t *testing.T) {
	t.Parallel()
	if os.Getenv("LIVE_TESTS") != "1" {
		t.Skip("set LIVE_TESTS=1")
	}

	c := NewClient()
	got, err := c.ListGlobalAdvisories(GlobalAdvisoryFilter{PerPage: 1, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected advisories")
	}
}

func TestGetGlobalAdvisory(t *testing.T) {
	t.Parallel()
	if os.Getenv("LIVE_TESTS") != "1" {
		t.Skip("set LIVE_TESTS=1")
	}

	c := NewClient()
	list, err := c.ListGlobalAdvisories(GlobalAdvisoryFilter{PerPage: 1, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("no advisories returned")
	}

	got, err := c.GetGlobalAdvisory(list[0].GHSAID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil advisory")
	}
	if got.GHSAID != list[0].GHSAID {
		t.Fatalf("ghsa_id = %q, want %q", got.GHSAID, list[0].GHSAID)
	}
}
