package githubsec

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const testAdvisoryJSON = `{
  "ghsa_id": "GHSA-p28v-f755-9qrg",
  "cve_id": "CVE-2026-73654",
  "url": "https://api.github.com/advisories/GHSA-p28v-f755-9qrg",
  "html_url": "https://github.com/advisories/GHSA-p28v-f755-9qrg",
  "repository_advisory_url": "https://api.github.com/repos/triggerdotdev/trigger.dev/security-advisories/GHSA-p28v-f755-9qrg",
  "summary": "Trigger.dev: Prototype pollution",
  "description": "Summary",
  "type": "reviewed",
  "severity": "high",
  "source_code_location": "https://github.com/triggerdotdev/trigger.dev",
  "identifiers": [
    {"type": "GHSA", "value": "GHSA-p28v-f755-9qrg"},
    {"type": "CVE", "value": "CVE-2026-73654"}
  ],
  "references": [
    "https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-p28v-f755-9qrg"
  ],
  "published_at": "2026-08-13T20:54:11Z",
  "updated_at": "2026-08-13T20:54:13Z",
  "github_reviewed_at": "2026-08-13T20:54:11Z",
  "nvd_published_at": null,
  "withdrawn_at": null,
  "vulnerabilities": [
    {
      "package": {"ecosystem": "npm", "name": "@trigger.dev/core"},
      "vulnerable_version_range": ">= 3.3.8, <= 4.5.5",
      "first_patched_version": "4.5.6",
      "vulnerable_functions": []
    }
  ],
  "cvss_severities": {
    "cvss_v3": {
      "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H",
      "score": 8.5
    },
    "cvss_v4": {
      "vector_string": null,
      "score": 0.0
    }
  },
  "cwes": [
    {"cwe_id": "CWE-1321", "name": "Prototype Pollution"}
  ],
  "credits": [
    {
      "user": {
        "login": "MatiasTilleriasLey",
        "id": 136657682,
        "node_id": "U_kgDOCCU7Eg",
        "avatar_url": "https://avatars.githubusercontent.com/u/136657682?v=4",
        "url": "https://api.github.com/users/MatiasTilleriasLey",
        "html_url": "https://github.com/MatiasTilleriasLey",
        "type": "User",
        "site_admin": false
      },
      "type": "reporter"
    }
  ],
  "cvss": {
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H",
    "score": 8.5
  },
  "epss": {
    "percentage": 0.99999,
    "percentile": 0.99995
  }
}`

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
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

func TestListGlobalAdvisories_SendsAllQueryParams(t *testing.T) {
	t.Parallel()

	var gotQuery string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/advisories" {
			t.Errorf("path = %q, want /advisories", r.URL.Path)
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	})

	withdrawn := true
	filter := GlobalAdvisoryFilter{
		GHSAID:         "GHSA-p28v-f755-9qrg",
		Type:           "reviewed",
		CVEID:          "CVE-2026-73654",
		Ecosystem:      "npm",
		Severity:       "high",
		CWEs:           []CWE{{ID: "CWE-1321"}, {ID: "CWE-79"}},
		IsWithdrawn:    &withdrawn,
		Affects:        []string{"express", "lodash@4.17.21"},
		Published:      "2024-01-01..2024-02-01",
		Updated:        "2024-01-01..2024-02-01",
		Modified:       "2024-03-01..2024-04-01",
		EPSSPercentage: "0.9",
		EPSSPercentile: "0.9",
		Before:         "cursor-before",
		After:          "cursor-after",
		Direction:      "asc",
		Sort:           "published",
		PerPage:        50,
		Page:           2,
	}

	c := NewClient(WithBaseURL(srv.URL))
	if _, err := c.ListGlobalAdvisories(filter); err != nil {
		t.Fatal(err)
	}

	want := url.Values{
		"affects":         {"express,lodash@4.17.21"},
		"after":           {"cursor-after"},
		"before":          {"cursor-before"},
		"cve_id":          {"CVE-2026-73654"},
		"cwes":            {"1321,79"},
		"direction":       {"asc"},
		"ecosystem":       {"npm"},
		"epss_percentage": {"0.9"},
		"epss_percentile": {"0.9"},
		"ghsa_id":         {"GHSA-p28v-f755-9qrg"},
		"is_withdrawn":    {"true"},
		"modified":        {"2024-03-01..2024-04-01"},
		"page":            {"2"},
		"per_page":        {"50"},
		"published":       {"2024-01-01..2024-02-01"},
		"severity":        {"high"},
		"sort":            {"published"},
		"type":            {"reviewed"},
		"updated":         {"2024-01-01..2024-02-01"},
	}.Encode()

	if gotQuery != want {
		t.Fatalf("query = %q, want %q", gotQuery, want)
	}
}

func TestListGlobalAdvisories_CWEsNormalization(t *testing.T) {
	t.Parallel()

	var gotCWEs string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotCWEs = r.URL.Query().Get("cwes")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	})

	c := NewClient(WithBaseURL(srv.URL))
	filter := GlobalAdvisoryFilter{
		CWEs: []CWE{
			{ID: "CWE-1321"},
			{ID: "cwe-79"},
			{ID: "89"},
		},
	}
	if _, err := c.ListGlobalAdvisories(filter); err != nil {
		t.Fatal(err)
	}
	if gotCWEs != "1321,79,89" {
		t.Fatalf("cwes = %q, want %q", gotCWEs, "1321,79,89")
	}
}

func TestListGlobalAdvisories_Non2xx(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Validation failed"}`, http.StatusUnprocessableEntity)
	})

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.ListGlobalAdvisories(GlobalAdvisoryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "422") {
		t.Fatalf("error = %q, want status 422", err)
	}
}

func TestGetGlobalAdvisory_RequestAndUnmarshal(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/advisories/GHSA-p28v-f755-9qrg" {
			t.Errorf("path = %q, want /advisories/GHSA-p28v-f755-9qrg", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testAdvisoryJSON)
	})

	c := NewClient(WithBaseURL(srv.URL))
	adv, err := c.GetGlobalAdvisory("GHSA-p28v-f755-9qrg")
	if err != nil {
		t.Fatal(err)
	}
	assertGlobalAdvisoryFields(t, adv)
}

func TestGetGlobalAdvisory_NotFound(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})

	c := NewClient(WithBaseURL(srv.URL))
	if _, err := c.GetGlobalAdvisory("GHSA-0000-0000-0000"); err == nil {
		t.Fatal("expected error")
	}
}

func assertGlobalAdvisoryFields(t *testing.T, adv *GlobalAdvisory) {
	t.Helper()

	if adv.GHSAID != "GHSA-p28v-f755-9qrg" {
		t.Errorf("GHSAID = %q", adv.GHSAID)
	}
	if adv.CVEID == nil || *adv.CVEID != "CVE-2026-73654" {
		t.Errorf("CVEID = %v", adv.CVEID)
	}
	if adv.URL != "https://api.github.com/advisories/GHSA-p28v-f755-9qrg" {
		t.Errorf("URL = %q", adv.URL)
	}
	if adv.HTMLURL != "https://github.com/advisories/GHSA-p28v-f755-9qrg" {
		t.Errorf("HTMLURL = %q", adv.HTMLURL)
	}
	if adv.RepositoryAdvisoryURL == nil || *adv.RepositoryAdvisoryURL != "https://api.github.com/repos/triggerdotdev/trigger.dev/security-advisories/GHSA-p28v-f755-9qrg" {
		t.Errorf("RepositoryAdvisoryURL = %v", adv.RepositoryAdvisoryURL)
	}
	if adv.Summary != "Trigger.dev: Prototype pollution" {
		t.Errorf("Summary = %q", adv.Summary)
	}
	if adv.Description != "Summary" {
		t.Errorf("Description = %q", adv.Description)
	}
	if adv.Type != "reviewed" {
		t.Errorf("Type = %q", adv.Type)
	}
	if adv.Severity != "high" {
		t.Errorf("Severity = %q", adv.Severity)
	}
	if adv.SourceCodeLocation == nil || *adv.SourceCodeLocation != "https://github.com/triggerdotdev/trigger.dev" {
		t.Errorf("SourceCodeLocation = %v", adv.SourceCodeLocation)
	}
	if len(adv.Identifiers) != 2 || adv.Identifiers[0].Type != "GHSA" || adv.Identifiers[1].Value != "CVE-2026-73654" {
		t.Errorf("Identifiers = %+v", adv.Identifiers)
	}
	if len(adv.References) != 1 || adv.References[0] != "https://github.com/triggerdotdev/trigger.dev/security/advisories/GHSA-p28v-f755-9qrg" {
		t.Errorf("References = %+v", adv.References)
	}
	if want := time.Date(2026, 8, 13, 20, 54, 11, 0, time.UTC); !adv.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", adv.PublishedAt, want)
	}
	if want := time.Date(2026, 8, 13, 20, 54, 13, 0, time.UTC); !adv.UpdatedAt.Equal(want) {
		t.Errorf("UpdatedAt = %v, want %v", adv.UpdatedAt, want)
	}
	if adv.GithubReviewedAt == nil {
		t.Error("GithubReviewedAt = nil, want non-nil")
	}
	if adv.NvdPublishedAt != nil {
		t.Errorf("NvdPublishedAt = %v, want nil", adv.NvdPublishedAt)
	}
	if adv.WithdrawnAt != nil {
		t.Errorf("WithdrawnAt = %v, want nil", adv.WithdrawnAt)
	}

	if len(adv.Vulnerabilities) != 1 {
		t.Fatalf("Vulnerabilities = %+v", adv.Vulnerabilities)
	}
	vuln := adv.Vulnerabilities[0]
	if vuln.Package.Ecosystem != "npm" || vuln.Package.Name != "@trigger.dev/core" {
		t.Errorf("Package = %+v", vuln.Package)
	}
	if vuln.VulnerableVersionRange != ">= 3.3.8, <= 4.5.5" {
		t.Errorf("VulnerableVersionRange = %q", vuln.VulnerableVersionRange)
	}
	if vuln.FirstPatchedVersion == nil || *vuln.FirstPatchedVersion != "4.5.6" {
		t.Errorf("FirstPatchedVersion = %v", vuln.FirstPatchedVersion)
	}
	if vuln.VulnerableFunctions == nil || len(vuln.VulnerableFunctions) != 0 {
		t.Errorf("VulnerableFunctions = %v, want empty slice", vuln.VulnerableFunctions)
	}

	if adv.CVSS == nil || adv.CVSS.VectorString == nil || *adv.CVSS.VectorString != "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H" || adv.CVSS.Score == nil || *adv.CVSS.Score != 8.5 {
		t.Errorf("CVSS = %+v", adv.CVSS)
	}
	if adv.CVSSSeverities == nil || adv.CVSSSeverities.CvssV3 == nil || adv.CVSSSeverities.CvssV3.Score == nil || *adv.CVSSSeverities.CvssV3.Score != 8.5 {
		t.Errorf("CVSSSeverities = %+v", adv.CVSSSeverities)
	}
	if adv.CVSSSeverities.CvssV4 == nil || adv.CVSSSeverities.CvssV4.VectorString != nil || adv.CVSSSeverities.CvssV4.Score == nil || *adv.CVSSSeverities.CvssV4.Score != 0 {
		t.Errorf("CvssV4 = %+v", adv.CVSSSeverities.CvssV4)
	}
	if adv.EPSS == nil || adv.EPSS.Percentage != 0.99999 || adv.EPSS.Percentile != 0.99995 {
		t.Errorf("EPSS = %+v", adv.EPSS)
	}
	if len(adv.CWEs) != 1 || adv.CWEs[0].ID != "CWE-1321" || adv.CWEs[0].Name != "Prototype Pollution" {
		t.Errorf("CWEs = %+v", adv.CWEs)
	}
	if len(adv.Credits) != 1 || adv.Credits[0].User == nil || adv.Credits[0].User.Login != "MatiasTilleriasLey" || adv.Credits[0].Type != "reporter" {
		t.Errorf("Credits = %+v", adv.Credits)
	}
}

func TestListGlobalAdvisories_Live(t *testing.T) {
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
	if got[0].GHSAID == "" || got[0].Type == "" || got[0].Severity == "" {
		t.Fatalf("incomplete advisory: %+v", got[0])
	}
}

func TestGetGlobalAdvisory_Live(t *testing.T) {
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

func TestGlobalAdvisories_AllTypes_Live(t *testing.T) {
	if os.Getenv("LIVE_TESTS") != "1" {
		t.Skip("set LIVE_TESTS=1")
	}

	c := NewClient()
	for _, typ := range []string{"reviewed", "malware", "unreviewed"} {
		got, err := c.ListGlobalAdvisories(GlobalAdvisoryFilter{Type: typ, PerPage: 2})
		if err != nil {
			t.Fatalf("type %s: %v", typ, err)
		}
		if len(got) == 0 {
			t.Fatalf("type %s: no advisories returned", typ)
		}
		for _, adv := range got {
			if adv.Type != typ {
				t.Fatalf("type %s: got advisory type %q", typ, adv.Type)
			}
			if adv.GHSAID == "" {
				t.Fatalf("type %s: empty GHSAID in %+v", typ, adv)
			}
		}
	}
}
