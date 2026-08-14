package githubsec

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://api.github.com"
	DefaultTimeout = 30 * time.Second
)

type Client struct {
	httpClient *http.Client
	baseURL    string
}

type Option func(*Client)

type GlobalAdvisory struct {
	GHSAID                string          `json:"ghsa_id"`
	CVEID                 *string         `json:"cve_id"`
	URL                   string          `json:"url"`
	HTMLURL               string          `json:"html_url"`
	RepositoryAdvisoryURL *string         `json:"repository_advisory_url"`
	Summary               string          `json:"summary"`
	Description           string          `json:"description"`
	Type                  string          `json:"type"`
	Severity              string          `json:"severity"`
	SourceCodeLocation    *string         `json:"source_code_location"`
	Identifiers           []Identifier    `json:"identifiers"`
	References            []string        `json:"references"`
	PublishedAt           time.Time       `json:"published_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	GithubReviewedAt      *time.Time      `json:"github_reviewed_at"`
	NvdPublishedAt        *time.Time      `json:"nvd_published_at"`
	WithdrawnAt           *time.Time      `json:"withdrawn_at"`
	Vulnerabilities       []Vulnerability `json:"vulnerabilities"`
	CVSS                  *CVSS           `json:"cvss"`
	CVSSSeverities        *CVSSSeverities `json:"cvss_severities"`
	EPSS                  *EPSS           `json:"epss"`
	CWEs                  []CWE           `json:"cwes"`
	Credits               []Credit        `json:"credits"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type CWE struct {
	ID   string `json:"cwe_id"`
	Name string `json:"name"`
}

type CVSS struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

type CVSSSeverities struct {
	CvssV3 *CVSS `json:"cvss_v3"`
	CvssV4 *CVSS `json:"cvss_v4"`
}

type EPSS struct {
	Percentage float64 `json:"percentage"`
	Percentile float64 `json:"percentile"`
}

type Vulnerability struct {
	Package                Package  `json:"package"`
	VulnerableVersionRange string   `json:"vulnerable_version_range"`
	FirstPatchedVersion    *string  `json:"first_patched_version"`
	VulnerableFunctions    []string `json:"vulnerable_functions"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Credit struct {
	User *User  `json:"user"`
	Type string `json:"type"`
}

type User struct {
	Login        string `json:"login"`
	ID           int64  `json:"id"`
	NodeID       string `json:"node_id"`
	AvatarURL    string `json:"avatar_url"`
	URL          string `json:"url"`
	HTMLURL      string `json:"html_url"`
	Type         string `json:"type"`
	SiteAdmin    bool   `json:"site_admin"`
	UserViewType string `json:"user_view_type,omitempty"`
}

type GlobalAdvisoryFilter struct {
	GHSAID         string
	CVEID          string
	Type           string
	Ecosystem      string
	Severity       string
	CWEs           []CWE
	IsWithdrawn    *bool
	Affects        []string
	Published      string
	Updated        string
	Modified       string
	EPSSPercentage string
	EPSSPercentile string
	Before         string
	After          string
	Direction      string
	Sort           string
	PerPage        int
	Page           int
}

func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

func WithBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.baseURL = baseURL }
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) ListGlobalAdvisories(filter GlobalAdvisoryFilter) ([]GlobalAdvisory, error) {
	params := url.Values{}

	if filter.GHSAID != "" {
		params.Set("ghsa_id", filter.GHSAID)
	}
	if filter.Type != "" {
		params.Set("type", filter.Type)
	}
	if filter.CVEID != "" {
		params.Set("cve_id", filter.CVEID)
	}
	if filter.Ecosystem != "" {
		params.Set("ecosystem", filter.Ecosystem)
	}
	if filter.Severity != "" {
		params.Set("severity", filter.Severity)
	}
	if len(filter.CWEs) > 0 {
		params.Set("cwes", joinCWEs(filter.CWEs))
	}
	if filter.IsWithdrawn != nil {
		params.Set("is_withdrawn", strconv.FormatBool(*filter.IsWithdrawn))
	}
	if len(filter.Affects) > 0 {
		params.Set("affects", strings.Join(filter.Affects, ","))
	}
	if filter.Published != "" {
		params.Set("published", filter.Published)
	}
	if filter.Updated != "" {
		params.Set("updated", filter.Updated)
	}
	if filter.Modified != "" {
		params.Set("modified", filter.Modified)
	}
	if filter.EPSSPercentage != "" {
		params.Set("epss_percentage", filter.EPSSPercentage)
	}
	if filter.EPSSPercentile != "" {
		params.Set("epss_percentile", filter.EPSSPercentile)
	}
	if filter.Before != "" {
		params.Set("before", filter.Before)
	}
	if filter.After != "" {
		params.Set("after", filter.After)
	}
	if filter.Direction != "" {
		params.Set("direction", filter.Direction)
	}
	if filter.Sort != "" {
		params.Set("sort", filter.Sort)
	}
	if filter.PerPage > 0 {
		params.Set("per_page", strconv.Itoa(filter.PerPage))
	}
	if filter.Page > 0 {
		params.Set("page", strconv.Itoa(filter.Page))
	}

	var result []GlobalAdvisory
	err := c.request("GET", "/advisories", params, &result)
	return result, err
}

func (c *Client) GetGlobalAdvisory(ghsaID string) (*GlobalAdvisory, error) {
	var result GlobalAdvisory
	err := c.request("GET", "/advisories/"+url.PathEscape(ghsaID), nil, &result)
	return &result, err
}

func joinCWEs(cwes []CWE) string {
	ids := make([]string, 0, len(cwes))
	for _, cwe := range cwes {
		id := strings.TrimSpace(cwe.ID)
		id = strings.TrimPrefix(strings.ToUpper(id), "CWE-")
		if id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

func (c *Client) request(method, path string, params url.Values, result interface{}) error {
	reqURL := c.baseURL + path
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	if result != nil {
		return json.Unmarshal(body, result)
	}
	return nil
}
