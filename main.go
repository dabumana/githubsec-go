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

type GlobalAdvisory struct {
	ID                  string          `json:"id"`
	GHSAID              string          `json:"ghsa_id"`
	CVEID               string          `json:"cve_id"`
	URL                 string          `json:"url"`
	HTMLURL             string          `json:"html_url"`
	Repository          *Repository     `json:"repository"`
	Summary             string          `json:"summary"`
	Description         string          `json:"description"`
	Severity            string          `json:"severity"`
	CVSS                *CVSS           `json:"cvss"`
	CWEs                []string        `json:"cwes"`
	Identifiers         []Identifier    `json:"identifiers"`
	References          []Reference     `json:"references"`
	PublishedAt         time.Time       `json:"published_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	WithdrawnAt         *time.Time      `json:"withdrawn_at"`
	Vulnerabilities     []Vulnerability `json:"vulnerabilities"`
	FirstPatchedVersion *VersionInfo    `json:"first_patched_version"`
}

type Repository struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	URL      string `json:"url"`
}

type CVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
	Severity     string  `json:"severity"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Reference struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type Vulnerability struct {
	Package                Package      `json:"package"`
	VulnerableVersionRange string       `json:"vulnerable_version_range"`
	FirstPatchedVersion    *VersionInfo `json:"first_patched_version"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type VersionInfo struct {
	Identifier string `json:"identifier"`
}

type GlobalAdvisoryFilter struct {
	GHSAID      string
	CVEID       string
	Type        string
	Ecosystem   string
	Severity    string
	CWEs        []string
	IsWithdrawn *bool
	Affects     []string
	Published   string
	Updated     string
	PerPage     int
	Page        int
}

func (c *Client) ListGlobalAdvisories(filter GlobalAdvisoryFilter) ([]GlobalAdvisory, error) {
	params := url.Values{}

	if filter.GHSAID != "" {
		params.Set("ghsa_id", filter.GHSAID)
	}
	if filter.CVEID != "" {
		params.Set("cve_id", filter.CVEID)
	}
	if filter.Type != "" {
		params.Set("type", filter.Type)
	}
	if filter.Ecosystem != "" {
		params.Set("ecosystem", filter.Ecosystem)
	}
	if filter.Severity != "" {
		params.Set("severity", filter.Severity)
	}
	if len(filter.CWEs) > 0 {
		params.Set("cwes", strings.Join(filter.CWEs, ","))
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
	err := c.request("GET", "/advisories/"+ghsaID, nil, &result)
	return &result, err
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
