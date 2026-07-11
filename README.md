# GitHub Security Advisories - Go Client

A Go client for the GitHub Global Security Advisories API, a public feed of security advisories that affect open source ecosystems (npm, Maven, Go, etc.).
This package allows you to list and retrieve advisory metadata without authentication (public data only).

---

## Installation

```bash
go get github.com/dabumana/githubsec-go
```

Replace with your actual module path if publishing.

### Quick Start

```go
package main

import (
    "fmt"
    "log"
    "github.com/dabumana/githubsec-go"
)

func main() {
    client := github.NewClient()
    advisories, err := client.ListGlobalAdvisories(github.GlobalAdvisoryFilter{})
    if err != nil {
        log.Fatal(err)
    }
    for _, adv := range advisories {
        fmt.Printf("%s: %s (severity: %s)\n", adv.GHSAID, adv.Summary, adv.Severity)
    }
}
```

## Authentication

This client uses the public GitHub API. It does not require an authentication token.

However, unauthenticated requests are limited to 60 per hour. If you need higher limits, you can supply a token by setting the Authorization header via a custom HTTP client (see Client Configuration below).

### Client Configuration

You can customise the client with optional Option functions:

### Option Description
* **WithHTTPClient(http.Client)** Use a custom HTTP client (e.g., to add an Authorization header for a token).
* **WithBaseURL(string)** Override the base URL (useful for testing or GitHub Enterprise).

Example with token:

```go
customClient := &http.Client{
    Transport: &customTransport{token: "your_token"},
}
client := github.NewClient(
    github.WithHTTPClient(customClient),
)
```

You would need to implement a custom http.RoundTripper to inject the token header.

## API Methods

|Method | Description|
|-------|------------|
|ListGlobalAdvisories(filter GlobalAdvisoryFilter) ([]GlobalAdvisory, error) | List advisories matching the filter.|
|GetGlobalAdvisory(ghsaID string) (*GlobalAdvisory, error) | Retrieve a single advisory by its GHSA ID (e.g., GHSA-xxxx-xxxx-xxxx).|

### Data Types

* GlobalAdvisory - The full advisory object, containing:
  * ID, GHSAID, CVEID - identifiers.
  * Summary, Description - text.
  * Severity - "critical", "high", etc.
  * CVSS - score and vector.
  * CWEs - list of CWE IDs.
  * PublishedAt, UpdatedAt, WithdrawnAt - timestamps.
  * Vulnerabilities - slice of affected packages and version ranges.
  * FirstPatchedVersion - if available.
* Repository - optional, if the advisory is tied to a specific repo.
* Vulnerability - details of a vulnerable package.
* GlobalAdvisoryFilter - struct for filtering listings (see below).

### Filtering (GlobalAdvisoryFilter)

The ListGlobalAdvisories method accepts a filter struct with the following optional fields:

|Field | Type | Description|
|------|------|------------|
|GHSAID | string | Exact GHSA ID (e.g., GHSA-xxxx).|
|CVEID | string | Exact CVE ID (e.g., CVE-2024-xxxx).|
|Type | string | Advisory type: "reviewed", "unreviewed", "malicious".|
|Ecosystem | string | Package ecosystem: "npm", "maven", "go", etc.|
|Severity | string | "critical", "high", "medium", "low".|
|CWEs | []string | Filter by CWE IDs (e.g., ["CWE-79", "CWE-89"]).|
|IsWithdrawn | *bool | Whether the advisory is withdrawn.|
|Affects | []string | Package names to match (e.g., ["lodash", "express"]).|
|Published | string | Date range in the format YYYY-MM-DD..YYYY-MM-DD.|
|Updated | string | Same as Published but for the updated_at field.|
|PerPage | int | Results per page (max 100).|
|Page | int | Page number for pagination.|

All text filters are exact (case‑sensitive for GHSA/CVE IDs; ecosystem and severity are case‑insensitive in practice).

### Error Handling

The client returns standard Go errors.
Common errors:

* Network issues.
* HTTP status non‑200 (e.g., 404 for invalid GHSA ID).
* JSON unmarshalling failures.

Check err != nil and optionally inspect the error string.

### Examples

1. List All Recent Advisories

```go
client := github.NewClient()
advs, err := client.ListGlobalAdvisories(github.GlobalAdvisoryFilter{})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d advisories\n", len(advs))
```

2. Get a Specific Advisory by GHSA ID

```go
adv, err := client.GetGlobalAdvisory("GHSA-6f4v-2c7q-3m9p")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Summary: %s\n", adv.Summary)
```

3. Filter by CVE ID and Severity

```go
filter := github.GlobalAdvisoryFilter{
    CVEID:    "CVE-2024-6387",
    Severity: "critical",
}
advs, err := client.ListGlobalAdvisories(filter)
// ...
```

4. Filter by Ecosystem and Withdrawn Status

```go
withdrawn := false
filter := github.GlobalAdvisoryFilter{
    Ecosystem:   "npm",
    IsWithdrawn: &withdrawn,
}
advs, err := client.ListGlobalAdvisories(filter)
// ...
```

5. Pagination

```go
filter := github.GlobalAdvisoryFilter{
    PerPage: 10,
    Page:    2,
}
advs, err := client.ListGlobalAdvisories(filter)
// ...
```

---

## Important Notes

* Rate Limits - Unauthenticated requests are limited to 60 per hour. If you need more, add a token via custom HTTP client.
* Data Freshness - The API returns live data. The client does not cache; call it as needed.
* Time Fields - PublishedAt, UpdatedAt, and WithdrawnAt are time.Time objects.
* Pagination - Use PerPage and Page to navigate large result sets.
* Public Data Only - This client only accesses global advisories. Repository‑specific or draft advisories (private) are not available without authentication.
