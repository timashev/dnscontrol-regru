// Package regru implements a DNSControl provider for REG.RU, built on
// REG.API v2 (https://api.reg.ru/api/regru2/). This file holds the API
// transport layer: authentication, the request/response envelope, client-side
// rate limiting, and retry-with-backoff. Provider logic lives elsewhere.
package regru

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	// defaultEndpoint is the REG.API v2 base URL. A function name (e.g.
	// "zone/get_resource_records") is appended to form the full request URL.
	defaultEndpoint = "https://api.reg.ru/api/regru2"

	// defaultMaxAttempts bounds the number of times a single call is tried,
	// including the first attempt.
	defaultMaxAttempts = 5

	// defaultRateLimit is the client-side sustained request rate (requests per
	// second). REG.API allows 1200 req/hr per account AND per IP — a single
	// shared bucket — so the sustained rate is held at exactly that ceiling
	// (1200/3600 ≈ 0.333 req/s). A faster rate (e.g. 1 req/s = 3600/hr) would
	// exhaust the hourly quota mid-run; backoff cannot outwait an hourly window,
	// so a large per-record push would abort with a partially applied zone.
	defaultRateLimit = 1200.0 / 3600.0

	// defaultBurst lets short bursts absorb latency without exceeding the
	// sustained ceiling over time.
	defaultBurst = 5

	// defaultRetryBaseDelay is the first backoff delay; it doubles each retry.
	defaultRetryBaseDelay = 1 * time.Second

	// maxRetryDelay caps the exponential backoff.
	maxRetryDelay = 30 * time.Second

	// httpTimeout bounds a single HTTP request/response.
	httpTimeout = 30 * time.Second
)

// Envelope error codes REG.API returns when a rate limit is hit. Both mean the
// request was rejected before being applied, so both are always retriable.
const (
	errIPExceeded      = "IP_EXCEEDED_ALLOWED_CONNECTION_RATE"
	errAccountExceeded = "ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE"
)

// Envelope error codes meaning the zone/domain has no manageable DNS service on
// this account. Surfaced with actionable guidance from GetZoneRecords.
const (
	errDomainNotFound  = "DOMAIN_NOT_FOUND"
	errServiceNotFound = "SERVICE_NOT_FOUND"
)

// retryPolicy controls whether transport-level failures (HTTP 5xx and network
// errors) are retried. Rate-limit rejections (HTTP 429 and the *_EXCEEDED_*
// envelope codes) are retried under both policies because the request is
// rejected before it is applied.
type retryPolicy int

const (
	// retryTransient is for read calls: a lost or 5xx response is harmless to
	// repeat, so retry transport failures too.
	retryTransient retryPolicy = iota
	// retryRateLimitOnly is for write calls: a 5xx or dropped connection may
	// mean the write was applied but the response was lost, so retrying could
	// double-apply or surface a false failure. Only pre-application rate-limit
	// rejections are retried.
	retryRateLimitOnly
)

// regruClient talks to REG.API v2. It is safe for use across goroutines only to
// the extent the embedded http.Client and rate.Limiter are; provider code uses
// it serially.
type regruClient struct {
	username   string
	password   string
	endpoint   string
	httpClient *http.Client
	limiter    *rate.Limiter

	// partnerTier selects the batched zone/update_records execution path
	// (partner-tier only). When false (the default), corrections are applied
	// with per-record zone/add_* + zone/remove_record calls (client-tier).
	partnerTier bool

	maxAttempts    int
	retryBaseDelay time.Duration
}

// apiEnvelope is the common REG.API v2 response wrapper. Answer carries the
// function-specific payload and is decoded into the caller's out value only on
// success.
type apiEnvelope struct {
	Result    string          `json:"result"`
	Answer    json.RawMessage `json:"answer"`
	ErrorCode string          `json:"error_code"`
	ErrorText string          `json:"error_text"`
}

// newClient builds a client from a DNSControl creds.json map, validating that
// the required credential keys are present. Credentials are never logged.
func newClient(m map[string]string) (*regruClient, error) {
	username := strings.TrimSpace(m["username"])
	if username == "" {
		return nil, errors.New("regru: missing 'username' in creds.json")
	}
	password := m["password"]
	if password == "" {
		return nil, errors.New("regru: missing 'password' in creds.json")
	}

	// api_tier selects the corrections execution mode. "partner" enables the
	// batched zone/update_records path; absence or any other value keeps the
	// default per-record path that works on every account tier.
	partnerTier := strings.EqualFold(strings.TrimSpace(m["api_tier"]), "partner")

	return &regruClient{
		username:       username,
		password:       password,
		endpoint:       defaultEndpoint,
		httpClient:     &http.Client{Timeout: httpTimeout},
		limiter:        rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurst),
		partnerTier:    partnerTier,
		maxAttempts:    defaultMaxAttempts,
		retryBaseDelay: defaultRetryBaseDelay,
	}, nil
}

// apiCall POSTs to REG.API function fn, sending input as JSON in the input_data
// parameter, and decodes the envelope's answer into out (which may be nil when
// the answer is not needed). Envelope errors are mapped to
// "regru: <fn>: <code>: <text>". The call is rate limited and retried with
// exponential backoff; policy decides whether transport failures are retried
// (see retryPolicy). Rate-limit rejections are always retried.
func (c *regruClient) apiCall(fn string, input any, out any, policy retryPolicy) error {
	if input == nil {
		input = struct{}{}
	}
	inputData, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("regru: %s: marshaling input: %w", fn, err)
	}

	form := url.Values{}
	form.Set("username", c.username)
	form.Set("password", c.password)
	form.Set("input_format", "json")
	form.Set("output_format", "json")
	form.Set("input_data", string(inputData))
	body := form.Encode()

	endpoint := strings.TrimRight(c.endpoint, "/") + "/" + fn

	var lastErr error
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		// Respect the client-side rate limit before every attempt (each
		// attempt is a real request that counts against REG.API's quota).
		if err := c.limiter.Wait(context.Background()); err != nil {
			return fmt.Errorf("regru: %s: %w", fn, err)
		}

		retriable, err := c.doAttempt(endpoint, fn, body, out, policy)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retriable || attempt == c.maxAttempts {
			return err
		}
		time.Sleep(c.backoff(attempt))
	}
	return lastErr
}

// doAttempt performs one HTTP request. It reports whether the error (if any) is
// worth retrying under the given policy.
func (c *regruClient) doAttempt(endpoint, fn, body string, out any, policy retryPolicy) (retriable bool, err error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("regru: %s: %w", fn, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transport-level failure (timeout, connection reset). The request may
		// have reached the server, so only reads retry.
		return policy == retryTransient, fmt.Errorf("regru: %s: %w", fn, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return policy == retryTransient, fmt.Errorf("regru: %s: reading response: %w", fn, err)
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// Rate limited before the request was applied — always safe to retry.
		return true, fmt.Errorf("regru: %s: HTTP %d", fn, resp.StatusCode)
	case resp.StatusCode >= 500:
		// The server may have applied a write before the 5xx; only reads retry.
		return policy == retryTransient, fmt.Errorf("regru: %s: HTTP %d", fn, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("regru: %s: HTTP %d", fn, resp.StatusCode)
	}

	var env apiEnvelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		return false, fmt.Errorf("regru: %s: decoding response: %w", fn, err)
	}

	if env.Result != "success" {
		// The *_EXCEEDED_* codes are pre-application rejections — always retry.
		retriable := env.ErrorCode == errIPExceeded || env.ErrorCode == errAccountExceeded
		return retriable, fmt.Errorf("regru: %s: %s: %s", fn, env.ErrorCode, env.ErrorText)
	}

	if out != nil && len(env.Answer) > 0 {
		if err := json.Unmarshal(env.Answer, out); err != nil {
			return false, fmt.Errorf("regru: %s: decoding answer: %w", fn, err)
		}
	}
	return false, nil
}

// backoff returns the delay to wait after a failed attempt (attempt >= 1),
// doubling from retryBaseDelay and capped at maxRetryDelay.
func (c *regruClient) backoff(attempt int) time.Duration {
	d := c.retryBaseDelay << (attempt - 1)
	if d <= 0 || d > maxRetryDelay {
		return maxRetryDelay
	}
	return d
}

// --- REG.API v2 zone/service function wrappers and their JSON shapes ---
//
// The response envelope has a top-level result plus a per-domain result inside
// answer.domains[]; a domain can fail while the request as a whole reports
// "success", so per-domain results must always be inspected.

// domainRef identifies a domain in a request. REG.RU expects punycode dnames.
type domainRef struct {
	DName string `json:"dname"`
}

// flexString decodes a JSON string OR bare number into a string. REG.API is
// inconsistent across accounts here: the canned test/test account returns
// fields like "prio" and "soa.ttl" as strings, while real accounts return
// bare numbers (observed live 2026-07-15: prio as number).
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

// nativeRR is a single resource record as returned by
// zone/get_resource_records. REG.RU carries no per-record TTL (the zone SOA TTL
// governs everything), so there is no TTL field here.
type nativeRR struct {
	Subname string     `json:"subname"` // relative name: "@" apex, "*" wildcard, or a label
	Rectype string     `json:"rectype"`
	Content string     `json:"content"`
	Prio    flexString `json:"prio"` // priority for MX/SRV, "0" otherwise; string or number on the wire
	State   string     `json:"state"`
}

type soaInfo struct {
	TTL        flexString `json:"ttl"` // "3600"/"1d" on test/test; may be a bare number live
	MinimumTTL flexString `json:"minimum_ttl"`
}

type domainRecords struct {
	DName     string     `json:"dname"`
	Result    string     `json:"result"`
	ErrorCode string     `json:"error_code"`
	ErrorText string     `json:"error_text"`
	RRs       []nativeRR `json:"rrs"`
	SOA       soaInfo    `json:"soa"`
}

type getRecordsRequest struct {
	Domains []domainRef `json:"domains"`
}

type getRecordsResponse struct {
	Domains []domainRecords `json:"domains"`
}

// getResourceRecords fetches the resource records for a single zone.
func (c *regruClient) getResourceRecords(dname string) (*domainRecords, error) {
	in := getRecordsRequest{Domains: []domainRef{{DName: dname}}}
	var out getRecordsResponse
	if err := c.apiCall("zone/get_resource_records", in, &out, retryTransient); err != nil {
		return nil, err
	}
	if len(out.Domains) == 0 {
		return nil, fmt.Errorf("regru: zone/get_resource_records: no data returned for %q", dname)
	}
	d := out.Domains[0]
	if d.Result != "success" {
		if d.ErrorCode == errDomainNotFound || d.ErrorCode == errServiceNotFound {
			return nil, fmt.Errorf("regru: zone %q has no DNS-hosting service on this REG.RU account (%s: %s): create the DNS hosting service for the domain in the REG.RU control panel, or verify the account owns the domain, then re-run", dname, d.ErrorCode, d.ErrorText)
		}
		return nil, fmt.Errorf("regru: zone/get_resource_records: %s: %s: %s", dname, d.ErrorCode, d.ErrorText)
	}
	return &d, nil
}

type service struct {
	DName    string `json:"dname"`
	Servtype string `json:"servtype"`
	State    string `json:"state"`
}

type serviceListResponse struct {
	Services []service `json:"services"`
}

// listServices returns every service on the account (domains, hosting, etc.).
func (c *regruClient) listServices() ([]service, error) {
	var out serviceListResponse
	if err := c.apiCall("service/get_list", struct{}{}, &out, retryTransient); err != nil {
		return nil, err
	}
	return out.Services, nil
}

// recordAction is one entry of a zone/update_records action_list. Every value
// is a string; the "action" key selects the operation (add_alias, add_mx,
// remove_record, ...). Marshaling a map yields deterministically sorted keys.
// The same map also drives per-record calls: the "action" value becomes the
// function suffix and the remaining keys become top-level input_data fields.
type recordAction map[string]string

// zoneOpResponse is the answer shape shared by the per-record zone functions
// (zone/add_*, zone/remove_record): a per-domain result with no action_list.
type zoneOpResponse struct {
	Domains []struct {
		DName     string `json:"dname"`
		Result    string `json:"result"`
		ErrorCode string `json:"error_code"`
		ErrorText string `json:"error_text"`
	} `json:"domains"`
}

// applyRecordAction executes a single action as an individual client-tier call
// to zone/<action> (e.g. zone/add_alias, zone/remove_record). The record fields
// are sent as top-level input_data siblings of "domains".
func (c *regruClient) applyRecordAction(dname string, act recordAction) error {
	fn := "zone/" + act["action"]
	payload := map[string]any{"domains": []domainRef{{DName: dname}}}
	for k, v := range act {
		if k == "action" {
			continue
		}
		payload[k] = v
	}
	var out zoneOpResponse
	if err := c.apiCall(fn, payload, &out, retryRateLimitOnly); err != nil {
		return err
	}
	if len(out.Domains) == 0 {
		return fmt.Errorf("regru: %s: no data returned for %q", fn, dname)
	}
	d := out.Domains[0]
	if d.Result != "success" {
		return fmt.Errorf("regru: %s: %s: %s: %s", fn, dname, d.ErrorCode, d.ErrorText)
	}
	return nil
}

type updateDomain struct {
	DName      string         `json:"dname"`
	ActionList []recordAction `json:"action_list"`
}

type updateRecordsRequest struct {
	Domains []updateDomain `json:"domains"`
}

type actionResult struct {
	Action    string `json:"action"`
	Result    string `json:"result"`
	ErrorCode string `json:"error_code"`
	ErrorText string `json:"error_text"`
}

type updateDomainResult struct {
	DName      string         `json:"dname"`
	Result     string         `json:"result"`
	ErrorCode  string         `json:"error_code"`
	ErrorText  string         `json:"error_text"`
	ActionList []actionResult `json:"action_list"`
}

type updateRecordsResponse struct {
	Domains []updateDomainResult `json:"domains"`
}

// updateRecords applies a batch of add/remove actions to one zone. Both the
// per-domain result and each per-action result are checked. REG.API stops at
// the first failing action and ignores the rest, so a partial error is fatal.
func (c *regruClient) updateRecords(dname string, actions []recordAction) error {
	in := updateRecordsRequest{Domains: []updateDomain{{DName: dname, ActionList: actions}}}
	var out updateRecordsResponse
	if err := c.apiCall("zone/update_records", in, &out, retryRateLimitOnly); err != nil {
		return err
	}
	if len(out.Domains) == 0 {
		return fmt.Errorf("regru: zone/update_records: no data returned for %q", dname)
	}
	d := out.Domains[0]
	if d.Result == "error" || d.ErrorCode != "" {
		return fmt.Errorf("regru: zone/update_records: %s: %s: %s", dname, d.ErrorCode, d.ErrorText)
	}
	for _, a := range d.ActionList {
		if a.Result != "success" {
			return fmt.Errorf("regru: zone/update_records: %s: action %s: %s: %s", dname, a.Action, a.ErrorCode, a.ErrorText)
		}
	}
	return nil
}

// --- Registrar (nameserver) functions: domain/get_nss, domain/update_nss ---

type nsEntry struct {
	NS string `json:"ns"`
}

type domainNSS struct {
	DName     string    `json:"dname"`
	ErrorCode string    `json:"error_code"`
	NSS       []nsEntry `json:"nss"`
}

type getNSSResponse struct {
	Domains []domainNSS `json:"domains"`
}

// getNameservers returns the delegation nameservers currently set for a domain.
func (c *regruClient) getNameservers(dname string) ([]string, error) {
	in := getRecordsRequest{Domains: []domainRef{{DName: dname}}}
	var out getNSSResponse
	if err := c.apiCall("domain/get_nss", in, &out, retryTransient); err != nil {
		return nil, err
	}
	if len(out.Domains) == 0 {
		return nil, fmt.Errorf("regru: domain/get_nss: no data returned for %q", dname)
	}
	d := out.Domains[0]
	if d.ErrorCode != "" {
		return nil, fmt.Errorf("regru: domain/get_nss: %s: %s", dname, d.ErrorCode)
	}
	nss := make([]string, 0, len(d.NSS))
	for _, e := range d.NSS {
		if e.NS != "" {
			nss = append(nss, e.NS)
		}
	}
	return nss, nil
}

type updateNSSRequest struct {
	Domains []domainRef       `json:"domains"`
	NSS     map[string]string `json:"nss"`
}

type updateNSSResponse struct {
	Domains []struct {
		DName     string `json:"dname"`
		Result    string `json:"result"`
		ErrorCode string `json:"error_code"`
	} `json:"domains"`
}

// updateNameservers sets a domain's delegation nameservers. The names are
// mapped to REG.API's ns0..nsN fields in the given priority order.
func (c *regruClient) updateNameservers(dname string, ns []string) error {
	if len(ns) == 0 {
		// Defense against wiping delegation if upstream's no-nameservers skip
		// ever changes. Removing all NS would deregister the domain's DNS.
		return fmt.Errorf("regru: domain/update_nss: refusing to set an empty NS set for %q", dname)
	}
	nss := make(map[string]string, len(ns))
	for i, n := range ns {
		nss[fmt.Sprintf("ns%d", i)] = n
	}
	in := updateNSSRequest{Domains: []domainRef{{DName: dname}}, NSS: nss}
	var out updateNSSResponse
	if err := c.apiCall("domain/update_nss", in, &out, retryRateLimitOnly); err != nil {
		return err
	}
	if len(out.Domains) == 0 {
		return fmt.Errorf("regru: domain/update_nss: no data returned for %q", dname)
	}
	d := out.Domains[0]
	// On error REG.API puts the code in error_code and the message in result.
	if d.ErrorCode != "" || d.Result != "success" {
		return fmt.Errorf("regru: domain/update_nss: %s: %s: %s", dname, d.ErrorCode, d.Result)
	}
	return nil
}
