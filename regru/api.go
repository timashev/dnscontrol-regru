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

	// defaultRateLimit is the client-side request rate (requests per second).
	// REG.API allows 1200 req/hr per account and per IP; 1 req/s stays well
	// under both ceilings.
	defaultRateLimit = 1.0

	// defaultRetryBaseDelay is the first backoff delay; it doubles each retry.
	defaultRetryBaseDelay = 1 * time.Second

	// maxRetryDelay caps the exponential backoff.
	maxRetryDelay = 30 * time.Second

	// httpTimeout bounds a single HTTP request/response.
	httpTimeout = 30 * time.Second
)

// Envelope error codes REG.API returns when a rate limit is hit. Both are
// retriable.
const (
	errIPExceeded      = "IP_EXCEEDED_ALLOWED_CONNECTION_RATE"
	errAccountExceeded = "ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE"
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

	return &regruClient{
		username:       username,
		password:       password,
		endpoint:       defaultEndpoint,
		httpClient:     &http.Client{Timeout: httpTimeout},
		limiter:        rate.NewLimiter(rate.Limit(defaultRateLimit), 1),
		maxAttempts:    defaultMaxAttempts,
		retryBaseDelay: defaultRetryBaseDelay,
	}, nil
}

// apiCall POSTs to REG.API function fn, sending input as JSON in the input_data
// parameter, and decodes the envelope's answer into out (which may be nil when
// the answer is not needed). Envelope errors are mapped to
// "regru: <fn>: <code>: <text>". The call is rate limited and retried with
// exponential backoff on rate-limit envelope codes and on HTTP 429/5xx.
func (c *regruClient) apiCall(fn string, input any, out any) error {
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

		retriable, err := c.doAttempt(endpoint, fn, body, out)
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
// worth retrying.
func (c *regruClient) doAttempt(endpoint, fn, body string, out any) (retriable bool, err error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("regru: %s: %w", fn, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transport-level failures (timeouts, connection resets) are transient.
		return true, fmt.Errorf("regru: %s: %w", fn, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, fmt.Errorf("regru: %s: reading response: %w", fn, err)
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("regru: %s: HTTP %d", fn, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("regru: %s: HTTP %d", fn, resp.StatusCode)
	}

	var env apiEnvelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		return false, fmt.Errorf("regru: %s: decoding response: %w", fn, err)
	}

	if env.Result != "success" {
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
