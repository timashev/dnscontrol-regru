package regru

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// testClient builds a client pointed at the given test-server URL with the
// rate limiter effectively disabled and a tiny retry backoff so tests are fast.
func testClient(t *testing.T, url string) *regruClient {
	t.Helper()
	c, err := newClient(map[string]string{"username": "user", "password": "secret"})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	c.endpoint = url
	c.limiter = rate.NewLimiter(rate.Inf, 1)
	c.retryBaseDelay = time.Millisecond
	return c
}

func TestNewClient(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		c, err := newClient(map[string]string{"username": "user", "password": "secret"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.username != "user" || c.password != "secret" {
			t.Fatalf("credentials not stored: %+v", c)
		}
		if c.endpoint != defaultEndpoint {
			t.Errorf("endpoint = %q, want %q", c.endpoint, defaultEndpoint)
		}
		if c.httpClient == nil {
			t.Error("httpClient is nil")
		}
		if c.limiter == nil {
			t.Error("limiter is nil")
		}
		if c.maxAttempts != defaultMaxAttempts {
			t.Errorf("maxAttempts = %d, want %d", c.maxAttempts, defaultMaxAttempts)
		}
	})

	t.Run("trims whitespace username", func(t *testing.T) {
		c, err := newClient(map[string]string{"username": "  user  ", "password": "secret"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.username != "user" {
			t.Errorf("username = %q, want %q", c.username, "user")
		}
	})

	t.Run("missing username", func(t *testing.T) {
		_, err := newClient(map[string]string{"password": "secret"})
		if err == nil {
			t.Fatal("expected error for missing username")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("error leaks credentials: %v", err)
		}
	})

	t.Run("missing password", func(t *testing.T) {
		_, err := newClient(map[string]string{"username": "user"})
		if err == nil {
			t.Fatal("expected error for missing password")
		}
	})
}

func TestAPICallSuccess(t *testing.T) {
	type answer struct {
		ServiceID string `json:"service_id"`
		DName     string `json:"dname"`
	}

	var gotPath, gotContentType, gotBody, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		gotBody = r.Form.Encode()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"success","answer":{"service_id":"42","dname":"xn--e1aybc.xn--p1ai"}}`))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)

	var out answer
	err := c.apiCall("zone/get_resource_records", map[string]string{"dname": "xn--e1aybc.xn--p1ai"}, &out)
	if err != nil {
		t.Fatalf("apiCall: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/zone/get_resource_records" {
		t.Errorf("path = %q, want /zone/get_resource_records", gotPath)
	}
	if !strings.HasPrefix(gotContentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q, want form-urlencoded", gotContentType)
	}
	for _, want := range []string{
		"username=user",
		"password=secret",
		"input_format=json",
		"output_format=json",
		`input_data=%7B%22dname%22%3A%22xn--e1aybc.xn--p1ai%22%7D`,
	} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("request body %q missing %q", gotBody, want)
		}
	}
	if out.ServiceID != "42" || out.DName != "xn--e1aybc.xn--p1ai" {
		t.Errorf("answer decoded wrong: %+v", out)
	}
}

func TestAPICallNilInput(t *testing.T) {
	var gotInputData string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotInputData = r.Form.Get("input_data")
		_, _ = w.Write([]byte(`{"result":"success","answer":{}}`))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	if err := c.apiCall("zone/clear", nil, nil); err != nil {
		t.Fatalf("apiCall: %v", err)
	}
	if gotInputData != "{}" {
		t.Errorf("input_data = %q, want {} for nil input", gotInputData)
	}
}

func TestAPICallAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":"error","error_code":"NO_SUCH_DOMAIN","error_text":"Domain not found"}`))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	err := c.apiCall("zone/get_resource_records", map[string]string{"dname": "nope.ru"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	want := "regru: zone/get_resource_records: NO_SUCH_DOMAIN: Domain not found"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks credentials: %v", err)
	}
}

func TestAPICallMalformedJSON(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`not json{`))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	err := c.apiCall("zone/get_resource_records", nil, nil)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("calls = %d, want 1 (malformed JSON must not be retried)", n)
	}
}

func TestAPICallRateLimitRetry(t *testing.T) {
	tests := []struct {
		name     string
		failResp func(w http.ResponseWriter)
	}{
		{
			name: "envelope IP exceeded",
			failResp: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte(`{"result":"error","error_code":"IP_EXCEEDED_ALLOWED_CONNECTION_RATE","error_text":"slow down"}`))
			},
		},
		{
			name: "envelope account exceeded",
			failResp: func(w http.ResponseWriter) {
				_, _ = w.Write([]byte(`{"result":"error","error_code":"ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE","error_text":"slow down"}`))
			},
		},
		{
			name: "http 429",
			failResp: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
		},
		{
			name: "http 503",
			failResp: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) < 3 {
					tc.failResp(w)
					return
				}
				_, _ = w.Write([]byte(`{"result":"success","answer":{"ok":"1"}}`))
			}))
			defer srv.Close()

			c := testClient(t, srv.URL)
			var out struct {
				OK string `json:"ok"`
			}
			if err := c.apiCall("zone/get_resource_records", nil, &out); err != nil {
				t.Fatalf("apiCall: %v", err)
			}
			if n := calls.Load(); n != 3 {
				t.Errorf("calls = %d, want 3 (2 failures then success)", n)
			}
			if out.OK != "1" {
				t.Errorf("answer not decoded after retries: %+v", out)
			}
		})
	}
}

func TestAPICallRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	err := c.apiCall("zone/get_resource_records", nil, nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if n := calls.Load(); n != int32(c.maxAttempts) {
		t.Errorf("calls = %d, want %d (maxAttempts)", n, c.maxAttempts)
	}
}
