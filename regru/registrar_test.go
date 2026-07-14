package regru

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

// get_nss envelope captured from the live test/test account.
const getNSSResp = `{"answer":{"domains":[{"dname":"test.ru","nss":[{"ns":"ns1.reg.ru"},{"ns":"ns2.reg.ru"}],"service_id":12345}]},"charset":"utf-8","messagestore":null,"result":"success"}`

// update_nss success envelope captured from the live test/test account.
const updateNSSResp = `{"answer":{"domains":[{"dname":"test.ru","result":"success","service_id":12345}]},"charset":"utf-8","messagestore":null,"result":"success"}`

func TestClientGetNameservers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/get_nss" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(getNSSResp))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	ns, err := c.getNameservers("test.ru")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0] != "ns1.reg.ru" || ns[1] != "ns2.reg.ru" {
		t.Errorf("nameservers = %v", ns)
	}
}

func TestGetRegistrarCorrectionsNoChange(t *testing.T) {
	var updateCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/domain/get_nss":
			// Returns ns1,ns2; desired is the same set reversed with dots.
			_, _ = w.Write([]byte(getNSSResp))
		case "/domain/update_nss":
			updateCalls.Add(1)
			_, _ = w.Write([]byte(updateNSSResp))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	// dnscontrol never leaves trailing dots on nameservers (ToNameservers errors
	// on them); test order + case insensitivity here, and the dot path in
	// TestNSSetsEqual.
	nss, err := models.ToNameservers([]string{"NS2.reg.ru", "ns1.reg.ru"}) // reversed, mixed case
	if err != nil {
		t.Fatal(err)
	}
	dc := &models.DomainConfig{Name: "test.ru", Nameservers: nss}

	corrections, err := p.GetRegistrarCorrections(dc)
	if err != nil {
		t.Fatal(err)
	}
	if len(corrections) != 0 {
		t.Errorf("expected no corrections (NS match modulo order/case/dot), got %d", len(corrections))
	}
	if updateCalls.Load() != 0 {
		t.Errorf("update_nss called %d times, want 0", updateCalls.Load())
	}
}

func TestGetRegistrarCorrectionsChange(t *testing.T) {
	var captured struct {
		Domains []struct {
			DName string `json:"dname"`
		} `json:"domains"`
		NSS map[string]string `json:"nss"`
	}
	var updatePath string
	var updateCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/domain/get_nss":
			_, _ = w.Write([]byte(getNSSResp)) // current: ns1.reg.ru, ns2.reg.ru
		case "/domain/update_nss":
			updateCalls.Add(1)
			updatePath = r.URL.Path
			decodeInputData(t, r, &captured)
			_, _ = w.Write([]byte(updateNSSResp))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	nss, _ := models.ToNameservers([]string{"ns1.example.com", "ns2.example.com"})
	dc := &models.DomainConfig{Name: "test.ru", Nameservers: nss}

	corrections, err := p.GetRegistrarCorrections(dc)
	if err != nil {
		t.Fatal(err)
	}
	if len(corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(corrections))
	}
	if err := corrections[0].F(); err != nil {
		t.Fatalf("correction F: %v", err)
	}

	if updateCalls.Load() != 1 || updatePath != "/domain/update_nss" {
		t.Fatalf("update_nss calls=%d path=%q", updateCalls.Load(), updatePath)
	}
	if len(captured.Domains) != 1 || captured.Domains[0].DName != "test.ru" {
		t.Errorf("domains = %+v", captured.Domains)
	}
	// NS names map to ns0..nsN in order.
	if captured.NSS["ns0"] != "ns1.example.com" || captured.NSS["ns1"] != "ns2.example.com" {
		t.Errorf("nss hash = %v, want {ns0:ns1.example.com, ns1:ns2.example.com}", captured.NSS)
	}
	if len(captured.NSS) != 2 {
		t.Errorf("nss hash has %d entries, want 2: %v", len(captured.NSS), captured.NSS)
	}
}

func TestNSSetsEqual(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{[]string{"ns1.reg.ru", "ns2.reg.ru"}, []string{"ns2.reg.ru", "ns1.reg.ru"}, true}, // order
		{[]string{"NS1.reg.ru"}, []string{"ns1.reg.ru"}, true},                             // case
		{[]string{"ns1.reg.ru."}, []string{"ns1.reg.ru"}, true},                            // trailing dot
		{[]string{"ns1.reg.ru", "ns2.reg.ru"}, []string{"ns1.reg.ru"}, false},              // count
		{[]string{"ns1.reg.ru"}, []string{"ns1.example.com"}, false},                       // different
	}
	for _, tc := range tests {
		if got := nsSetsEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("nsSetsEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestUpdateNameserversEmptyRejected(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(updateNSSResp))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	if err := c.updateNameservers("test.ru", nil); err == nil {
		t.Fatal("expected error for empty NS set")
	}
	if calls.Load() != 0 {
		t.Errorf("update_nss called %d times, want 0 (must not hit the API)", calls.Load())
	}
}

func TestUpdateNameserversMapsIndices(t *testing.T) {
	var captured struct {
		NSS map[string]string `json:"nss"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decodeInputData(t, r, &captured)
		_, _ = w.Write([]byte(updateNSSResp))
	}))
	defer srv.Close()

	c := testClient(t, srv.URL)
	if err := c.updateNameservers("test.ru", []string{"a.ns", "b.ns", "c.ns"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ns0": "a.ns", "ns1": "b.ns", "ns2": "c.ns"}
	for k, v := range want {
		if captured.NSS[k] != v {
			t.Errorf("nss[%s] = %q, want %q", k, captured.NSS[k], v)
		}
	}
}
