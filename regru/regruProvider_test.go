package regru

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/printer"
)

// newTestProvider builds a provider whose client points at the test server.
func newTestProvider(t *testing.T, url string) *regruProvider {
	t.Helper()
	return &regruProvider{regruClient: testClient(t, url)}
}

// captured is the shape we parse out of an update_records request to assert the
// action_list that the provider generated.
type capturedUpdate struct {
	Domains []struct {
		DName      string           `json:"dname"`
		ActionList []map[string]any `json:"action_list"`
	} `json:"domains"`
}

func decodeInputData(t *testing.T, r *http.Request, out any) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if err := json.Unmarshal([]byte(r.Form.Get("input_data")), out); err != nil {
		t.Fatalf("unmarshal input_data %q: %v", r.Form.Get("input_data"), err)
	}
}

func TestGetNameservers(t *testing.T) {
	p := newTestProvider(t, "http://unused")
	ns, err := p.GetNameservers("example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{ns[0].Name, ns[1].Name}
	want := []string{"ns1.reg.ru", "ns2.reg.ru"}
	if len(ns) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("nameservers = %v, want %v", got, want)
	}
}

func TestListZones(t *testing.T) {
	// Fixture mirrors the shape captured from the live test/test account, with
	// an extra non-DNS service that must be filtered out.
	const resp = `{"answer":{"services":[
		{"dname":"test.ru","servtype":"domain","state":"A"},
		{"dname":"hosting.example","servtype":"srv_hosting_ispmgr","state":"A"},
		{"dname":"beta.ru","servtype":"domain","state":"A"}
	]},"result":"success"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/service/get_list" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(resp))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	zones, err := p.ListZones()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"beta.ru", "test.ru"} // sorted, domain-only
	if len(zones) != len(want) || zones[0] != want[0] || zones[1] != want[1] {
		t.Errorf("zones = %v, want %v", zones, want)
	}
}

func TestGetZoneRecords(t *testing.T) {
	// Exact envelope captured from the live test/test account.
	const resp = `{"answer":{"domains":[{"dname":"test.ru","result":"success","rrs":[{"content":"111.222.111.222","prio":"0","rectype":"A","state":"A","subname":"www"}],"service_id":12345,"servtype":"domain","soa":{"minimum_ttl":"12h","ttl":"1d"}}]},"charset":"utf-8","messagestore":null,"result":"success"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zone/get_resource_records" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var in struct {
			Domains []struct {
				DName string `json:"dname"`
			} `json:"domains"`
		}
		decodeInputData(t, r, &in)
		if len(in.Domains) != 1 || in.Domains[0].DName != "test.ru" {
			t.Errorf("request domains = %+v", in.Domains)
		}
		_, _ = w.Write([]byte(resp))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	recs, err := p.GetZoneRecords(&models.DomainConfig{Name: "test.ru"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.Type != "A" || r.GetLabel() != "www" || r.GetTargetField() != "111.222.111.222" {
		t.Errorf("record = %+v", r)
	}
	if r.TTL != 86400 { // soa ttl "1d"
		t.Errorf("ttl = %d, want 86400 (zone soa ttl)", r.TTL)
	}
}

func TestGetZoneRecordsDomainError(t *testing.T) {
	const resp = `{"answer":{"domains":[{"dname":"nope.ru","result":"error","error_code":"NO_SUCH_DOMAIN","error_text":"Domain not found"}]},"result":"success"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(resp))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	_, err := p.GetZoneRecords(&models.DomainConfig{Name: "nope.ru"})
	if err == nil {
		t.Fatal("expected error for per-domain NO_SUCH_DOMAIN")
	}
}

// DOMAIN_NOT_FOUND / SERVICE_NOT_FOUND get actionable guidance pointing at the
// reg.ru control panel (closes the spec's EnsureZoneExists intent).
func TestGetZoneRecordsNoServiceGuidance(t *testing.T) {
	for _, code := range []string{"DOMAIN_NOT_FOUND", "SERVICE_NOT_FOUND"} {
		t.Run(code, func(t *testing.T) {
			resp := `{"answer":{"domains":[{"dname":"absent.ru","result":"error","error_code":"` + code + `","error_text":"not found"}]},"result":"success"}`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(resp))
			}))
			defer srv.Close()

			p := newTestProvider(t, srv.URL)
			_, err := p.GetZoneRecords(&models.DomainConfig{Name: "absent.ru"})
			if err == nil {
				t.Fatalf("expected error for %s", code)
			}
			for _, want := range []string{"control panel", code, "absent.ru"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func buildExisting(t *testing.T, origin string, rrs ...*nativeRR) models.Records {
	t.Helper()
	var recs models.Records
	for _, rr := range rrs {
		rc, err := nativeToRecordConfig(origin, rr, 3600)
		if err != nil {
			t.Fatalf("nativeToRecordConfig: %v", err)
		}
		recs = append(recs, rc)
	}
	return recs
}

// goldenScenario returns the shared existing+desired inputs used by both the
// per-record and partner corrections golden tests: change www, keep MX, add
// new, drop old.
func goldenScenario(t *testing.T) (models.Records, *models.DomainConfig) {
	t.Helper()
	const origin = "example.com"

	existing := buildExisting(t, origin,
		&nativeRR{Subname: "www", Rectype: "A", Content: "1.1.1.1", Prio: "0"},
		&nativeRR{Subname: "old", Rectype: "A", Content: "9.9.9.9", Prio: "0"},
		&nativeRR{Subname: "@", Rectype: "MX", Content: "mail.example.com", Prio: "10"},
	)

	// Desired TTLs match the existing zone TTL (buildExisting uses 3600) so
	// these record-diff tests stay independent of zone-TTL (SOA) management.
	wwwNew := &models.RecordConfig{Type: "A", TTL: 3600}
	wwwNew.SetLabel("www", origin)
	_ = wwwNew.SetTarget("2.2.2.2")

	mxSame := &models.RecordConfig{Type: "MX", TTL: 3600}
	mxSame.SetLabel("@", origin)
	_ = mxSame.SetTargetMX(10, "mail.example.com.")

	newRec := &models.RecordConfig{Type: "A", TTL: 3600}
	newRec.SetLabel("new", origin)
	_ = newRec.SetTarget("3.3.3.3")

	dc := &models.DomainConfig{Name: origin, Records: models.Records{wwwNew, mxSame, newRec}}
	return existing, dc
}

func runCorrections(t *testing.T, corrections []*models.Correction) {
	t.Helper()
	for _, c := range corrections {
		if c.F != nil {
			if err := c.F(); err != nil {
				t.Fatalf("correction F: %v", err)
			}
		}
	}
}

// TestGetZoneRecordsCorrectionsPerRecord is the default mode: each change is a
// sequence of individual zone/add_* + zone/remove_record calls, removals of a
// rrset immediately before its additions.
func TestGetZoneRecordsCorrectionsPerRecord(t *testing.T) {
	existing, dc := goldenScenario(t)

	var seq []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		seq = append(seq, r.URL.Path+" "+r.Form.Get("input_data"))
		_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success"}]},"result":"success"}`))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL) // default: per-record
	corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("actualChangeCount = %d, want 3", count)
	}
	runCorrections(t, corrections)

	want := []string{
		`/zone/remove_record {"content":"9.9.9.9","domains":[{"dname":"example.com"}],"record_type":"A","subdomain":"old"}`,
		`/zone/remove_record {"content":"1.1.1.1","domains":[{"dname":"example.com"}],"record_type":"A","subdomain":"www"}`,
		`/zone/add_alias {"domains":[{"dname":"example.com"}],"ipaddr":"2.2.2.2","subdomain":"www"}`,
		`/zone/add_alias {"domains":[{"dname":"example.com"}],"ipaddr":"3.3.3.3","subdomain":"new"}`,
	}
	if len(seq) != len(want) {
		t.Fatalf("call sequence has %d calls, want %d:\n%v", len(seq), len(want), seq)
	}
	for i := range want {
		if seq[i] != want[i] {
			t.Errorf("call %d:\n got  %s\n want %s", i, seq[i], want[i])
		}
	}
}

// TestGetZoneRecordsCorrectionsPartner is the api_tier=partner mode: one batched
// zone/update_records call carrying the full action_list.
func TestGetZoneRecordsCorrectionsPartner(t *testing.T) {
	existing, dc := goldenScenario(t)

	var captured capturedUpdate
	var calls atomic.Int32
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		path = r.URL.Path
		decodeInputData(t, r, &captured)
		_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success","action_list":[{"action":"remove_record","result":"success"}]}]},"result":"success"}`))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	p.partnerTier = true

	corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("actualChangeCount = %d, want 3", count)
	}
	runCorrections(t, corrections)

	if calls.Load() != 1 {
		t.Fatalf("update_records calls = %d, want 1", calls.Load())
	}
	if path != "/zone/update_records" {
		t.Errorf("path = %q, want /zone/update_records", path)
	}
	if len(captured.Domains) != 1 || captured.Domains[0].DName != "example.com" {
		t.Fatalf("captured domains = %+v", captured.Domains)
	}

	got, _ := json.Marshal(captured.Domains[0].ActionList)
	// Removals first (pure delete of `old`), then the change pair
	// (remove+add of `www`), then pure creates (`new`).
	want := `[{"action":"remove_record","content":"9.9.9.9","record_type":"A","subdomain":"old"},` +
		`{"action":"remove_record","content":"1.1.1.1","record_type":"A","subdomain":"www"},` +
		`{"action":"add_alias","ipaddr":"2.2.2.2","subdomain":"www"},` +
		`{"action":"add_alias","ipaddr":"3.3.3.3","subdomain":"new"}]`
	if string(got) != want {
		t.Errorf("action_list mismatch:\n got  %s\n want %s", got, want)
	}
}

// Apex NS are ignored (fixed reg.ru set), but subdomain NS delegation is
// still managed.
func TestGetZoneRecordsCorrectionsApexNSIgnored(t *testing.T) {
	const origin = "example.com"
	existing := buildExisting(t, origin,
		&nativeRR{Subname: "@", Rectype: "NS", Content: "ns1.reg.ru", Prio: "0"},
		&nativeRR{Subname: "@", Rectype: "NS", Content: "ns2.reg.ru", Prio: "0"},
	)

	// Desired: apex NS (as dnscontrol's AddNSRecords would inject) + a real
	// subdomain NS delegation that must be created. All existing records are
	// apex NS, so after the apex-NS filter existing is empty and the zone TTL
	// falls back to defaultZoneTTL; match it to keep this test SOA-neutral.
	apex1 := &models.RecordConfig{Type: "NS", TTL: defaultZoneTTL}
	apex1.SetLabel("@", origin)
	_ = apex1.SetTarget("ns1.reg.ru.")
	apex2 := &models.RecordConfig{Type: "NS", TTL: defaultZoneTTL}
	apex2.SetLabel("@", origin)
	_ = apex2.SetTarget("ns2.reg.ru.")
	sub := &models.RecordConfig{Type: "NS", TTL: defaultZoneTTL}
	sub.SetLabel("deleg", origin)
	_ = sub.SetTarget("ns1.other.net.")

	dc := &models.DomainConfig{Name: origin, Records: models.Records{apex1, apex2, sub}}

	var seq []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		seq = append(seq, r.URL.Path)
		_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success"}]},"result":"success"}`))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("actualChangeCount = %d, want 1 (only the subdomain NS)", count)
	}
	runCorrections(t, corrections)
	if len(seq) != 1 || seq[0] != "/zone/add_ns" {
		t.Errorf("calls = %v, want one /zone/add_ns for the subdomain delegation", seq)
	}
}

func TestGetZoneRecordsCorrectionsNoChange(t *testing.T) {
	const origin = "example.com"
	existing := buildExisting(t, origin, &nativeRR{Subname: "www", Rectype: "A", Content: "1.2.3.4", Prio: "0"})

	same := &models.RecordConfig{Type: "A", TTL: 3600} // matches existing zone TTL
	same.SetLabel("www", origin)
	_ = same.SetTarget("1.2.3.4")
	dc := &models.DomainConfig{Name: origin, Records: models.Records{same}}

	p := newTestProvider(t, "http://unused")
	corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || len(corrections) != 0 {
		t.Errorf("expected no changes; count=%d corrections=%d", count, len(corrections))
	}
}

func manyCreates(t *testing.T, origin string, n int) *models.DomainConfig {
	t.Helper()
	var desired models.Records
	for i := 0; i < n; i++ {
		// Existing is empty in these tests, so the zone TTL falls back to
		// defaultZoneTTL; match it so no SOA correction is produced.
		rc := &models.RecordConfig{Type: "TXT", TTL: defaultZoneTTL}
		rc.SetLabel("n"+strconv.Itoa(i), origin)
		_ = rc.SetTargetTXT("v")
		desired = append(desired, rc)
	}
	return &models.DomainConfig{Name: origin, Records: desired}
}

// Chunking applies only to the partner (batched) mode.
func TestGetZoneRecordsCorrectionsPartnerChunking(t *testing.T) {
	dc := manyCreates(t, "example.com", 150) // -> 2 update_records calls (100 + 50)

	var calls atomic.Int32
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var c capturedUpdate
		decodeInputData(t, r, &c)
		sizes = append(sizes, len(c.Domains[0].ActionList))
		_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success","action_list":[{"action":"add_txt","result":"success"}]}]},"result":"success"}`))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL)
	p.partnerTier = true

	corrections, count, err := p.GetZoneRecordsCorrections(dc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 150 {
		t.Errorf("count = %d, want 150", count)
	}
	runCorrections(t, corrections)

	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	if len(sizes) != 2 || sizes[0] != 100 || sizes[1] != 50 {
		t.Errorf("chunk sizes = %v, want [100 50]", sizes)
	}
}

// Per-record mode does not chunk: N creates -> N individual zone/add_txt calls.
func TestGetZoneRecordsCorrectionsPerRecordManyCalls(t *testing.T) {
	dc := manyCreates(t, "example.com", 150)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/zone/add_txt" {
			t.Errorf("path = %q, want /zone/add_txt", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success"}]},"result":"success"}`))
	}))
	defer srv.Close()

	p := newTestProvider(t, srv.URL) // default: per-record
	corrections, _, err := p.GetZoneRecordsCorrections(dc, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCorrections(t, corrections)

	if calls.Load() != 150 {
		t.Fatalf("calls = %d, want 150", calls.Load())
	}
}

func TestUniformDesiredTTL(t *testing.T) {
	mk := func(ttls ...uint32) models.Records {
		var recs models.Records
		for i, ttl := range ttls {
			rc := &models.RecordConfig{Type: "A", TTL: ttl}
			rc.SetLabel("n"+strconv.Itoa(i), "example.com")
			_ = rc.SetTarget("1.2.3.4")
			recs = append(recs, rc)
		}
		return recs
	}
	t.Run("empty", func(t *testing.T) {
		if _, ok := uniformDesiredTTL(nil); ok {
			t.Error("empty set should not be uniform")
		}
	})
	t.Run("uniform", func(t *testing.T) {
		ttl, ok := uniformDesiredTTL(mk(3600, 3600, 3600))
		if !ok || ttl != 3600 {
			t.Errorf("got (%d, %v), want (3600, true)", ttl, ok)
		}
	})
	t.Run("mixed", func(t *testing.T) {
		if _, ok := uniformDesiredTTL(mk(3600, 7200)); ok {
			t.Error("mixed TTLs should not be uniform")
		}
	})
}

// desiredA builds a desired A record at a given TTL.
func desiredA(origin, label, ip string, ttl uint32) *models.RecordConfig {
	rc := &models.RecordConfig{Type: "A", TTL: ttl}
	rc.SetLabel(label, origin)
	_ = rc.SetTarget(ip)
	return rc
}

// TestGetZoneRecordsCorrectionsSOA covers zone-wide TTL management. Existing
// records are built at TTL 3600 (buildExisting), so the live zone TTL is 3600.
func TestGetZoneRecordsCorrectionsSOA(t *testing.T) {
	const origin = "example.com"

	t.Run("uniform and differs emits one SOA correction first", func(t *testing.T) {
		existing := buildExisting(t, origin, &nativeRR{Subname: "www", Rectype: "A", Content: "1.2.3.4", Prio: "0"})
		dc := &models.DomainConfig{Name: origin, Records: models.Records{desiredA(origin, "www", "1.2.3.4", 7200)}}

		var gotPath, gotTTL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			var in struct {
				TTL string `json:"ttl"`
			}
			decodeInputData(t, r, &in)
			gotTTL = in.TTL
			_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success"}]},"result":"success"}`))
		}))
		defer srv.Close()

		p := newTestProvider(t, srv.URL)
		corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("actualChangeCount = %d, want 1 (SOA only; record is TTL-neutral)", count)
		}
		if len(corrections) != 1 {
			t.Fatalf("corrections = %d, want 1", len(corrections))
		}
		if !strings.Contains(corrections[0].Msg, "update zone TTL 3600") || !strings.Contains(corrections[0].Msg, "7200") {
			t.Errorf("SOA correction Msg = %q", corrections[0].Msg)
		}
		runCorrections(t, corrections)
		if gotPath != "/zone/update_soa" || gotTTL != "7200" {
			t.Errorf("update_soa call: path=%q ttl=%q, want /zone/update_soa 7200", gotPath, gotTTL)
		}
	})

	t.Run("uniform and equal emits nothing", func(t *testing.T) {
		existing := buildExisting(t, origin, &nativeRR{Subname: "www", Rectype: "A", Content: "1.2.3.4", Prio: "0"})
		dc := &models.DomainConfig{Name: origin, Records: models.Records{desiredA(origin, "www", "1.2.3.4", 3600)}}

		p := newTestProvider(t, "http://unused")
		corrections, count, err := p.GetZoneRecordsCorrections(dc, existing)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 || len(corrections) != 0 {
			t.Errorf("want no corrections; got count=%d corrections=%d", count, len(corrections))
		}
	})

	t.Run("mixed TTLs warn and emit no SOA", func(t *testing.T) {
		// Two new records with different TTLs, empty existing.
		dc := &models.DomainConfig{Name: origin, Records: models.Records{
			desiredA(origin, "a", "1.1.1.1", 3600),
			desiredA(origin, "b", "2.2.2.2", 7200),
		}}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/zone/update_soa" {
				t.Errorf("update_soa must not be called for mixed TTLs")
			}
			_, _ = w.Write([]byte(`{"answer":{"domains":[{"dname":"example.com","result":"success"}]},"result":"success"}`))
		}))
		defer srv.Close()

		buf := &bytes.Buffer{}
		old := printer.DefaultPrinter
		printer.DefaultPrinter = &printer.ConsolePrinter{Writer: buf}
		defer func() { printer.DefaultPrinter = old }()

		p := newTestProvider(t, srv.URL)
		corrections, count, err := p.GetZoneRecordsCorrections(dc, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range corrections {
			if strings.Contains(c.Msg, "update zone TTL") {
				t.Errorf("unexpected SOA correction for mixed TTLs: %q", c.Msg)
			}
		}
		if count != 2 { // two creates, no SOA
			t.Errorf("actualChangeCount = %d, want 2", count)
		}
		if !strings.Contains(buf.String(), "mixed") {
			t.Errorf("expected a mixed-TTL warning, got %q", buf.String())
		}
	})

	t.Run("empty desired set emits no SOA", func(t *testing.T) {
		dc := &models.DomainConfig{Name: origin} // no records
		p := newTestProvider(t, "http://unused")
		corrections, count, err := p.GetZoneRecordsCorrections(dc, nil)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 || len(corrections) != 0 {
			t.Errorf("want nothing for empty desired set; got count=%d corrections=%d", count, len(corrections))
		}
	})

	// Defense-in-depth: an unset (0) TTL must never drive an SOA write, even
	// though dnscontrol normalizes 0 -> DefaultTTL upstream. No warning either.
	t.Run("uniform TTL 0 emits no SOA and no warning", func(t *testing.T) {
		dc := &models.DomainConfig{Name: origin, Records: models.Records{
			desiredA(origin, "a", "1.1.1.1", 0),
			desiredA(origin, "b", "2.2.2.2", 0),
		}}

		buf := &bytes.Buffer{}
		old := printer.DefaultPrinter
		printer.DefaultPrinter = &printer.ConsolePrinter{Writer: buf}
		defer func() { printer.DefaultPrinter = old }()

		p := newTestProvider(t, "http://unused")
		corrections, count, err := p.GetZoneRecordsCorrections(dc, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range corrections {
			if strings.Contains(c.Msg, "update zone TTL") {
				t.Errorf("unexpected SOA correction for TTL 0: %q", c.Msg)
			}
		}
		// Two creates, no SOA; and the guard is silent (no warning).
		if count != 2 {
			t.Errorf("actualChangeCount = %d, want 2 (creates only, no SOA)", count)
		}
		if buf.Len() != 0 {
			t.Errorf("expected no warning for uniform TTL 0, got %q", buf.String())
		}
	})
}
