package regru

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
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

	wwwNew := &models.RecordConfig{Type: "A"}
	wwwNew.SetLabel("www", origin)
	_ = wwwNew.SetTarget("2.2.2.2")

	mxSame := &models.RecordConfig{Type: "MX"}
	mxSame.SetLabel("@", origin)
	_ = mxSame.SetTargetMX(10, "mail.example.com.")

	newRec := &models.RecordConfig{Type: "A"}
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
	// subdomain NS delegation that must be created.
	apex1 := &models.RecordConfig{Type: "NS"}
	apex1.SetLabel("@", origin)
	_ = apex1.SetTarget("ns1.reg.ru.")
	apex2 := &models.RecordConfig{Type: "NS"}
	apex2.SetLabel("@", origin)
	_ = apex2.SetTarget("ns2.reg.ru.")
	sub := &models.RecordConfig{Type: "NS"}
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

	same := &models.RecordConfig{Type: "A"}
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
		rc := &models.RecordConfig{Type: "TXT"}
		rc.SetLabel("n"+itoaTest(i), origin)
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

// itoaTest avoids importing strconv in the test for one call site.
func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
