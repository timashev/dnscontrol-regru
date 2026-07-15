package regru

import (
	"encoding/json"
	"testing"
)

// Real accounts return prio and soa.ttl as bare JSON numbers; the canned
// test/test account returns them as strings (observed live 2026-07-15).
// Both wire formats must decode.
func TestNativeRRFlexibleNumbers(t *testing.T) {
	blob := []byte(`{
		"dname": "example.ru", "result": "success",
		"rrs": [
			{"subname": "@", "rectype": "MX", "content": "mail.example.ru", "prio": 10,   "state": "A"},
			{"subname": "@", "rectype": "MX", "content": "mx2.example.ru",  "prio": "20", "state": "A"},
			{"subname": "www", "rectype": "A", "content": "192.0.2.1", "state": "A"}
		],
		"soa": {"ttl": 3600, "minimum_ttl": "1h"}
	}`)
	var dom domainRecords
	if err := json.Unmarshal(blob, &dom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(dom.RRs[0].Prio); got != "10" {
		t.Errorf("numeric prio = %q, want %q", got, "10")
	}
	if got := string(dom.RRs[1].Prio); got != "20" {
		t.Errorf("string prio = %q, want %q", got, "20")
	}
	if got := string(dom.RRs[2].Prio); got != "" {
		t.Errorf("absent prio = %q, want empty", got)
	}
	if got := parseRegruTTL(string(dom.SOA.TTL)); got != 3600 {
		t.Errorf("numeric soa ttl = %d, want 3600", got)
	}
	if got := parseRegruTTL(string(dom.SOA.MinimumTTL)); got != 3600 {
		t.Errorf("minimum_ttl 1h = %d, want 3600", got)
	}
}
