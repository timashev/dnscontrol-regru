package regru

import (
	"encoding/json"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestRecordToAddAction(t *testing.T) {
	const origin = "example.com"

	mkA := func(fn func(rc *models.RecordConfig)) *models.RecordConfig {
		rc := &models.RecordConfig{}
		fn(rc)
		return rc
	}

	tests := []struct {
		name string
		rec  *models.RecordConfig
		want string
	}{
		{
			name: "A",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "A"
				rc.SetLabel("www", origin)
				_ = rc.SetTarget("1.2.3.4")
			}),
			want: `{"action":"add_alias","ipaddr":"1.2.3.4","subdomain":"www"}`,
		},
		{
			name: "AAAA apex",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "AAAA"
				rc.SetLabel("@", origin)
				_ = rc.SetTarget("2001:db8::1")
			}),
			want: `{"action":"add_aaaa","ipaddr":"2001:db8::1","subdomain":"@"}`,
		},
		{
			name: "CNAME trailing dot stripped",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "CNAME"
				rc.SetLabel("www", origin)
				_ = rc.SetTarget("target.example.com.")
			}),
			want: `{"action":"add_cname","canonical_name":"target.example.com","subdomain":"www"}`,
		},
		{
			name: "MX",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "MX"
				rc.SetLabel("@", origin)
				_ = rc.SetTargetMX(10, "mail.example.com.")
			}),
			want: `{"action":"add_mx","mail_server":"mail.example.com","priority":"10","subdomain":"@"}`,
		},
		{
			name: "NS",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "NS"
				rc.SetLabel("sub", origin)
				_ = rc.SetTarget("ns1.example.net.")
			}),
			want: `{"action":"add_ns","dns_server":"ns1.example.net","subdomain":"sub"}`,
		},
		{
			name: "TXT",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "TXT"
				rc.SetLabel("@", origin)
				_ = rc.SetTargetTXT("hello world")
			}),
			want: `{"action":"add_txt","subdomain":"@","text":"hello world"}`,
		},
		{
			name: "SRV",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "SRV"
				rc.SetLabel("_sip._tcp", origin)
				_ = rc.SetTargetSRV(10, 5, 5060, "sip.example.com.")
			}),
			want: `{"action":"add_srv","port":"5060","priority":"10","service":"sip.tcp","target":"sip.example.com","weight":"5"}`,
		},
		{
			name: "CAA",
			rec: mkA(func(rc *models.RecordConfig) {
				rc.Type = "CAA"
				rc.SetLabel("@", origin)
				_ = rc.SetTargetCAA(0, "issue", "letsencrypt.org")
			}),
			want: `{"action":"add_caa","flags":"0","subdomain":"@","tag":"issue","value":"letsencrypt.org"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			act, err := recordToAddAction(tc.rec)
			if err != nil {
				t.Fatalf("recordToAddAction: %v", err)
			}
			if got := mustJSON(t, act); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestRecordToAddActionUnsupported(t *testing.T) {
	rc := &models.RecordConfig{Type: "PTR"}
	rc.SetLabel("@", "example.com")
	if _, err := recordToAddAction(rc); err == nil {
		t.Fatal("expected error for unsupported type PTR")
	}
}

func TestRecordToRemoveAction(t *testing.T) {
	// Removal must be derived from the stored native record so the content
	// matches exactly what REG.RU has, targeting a single record.
	tests := []struct {
		name   string
		native *nativeRR
		rtype  string
		want   string
	}{
		{
			name:   "A",
			native: &nativeRR{Subname: "www", Rectype: "A", Content: "1.1.1.1", Prio: "0"},
			rtype:  "A",
			want:   `{"action":"remove_record","content":"1.1.1.1","record_type":"A","subdomain":"www"}`,
		},
		{
			name:   "MX carries priority",
			native: &nativeRR{Subname: "@", Rectype: "MX", Content: "mail.example.com", Prio: "10"},
			rtype:  "MX",
			want:   `{"action":"remove_record","content":"mail.example.com","priority":"10","record_type":"MX","subdomain":"@"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := &models.RecordConfig{Type: tc.rtype, Original: tc.native}
			rc.SetLabel(tc.native.Subname, "example.com")
			got := mustJSON(t, recordToRemoveAction(rc))
			if got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestNativeToRecordConfig(t *testing.T) {
	const origin = "example.com"
	const ttl = 3600

	tests := []struct {
		name       string
		rr         *nativeRR
		wantType   string
		wantLabel  string
		wantTarget string
		skip       bool
	}{
		{"A", &nativeRR{Subname: "www", Rectype: "A", Content: "1.2.3.4", Prio: "0"}, "A", "www", "1.2.3.4", false},
		{"apex A", &nativeRR{Subname: "@", Rectype: "A", Content: "1.2.3.4", Prio: "0"}, "A", "@", "1.2.3.4", false},
		{"CNAME gets trailing dot", &nativeRR{Subname: "www", Rectype: "CNAME", Content: "target.example.com", Prio: "0"}, "CNAME", "www", "target.example.com.", false},
		{"MX", &nativeRR{Subname: "@", Rectype: "MX", Content: "mail.example.com", Prio: "10"}, "MX", "@", "mail.example.com.", false},
		{"TXT", &nativeRR{Subname: "@", Rectype: "TXT", Content: "v=spf1 -all", Prio: "0"}, "TXT", "@", "v=spf1 -all", false},
		{"SOA skipped", &nativeRR{Subname: "@", Rectype: "SOA", Content: "x", Prio: "0"}, "", "", "", true},
		{"unsupported skipped", &nativeRR{Subname: "@", Rectype: "TLSA", Content: "x", Prio: "0"}, "", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := nativeToRecordConfig(origin, tc.rr, ttl)
			if err != nil {
				t.Fatalf("nativeToRecordConfig: %v", err)
			}
			if tc.skip {
				if rc != nil {
					t.Fatalf("expected skip (nil), got %+v", rc)
				}
				return
			}
			if rc == nil {
				t.Fatal("unexpected nil")
			}
			if rc.Type != tc.wantType {
				t.Errorf("type = %q, want %q", rc.Type, tc.wantType)
			}
			if rc.GetLabel() != tc.wantLabel {
				t.Errorf("label = %q, want %q", rc.GetLabel(), tc.wantLabel)
			}
			if rc.GetTargetField() != tc.wantTarget {
				t.Errorf("target = %q, want %q", rc.GetTargetField(), tc.wantTarget)
			}
			if rc.TTL != ttl {
				t.Errorf("ttl = %d, want %d", rc.TTL, ttl)
			}
			if rc.Original == nil {
				t.Error("Original not preserved")
			}
		})
	}
}

func TestNativeToRecordConfigMXPriority(t *testing.T) {
	rc, err := nativeToRecordConfig("example.com", &nativeRR{Subname: "@", Rectype: "MX", Content: "mail.example.com", Prio: "20"}, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if rc.MxPreference != 20 {
		t.Errorf("MxPreference = %d, want 20", rc.MxPreference)
	}
}

func TestParseRegruTTL(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
	}{
		{"3600", 3600},
		{"1d", 86400},
		{"12h", 43200},
		{"1w", 604800},
		{"", defaultZoneTTL},
		{"garbage", defaultZoneTTL},
	}
	for _, tc := range tests {
		if got := parseRegruTTL(tc.in); got != tc.want {
			t.Errorf("parseRegruTTL(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestChunkActions(t *testing.T) {
	mk := func(n int) []recordAction {
		g := make([]recordAction, n)
		for i := range g {
			g[i] = recordAction{"action": "add_alias"}
		}
		return g
	}

	t.Run("keeps pairs intact at boundary", func(t *testing.T) {
		// 99 single-action groups + one 2-action group, max 100.
		var groups [][]recordAction
		for i := 0; i < 99; i++ {
			groups = append(groups, mk(1))
		}
		groups = append(groups, mk(2)) // a change pair
		chunks := chunkActions(groups, 100)
		if len(chunks) != 2 {
			t.Fatalf("chunks = %d, want 2", len(chunks))
		}
		if len(chunks[0]) != 99 {
			t.Errorf("chunk0 = %d, want 99 (pair must not be split)", len(chunks[0]))
		}
		if len(chunks[1]) != 2 {
			t.Errorf("chunk1 = %d, want 2", len(chunks[1]))
		}
	})

	t.Run("single chunk under limit", func(t *testing.T) {
		chunks := chunkActions([][]recordAction{mk(1), mk(2), mk(1)}, 100)
		if len(chunks) != 1 || len(chunks[0]) != 4 {
			t.Fatalf("got %d chunks, chunk0=%d", len(chunks), len(chunks[0]))
		}
	})

	t.Run("empty", func(t *testing.T) {
		if chunks := chunkActions(nil, 100); len(chunks) != 0 {
			t.Fatalf("want 0 chunks, got %d", len(chunks))
		}
	})
}
