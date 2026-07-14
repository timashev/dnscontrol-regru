package regru

import (
	"strings"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

func srvRec(t *testing.T, label string) *models.RecordConfig {
	t.Helper()
	rc := &models.RecordConfig{Type: "SRV"}
	rc.SetLabel(label, "example.com")
	if err := rc.SetTargetSRV(10, 5, 5060, "sip.example.com."); err != nil {
		t.Fatal(err)
	}
	return rc
}

func txtRec(t *testing.T, label, value string) *models.RecordConfig {
	t.Helper()
	rc := &models.RecordConfig{Type: "TXT"}
	rc.SetLabel(label, "example.com")
	if err := rc.SetTargetTXT(value); err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestAuditRecords(t *testing.T) {
	t.Run("accepts _service._proto SRV", func(t *testing.T) {
		if errs := AuditRecords([]*models.RecordConfig{srvRec(t, "_sip._tcp")}); len(errs) != 0 {
			t.Errorf("expected no audit errors, got %v", errs)
		}
	})

	t.Run("rejects SRV deeper than _service._proto", func(t *testing.T) {
		errs := AuditRecords([]*models.RecordConfig{srvRec(t, "_sip._tcp.dept")})
		if len(errs) != 1 {
			t.Fatalf("expected 1 audit error, got %v", errs)
		}
		if !strings.Contains(errs[0].Error(), "_service._proto") {
			t.Errorf("error %q should mention _service._proto", errs[0].Error())
		}
	})

	t.Run("rejects empty TXT", func(t *testing.T) {
		if errs := AuditRecords([]*models.RecordConfig{txtRec(t, "@", "")}); len(errs) != 1 {
			t.Errorf("expected 1 audit error for empty TXT, got %v", errs)
		}
	})

	t.Run("accepts a supported record set", func(t *testing.T) {
		if errs := AuditRecords([]*models.RecordConfig{srvRec(t, "_sip._tcp"), txtRec(t, "@", "v=spf1 -all")}); len(errs) != 0 {
			t.Errorf("expected no audit errors, got %v", errs)
		}
	})
}
