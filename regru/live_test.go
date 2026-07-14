package regru

import (
	"os"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestLive exercises the read paths and a no-op corrections computation against
// a real REG.API account. It is gated on REGRU_LIVE=1 and defaults to the
// canned test/test account. It never executes corrections, so it makes no
// changes to any domain.
func TestLive(t *testing.T) {
	if os.Getenv("REGRU_LIVE") != "1" {
		t.Skip("set REGRU_LIVE=1 to run live tests against api.reg.ru")
	}

	creds := map[string]string{
		"username": envOr("REGRU_USERNAME", "test"),
		"password": envOr("REGRU_PASSWORD", "test"),
	}
	dsp, err := newDsp(creds, nil)
	if err != nil {
		t.Fatalf("newDsp: %v", err)
	}
	p := dsp.(*regruProvider)

	zones, err := p.ListZones()
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	t.Logf("ListZones: %v", zones)

	const zone = "test.ru"
	recs, err := p.GetZoneRecords(&models.DomainConfig{Name: zone})
	if err != nil {
		t.Fatalf("GetZoneRecords: %v", err)
	}
	t.Logf("GetZoneRecords(%s): %d records", zone, len(recs))
	for _, r := range recs {
		t.Logf("  %s %s -> %s (ttl %d)", r.Type, r.GetLabel(), r.GetTargetField(), r.TTL)
	}

	// Desired == existing must yield no corrections and change count 0.
	dc := &models.DomainConfig{Name: zone, Records: recs}
	corrections, count, err := p.GetZoneRecordsCorrections(dc, recs)
	if err != nil {
		t.Fatalf("GetZoneRecordsCorrections: %v", err)
	}
	if count != 0 || len(corrections) != 0 {
		t.Errorf("expected no-op corrections, got count=%d corrections=%d", count, len(corrections))
	}
}
