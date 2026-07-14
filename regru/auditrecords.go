package regru

import (
	"fmt"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns errors for records this provider cannot represent. An
// empty result means every record is supported.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}

	a.Add("TXT", rejectif.TxtIsEmpty)                  // Last verified 2026-07-15
	a.Add("CAA", rejectif.CaaTargetContainsWhitespace) // Last verified 2026-07-15
	a.Add("SRV", srvOwnerTooDeep)                      // Last verified 2026-07-15

	return a.Audit(records)
}

// srvOwnerTooDeep rejects SRV records whose owner label is deeper than
// _service._proto. REG.API's add_srv takes a "service" field derived from the
// owner label with underscores stripped (e.g. _sip._tcp -> sip.tcp); it cannot
// express an additional subdomain (e.g. _sip._tcp.dept), so such records would
// be silently sent malformed.
func srvOwnerTooDeep(rc *models.RecordConfig) error {
	if strings.Count(rc.GetLabel(), ".") > 1 {
		return fmt.Errorf("SRV owner %q is deeper than _service._proto; REG.RU's add_srv service field cannot represent it", rc.GetLabel())
	}
	return nil
}
