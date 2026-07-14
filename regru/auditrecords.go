package regru

import (
	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns errors for records this provider cannot represent. An
// empty result means every record is supported.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}

	a.Add("TXT", rejectif.TxtIsEmpty)                  // REG.API rejects empty TXT
	a.Add("CAA", rejectif.CaaTargetContainsWhitespace) // value is sent unquoted

	return a.Audit(records)
}
