package regru

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
)

// defaultZoneTTL is used only for TTL normalization when a zone has no existing
// records to borrow a TTL from. REG.RU does not honor per-record TTLs, so the
// exact value is immaterial to correctness — it only keeps TTL from ever being
// a diff source.
const defaultZoneTTL uint32 = 86400

// recordToAddAction converts a desired RecordConfig into the matching
// zone/update_records add_* action. REG.RU's relative names (@, *, labels) map
// directly to dnscontrol's short label, so no @<->"" translation is needed.
func recordToAddAction(rc *models.RecordConfig) (recordAction, error) {
	sub := rc.GetLabel()
	switch rc.Type {
	case "A":
		return recordAction{"action": "add_alias", "subdomain": sub, "ipaddr": rc.GetTargetField()}, nil
	case "AAAA":
		return recordAction{"action": "add_aaaa", "subdomain": sub, "ipaddr": rc.GetTargetField()}, nil
	case "CNAME":
		return recordAction{"action": "add_cname", "subdomain": sub, "canonical_name": trimDot(rc.GetTargetField())}, nil
	case "MX":
		return recordAction{"action": "add_mx", "subdomain": sub, "priority": u16(rc.MxPreference), "mail_server": trimDot(rc.GetTargetField())}, nil
	case "NS":
		return recordAction{"action": "add_ns", "subdomain": sub, "dns_server": trimDot(rc.GetTargetField())}, nil
	case "TXT":
		return recordAction{"action": "add_txt", "subdomain": sub, "text": rc.GetTargetTXTJoined()}, nil
	case "SRV":
		// REG.API add_srv takes a "service" field (e.g. "sip.tcp"), not a
		// subdomain: it is the SRV owner label (_sip._tcp) with underscores
		// stripped.
		return recordAction{
			"action":   "add_srv",
			"service":  srvService(rc.GetLabel()),
			"priority": u16(rc.SrvPriority),
			"weight":   u16(rc.SrvWeight),
			"port":     u16(rc.SrvPort),
			"target":   trimDot(rc.GetTargetField()),
		}, nil
	case "CAA":
		return recordAction{"action": "add_caa", "subdomain": sub, "flags": u8(rc.CaaFlag), "tag": rc.CaaTag, "value": rc.GetTargetField()}, nil
	default:
		return nil, fmt.Errorf("regru: unsupported record type %q", rc.Type)
	}
}

// recordToRemoveAction builds a remove_record action for an existing record.
// It derives subdomain/content/priority from the stored native record so the
// removal targets exactly that record (content matches what REG.RU has).
func recordToRemoveAction(rc *models.RecordConfig) recordAction {
	a := recordAction{"action": "remove_record", "record_type": rc.Type}
	if native, ok := rc.Original.(*nativeRR); ok && native != nil {
		a["subdomain"] = native.Subname
		a["content"] = native.Content
		if native.Prio != "" && (rc.Type == "MX" || rc.Type == "SRV") {
			a["priority"] = native.Prio
		}
	} else {
		// Fallback (existing records always carry Original in practice).
		a["subdomain"] = rc.GetLabel()
		a["content"] = rc.GetTargetField()
	}
	return a
}

// nativeToRecordConfig converts one REG.RU resource record into a
// RecordConfig, tagging it with the zone TTL and preserving the native record
// (used later to build exact removals). Unsupported types (incl. SOA) return
// (nil, nil) so callers skip them.
func nativeToRecordConfig(origin string, rr *nativeRR, ttl uint32) (*models.RecordConfig, error) {
	rc := &models.RecordConfig{Type: rr.Rectype, TTL: ttl, Original: rr}
	rc.SetLabel(rr.Subname, origin)
	prio, _ := strconv.ParseUint(rr.Prio, 10, 16)

	var err error
	switch rr.Rectype {
	case "A", "AAAA":
		err = rc.SetTarget(rr.Content)
	case "CNAME", "NS":
		err = rc.SetTarget(ensureDot(rr.Content))
	case "MX":
		err = rc.SetTargetMX(uint16(prio), ensureDot(rr.Content))
	case "TXT":
		err = rc.SetTargetTXT(rr.Content)
	case "SRV":
		// Assumed content shape: "weight port target" (priority is the prio
		// field). Verify against a live account in the smoke test (brief 003).
		err = rc.SetTargetSRVPriorityString(uint16(prio), ensureDotSRVTarget(rr.Content))
	case "CAA":
		// Assumed content shape: `flags tag value` (optionally quoted value).
		err = rc.SetTargetCAAString(rr.Content)
	default:
		// SOA and any record type this provider does not manage are skipped.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("regru: parsing %s record %q: %w", rr.Rectype, rr.Subname, err)
	}
	return rc, nil
}

// chunkActions groups action-groups into chunks of at most max actions, never
// splitting a group. A group is a single add/remove for a CREATE/DELETE, or a
// [remove, add] pair for a CHANGE — keeping the pair together guarantees a
// same-rrset replace is applied atomically within one request.
func chunkActions(groups [][]recordAction, max int) [][]recordAction {
	var chunks [][]recordAction
	var cur []recordAction
	for _, g := range groups {
		if len(cur) > 0 && len(cur)+len(g) > max {
			chunks = append(chunks, cur)
			cur = nil
		}
		cur = append(cur, g...)
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// parseRegruTTL parses a REG.RU TTL string ("3600", "1d", "12h", "1w", "1m")
// into seconds. m is months (30 days) per REG.API, not minutes. Unparseable
// input falls back to defaultZoneTTL.
func parseRegruTTL(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultZoneTTL
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n)
	}
	unit := s[len(s)-1]
	n, err := strconv.ParseUint(s[:len(s)-1], 10, 32)
	if err != nil {
		return defaultZoneTTL
	}
	var mult uint64
	switch unit {
	case 'h', 'H':
		mult = 3600
	case 'd', 'D':
		mult = 86400
	case 'w', 'W':
		mult = 604800
	case 'm', 'M':
		mult = 2592000 // 30 days
	default:
		return defaultZoneTTL
	}
	return uint32(n * mult)
}

func u16(v uint16) string { return strconv.FormatUint(uint64(v), 10) }
func u8(v uint8) string   { return strconv.FormatUint(uint64(v), 10) }

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func ensureDot(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// ensureDotSRVTarget adds a trailing dot to the target (3rd field) of an SRV
// "weight port target" content string, matching how dnscontrol stores targets.
func ensureDotSRVTarget(content string) string {
	f := strings.Fields(content)
	if len(f) == 3 {
		f[2] = ensureDot(f[2])
		return strings.Join(f, " ")
	}
	return content
}

// srvService turns an SRV owner label ("_sip._tcp") into REG.API's "service"
// value ("sip.tcp") by removing underscores.
func srvService(label string) string { return strings.ReplaceAll(label, "_", "") }
