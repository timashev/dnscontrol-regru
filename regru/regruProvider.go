package regru

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/diff2"
	"github.com/DNSControl/dnscontrol/v4/pkg/providers"
)

const providerName = "REGRU"

// maxActionsPerChunk bounds how many actions go into one zone/update_records
// request.
const maxActionsPerChunk = 100

// defaultNameServers is REG.RU's DNS-hosting nameserver pair.
var defaultNameServers = []string{"ns1.reg.ru", "ns2.reg.ru"}

// regruProvider is a REGRU DNS service provider. It embeds the REG.API client.
type regruProvider struct {
	*regruClient
}

var (
	_ providers.DNSServiceProvider = (*regruProvider)(nil)
	_ providers.ZoneLister         = (*regruProvider)(nil)
	_ providers.Registrar          = (*regruProvider)(nil)
)

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	providers.CanGetZones:            providers.Can(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanConcur:              providers.Cannot("REG.RU rate-limits per account and per IP (one shared bucket), so concurrent zone processing is counterproductive."),
	providers.DocDualHost:            providers.Cannot("REG.RU DNS hosting serves a fixed nameserver set."),
	providers.DocCreateDomains:       providers.Cannot("Creating the DNS-hosting service is a billing/order operation; create it in the REG.RU control panel first."),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	fns := providers.DspFuncs{
		Initializer:   newDsp,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterRegistrarType(providerName, newRegistrar)
	providers.RegisterMaintainer(providerName, "@timashev")
}

// newDsp builds a REGRU DNS service provider from creds.json.
func newDsp(m map[string]string, _ json.RawMessage) (providers.DNSServiceProvider, error) {
	c, err := newClient(m)
	if err != nil {
		return nil, err
	}
	return &regruProvider{regruClient: c}, nil
}

// newRegistrar builds a REGRU registrar from creds.json.
func newRegistrar(m map[string]string) (providers.Registrar, error) {
	c, err := newClient(m)
	if err != nil {
		return nil, err
	}
	return &regruProvider{regruClient: c}, nil
}

// GetNameservers returns REG.RU's fixed DNS-hosting nameservers.
func (p *regruProvider) GetNameservers(string) ([]*models.Nameserver, error) {
	return models.ToNameservers(defaultNameServers)
}

// ListZones returns the account's domains (services of type "domain").
func (p *regruProvider) ListZones() ([]string, error) {
	svcs, err := p.listServices()
	if err != nil {
		return nil, err
	}
	var zones []string
	for _, s := range svcs {
		if s.Servtype == "domain" {
			zones = append(zones, s.DName)
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// GetZoneRecords fetches the zone's records in dnscontrol's native format.
func (p *regruProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	// dnscontrol hands us punycode; send it through unchanged.
	dom, err := p.getResourceRecords(dc.Name)
	if err != nil {
		return nil, err
	}
	zoneTTL := parseRegruTTL(dom.SOA.TTL)

	var records models.Records
	for i := range dom.RRs {
		rc, err := nativeToRecordConfig(dc.Name, &dom.RRs[i], zoneTTL)
		if err != nil {
			return nil, err
		}
		if rc == nil { // unsupported type or SOA — skip
			continue
		}
		records = append(records, rc)
	}
	return records, nil
}

// recordChange is one diff2 change lowered to REG.API actions. For a rrset
// replace, removes precede adds; a pure create has only adds, a pure delete
// only removes.
type recordChange struct {
	msg     string
	removes []recordAction
	adds    []recordAction
}

// GetZoneRecordsCorrections computes the actions that turn existing into
// dc.Records. By default each change is applied with per-record client-tier
// calls; with api_tier=partner the actions are batched into chunked
// zone/update_records requests.
func (p *regruProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existing models.Records) ([]*models.Correction, int, error) {
	// Apex NS are fixed/managed by REG.RU; never manage them as zone records.
	existing = dropApexNS(existing)
	dc.Records = dropApexNS(dc.Records)

	// REG.RU has no per-record TTL. Equalize desired TTLs to the zone TTL so a
	// TTL difference alone never produces a correction.
	zoneTTL := defaultZoneTTL
	if len(existing) > 0 {
		zoneTTL = existing[0].TTL
	}
	for _, rec := range dc.Records {
		rec.TTL = zoneTTL
	}

	changes, actualChangeCount, err := diff2.ByRecord(existing, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	var corrections []*models.Correction
	var deletes, replaces, creates []recordChange

	for _, ch := range changes {
		switch ch.Type {
		case diff2.REPORT:
			corrections = append(corrections, ch.CreateMessage())
		case diff2.CREATE:
			add, err := recordToAddAction(ch.New[0])
			if err != nil {
				return nil, 0, err
			}
			creates = append(creates, recordChange{msg: ch.MsgsJoined, adds: []recordAction{add}})
		case diff2.DELETE:
			deletes = append(deletes, recordChange{msg: ch.MsgsJoined, removes: []recordAction{recordToRemoveAction(ch.Old[0])}})
		case diff2.CHANGE:
			// REG.RU cannot modify a record in place; replace = remove old +
			// add new, applied in that order for the same rrset.
			add, err := recordToAddAction(ch.New[0])
			if err != nil {
				return nil, 0, err
			}
			replaces = append(replaces, recordChange{
				msg:     ch.MsgsJoined,
				removes: []recordAction{recordToRemoveAction(ch.Old[0])},
				adds:    []recordAction{add},
			})
		default:
			return nil, 0, fmt.Errorf("regru: unhandled change type %v", ch.Type)
		}
	}

	// Order: pure removals first (also handles type swaps at a name), then
	// same-rrset replaces (each removals-then-additions), then pure creates.
	ordered := make([]recordChange, 0, len(deletes)+len(replaces)+len(creates))
	ordered = append(ordered, deletes...)
	ordered = append(ordered, replaces...)
	ordered = append(ordered, creates...)

	if p.partnerTier {
		corrections = append(corrections, p.partnerCorrections(dc.Name, ordered)...)
	} else {
		corrections = append(corrections, p.perRecordCorrections(dc.Name, ordered)...)
	}

	return corrections, actualChangeCount, nil
}

// perRecordCorrections emits one correction per change; each executes its
// removals immediately followed by its additions as individual client-tier
// zone/add_* + zone/remove_record calls.
func (p *regruProvider) perRecordCorrections(dname string, changes []recordChange) []*models.Correction {
	var corrections []*models.Correction
	for _, ch := range changes {
		ch := ch
		corrections = append(corrections, &models.Correction{
			Msg: ch.msg,
			F: func() error {
				for _, a := range ch.removes {
					if err := p.applyRecordAction(dname, a); err != nil {
						return err
					}
				}
				for _, a := range ch.adds {
					if err := p.applyRecordAction(dname, a); err != nil {
						return err
					}
				}
				return nil
			},
		})
	}
	return corrections
}

// partnerCorrections batches all actions into chunked zone/update_records
// requests (partner-tier). Each change is one group (removals then additions)
// kept intact within a chunk so a replace never splits across requests.
func (p *regruProvider) partnerCorrections(dname string, changes []recordChange) []*models.Correction {
	var groups [][]recordAction
	var msgs []string
	for _, ch := range changes {
		group := make([]recordAction, 0, len(ch.removes)+len(ch.adds))
		group = append(group, ch.removes...)
		group = append(group, ch.adds...)
		groups = append(groups, group)
		msgs = append(msgs, ch.msg)
	}

	chunks := chunkActions(groups, maxActionsPerChunk)
	if len(chunks) == 0 {
		return nil
	}
	return []*models.Correction{{
		Msg: strings.Join(msgs, "\n"),
		F: func() error {
			for _, chunk := range chunks {
				if err := p.updateRecords(dname, chunk); err != nil {
					return err
				}
			}
			return nil
		},
	}}
}

// GetRegistrarCorrections syncs the domain's delegation nameservers with
// dc.Nameservers. It emits nothing when the sets match modulo order, case, and
// trailing dots.
func (p *regruProvider) GetRegistrarCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	current, err := p.getNameservers(dc.Name)
	if err != nil {
		return nil, err
	}

	desired := make([]string, 0, len(dc.Nameservers))
	for _, ns := range dc.Nameservers {
		desired = append(desired, ns.Name)
	}

	if nsSetsEqual(current, desired) {
		return nil, nil
	}

	dname := dc.Name
	want := desired
	return []*models.Correction{{
		Msg: fmt.Sprintf("Update nameservers %s -> %s",
			strings.Join(sortedNormalizedNS(current), ","),
			strings.Join(sortedNormalizedNS(want), ",")),
		F: func() error { return p.updateNameservers(dname, want) },
	}}, nil
}

// normalizeNS lowercases and strips a trailing dot for order/case/dot-insensitive
// nameserver comparison.
func normalizeNS(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func sortedNormalizedNS(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = normalizeNS(s)
	}
	sort.Strings(out)
	return out
}

func nsSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	na, nb := sortedNormalizedNS(a), sortedNormalizedNS(b)
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}
