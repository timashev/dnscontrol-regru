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

// GetZoneRecordsCorrections computes the actions that turn existing into
// dc.Records and returns a single correction that applies them via chunked
// zone/update_records calls.
func (p *regruProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existing models.Records) ([]*models.Correction, int, error) {
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
	var deletes, replaces, creates [][]recordAction
	var msgs []string

	for _, ch := range changes {
		switch ch.Type {
		case diff2.REPORT:
			corrections = append(corrections, ch.CreateMessage())
		case diff2.CREATE:
			add, err := recordToAddAction(ch.New[0])
			if err != nil {
				return nil, 0, err
			}
			creates = append(creates, []recordAction{add})
			msgs = append(msgs, ch.Msgs...)
		case diff2.DELETE:
			deletes = append(deletes, []recordAction{recordToRemoveAction(ch.Old[0])})
			msgs = append(msgs, ch.Msgs...)
		case diff2.CHANGE:
			// REG.RU cannot modify a record in place; replace = remove old +
			// add new. Keep the pair together so it lands in one request.
			add, err := recordToAddAction(ch.New[0])
			if err != nil {
				return nil, 0, err
			}
			replaces = append(replaces, []recordAction{recordToRemoveAction(ch.Old[0]), add})
			msgs = append(msgs, ch.Msgs...)
		default:
			return nil, 0, fmt.Errorf("regru: unhandled change type %v", ch.Type)
		}
	}

	// Order: pure removals first (also handles type swaps at a name), then
	// same-rrset replaces (each an atomic remove+add pair), then pure creates.
	var groups [][]recordAction
	groups = append(groups, deletes...)
	groups = append(groups, replaces...)
	groups = append(groups, creates...)

	if chunks := chunkActions(groups, maxActionsPerChunk); len(chunks) > 0 {
		dname := dc.Name
		corrections = append(corrections, &models.Correction{
			Msg: strings.Join(msgs, "\n"),
			F: func() error {
				for _, chunk := range chunks {
					if err := p.updateRecords(dname, chunk); err != nil {
						return err
					}
				}
				return nil
			},
		})
	}

	return corrections, actualChangeCount, nil
}
