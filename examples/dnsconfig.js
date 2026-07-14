// Example dnsconfig.js for the REGRU provider.
// Addresses use the documentation ranges (RFC 5737 / RFC 3849).

var REG_REGRU = NewRegistrar("regru");
var DSP_REGRU = NewDnsProvider("regru");

D("example.ru", REG_REGRU, DnsProvider(DSP_REGRU),
    A("@", "192.0.2.1"),
    A("www", "192.0.2.1"),
    AAAA("@", "2001:db8::1"),
    CNAME("blog", "www.example.ru."),
    MX("@", 10, "mail.example.ru."),
    TXT("@", "v=spf1 -all"),
    SRV("_sip._tcp", 10, 5, 5060, "sip.example.ru."),
    CAA("@", "issue", "letsencrypt.org"),
);
