---
name: REG.RU
title: REG.RU Provider
jsId: REGRU
---

# REG.RU Provider

This is the provider for [REG.RU](https://www.reg.ru/), using
[REG.API v2](https://www.reg.ru/support/help/api2). It acts as both a DNS
service provider and a registrar (nameserver delegation), and manages the
zone-wide TTL (REG.RU has no per-record TTLs) via `zone/update_soa`.

## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to `REGRU`
along with your REG.RU `username` and API `password`.

Example:

{% code title="creds.json" %}
```json
{
  "regru": {
    "TYPE": "REGRU",
    "username": "your-reg.ru-username",
    "password": "your-dedicated-api-password"
  }
}
```
{% endcode %}

### `api_tier`

The optional `api_tier` key selects how record changes are applied:

- **absent / any value other than `partner`** (default): each change is applied
  with individual client-tier calls (`zone/add_*`, `zone/remove_record`). This
  works on every account.
- **`partner`**: all changes for a zone are batched into a single
  `zone/update_records` call (chunked at 100 actions). `zone/update_records` is
  a partner-tier REG.API function, so only enable this on a partner account.

{% code title="creds.json" %}
```json
{
  "regru": {
    "TYPE": "REGRU",
    "username": "your-reg.ru-username",
    "password": "your-dedicated-api-password",
    "api_tier": "partner"
  }
}
```
{% endcode %}

## Metadata

This provider does not recognize any special metadata fields unique to REG.RU.

## Usage

An example configuration (DNS hosted with REG.RU, REG.RU as registrar):

{% code title="dnsconfig.js" %}
```javascript
var REG_REGRU = NewRegistrar("regru");
var DSP_REGRU = NewDnsProvider("regru");

D("example.ru", REG_REGRU, DnsProvider(DSP_REGRU),
    A("@", "192.0.2.1"),
    A("www", "192.0.2.1"),
    MX("@", 10, "mail.example.ru."),
    TXT("@", "v=spf1 -all"),
    CAA("@", "issue", "letsencrypt.org"),
);
```
{% endcode %}

Registrar only (DNS hosted elsewhere):

{% code title="dnsconfig.js" %}
```javascript
var REG_REGRU = NewRegistrar("regru");
var DSP_R53 = NewDnsProvider("r53");

D("example.ru", REG_REGRU, DnsProvider(DSP_R53),
    A("www", "192.0.2.1"),
);
```
{% endcode %}

## Activation

DNSControl needs a REG.RU account `username` and API `password`.

{% hint style="warning" %}
**IP allowlist is mandatory.** REG.API rejects every request from an IP that is
not on the account's API allowlist. Add the IP that will run DNSControl in the
REG.RU control panel under **Settings → API** before use.
{% endhint %}

{% hint style="info" %}
Create a **dedicated API password** in the REG.RU control panel rather than
reusing your account login password.
{% endhint %}

REG.RU publishes a canned test account, `test`/`test`, that returns fixed
success responses and makes no real changes — useful for smoke testing.

## Rate limits

REG.API allows 1200 requests/hour per account and per IP (a single shared
bucket). The provider's client-side limiter holds the sustained rate at that
ceiling (≈0.333 req/s ≈ 1200 ops/hour) with a small burst. In the default
per-record mode a large initial push is deliberately slow (each record is one
call, paced at ≈1200 ops/hour); `api_tier: partner` batch mode is the fast path.

Requests retry with exponential backoff (up to 5 attempts). Read calls retry on
rate-limit rejections and transient transport failures (HTTP 429/5xx, network
errors); write calls retry only on pre-application rate-limit rejections (HTTP
429 and the `*_EXCEEDED_ALLOWED_CONNECTION_RATE` codes), never on 5xx or a
dropped connection (a lost response could mean the write applied). Zones are
processed serially.

## Limitations

- **TTL is zone-wide, not per-record.** REG.RU has no per-record TTLs — one TTL
  (the SOA TTL) applies to the whole zone. The provider manages it: when all of
  a zone's records share one TTL that differs from the live zone TTL, one
  `zone/update_soa` correction is emitted to set it. Mixed TTLs leave the zone
  TTL unchanged and print a warning. Per-record TTL differences never produce a
  per-record correction. `minimum_ttl` and other SOA fields are not managed.
- **In-zone apex `NS` records are not manageable.** REG.RU's nameserver set is
  fixed and managed by REG.RU; apex `NS` records are ignored by the record diff.
  Delegation is handled by the registrar role (`domain/update_nss`). Subdomain
  `NS` delegation records are managed normally.
- **No zone creation.** Create the DNS-hosting service for the domain in the
  REG.RU control panel first; DNSControl will not create it (it is a
  billing/order operation).
- **No DNSSEC management** (future work).
- **Supported record types**: A, AAAA, CNAME, MX, NS, TXT, SRV, CAA. ALIAS/ANAME,
  HTTPS/SVCB, PTR, NAPTR, SSHFP, TLSA, and DS/DNSKEY are not supported.
- **SRV/CAA read format** is assumed (`weight port target` for SRV with priority
  in the `prio` field; `flags tag value` for CAA) and has not been verified
  against a live account, because the `test`/`test` account only returns an A
  record. SRV records use REG.API's `service` field derived from the owner label
  (`_sip._tcp` → `sip.tcp`), so SRV is supported only at `_service._proto`
  owners; deeper owners (e.g. `_sip._tcp.dept`) are rejected by the auditor.
