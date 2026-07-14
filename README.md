# dnscontrol-regru

An out-of-tree [DNSControl](https://dnscontrol.org/) provider for
[REG.RU](https://www.reg.ru/), built on REG.API v2. It manages both DNS records
and registrar nameserver delegation for domains hosted on REG.RU's DNS.

DNSControl has no in-tree REG.RU provider, and providers are compiled in (there
is no plugin system). This repo therefore ships two things:

1. the provider package (`regru/`), implementing the standard DNSControl
   interfaces and shaped for a future upstream `providers/regru` PR; and
2. `cmd/dnscontrol` — the stock DNSControl wrapper plus a blank import of this
   provider, producing a drop-in `dnscontrol` binary with the `REGRU` type
   available alongside every built-in provider.

## Features

- **DNS service provider** — read and apply record corrections.
- **Registrar** — sync nameserver delegation (`domain/update_nss`).
- **Record types**: A, AAAA, CNAME, MX, NS, TXT, SRV, CAA.
- Built-in client-side rate limiting and retry/backoff for REG.API's limits.

## Quick start

### 1. Build

```sh
git clone https://github.com/timashev/dnscontrol-regru
cd dnscontrol-regru
make build      # -> ./dnscontrol (REGRU + all stock providers compiled in)
```

`make build` injects the version so `./dnscontrol version` reports
`v4.42.0+regru`. A plain `go build ./cmd/dnscontrol` (or
`go install github.com/timashev/dnscontrol-regru/cmd/dnscontrol@latest`) also
works; without the Makefile's `-ldflags`, the `version` subcommand shows the Go
module version instead of the `+regru` marker.

### 2. Configure credentials

Create `creds.json` (see [`examples/creds.json.example`](examples/creds.json.example)):

```json
{
  "regru": {
    "TYPE": "REGRU",
    "username": "your-reg.ru-username",
    "password": "your-dedicated-api-password"
  }
}
```

> **Authentication requirements (read this first).** REG.API requires a
> **mandatory IP allowlist**: every calling IP must be whitelisted in the REG.RU
> control panel (Settings → API), or all requests fail. You should also create a
> **dedicated API password** rather than using your account login password. See
> [Activation](#activation) below.

### 3. Write `dnsconfig.js`

See [`examples/dnsconfig.js`](examples/dnsconfig.js):

```javascript
var REG_REGRU = NewRegistrar("regru");
var DSP_REGRU = NewDnsProvider("regru");

D("example.ru", REG_REGRU, DnsProvider(DSP_REGRU),
    A("@", "192.0.2.1"),
    A("www", "192.0.2.1"),
    MX("@", 10, "mail.example.ru."),
    TXT("@", "v=spf1 -all"),
);
```

### 4. Preview and apply

```sh
./dnscontrol check
./dnscontrol preview
./dnscontrol push
```

## Configuration

`creds.json` keys:

| Key | Required | Description |
| --- | --- | --- |
| `TYPE` | yes | Must be `REGRU`. |
| `username` | yes | REG.RU account username. |
| `password` | yes | API password (use a dedicated one; see Activation). |
| `api_tier` | no | `partner` batches all changes into one `zone/update_records` call per zone (partner-tier API). Absent or any other value uses the default **per-record** mode (client-tier `zone/add_*` + `zone/remove_record` calls), which works on every account. |

The same entry serves both the registrar and the DNS service provider.

## Rate limits

REG.API allows **1200 requests/hour per account and per IP**. The provider adds
a client-side limiter (default 1 request/second) and retries with exponential
backoff (up to 5 attempts) on the `IP_EXCEEDED_ALLOWED_CONNECTION_RATE` and
`ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE` error codes and on HTTP 429/5xx.
Because the account and per-IP quota is a single shared bucket, the provider does
not run zones concurrently.

## Limitations

- **TTL is not manageable.** REG.RU DNS uses a fixed per-zone TTL; the zone
  functions carry no per-record TTL. Existing records are reported with the
  zone TTL, and TTL differences never produce a correction.
- **Apex NS records are not manageable.** REG.RU's nameserver set is fixed and
  managed by REG.RU; in-zone apex `NS` records are ignored by the diff.
  Nameserver delegation is handled by the **registrar** role
  (`domain/update_nss`). (Subdomain `NS` delegation records *are* managed.)
- **No zone creation.** DNSControl will not create the DNS-hosting service —
  that is a billing/order operation. Create the DNS hosting service for the
  domain in the REG.RU control panel first.
- **No DNSSEC management** and no `undelegate` handling — future work.
- **Unsupported record types**: ALIAS/ANAME, HTTPS/SVCB, PTR, NAPTR, SSHFP,
  TLSA, DS/DNSKEY. Only A, AAAA, CNAME, MX, NS, TXT, SRV, CAA are supported.
- **SRV/CAA read format is assumed, not verified.** The REG.API `test`/`test`
  account only ever returns a single A record, so the exact `content` shape of
  SRV and CAA records as returned by `zone/get_resource_records` could not be
  verified live. SRV `content` is assumed to be `weight port target` (priority
  in the `prio` field) and CAA `content` is assumed to be `flags tag value`. The
  write paths use REG.API's documented `add_srv`/`add_caa` fields. Please report
  any mismatch.
- **SRV service label.** REG.API's `add_srv` takes a `service` field (e.g.
  `sip.tcp`) rather than a subdomain; the provider derives it from the SRV owner
  label (`_sip._tcp`) by stripping underscores.

## Test account

REG.RU publishes a canned test account, `test`/`test`, that returns fixed
success responses and makes no real changes or charges. It is useful for a smoke
test:

```sh
# creds.json uses {"username":"test","password":"test"}
./dnscontrol get-zones test REGRU test.ru
./dnscontrol preview
```

## Upstream

This provider is deliberately shaped to move into
[`DNSControl/dnscontrol`](https://github.com/DNSControl/dnscontrol) as
`providers/regru`. [`docs/regru.md`](docs/regru.md) is written in DNSControl's
provider-documentation format, ready to accompany that PR.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: `make check` must pass
(`gofmt`, `go vet`, `golangci-lint`, `go test`), and changes need tests.

## License

[MIT](LICENSE) © Albert Timashev.
