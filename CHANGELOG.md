# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-07-15

### Fixed

- IDN (`xn--*`) zones that REG.API lists in Unicode are now returned as punycode
  from `ListZones`, matching dnscontrol's punycode comparison. Fixes
  `Zone "…" does not exist … does not implement ZoneCreator` on `preview`/`push`
  for internationalized domains (e.g. `.рф`).

## [1.1.0] - 2026-07-15

### Added

- Zone-wide TTL management via `zone/update_soa`. When every record in a zone
  shares one TTL that differs from the live zone TTL, `preview`/`push` emits a
  single correction to update the zone (SOA) TTL. Mixed TTLs leave the zone TTL
  unchanged and print a warning; `minimum_ttl` and other SOA fields are not
  managed.

## [1.0.0] - 2026-07-15

Initial release: an out-of-tree DNSControl provider for REG.RU (REG.API v2),
plus a drop-in `dnscontrol` wrapper binary.

### Added

- DNS service provider: A, AAAA, CNAME, MX, NS, TXT, SRV, CAA records via
  `pkg/diff2` ByRecord.
- Registrar role: nameserver delegation sync via `domain/get_nss` /
  `domain/update_nss`.
- Two execution modes: default per-record (client-tier) calls, and a batched
  `zone/update_records` path behind the `api_tier: "partner"` creds option.
- Client-side rate limiter at REG.API's 1200 req/hr ceiling, with retry/backoff
  (reads retry transient transport failures; writes retry only pre-application
  rate-limit rejections).
- Fixed nameserver set (`ns1.reg.ru`, `ns2.reg.ru`); apex NS records are treated
  as REG.RU-managed and excluded from the record diff.

### Fixed

- Accept JSON numbers (not only strings) for `rrs[].prio` and `soa.ttl` /
  `soa.minimum_ttl`, which real accounts return as bare numbers (the canned
  `test`/`test` account returns strings).
