# Contributing

Issues and pull requests are welcome.

## Ground rules

- **Formatting**: code must be `gofmt`-clean.
- **Linting**: `golangci-lint run ./...` must pass with no issues.
- **Tests**: changes need tests. Unit tests use `httptest` — no live network
  calls. Run the full suite with `go test ./...`.
- Run everything CI runs before opening a PR:

  ```sh
  make check   # gofmt + go vet + golangci-lint + go test + build
  ```

## Live tests

`regru/live_test.go` is gated on `REGRU_LIVE=1` and defaults to the canned
`test`/`test` account. It only reads and computes a no-op correction — it never
applies changes. Never point live tests at a real domain.

```sh
REGRU_LIVE=1 go test ./regru/ -run TestLive -v
```

## Layout

The `regru/` package is deliberately shaped to move into
[`DNSControl/dnscontrol`](https://github.com/DNSControl/dnscontrol) as
`providers/regru`. Keep it importing only the standard library, the dnscontrol
module, and `golang.org/x/time/rate`. The wrapper binary lives in
`cmd/dnscontrol`.
