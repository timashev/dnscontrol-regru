package main

import (
	"strings"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/pkg/providers"
)

// The blank import must register REGRU as both a DNS provider and a registrar.
func TestRegruRegistered(t *testing.T) {
	if _, ok := providers.DNSProviderTypes["REGRU"]; !ok {
		t.Error("REGRU is not registered as a DNS provider")
	}
	if _, ok := providers.RegistrarTypes["REGRU"]; !ok {
		t.Error("REGRU is not registered as a registrar")
	}
}

// Stock providers must still be compiled in alongside REGRU.
func TestStockProvidersRegistered(t *testing.T) {
	for _, name := range []string{"BIND", "CLOUDFLAREAPI"} {
		if _, ok := providers.DNSProviderTypes[name]; !ok {
			t.Errorf("stock provider %s is not registered", name)
		}
	}
}

func TestRegruVersionMarkedOnce(t *testing.T) {
	v := regruVersion()
	if n := strings.Count(v, "+regru"); n != 1 {
		t.Errorf("regruVersion() = %q, want exactly one +regru marker, got %d", v, n)
	}
}
