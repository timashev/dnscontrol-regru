// Command dnscontrol is a drop-in DNSControl binary with the REGRU provider
// compiled in. It is the upstream wrapper (commands.Run + blank imports of the
// built-in providers and record types) plus a blank import of this repo's
// provider package, so the REGRU type is available alongside every stock one.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/commands"
	_ "github.com/DNSControl/dnscontrol/v4/pkg/providers/_all"
	_ "github.com/DNSControl/dnscontrol/v4/pkg/rtype"
	"github.com/DNSControl/dnscontrol/v4/pkg/version"
	"github.com/fatih/color"

	// Register the out-of-tree REGRU provider.
	_ "github.com/timashev/dnscontrol-regru/regru"
)

// regruVersion returns dnscontrol's version string marked with "+regru" to
// identify this REGRU-enabled build. The Makefile injects the marker into the
// version at build time (-ldflags -X .../pkg/version.version=...+regru), which
// also makes `dnscontrol version` report it; for plain `go build`/`go install`
// (no ldflags) we append it here so the banner still reflects the fork.
func regruVersion() string {
	v := version.Version()
	if !strings.Contains(v, "+regru") {
		v += "+regru"
	}
	return v
}

func main() {
	if os.Getenv("CI") == "true" {
		color.NoColor = false
	}
	if info, ok := debug.ReadBuildInfo(); !ok && info == nil {
		fmt.Fprint(os.Stderr, "Warning: dnscontrol was built without Go modules. See https://docs.dnscontrol.org/getting-started/getting-started#source for more information on how to build dnscontrol correctly.\n\n")
	}
	os.Exit(commands.Run("DNSControl version " + regruVersion()))
}
