// Command dnscontrol is a drop-in DNSControl binary with the REGRU provider
// compiled in. It is the upstream wrapper (commands.Run + blank imports of the
// built-in providers and record types) plus a blank import of this repo's
// provider package, so the REGRU type is available alongside every stock one.
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/DNSControl/dnscontrol/v4/commands"
	_ "github.com/DNSControl/dnscontrol/v4/pkg/providers/_all"
	_ "github.com/DNSControl/dnscontrol/v4/pkg/rtype"
	"github.com/DNSControl/dnscontrol/v4/pkg/version"
	"github.com/fatih/color"

	// Register the out-of-tree REGRU provider.
	_ "github.com/timashev/dnscontrol-regru/regru"
)

func main() {
	if os.Getenv("CI") == "true" {
		color.NoColor = false
	}
	if info, ok := debug.ReadBuildInfo(); !ok && info == nil {
		fmt.Fprint(os.Stderr, "Warning: dnscontrol was built without Go modules. See https://docs.dnscontrol.org/getting-started/getting-started#source for more information on how to build dnscontrol correctly.\n\n")
	}
	os.Exit(commands.Run("DNSControl version " + version.Version() + "+regru"))
}
