package render

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func TestLintWarnsOnLockoutFootguns(t *testing.T) {
	fw := store.Firewall{InputPolicy: "drop"}

	// Nothing accepted: both the UI port and SSH draw a warning.
	warns := Lint(Model{FW: fw}, "0.0.0.0:8080")
	if len(warns) != 2 {
		t.Fatalf("warns = %v", warns)
	}
	if !strings.Contains(warns[0], "8080") || !strings.Contains(warns[1], "SSH") {
		t.Fatalf("unexpected warnings: %v", warns)
	}

	// A rule covering the port silences its warning — even source-restricted.
	rules := []store.Rule{
		{Action: "accept", Proto: "tcp", DPorts: "22", SAddrs: "10.0.0.0/8", Enabled: true},
		{Action: "accept", Proto: "tcp", DPorts: "8000-8100", Enabled: true},
	}
	if warns := Lint(Model{FW: fw, Rules: rules}, "0.0.0.0:8080"); len(warns) != 0 {
		t.Fatalf("covered ports still warned: %v", warns)
	}

	// A disabled rule does not count.
	rules[0].Enabled = false
	if warns := Lint(Model{FW: fw, Rules: rules[:1]}, "127.0.0.1:8080"); len(warns) != 1 || !strings.Contains(warns[0], "SSH") {
		t.Fatalf("disabled rule should not silence the SSH warning: %v", warns)
	}

	// proto any accept silences everything; accept policy lints nothing.
	if warns := Lint(Model{FW: fw, Rules: []store.Rule{{Action: "accept", Proto: "any", Enabled: true}}}, "0.0.0.0:8080"); len(warns) != 0 {
		t.Fatalf("proto any: %v", warns)
	}
	if warns := Lint(Model{FW: store.Firewall{InputPolicy: "accept"}}, "0.0.0.0:8080"); warns != nil {
		t.Fatalf("accept policy: %v", warns)
	}

	// A loopback bind never warns about the UI port.
	warns = Lint(Model{FW: fw}, "127.0.0.1:8080")
	if len(warns) != 1 || !strings.Contains(warns[0], "SSH") {
		t.Fatalf("loopback bind: %v", warns)
	}

	// A populated management list is a guaranteed way in: those sources are
	// accepted before everything, so the lockout warnings stand down.
	mgmt := []store.ListEntry{{List: store.ListMgmt, CIDR: "10.0.0.0/24"}}
	if warns := Lint(Model{FW: fw, Mgmt: mgmt}, "0.0.0.0:8080"); len(warns) != 0 {
		t.Fatalf("management list should silence lockout warnings: %v", warns)
	}
}

func TestLintWarnsOnDormantForwarding(t *testing.T) {
	// Forwarding config without a WAN interface silently renders nothing —
	// lint says so. Policy accept, so the lockout warnings stay out of the way.
	fw := store.Firewall{InputPolicy: "accept"}
	pfs := []store.PortForward{{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", Enabled: true}}
	fwdRules := []store.Rule{{Chain: "forward", Action: "drop", Proto: "any", Enabled: true}}

	warns := Lint(Model{FW: fw, Rules: fwdRules, Forwards: pfs}, "127.0.0.1:8080")
	if len(warns) != 2 {
		t.Fatalf("warns = %v", warns)
	}
	for _, w := range warns {
		if !strings.Contains(w, "WAN interface") {
			t.Fatalf("unexpected warning: %q", w)
		}
	}

	// With the WAN set (or the items disabled) the warnings go away.
	fw.WANIface = "eth0"
	if warns := Lint(Model{FW: fw, Rules: fwdRules, Forwards: pfs}, "127.0.0.1:8080"); len(warns) != 0 {
		t.Fatalf("WAN set, still warned: %v", warns)
	}
	fw.WANIface = ""
	pfs[0].Enabled = false
	fwdRules[0].Enabled = false
	if warns := Lint(Model{FW: fw, Rules: fwdRules, Forwards: pfs}, "127.0.0.1:8080"); len(warns) != 0 {
		t.Fatalf("disabled forwarding items warned: %v", warns)
	}

	// A forward-chain accept rule must not silence input-chain lockout lint.
	fw = store.Firewall{InputPolicy: "drop", WANIface: "eth0"}
	fwdAccept := []store.Rule{{Chain: "forward", Action: "accept", Proto: "any", Enabled: true}}
	warns = Lint(Model{FW: fw, Rules: fwdAccept}, "0.0.0.0:8080")
	if len(warns) != 2 {
		t.Fatalf("forward accept silenced input lint: %v", warns)
	}
}
