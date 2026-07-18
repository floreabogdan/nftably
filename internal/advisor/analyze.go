package advisor

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/simulate"
)

// Finding is one grounded piece of advice: an observed fact about the box, what
// the firewall model does about it (Verdict), and optionally a one-click fix
// (Allow) or a link into the simulator (Sim).
type Finding struct {
	Key      string // stable id, for dismissal
	Severity string // "warn" | "info"
	Title    string
	Detail   string
	Verdict  string       // the firewall's verdict for the exposure: ACCEPT|DROP|REJECT|""
	Allow    *AllowAction // present when a one-click accept rule makes sense
	Sim      string       // query string that opens this case in /simulate
}

// AllowAction is the one-click "let this in" a blocked-listener finding offers.
type AllowAction struct {
	Proto string
	Port  int
	Label string
}

// Options is the context the analysis needs beyond the scan and the model.
type Options struct {
	ListenPort int    // nftably's own port — skipped (handled by access control)
	ExternalIf string // a non-loopback interface to trace arriving on ("" = unspecified)
}

// serviceNames labels well-known ports when the process name is unknown.
var serviceNames = map[int]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "an HTTP server", 111: "rpcbind", 143: "IMAP",
	179: "BGP", 443: "an HTTPS server", 445: "SMB", 587: "SMTP submission", 993: "IMAPS",
	3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 8080: "an HTTP server",
	9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB", 51820: "WireGuard",
}

// sensitivePorts are services that generally should not face the open internet;
// the value is a short description used in the exposure warning.
var sensitivePorts = map[int]string{
	111: "an RPC endpoint", 445: "SMB file sharing", 2375: "the Docker API",
	3306: "a MySQL/MariaDB database", 5432: "a PostgreSQL database", 6379: "a Redis instance",
	9200: "an Elasticsearch node", 11211: "a memcached instance", 27017: "a MongoDB database",
	5984: "a CouchDB database", 9000: "an admin/RPC service",
}

// externalSrc/externalDst are the stand-in "from the internet" endpoints the
// analysis traces with: documentation-range addresses (RFC 5737) that are in no
// management set, so they represent an untrusted outsider.
var (
	externalSrc = netip.MustParseAddr("198.51.100.7")
	externalDst = netip.MustParseAddr("192.0.2.1")
)

// Analyze turns a scan plus the firewall model into grounded findings, using the
// packet simulator to decide what the firewall actually does with each observed
// listener.
func Analyze(scan Scan, model nftconf.Model, opts Options) []Finding {
	var out []Finding

	// Per-listener exposure — the core. A service bound to 0.0.0.0 and :: shows
	// as two listeners on one port; one finding per proto/port is enough.
	seen := map[string]bool{}
	for _, l := range scan.Listeners {
		if !l.Wild || l.Port == opts.ListenPort {
			continue // loopback-only isn't externally exposed; skip nftably's own port
		}
		pk := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		if seen[pk] {
			continue
		}
		seen[pk] = true
		if f, ok := listenerFinding(l, model, opts); ok {
			out = append(out, f)
		}
	}

	// High-level inbound posture.
	out = append(out, postureFindings(model)...)

	// Routing.
	if scan.IPForward {
		if f, ok := forwardingFinding(model); ok {
			out = append(out, f)
		}
	}

	// Tools that manage their own netfilter rules — the advisor can't see them.
	if scan.HasSoftware("docker") {
		out = append(out, Finding{Key: "docker-bypass", Severity: "info",
			Title:  "Docker manages its own netfilter rules",
			Detail: "Published container ports (-p) are DNAT'd before your input chain, so input rules don't gate them and this analysis can't see them. Audit with `docker ps`, and publish on 127.0.0.1 where a container isn't meant to be public."})
	}
	if scan.HasSoftware("incus") {
		out = append(out, Finding{Key: "incus-bypass", Severity: "info",
			Title:  "Incus/LXD instance traffic bypasses the input chain",
			Detail: "Bridged instances are forwarded, not delivered to this host, so input rules don't filter them. Filter them with forward-chain rules and Incus's own network ACLs."})
	}

	sortFindings(out)
	return out
}

// listenerFinding traces an external connection to a listener and classifies the
// result.
func listenerFinding(l Listener, model nftconf.Model, opts Options) (Finding, bool) {
	tr := simulate.Simulate(model, "input", simulate.Packet{
		Proto: l.Proto, Src: externalSrc, Dst: externalDst,
		DPort: l.Port, Iif: opts.ExternalIf, CtState: "new",
	})
	svc := serviceLabel(l)
	sim := simQuery(l, opts)
	base := fmt.Sprintf("listener-%s-%d", l.Proto, l.Port)
	uncertain := ""
	if tr.Uncertain {
		uncertain = " (a rule ahead of it couldn't be fully evaluated — open the simulator for the full trace)"
	}

	switch tr.Final {
	case "ACCEPT":
		if sens, ok := sensitivePorts[l.Port]; ok {
			return Finding{
				Key: base + "-exposed", Severity: "warn", Verdict: "ACCEPT", Sim: sim,
				Title:  fmt.Sprintf("%s is reachable from the internet (%s/%d)", svc, l.Proto, l.Port),
				Detail: fmt.Sprintf("Your firewall would accept a connection from any address to %s. Restrict this rule to the sources that need it, or bind the service to localhost / an internal interface.%s", sens, uncertain),
			}, true
		}
		return Finding{
			Key: base + "-open", Severity: "info", Verdict: "ACCEPT", Sim: sim,
			Title:  fmt.Sprintf("%s accepts connections from any address (%s/%d)", svc, l.Proto, l.Port),
			Detail: "Fine for a public service. If it's only meant for a management network or specific clients, restrict the rule's source addresses." + uncertain,
		}, true
	case "DROP", "REJECT":
		return Finding{
			Key: base + "-blocked", Severity: "info", Verdict: tr.Final, Sim: sim,
			Title:  fmt.Sprintf("%s is listening but the firewall blocks it (%s/%d)", svc, l.Proto, l.Port),
			Detail: fmt.Sprintf("A connection from outside would be %s. If this service should be reachable, allow it — ideally restricted to the sources that need it.%s", verdictPast(tr.Final), uncertain),
			Allow:  &AllowAction{Proto: l.Proto, Port: l.Port, Label: "Allow " + svc},
		}, true
	}
	return Finding{}, false
}

// postureFindings reports the overall inbound-filtering stance from the model.
func postureFindings(model nftconf.Model) []Finding {
	var inputChains []nftconf.ChainTree
	for _, t := range model.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "input" && c.ChainType != "nat" {
				inputChains = append(inputChains, c)
			}
		}
	}
	if len(inputChains) == 0 {
		return []Finding{{Key: "no-input-chain", Severity: "warn",
			Title:  "Nothing filters inbound traffic to this box",
			Detail: "No base chain hooks the input path, so netfilter accepts everything by default — every listening service is reachable. Add an input chain (a preset is the quickest way) to start filtering."}}
	}
	allAccept := true
	for _, c := range inputChains {
		if c.Policy == "drop" {
			allAccept = false
			break
		}
	}
	if allAccept {
		return []Finding{{Key: "input-accept-policy", Severity: "warn",
			Title:  "Your input chain accepts by default",
			Detail: "The input chain's policy is accept, so anything not explicitly dropped is let in. A default-drop policy with explicit allow rules is the safer posture — the presets set one up without locking you out."}}
	}
	return nil
}

// forwardingFinding fires when the box routes but the forward path isn't filtered.
func forwardingFinding(model nftconf.Model) (Finding, bool) {
	for _, t := range model.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "forward" && c.ChainType != "nat" && c.Policy == "drop" {
				return Finding{}, false // a drop-policy forward chain is filtering
			}
		}
	}
	return Finding{Key: "forwarding-open", Severity: "info",
		Title:  "This box routes traffic, but the forward path isn't filtered",
		Detail: "The kernel forwards packets between interfaces (net.ipv4.ip_forward=1), and that routed traffic never touches the input chain. Add a forward base chain with a drop policy to filter it — replies and anything you allow keep flowing."}, true
}

func serviceLabel(l Listener) string {
	if l.Process != "" {
		return l.Process
	}
	if n, ok := serviceNames[l.Port]; ok {
		return n
	}
	return "a service"
}

func simQuery(l Listener, opts Options) string {
	v := url.Values{}
	v.Set("run", "1")
	v.Set("hook", "input")
	v.Set("proto", l.Proto)
	v.Set("src", externalSrc.String())
	v.Set("dport", strconv.Itoa(l.Port))
	v.Set("ctstate", "new")
	if opts.ExternalIf != "" {
		v.Set("iif", opts.ExternalIf)
	}
	return v.Encode()
}

func verdictPast(v string) string {
	if v == "REJECT" {
		return "rejected"
	}
	return "dropped"
}

// sortFindings puts warnings first, then keeps a stable order.
func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		return f[i].Severity == "warn" && f[j].Severity != "warn"
	})
}

// Filter drops findings the operator has dismissed, returning the visible set
// and the dismissed ones separately (so the UI can offer to restore them).
func Filter(findings []Finding, dismissed map[string]bool) (visible, hidden []Finding) {
	for _, f := range findings {
		if dismissed[f.Key] {
			hidden = append(hidden, f)
		} else {
			visible = append(visible, f)
		}
	}
	return visible, hidden
}
