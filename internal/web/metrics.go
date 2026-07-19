package web

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/floreabogdan/nftably/internal/buildinfo"
	"github.com/floreabogdan/nftably/internal/nft"
)

// metrics.go serves a Prometheus exposition endpoint at /metrics, so nftably's
// firewall can be graphed and alerted on in Grafana/Prometheus like any other
// service. The headline series are the per-rule packet/byte counters — a rule
// that carries a Count action becomes a time series, so you can watch drops and
// accepts move. It reads the live ruleset once per scrape (one nft call) and
// touches nothing.
//
// The endpoint is opt-in and session-exempt: it is disabled (404) until an
// operator sets a bearer token under Settings, after which a scrape must present
// "Authorization: Bearer <token>". A scraper has no login session, so the token
// is what gates it — on top of the access-list that already fronts every route.

// handleMetrics renders the Prometheus text exposition format. It is registered
// without requireAuth; access is gated by the configured bearer token instead.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	token := s.metricsToken()
	if token == "" {
		http.NotFound(w, r) // feature off — don't even admit the endpoint exists
		return
	}
	if !metricsAuthorized(r, token) {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := reqCtx(r)
	defer cancel()

	var b strings.Builder
	writeMetricsHeader(&b, "nftably_build_info", "gauge", "Build version and commit as labels; value is always 1.")
	fmt.Fprintf(&b, "nftably_build_info{version=\"%s\",commit=\"%s\"} 1\n", metricLabel(buildinfo.Version), metricLabel(buildinfo.Commit))

	up := 0
	var rs *nft.Ruleset
	if s.nft.Available() {
		if got, err := s.nft.Ruleset(ctx); err == nil {
			rs, up = got, 1
		}
	}
	writeMetricsHeader(&b, "nftably_up", "gauge", "1 if nft is installed and the live ruleset is readable, else 0.")
	fmt.Fprintf(&b, "nftably_up %d\n", up)

	// Whether an armed apply is waiting for confirmation (auto-revert pending).
	pending := 0
	if _, ok, err := s.store.GetPendingApply(); err == nil && ok {
		pending = 1
	}
	writeMetricsHeader(&b, "nftably_apply_pending", "gauge", "1 while an applied ruleset is awaiting confirmation before auto-revert, else 0.")
	fmt.Fprintf(&b, "nftably_apply_pending %d\n", pending)

	if rs != nil {
		writeMetricsHeader(&b, "nftably_tables", "gauge", "Number of tables in the live ruleset.")
		fmt.Fprintf(&b, "nftably_tables %d\n", len(rs.Tables))
		writeMetricsHeader(&b, "nftably_chains", "gauge", "Number of chains in the live ruleset.")
		fmt.Fprintf(&b, "nftably_chains %d\n", rs.TotalChains())
		writeMetricsHeader(&b, "nftably_rules", "gauge", "Number of rules in the live ruleset.")
		fmt.Fprintf(&b, "nftably_rules %d\n", rs.TotalRules())
		writeRuleCounters(&b, rs)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// writeRuleCounters emits the per-rule packet/byte counters for every rule that
// carries a `counter` statement, labelled by its position in the firewall.
func writeRuleCounters(b *strings.Builder, rs *nft.Ruleset) {
	type series struct {
		family, table, chain, comment string
		index                         int
		packets, bytes                uint64
	}
	var rows []series
	for _, t := range rs.Tables {
		for _, c := range t.Chains {
			for i, rule := range c.Rules {
				ctr := nft.CounterOf(rule)
				if !ctr.Present {
					continue
				}
				rows = append(rows, series{
					family: string(t.Family), table: t.Name, chain: c.Name,
					comment: rule.Comment, index: i, packets: ctr.Packets, bytes: ctr.Bytes,
				})
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	// Stable output order keeps diffs quiet and scrapes deterministic.
	sort.Slice(rows, func(i, j int) bool {
		a, c := rows[i], rows[j]
		if a.family != c.family {
			return a.family < c.family
		}
		if a.table != c.table {
			return a.table < c.table
		}
		if a.chain != c.chain {
			return a.chain < c.chain
		}
		return a.index < c.index
	})

	writeMetricsHeader(b, "nftably_rule_packets_total", "counter", "Packets matched by a rule carrying a Count action, by table/chain/rule.")
	for _, s := range rows {
		fmt.Fprintf(b, "nftably_rule_packets_total%s %d\n", ruleLabels(s.family, s.table, s.chain, s.comment, s.index), s.packets)
	}
	writeMetricsHeader(b, "nftably_rule_bytes_total", "counter", "Bytes matched by a rule carrying a Count action, by table/chain/rule.")
	for _, s := range rows {
		fmt.Fprintf(b, "nftably_rule_bytes_total%s %d\n", ruleLabels(s.family, s.table, s.chain, s.comment, s.index), s.bytes)
	}
}

// ruleLabels builds the label set for a per-rule counter. A rule's comment is
// its name where it has one; index disambiguates unnamed rules so two counters
// in the same chain never collide on an identical label set.
func ruleLabels(family, table, chain, comment string, index int) string {
	return fmt.Sprintf("{family=\"%s\",table=\"%s\",chain=\"%s\",rule=\"%s\",index=\"%d\"}",
		metricLabel(family), metricLabel(table), metricLabel(chain), metricLabel(comment), index)
}

func writeMetricsHeader(b *strings.Builder, name, typ, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// metricLabel escapes a Prometheus label value: backslash, double-quote and
// newline, per the exposition format.
func metricLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// metricsToken reads the configured bearer token (empty ⇒ endpoint disabled).
func (s *Server) metricsToken() string {
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		return st.MetricsToken
	}
	return ""
}

// metricsAuthorized checks the request's bearer token against want in constant
// time.
func metricsAuthorized(r *http.Request, want string) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
