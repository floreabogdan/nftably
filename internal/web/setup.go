package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"github.com/floreabogdan/nftably/internal/advisor"
	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// The guided setup: one page that turns a blank box into a configured
// firewall — management network, the services that actually run here
// (detected and pre-checked), router settings when the box routes, and the
// drop policy. Everything it saves is the same model the individual pages
// edit; it ends on /changes where the apply arms the auto-revert as always.

// setupService is one library entry as the wizard shows it: pre-checked when
// detection saw the service running (DetectedWhy says what gave it away),
// marked when a rule already exists.
type setupService struct {
	Key         string
	Name        string
	Why         string
	Ports       string
	Detected    bool
	DetectedWhy string
	Have        bool
	Restrict    bool
}

type setupVM struct {
	nav
	Err string
	// ClientIP prefills the management network — the address the operator is
	// connecting from right now (empty when they come through loopback).
	ClientIP   string
	ClientCIDR string // the /24 (or /64) around ClientIP, the usual intent
	HasMgmt    bool
	Services   []setupService
	Detected   int
	Ifaces     []string
	RouterHint bool // the kernel forwards; router settings are probably wanted
	FW         store.Firewall
	// PreviewVM is the first-paint rendered config for the form's defaults;
	// the live endpoint replaces it as the operator changes choices.
	PreviewVM setupPreviewVM
}

// softwareToLibrary maps what the advisor sees to library entries.
var softwareToLibrary = map[string]string{
	"sshd": "ssh", "nginx": "web", "apache": "web", "caddy": "web",
	"haproxy": "web", "dns": "dns", "wireguard": "wireguard",
	"samba": "samba", "bird": "bgp",
}

var portToLibrary = map[int]string{
	22: "ssh", 80: "web", 443: "web", 53: "dns", 51820: "wireguard",
	1194: "openvpn", 25: "smtp", 445: "samba", 2049: "nfs", 9100: "node-exporter",
	123: "ntp", 179: "bgp",
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	vm, ok := s.buildSetupVM(w, r)
	if !ok {
		return
	}
	render(w, s.log, "setup.html", vm)
}

func (s *Server) buildSetupVM(w http.ResponseWriter, r *http.Request) (setupVM, bool) {
	rules, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return setupVM{}, false
	}
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return setupVM{}, false
	}
	lists, err := s.store.ListLists()
	if err != nil {
		s.serverError(w, "list lists", err)
		return setupVM{}, false
	}
	entries, err := s.store.AllEntries()
	if err != nil {
		s.serverError(w, "list entries", err)
		return setupVM{}, false
	}
	hasMgmt := false
	for _, l := range lists {
		if l.Role == store.RoleAllow && len(entries[l.ID]) > 0 {
			hasMgmt = true
		}
	}

	scan := advisor.Detect()
	detected := map[string]string{} // library key -> what gave it away
	for _, sw := range scan.Software {
		if k, ok := softwareToLibrary[sw.Key]; ok && detected[k] == "" {
			detected[k] = sw.Name + " is installed"
		}
	}
	for _, l := range scan.Listeners {
		if !l.Wild {
			continue
		}
		if k, ok := portToLibrary[l.Port]; ok {
			why := fmt.Sprintf("listening on %s %d", l.Proto, l.Port)
			if l.Process != "" {
				why = fmt.Sprintf("%s is listening on %s %d", l.Process, l.Proto, l.Port)
			}
			detected[k] = why // a live listener beats "installed"
		}
	}

	have := map[string]bool{}
	for _, rule := range rules {
		have[rule.Name] = true
	}

	vm := setupVM{
		nav:        s.navFor(r, "setup"),
		HasMgmt:    hasMgmt,
		Ifaces:     interfaceNames(),
		RouterHint: scan.IPForward,
		FW:         fw,
	}
	for _, g := range library {
		for _, e := range g.Entries {
			vm.Services = append(vm.Services, setupService{
				Key: e.Key, Name: e.Name, Why: e.Why,
				Ports:       entryPorts(e),
				Detected:    detected[e.Key] != "",
				DetectedWhy: detected[e.Key],
				Have:        have[e.Rules[0].Name],
				Restrict:    e.Restrict,
			})
			if detected[e.Key] != "" {
				vm.Detected++
			}
		}
	}
	// Detected services first — the operator confirms reality, then browses
	// the rest.
	sort.SliceStable(vm.Services, func(i, j int) bool {
		return vm.Services[i].Detected && !vm.Services[j].Detected
	})

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil && !addr.IsLoopback() {
			addr = addr.Unmap()
			vm.ClientIP = addr.String()
			bits := 24
			if addr.Is6() {
				bits = 64
			}
			if p, err := addr.Prefix(bits); err == nil {
				vm.ClientCIDR = p.String()
			}
		}
	}

	// First-paint preview: what the form's current (default) choices render
	// to. The live endpoint uses the same candidate builder, so the preview
	// with JavaScript off is simply this one, still correct.
	prefill := map[string][]string{"input_policy": {"drop"}}
	if !vm.HasMgmt && vm.ClientCIDR != "" {
		prefill["mgmt_cidr"] = []string{vm.ClientCIDR}
	}
	for _, svc := range vm.Services {
		if svc.Detected || svc.Have {
			prefill["svc"] = append(prefill["svc"], svc.Key)
		}
	}
	m, warns, err := s.setupCandidate(prefill)
	if err == nil {
		vm.PreviewVM = setupPreviewVM{Config: nftconf.Config(m), Warns: warns}
	} else {
		vm.PreviewVM = setupPreviewVM{Err: err.Error()}
	}
	return vm, true
}

// setupCandidate interprets the wizard form as a candidate model WITHOUT
// persisting anything: the stored model plus the form's additions. Both the
// live preview and the final save read the form through this one function,
// so what the preview shows is exactly what saving produces.
func (s *Server) setupCandidate(form map[string][]string) (nftconf.Model, []string, error) {
	get := func(key string) string {
		if v := form[key]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}

	m, err := s.loadModel()
	if err != nil {
		return m, nil, err
	}

	if cidr := get("mgmt_cidr"); cidr != "" {
		norm, msg := store.NormalizeCIDR(cidr)
		if msg != "" {
			return m, nil, fmt.Errorf("%s", msg)
		}
		// Into the first allow-role list — synthesized for the preview when
		// the operator deleted them all (the save path recreates it).
		idx := -1
		for i, l := range m.Lists {
			if l.Role == store.RoleAllow {
				idx = i
				break
			}
		}
		if idx == -1 {
			m.Lists = append(m.Lists, nftconf.ListWithEntries{IPList: store.IPList{ID: -1, Name: "management", Role: store.RoleAllow}})
			idx = len(m.Lists) - 1
		}
		covered := false
		for _, e := range m.Lists[idx].Entries {
			if e.CIDR == norm {
				covered = true
			}
		}
		if !covered {
			m.Lists[idx].Entries = append(m.Lists[idx].Entries, store.ListEntry{CIDR: norm})
		}
	}

	names := map[string]bool{}
	for _, rule := range m.Rules {
		names[rule.Name] = true
	}
	chosen := map[string]bool{}
	for _, key := range form["svc"] {
		chosen[key] = true
	}
	for _, g := range library {
		for _, e := range g.Entries {
			if !chosen[e.Key] {
				continue
			}
			for _, rule := range e.Rules {
				if !names[rule.Name] {
					m.Rules = append(m.Rules, rule)
				}
			}
		}
	}

	if p := get("input_policy"); p == "drop" || p == "accept" {
		m.FW.InputPolicy = p
	}
	m.FW.WANIface = get("wan_iface")
	m.FW.Masquerade = get("masquerade") == "on" && m.FW.WANIface != ""

	return m, nftconf.Lint(m, s.listenAddr), nil
}

// handleSetupPreview is the live preview: the wizard form posts itself here
// (debounced) and swaps the response fragment in beside the form.
func (s *Server) handleSetupPreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	m, warns, err := s.setupCandidate(r.PostForm)
	vm := setupPreviewVM{Warns: warns}
	if err != nil {
		vm.Err = err.Error()
	} else {
		vm.Config = nftconf.Config(m)
	}
	render(w, s.log, "setup_preview.html", vm)
}

type setupPreviewVM struct {
	Config string
	Warns  []string
	Err    string
}

func (s *Server) handleSetupApply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Management network first: it is what makes everything else safe. An
	// entry that overlaps an existing one means it is already covered — fine.
	if cidr := strings.TrimSpace(r.FormValue("mgmt_cidr")); cidr != "" {
		mgmt, err := s.allowRoleList()
		if err != nil {
			s.serverError(w, "find management list", err)
			return
		}
		if err := s.store.AddListEntry(mgmt.ID, cidr, "management (guided setup)"); err != nil && !errorsIsOverlap(err) {
			s.setupError(w, r, err.Error())
			return
		}
	}

	// The chosen services, straight from the library catalogue.
	existing, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return
	}
	names := map[string]bool{}
	for _, rule := range existing {
		names[rule.Name] = true
	}
	chosen := map[string]bool{}
	for _, key := range r.Form["svc"] {
		chosen[key] = true
	}
	added := 0
	for _, g := range library {
		for _, e := range g.Entries {
			if !chosen[e.Key] {
				continue
			}
			for _, rule := range e.Rules {
				if names[rule.Name] {
					continue
				}
				if _, err := s.store.CreateRule(rule); err != nil {
					s.serverError(w, "create rule", err)
					return
				}
				added++
			}
		}
	}

	// Firewall-wide settings: policy and, when asked, the router bits.
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return
	}
	if p := r.FormValue("input_policy"); p == "drop" || p == "accept" {
		fw.InputPolicy = p
	}
	fw.WANIface = strings.TrimSpace(r.FormValue("wan_iface"))
	fw.Masquerade = r.FormValue("masquerade") == "on" && fw.WANIface != ""
	if err := s.store.SaveFirewall(fw); err != nil {
		s.setupError(w, r, strings.TrimPrefix(err.Error(), "store: "))
		return
	}

	s.audit(r, fmt.Sprintf("guided setup: %d rule(s), policy %s", added, fw.InputPolicy))
	http.Redirect(w, r, "/changes?setup=1", http.StatusSeeOther)
}

// setupError re-renders the wizard with the message on top; the form is
// cheap to refill since almost everything is pre-checked detection.
func (s *Server) setupError(w http.ResponseWriter, r *http.Request, msg string) {
	vm, ok := s.buildSetupVM(w, r)
	if !ok {
		return
	}
	vm.Err = msg
	render(w, s.log, "setup.html", vm)
}

func errorsIsOverlap(err error) bool { return errors.Is(err, store.ErrOverlap) }

func entryPorts(e libEntry) string {
	var parts []string
	for _, rule := range e.Rules {
		parts = append(parts, rule.Proto+" "+rule.DPorts)
	}
	return strings.Join(parts, ", ")
}

func interfaceNames() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, i.Name)
	}
	return out
}
