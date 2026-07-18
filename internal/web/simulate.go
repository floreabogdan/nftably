package web

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/simulate"
)

// This file is the /simulate surface: trace a synthetic packet through the
// candidate model and show, step by step, which rule decides it. It reads the
// model the same way apply does, so the answer matches what would happen once
// applied — but it touches nothing (no kernel, no privilege).

type simVM struct {
	nav
	Hooks      []string
	Interfaces []string
	// Echoed form values.
	Hook, Proto, Src, Dst, SPort, DPort, Iif, Oif, CtState string
	FormErr                                                string
	Ran                                                    bool
	Trace                                                  simulate.Trace
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	vm := simVM{
		nav:        s.navFor(r, "simulate"),
		Hooks:      []string{"input", "output", "forward", "prerouting", "postrouting"},
		Interfaces: hostInterfaces(),
		Hook:       "input",
		Proto:      "tcp",
	}
	render(w, s.log, "simulate.html", vm)
}

func (s *Server) handleSimulateRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	vm := simVM{
		nav:        s.navFor(r, "simulate"),
		Hooks:      []string{"input", "output", "forward", "prerouting", "postrouting"},
		Interfaces: hostInterfaces(),
		Hook:       def(r.FormValue("hook"), "input"),
		Proto:      r.FormValue("proto"),
		Src:        strings.TrimSpace(r.FormValue("src")),
		Dst:        strings.TrimSpace(r.FormValue("dst")),
		SPort:      strings.TrimSpace(r.FormValue("sport")),
		DPort:      strings.TrimSpace(r.FormValue("dport")),
		Iif:        strings.TrimSpace(r.FormValue("iif")),
		Oif:        strings.TrimSpace(r.FormValue("oif")),
		CtState:    r.FormValue("ctstate"),
	}

	pkt := simulate.Packet{
		Proto:   vm.Proto,
		Iif:     vm.Iif,
		Oif:     vm.Oif,
		CtState: vm.CtState,
	}
	var err error
	if pkt.Src, err = parseOptAddr(vm.Src); err != nil {
		vm.FormErr = "Source address is not a valid IP: " + vm.Src
	}
	if pkt.Dst, err = parseOptAddr(vm.Dst); err != nil {
		vm.FormErr = "Destination address is not a valid IP: " + vm.Dst
	}
	if pkt.SPort, err = parseOptPort(vm.SPort); err != nil {
		vm.FormErr = "Source port must be a number 1–65535."
	}
	if pkt.DPort, err = parseOptPort(vm.DPort); err != nil {
		vm.FormErr = "Destination port must be a number 1–65535."
	}

	if vm.FormErr == "" {
		m, err := s.loadModel()
		if err != nil {
			s.serverError(w, "load model", err)
			return
		}
		vm.Trace = simulate.Simulate(m, vm.Hook, pkt)
		vm.Ran = true
	}
	render(w, s.log, "simulate.html", vm)
}

// parseOptAddr parses an optional address: blank yields the zero Addr (which the
// simulator treats as unspecified), a bad value is an error.
func parseOptAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

// parseOptPort parses an optional port: blank yields 0 (unspecified).
func parseOptPort(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errBadPort
	}
	return n, nil
}

var errBadPort = &simError{"bad port"}

type simError struct{ msg string }

func (e *simError) Error() string { return e.msg }

func def(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
