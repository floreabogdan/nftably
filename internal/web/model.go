package web

import (
	nftconf "github.com/floreabogdan/nftably/internal/render"
)

// loadModel reads everything the render layer needs from the store. Every
// path that renders or lints the candidate config goes through here, so the
// two can never disagree about what the model contains.
func (s *Server) loadModel() (nftconf.Model, error) {
	var m nftconf.Model
	var err error
	if m.Rules, err = s.store.ListRules(); err != nil {
		return m, err
	}
	if m.FW, err = s.store.GetFirewall(); err != nil {
		return m, err
	}
	if m.Forwards, err = s.store.ListPortForwards(); err != nil {
		return m, err
	}
	lists, err := s.store.ListLists()
	if err != nil {
		return m, err
	}
	entries, err := s.store.AllEntries()
	if err != nil {
		return m, err
	}
	for _, l := range lists {
		m.Lists = append(m.Lists, nftconf.ListWithEntries{IPList: l, Entries: entries[l.ID]})
	}
	return m, nil
}
