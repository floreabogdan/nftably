package web

import (
	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
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
	if m.Mgmt, err = s.store.ListEntries(store.ListMgmt); err != nil {
		return m, err
	}
	if m.Block, err = s.store.ListEntries(store.ListBlock); err != nil {
		return m, err
	}
	return m, nil
}
