package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// postBackup uploads data as the "backup" file to the restore endpoint.
func postBackup(srv *Server, cookie *http.Cookie, data []byte) *httptest.ResponseRecorder {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("backup", "nftably-config.json")
	_, _ = fw.Write(data)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/settings/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestBackupRoundTrip applies a preset, exports it, restores the export into a
// fresh server, and asserts the rendered config and named sets come back
// identical — the guarantee a backup has to make.
func TestBackupRoundTrip(t *testing.T) {
	src, cookie := newTestServer(t)
	if rec := postForm(src, "/presets/apply", url.Values{"preset": {"bgp-router"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}
	m1, err := src.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	want := nftconf.Config(m1)

	doc, err := src.buildBackup()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Restore into a fresh server via the HTTP endpoint.
	dst, dstCookie := newTestServer(t)
	rec := postBackup(dst, dstCookie, data)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/changes" {
		t.Fatalf("restore: status %d loc %q, want 303 /changes", rec.Code, rec.Header().Get("Location"))
	}
	m2, err := dst.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	if got := nftconf.Config(m2); got != want {
		t.Errorf("round-trip config differs:\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
	// The named sets and their seeded entries came across.
	mgmt, err := dst.store.GetListByName("mgmt")
	if err != nil {
		t.Fatalf("mgmt set missing after restore: %v", err)
	}
	if entries, _ := dst.store.ListEntries(mgmt.ID); len(entries) == 0 {
		t.Error("mgmt entries were not restored")
	}
}

// TestConfigRestoreRejectsBadRuleWithoutWiping checks that a structurally valid
// backup (good JSON, valid table + chain) whose rule cannot render is refused
// during the up-front validation pass, leaving the existing model intact — the
// restore must never wipe the current config and then fail partway through the
// rebuild.
func TestConfigRestoreRejectsBadRuleWithoutWiping(t *testing.T) {
	srv, cookie := newTestServer(t)
	if rec := postForm(srv, "/presets/apply", url.Values{"preset": {"secure-server"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}
	before, _ := srv.store.ListTables()
	if len(before) == 0 {
		t.Fatal("preset produced no tables to protect")
	}

	doc := backupDoc{
		Version: backupVersion,
		Tables: []backupTable{{
			Family: "inet", Name: "filter",
			Chains: []backupChain{{
				Name: "block", Kind: "regular",
				Rules: []backupRule{{
					Enabled: true,
					// A match key nft never defines — valid shape, cannot render.
					Matches: []backupMatch{{Key: "not_a_real_match_key", Op: "==", Value: "x"}},
				}},
			}},
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	rec := postBackup(srv, cookie, data)
	if rec.Header().Get("Location") == "/changes" {
		t.Error("a backup with an unrenderable rule was accepted")
	}
	// Crucially, the pre-existing model must be exactly as it was.
	if after, _ := srv.store.ListTables(); len(after) != len(before) {
		t.Errorf("a rejected restore mutated the model: %d tables → %d", len(before), len(after))
	}
}

// TestBackupRoundTripRawTagsFlowtables guards the newer object types the export
// format has to carry: a raw (verbatim) rule, a rule's freeform tags, and a
// flowtable. A preset can seed none of these (flowtables need a real device), so
// this builds them straight on the store, exports, and restores into a fresh
// server — the exact path a config-version restore takes. Dropping any of them
// is silent config loss; dropping a raw rule aborted restore entirely.
func TestBackupRoundTripRawTagsFlowtables(t *testing.T) {
	src, _ := newTestServer(t)
	// A distinct table name — the test server already seeds an inet/filter table.
	tid, err := src.store.CreateTable(store.Table{Family: "inet", Name: "fastpath"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.store.CreateFlowtable(store.Flowtable{TableID: tid, Name: "ft", Priority: "filter", Devices: "eth0, eth1", HWOffload: true}); err != nil {
		t.Fatal(err)
	}
	fwd, err := src.store.CreateChain(store.Chain{TableID: tid, Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "accept"})
	if err != nil {
		t.Fatal(err)
	}
	// A raw rule (verbatim nft the catalogue can't express).
	if _, err := src.store.CreateChainRule(store.ChainRule{ChainID: fwd, Enabled: true, Comment: "connlimit", Raw: "ip saddr 10.0.0.0/8 ct count over 20 drop"}); err != nil {
		t.Fatal(err)
	}
	// A structured rule carrying tags.
	if _, err := src.store.CreateChainRule(store.ChainRule{ChainID: fwd, Enabled: true, Comment: "offload", Tags: "router,fastpath",
		Matches:    []store.RuleMatch{{Key: "ct.state", Op: "==", Value: "established, related"}},
		Statements: []store.RuleStatement{{Key: "flow", Params: `{"ft":"ft"}`}}}); err != nil {
		t.Fatal(err)
	}
	want := nftconf.Config(mustModel(t, src))

	doc, err := src.buildBackup()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	dst, dstCookie := newTestServer(t)
	if rec := postBackup(dst, dstCookie, data); rec.Header().Get("Location") != "/changes" {
		t.Fatalf("restore: status %d loc %q, want /changes", rec.Code, rec.Header().Get("Location"))
	}
	if got := nftconf.Config(mustModel(t, dst)); got != want {
		t.Errorf("raw/tags/flowtable round-trip differs:\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
	// Tags are not visible in rendered nft, so assert them on the store directly.
	dstTables, _ := dst.store.ListTables()
	var dstTbl store.Table
	for _, tb := range dstTables {
		if tb.Family == "inet" && tb.Name == "fastpath" {
			dstTbl = tb
		}
	}
	if dstTbl.ID == 0 {
		t.Fatal("fastpath table missing after restore")
	}
	fts, _ := dst.store.AllFlowtables()
	if len(fts[dstTbl.ID]) != 1 {
		t.Errorf("flowtable was not restored: %+v", fts)
	}
	chains, _ := dst.store.ListChains(dstTbl.ID)
	var sawRaw, sawTags bool
	for _, c := range chains {
		rules, _ := dst.store.ListChainRules(c.ID)
		for _, r := range rules {
			if r.IsRaw() {
				sawRaw = true
			}
			if r.Tags == "router,fastpath" {
				sawTags = true
			}
		}
	}
	if !sawRaw {
		t.Error("raw rule was lost across restore")
	}
	if !sawTags {
		t.Error("rule tags were lost across restore")
	}
}

// mustModel loads a server's model or fails the test.
func mustModel(t *testing.T, s *Server) nftconf.Model {
	t.Helper()
	m, err := s.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestConfigExportDownload checks the export streams a JSON attachment.
func TestConfigExportDownload(t *testing.T) {
	srv, cookie := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/settings/backup/export", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: status %d, want 200", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "nftably-config.json") {
		t.Errorf("missing attachment filename, got %q", cd)
	}
	var doc backupDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("export body is not valid JSON: %v", err)
	}
	if doc.Version != backupVersion {
		t.Errorf("export version = %d, want %d", doc.Version, backupVersion)
	}
}

// TestConfigRestoreRejectsGarbage checks a non-backup upload is refused without
// wiping the current model.
func TestConfigRestoreRejectsGarbage(t *testing.T) {
	srv, cookie := newTestServer(t)
	if rec := postForm(srv, "/presets/apply", url.Values{"preset": {"secure-server"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}
	before, _ := srv.store.ListTables()

	rec := postBackup(srv, cookie, []byte("this is not json"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") == "/changes" {
		t.Errorf("garbage restore should redirect back with an error, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The model must be untouched (validation happens before any mutation).
	if after, _ := srv.store.ListTables(); len(after) != len(before) {
		t.Errorf("a rejected restore changed the model: %d tables → %d", len(before), len(after))
	}
}
