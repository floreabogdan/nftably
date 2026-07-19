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
