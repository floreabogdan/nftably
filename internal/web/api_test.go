package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// apiReq builds a request to the automation API with an optional bearer token.
func apiReq(method, path, token, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestBlockAPI(t *testing.T) {
	srv, _ := newTestServer(t)

	// Off by default: the endpoint isn't even advertised.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, apiReq(http.MethodPost, "/api/block", "", `{"ip":"1.2.3.4"}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("API off: code=%d, want 404", rec.Code)
	}

	// Enable it.
	if err := srv.store.SaveAPIToken("secret-token"); err != nil {
		t.Fatal(err)
	}

	// Wrong token → 401.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, apiReq(http.MethodPost, "/api/block", "nope", `{"ip":"1.2.3.4"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: code=%d, want 401", rec.Code)
	}

	// Block with the right token.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, apiReq(http.MethodPost, "/api/block", "secret-token", `{"ip":"203.0.113.9","note":"ids"}`))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "203.0.113.9") {
		t.Fatalf("block: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if bl, err := srv.store.GetListByName(blockListName); err != nil {
		t.Fatal("block list not created")
	} else if entries, _ := srv.store.ListEntries(bl.ID); len(entries) != 1 || entries[0].CIDR != "203.0.113.9" {
		t.Fatalf("block did not persist: %+v", entries)
	}

	// A bad address is rejected.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, apiReq(http.MethodPost, "/api/block", "secret-token", `{"ip":"not-an-ip"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ip: code=%d, want 400", rec.Code)
	}

	// List, then unblock.
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, apiReq(http.MethodGet, "/api/blocked", "secret-token", ""))
	if !strings.Contains(rec.Body.String(), "203.0.113.9") {
		t.Errorf("blocked list missing the address: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, apiReq(http.MethodPost, "/api/unblock", "secret-token", `{"ip":"203.0.113.9"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("unblock: code=%d", rec.Code)
	}
	if bl, _ := srv.store.GetListByName(blockListName); bl.ID != 0 {
		if entries, _ := srv.store.ListEntries(bl.ID); len(entries) != 0 {
			t.Errorf("unblock left %d entries", len(entries))
		}
	}
}
