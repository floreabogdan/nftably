package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func tempStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestSendTestDeliversWebhook stands up a real HTTP receiver and confirms
// SendTest POSTs a well-formed JSON body to a webhook destination.
func TestSendTestDeliversWebhook(t *testing.T) {
	var (
		mu   sync.Mutex
		body []byte
		ct   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ = io.ReadAll(r.Body)
		ct = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDispatcher(tempStore(t), nil, 0)
	dest := store.Destination{Name: "hook", Type: store.AlertWebhook, Enabled: true, URL: srv.URL}
	if err := d.SendTest(dest); err != nil {
		t.Fatalf("SendTest: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if txt, _ := payload["text"].(string); !strings.Contains(txt, "test alert") {
		t.Errorf("payload text = %q, want a test-alert line", txt)
	}
}

// TestSendTestReportsFailure confirms a non-2xx endpoint surfaces as an error,
// which is what the UI's "Test" button relies on.
func TestSendTestReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := NewDispatcher(tempStore(t), nil, 0)
	dest := store.Destination{Name: "hook", Type: store.AlertWebhook, Enabled: true, URL: srv.URL}
	if err := d.SendTest(dest); err == nil {
		t.Error("expected an error from a 500 endpoint")
	}
}
