package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/store"
)

// fakeNft plays the kernel: it remembers the table text each ApplyFile loads,
// so tests can watch applies and reverts land.
type fakeNft struct {
	mu        sync.Mutex
	table     string // current "kernel" table text; empty = absent
	checkErr  error
	applyErr  error
	applied   []string // every script ApplyFile ran, in order
	available bool
}

func (f *fakeNft) Available() bool { return f.available }

func (f *fakeNft) Table(ctx context.Context, family, name string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.table, f.table != "", nil
}

func (f *fakeNft) CheckFile(ctx context.Context, path string) error { return f.checkErr }

func (f *fakeNft) ApplyFile(ctx context.Context, path string) error {
	if f.applyErr != nil {
		return f.applyErr
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	script := string(content)
	f.applied = append(f.applied, script)
	// The script is ensure+delete+body: what remains as the "kernel" table is
	// everything after the delete line, which may be nothing (a revert to
	// absent).
	_, body, _ := strings.Cut(script, "delete table inet nftably\n")
	f.table = body
	return nil
}

func newApplyTestServer(t *testing.T) (*Server, *fakeNft, *http.Cookie) {
	t.Helper()
	srv, cookie := newTestServer(t)
	fake := &fakeNft{available: true}
	srv.applier = fake
	return srv, fake, cookie
}

func TestApplyConfirmKeepsConfig(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	if _, err := srv.store.CreateRule(store.Rule{Name: "ssh", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(fake.table, "nftably: ssh") {
		t.Fatalf("kernel table after apply: %q", fake.table)
	}
	if _, pending, _ := srv.store.GetPendingApply(); !pending {
		t.Fatal("no pending apply recorded")
	}

	// The changes page shows the pending panel.
	req := httptest.NewRequest(http.MethodGet, "/changes", nil)
	req.AddCookie(cookie)
	crec := httptest.NewRecorder()
	srv.ServeHTTP(crec, req)
	if !strings.Contains(crec.Body.String(), "waiting for your confirmation") {
		t.Error("pending panel missing from changes page")
	}

	// Confirm keeps it.
	if rec := postForm(srv, "/apply/confirm", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d", rec.Code)
	}
	if _, pending, _ := srv.store.GetPendingApply(); pending {
		t.Fatal("pending apply should be cleared after confirm")
	}
	versions, _ := srv.store.ListConfigVersions(5)
	if len(versions) != 1 || versions[0].Status != store.VersionConfirmed {
		t.Fatalf("versions after confirm: %+v", versions)
	}
	if !strings.Contains(fake.table, "nftably: ssh") {
		t.Fatal("confirm must not touch the kernel table")
	}
}

func TestApplyRollbackRestoresPrevious(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	fake.table = "table inet nftably {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
	prev := fake.table

	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	if fake.table == prev {
		t.Fatal("apply did not change the kernel table")
	}

	if rec := postForm(srv, "/apply/rollback", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("rollback: %d", rec.Code)
	}
	if fake.table != prev {
		t.Fatalf("rollback did not restore the previous table:\ngot:  %q\nwant: %q", fake.table, prev)
	}
	versions, _ := srv.store.ListConfigVersions(5)
	if len(versions) != 1 || versions[0].Status != store.VersionReverted {
		t.Fatalf("versions after rollback: %+v", versions)
	}
}

func TestApplyAutoRevertFires(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	// The form clamps to minApplyTimeout, so drive the timer directly: apply,
	// then invoke the auto-revert as the timer callback would.
	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	p, pending, _ := srv.store.GetPendingApply()
	if !pending {
		t.Fatal("no pending apply")
	}
	srv.stopPendingTimer()
	srv.autoRevert(p.VersionID)

	if _, stillPending, _ := srv.store.GetPendingApply(); stillPending {
		t.Fatal("auto-revert did not clear the pending apply")
	}
	if fake.table != "" {
		t.Fatalf("auto-revert should remove the table that did not exist before: %q", fake.table)
	}
	versions, _ := srv.store.ListConfigVersions(5)
	if versions[0].Status != store.VersionReverted {
		t.Fatalf("version status: %+v", versions[0])
	}

	// A stale timer firing after a later apply must not revert it.
	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("second apply: %d", rec.Code)
	}
	srv.autoRevert(p.VersionID) // old version id — must be a no-op
	if _, stillPending, _ := srv.store.GetPendingApply(); !stillPending {
		t.Fatal("stale auto-revert cancelled the wrong apply")
	}
	srv.stopPendingTimer()
}

func TestApplyRejectedByCheckRecordsNothing(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	fake.checkErr = context.DeadlineExceeded

	rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pre-apply check") {
		t.Fatalf("check failure not surfaced: %d", rec.Code)
	}
	if versions, _ := srv.store.ListConfigVersions(5); len(versions) != 0 {
		t.Fatalf("a rejected config must not be recorded: %+v", versions)
	}
	if _, pending, _ := srv.store.GetPendingApply(); pending {
		t.Fatal("no pending apply should exist")
	}
}

func TestRecoverPendingApplyRevertsOnStartup(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	// Simulate the crash: the timer dies with the process.
	srv.stopPendingTimer()

	srv.RecoverPendingApply()
	if _, pending, _ := srv.store.GetPendingApply(); pending {
		t.Fatal("startup recovery left the pending apply armed")
	}
	if fake.table != "" {
		t.Fatalf("startup recovery should restore the pre-apply state: %q", fake.table)
	}
}

func TestSecondApplyRefusedWhilePending(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	applied := len(fake.applied)
	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("second apply: %d", rec.Code)
	}
	if len(fake.applied) != applied {
		t.Fatal("a second apply ran while one was pending")
	}
	srv.stopPendingTimer()
}

// The real nft.Client satisfies the applier interface.
var _ applier = (*nft.Client)(nil)
