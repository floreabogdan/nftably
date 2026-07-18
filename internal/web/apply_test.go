package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/store"
)

// fakeNft plays the kernel: it remembers each owned table's text, applying the
// same ensure/delete/body transactions nftably writes, so tests can watch
// applies and reverts land across the multi-table model.
type fakeNft struct {
	mu        sync.Mutex
	tables    map[string]string // "family name" -> full block text; absent = not present
	checkErr  error
	applyErr  error
	applied   []string // every script ApplyFile ran, in order
	available bool
}

func newFakeNft() *fakeNft { return &fakeNft{tables: map[string]string{}, available: true} }

func (f *fakeNft) Available() bool { return f.available }

func (f *fakeNft) Table(ctx context.Context, family, name string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tables[family+" "+name]
	return t, ok, nil
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
	f.applied = append(f.applied, string(content))
	applyScript(f.tables, string(content))
	return nil
}

func (f *fakeNft) text(family, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tables[family+" "+name]
}

var (
	reDelete = regexp.MustCompile(`^delete table (\S+) (\S+)$`)
	reEmpty  = regexp.MustCompile(`^table (\S+) (\S+) \{\}$`)
	reOpen   = regexp.MustCompile(`^table (\S+) (\S+) \{$`)
)

// applyScript replays an nft -f script against the fake kernel map: a delete
// removes a table; a non-empty `table F N { … }` block (closed by a column-0
// `}`) sets it; the empty `table F N {}` ensure line is a no-op here (it is
// always followed by a delete).
func applyScript(tables map[string]string, script string) {
	lines := strings.Split(script, "\n")
	for i := 0; i < len(lines); {
		line := lines[i]
		if m := reDelete.FindStringSubmatch(line); m != nil {
			delete(tables, m[1]+" "+m[2])
			i++
			continue
		}
		if reEmpty.MatchString(line) {
			i++
			continue
		}
		if m := reOpen.FindStringSubmatch(line); m != nil {
			j := i + 1
			for j < len(lines) && lines[j] != "}" {
				j++
			}
			tables[m[1]+" "+m[2]] = strings.Join(lines[i:j+1], "\n") + "\n"
			i = j + 1
			continue
		}
		i++
	}
}

func newApplyTestServer(t *testing.T) (*Server, *fakeNft, *http.Cookie) {
	t.Helper()
	srv, cookie := newTestServer(t)
	fake := newFakeNft()
	srv.applier = fake
	return srv, fake, cookie
}

// seededInputChain returns the id of the migration-seeded inet/filter input
// chain, where the apply tests hang a rule.
func seededInputChain(t *testing.T, srv *Server) int64 {
	t.Helper()
	tables, err := srv.store.ListTables()
	if err != nil || len(tables) == 0 {
		t.Fatalf("no seeded tables: %v", err)
	}
	for _, tbl := range tables {
		chains, _ := srv.store.ListChains(tbl.ID)
		for _, c := range chains {
			if c.Name == "input" {
				return c.ID
			}
		}
	}
	t.Fatal("no seeded input chain")
	return 0
}

func TestApplyConfirmKeepsConfig(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	input := seededInputChain(t, srv)
	if _, err := srv.store.CreateChainRule(store.ChainRule{
		ChainID: input, Enabled: true, Comment: "ssh",
		Matches:    []store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}},
		Statements: []store.RuleStatement{{Key: "accept", Params: "{}"}},
	}); err != nil {
		t.Fatal(err)
	}

	rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(fake.text("inet", "filter"), "nftably: ssh") {
		t.Fatalf("kernel table after apply: %q", fake.text("inet", "filter"))
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
	if !strings.Contains(fake.text("inet", "filter"), "nftably: ssh") {
		t.Fatal("confirm must not touch the kernel table")
	}
	// The applied-tables ledger now knows about inet/filter.
	if refs, _ := srv.store.GetAppliedTables(); len(refs) != 1 || refs[0].Name != "filter" {
		t.Fatalf("applied ledger after confirm: %+v", refs)
	}
}

// A model edit made during the pending window must not drift the applied-tables
// ledger: confirm records the set that was actually applied, not the live model.
func TestConfirmLedgerIgnoresPendingModelEdit(t *testing.T) {
	srv, _, cookie := newApplyTestServer(t)
	_ = seededInputChain(t, srv) // ensures the inet/filter table exists

	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	// Edit the model while the apply is pending: delete every owned table.
	tables, _ := srv.store.ListTables()
	for _, tbl := range tables {
		if err := srv.store.DeleteTable(tbl.ID); err != nil {
			t.Fatal(err)
		}
	}
	if rec := postForm(srv, "/apply/confirm", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d", rec.Code)
	}
	// The ledger must record what was applied (inet/filter), so a later apply can
	// still diff it for removal — not the now-empty edited model.
	if refs, _ := srv.store.GetAppliedTables(); len(refs) != 1 || refs[0].Name != "filter" {
		t.Fatalf("ledger should reflect the applied set (inet/filter), got %+v", refs)
	}
}

func TestApplyRollbackRestoresPrevious(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	prev := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	fake.tables["inet filter"] = prev

	if rec := postForm(srv, "/apply", url.Values{"timeout": {"60"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d", rec.Code)
	}
	if fake.text("inet", "filter") == prev {
		t.Fatal("apply did not change the kernel table")
	}

	if rec := postForm(srv, "/apply/rollback", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("rollback: %d", rec.Code)
	}
	if got := fake.text("inet", "filter"); got != prev {
		t.Fatalf("rollback did not restore the previous table:\ngot:  %q\nwant: %q", got, prev)
	}
	versions, _ := srv.store.ListConfigVersions(5)
	if len(versions) != 1 || versions[0].Status != store.VersionReverted {
		t.Fatalf("versions after rollback: %+v", versions)
	}
}

func TestApplyAutoRevertFires(t *testing.T) {
	srv, fake, cookie := newApplyTestServer(t)
	// inet/filter does not exist before this apply, so the revert must remove it.
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
	if got := fake.text("inet", "filter"); got != "" {
		t.Fatalf("auto-revert should remove the table that did not exist before: %q", got)
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
	srv, _, cookie := newApplyTestServer(t)
	srv.applier.(*fakeNft).checkErr = context.DeadlineExceeded

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
	if got := fake.text("inet", "filter"); got != "" {
		t.Fatalf("startup recovery should restore the pre-apply state: %q", got)
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
