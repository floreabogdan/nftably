package store

import (
	"testing"
	"time"
)

// TestSessionTokenHashedAtRest verifies the raw token still resolves a session
// (round-trip through hashing) while the raw token itself is never stored.
func TestSessionTokenHashedAtRest(t *testing.T) {
	s := testStore(t)
	uid, err := s.CreateUser("admin", "x")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	const raw = "raw-session-token-abc123"
	if err := s.CreateSession(raw, uid, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// The raw token resolves.
	sess, ok, err := s.GetSession(raw)
	if err != nil || !ok {
		t.Fatalf("GetSession(raw): ok=%v err=%v", ok, err)
	}
	if sess.UserID != uid {
		t.Errorf("session user = %d, want %d", sess.UserID, uid)
	}

	// The raw token is not what's stored: a lookup by its hash-of-hash fails.
	if _, ok, _ := s.GetSession(hashToken(raw)); ok {
		t.Error("a hashed token value should not itself resolve a session")
	}

	// The stored column holds the hash, never the raw token.
	var stored string
	if err := s.db.QueryRow(`SELECT token FROM sessions WHERE user_id = ?`, uid).Scan(&stored); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if stored == raw {
		t.Error("raw token stored in the clear")
	}
	if stored != hashToken(raw) {
		t.Error("stored token is not the token hash")
	}
}

// TestDeleteUserSessionsExcept evicts every other session on a password change
// while keeping the current one.
func TestDeleteUserSessionsExcept(t *testing.T) {
	s := testStore(t)
	uid, err := s.CreateUser("admin", "x")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	for _, tok := range []string{"keep", "old1", "old2"} {
		if err := s.CreateSession(tok, uid, exp); err != nil {
			t.Fatalf("create session %s: %v", tok, err)
		}
	}

	if err := s.DeleteUserSessionsExcept(uid, "keep"); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if _, ok, _ := s.GetSession("keep"); !ok {
		t.Error("current session was evicted")
	}
	for _, tok := range []string{"old1", "old2"} {
		if _, ok, _ := s.GetSession(tok); ok {
			t.Errorf("session %q survived the eviction", tok)
		}
	}
}
