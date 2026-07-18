package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// Session is a logged-in browser session, keyed by an opaque cookie token and
// expiring at a fixed time.
type Session struct {
	UserID    int64
	ExpiresAt time.Time
}

// hashToken derives the at-rest key for a session token. Only the hash is
// stored, so a database read (a stolen backup, a read-only leak) does not hand
// over usable bearer tokens the way a plaintext token column would. SHA-256 is
// right here: the token is 32 bytes of CSPRNG output, so it is not brute-forceable
// and needs no slow/salted password hash.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateSession stores a new login session token (by its hash).
func (s *Store) CreateSession(token string, userID int64, expiresAt time.Time) error {
	ts := now()
	_, err := s.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashToken(token), userID, ts, expiresAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession returns (Session{}, false, nil) if the token doesn't exist or has
// expired.
func (s *Store) GetSession(token string) (Session, bool, error) {
	var sess Session
	var expiresAt string
	row := s.db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token = ?`, hashToken(token))
	err := row.Scan(&sess.UserID, &expiresAt)
	if err == sql.ErrNoRows {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("store: get session: %w", err)
	}
	sess.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return Session{}, false, fmt.Errorf("store: parse session expiry: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		return Session{}, false, nil
	}
	return sess, true, nil
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, hashToken(token))
	if err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// DeleteUserSessionsExcept removes every session for a user except the one whose
// token is keep — used on a password change so a leaked/old session cannot
// outlive the credential it was created under, while the operator making the
// change stays logged in.
func (s *Store) DeleteUserSessionsExcept(userID int64, keep string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND token != ?`, userID, hashToken(keep))
	if err != nil {
		return fmt.Errorf("store: delete user sessions: %w", err)
	}
	return nil
}

// PruneExpiredSessions deletes all sessions past their expiry.
func (s *Store) PruneExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now())
	if err != nil {
		return fmt.Errorf("store: prune sessions: %w", err)
	}
	return nil
}
