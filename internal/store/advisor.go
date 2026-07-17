package store

import "fmt"

// DismissSuggestion hides an advisor suggestion by its stable key. Re-running
// the scan keeps it hidden until RestoreSuggestion.
func (s *Store) DismissSuggestion(key string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO advisor_dismissed (key, dismissed_at) VALUES (?, ?)`, key, now())
	if err != nil {
		return fmt.Errorf("store: dismiss suggestion: %w", err)
	}
	return nil
}

// RestoreSuggestion un-hides a dismissed suggestion.
func (s *Store) RestoreSuggestion(key string) error {
	if _, err := s.db.Exec(`DELETE FROM advisor_dismissed WHERE key = ?`, key); err != nil {
		return fmt.Errorf("store: restore suggestion: %w", err)
	}
	return nil
}

// DismissedSuggestions returns the set of hidden suggestion keys.
func (s *Store) DismissedSuggestions() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT key FROM advisor_dismissed`)
	if err != nil {
		return nil, fmt.Errorf("store: list dismissed: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("store: scan dismissed: %w", err)
		}
		out[k] = true
	}
	return out, rows.Err()
}
