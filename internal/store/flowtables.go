package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// flowtables.go models nftables flowtables — the fast-path offload objects. A
// flowtable binds a set of interfaces at the ingress hook; a `flow add @ft`
// statement in a forward chain then hands established connections to the flow
// fast path, bypassing the rest of the ruleset for a big throughput win on a
// router. Owned per table, like chains.

// Flowtable is one flowtable nftably owns in a table.
type Flowtable struct {
	ID        int64
	TableID   int64
	Name      string
	Priority  string // keyword (filter…) or signed int; default "filter"
	Devices   string // comma-separated interface names bound at ingress
	HWOffload bool   // true adds `flags offload` (hardware offload)
	Position  int
}

// DeviceList splits Devices into individual interface names.
func (f Flowtable) DeviceList() []string {
	var out []string
	for _, d := range strings.Split(f.Devices, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// Validate returns human-readable problems; empty means valid.
func (f *Flowtable) Validate() []string {
	var errs []string
	f.Name = strings.TrimSpace(f.Name)
	f.Priority = strings.TrimSpace(f.Priority)
	if f.Priority == "" {
		f.Priority = "filter"
	}
	if !identRe.MatchString(f.Name) {
		errs = append(errs, "Name must start with a letter and contain only letters, digits and underscores (max 64).")
	}
	if !validPriority(f.Priority) {
		errs = append(errs, "Priority must be a keyword (filter, …) or a whole number.")
	}
	devs := f.DeviceList()
	if len(devs) == 0 {
		errs = append(errs, "A flowtable needs at least one interface (e.g. eth0).")
	}
	for _, d := range devs {
		if !ifaceNameRe.MatchString(d) {
			errs = append(errs, fmt.Sprintf("Interface %q has invalid characters.", d))
		}
	}
	// Re-normalize the device list to the cleaned, comma-joined form.
	f.Devices = strings.Join(devs, ", ")
	return errs
}

// AllFlowtables returns every flowtable grouped by table id — the render load.
func (s *Store) AllFlowtables() (map[int64][]Flowtable, error) {
	rows, err := s.db.Query(`SELECT id, table_id, name, priority, devices, hw_offload, position
		FROM nft_flowtables ORDER BY table_id, position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: all flowtables: %w", err)
	}
	defer rows.Close()
	out := map[int64][]Flowtable{}
	for rows.Next() {
		var f Flowtable
		if err := rows.Scan(&f.ID, &f.TableID, &f.Name, &f.Priority, &f.Devices, &f.HWOffload, &f.Position); err != nil {
			return nil, fmt.Errorf("store: scan flowtable: %w", err)
		}
		out[f.TableID] = append(out[f.TableID], f)
	}
	return out, rows.Err()
}

// GetFlowtable returns one flowtable.
func (s *Store) GetFlowtable(id int64) (Flowtable, error) {
	var f Flowtable
	row := s.db.QueryRow(`SELECT id, table_id, name, priority, devices, hw_offload, position
		FROM nft_flowtables WHERE id = ?`, id)
	err := row.Scan(&f.ID, &f.TableID, &f.Name, &f.Priority, &f.Devices, &f.HWOffload, &f.Position)
	if err == sql.ErrNoRows {
		return Flowtable{}, ErrNotFound
	}
	if err != nil {
		return Flowtable{}, fmt.Errorf("store: get flowtable: %w", err)
	}
	return f, nil
}

// CreateFlowtable adds a flowtable at the end of its table's order.
func (s *Store) CreateFlowtable(f Flowtable) (int64, error) {
	if errs := f.Validate(); len(errs) > 0 {
		return 0, fmt.Errorf("%s", errs[0])
	}
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO nft_flowtables (table_id, name, priority, devices, hw_offload, position, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM nft_flowtables WHERE table_id = ?), ?, ?)`,
		f.TableID, f.Name, f.Priority, f.Devices, f.HWOffload, f.TableID, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: create flowtable: %w", err)
	}
	return res.LastInsertId()
}

// DeleteFlowtable removes a flowtable.
func (s *Store) DeleteFlowtable(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nft_flowtables WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete flowtable: %w", err)
	}
	return notFoundIfZero(res)
}
