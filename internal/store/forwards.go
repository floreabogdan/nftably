package store

import (
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
)

// PortForward is one DNAT mapping on the WAN interface: traffic arriving on
// WANIface at proto/DPort is rewritten to Dest (and DestPort, when set) and
// then rides the forward chain's `ct status dnat accept`. None of these render
// while the firewall row has no WAN interface.
type PortForward struct {
	ID       int64
	Position int
	// Name is a short operator label; it becomes the rule's comment.
	Name  string
	Proto string // tcp | udp
	// DPort is the external port — one number or one a-b range.
	DPort string
	// Dest is the internal destination IP, v4 or v6.
	Dest string
	// DestPort is the internal port; empty preserves the external port (and is
	// required to be empty when DPort is a range).
	DestPort string
	Enabled  bool
}

// Validate returns human-readable problems with the forward; empty means
// valid. It also normalizes the fields (trimming, canonical port tokens).
func (p *PortForward) Validate() []string {
	var errs []string
	p.Name = strings.TrimSpace(p.Name)
	p.DPort = strings.TrimSpace(p.DPort)
	p.Dest = strings.TrimSpace(p.Dest)
	p.DestPort = strings.TrimSpace(p.DestPort)

	if len(p.Name) > 64 {
		errs = append(errs, "Name must be 64 characters or fewer.")
	}
	if strings.ContainsAny(p.Name, "\"\\\n\r") {
		errs = append(errs, `Name must not contain quotes, backslashes or line breaks.`)
	}
	if p.Proto != "tcp" && p.Proto != "udp" {
		errs = append(errs, fmt.Sprintf("Protocol %q is not one of tcp, udp.", p.Proto))
	}

	lo, hi, ok := parsePortToken(p.DPort)
	if !ok {
		errs = append(errs, fmt.Sprintf("%q is not a port (1-65535) or range (e.g. 8000-8100).", p.DPort))
	} else if lo == hi {
		p.DPort = fmt.Sprint(lo)
	} else {
		p.DPort = fmt.Sprintf("%d-%d", lo, hi)
	}

	addr, err := netip.ParseAddr(p.Dest)
	switch {
	case err != nil:
		errs = append(errs, fmt.Sprintf("%q is not an IP address.", p.Dest))
	case !addr.IsGlobalUnicast():
		errs = append(errs, fmt.Sprintf("%q is not a routable destination (loopback, multicast and link-local cannot be forwarded to).", p.Dest))
	default:
		p.Dest = addr.String()
	}

	if p.DestPort != "" {
		dlo, dhi, dok := parsePortToken(p.DestPort)
		switch {
		case !dok || dlo != dhi:
			errs = append(errs, fmt.Sprintf("%q is not a single port (1-65535).", p.DestPort))
		case ok && lo != hi:
			errs = append(errs, "A port range keeps its ports — leave the destination port empty when forwarding a range.")
		default:
			p.DestPort = fmt.Sprint(dlo)
		}
	}
	return errs
}

// ListPortForwards returns every port-forward in render order.
func (s *Store) ListPortForwards() ([]PortForward, error) {
	rows, err := s.db.Query(`
		SELECT id, position, name, proto, dport, dest, dest_port, enabled
		FROM port_forwards ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list port forwards: %w", err)
	}
	defer rows.Close()

	var out []PortForward
	for rows.Next() {
		var p PortForward
		if err := rows.Scan(&p.ID, &p.Position, &p.Name, &p.Proto, &p.DPort, &p.Dest, &p.DestPort, &p.Enabled); err != nil {
			return nil, fmt.Errorf("store: scan port forward: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPortForward returns the port-forward with id, or ErrNotFound.
func (s *Store) GetPortForward(id int64) (PortForward, error) {
	var p PortForward
	row := s.db.QueryRow(`
		SELECT id, position, name, proto, dport, dest, dest_port, enabled
		FROM port_forwards WHERE id = ?`, id)
	err := row.Scan(&p.ID, &p.Position, &p.Name, &p.Proto, &p.DPort, &p.Dest, &p.DestPort, &p.Enabled)
	if err == sql.ErrNoRows {
		return PortForward{}, ErrNotFound
	}
	if err != nil {
		return PortForward{}, fmt.Errorf("store: get port forward: %w", err)
	}
	return p, nil
}

// CreatePortForward inserts a port-forward at the end of the order.
func (s *Store) CreatePortForward(p PortForward) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO port_forwards (position, name, proto, dport, dest, dest_port, enabled, created_at, updated_at)
		VALUES ((SELECT COALESCE(MAX(position), 0) + 1 FROM port_forwards), ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Proto, p.DPort, p.Dest, p.DestPort, p.Enabled, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: create port forward: %w", err)
	}
	return res.LastInsertId()
}

// UpdatePortForward saves an edited port-forward (not its position).
func (s *Store) UpdatePortForward(p PortForward) error {
	res, err := s.db.Exec(`
		UPDATE port_forwards SET name = ?, proto = ?, dport = ?, dest = ?, dest_port = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.Proto, p.DPort, p.Dest, p.DestPort, p.Enabled, now(), p.ID)
	if err != nil {
		return fmt.Errorf("store: update port forward: %w", err)
	}
	return notFoundIfZero(res)
}

// DeletePortForward removes a port-forward.
func (s *Store) DeletePortForward(id int64) error {
	res, err := s.db.Exec(`DELETE FROM port_forwards WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete port forward: %w", err)
	}
	return notFoundIfZero(res)
}

// SetPortForwardEnabled flips a port-forward on or off.
func (s *Store) SetPortForwardEnabled(id int64, enabled bool) error {
	res, err := s.db.Exec(`UPDATE port_forwards SET enabled = ?, updated_at = ? WHERE id = ?`, enabled, now(), id)
	if err != nil {
		return fmt.Errorf("store: toggle port forward: %w", err)
	}
	return notFoundIfZero(res)
}

// MovePortForward shifts a port-forward one step in the order; see MoveRule.
func (s *Store) MovePortForward(id int64, dir int) error {
	return s.moveInOrder("port_forwards", id, dir)
}
