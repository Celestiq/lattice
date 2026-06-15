// Package fedstore implements SQLite persistence for federation peer state.
//
// Schema:
//   - federation_peers          — peer identity, address, state
//   - federation_outbound_policy — ordered subject forwarding rules per peer
//   - federation_inbound_policy  — ordered subject acceptance rules per peer
//   - remote_entities            — entity-pubkey → peer-pubkey routing index
//
// The DB is opened with WAL mode and a single connection (MaxOpenConns=1) so
// that the caller does not need to worry about concurrent write serialization.
// The federation manager (Session 3) serializes all writes through one goroutine.
package fedstore

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS federation_peers (
    pubkey_hex          TEXT    NOT NULL PRIMARY KEY,
    name                TEXT    NOT NULL DEFAULT '',
    addr                TEXT    NOT NULL DEFAULT '',
    introduction_method TEXT    NOT NULL DEFAULT 'manual',
    state               TEXT    NOT NULL DEFAULT 'pending',
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS federation_outbound_policy (
    peer_pubkey_hex TEXT    NOT NULL REFERENCES federation_peers(pubkey_hex),
    position        INTEGER NOT NULL,
    subject_pattern TEXT    NOT NULL,
    effect          TEXT    NOT NULL,
    PRIMARY KEY (peer_pubkey_hex, position)
);

CREATE TABLE IF NOT EXISTS federation_inbound_policy (
    peer_pubkey_hex TEXT    NOT NULL REFERENCES federation_peers(pubkey_hex),
    position        INTEGER NOT NULL,
    subject_pattern TEXT    NOT NULL,
    effect          TEXT    NOT NULL,
    PRIMARY KEY (peer_pubkey_hex, position)
);

CREATE TABLE IF NOT EXISTS remote_entities (
    peer_pubkey_hex   TEXT NOT NULL REFERENCES federation_peers(pubkey_hex),
    entity_pubkey_hex TEXT NOT NULL,
    PRIMARY KEY (peer_pubkey_hex, entity_pubkey_hex)
);
`

// PolicyRule is a single forwarding policy entry. Rules are evaluated in
// insertion order (first match wins); default is deny.
type PolicyRule struct {
	SubjectPattern string
	Effect         string // outbound: "forward"|"deny"; inbound: "accept"|"deny"
}

// PeerRecord is a row from federation_peers.
type PeerRecord struct {
	PubkeyHex   string
	Name        string
	Addr        string
	IntroMethod string
	State       string
	CreatedAt   int64 // Unix milliseconds
	UpdatedAt   int64 // Unix milliseconds
}

// Store is the SQLite-backed federation state store.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and applies the schema.
// Use ":memory:" for ephemeral in-process databases (tests).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("fedstore: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // single connection; WAL handles concurrent reads

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("fedstore: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

// UpsertPeer inserts or updates a peer record. On conflict (same pubkey_hex),
// name, addr, and state are updated; created_at and introduction_method are
// preserved from the original row.
func (s *Store) UpsertPeer(pubkeyHex, name, addr, introMethod, state string) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(`
		INSERT INTO federation_peers
		    (pubkey_hex, name, addr, introduction_method, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(pubkey_hex) DO UPDATE SET
		    name       = excluded.name,
		    addr       = excluded.addr,
		    state      = excluded.state,
		    updated_at = excluded.updated_at`,
		pubkeyHex, name, addr, introMethod, state, now, now)
	if err != nil {
		return fmt.Errorf("fedstore: upsert peer %s: %w", pubkeyHex, err)
	}
	return nil
}

// UpdatePeerState updates only the state and updated_at of an existing peer.
func (s *Store) UpdatePeerState(pubkeyHex, state string) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(
		`UPDATE federation_peers SET state = ?, updated_at = ? WHERE pubkey_hex = ?`,
		state, now, pubkeyHex)
	if err != nil {
		return fmt.Errorf("fedstore: update state for %s: %w", pubkeyHex, err)
	}
	return nil
}

// GetPeer returns the peer record for pubkeyHex, or nil if not found.
func (s *Store) GetPeer(pubkeyHex string) (*PeerRecord, error) {
	row := s.db.QueryRow(
		`SELECT pubkey_hex, name, addr, introduction_method, state, created_at, updated_at
		 FROM federation_peers WHERE pubkey_hex = ?`,
		pubkeyHex)
	var p PeerRecord
	err := row.Scan(&p.PubkeyHex, &p.Name, &p.Addr, &p.IntroMethod, &p.State, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fedstore: get peer %s: %w", pubkeyHex, err)
	}
	return &p, nil
}

// AllActivePeers returns all peers with state = "active".
func (s *Store) AllActivePeers() ([]*PeerRecord, error) {
	return s.queryPeers(`
		SELECT pubkey_hex, name, addr, introduction_method, state, created_at, updated_at
		FROM federation_peers WHERE state = 'active'`)
}

// AllPeers returns all peer records regardless of state.
func (s *Store) AllPeers() ([]*PeerRecord, error) {
	return s.queryPeers(`
		SELECT pubkey_hex, name, addr, introduction_method, state, created_at, updated_at
		FROM federation_peers`)
}

func (s *Store) queryPeers(query string, args ...any) ([]*PeerRecord, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("fedstore: query peers: %w", err)
	}
	defer rows.Close()
	var peers []*PeerRecord
	for rows.Next() {
		var p PeerRecord
		if err := rows.Scan(&p.PubkeyHex, &p.Name, &p.Addr, &p.IntroMethod, &p.State, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("fedstore: scan peer: %w", err)
		}
		peers = append(peers, &p)
	}
	return peers, rows.Err()
}

// SetOutboundPolicy replaces all outbound policy rules for peerHex.
// Rules are stored in insertion order; first match wins at evaluation time.
func (s *Store) SetOutboundPolicy(peerHex string, rules []PolicyRule) error {
	return s.setPolicy("federation_outbound_policy", peerHex, rules)
}

// SetInboundPolicy replaces all inbound policy rules for peerHex.
func (s *Store) SetInboundPolicy(peerHex string, rules []PolicyRule) error {
	return s.setPolicy("federation_inbound_policy", peerHex, rules)
}

func (s *Store) setPolicy(table, peerHex string, rules []PolicyRule) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("fedstore: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(
		`DELETE FROM `+table+` WHERE peer_pubkey_hex = ?`, peerHex); err != nil {
		return fmt.Errorf("fedstore: clear %s: %w", table, err)
	}
	for i, rule := range rules {
		if _, err := tx.Exec(
			`INSERT INTO `+table+` (peer_pubkey_hex, position, subject_pattern, effect) VALUES (?, ?, ?, ?)`,
			peerHex, i, rule.SubjectPattern, rule.Effect); err != nil {
			return fmt.Errorf("fedstore: insert %s rule %d: %w", table, i, err)
		}
	}
	return tx.Commit()
}

// GetOutboundPolicy returns outbound rules for peerHex in position order.
func (s *Store) GetOutboundPolicy(peerHex string) ([]PolicyRule, error) {
	return s.getPolicy("federation_outbound_policy", peerHex)
}

// GetInboundPolicy returns inbound rules for peerHex in position order.
func (s *Store) GetInboundPolicy(peerHex string) ([]PolicyRule, error) {
	return s.getPolicy("federation_inbound_policy", peerHex)
}

func (s *Store) getPolicy(table, peerHex string) ([]PolicyRule, error) {
	rows, err := s.db.Query(
		`SELECT subject_pattern, effect FROM `+table+
			` WHERE peer_pubkey_hex = ? ORDER BY position ASC`,
		peerHex)
	if err != nil {
		return nil, fmt.Errorf("fedstore: query %s: %w", table, err)
	}
	defer rows.Close()
	var rules []PolicyRule
	for rows.Next() {
		var r PolicyRule
		if err := rows.Scan(&r.SubjectPattern, &r.Effect); err != nil {
			return nil, fmt.Errorf("fedstore: scan policy: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// SetExportList replaces all remote_entities entries for peerHex.
// entityHexes are the Ed25519 pubkeys (hex-encoded) of entities reachable
// via peerHex. Called when a FedPolicy with exported_pubkeys is received.
func (s *Store) SetExportList(peerHex string, entityHexes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("fedstore: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(
		`DELETE FROM remote_entities WHERE peer_pubkey_hex = ?`, peerHex); err != nil {
		return fmt.Errorf("fedstore: clear remote_entities: %w", err)
	}
	for _, entityHex := range entityHexes {
		if _, err := tx.Exec(
			`INSERT INTO remote_entities (peer_pubkey_hex, entity_pubkey_hex) VALUES (?, ?)`,
			peerHex, entityHex); err != nil {
			return fmt.Errorf("fedstore: insert entity %s: %w", entityHex, err)
		}
	}
	return tx.Commit()
}

// DeletePeer removes a peer and all associated policy/entity rows.
// Child rows (policy, entities) are deleted first to satisfy the foreign-key constraint.
func (s *Store) DeletePeer(pubkeyHex string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("fedstore: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	for _, tbl := range []string{"federation_outbound_policy", "federation_inbound_policy", "remote_entities"} {
		if _, err := tx.Exec("DELETE FROM "+tbl+" WHERE peer_pubkey_hex = ?", pubkeyHex); err != nil {
			return fmt.Errorf("fedstore: delete from %s: %w", tbl, err)
		}
	}
	if _, err := tx.Exec("DELETE FROM federation_peers WHERE pubkey_hex = ?", pubkeyHex); err != nil {
		return fmt.Errorf("fedstore: delete peer %s: %w", pubkeyHex, err)
	}
	return tx.Commit()
}

// GetRemoteEntityMap returns a map of entity_pubkey_hex → peer_pubkey_hex for
// all stored remote entities. Used at startup to hydrate the in-memory routing
// table.
func (s *Store) GetRemoteEntityMap() (map[string]string, error) {
	rows, err := s.db.Query(
		`SELECT entity_pubkey_hex, peer_pubkey_hex FROM remote_entities`)
	if err != nil {
		return nil, fmt.Errorf("fedstore: query remote_entities: %w", err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var entityHex, peerHex string
		if err := rows.Scan(&entityHex, &peerHex); err != nil {
			return nil, fmt.Errorf("fedstore: scan remote entity: %w", err)
		}
		result[entityHex] = peerHex
	}
	return result, rows.Err()
}
