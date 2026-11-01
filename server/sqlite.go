package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo
)

// SQLiteStore is the default Store, backed by a single SQLite file.
//
// The driver is modernc.org/sqlite (pure Go, no cgo) so the server
// cross-compiles like the rest of the tree. Nothing above this file
// knows SQL exists: swapping in PostgreSQL means writing another Store.
type SQLiteStore struct {
	db *sql.DB
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS accounts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	pass_hash  TEXT    NOT NULL,
	roles      TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS player_state (
	account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
	data       TEXT    NOT NULL,
	updated_at INTEGER NOT NULL
);
`

// OpenSQLite opens (creating if needed) the database at path and
// applies the schema. Use ":memory:" for tests.
func OpenSQLite(path string) (*SQLiteStore, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("server: open sqlite: %w", err)
	}
	// SQLite serialises writers anyway; one connection keeps our own
	// goroutines from fighting over SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("server: migrate: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// isUniqueViolation reports whether err is a UNIQUE constraint failure.
// The driver does not export a typed sentinel for this, so match the
// message SQLite itself produces.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateAccount inserts a new account, filling a.ID and normalizing
// a.Name. It returns ErrExists when the name is taken.
func (s *SQLiteStore) CreateAccount(ctx context.Context, a *Account) error {
	name := NormalizeName(a.Name)
	if name == "" {
		return fmt.Errorf("server: empty account name")
	}
	if a.Created.IsZero() {
		a.Created = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (name, pass_hash, roles, created_at) VALUES (?, ?, ?, ?)`,
		name, a.PassHash, strings.Join(a.Roles, ","), a.Created.Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrExists
		}
		return fmt.Errorf("server: create account: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("server: create account id: %w", err)
	}
	a.ID = id
	a.Name = name
	return nil
}

// AccountByName looks an account up by its normalized name.
func (s *SQLiteStore) AccountByName(ctx context.Context, name string) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, pass_hash, roles, created_at FROM accounts WHERE name = ?`,
		NormalizeName(name))
	return scanAccount(row)
}

// AccountByID looks an account up by its primary key.
func (s *SQLiteStore) AccountByID(ctx context.Context, id int64) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, pass_hash, roles, created_at FROM accounts WHERE id = ?`, id)
	return scanAccount(row)
}

// UpdateAccount rewrites the mutable fields (password hash, roles).
func (s *SQLiteStore) UpdateAccount(ctx context.Context, a *Account) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET pass_hash = ?, roles = ? WHERE id = ?`,
		a.PassHash, strings.Join(a.Roles, ","), a.ID)
	if err != nil {
		return fmt.Errorf("server: update account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("server: update account: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// LoadState returns the account's player state.
func (s *SQLiteStore) LoadState(ctx context.Context, accountID int64) (*PlayerState, error) {
	var data string
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM player_state WHERE account_id = ?`, accountID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("server: load state: %w", err)
	}
	var st PlayerState
	if err := json.Unmarshal([]byte(data), &st); err != nil {
		return nil, fmt.Errorf("server: decode state: %w", err)
	}
	st.AccountID = accountID
	return &st, nil
}

// SaveState writes the account's player state, creating the row on
// first save.
func (s *SQLiteStore) SaveState(ctx context.Context, accountID int64, st *PlayerState) error {
	st.AccountID = accountID
	st.Updated = time.Now().UTC()
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("server: encode state: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO player_state (account_id, data, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(account_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
		accountID, string(data), st.Updated.Unix())
	if err != nil {
		return fmt.Errorf("server: save state: %w", err)
	}
	return nil
}

// rowScanner is the subset of *sql.Row that scanAccount needs.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAccount(row rowScanner) (*Account, error) {
	var (
		a       Account
		roles   string
		created int64
	)
	err := row.Scan(&a.ID, &a.Name, &a.PassHash, &roles, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("server: scan account: %w", err)
	}
	a.Created = time.Unix(created, 0).UTC()
	if roles != "" {
		a.Roles = strings.Split(roles, ",")
	}
	return &a, nil
}
