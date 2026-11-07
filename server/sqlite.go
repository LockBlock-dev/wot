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
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	name            TEXT    NOT NULL UNIQUE,
	pass_hash       TEXT    NOT NULL,
	roles           TEXT    NOT NULL DEFAULT '',
	created_at      INTEGER NOT NULL,
	remember_token  TEXT    NOT NULL DEFAULT '',
	remember_issued INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS player_state (
	account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
	data       TEXT    NOT NULL,
	updated_at INTEGER NOT NULL
);
` + socialSchema

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
	s := &SQLiteStore{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// migrate adds the columns a database created before them lacks. The
// CREATE TABLE IF NOT EXISTS above does not touch an existing table.
func (s *SQLiteStore) migrate(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(accounts)`)
	if err != nil {
		return fmt.Errorf("server: migrate: %w", err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			dflt             any
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("server: migrate: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("server: migrate: %w", err)
	}
	rows.Close()
	for _, c := range []struct{ name, ddl string }{
		{"remember_token", `ALTER TABLE accounts ADD COLUMN remember_token TEXT NOT NULL DEFAULT ''`},
		{"remember_issued", `ALTER TABLE accounts ADD COLUMN remember_issued INTEGER NOT NULL DEFAULT 0`},
	} {
		if have[c.name] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("server: migrate %s: %w", c.name, err)
		}
	}
	return nil
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
	issued := int64(0)
	if !a.RememberIssued.IsZero() {
		issued = a.RememberIssued.Unix()
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (name, pass_hash, roles, created_at, remember_token, remember_issued) VALUES (?, ?, ?, ?, ?, ?)`,
		name, a.PassHash, strings.Join(a.Roles, ","), a.Created.Unix(), a.RememberToken, issued)
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
		`SELECT id, name, pass_hash, roles, created_at, remember_token, remember_issued FROM accounts WHERE name = ?`,
		NormalizeName(name))
	return scanAccount(row)
}

// AccountByID looks an account up by its primary key.
func (s *SQLiteStore) AccountByID(ctx context.Context, id int64) (*Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, pass_hash, roles, created_at, remember_token, remember_issued FROM accounts WHERE id = ?`, id)
	return scanAccount(row)
}

// ListAccounts returns every account, ordered by id.
func (s *SQLiteStore) ListAccounts(ctx context.Context) ([]*Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, pass_hash, roles, created_at, remember_token, remember_issued FROM accounts ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("server: list accounts: %w", err)
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("server: list accounts: %w", err)
	}
	return out, nil
}

// UpdateAccount rewrites the mutable fields (password hash, roles).
func (s *SQLiteStore) UpdateAccount(ctx context.Context, a *Account) error {
	issued := int64(0)
	if !a.RememberIssued.IsZero() {
		issued = a.RememberIssued.Unix()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET pass_hash = ?, roles = ?, remember_token = ?, remember_issued = ? WHERE id = ?`,
		a.PassHash, strings.Join(a.Roles, ","), a.RememberToken, issued, a.ID)
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
		token   sql.NullString
		issued  sql.NullInt64
	)
	err := row.Scan(&a.ID, &a.Name, &a.PassHash, &roles, &created, &token, &issued)
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
	if token.Valid {
		a.RememberToken = token.String
	}
	if issued.Valid && issued.Int64 > 0 {
		a.RememberIssued = time.Unix(issued.Int64, 0).UTC()
	}
	return &a, nil
}

// SetRememberToken stores the account's current "remember me" token2,
// replacing the previous one (single-use-forward).
func (s *SQLiteStore) SetRememberToken(ctx context.Context, accountID int64, token string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET remember_token = ?, remember_issued = ? WHERE id = ?`,
		token, time.Now().UTC().Unix(), accountID)
	if err != nil {
		return fmt.Errorf("server: set remember token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("server: set remember token: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AccountByRememberToken finds the account whose stored token2 is token.
func (s *SQLiteStore) AccountByRememberToken(ctx context.Context, token string) (*Account, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, pass_hash, roles, created_at, remember_token, remember_issued FROM accounts WHERE remember_token = ?`,
		token)
	return scanAccount(row)
}
