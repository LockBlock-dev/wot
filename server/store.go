// Package server is the private server's application layer: accounts,
// sessions, player state, and the lobby content generated from it.
//
// It sits on top of login/ (the wire) and lobby/ (the protocol codecs):
// login/ decides what the bytes are, server/ decides what they mean.
package server

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("server: not found")

// ErrExists is returned when a create collides on a unique key.
var ErrExists = errors.New("server: already exists")

// Store is the persistence boundary. Everything the server needs to
// remember goes through it, so the backend can be swapped (SQLite now,
// PostgreSQL later) without touching the application layer.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// CreateAccount inserts a new account. It returns ErrExists when
	// the normalized name is already taken, and fills a.ID on success.
	CreateAccount(ctx context.Context, a *Account) error

	// AccountByName looks an account up by its normalized name.
	AccountByName(ctx context.Context, name string) (*Account, error)

	// AccountByID looks an account up by its primary key.
	AccountByID(ctx context.Context, id int64) (*Account, error)

	// ListAccounts returns every account, ordered by id. It backs the
	// operator CLI; the wire never needs it.
	ListAccounts(ctx context.Context) ([]*Account, error)

	// UpdateAccount rewrites the mutable account fields (password hash,
	// roles, remember token). The name is immutable.
	UpdateAccount(ctx context.Context, a *Account) error

	// SetRememberToken stores the account's current "remember me"
	// token2, replacing the previous one (single-use-forward).
	SetRememberToken(ctx context.Context, accountID int64, token string) error

	// AccountByRememberToken finds the account whose stored token2 is
	// token, or ErrNotFound.
	AccountByRememberToken(ctx context.Context, token string) (*Account, error)

	// LoadState returns the account's player state, or ErrNotFound when
	// the account has never been provisioned.
	LoadState(ctx context.Context, accountID int64) (*PlayerState, error)

	// SaveState writes the account's player state, creating the row on
	// first save.
	SaveState(ctx context.Context, accountID int64, st *PlayerState) error

	// Close releases the backend.
	Close() error
}
