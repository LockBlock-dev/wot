package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/LockBlock-dev/wot/xmppserver"
)

// socialSchema is the chat layer's table. It is keyed by the client
// databaseID rather than the account id because that is the key the XMPP
// layer sees (the JID node), and the mapping is a fixed offset — storing
// the id the wire uses keeps the two sides from having to agree on it.
const socialSchema = `
CREATE TABLE IF NOT EXISTS social (
	dbid       INTEGER PRIMARY KEY,
	data       TEXT    NOT NULL,
	updated_at INTEGER NOT NULL
);
`

// LoadSocial implements xmppserver.SocialStore.
func (s *SQLiteStore) LoadSocial(ctx context.Context, dbid int64) (*xmppserver.Social, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM social WHERE dbid = ?`, dbid).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return &xmppserver.Social{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("server: load social %d: %w", dbid, err)
	}
	var st xmppserver.Social
	if err := json.Unmarshal([]byte(data), &st); err != nil {
		return nil, fmt.Errorf("server: decode social %d: %w", dbid, err)
	}
	return &st, nil
}

// SaveSocial implements xmppserver.SocialStore.
func (s *SQLiteStore) SaveSocial(ctx context.Context, dbid int64, st *xmppserver.Social) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("server: encode social %d: %w", dbid, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO social (dbid, data, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(dbid) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
		dbid, string(data), time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("server: save social %d: %w", dbid, err)
	}
	return nil
}
