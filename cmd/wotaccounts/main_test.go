package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/LockBlock-dev/wot/server"
)

// TestAddThenLogin is the point of the CLI: an account created here must
// be one the server accepts, with a starting state the lobby can show.
func TestAddThenLogin(t *testing.T) {
	ctx := context.Background()
	st, err := server.OpenSQLite(filepath.Join(t.TempDir(), "acct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := add(ctx, st, "PlayerOne", "hunter2", "admin"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// The name is normalized on the way in, so the client's casing works.
	acct, err := st.AccountByName(ctx, "PLAYERONE")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if acct.Name != "playerone" {
		t.Errorf("name = %q, want normalized", acct.Name)
	}
	if !acct.HasRole("admin") {
		t.Errorf("roles = %v, want admin", acct.Roles)
	}
	if !acct.CheckPassword("hunter2") {
		t.Error("password does not verify")
	}

	// The server's own auth path must accept it.
	srv := server.New(st, server.Config{})
	if _, err := srv.Authenticate(ctx, "playerone", "hunter2"); err != nil {
		t.Fatalf("server rejected the created account: %v", err)
	}
	if _, err := srv.Authenticate(ctx, "playerone", "wrong"); err == nil {
		t.Fatal("server accepted a wrong password")
	}

	// A starting state exists, so the first login has something to show.
	state, err := st.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if state.FreeXP == 0 {
		t.Error("provisioned state has no free XP")
	}
}

// TestAddRejectsDuplicate keeps the CLI from silently overwriting.
func TestAddRejectsDuplicate(t *testing.T) {
	ctx := context.Background()
	st, err := server.OpenSQLite(filepath.Join(t.TempDir(), "acct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := add(ctx, st, "dup", "a", ""); err != nil {
		t.Fatal(err)
	}
	if err := add(ctx, st, "DUP", "b", ""); err == nil {
		t.Fatal("duplicate account accepted")
	}
}

// TestPasswdAndSetState covers the two mutating commands.
func TestPasswdAndSetState(t *testing.T) {
	ctx := context.Background()
	st, err := server.OpenSQLite(filepath.Join(t.TempDir(), "acct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := add(ctx, st, "p", "old", ""); err != nil {
		t.Fatal(err)
	}
	if err := passwd(ctx, st, "p", "new"); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	acct, err := st.AccountByName(ctx, "p")
	if err != nil {
		t.Fatal(err)
	}
	if acct.CheckPassword("old") {
		t.Error("old password still works")
	}
	if !acct.CheckPassword("new") {
		t.Error("new password does not work")
	}

	if err := setState(ctx, st, "p", 500, 7, 42); err != nil {
		t.Fatalf("set: %v", err)
	}
	state, err := st.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Credits != 500 || state.Gold != 7 || state.FreeXP != 42 {
		t.Errorf("state = %+v, want 500/7/42", state)
	}
	// -1 means "leave alone".
	if err := setState(ctx, st, "p", -1, 9, -1); err != nil {
		t.Fatal(err)
	}
	state, err = st.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Credits != 500 || state.Gold != 9 || state.FreeXP != 42 {
		t.Errorf("state = %+v, want credits/freeXP untouched", state)
	}
}

// TestSplitArgs pins the flag/positional split that lets the subcommand
// come first.
func TestSplitArgs(t *testing.T) {
	cases := []struct {
		argv       []string
		flags, pos []string
	}{
		{[]string{"add", "NAME", "-pass", "p"}, []string{"-pass", "p"}, []string{"add", "NAME"}},
		{[]string{"-db", "x.db", "list"}, []string{"-db", "x.db"}, []string{"list"}},
		{[]string{"set", "NAME", "-credits", "5"}, []string{"-credits", "5"}, []string{"set", "NAME"}},
		{[]string{"add", "NAME", "-pass=p"}, []string{"-pass=p"}, []string{"add", "NAME"}},
		{[]string{"list", "--", "-weird"}, nil, []string{"list", "-weird"}},
	}
	for _, c := range cases {
		flags, pos := splitArgs(c.argv)
		if len(flags) != len(c.flags) || len(pos) != len(c.pos) {
			t.Errorf("splitArgs(%v) = %v / %v, want %v / %v", c.argv, flags, pos, c.flags, c.pos)
			continue
		}
		for i := range flags {
			if flags[i] != c.flags[i] {
				t.Errorf("splitArgs(%v) flags = %v, want %v", c.argv, flags, c.flags)
				break
			}
		}
		for i := range pos {
			if pos[i] != c.pos[i] {
				t.Errorf("splitArgs(%v) positional = %v, want %v", c.argv, pos, c.pos)
				break
			}
		}
	}
}
