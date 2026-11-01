// Command wotaccounts is the operator CLI for the private server's
// account store. wotserver can only bootstrap one default account, so
// this is how a real roster gets created and inspected.
//
// Usage:
//
//	wotaccounts [-db wotserver.db] list
//	wotaccounts [-db wotserver.db] add NAME [-pass P] [-role R]
//	wotaccounts [-db wotserver.db] passwd NAME [-pass P]
//	wotaccounts [-db wotserver.db] state NAME
//	wotaccounts [-db wotserver.db] set NAME [-credits N] [-gold N] [-freexp N]
//
// A password given as -pass is visible in the process list; omit it and
// the CLI reads one line from stdin instead. Passwords are never
// printed, only their bcrypt cost.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/LockBlock-dev/wot/server"
)

// valueFlags are the flags that consume the following token, so the
// argument splitter knows not to mistake a password for a command.
var valueFlags = map[string]bool{
	"db": true, "pass": true, "role": true,
	"credits": true, "gold": true, "freexp": true,
	"piggybank": true, "rating": true,
}

func main() {
	fs := flag.NewFlagSet("wotaccounts", flag.ExitOnError)
	dbPath := fs.String("db", "wotserver.db", "SQLite database path")
	pass := fs.String("pass", "", "password (omit to read one line from stdin)")
	role := fs.String("role", "", "comma-separated roles for add")
	credits := fs.Int64("credits", -1, "set credits (-1 = leave alone)")
	gold := fs.Int64("gold", -1, "set gold (-1 = leave alone)")
	freexp := fs.Int64("freexp", -1, "set free XP (-1 = leave alone)")
	piggy := fs.Int64("piggybank", -1, "set piggy bank credits (-1 = leave alone)")
	rating := fs.Float64("rating", -1, "set global rating (-1 = leave alone)")
	fs.Usage = usage

	// Flags may sit on either side of the subcommand (`-db X add NAME`
	// and `add NAME -pass P` both work), which the stdlib parser does
	// not do on its own: it stops at the first positional.
	flags, positional := splitArgs(os.Args[1:])
	if err := fs.Parse(flags); err != nil {
		fatal(err)
	}
	if len(positional) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := positional[0], positional[1:]

	store, err := server.OpenSQLite(*dbPath)
	if err != nil {
		fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	switch cmd {
	case "list":
		if err := list(ctx, store); err != nil {
			fatal(err)
		}
	case "add":
		name, err := oneName(rest)
		if err != nil {
			fatal(err)
		}
		pw, err := password(*pass)
		if err != nil {
			fatal(err)
		}
		if err := add(ctx, store, name, pw, *role); err != nil {
			fatal(err)
		}
	case "passwd":
		name, err := oneName(rest)
		if err != nil {
			fatal(err)
		}
		pw, err := password(*pass)
		if err != nil {
			fatal(err)
		}
		if err := passwd(ctx, store, name, pw); err != nil {
			fatal(err)
		}
	case "state":
		name, err := oneName(rest)
		if err != nil {
			fatal(err)
		}
		if err := showState(ctx, store, name); err != nil {
			fatal(err)
		}
	case "set":
		name, err := oneName(rest)
		if err != nil {
			fatal(err)
		}
		if err := setState(ctx, store, name, *credits, *gold, *freexp, *piggy, *rating); err != nil {
			fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "wotaccounts: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

// splitArgs separates flags from positionals so the subcommand can come
// first. A flag written as -name=value is self-contained; a bare
// -name consumes the next token when it is a known value flag.
func splitArgs(argv []string) (flags, positional []string) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			positional = append(positional, argv[i+1:]...)
			return flags, positional
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && valueFlags[name] && i+1 < len(argv) {
				i++
				flags = append(flags, argv[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return flags, positional
}

func usage() {
	fmt.Fprint(os.Stderr, `wotaccounts — manage the private server's accounts

  wotaccounts [-db FILE] list
  wotaccounts [-db FILE] add NAME [-pass P] [-role R,R]
  wotaccounts [-db FILE] passwd NAME [-pass P]
  wotaccounts [-db FILE] state NAME
  wotaccounts [-db FILE] set NAME [-credits N] [-gold N] [-freexp N]
                              [-piggybank N] [-rating F]

Omit -pass to read the password from stdin (keeps it out of the process
list). Passwords are never printed.
`)
}

func oneName(rest []string) (string, error) {
	if len(rest) != 1 {
		return "", fmt.Errorf("expected exactly one account name, got %d", len(rest))
	}
	return rest[0], nil
}

// password returns the -pass value, or reads one line from stdin.
func password(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	fmt.Fprint(os.Stderr, "password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read password: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", errors.New("empty password")
	}
	return pw, nil
}

func list(ctx context.Context, st server.Store) error {
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		return err
	}
	if len(accts) == 0 {
		fmt.Println("no accounts")
		return nil
	}
	fmt.Printf("%-4s %-24s %-16s %s\n", "id", "name", "roles", "created")
	for _, a := range accts {
		roles := strings.Join(a.Roles, ",")
		if roles == "" {
			roles = "-"
		}
		fmt.Printf("%-4d %-24s %-16s %s\n", a.ID, a.Name, roles, a.Created.Format("2006-01-02 15:04"))
	}
	return nil
}

func add(ctx context.Context, st server.Store, name, pw, roles string) error {
	if !server.LoginNameValid(name) {
		// Not fatal — the store takes any name — but the client's login
		// form only accepts an email, so this account cannot be typed in.
		fmt.Fprintf(os.Stderr,
			"warning: %q is not a login the client accepts (the form requires an email, e.g. admin@wot.test)\n",
			server.NormalizeName(name))
	}
	hash, err := server.HashPassword(pw)
	if err != nil {
		return err
	}
	a := &server.Account{Name: name, PassHash: hash}
	if roles != "" {
		a.Roles = strings.Split(roles, ",")
	}
	if err := st.CreateAccount(ctx, a); err != nil {
		if errors.Is(err, server.ErrExists) {
			return fmt.Errorf("account %q already exists", server.NormalizeName(name))
		}
		return err
	}
	// Give the account a starting state so the lobby has something to
	// show on the first login.
	if err := st.SaveState(ctx, a.ID, server.DefaultPlayerState(a.ID)); err != nil {
		return err
	}
	fmt.Printf("created account %q (id %d)\n", a.Name, a.ID)
	return nil
}

func passwd(ctx context.Context, st server.Store, name, pw string) error {
	a, err := st.AccountByName(ctx, name)
	if err != nil {
		return notFound(err, name)
	}
	hash, err := server.HashPassword(pw)
	if err != nil {
		return err
	}
	a.PassHash = hash
	if err := st.UpdateAccount(ctx, a); err != nil {
		return err
	}
	fmt.Printf("password updated for %q\n", a.Name)
	return nil
}

func showState(ctx context.Context, st server.Store, name string) error {
	a, err := st.AccountByName(ctx, name)
	if err != nil {
		return notFound(err, name)
	}
	s, err := st.LoadState(ctx, a.ID)
	if err != nil {
		return notFound(err, name)
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s (id %d)\n%s\n", a.Name, a.ID, out)
	return nil
}

func setState(ctx context.Context, st server.Store, name string, credits, gold, freexp, piggy int64, rating float64) error {
	a, err := st.AccountByName(ctx, name)
	if err != nil {
		return notFound(err, name)
	}
	s, err := st.LoadState(ctx, a.ID)
	if err != nil {
		return notFound(err, name)
	}
	if credits >= 0 {
		s.Credits = credits
	}
	if gold >= 0 {
		s.Gold = gold
	}
	if freexp >= 0 {
		s.FreeXP = freexp
	}
	if piggy >= 0 {
		s.PiggyBank = piggy
	}
	if rating >= 0 {
		s.GlobalRating = rating
	}
	if err := st.SaveState(ctx, a.ID, s); err != nil {
		return err
	}
	fmt.Printf("%s: credits %d, gold %d, free XP %d, piggy bank %d, rating %.2f\n",
		a.Name, s.Credits, s.Gold, s.FreeXP, s.PiggyBank, s.GlobalRating)
	return nil
}

func notFound(err error, name string) error {
	if errors.Is(err, server.ErrNotFound) {
		return fmt.Errorf("no account or state for %q", server.NormalizeName(name))
	}
	return err
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wotaccounts: %v\n", err)
	os.Exit(1)
}
