package server

import (
	"context"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/login"
)

// economyFixture provisions one account and returns the purchase surface
// plus the account id.
func economyFixture(t *testing.T) (*Economy, *SQLiteStore, int64) {
	t.Helper()
	ctx := context.Background()
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := New(store, Config{DefaultUser: "admin@wot.test", DefaultPassword: "admin"})
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := store.AccountByName(ctx, NormalizeName("admin@wot.test"))
	if err != nil {
		t.Fatal(err)
	}
	return NewEconomy(store), store, acct.ID
}

// setState rewrites the account state for a test.
func setState(t *testing.T, store *SQLiteStore, id int64, fn func(st *PlayerState)) *PlayerState {
	t.Helper()
	ctx := context.Background()
	st, err := store.LoadState(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	fn(st)
	if err := store.SaveState(ctx, id, st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestExchangeUsesTheServerRate checks that the credits come from the
// server's rate, not from the number the client sent.
func TestExchangeUsesTheServerRate(t *testing.T) {
	econ, store, id := economyFixture(t)
	setState(t, store, id, func(st *PlayerState) {
		st.Gold = 1000
		st.Credits = 0
	})
	// The client claims 1 credit per gold; the server pays 400.
	res := econ.Exchange(id, 10, 10)
	if !res.Ok() {
		t.Fatalf("Exchange failed: %+v", res)
	}
	if res.Gold != 990 {
		t.Fatalf("gold = %d, want 990", res.Gold)
	}
	if res.Credits != 10*login.ExchangeRate {
		t.Fatalf("credits = %d, want %d", res.Credits, 10*login.ExchangeRate)
	}
}

// TestExchangeRefusesWhenShort checks the not-enough-gold path.
func TestExchangeRefusesWhenShort(t *testing.T) {
	econ, store, id := economyFixture(t)
	setState(t, store, id, func(st *PlayerState) { st.Gold = 5 })
	res := econ.Exchange(id, 10, 4000)
	if res.Ok() {
		t.Fatalf("Exchange succeeded with 5 gold: %+v", res)
	}
	if res.Code != resNotAvailable {
		t.Fatalf("code = %d, want %d", res.Code, resNotAvailable)
	}
	// The state is untouched.
	st, err := store.LoadState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if st.Gold != 5 {
		t.Fatalf("gold = %d after a refused exchange, want 5", st.Gold)
	}
}

// TestConvertFreeXP checks the free-XP purchase: the price is the
// server's rate, rounded up.
func TestConvertFreeXP(t *testing.T) {
	econ, store, id := economyFixture(t)
	setState(t, store, id, func(st *PlayerState) {
		st.Gold = 1000
		st.FreeXP = 0
	})
	// 100 XP at 25 XP per gold = 4 gold.
	res := econ.ConvertFreeXP(id, 100, 4)
	if !res.Ok() {
		t.Fatalf("ConvertFreeXP failed: %+v", res)
	}
	if res.Gold != 996 || res.FreeXP != 100 {
		t.Fatalf("gold/freeXP = %d/%d, want 996/100", res.Gold, res.FreeXP)
	}
	// A client that under-pays is charged the server's price.
	res = econ.ConvertFreeXP(id, 100, 1)
	if !res.Ok() {
		t.Fatalf("ConvertFreeXP failed: %+v", res)
	}
	if res.Gold != 992 {
		t.Fatalf("gold = %d, want 992 (charged 4, not the 1 the client sent)", res.Gold)
	}
}

// TestBuyPremiumExtendsAndClamps checks the premium purchase: the expiry
// moves by the package length and never past the client's ceiling.
func TestBuyPremiumExtendsAndClamps(t *testing.T) {
	econ, store, id := economyFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	econ.now = func() time.Time { return now }
	setState(t, store, id, func(st *PlayerState) {
		st.Gold = 100000
		st.PremiumExpiry = now.Unix()
	})
	res := econ.BuyPremium(id, 30)
	if !res.Ok() {
		t.Fatalf("BuyPremium failed: %+v", res)
	}
	if want := now.Unix() + 30*86400; res.PremiumExpiry != want {
		t.Fatalf("expiry = %d, want %d", res.PremiumExpiry, want)
	}
	if res.Gold != 100000-2500 {
		t.Fatalf("gold = %d, want %d", res.Gold, 100000-2500)
	}
	// A package that would run past the ceiling is clamped: the client's
	// date formatter rejects anything past 3001-01-01.
	setState(t, store, id, func(st *PlayerState) {
		st.PremiumExpiry = MaxPremiumExpiry - 86400
	})
	res = econ.BuyPremium(id, 360)
	if !res.Ok() {
		t.Fatalf("BuyPremium failed: %+v", res)
	}
	if res.PremiumExpiry != MaxPremiumExpiry {
		t.Fatalf("expiry = %d, want the ceiling %d", res.PremiumExpiry, MaxPremiumExpiry)
	}
	// An unknown package is refused.
	if got := econ.BuyPremium(id, 5); got.Ok() {
		t.Fatalf("BuyPremium(5 days) succeeded: %+v", got)
	}
}

// TestBuySlotAndBerths checks the two capacity purchases.
func TestBuySlotAndBerths(t *testing.T) {
	econ, store, id := economyFixture(t)
	setState(t, store, id, func(st *PlayerState) {
		st.Credits = 100000
		st.Gold = 100000
		st.Slots = 0
		st.Berths = 0
	})
	res := econ.BuySlot(id)
	if !res.Ok() {
		t.Fatalf("BuySlot failed: %+v", res)
	}
	if res.Slots != 1 || res.Credits != 100000-300 {
		t.Fatalf("slots/credits = %d/%d, want 1/%d", res.Slots, res.Credits, 100000-300)
	}
	res = econ.BuyBerths(id, 2)
	if !res.Ok() {
		t.Fatalf("BuyBerths failed: %+v", res)
	}
	if res.Berths != 2*login.BerthPackSize {
		t.Fatalf("berths = %d, want %d", res.Berths, 2*login.BerthPackSize)
	}
	if res.Gold != 100000-2*300 {
		t.Fatalf("gold = %d, want %d", res.Gold, 100000-2*300)
	}
}

// TestPiggyBankRoundTrip checks the reserve: set, smash, empty.
func TestPiggyBankRoundTrip(t *testing.T) {
	econ, store, id := economyFixture(t)
	setState(t, store, id, func(st *PlayerState) {
		st.Credits = 0
		st.Gold = 0
		st.PiggyBank = 0
		st.PiggyBankGold = 0
	})
	res := econ.SetPiggyBank(id, 5000, 100)
	if !res.Ok() {
		t.Fatalf("SetPiggyBank failed: %+v", res)
	}
	if res.PiggyBank != 5000 || res.PiggyBankGold != 100 {
		t.Fatalf("reserve = %d/%d, want 5000/100", res.PiggyBank, res.PiggyBankGold)
	}
	res = econ.SmashPiggyBank(id)
	if !res.Ok() {
		t.Fatalf("SmashPiggyBank failed: %+v", res)
	}
	if res.Credits != 5000 || res.Gold != 100 {
		t.Fatalf("balances = %d/%d, want 5000/100", res.Credits, res.Gold)
	}
	if res.PiggyBank != 0 || res.PiggyBankGold != 0 {
		t.Fatalf("reserve after smash = %d/%d, want 0/0", res.PiggyBank, res.PiggyBankGold)
	}
	// Smashing an empty reserve is refused.
	if got := econ.SmashPiggyBank(id); got.Ok() {
		t.Fatalf("SmashPiggyBank on an empty reserve succeeded: %+v", got)
	}
}

// TestPremiumPriceLadder pins the package table the shop document
// advertises, so the two cannot drift.
func TestPremiumPriceLadder(t *testing.T) {
	for _, days := range []int64{1, 3, 7, 30, 90, 180, 360} {
		if _, ok := premiumPrice(days); !ok {
			t.Fatalf("premiumPrice(%d) missing", days)
		}
	}
	if _, ok := premiumPrice(2); ok {
		t.Fatal("premiumPrice(2) exists")
	}
}
