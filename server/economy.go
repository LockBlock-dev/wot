package server

import (
	"context"
	"fmt"
	"time"

	"github.com/LockBlock-dev/wot/login"
)

// Economy is the purchase surface: every flow the client can trigger that
// moves money.
//
// It implements login.EconomyBackend, so the wire layer never touches the
// store and this file never touches a socket. Every method loads the
// account state, applies the purchase, saves it and returns the new
// balances — the wire layer pushes those to the client through
// `Account.update(diff)`, because the client never reads a balance out of
// a command answer.
type Economy struct {
	store Store
	// now is the clock, injectable so a test can pin the premium expiry.
	now func() time.Time
}

// NewEconomy returns the purchase surface over a store.
func NewEconomy(store Store) *Economy {
	return &Economy{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// The client's RES_* result codes (`common/AccountCommands.pyc`).
const (
	resSuccess      int32 = 0
	resFailure      int32 = -1
	resWrongArgs    int32 = -2
	resNotAvailable int32 = -10
)

// resultOf renders a state as an EconomyResult.
func resultOf(st *PlayerState) login.EconomyResult {
	return login.EconomyResult{
		Credits:       st.Credits,
		Gold:          st.Gold,
		FreeXP:        st.FreeXP,
		Crystal:       st.Crystal,
		Slots:         st.Slots,
		Berths:        st.Berths,
		PremiumExpiry: st.PremiumExpiry,
		PiggyBank:     st.PiggyBank,
		PiggyBankGold: st.PiggyBankGold,
	}
}

// fail renders a refusal.
func fail(code int32, format string, args ...any) login.EconomyResult {
	return login.EconomyResult{Code: code, Message: fmt.Sprintf(format, args...)}
}

// apply loads the state, runs fn and saves the result. A nil error means
// the purchase applied and the returned state is the new one.
func (e *Economy) apply(accountID int64, fn func(st *PlayerState) (int32, string)) (login.EconomyResult, error) {
	ctx := context.Background()
	st, err := e.store.LoadState(ctx, accountID)
	if err != nil {
		return fail(resFailure, "account state unavailable"), err
	}
	if code, msg := fn(st); code != resSuccess {
		return login.EconomyResult{Code: code, Message: msg}, nil
	}
	st.Updated = e.now()
	if err := e.store.SaveState(ctx, accountID, st); err != nil {
		return fail(resFailure, "could not save the account"), err
	}
	return resultOf(st), nil
}

// Exchange converts gold into credits at the shop's rate.
//
// The rate is the server's, not the client's: `Stats.exchange(gold,
// credits)` sends both numbers, and trusting the credits would let a
// client name its own price. A mismatch is logged and the server's value
// wins.
func (e *Economy) Exchange(accountID int64, gold, credits int64) login.EconomyResult {
	if gold <= 0 {
		return fail(resWrongArgs, "nothing to exchange")
	}
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		if st.Gold < gold {
			return resNotAvailable, "not enough gold"
		}
		st.Gold -= gold
		st.Credits += gold * login.ExchangeRate
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// ConvertFreeXP buys free experience with gold.
//
// `CMD_FREE_XP_CONV` carries `[shopRev, xp, gold, ...vehCDs]`; the vehicle
// compact descriptors are the tanks whose own XP is being converted, which
// this server does not model (the garage has no per-vehicle XP yet), so
// only the free-XP side applies.
func (e *Economy) ConvertFreeXP(accountID int64, xp, gold int64) login.EconomyResult {
	if xp <= 0 {
		return fail(resWrongArgs, "nothing to convert")
	}
	// The price is the server's: `freeXPConversion` is (xp per gold).
	price := (xp + login.FreeXPPerGold - 1) / login.FreeXPPerGold
	if gold > 0 && gold != price {
		// The client computed a different price (a discount it believes
		// in); the server's rate wins.
		gold = price
	}
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		if st.Gold < price {
			return resNotAvailable, "not enough gold"
		}
		st.Gold -= price
		st.FreeXP += xp
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// BuyPremium extends the account's premium by days.
//
// The expiry is clamped to MaxPremiumExpiry: the client's date
// formatter rejects anything past 3001-01-01, and a raise there aborts the
// hangar header. An account already at the ceiling still pays — the
// purchase is real, the clock just cannot move.
func (e *Economy) BuyPremium(accountID int64, days int64) login.EconomyResult {
	price, ok := premiumPrice(days)
	if !ok {
		return fail(resWrongArgs, "no such premium package")
	}
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		if st.Gold < price {
			return resNotAvailable, "not enough gold"
		}
		st.Gold -= price
		base := st.PremiumExpiry
		if now := e.now().Unix(); now > base {
			base = now
		}
		st.PremiumExpiry = base + days*86400
		if st.PremiumExpiry > MaxPremiumExpiry {
			st.PremiumExpiry = MaxPremiumExpiry
		}
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// BuySlot buys one garage slot at the next price on the ladder.
func (e *Economy) BuySlot(accountID int64) login.EconomyResult {
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		price := nextSlotPrice(st.Slots)
		if st.Credits < price {
			return resNotAvailable, "not enough credits"
		}
		st.Credits -= price
		st.Slots++
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// BuyBerths buys `packs` barracks berth packs with gold.
func (e *Economy) BuyBerths(accountID int64, packs int64) login.EconomyResult {
	if packs <= 0 {
		return fail(resWrongArgs, "nothing to buy")
	}
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		price := nextBerthPackPrice(st.Berths) * packs
		if st.Gold < price {
			return resNotAvailable, "not enough gold"
		}
		st.Gold -= price
		st.Berths += packs * login.BerthPackSize
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// SetPiggyBank sets the two reserves (the dev command).
func (e *Economy) SetPiggyBank(accountID int64, credits, gold int64) login.EconomyResult {
	if credits < 0 || gold < 0 {
		return fail(resWrongArgs, "negative reserve")
	}
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		st.PiggyBank = credits
		st.PiggyBankGold = gold
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// SmashPiggyBank pays the reserves out and empties them.
//
// The live server does this from a service-channel push; a private server
// has no such push, so the dev command is the honest path to the same
// state.
func (e *Economy) SmashPiggyBank(accountID int64) login.EconomyResult {
	res, err := e.apply(accountID, func(st *PlayerState) (int32, string) {
		if st.PiggyBank == 0 && st.PiggyBankGold == 0 {
			return resNotAvailable, "the reserve is empty"
		}
		st.Credits += st.PiggyBank
		st.Gold += st.PiggyBankGold
		st.PiggyBank = 0
		st.PiggyBankGold = 0
		return resSuccess, ""
	})
	if err != nil {
		return res
	}
	return res
}

// premiumPrice returns the gold price of a premium package, mirroring
// `shop.premiumCost`.
func premiumPrice(days int64) (int64, bool) {
	switch days {
	case 1:
		return 250, true
	case 3:
		return 650, true
	case 7:
		return 1250, true
	case 30:
		return 2500, true
	case 90:
		return 6500, true
	case 180:
		return 11000, true
	case 360:
		return 20000, true
	}
	return 0, false
}

// nextSlotPrice mirrors `items/item_price.getNextSlotPrice`: index the
// ladder by the current slot count and fall back to its last entry.
func nextSlotPrice(slots int64) int64 {
	ladder := []int64{300, 600, 1200, 2400, 4800}
	i := slots
	if i < 0 {
		i = 0
	}
	if i >= int64(len(ladder)) {
		i = int64(len(ladder)) - 1
	}
	return ladder[i]
}

// nextBerthPackPrice mirrors `items/item_price.getNextBerthPackPrice`.
func nextBerthPackPrice(berths int64) int64 {
	ladder := []int64{300, 600, 1200, 2400}
	i := berths / login.BerthPackSize
	if i < 0 {
		i = 0
	}
	if i >= int64(len(ladder)) {
		i = int64(len(ladder)) - 1
	}
	return ladder[i]
}
