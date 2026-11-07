package server

import (
	"math"
	"time"
)

// PlayerState is everything the lobby shows about one account.
//
// It is stored as an opaque JSON document so the model can grow without
// schema migrations while the server is still being built out. The
// typed fields below are the part the server currently reads and
// writes; anything the client shows but we do not model yet keeps
// whatever the lobby bundle template carries (see bundle.go).
type PlayerState struct {
	AccountID int64 `json:"account_id"`

	// Economy.
	Credits int64 `json:"credits"`
	Gold    int64 `json:"gold"`
	FreeXP  int64 `json:"free_xp"`
	// Crystal is the bond balance. The client's stats diff calls it
	// `crystal` (Currency.CRYSTAL); the UI shows it as bonds.
	Crystal int64 `json:"crystal"`
	// Slots is the garage capacity (`stats.slots`). The client compares it
	// against the owned-vehicle count to decide whether a purchase fits, so
	// it must be at least len(Garage).
	Slots int64 `json:"slots"`
	// PiggyBank is the credits held in the piggy bank, a separate
	// balance the client shows next to the main one.
	PiggyBank int64 `json:"piggy_bank"`
	// PiggyBankGold is the gold reserve, the second piggy-bank balance
	// (`piggyBank.gold`).
	PiggyBankGold int64 `json:"piggy_bank_gold"`
	// Berths is the barracks capacity (`stats.berths`), the crew-side
	// twin of Slots.
	Berths int64 `json:"berths"`
	// PremiumExpiry is the unix time the account's premium runs out
	// (`account.premiumExpiryTime`). It is per-account state, not a
	// constant: buying premium moves it.
	PremiumExpiry int64 `json:"premium_expiry"`

	// GlobalRating is the account's WTR-style rating, a float on the
	// wire (account.globalRating).
	GlobalRating float64 `json:"global_rating"`

	// Garage is the owned-vehicle list. Empty means "not modelled yet":
	// the bundle template's garage is served unchanged.
	Garage []GarageVehicle `json:"garage,omitempty"`

	// Research holds researched vehicle compact descriptors.
	Research [][]byte `json:"research,omitempty"`

	// Clan is the account's clan membership, or nil for a clanless
	// account.
	Clan *Clan `json:"clan,omitempty"`

	Updated time.Time `json:"updated"`
}

// Clan is the account's clan membership.
//
// The game protocol can show the tag next to the player, the role and
// join date on the profile summary, and the clan chat channel. The clan
// profile WINDOW (search, applications, the members table) is served by
// the web API, which a private server does not have — so this is the
// whole of what the game itself can display.
type Clan struct {
	DBID   int64  `json:"dbid"`
	Name   string `json:"name"`
	Abbrev string `json:"abbrev"`
	Motto  string `json:"motto,omitempty"`
	// Description is the clan's free-text blurb.
	Description string `json:"description,omitempty"`
	// Role is a CLAN_MEMBER_FLAGS bit for this account (1 = leader,
	// 2 = vice leader, 64 = private, 128 = recruit).
	Role int64 `json:"role"`
	// Joined is the unix time the account joined the clan.
	Joined int64 `json:"joined"`
	// ChatChannelDBID is the clan's chat channel id, the node of the
	// clan MUC room JID.
	ChatChannelDBID int64 `json:"chat_channel_dbid,omitempty"`
}

// GarageVehicle is one owned vehicle.
type GarageVehicle struct {
	// CompactDescr is the packed nation|type|id header the client uses
	// everywhere; lobby.ResolveCompactDescr decodes it against the
	// component table. It is a variable-length byte string, not an
	// integer (the header nibbles plus a 1-2 byte vehicle id).
	CompactDescr []byte `json:"compact_descr"`

	// XP is the vehicle's own experience.
	XP int64 `json:"xp"`

	// Locked marks a vehicle the client must not sell.
	Locked bool `json:"locked,omitempty"`

	// CrewSize is how many crew slots the vehicle type has. The client's
	// `VehicleDescrCrew` requires the crew list to be exactly this long,
	// so every list the server sends is padded to it.
	CrewSize uint8 `json:"crew_size,omitempty"`

	// Shells is the vehicle's ammunition layout, flat `[cd, count, cd,
	// count, …]` — the shape `CMD_SET_AND_FILL_LAYOUTS` carries and the
	// client reads back as `inventory[1].shellsLayout[vehInvID][0]`.
	Shells []int64 `json:"shells,omitempty"`

	// Eqs is the vehicle's consumables layout, flat `[cd, cd, …]`.
	Eqs []int64 `json:"eqs,omitempty"`

	// Crew is the tankman instance id in each crew slot, indexed by slot.
	// A slot holding 0 is empty. The client derives a tankman's vehicle
	// from this list (`InventoryRequester.__makeVehicle` reads
	// `inventory[1].crew[vehInvID]`), so it is the only place the
	// assignment is stored — the tankman's own descriptor carries the
	// vehicle TYPE it is trained for, never the instance.
	Crew []int64 `json:"crew,omitempty"`
}

// ServedFields names the PlayerState fields that reach the client, and
// the wire slot each one rides.
//
// It is the honest inventory of the account model: what reaches the client
// from PlayerState, what reaches it from the carrier unchanged, and what
// has no slot at all.
func ServedFields() map[string]string {
	return map[string]string{
		"FreeXP":       "1a/69 stats small + bundle stats.freeXP",
		"Credits":      "bundle stats.credits",
		"Gold":         "bundle stats.gold",
		"Crystal":      "bundle stats.crystal (bonds)",
		"Slots":        "bundle stats.slots (garage capacity)",
		"PiggyBank":    "bundle piggyBank.credits",
		"GlobalRating": "bundle account.globalRating",
	}
}

// CaptureFields names the account-document keys the client sees but that
// come from the carrier unchanged. They have a wire slot — the garage is
// `inventory`, progression is `sessionStats`/`wtr`/`battlePass`/`quests`/
// `tokens`/`dogTags` — we just do not drive them from PlayerState yet, so
// every account sees the capture's player.
func CaptureFields() map[string]string {
	return map[string]string{
		"Garage":      "bundle inventory (vehicles, equipment, shells)",
		"Progression": "bundle sessionStats, wtr, battlePass, dogTags, quests, tokens",
		"Dossier":     "bundle stats.dossier (opaque blob)",
		"Revisions":   "bundle prevRev, rev, cache",
	}
}

// UnservedFields names the PlayerState fields with no wire slot in any
// capture, so an operator is not surprised when setting them changes
// nothing in game. The garage is NOT here: it has a slot (`inventory`), it
// is just served from the carrier — see CaptureFields.
func UnservedFields() []string {
	return []string{"Research"}
}

// MaxCurrency is the largest value the client's currency counters hold:
// they are signed 32-bit on the wire, so this is the ceiling rather than a
// round number. A test account starts here so nothing in the hangar is
// gated on a balance.
const MaxCurrency = math.MaxInt32

// DefaultSlots is the garage capacity a fresh account starts with. It is
// the client's own starting value (the garage a new player gets), not a
// limit: an account seeded with every ownable vehicle needs far more, and
// the seeding path raises it to fit.
const DefaultSlots = 8

// DefaultPlayerState is the state a freshly provisioned account starts
// with. The garage is left empty on purpose: seeding it needs real
// compact descriptors from the vehicle table, which is a later step.
// Until then the bundle template's garage is what the client sees.
func DefaultPlayerState(accountID int64) *PlayerState {
	return &PlayerState{
		AccountID:     accountID,
		Credits:       MaxCurrency,
		Gold:          MaxCurrency,
		FreeXP:        MaxCurrency,
		Crystal:       MaxCurrency,
		Slots:         DefaultSlots,
		Berths:        DefaultBerths,
		PremiumExpiry: MaxPremiumExpiry,
		Updated:       time.Now().UTC(),
	}
}

// DefaultBerths is the barracks capacity a fresh account starts with. The
// client shows free beds as `berths - tankmen`, so it has to exceed the
// crew count; the seeding path raises it to fit.
const DefaultBerths = 10000

// MaxPremiumExpiry is the highest premium expiry the client renders.
//
// `gui/shared/gui_items/...` formats the expiry with the client's own
// date code, which rejects anything past 3001-01-01: 32535216000 renders,
// 33000000000 raises `(22, 'Invalid argument')`. So this is a ceiling,
// not a round number — a purchase that would go past it is clamped.
const MaxPremiumExpiry int64 = 32535216000
