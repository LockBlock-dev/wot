package server

import "time"

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
	// PiggyBank is the credits held in the piggy bank, a separate
	// balance the client shows next to the main one.
	PiggyBank int64 `json:"piggy_bank"`

	// GlobalRating is the account's WTR-style rating, a float on the
	// wire (account.globalRating).
	GlobalRating float64 `json:"global_rating"`

	// Garage is the owned-vehicle list. Empty means "not modelled yet":
	// the bundle template's garage is served unchanged.
	Garage []GarageVehicle `json:"garage,omitempty"`

	// Research holds researched vehicle compact descriptors.
	Research [][]byte `json:"research,omitempty"`

	Updated time.Time `json:"updated"`
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
	return []string{"Gold", "Research"}
}

// DefaultPlayerState is the state a freshly provisioned account starts
// with. The garage is left empty on purpose: seeding it needs real
// compact descriptors from the vehicle table, which is a later step.
// Until then the bundle template's garage is what the client sees.
func DefaultPlayerState(accountID int64) *PlayerState {
	return &PlayerState{
		AccountID: accountID,
		Credits:   1_000_000,
		Gold:      1_000,
		FreeXP:    10_000,
		Updated:   time.Now().UTC(),
	}
}
