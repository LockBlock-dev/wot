package login

import (
	"bytes"
	"net"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// fakeEconomy records the calls and returns a fixed result.
type fakeEconomy struct {
	calls  []string
	result EconomyResult
}

func (f *fakeEconomy) Exchange(int64, int64, int64) EconomyResult {
	f.calls = append(f.calls, "exchange")
	return f.result
}
func (f *fakeEconomy) ConvertFreeXP(int64, int64, int64) EconomyResult {
	f.calls = append(f.calls, "freexp")
	return f.result
}
func (f *fakeEconomy) BuyPremium(int64, int64) EconomyResult {
	f.calls = append(f.calls, "premium")
	return f.result
}
func (f *fakeEconomy) BuySlot(int64) EconomyResult {
	f.calls = append(f.calls, "slot")
	return f.result
}
func (f *fakeEconomy) BuyBerths(int64, int64) EconomyResult {
	f.calls = append(f.calls, "berths")
	return f.result
}
func (f *fakeEconomy) SetPiggyBank(int64, int64, int64) EconomyResult {
	f.calls = append(f.calls, "setpiggy")
	return f.result
}
func (f *fakeEconomy) SmashPiggyBank(int64) EconomyResult {
	f.calls = append(f.calls, "smash")
	return f.result
}

// economyServer builds a server with the Account dispatch and a fake
// economy backend.
func economyServer(t *testing.T, econ EconomyBackend) *BaseAppServer {
	t.Helper()
	s := tokenTestServer(t, nil)
	s.cfg.Economy = econ
	return s
}

// economyCall builds a postCall for one economy command.
func economyCall(t *testing.T, s *BaseAppServer, method string, args ...entdef.Value) postCall {
	t.Helper()
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, method)
	if m == nil {
		t.Fatalf("no %s in the Account base methods", method)
	}
	// decodeBaseCall fills Req/Cmd from the first two integer arguments;
	// a hand-built call has to do the same.
	call := postCall{Method: m, Args: args}
	if len(args) > 0 {
		call.Req = uint16(uintOf(args[0]))
	}
	if len(args) > 1 {
		call.Cmd = uint16(uintOf(args[1]))
	}
	return call
}

// TestExchangeAnswersAndPushes checks the two-part answer: the command
// response clears the client's request, then Account.update carries the
// new balances.
func TestExchangeAnswersAndPushes(t *testing.T) {
	econ := &fakeEconomy{result: EconomyResult{
		Credits: 4000, Gold: 990, FreeXP: 7, Crystal: 3,
		Slots: 12, Berths: 100, PremiumExpiry: 1700000000,
		PiggyBank: 500, PiggyBankGold: 50,
	}}
	s := economyServer(t, econ)
	call := economyCall(t, s, "doCmdInt4",
		entdef.Value{Kind: entdef.VInt, Int: 7},    // requestID
		entdef.Value{Kind: entdef.VInt, Int: 202},  // CMD_EXCHANGE
		entdef.Value{Kind: entdef.VInt, Int: 1},    // shopRev
		entdef.Value{Kind: entdef.VInt, Int: 10},   // gold
		entdef.Value{Kind: entdef.VInt, Int: 4000}, // credits
		entdef.Value{Kind: entdef.VInt, Int: 0},
	)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.answerPostCall(tr, addr, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(econ.calls) != 1 || econ.calls[0] != "exchange" {
		t.Fatalf("calls = %v", econ.calls)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d writes, want 2 (response + push)", len(tr.writes))
	}
	// The first write is the command response.
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if !bytes.Contains(app, []byte{0x1a, smallRevisions}) {
		t.Fatalf("first write is not a command response: % x", app)
	}
	// The second is Account.update with the balances.
	push := findAppInPacket(t, tr.writes[1], st.blockKey)
	for _, want := range []string{"prevRev", "rev", "stats", "credits", "gold", "freeXP", "slots", "berths", "account", "premiumExpiryTime", "premium", "premMask", "piggyBank"} {
		if !bytes.Contains(push, []byte(want)) {
			t.Fatalf("push is missing %q: % x", want, push)
		}
	}
}

// TestEconomyFailureSendsNoPush checks that a refused purchase answers
// with the negative result and does not touch the balances.
func TestEconomyFailureSendsNoPush(t *testing.T) {
	econ := &fakeEconomy{result: EconomyResult{Code: -10, Message: "not enough gold"}}
	s := economyServer(t, econ)
	call := economyCall(t, s, "doCmdInt3",
		entdef.Value{Kind: entdef.VInt, Int: 8},
		entdef.Value{Kind: entdef.VInt, Int: 204}, // CMD_PREMIUM
		entdef.Value{Kind: entdef.VInt, Int: 1},
		entdef.Value{Kind: entdef.VInt, Int: 30},
		entdef.Value{Kind: entdef.VInt, Int: 0},
	)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes, want 1 (response only)", len(tr.writes))
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	// resultID -10 is 0xfff6 little-endian, and the error string follows.
	if !bytes.Contains(app, []byte{0xf6, 0xff}) {
		t.Fatalf("result is not -10: % x", app)
	}
	if !bytes.Contains(app, []byte("not enough gold")) {
		t.Fatalf("error string missing: % x", app)
	}
}

// TestFreeXPConvReadsTheArray checks the doCmdIntArr layout: the command
// carries [shopRev, xp, gold, ...vehCDs].
func TestFreeXPConvReadsTheArray(t *testing.T) {
	econ := &fakeEconomy{result: EconomyResult{Credits: 1, Gold: 2, FreeXP: 3}}
	s := economyServer(t, econ)
	arr := entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VInt, Int: 1},     // shopRev
		{Kind: entdef.VInt, Int: 100},   // xp
		{Kind: entdef.VInt, Int: 4},     // gold
		{Kind: entdef.VInt, Int: 46849}, // a vehicle compact descriptor
	}}
	call := economyCall(t, s, "doCmdIntArr",
		entdef.Value{Kind: entdef.VInt, Int: 9},
		entdef.Value{Kind: entdef.VInt, Int: 203}, // CMD_FREE_XP_CONV
		arr,
	)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(econ.calls) != 1 || econ.calls[0] != "freexp" {
		t.Fatalf("calls = %v", econ.calls)
	}
}

// TestShopDocCarriesThePurchaseTables checks the keys the purchase flows
// read through the RAW Shop object, where an absent key is None and the
// flow aborts before it sends anything.
func TestShopDocCarriesThePurchaseTables(t *testing.T) {
	doc, err := ShopDoc(nil)
	if err != nil {
		t.Fatalf("ShopDoc: %v", err)
	}
	for _, key := range []string{
		"exchangeRate", "exchangeRateForShellsAndEqs", "crystalExchangeRate",
		"premiumCost", "slotsPrices", "berthsPrices", "freeXPConversion",
		"sellPriceModif", "clanCreationCost", "items",
	} {
		if doc.Get(key) == nil {
			t.Fatalf("shop document is missing %q", key)
		}
	}
	// premiumCost is {days: gold} and must not be empty: the client's own
	// default is {}, which leaves the premium window with nothing to buy.
	cost := doc.Get("premiumCost")
	if cost.Kind != lobby.FDict || len(cost.Keys) == 0 {
		t.Fatalf("premiumCost = %+v", cost)
	}
	// slotsPrices is (base, [[currency, amount]]).
	slots := doc.Get("slotsPrices")
	if slots.Kind != lobby.FTuple || len(slots.Items) != 2 {
		t.Fatalf("slotsPrices = %+v", slots)
	}
	if slots.Items[1].Kind != lobby.FList || len(slots.Items[1].Items) == 0 {
		t.Fatalf("slotsPrices ladder = %+v", slots.Items[1])
	}
	// berthsPrices is (base, packSize, [gold]).
	berths := doc.Get("berthsPrices")
	if berths.Kind != lobby.FTuple || len(berths.Items) != 3 {
		t.Fatalf("berthsPrices = %+v", berths)
	}
	// freeXPConversion is (xp, gold).
	conv := doc.Get("freeXPConversion")
	if conv.Kind != lobby.FTuple || len(conv.Items) != 2 {
		t.Fatalf("freeXPConversion = %+v", conv)
	}
	if conv.Items[0].I != FreeXPPerGold || conv.Items[1].I != 1 {
		t.Fatalf("freeXPConversion = %d/%d", conv.Items[0].I, conv.Items[1].I)
	}
}

// TestShopDocCarriesTheDialogTables pins the keys the crew and
// customization dialogs index without a default. `tankmanCost` is the one
// that bit: `processors/tankman.pyc _getRecruitPrice` does
// `shop.tankmanCost[tmanCostTypeIdx]` with no guard, so an empty tuple is
// an IndexError the moment the recruit window opens.
func TestShopDocCarriesTheDialogTables(t *testing.T) {
	doc, err := ShopDoc(nil)
	if err != nil {
		t.Fatalf("ShopDoc: %v", err)
	}
	for _, key := range []string{
		"tankmanCost", "tankman", "changeRoleCost", "dropSkillsCost",
		"freeXPToTManXPRate", "dailyXPFactor", "winXPFactorMode",
		"restore_config", "camouflageCost", "playerEmblemCost",
		"playerInscriptionCost", "paidRemovalCost", "paidDeluxeRemovalCost",
		"customRoleSlotChangeCost", "battlePassLevelCost",
		"isEnabledBuyingGoldEqsForCredits", "isEnabledBuyingGoldShellsForCredits",
		"defaults", "goodies", "specialPrices", "spgRedesignFeatures",
	} {
		if doc.Get(key) == nil {
			t.Fatalf("shop document is missing %q", key)
		}
	}
	// tankmanCost is a tuple of at least one entry, and entry 0 carries the
	// currency keys Money reads.
	cost := doc.Get("tankmanCost")
	if cost.Kind != lobby.FTuple || len(cost.Items) < 1 {
		t.Fatalf("tankmanCost = %+v", cost)
	}
	first := cost.Items[0]
	if first.Kind != lobby.FDict {
		t.Fatalf("tankmanCost[0] = %+v", first)
	}
	for _, key := range []string{"credits", "gold", "isPremium", "roleLevel"} {
		if first.Get(key) == nil {
			t.Fatalf("tankmanCost[0] is missing %q", key)
		}
	}
	// tankman.recruit.options is indexed by the same cost type.
	recruit := doc.Get("tankman").Get("recruit").Get("options")
	if recruit == nil || recruit.Kind != lobby.FTuple || len(recruit.Items) < 1 {
		t.Fatalf("tankman.recruit.options = %+v", recruit)
	}
	// The items block keeps the price table and the not-for-sale sets.
	items := doc.Get("items")
	if items.Get("itemPrices") == nil || items.Get("notInShopItems") == nil {
		t.Fatalf("shop.items = %+v", items)
	}
}
