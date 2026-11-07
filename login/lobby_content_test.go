package login

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestFullSyncAnswerShape pins the 1a/5f answer's two forms.
//
// AccountSyncData.isFullSyncDiff() is `diff.get('prevRev') is None`, so a
// full sync must NOT carry prevRev — that absence is what makes the client
// clear its caches and take the answer as the whole state. A diff carries
// prevRev and nothing else changes.
func TestFullSyncAnswerShape(t *testing.T) {
	stats := map[string]any{"credits": int64(12715044), "gold": int64(500), "freeXP": int64(2003)}
	small, err := BuildFullSyncAnswer(224, 0, stats, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildFullSyncAnswer: %v", err)
	}
	s, _, err := lobby.ParseSmall(small)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Family != 0x1a || s.Type != 0x5f {
		t.Fatalf("small is %#02x/%#02x, want 1a/5f", s.Family, s.Type)
	}
	if got := binary.LittleEndian.Uint32(s.Body[:4]); got != 224 {
		t.Fatalf("request id %d, want 224", got)
	}
	// The ext length is a packed-u24 blob length, so it is one byte below
	// 255 and four above — this document is well past that.
	_, _, _, ext, err := ParseCommandResponse(small)
	if err != nil {
		t.Fatalf("command response: %v", err)
	}
	stk, _, err := lobby.DecodePrefix(ext)
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	d, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("stack top %T, want *PDict", stk[len(stk)-1])
	}
	has := func(key string) any {
		for _, e := range d.Entries {
			if k, isStr := e.Key.(string); isStr && k == key {
				return e.Value
			}
		}
		return nil
	}
	if has("prevRev") != nil {
		t.Fatal("full sync carries prevRev: the client would treat it as a diff")
	}
	if has("rev") == nil {
		t.Fatal("full sync lacks rev")
	}
	st, ok := has("stats").(*lobby.PDict)
	if !ok {
		t.Fatalf("full sync stats = %T, want *PDict", has("stats"))
	}
	for _, k := range []string{"credits", "gold", "freeXP"} {
		found := false
		for _, e := range st.Entries {
			if key, isStr := e.Key.(string); isStr && key == k {
				found = true
				if v, isInt := e.Value.(int64); !isInt || v != stats[k] {
					t.Fatalf("stats.%s = %v, want %v", k, e.Value, stats[k])
				}
			}
		}
		if !found {
			t.Fatalf("stats lacks %q", k)
		}
	}

	// The diff form keeps prevRev.
	diff, err := BuildRevisionsAnswer(224, 88, 88)
	if err != nil {
		t.Fatalf("BuildRevisionsAnswer: %v", err)
	}
	ds, _, err := lobby.ParseSmall(diff)
	if err != nil {
		t.Fatalf("parse diff: %v", err)
	}
	dstk, _, err := lobby.DecodePrefix(ds.Body[6:])
	if err != nil {
		t.Fatalf("diff pickle: %v", err)
	}
	dd, ok := dstk[len(dstk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("diff stack top %T, want *PDict", dstk[len(dstk)-1])
	}
	found := false
	for _, e := range dd.Entries {
		if k, isStr := e.Key.(string); isStr && k == "prevRev" {
			found = true
			if v, isInt := e.Value.(int64); !isInt || v != 88 {
				t.Fatalf("prevRev = %v, want 88", e.Value)
			}
		}
	}
	if !found {
		t.Fatal("diff form lacks prevRev")
	}
}

// TestFullSyncAnswerCarriesTheGarage pins the inventory shape the client's
// InventoryRequester reads: `invData[GUI_ITEM_TYPE.VEHICLE]['compDescr']`
// is indexed UNCONDITIONALLY, so a full sync without item type 1 raises
// KeyError(1) and the hangar's items-cache sync aborts. compDescr is keyed
// by instance id (int) and its values are py2 strs (bytes).
func TestFullSyncAnswerCarriesTheGarage(t *testing.T) {
	inv := map[int64]any{
		1: map[string]any{
			"compDescr":       map[int64]any{7: []byte{0x11, 0x02, 0x2d}},
			"postProgression": map[int64]any{},
		},
	}
	small, err := BuildFullSyncAnswer(224, 0, map[string]any{"freeXP": 1}, inv, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildFullSyncAnswer: %v", err)
	}
	_, _, _, ext, err := ParseCommandResponse(small)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stk, _, err := lobby.DecodePrefix(ext)
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	root, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("stack top %T", stk[len(stk)-1])
	}
	var inventory *lobby.PDict
	for _, e := range root.Entries {
		if k, isStr := e.Key.(string); isStr && k == "inventory" {
			inventory, _ = e.Value.(*lobby.PDict)
		}
	}
	if inventory == nil {
		t.Fatal("full sync has no inventory")
	}
	var vehicles *lobby.PDict
	for _, e := range inventory.Entries {
		if n, isInt := e.Key.(int64); isInt && n == 1 {
			vehicles, _ = e.Value.(*lobby.PDict)
		}
	}
	if vehicles == nil {
		t.Fatal("inventory has no item type 1 (vehicles): InventoryRequester would raise KeyError(1)")
	}
	var compDescr *lobby.PDict
	for _, e := range vehicles.Entries {
		if k, isStr := e.Key.(string); isStr && k == "compDescr" {
			compDescr, _ = e.Value.(*lobby.PDict)
		}
	}
	if compDescr == nil {
		t.Fatal("item type 1 has no compDescr")
	}
	if len(compDescr.Entries) != 1 {
		t.Fatalf("compDescr has %d entries, want 1", len(compDescr.Entries))
	}
	e := compDescr.Entries[0]
	if n, isInt := e.Key.(int64); !isInt || n != 7 {
		t.Fatalf("compDescr key %v (%T), want the int instance id 7", e.Key, e.Key)
	}
	if got, isStr := e.Value.(string); !isStr || got != string([]byte{0x11, 0x02, 0x2d}) {
		t.Fatalf("compDescr value %v (%T), want the raw bytes", e.Value, e.Value)
	}
}

// TestCommandResponseShape pins the 1a/5f command answer the shop and
// dossier syncs need. The genuine element is
// `1a 5f 24 e0 00 00 00 00 1e <30B>`:
//
//	[1a][5f][u8 elementLen][u16 requestID][u16 resultID]
//	[u8 errorLen][u8 extLen][ext]
//
// The TWO length bytes are the trap: an error-string length and an ext
// length. Writing one shifts the ext by a byte, the client reads a
// garbage ext length out of the pickle's PROTO opcode, and the sync
// never completes.
func TestCommandResponseShape(t *testing.T) {
	small, err := BuildCommandResponse(222, 0, lobby.NewDict())
	if err != nil {
		t.Fatalf("BuildCommandResponse: %v", err)
	}
	if small[0] != 0x1a || small[1] != 0x5f {
		t.Fatalf("head % x, want 1a 5f", small[:2])
	}
	if int(small[2]) != len(small)-3 {
		t.Fatalf("element length %d, element %d B", small[2], len(small))
	}
	body := small[3:]
	if got := binary.LittleEndian.Uint16(body[0:2]); got != 222 {
		t.Fatalf("request id %d, want 222", got)
	}
	if got := binary.LittleEndian.Uint16(body[2:4]); got != 0 {
		t.Fatalf("resultID %d, want 0 (RES_SUCCESS)", got)
	}
	if body[4] != 0 {
		t.Fatalf("error length %d, want 0", body[4])
	}
	if int(body[5]) != len(body)-6 {
		t.Fatalf("ext length %d, body %d B", body[5], len(body))
	}
	stk, _, err := lobby.DecodePrefix(body[6:])
	if err != nil {
		t.Fatalf("ext pickle: %v", err)
	}
	if _, ok := stk[len(stk)-1].(*lobby.PDict); !ok {
		t.Fatalf("ext is %T, want *PDict", stk[len(stk)-1])
	}
	// RES_STREAM rides the same u16 field.
	stream, err := BuildCommandResponse(223, 1, lobby.NewDict())
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(stream[5:7]); got != 1 {
		t.Fatalf("resultID %d, want 1 (RES_STREAM)", got)
	}
}

// TestStreamElementsShape pins the two elements the dossier sync needs.
//
// The client keeps a table of in-flight resources keyed by id and DROPS a
// fragment whose id has no header — silently. Sending the fragment alone
// is why the hangar stalled on "Synchronisation du fichier personnel":
// Account.onStreamComplete was never called, so DossierCache never cleared
// __isSynchronizing and DossierRequester parked forever.
//
//	[45][u16 bodyLen][u16 streamID][packed-u24 descLen][pickled (len, crc32)]
//	[46][u16 bodyLen][u16 streamID][u8 seq][u8 last][zlib(pickle)]
func TestStreamElementsShape(t *testing.T) {
	payload := lobby.NewTuple(lobby.NewInt(0), lobby.NewList())
	elems, err := BuildStreamElements(223, payload)
	if err != nil {
		t.Fatalf("BuildStreamElements: %v", err)
	}
	if len(elems) != 2 {
		t.Fatalf("%d elements, want 2 (header then fragment)", len(elems))
	}
	header, fragment := elems[0], elems[1]

	if header[0] != 0x45 {
		t.Fatalf("first element id %#02x, want 0x45 (RESOURCE_HEADER)", header[0])
	}
	if n := int(binary.LittleEndian.Uint16(header[1:3])); 3+n != len(header) {
		t.Fatalf("header body length %d, element %d B", n, len(header))
	}
	hbody := header[3:]
	if got := binary.LittleEndian.Uint16(hbody[:2]); got != 223 {
		t.Fatalf("header stream id %d, want 223 (the request id)", got)
	}
	descLen := int(hbody[2])
	if descLen == 0xFF {
		t.Fatalf("description length uses the 0xFF escape; the test payload is small")
	}
	desc := hbody[3 : 3+descLen]
	if 3+descLen != len(hbody) {
		t.Fatalf("header body is %d B, description ends at %d", len(hbody), 3+descLen)
	}

	if fragment[0] != 0x46 {
		t.Fatalf("second element id %#02x, want 0x46 (RESOURCE_FRAGMENT)", fragment[0])
	}
	if n := int(binary.LittleEndian.Uint16(fragment[1:3])); 3+n != len(fragment) {
		t.Fatalf("fragment body length %d, element %d B", n, len(fragment))
	}
	fbody := fragment[3:]
	if got := binary.LittleEndian.Uint16(fbody[:2]); got != 223 {
		t.Fatalf("fragment stream id %d, want 223", got)
	}
	if fbody[2] != 0 || fbody[3] != 1 {
		t.Fatalf("fragment header % x, want 00 01 (sequence 0, last)", fbody[2:4])
	}
	data := fbody[4:]

	// The description is the pickled (len, crc32) the client checks the
	// data against, over the COMPRESSED bytes, CRC signed as Python 2's
	// zlib.crc32 returns it.
	stk, _, err := lobby.DecodePrefix(desc)
	if err != nil {
		t.Fatalf("description pickle: %v", err)
	}
	dtup, ok := stk[len(stk)-1].(*lobby.PTuple)
	if !ok {
		t.Fatalf("description is %T, want *PTuple", stk[len(stk)-1])
	}
	if len(dtup.Items) != 2 {
		t.Fatalf("description tuple has %d items, want 2 (len, crc32)", len(dtup.Items))
	}
	wantLen := int64(len(data))
	wantCRC := int64(int32(crc32.ChecksumIEEE(data)))
	if got, ok := dtup.Items[0].(int64); !ok || got != wantLen {
		t.Fatalf("description length %v, want %d", dtup.Items[0], wantLen)
	}
	if got, ok := dtup.Items[1].(int64); !ok || got != wantCRC {
		t.Fatalf("description crc32 %v, want %d", dtup.Items[1], wantCRC)
	}

	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	raw, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatalf("zlib read: %v", err)
	}
	stk, _, err = lobby.DecodePrefix(raw)
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	tup, ok := stk[len(stk)-1].(*lobby.PTuple)
	if !ok {
		t.Fatalf("payload is %T, want *PTuple", stk[len(stk)-1])
	}
	if len(tup.Items) != 2 {
		t.Fatalf("tuple has %d items, want 2 (version, dossiers)", len(tup.Items))
	}
}

// TestFullSyncCarriesTheKeysTheClientIndexes pins the sections the client
// reads with a bare `cache[key]` rather than `.get(key, default)`. Each one
// missing is a KeyError inside a sync handler, and a KeyError there does not
// just lose that section: the account dashboard fills its features in one
// loop, so the first raise leaves every later feature at its MODEL DEFAULT.
//
//	potapovQuests.compDescr  PersonalMissionsProgressRequester.request
//	                         -> PMStorage(cache['potapovQuests']['compDescr'])
//	dogTags.playerDogTag     DogTags.getDisplayableDT -> PlayerDogTagStorage
//	                         -> Storage.__init__ does data['playerDogTag']
//
// The dog-tag one is why the profile showed the parental-control block
// ("time limits enforced") on an account with no restrictions:
// `isParentalControlEnabled` defaults to True and the feature that sets it
// from `gameRestrictions.hasSessionLimit` never ran.
func TestFullSyncCarriesTheKeysTheClientIndexes(t *testing.T) {
	small, err := BuildFullSyncAnswer(221, 0, map[string]any{"credits": 1}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildFullSyncAnswer: %v", err)
	}
	_, _, _, ext, err := ParseCommandResponse(small)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stk, _, err := lobby.DecodePrefix(ext)
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	root, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("stack top %T", stk[len(stk)-1])
	}
	section := func(name string) *lobby.PDict {
		for _, e := range root.Entries {
			if k, isStr := e.Key.(string); isStr && k == name {
				d, _ := e.Value.(*lobby.PDict)
				return d
			}
		}
		return nil
	}
	field := func(d *lobby.PDict, name string) any {
		for _, e := range d.Entries {
			if k, isStr := e.Key.(string); isStr && k == name {
				return e.Value
			}
		}
		return nil
	}

	quests := section("potapovQuests")
	if quests == nil {
		t.Fatal("full sync has no potapovQuests: PMStorage would raise KeyError('compDescr')")
	}
	if _, ok := field(quests, "compDescr").(string); !ok {
		t.Fatalf("potapovQuests.compDescr is %T, want a str blob", field(quests, "compDescr"))
	}

	tags := section("dogTags")
	if tags == nil {
		t.Fatal("full sync has no dogTags: PlayerDogTagStorage would raise KeyError('playerDogTag')")
	}
	for _, name := range []string{"playerDogTag", "unlockedComponents", "progress"} {
		if field(tags, name) == nil {
			t.Fatalf("dogTags has no %s: Storage.__init__ does data[%q]", name, name)
		}
	}

	// The wallet gate. Without it WalletController starts in SYNCING and
	// flips to NOT_AVAILABLE after 30 s, which is the state where the
	// hangar header shows "-" for every resource and clicking one says the
	// balance is still being fetched.
	cache := section("cache")
	if cache == nil {
		t.Fatal("full sync has no cache: the wallet would never become available")
	}
	if v, ok := field(cache, "isResourcesConsumptionAllowed").(bool); !ok || !v {
		t.Fatalf("cache.isResourcesConsumptionAllowed = %v, want true", field(cache, "isResourcesConsumptionAllowed"))
	}

	// The account-level stats. `attrs` is a bitmask AOGAS tests with
	// `ACCOUNT_ATTR.AOGAS & attrs`, so a missing key is a TypeError on
	// None rather than a default.
	account := section("account")
	if account == nil {
		t.Fatal("full sync has no account: AOGAS would raise TypeError on attrs")
	}
	if _, ok := field(account, "attrs").(int64); !ok {
		t.Fatalf("account.attrs is %T, want an int", field(account, "attrs"))
	}
}

// TestCommandResponseOversizedLength pins the element-length escape.
//
// onCmdResponseExt's VariableLengthHeaderSize is 1, so its length field is
// one byte — and 0xFF is not "the largest that fits", it is the ESCAPE. The
// client's own writer fills the field with ones, replaces the body's first
// four bytes with the full u32 length, and moves those four displaced bytes
// to the end of the element; the reader reverses it. Writing a plain 0xFF
// for a 255-byte body makes the client read the next four bytes as the
// length, over-read the bundle and die on
//
//	MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_
//
// which is what happened once the account full sync grew past 254 bytes: the
// client crashed right after SHOW GUI and the hangar showed "-" for every
// resource, because the sync carrying them never parsed.
func TestCommandResponseOversizedLength(t *testing.T) {
	// A payload big enough that the element body passes 254 bytes.
	big := lobby.NewDict()
	for i := 0; i < 40; i++ {
		big.Set(fmt.Sprintf("key%02d", i), lobby.NewInt(int64(i)))
	}
	el, err := BuildCommandResponse(221, 0, big)
	if err != nil {
		t.Fatalf("BuildCommandResponse: %v", err)
	}
	if el[0] != 0x1a || el[1] != 0x5f {
		t.Fatalf("head % x, want 1a 5f", el[:2])
	}
	if el[2] != 0xFF {
		t.Fatalf("length byte %#02x, want the 0xFF escape (body is %d B)", el[2], len(el)-3)
	}
	// [1a][5f][FF][u32 len][body[4:]][body[:4]]
	bodyLen := int(binary.LittleEndian.Uint32(el[3:7]))
	if bodyLen < 255 {
		t.Fatalf("escaped length %d, want >= 255", bodyLen)
	}
	if got := len(el); got != 2+1+4+bodyLen {
		t.Fatalf("element is %d B, want %d (2 id + 1 escape + 4 length + body)", got, 2+1+4+bodyLen)
	}
	// Undo the escape the way the client does: the last four bytes are the
	// body's original first four, and the rest is the body from offset 4.
	tail := el[7+bodyLen-4:]
	body := append(append([]byte{}, tail...), el[7:7+bodyLen-4]...)
	if got := binary.LittleEndian.Uint16(body[:2]); got != 221 {
		t.Fatalf("request id %d, want 221", got)
	}
	if got := binary.LittleEndian.Uint16(body[2:4]); got != 0 {
		t.Fatalf("result id %d, want 0", got)
	}
	if body[4] != 0 {
		t.Fatalf("error length %#02x, want 0", body[4])
	}
	// The ext is a STRING argument: packed-u24 length, so 0xFF means the
	// next three bytes are the real length.
	extLen, extAt := int(body[5]), 6
	if extLen == 0xFF {
		extLen = int(body[6]) | int(body[7])<<8 | int(body[8])<<16
		extAt = 9
	}
	if extAt+extLen != len(body) {
		t.Fatalf("ext length %d at %d, body %d B", extLen, extAt, len(body))
	}
	stk, _, err := lobby.DecodePrefix(body[extAt:])
	if err != nil {
		t.Fatalf("ext pickle: %v", err)
	}
	if _, ok := stk[len(stk)-1].(*lobby.PDict); !ok {
		t.Fatalf("ext is %T, want *PDict", stk[len(stk)-1])
	}
}

// TestStreamElementsChunkLargePayloads pins the fragment chunking.
//
// Each element rides its own datagram and the channel MTU is 1300 B, so a
// single fragment carrying a multi-kilobyte account cache is simply lost —
// the client then sits on the sync forever with no error on either side.
// That is exactly what happened when the garage grew to every ownable
// vehicle: the hangar stalled on "Synchronisation de l'équipement".
func TestStreamElementsChunkLargePayloads(t *testing.T) {
	// A payload well past one datagram: 40 KB of dict.
	big := lobby.NewDict()
	for i := 0; i < 4000; i++ {
		big.Set(fmt.Sprintf("key%04d", i), lobby.NewInt(int64(i)))
	}
	elems, err := BuildStreamElements(223, big)
	if err != nil {
		t.Fatalf("BuildStreamElements: %v", err)
	}
	if len(elems) < 3 {
		t.Fatalf("%d elements, want a header plus several fragments", len(elems))
	}
	if elems[0][0] != 0x45 {
		t.Fatalf("first element id %#02x, want 0x45 (RESOURCE_HEADER)", elems[0][0])
	}
	// Every element must fit one datagram: element + tick head (2) +
	// channel flags (2) + trailer (8) + nonce (4) + blowfish padding (8).
	const mtu = 1300
	for i, el := range elems {
		if len(el)+2+2+8+4+8 > mtu {
			t.Fatalf("element %d is %d B, past the %d B MTU", i, len(el), mtu)
		}
	}
	// The fragments carry dense sequence numbers and only the last is
	// flagged last.
	var data []byte
	for i, el := range elems[1:] {
		if el[0] != 0x46 {
			t.Fatalf("element %d id %#02x, want 0x46 (RESOURCE_FRAGMENT)", i+1, el[0])
		}
		sm, _, err := lobby.ParseSmall(el)
		if err != nil {
			t.Fatalf("fragment %d: %v", i, err)
		}
		if got := binary.LittleEndian.Uint16(sm.Body[:2]); got != 223 {
			t.Fatalf("fragment %d stream id %d, want 223", i, got)
		}
		if got := int(sm.Body[2]); got != i {
			t.Fatalf("fragment %d sequence %d, want %d", i, got, i)
		}
		wantLast := byte(0)
		if i == len(elems)-2 {
			wantLast = 1
		}
		if sm.Body[3] != wantLast {
			t.Fatalf("fragment %d last=%d, want %d", i, sm.Body[3], wantLast)
		}
		data = append(data, sm.Body[4:]...)
	}
	// The reassembled stream is the zlib-compressed document.
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("reassembled zlib: %v", err)
	}
	raw, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatalf("reassembled zlib read: %v", err)
	}
	stk, _, err := lobby.DecodePrefix(raw)
	if err != nil {
		t.Fatalf("reassembled pickle: %v", err)
	}
	if _, ok := stk[len(stk)-1].(*lobby.PDict); !ok {
		t.Fatalf("reassembled payload is %T, want *PDict", stk[len(stk)-1])
	}
}

// TestShopDocCarriesTheExchangeRates pins the shop document's scalar keys.
//
// `Shop.getSellPrice` reads `self.__cache['crystalExchangeRate']` directly
// whenever a buy price carries a `crystal` entry, so a document without it
// raises KeyError while building any crystal-priced item — every deluxe
// optional device — and that raise aborts the hangar's crew and loadout
// presenters, leaving the whole panel empty.
func TestShopDocCarriesTheExchangeRates(t *testing.T) {
	doc, err := ShopDoc(map[int64]map[string]int64{11257: {"crystal": 3000}})
	if err != nil {
		t.Fatalf("ShopDoc: %v", err)
	}
	raw, err := lobby.EncodeDocument(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, key := range []string{"sellPriceFactor", "exchangeRate", "exchangeRateForShellsAndEqs", "crystalExchangeRate", "items", "itemPrices"} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("shop document lacks %q: % x", key, raw)
		}
	}
}

// TestFullSyncCarriesClan checks the clan membership slots: `clanDBID`
// is an ACCOUNT stat and `clanInfo` a STAT, and the client unpacks
// clanInfo straight into its own 5-tuple
// (clanName, clanAbbrev, chatChannelDBID, memberFlags, enteringTime).
func TestFullSyncCarriesClan(t *testing.T) {
	clan := &ClanDoc{
		DBID:            8760142,
		Name:            "Admin Clan",
		Abbrev:          "ADMIN",
		ChatChannelDBID: 8760142,
		Role:            1,
		Joined:          1700000000,
	}
	doc, err := FullSyncDoc(1, map[string]any{"credits": 1}, nil, nil, clan, nil)
	if err != nil {
		t.Fatalf("FullSyncDoc: %v", err)
	}
	raw, err := lobby.EncodeDocument(doc)
	if err != nil {
		t.Fatalf("EncodeDocument: %v", err)
	}
	// The account block carries clanDBID.
	account := doc.Get("account")
	if account == nil {
		t.Fatal("no account block")
	}
	if got := account.Get("clanDBID"); got == nil || got.I != 8760142 {
		t.Fatalf("account.clanDBID = %+v", got)
	}
	// The stats block carries the 5-tuple.
	stats := doc.Get("stats")
	if stats == nil {
		t.Fatal("no stats block")
	}
	info := stats.Get("clanInfo")
	if info == nil || info.Kind != lobby.FList || len(info.Items) != 5 {
		t.Fatalf("stats.clanInfo = %+v", info)
	}
	if info.Items[0].S != "Admin Clan" || info.Items[1].S != "ADMIN" {
		t.Fatalf("clanInfo name/abbrev = %q/%q", info.Items[0].S, info.Items[1].S)
	}
	if info.Items[2].I != 8760142 || info.Items[3].I != 1 || info.Items[4].I != 1700000000 {
		t.Fatalf("clanInfo tail = %d/%d/%d", info.Items[2].I, info.Items[3].I, info.Items[4].I)
	}
	if len(raw) == 0 {
		t.Fatal("empty document")
	}
}

// TestFullSyncClanless checks that a clanless account keeps the zero
// clanDBID and no clanInfo key, which is what the client's
// `getClanInfo` treats as "no clan".
func TestFullSyncClanless(t *testing.T) {
	doc, err := FullSyncDoc(1, map[string]any{"credits": 1}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("FullSyncDoc: %v", err)
	}
	if got := doc.Get("account").Get("clanDBID"); got == nil || got.I != 0 {
		t.Fatalf("account.clanDBID = %+v", got)
	}
	if got := doc.Get("stats").Get("clanInfo"); got != nil {
		t.Fatalf("stats.clanInfo = %+v, want absent", got)
	}
}

// TestShopDocCarriesARecertificationForm pins the one goodie the client's own
// notification listeners index without a guard.
//
// `RecertificationFormStateListener._getState` does
// `goodiesCache.getRecertificationForm(currency='credits').enabled`, and
// `getRecertificationForm` returns None when the shop holds no
// RECERTIFICATION_FORM (variety 3) with a credits resource (20) — the listener
// is started on every hangar load, so an empty table logs
// `AttributeError: 'NoneType' object has no attribute 'enabled'` each time.
func TestShopDocCarriesARecertificationForm(t *testing.T) {
	doc, err := ShopDoc(nil)
	if err != nil {
		t.Fatalf("ShopDoc: %v", err)
	}
	goodies := doc.Get("goodies")
	if goodies == nil {
		t.Fatal("shop has no goodies node")
	}
	forms := goodies.Get("goodies")
	if forms == nil || forms.Kind != lobby.FDict || len(forms.Items) == 0 {
		t.Fatalf("shop.goodies.goodies = %+v, want at least one goodie", forms)
	}
	// The client reads the tuple as (variety, target, enabled, lifetime,
	// useby, limit, autostart, condition, resource, expireAfter,
	// roundToEndOfGameDay); variety 3 is RECERTIFICATION_FORM and the
	// resource's first field 20 is CREDITS.
	entry := forms.Items[0]
	if entry.Kind != lobby.FTuple || len(entry.Items) != 11 {
		t.Fatalf("goodie = %+v, want an 11-tuple", entry)
	}
	if got := entry.Items[0].I; got != 3 {
		t.Fatalf("variety = %d, want 3 (RECERTIFICATION_FORM)", got)
	}
	if entry.Items[2].Kind != lobby.FBool || entry.Items[2].B {
		t.Fatalf("enabled = %+v, want false (the form is not on sale)", entry.Items[2])
	}
	res := entry.Items[8]
	if res.Kind != lobby.FTuple || len(res.Items) != 3 || res.Items[0].I != 20 {
		t.Fatalf("resource = %+v, want (20, value, isPercentage)", res)
	}
}
