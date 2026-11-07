package login

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"time"

	"github.com/LockBlock-dev/wot/lobby"
)

// The stage-2 lobby's smalls, AUTHORED from the client's own scripts
// instead of replayed from a capture.
//
// Every one of them is a `lobby.Small` (family 0x1a) behind a tick head,
// and every body is a pickle the client's Python reads with
// cPickle.loads. The shapes below come from the client's handlers:
//
//	1a/76  session dict   {serverUTC, databaseID, aogasStartedAt,
//	                       sessionStartedAt, isAogasEnabled,
//	                       collectUiStats, logUXEvents}
//	                       Account.py / _AccountRepository
//	1a/5f  revisions      {rev, prevRev}   AccountSyncData
//	1a/5b  server stats   two u32 counters (no pickle, no length byte)
//	1a/5e  command error  [req u16][status u8][pad]
//	1a/67  queue census   {players, classes}
//
// The 1a/76 body is [status 0][pickle length][pickle]; the 1a/5f body is
// [request id u32][status 0][pickle length][pickle].

const (
	// smallSessionDict is `Account.showGUI` (entityMethodBase 0x4E + 40).
	smallSessionDict = 0x76
	// smallRevisions is `Account.onCmdResponseExt` (0x4E + 17): the command
	// answer that carries the ext pickle. `onCmdResponse` (no ext) is the
	// element before it, 0x5e.
	smallRevisions = 0x5f
	smallStats     = 0x5b
	smallError     = 0x5e
	smallQueueInfo = 0x67
)

// sessionDictDoc is the per-session identity/clock dict. The client reads
// it twice: as the 1a/76 small at login, and as the STRING argument of
// the Account client method showGUI — the live game.log shows the same
// seven keys in both (`[Account] showGUI {'serverUTC': …, 'databaseID':
// …, 'aogasStartedAt': …, 'sessionStartedAt': …, 'isAogasEnabled': True,
// 'collectUiStats': True, 'logUXEvents': False}`).
//
// serverUTC and aogasStartedAt are BINFLOAT (the client compares them
// against its own clock); databaseID and sessionStartedAt are BININT.
// The three booleans are the playtime-telemetry gates; the client only
// reads them, so they carry the values a normal session has.
func sessionDictDoc(accountID int64, started, now time.Time) *lobby.FNode {
	utc := float64(now.UnixNano()) / 1e9
	return lobby.NewDict().
		Set("serverUTC", lobby.NewFloat(utc)).
		Set("databaseID", lobby.NewInt(accountID)).
		// The aogas playtime watcher starts a hair after the session
		// UTC stamp (1.951 ms on the live capture).
		Set("aogasStartedAt", lobby.NewFloat(utc-0.001951)).
		Set("sessionStartedAt", lobby.NewInt(started.Unix())).
		Set("isAogasEnabled", lobby.NewBool(true)).
		Set("collectUiStats", lobby.NewBool(true)).
		Set("logUXEvents", lobby.NewBool(false))
}

// BuildSessionDict mints the 1a/76 session dict: the per-session identity
// and clock the client's account repository reads at login.
func BuildSessionDict(accountID int64, started, now time.Time) ([]byte, error) {
	pickle, err := lobby.EncodeDocument(sessionDictDoc(accountID, started, now))
	if err != nil {
		return nil, fmt.Errorf("wotlogin: session dict: %w", err)
	}
	if len(pickle) > 0xFF {
		return nil, fmt.Errorf("wotlogin: session dict pickle is %d B, beyond the u8 length", len(pickle))
	}
	// Body = [u8 pickle length][pickle]. The genuine 1a/76 (flows3-s2,
	// live-flood.hex, proxy-20261014-1752) is `1a 76 9c 00 9b <155B>`:
	// the u16 is the body length and the single byte after it is the
	// pickle's own length (0x9b = 155 = 156 - 1). There is NO status
	// byte — an extra one makes the client read a zero-length pickle
	// and then assert on the 140 bytes it left behind.
	body := append([]byte{byte(len(pickle))}, pickle...)
	return lobby.Small{Family: 0x1a, Type: smallSessionDict, Body: body}.Encode()
}

// BuildRevisionsAnswer mints the 1a/5f answer to the client's
// CMD_SYNC_DATA: the account's revision pair. The client compares prevRev
// against the revision it asked with and resyncs on a mismatch, so prevRev
// is the client's own value and rev is what it becomes.
func BuildRevisionsAnswer(reqID uint32, rev, prevRev int64) ([]byte, error) {
	return buildSyncAnswer(reqID, lobby.NewDict().
		Set("rev", lobby.NewInt(rev)).
		Set("prevRev", lobby.NewInt(prevRev)))
}

// fullSyncRev is the revision every full sync carries. It is non-zero on
// purpose: AccountSyncData.__onSyncComplete stores it and then calls
// `self._synchronize()`, which asks again with it — and that follow-up is
// what the server answers with a cheap revision ack instead of resending
// the whole state. A zero revision would make the follow-up look like a
// first sync and pull the full document a second time.
const fullSyncRev = 1

// premiumExpiryUnix is the DEFAULT premium expiry the full sync carries: 3001-01-01,
// which the client reads as a permanent premium account.
//
// It is not "as large as an int64 allows" on purpose. The client formats the
// expiry through `time.localtime`, and the C runtime behind it rejects
// anything past roughly year 3001 — measured in the live client:
//
//	32535216000 -> 3001-01-01   ok
//	33000000000 ->              (22, 'Invalid argument')
//	41024448000 ->              (22, 'Invalid argument')
//
// so this is the highest value that still renders.
const premiumExpiryUnix = 32535216000 // 3001-01-01T00:00:00Z

// EconomyDoc is the per-account economy the full sync carries OUTSIDE the
// `stats` map: the premium expiry (an ACCOUNT stat, and the `premium`
// block) and the two piggy-bank reserves.
type EconomyDoc struct {
	PremiumExpiry    int64
	PiggyBankCredits int64
	PiggyBankGold    int64
}

// premiumExpiry returns the expiry, or the default when no document was
// supplied (a server running without an account store).
func (e *EconomyDoc) premiumExpiry() int64 {
	if e == nil || e.PremiumExpiry == 0 {
		return premiumExpiryUnix
	}
	return e.PremiumExpiry
}

func (e *EconomyDoc) piggyCredits() int64 {
	if e == nil {
		return 0
	}
	return e.PiggyBankCredits
}

func (e *EconomyDoc) piggyGold() int64 {
	if e == nil {
		return 0
	}
	return e.PiggyBankGold
}

// ClanDoc is the clan membership the account sync carries.
//
// The client's own tuple is `ClanInfo(clanName, clanAbbrev,
// chatChannelDBID, memberFlags, enteringTime)` (gui/clans/clan_cache.pyc),
// and `memberFlags` is a CLAN_MEMBER_FLAGS bit (1 = leader). The clan
// profile WINDOW is served by the web API, not by the game protocol, so
// this is what the game itself can show: the tag next to the player, the
// role and join date on the profile summary, and the clan chat channel.
type ClanDoc struct {
	DBID            int64
	Name            string
	Abbrev          string
	ChatChannelDBID int64
	Role            int64
	Joined          int64
	// Motto and Description do not ride the sync: they go out through
	// `onClanInfoReceived`, which is the only place the client keeps
	// them (`g_clanCache.onClanInfoReceived`).
	Motto       string
	Description string
}

// statsWithClan returns the stats dict with `clanInfo` set, creating the
// dict when the caller passed no stats at all.
func statsWithClan(stats *lobby.FNode, info *lobby.FNode) *lobby.FNode {
	if stats == nil || stats.Kind != lobby.FDict {
		stats = lobby.NewDict()
	}
	return stats.Set("clanInfo", info)
}

// BuildFullSyncAnswer mints the 1a/5f answer for a client that holds no
// account cache: the whole state, and NO prevRev.
//
// AccountSyncData.isFullSyncDiff() is `diff.get('prevRev') is None`, so
// the absence of prevRev is what tells the client to clear its caches and
// take this as the full picture. The `stats` dict carries the economy
// (Currency.ALL + freeXP, see gui/shared/money.py and
// account_helpers/Stats.py); `inventory` is keyed by item type index
// (1 = vehicle, 8 = tankman, 11 = equipment, 13 = crewSkin — see
// items.ITEM_TYPE_NAMES), each section in whatever shape its type uses.
func BuildFullSyncAnswer(reqID uint32, rev int64, stats map[string]any, inventory map[int64]any, unlocks []int64, clan *ClanDoc, econ *EconomyDoc) ([]byte, error) {
	root, err := FullSyncDoc(rev, stats, inventory, unlocks, clan, econ)
	if err != nil {
		return nil, err
	}
	return buildSyncAnswer(reqID, root)
}

// FullSyncDoc is the full-sync document itself, without the 1a/5f framing.
// The account sync is answered as a RESOURCE STREAM rather than an inline
// element because a garage of every ownable vehicle is ~9 KB, far past the
// 1223-byte bundle payload — see answerPostCall's CmdSyncData case.
func FullSyncDoc(rev int64, stats map[string]any, inventory map[int64]any, unlocks []int64, clan *ClanDoc, econ *EconomyDoc) (*lobby.FNode, error) {
	root := lobby.NewDict().Set("rev", lobby.NewInt(rev))
	if len(stats) > 0 || len(unlocks) > 0 {
		st := lobby.NewDict()
		for k, v := range stats {
			node, err := anyNode(v)
			if err != nil {
				return nil, fmt.Errorf("wotlogin: full sync stat %q: %w", k, err)
			}
			st.Set(k, node)
		}
		// `unlocks` is a GROWING SET stat (Stats._GROWING_SET_STATS), so
		// the diff value is a list the client unions into its set. It is
		// what `gui_items/vehicle.py isUnlocked` tests, so an empty one
		// renders the whole tech tree greyed out as unresearched.
		if len(unlocks) > 0 {
			items := lobby.NewList()
			for _, cd := range unlocks {
				items.Append(lobby.NewInt(cd))
			}
			st.Set("unlocks", items)
		}
		root.Set("stats", st)
	}
	if len(inventory) > 0 {
		// A section is either field-keyed (`{compDescr: …}`, the garage and
		// the barracks) or intCD-keyed (`{intCD: count}`, consumables and
		// crew skins); anyNode handles both, so the shape is the caller's.
		inv := lobby.NewDict()
		for itemType, items := range inventory {
			node, err := anyNode(items)
			if err != nil {
				return nil, fmt.Errorf("wotlogin: full sync inventory %d: %w", itemType, err)
			}
			inv.SetNode(lobby.NewInt(itemType), node)
		}
		root.Set("inventory", inv)
	}
	// The personal-mission progress blob. `QuestProgress.synchronize` reads
	// the `potapovQuests` key (PMProgressKeys.REGULAR) and
	// `PersonalMissionsProgressRequester.request` then does
	// `PMStorage(cache['potapovQuests']['compDescr'])` — with no key at all
	// that raises KeyError('compDescr') and the quests sync dies. The blob
	// is `[u16 count][u16 questID]...` (PMStorage.__init__ unpacks '<H'
	// then '<%sH'), so an empty one is two zero bytes.
	root.Set("potapovQuests", lobby.NewDict().
		Set("compDescr", lobby.NewString("\x00\x00")))
	// The dog-tag document. `DogTags.synchronize` reads the `dogTags` key
	// (DT_PDATA_KEY) and `DogTags.getDisplayableDT` then builds
	// `PlayerDogTagStorage(cache)`, whose `Storage.__init__` does
	// `data['playerDogTag']` — with no key at all that raises
	// KeyError('playerDogTag'). The account dashboard fills its features in
	// one loop, so that exception aborts the loop and every feature after
	// dog tags keeps its MODEL DEFAULT — which is why the profile showed
	// the parental-control block ("time limits enforced") on an account
	// with no restrictions: `isParentalControlEnabled` defaults to True and
	// the feature that sets it from `gameRestrictions.hasSessionLimit`
	// never ran. An empty `playerDogTag` falls back to the default tag
	// (`compIds = self._section or self.default()`).
	unlocked := lobby.NewList()
	for _, id := range lobby.DogTagUnlockedComponents(lobby.AllDogTagComponentIDs) {
		unlocked.Append(lobby.NewInt(id))
	}
	root.Set("dogTags", lobby.NewDict().
		Set("playerDogTag", lobby.NewList()).
		Set("unlockedComponents", unlocked).
		Set("progress", lobby.NewDict()))
	// The wallet gate. `WalletController.onLobbyStarted` reads
	// `itemsCache.items.stats.isResourcesConsumptionAllowed` (2.4.1.1;
	// `mayConsumeWalletResources` on 2.4.0) and starts in SYNCING when it
	// is false, flipping to NOT_AVAILABLE after 30 s. That is the state
	// where the hangar header shows "-" for every resource and clicking
	// one says the balance is still being fetched. The key lives under
	// `cache` (Stats._CACHE_STATS), not under `stats`.
	root.Set("cache", lobby.NewDict().
		Set("isResourcesConsumptionAllowed", lobby.NewBool(true)))
	// The account-level stats (Stats._ACCOUNT_STATS). `attrs` is a bitmask
	// AOGAS tests with `ACCOUNT_ATTR.AOGAS & attrs`, so a missing key is a
	// TypeError on None, not a default.
	account := lobby.NewDict().
		Set("attrs", lobby.NewInt(0)).
		Set("globalRating", lobby.NewInt(0)).
		Set("clanDBID", lobby.NewInt(0)).
		Set("premiumExpiryTime", lobby.NewInt(econ.premiumExpiry()))
	// Clan membership. `clanDBID` is an ACCOUNT stat and `clanInfo` a
	// STAT (account_helpers/Stats.pyc _ACCOUNT_STATS / _SIMPLE_VALUE_STATS),
	// and both land in the same cache, which is what
	// `StatsRequester.clanDBID` / `.clanInfo` read. `clanInfo` is the
	// client's own 5-tuple — `ClanInfo(clanName, clanAbbrev,
	// chatChannelDBID, memberFlags, enteringTime)` from
	// gui/clans/clan_cache.pyc — and `gui_items.getClanInfo` unpacks it
	// straight into that namedtuple, so the order is not negotiable.
	if clan != nil && clan.DBID != 0 {
		account.Set("clanDBID", lobby.NewInt(clan.DBID))
		info := lobby.NewList().
			Append(lobby.NewString(clan.Name)).
			Append(lobby.NewString(clan.Abbrev)).
			Append(lobby.NewInt(clan.ChatChannelDBID)).
			Append(lobby.NewInt(clan.Role)).
			Append(lobby.NewInt(clan.Joined))
		root.Set("stats", statsWithClan(root.Get("stats"), info))
	}
	root.Set("account", account)
	// Premium. `Stats.isPremium` is `getCacheValue('premiumInfo',
	// PremiumInfo()).isPremium`, and `PremiumInfo.update` merges the diff
	// into `_rawPremiumInfo`, which is keyed by PREMIUM TYPE ID (1, 2, 4)
	// plus `premMask` — not by name. `activePremiumExpiryTime` reads the
	// highest active type, so all three are stamped and the mask says all
	// three are on.
	root.Set("premium", premiumNode(econ.premiumExpiry()))
	// The piggy bank. `Stats.synchronize` merges `diff['piggyBank']` into
	// its cache, and the account dashboard's reserve widget reads
	// `piggyBank.credits` / `.gold` plus the two smash timestamps.
	root.Set("piggyBank", lobby.NewDict().
		Set("credits", lobby.NewInt(econ.piggyCredits())).
		Set("gold", lobby.NewInt(econ.piggyGold())).
		Set("lastSmashTimestamp", lobby.NewInt(0)).
		Set("lastSmashTimestampGold", lobby.NewInt(0)))
	return root, nil
}

// BuildStreamElements frames one RES_STREAM payload as the two elements the
// client's resource layer needs, in order: a RESOURCE_HEADER (0x45) that
// registers the stream, then a RESOURCE_FRAGMENT (0x46) carrying the data.
//
// The header is not optional. The client keeps a table of in-flight
// resources keyed by id, and a fragment whose id has no header is dropped
// on the floor — no error, no log, nothing. That is exactly how the hangar
// stalled on "Synchronisation du fichier personnel": the dossier answer
// (RES_STREAM for request 223) was followed by a bare fragment, so
// `Account.onStreamComplete` was never called, `DossierCache.__isSynchronizing`
// stayed true, and `DossierRequester` parked forever.
//
// Wire, both elements (client element ids from the exe's own table:
// RESOURCE_HEADER = 0x45, RESOURCE_FRAGMENT = 0x46, both Variable16):
//
//	[45][u16 bodyLen][u16 streamID][packed-u24 descLen][desc]
//	[46][u16 bodyLen][u16 streamID][u8 sequenceNum][u8 last][data]
//
// `desc` is a pickled `(len(data), crc32(data))` — the client unpickles it
// and builds the `(isCorrupted, origPacketLen, packetLen, origCrc32, crc32)`
// tuple `Account.onStreamComplete` unpacks, checking the data against the
// CRC. `len` and the CRC are over the COMPRESSED bytes, and the CRC is
// signed the way Python 2's `zlib.crc32` returns it. `packed-u24` is one
// byte below 255, else 0xFF followed by a u24.
//
// `data` is the zlib-compressed pickle the SyncController decompresses.
func BuildStreamElements(streamID uint16, payload *lobby.FNode) ([][]byte, error) {
	raw, err := lobby.EncodeDocument(payload)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: stream payload: %w", err)
	}
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("wotlogin: stream zlib: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("wotlogin: stream zlib: %w", err)
	}
	data := zbuf.Bytes()

	desc, err := lobby.EncodeDocument(lobby.NewTuple(
		lobby.NewInt(int64(len(data))),
		lobby.NewInt(int64(int32(crc32.ChecksumIEEE(data)))),
	))
	if err != nil {
		return nil, fmt.Errorf("wotlogin: stream description: %w", err)
	}

	header := binary.LittleEndian.AppendUint16(nil, streamID)
	header = appendPackedU24(header, len(desc))
	header = append(header, desc...)

	// The payload is chunked, not sent whole. Each element rides its own
	// datagram, and the channel MTU is 1300 B, so a single fragment
	// carrying a multi-kilobyte account cache is simply lost — the client
	// then sits on the sync forever with no error on either side. The
	// sequence number is one byte, so 256 fragments is the ceiling; at
	// streamFragmentSize that is 256 KB, far past any account document.
	chunks := make([][]byte, 0, (len(data)+streamFragmentSize-1)/streamFragmentSize)
	for lo := 0; lo < len(data); lo += streamFragmentSize {
		hi := lo + streamFragmentSize
		if hi > len(data) {
			hi = len(data)
		}
		chunks = append(chunks, data[lo:hi])
	}
	if len(chunks) == 0 {
		chunks = append(chunks, nil)
	}
	if len(chunks) > 256 {
		return nil, fmt.Errorf("wotlogin: stream is %d B, more than 256 fragments of %d B", len(data), streamFragmentSize)
	}

	out := make([][]byte, 0, 1+len(chunks))
	hdr, err := appendElement(nil, 0x45, 2, header)
	if err != nil {
		return nil, err
	}
	out = append(out, hdr)
	for i, chunk := range chunks {
		body := binary.LittleEndian.AppendUint16(nil, streamID)
		body = append(body, byte(i), boolByte(i == len(chunks)-1))
		body = append(body, chunk...)
		el, err := appendElement(nil, 0x46, 2, body)
		if err != nil {
			return nil, err
		}
		out = append(out, el)
	}
	return out, nil
}

// streamFragmentSize is the resource fragment payload. The element adds 7
// bytes of its own (id, u16 length, u16 stream id, sequence, last) and the
// frame adds the tick head, the channel flags and the 8-byte trailer, so
// this keeps a fragment inside the 1300-byte channel MTU.
const streamFragmentSize = 1000

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// appendElement frames one element as [id][length][body], the length field
// being `width` bytes wide (the method's VariableLengthHeaderSize).
//
// A body that does not FIT the field is not truncated and not written as a
// plain all-ones field: all-ones IS the escape. The client's own writer
// (InterfaceElement::compressLength) fills the field with ones, replaces the
// body's FIRST FOUR BYTES with the full u32 length, and moves those four
// displaced bytes to the END of the element; the reader reverses it. So:
//
//	[id][FF…][u32 len LE][body[4:]][body[:4]]
//
// Writing `[id][FF][body]` for a 255-byte body makes the client read the
// next four bytes as the length, over-read the bundle and die on
// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_` — which is exactly what
// happened once the account full sync grew past 254 bytes: the client
// crashed right after SHOW GUI and the hangar showed "-" for every resource,
// because the sync that carries them never parsed.
func appendElement(dst []byte, id byte, width int, body []byte) ([]byte, error) {
	if width < 1 || width > 4 {
		return nil, fmt.Errorf("wotlogin: element %#02x length width %d", id, width)
	}
	escape := uint64(1)<<(8*width) - 1
	if uint64(len(body)) < escape {
		dst = append(dst, id)
		for i := 0; i < width; i++ {
			dst = append(dst, byte(uint64(len(body))>>(8*i)))
		}
		return append(dst, body...), nil
	}
	if len(body) < 4 {
		return nil, fmt.Errorf("wotlogin: element %#02x body is %d B, too short for the oversized length", id, len(body))
	}
	dst = append(dst, id)
	for i := 0; i < width; i++ {
		dst = append(dst, 0xFF)
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(body)))
	dst = append(dst, body[4:]...)
	return append(dst, body[:4]...), nil
}

// appendPackedU24 writes a length the way the client's blob reader wants it:
// one byte below 255, else 0xFF and a little-endian u24.
func appendPackedU24(dst []byte, n int) []byte {
	if n < 255 {
		return append(dst, byte(n))
	}
	return append(dst, 0xFF, byte(n), byte(n>>8), byte(n>>16))
}

// BuildCommandResponse frames one 1a/5f command answer.
//
// Wire (genuine, flows3-s2 `1a 5f 24 e0 00 00 00 00 1e <30B>`):
//
//	[1a] selectPlayerEntity (FIXED 0)
//	[5f] the command-response client method (entityMethodBase 0x4E + 17)
//	[u8  elementLen]  6 + len(ext)
//	[u16 requestID]
//	[u16 resultID]    AccountCommands: 0 RES_SUCCESS, 1 RES_STREAM, 2 RES_CACHE
//	[u8  errorLen]    always 0 here
//	[u8  extLen]
//	[ext]             the pickle the client's SyncController hands on
//
// The two length bytes are the trap: there is an error-string length AND
// an ext length. Writing a single length byte shifts the ext by one, the
// client reads a garbage ext length out of the pickle's PROTO opcode, and
// the sync never completes — the hangar stalls on "personal file
// synchronisation" with no error, because SyncController keeps the
// request in __syncRequests and waitForSync never re-sends.
func BuildCommandResponse(reqID uint16, resultID uint16, ext *lobby.FNode) ([]byte, error) {
	return BuildCommandResponseErr(reqID, resultID, "", ext)
}

// BuildCommandResponseErr is BuildCommandResponse with the error string
// the client shows when resultID is negative. The string is a plain u8
// length, not a packed one — the two length bytes in this element are
// the error string's and the ext's, and only the ext's is packed.
func BuildCommandResponseErr(reqID uint16, resultID uint16, errStr string, ext *lobby.FNode) ([]byte, error) {
	pickle, err := lobby.EncodeDocument(ext)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: command response: %w", err)
	}
	if len(errStr) > 65535 {
		errStr = errStr[:65535]
	}
	body := binary.LittleEndian.AppendUint16(nil, reqID)
	body = binary.LittleEndian.AppendUint16(body, resultID)
	// The error string is a STRING argument like the ext, so its length
	// is the same packed-u24 form (one byte below 255, else 0xFF + u24).
	body = appendPackedU24(body, len(errStr))
	body = append(body, errStr...)
	// The ext is a STRING argument, so its length is a packed-u24 blob
	// length (one byte below 255, else 0xFF and a u24) — not a plain byte.
	body = appendPackedU24(body, len(pickle))
	body = append(body, pickle...)
	// `1a` is selectPlayerEntity (FIXED 0, no length field); the method
	// element that follows carries the length, one byte wide here
	// (onCmdResponseExt's VariableLengthHeaderSize is 1).
	return appendElement([]byte{0x1a}, smallRevisions, 1, body)
}

// ParseCommandResponse is the inverse of BuildCommandResponse: it reads one
// `1a/5f` element and returns its fields. The ext length is a packed-u24
// blob length, so it is one byte below 255 and four above — a reader that
// assumes one byte mis-slices every answer whose ext grew past 254.
func ParseCommandResponse(el []byte) (reqID, resultID uint16, errStr string, ext []byte, err error) {
	if len(el) < 2 || el[0] != 0x1a || el[1] != smallRevisions {
		return 0, 0, "", nil, fmt.Errorf("wotlogin: not a 1a/5f element")
	}
	body, _, err := lobby.ParseSmall(el)
	if err != nil {
		return 0, 0, "", nil, err
	}
	if len(body.Body) < 6 {
		return 0, 0, "", nil, fmt.Errorf("wotlogin: command response body is %d B", len(body.Body))
	}
	b := body.Body
	reqID = binary.LittleEndian.Uint16(b[0:2])
	resultID = binary.LittleEndian.Uint16(b[2:4])
	errLen := int(b[4])
	if len(b) < 5+errLen+1 {
		return 0, 0, "", nil, fmt.Errorf("wotlogin: command response error string is %d B", errLen)
	}
	errStr = string(b[5 : 5+errLen])
	at := 5 + errLen
	extLen := int(b[at])
	at++
	if extLen == 0xFF {
		if len(b) < at+3 {
			return 0, 0, "", nil, fmt.Errorf("wotlogin: truncated ext length")
		}
		extLen = int(b[at]) | int(b[at+1])<<8 | int(b[at+2])<<16
		at += 3
	}
	if len(b) < at+extLen {
		return 0, 0, "", nil, fmt.Errorf("wotlogin: ext is %d B, body has %d", extLen, len(b)-at)
	}
	return reqID, resultID, errStr, b[at : at+extLen], nil
}

// buildSyncAnswer frames one 1a/5f answer: [req u32][status 0][len][pickle].
func buildSyncAnswer(reqID uint32, root *lobby.FNode) ([]byte, error) {
	return BuildCommandResponse(uint16(reqID), 0, root)
}

// anyNode converts a plain Go value into a pickle node, for the inventory
// entries the application layer hands over.
func anyNode(v any) (*lobby.FNode, error) {
	switch x := v.(type) {
	case nil:
		return lobby.NewNone(), nil
	case bool:
		return lobby.NewBool(x), nil
	case string:
		return lobby.NewString(x), nil
	case int:
		return lobby.NewInt(int64(x)), nil
	case int64:
		return lobby.NewInt(x), nil
	case float64:
		return lobby.NewFloat(x), nil
	case []any:
		list := lobby.NewList()
		for _, item := range x {
			n, err := anyNode(item)
			if err != nil {
				return nil, err
			}
			list.Append(n)
		}
		return list, nil
	case map[string]any:
		dict := lobby.NewDict()
		for k, item := range x {
			n, err := anyNode(item)
			if err != nil {
				return nil, err
			}
			dict.Set(k, n)
		}
		return dict, nil
	case map[int64]any:
		// Integer-keyed dicts: the inventory's compDescr/postProgression
		// are keyed by instance id and vehicle type id.
		dict := lobby.NewDict()
		for k, item := range x {
			n, err := anyNode(item)
			if err != nil {
				return nil, err
			}
			dict.SetNode(lobby.NewInt(k), n)
		}
		return dict, nil
	case *lobby.FNode:
		// A caller-built node, for the shapes anyNode cannot infer (a dict
		// keyed by a tuple, say).
		return x, nil
	case []int64:
		// A crew list: one tankman instance id per slot, 0 for an empty
		// slot. The client replaces the whole list on a diff, so the
		// order is the slot order.
		list := lobby.NewList()
		for _, item := range x {
			list.Append(lobby.NewInt(item))
		}
		return list, nil
	case []byte:
		// A compact descriptor is a py2 str (bytes), not text.
		return lobby.NewString(string(x)), nil
	}
	return nil, fmt.Errorf("unsupported value %T", v)
}

// BuildServerStatsAnswer mints the 1a/5b answer to a
// CMD_REQ_SERVER_STATS poll: two u32 counters, no length byte.
func BuildServerStatsAnswer(a, b uint32) ([]byte, error) {
	body := binary.LittleEndian.AppendUint32(nil, a)
	body = binary.LittleEndian.AppendUint32(body, b)
	return lobby.Small{Family: 0x1a, Type: smallStats, Body: body}.Encode()
}

// BuildCommandError mints the 1a/5e answer to a command the server
// refuses: the request id it echoes, a status byte, and two pad bytes
// (the small's body is five bytes: `1a 5e 05` + req u16 + status + 00 00).
func BuildCommandError(reqID uint16, status uint8) ([]byte, error) {
	body := binary.LittleEndian.AppendUint16(nil, reqID)
	body = append(body, status, 0, 0)
	return lobby.Small{Family: 0x1a, Type: smallError, Body: body}.Encode()
}

// BuildQueueCensus mints the 1a/67 answer to a CMD_REQ_QUEUE_INFO poll:
// the player count and the per-vehicle-class breakdown.
func BuildQueueCensus(players int64, classes []int64) ([]byte, error) {
	cls := lobby.NewTuple()
	for _, c := range classes {
		cls.Append(lobby.NewInt(c))
	}
	root := lobby.NewDict().
		Set("players", lobby.NewInt(players)).
		Set("classes", cls)
	pickle, err := lobby.EncodeDocument(root)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: queue census: %w", err)
	}
	if len(pickle) > 0xFF {
		return nil, fmt.Errorf("wotlogin: queue census pickle is %d B, beyond the u8 length", len(pickle))
	}
	body := append([]byte{byte(len(pickle))}, pickle...)
	return lobby.Small{Family: 0x1a, Type: smallQueueInfo, Body: body}.Encode()
}

// InfoApp is the pre-flood "info" app: updateFrequencyNotification plus a
// tickSync. The 2.4.0 flow sends it as its own seq-1 frame; the 2.4.1 flow
// folds the same two elements into the flood chain's first fragment.
func InfoApp(frequency uint8, gameTime uint32, tag byte) []byte {
	app := []byte{0x02, frequency}
	app = binary.LittleEndian.AppendUint16(app, 1)
	app = binary.LittleEndian.AppendUint32(app, gameTime)
	return append(app, 0x13, tag)
}

// BuildShopAnswer mints the 1a/5f answer to the client's CMD_SYNC_SHOP: the
// shop's item price table.
//
// `Shop.__onSyncDataReceived` does `data['sellPriceFactor']` unconditionally,
// so that key must be present even though nothing reads its value here.
// `items.itemPrices` is `{intCD: (credits, gold)}` and is what
// `vehicle_items_getter.getItemsIterator` walks — the tech tree's vehicle
// list AND every `getVehicles()` call without REQ_CRITERIA.INVENTORY, which
// is the hangar carousel's own filter. An empty table is why the carousel
// resolved to zero vehicles while the inventory held 1256.
func BuildShopAnswer(reqID uint16, prices map[int64]map[string]int64) ([]byte, error) {
	root, err := ShopDoc(prices)
	if err != nil {
		return nil, err
	}
	return BuildCommandResponse(reqID, 0, root)
}

// ShopDoc is the shop document itself, without the 1a/5f framing. Like the
// account sync it is answered as a RESOURCE STREAM: the price table for a
// garage of every ownable vehicle is ~63 KB of pickle, far past the
// 1223-byte bundle payload, and an inline element that size is simply lost.
func ShopDoc(prices map[int64]map[string]int64) (*lobby.FNode, error) {
	return lobby.NewDict().
		Set("sellPriceFactor", lobby.NewFloat(1)).
		// The exchange rates. `Shop.getSellPrice` reads
		// `self.__cache['crystalExchangeRate']` DIRECTLY (not through the
		// requester's defaults) whenever the buy price carries a `crystal`
		// entry, so a shop document without it raises KeyError the moment
		// any crystal-priced item is built — which is every deluxe optional
		// device, and that raise aborts the hangar's crew and loadout
		// presenters. The values are the client's own defaults
		// (`DefaultShopRequester`): 400 credits per gold, 200 per crystal.
		Set("exchangeRate", lobby.NewInt(ExchangeRate)).
		Set("exchangeRateForShellsAndEqs", lobby.NewInt(ExchangeRate)).
		Set("crystalExchangeRate", lobby.NewInt(CrystalExchangeRate)).
		// The purchase tables. `Stats.exchange` / `convertToFreeXP` /
		// `upgradeToPremium` read these through the RAW `Shop` object
		// (`self.__account.shop.getPremiumCost(...)`), not through the
		// requester that carries the client's defaults — so an absent key
		// is `None`, and the flow aborts with "Result of the getPremiumCost
		// request is None" before it ever sends the command.
		Set("premiumCost", PremiumCostNode()).
		Set("slotsPrices", SlotsPricesNode()).
		Set("berthsPrices", BerthsPricesNode()).
		Set("freeXPConversion", lobby.NewTuple(
			lobby.NewInt(FreeXPPerGold), lobby.NewInt(1))).
		// `sellPriceModif` is the fraction of the buy price a sale returns
		// (`Shop.getSellPrice` multiplies by it). The client's own default
		// is 0.5; the old document carried a `sellPriceFactor` key, which
		// nothing reads.
		Set("sellPriceModif", lobby.NewFloat(SellPriceModif)).
		Set("clanCreationCost", lobby.NewInt(ClanCreationCost)).
		// The rest of the document: the ladders and option tables the
		// client's dialogs read straight out of the shop cache. Every key
		// here is one a dialog indexes without a default, so an absent one
		// is an IndexError or a KeyError in the middle of a window.
		Set("tankmanCost", TankmanCostNode()).
		Set("tankman", TankmanOptionsNode()).
		Set("changeRoleCost", lobby.NewInt(ChangeRoleCost)).
		Set("dropSkillsCost", DropSkillsCostNode()).
		Set("freeXPToTManXPRate", lobby.NewInt(FreeXPToTankmanXPRate)).
		Set("dailyXPFactor", lobby.NewInt(DailyXPFactor)).
		Set("winXPFactorMode", lobby.NewInt(0)).
		Set("restore_config", RestoreConfigNode()).
		Set("camouflageCost", CamouflageCostNode()).
		Set("playerEmblemCost", PlayerEmblemCostNode()).
		Set("playerInscriptionCost", PlayerInscriptionCostNode()).
		Set("paidRemovalCost", lobby.NewDict().Set("gold", lobby.NewInt(10))).
		Set("paidDeluxeRemovalCost", lobby.NewDict().Set("crystal", lobby.NewInt(200))).
		Set("paidModernized1RemovalCost", lobby.NewDict().Set("gold", lobby.NewInt(10))).
		Set("paidModernized2RemovalCost", lobby.NewDict().Set("equipCoin", lobby.NewInt(50))).
		Set("paidModernized3RemovalCost", lobby.NewDict().Set("equipCoin", lobby.NewInt(100))).
		Set("paidTrophyBasicRemovalCost", lobby.NewDict().Set("gold", lobby.NewInt(10))).
		Set("paidTrophyUpgradedRemovalCost", lobby.NewDict().Set("gold", lobby.NewInt(10))).
		Set("customRoleSlotChangeCost", CustomRoleSlotChangeCostNode()).
		Set("battlePassLevelCost", lobby.NewDict().Set("gold", lobby.NewInt(250))).
		Set("isEnabledBuyingGoldEqsForCredits", lobby.NewBool(true)).
		Set("isEnabledBuyingGoldShellsForCredits", lobby.NewBool(true)).
		Set("defaults", lobby.NewDict().
			Set("goodies", lobby.NewDict().Set("prices", lobby.NewDict())).
			Set("items", lobby.NewDict())).
		Set("goodies", lobby.NewDict().
			Set("goodies", RecertificationFormsNode()).
			Set("notInShop", lobby.NewList()).
			Set("prices", lobby.NewDict())).
		Set("specialPrices", lobby.NewDict()).
		Set("spgRedesignFeatures", lobby.NewDict().
			Set("markTargetAreaEnabled", lobby.NewBool(true)).
			Set("stunEnabled", lobby.NewBool(true))).
		Set("items", ShopItemsNode(prices)), nil
}

// RecertificationFormsNode is `shop.goodies.goodies`: the one goodie the
// client's own listeners index without a guard.
//
// `RecertificationFormStateListener._getState` (notification/listeners.py) does
// `goodiesCache.getRecertificationForm(currency='credits').enabled`, and
// `getRecertificationForm` returns None when the shop holds no
// `GOODIE_VARIETY.RECERTIFICATION_FORM` (3) with a credits resource (20). The
// listener is started by `NotificationsModel.setup` on every hangar load, so
// an empty table raises
//
//	AttributeError: 'NoneType' object has no attribute 'enabled'
//
// into the log each time. The form is DISABLED (`enabled` false), which is
// what `_getState` needs to report DISABLED and skip the popup.
//
// The tuple is the client's `loadDefinitions` / `_NamedGoodieData` order:
// variety, target, enabled, lifetime, useby, limit, autostart, condition,
// resource, expireAfter, roundToEndOfGameDay.
func RecertificationFormsNode() *lobby.FNode {
	return lobby.NewDict().SetNode(lobby.NewInt(1), lobby.NewTuple(
		lobby.NewInt(3),      // GOODIE_VARIETY.RECERTIFICATION_FORM
		lobby.NewNone(),      // target
		lobby.NewBool(false), // enabled
		lobby.NewInt(0),      // lifetime
		lobby.NewInt(0),      // useby
		lobby.NewInt(0),      // limit
		lobby.NewBool(false), // autostart
		lobby.NewNone(),      // condition
		// resource: (GOODIE_RESOURCE_TYPE.CREDITS, value, isPercentage)
		lobby.NewTuple(lobby.NewInt(20), lobby.NewInt(0), lobby.NewBool(false)),
		lobby.NewNone(),     // expireAfter
		lobby.NewBool(true), // roundToEndOfGameDay
	))
}

// TankmanCostNode is `shop.tankmanCost`: one entry per recruit tier, read
// as `Money(**entry)` by `processors/tankman.pyc _getRecruitPrice`. The
// recruit dialog indexes entry 0 unconditionally, so an empty tuple is an
// IndexError the moment the window opens. `Money.__init__` takes
// `**kwargs`, so the non-currency keys ride along harmlessly.
func TankmanCostNode() *lobby.FNode {
	tier := func(roleLoss, credits, gold float64, premium bool, roleLevel int64) *lobby.FNode {
		return lobby.NewDict().
			Set("baseRoleLoss", lobby.NewFloat(roleLoss)).
			Set("classChangeRoleLoss", lobby.NewFloat(roleLoss)).
			Set("credits", lobby.NewInt(int64(credits))).
			Set("gold", lobby.NewInt(int64(gold))).
			Set("isPremium", lobby.NewBool(premium)).
			Set("roleLevel", lobby.NewInt(roleLevel))
	}
	return lobby.NewTuple(
		tier(0.2, 0, 0, false, 50),
		tier(0.1, 20000, 0, false, 75),
		tier(0.0, 0, 200, true, 100),
	)
}

// TankmanOptionsNode is `shop.tankman`: the recruit and retrain option
// tables. `recruit.options` is indexed by the recruit dialog's cost type,
// and `retrain.options` by the retrain dialog's.
func TankmanOptionsNode() *lobby.FNode {
	recruit := lobby.NewTuple(lobby.NewDict().
		Set("credits", lobby.NewInt(0)).
		Set("gold", lobby.NewInt(0)).
		Set("xp", lobby.NewInt(0)))
	retrain := func(efficiency, withRoleChange float64, discounts *lobby.FNode) *lobby.FNode {
		return lobby.NewDict().
			Set("discounts", discounts).
			Set("skillsEfficiency", lobby.NewFloat(efficiency)).
			Set("skillsEfficiencyWithRoleChange", lobby.NewFloat(withRoleChange))
	}
	perks := func() *lobby.FNode {
		return lobby.NewDict().
			Set("perk_0", lobby.NewFloat(0)).
			Set("perk_1", lobby.NewFloat(0.5))
	}
	return lobby.NewDict().
		Set("recruit", lobby.NewDict().Set("options", recruit)).
		Set("retrain", lobby.NewDict().Set("options", lobby.NewTuple(
			retrain(0.3, -1.0, lobby.NewDict()),
			retrain(0.6, 0.4, perks()),
			retrain(1.0, 1.0, perks()),
		)))
}

// DropSkillsCostNode is `shop.dropSkillsCost`: the five ways to reset a
// crew member's skills, indexed by the dialog's option.
func DropSkillsCostNode() *lobby.FNode {
	entry := func(credits, gold, form int64, reuse float64) *lobby.FNode {
		return lobby.NewDict().
			Set("credits", lobby.NewInt(credits)).
			Set("gold", lobby.NewInt(gold)).
			Set("recertificationForm", lobby.NewInt(form)).
			Set("xpReuseFraction", lobby.NewFloat(reuse))
	}
	d := lobby.NewDict()
	d.SetNode(lobby.NewInt(0), entry(0, 0, 0, 0.8))
	d.SetNode(lobby.NewInt(1), entry(20000, 0, 0, 0.9))
	d.SetNode(lobby.NewInt(2), entry(0, 200, 0, 1.0))
	d.SetNode(lobby.NewInt(3), entry(0, 0, 1, 1.0))
	d.SetNode(lobby.NewInt(4), entry(100000, 0, 0, 1.0))
	return d
}

// RestoreConfigNode is `shop.restore_config`: the price and window of
// restoring a dismissed crew member or a sold vehicle.
func RestoreConfigNode() *lobby.FNode {
	return lobby.NewDict().
		Set("tankmen", lobby.NewDict().
			Set("creditsCost", lobby.NewInt(60000)).
			Set("creditsDuration", lobby.NewInt(2764800)).
			Set("freeDuration", lobby.NewInt(172800)).
			Set("goldCost", lobby.NewInt(20)).
			Set("goldDuration", lobby.NewInt(2764800)).
			Set("limit", lobby.NewInt(100))).
		Set("vehicles", lobby.NewDict().
			Set("actionCooldown", lobby.NewInt(259200)).
			Set("premiumDuration", lobby.NewInt(259200)).
			Set("sellToRestoreFactor", lobby.NewFloat(1.1)))
}

// CamouflageCostNode is `shop.camouflageCost`: `{days: (gold, credits)}`.
func CamouflageCostNode() *lobby.FNode {
	d := lobby.NewDict()
	for _, e := range []struct{ days, gold, credits int64 }{
		{0, 250, 1}, {7, 25000, 0}, {30, 100000, 0},
	} {
		d.SetNode(lobby.NewInt(e.days), lobby.NewTuple(
			lobby.NewInt(e.gold), lobby.NewInt(e.credits)))
	}
	return d
}

// PlayerEmblemCostNode is `shop.playerEmblemCost`: `{days: (gold, credits)}`.
func PlayerEmblemCostNode() *lobby.FNode {
	d := lobby.NewDict()
	for _, e := range []struct{ days, gold, credits int64 }{
		{0, 15, 1}, {7, 1500, 0}, {30, 6000, 0},
	} {
		d.SetNode(lobby.NewInt(e.days), lobby.NewTuple(
			lobby.NewInt(e.gold), lobby.NewInt(e.credits)))
	}
	return d
}

// PlayerInscriptionCostNode is `shop.playerInscriptionCost`: the same
// ladder as the emblem, plus a per-nation override table.
func PlayerInscriptionCostNode() *lobby.FNode {
	d := PlayerEmblemCostNode()
	d.Set("nations", lobby.NewDict())
	return d
}

// CustomRoleSlotChangeCostNode is `shop.customRoleSlotChangeCost`: the
// credit price of changing a role slot, by slot type id.
func CustomRoleSlotChangeCostNode() *lobby.FNode {
	d := lobby.NewDict()
	for i, credits := range []int64{10000, 25000, 50000, 100000, 150000, 200000} {
		d.SetNode(lobby.NewInt(int64(6+i)),
			lobby.NewDict().Set("credits", lobby.NewInt(credits)))
	}
	return d
}

// ShopItemsNode is `shop.items`: the price table plus the "not for sale"
// sets the client filters its lists with. The sets are empty lists — the
// client only tests membership and iterates them.
func ShopItemsNode(prices map[int64]map[string]int64) *lobby.FNode {
	perNation := func() *lobby.FNode {
		d := lobby.NewDict()
		for i := int64(0); i < 8; i++ {
			d.SetNode(lobby.NewInt(i), lobby.NewList())
		}
		return d
	}
	return lobby.NewDict().
		Set("itemPrices", lobby.ItemsPricesNode(prices)).
		Set("notInShopItems", lobby.NewList()).
		Set("vehiclesNotToBuy", lobby.NewList()).
		Set("vehiclesToSellForGold", lobby.NewList()).
		Set("notInShopCamouflages", perNation()).
		Set("notInShopInscriptionGroups", perNation()).
		Set("notInShopPlayerEmblemGroups", lobby.NewList()).
		Set("notInShopProgressionLvlItems", lobby.NewDict()).
		Set("operationPrices", lobby.NewDict()).
		Set("playerEmblemGroupPriceFactors", lobby.NewDict()).
		Set("progressionLvlPrices", lobby.NewDict()).
		Set("vehicleCamouflagePriceFactors", lobby.NewDict()).
		Set("vehicleSellPriceFactors", lobby.NewDict()).
		Set("vehiclesRentPrices", lobby.NewDict()).
		Set("camouflagePriceFactors", perNation()).
		Set("inscriptionGroupPriceFactors", perNation())
}

// The economy constants the shop document and the purchase handlers share.
//
// They are the client's own defaults where it has one
// (`gui/shared/utils/requesters/ShopRequester.pyc`: 400 credits per gold,
// 200 per crystal, 0.5 sell modifier, 25 free XP per gold, 2500 gold to
// found a clan) and the live server's ladder where it does not.
const (
	// ExchangeRate is credits per gold (`shop.exchangeRate`).
	ExchangeRate = 400
	// CrystalExchangeRate is credits per bond (`shop.crystalExchangeRate`).
	CrystalExchangeRate = 200
	// SellPriceModif is the fraction of the buy price a sale returns.
	SellPriceModif = 0.5
	// FreeXPPerGold is free XP bought per gold (`shop.freeXPConversion`).
	FreeXPPerGold = 25
	// ClanCreationCost is the gold price of founding a clan.
	ClanCreationCost = 2500
	// BerthPackSize is how many barracks berths one pack buys.
	BerthPackSize = 1
	// BerthPackGold is the gold price of one berth pack.
	BerthPackGold = 300
	// SlotCredits is the credit price of one garage slot.
	SlotCredits = 300
	// ChangeRoleCost is the gold price of changing a crew member's role.
	// The live server charges nothing for it.
	ChangeRoleCost = 0
	// FreeXPToTankmanXPRate is how much crew XP one free XP buys.
	FreeXPToTankmanXPRate = 5
	// DailyXPFactor is the multiplier on the first win of the day.
	DailyXPFactor = 2
)

// PremiumCostNode is `shop.premiumCost`: {days: gold}. The client's
// default is an EMPTY dict, so without this the premium window has no
// option to buy at all.
func PremiumCostNode() *lobby.FNode {
	days := []int64{1, 3, 7, 30, 90, 180, 360}
	gold := []int64{250, 650, 1250, 2500, 6500, 11000, 20000}
	d := lobby.NewDict()
	for i, n := range days {
		d.SetNode(lobby.NewInt(n), lobby.NewInt(gold[i]))
	}
	return d
}

// SlotsPricesNode is `shop.slotsPrices`: `(baseSlots, [[currency, amount]])`.
// `items/item_price.getNextSlotPrice` indexes the list by
// `slots - baseSlots` and falls back to the last entry, so a ladder that
// runs out is still priced.
func SlotsPricesNode() *lobby.FNode {
	ladder := lobby.NewList()
	for _, amount := range []int64{300, 600, 1200, 2400, 4800} {
		ladder.Append(lobby.NewList(
			lobby.NewString("credits"), lobby.NewInt(amount)))
	}
	return lobby.NewTuple(lobby.NewInt(0), ladder)
}

// BerthsPricesNode is `shop.berthsPrices`: `(baseBerths, packSize,
// [gold])`. `getNextBerthPackPrice` divides by the pack size and falls
// back to the last entry.
func BerthsPricesNode() *lobby.FNode {
	ladder := lobby.NewList()
	for _, amount := range []int64{300, 600, 1200, 2400} {
		ladder.Append(lobby.NewInt(amount))
	}
	return lobby.NewTuple(
		lobby.NewInt(0), lobby.NewInt(BerthPackSize), ladder)
}
