package server

import (
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestSettingsDocumentLoads pins the committed lobby settings document:
// it must parse, pickle, and decode back to the same keys. The document
// is generated from the client's own schemas by
// ../tools/gen_server_settings.py.
func TestSettingsDocumentLoads(t *testing.T) {
	const path = "../wotserver.settings.json"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no settings document (%v)", err)
	}
	raw, err := SettingsFromJSON(path)
	if err != nil {
		t.Fatalf("SettingsFromJSON: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("empty pickle")
	}
	// The pickle must decode to one dict with the document's keys.
	stk, _, err := lobby.DecodePrefix(raw)
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	d, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("stack top %T, want *PDict", stk[len(stk)-1])
	}
	if len(d.Entries) < 30 {
		t.Fatalf("%d keys, want the generated document", len(d.Entries))
	}
	// The keys the client reads through the schema manager must be
	// present, or its app_loader aborts before the hangar.
	for _, k := range []string{
		"prefab_effects_availability_config",
		"story_mode_settings",
		"regional_settings",
		"spgRedesignFeatures",
		"shop",
		"epic_config",
		// `Achievements20GeneralConfig.getRequiredCountOfBattles` is
		// `self._config.get('requiredCountOfBattles')` with NO default, and
		// `notifications_utils._NotificationNewSummaryPage.req` subtracts it
		// from an int on every lobby tick. Absent, it returns None and the
		// client throws `TypeError: unsupported operand type(s) for -:
		// 'NoneType' and 'int'` about three times a second, which locks the
		// hangar up.
		"achievements20_config",
		// `battle_royale_controller.__getTournamentBannerAvailability` does
		// `getModeSettings().tournamentsWidget['isWidgetEnabled']`, and
		// BattleRoyaleConfig's own default for `tournamentsWidget` is `{}`.
		"battle_royale_config",
		// `epic_meta_game_ctrl.__setData` does
		// `self.__metaSettings.metaLevel.get('maxLevel', 0)`, and
		// _EpicMetaGameConfig's own default for `metaLevel` is the TUPLE
		// `(0, False)` — the one tuple default in the whole settings module.
		"epic_config",
		// `_IngameTournamentConfig._preprocessData` only converts a
		// tournament type to a namedtuple when its key is PRESENT; otherwise
		// it stores a plain dict and `getCurrentShowmatch` does
		// `config.isEnabled` on it.
		"ingame_tournament_config",
		"personal_reserves_config",
	} {
		found := false
		for _, e := range d.Entries {
			if e.Key == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("settings document lacks %q", k)
		}
	}
	t.Logf("%d keys, %d B pickle", len(d.Entries), len(raw))
}

// TestSettingsSubsetFitsOnePacket pins the subset that rides the Account entity
// when it is re-created after a battle. The full document is ~4.5 KB and the
// bundle payload is ~1.2 KB, so sending it whole is not an option; the subset
// has to carry the keys the client's schema manager requires and still fit.
func TestSettingsSubsetFitsOnePacket(t *testing.T) {
	const path = "../wotserver.settings.json"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no settings document (%v)", err)
	}
	keys := []string{
		"prefab_effects_availability_config", "story_mode_settings",
		"regional_settings", "spgRedesignFeatures", "shop", "epic_config",
		"dog_tags_config",
	}
	raw, err := SettingsSubsetFromJSON(path, keys)
	if err != nil {
		t.Fatalf("SettingsSubsetFromJSON: %v", err)
	}
	if len(raw) > 1100 {
		t.Fatalf("subset is %d B, too big for one bundle payload", len(raw))
	}
	stk, _, err := lobby.DecodePrefix(raw)
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	d, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("stack top %T, want *PDict", stk[len(stk)-1])
	}
	have := map[any]bool{}
	for _, e := range d.Entries {
		have[e.Key] = true
	}
	for _, k := range keys {
		if !have[k] {
			t.Errorf("subset lacks %q", k)
		}
	}
}
