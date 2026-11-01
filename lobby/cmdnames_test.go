package lobby

import "testing"

// TestCmdName pins the shipped command table: the ids the server already
// answers, the ones a hangar exercises, and the miss case.
func TestCmdName(t *testing.T) {
	for _, c := range []struct {
		id   uint16
		want string
	}{
		{CmdSyncData, "CMD_SYNC_DATA"},
		{CmdSetActiveVehSeason, "CMD_SET_ACTIVE_VEH_SEASON"},
		{CmdSyncShop, "CMD_SYNC_SHOP"},
		{CmdReqServerStats, "CMD_REQ_SERVER_STATS"},
		{CmdSyncDossiers, "CMD_SYNC_DOSSIERS"},
		{CmdEnqueueInBattleQueue, "CMD_ENQUEUE_IN_BATTLE_QUEUE"},
		{301, "CMD_BUY_VEHICLE"},
		{304, "CMD_SELL_VEHICLE"},
		{201, "CMD_UNLOCK"},
		{0, "CMD_RESERVED"},
	} {
		if got := CmdName(c.id); got != c.want {
			t.Errorf("CmdName(%d) = %q, want %q", c.id, got, c.want)
		}
	}
	if got := CmdName(9999); got != "" {
		t.Errorf("CmdName(9999) = %q, want empty", got)
	}
	// The table is the shipped set; a drift here means the .pyc changed.
	if len(cmdNames) != 259 {
		t.Errorf("cmdNames has %d entries, want 259", len(cmdNames))
	}
}
