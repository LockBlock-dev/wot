package login

import (
	"testing"
	"time"
)

// TestRepeatBattlePeriodNeedsTheClientOnArena pins the re-send's gate: it only
// fires while the client has not shown it applied the BATTLE period, and only
// after the two-second wait.
func TestRepeatBattlePeriodNeedsTheClientOnArena(t *testing.T) {
	s := &BaseAppServer{}
	st := &clientState{battleStarted: true, battlePeriodAt: time.Now()}
	// Just sent: nothing to re-send yet.
	s.repeatBattlePeriod(nil, nil, st, 1)
	// The client proved it is on the arena: no re-send ever.
	st.clientOnArena = true
	st.battlePeriodAt = time.Now().Add(-time.Minute)
	s.repeatBattlePeriod(nil, nil, st, 1)
	if !st.clientOnArena {
		t.Fatal("the gate cleared the arena flag")
	}
	// The battle over: no re-send.
	st.clientOnArena = false
	st.battleEnded = true
	s.repeatBattlePeriod(nil, nil, st, 1)
}
