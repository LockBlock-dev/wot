package login

import (
	"net"
	"time"
)

// The battle's end: one side wiped out, or the timer running out, sends the
// AFTERBATTLE period with the win status. The client's
// `Avatar.onArenaPeriodChange` then shows the end screen, and its
// `battleResults` request asks for the results document.
//
// The win status the period carries is the client's own convention: 1 for the
// player's team winning, 0 for losing (the client's `battleCtx` reads it out of
// the period's additional info and shows "victory"/"defeat").

const (
	// ArenaPeriodAfter is `ARENA_PERIOD.AFTERBATTLE`.
	ArenaPeriodAfter uint8 = 4
	// winStatusVictory and winStatusDefeat are the values the client reads.
	winStatusVictory = 1
	winStatusDefeat  = 0
)

// checkBattleEnd ends the battle when one side has nothing left, or the BATTLE
// period's length has run out. It runs once.
func (s *BaseAppServer) checkBattleEnd(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64) {
	s.mu.Lock()
	if st.battleEnded || !st.battleStarted || st.arena == nil {
		s.mu.Unlock()
		return
	}
	playerTeam := st.arena.Player.Team
	targets := append([]*botTarget(nil), st.targets...)
	playerAlive := !st.overturned
	elapsed := st.arenaTime
	s.mu.Unlock()

	alive := map[uint8]int{playerTeam: 0, playerTeam ^ 3: 0}
	if playerAlive {
		alive[playerTeam] = 1
	}
	for _, t := range targets {
		if t == nil || t.health <= 0 {
			continue
		}
		alive[t.team]++
	}
	// The battle ends when a side has none left, or when its length is up.
	wiped := alive[playerTeam] == 0 || alive[playerTeam^3] == 0
	timedOut := elapsed >= battleLength
	if !wiped && !timedOut {
		return
	}
	win := winStatusDefeat
	if alive[playerTeam] > 0 && (alive[playerTeam^3] == 0 || alive[playerTeam] > alive[playerTeam^3]) {
		win = winStatusVictory
	}
	s.mu.Lock()
	st.battleEnded = true
	avatar := st.avatar
	s.mu.Unlock()
	if avatar == nil {
		return
	}
	s.logf("arena %d: battle over (%d vs %d alive, %.0f s): win=%d",
		arenaID, alive[playerTeam], alive[playerTeam^3], elapsed, win)
	el, err := arenaPeriodUpdateFull(avatar, ArenaPeriodAfter, arenaPeriodEnd(st.tick, 0), 0, []float64{float64(win)})
	if err != nil {
		s.logf("arena %d: AFTERBATTLE: %v", arenaID, err)
		return
	}
	var app []byte
	if sel, serr := EncodeSelectEntity(avatar.ID); serr == nil {
		app = append(app, sel...)
	}
	app = append(app, el...)
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, app, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("arena %d: AFTERBATTLE send: %v", arenaID, err)
	}
}

// battleLength is how long a battle runs before the timer ends it, in seconds:
// the BATTLE period's own 1500.
const battleLength = 1500

// repeatBattlePeriod re-sends the BATTLE period until the client proves it
// applied it, every two seconds for the first half minute. The proof is a
// `vehicle_moveWith`: the client's `Avatar.moveVehicle` returns early unless
// `isOnArena`, which only the BATTLE period sets.
func (s *BaseAppServer) repeatBattlePeriod(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64) {
	s.mu.Lock()
	if !st.battleStarted || st.clientOnArena || st.battleEnded || st.arena == nil {
		s.mu.Unlock()
		return
	}
	wait := time.Since(st.battlePeriodAt)
	elapsed := time.Since(st.battlePeriodAt)
	avatar := st.avatar
	// Never run ahead of the client's cumulative ack. Re-sending the period
	// while the client is still behind pushes the server past its receive
	// window; the client then drops the EARLIEST unacknowledged packet (the
	// entry's own) as out of window, and the ack stalls on a hole the replays
	// cannot fill either.
	//
	// The measure is the resend queue's outstanding count, not
	// `postSeq - postCumul`: postCumul is the CLIENT's own reliable-out counter
	// (the value our packets carry as their cumul field), so that difference
	// grows with the client's traffic and never shrinks with its acks.
	resendKey := st.resendKey
	s.mu.Unlock()
	if s.resend.outstanding(resendKey) > 24 {
		return
	}
	if avatar == nil || wait < 2*time.Second || elapsed > 30*time.Second {
		return
	}
	// The period's own end time is the battle's length from when it started.
	el, err := arenaPeriodUpdateFull(avatar, ArenaPeriodBattle, arenaPeriodEnd(st.tick, 1500), 1500, []float64{10, 10})
	if err != nil {
		return
	}
	var app []byte
	if sel, serr := EncodeSelectEntity(avatar.ID); serr == nil {
		app = append(app, sel...)
	}
	app = append(app, el...)
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, app, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("arena %d: BATTLE period re-send: %v", arenaID, err)
		return
	}
	s.mu.Lock()
	st.battlePeriodAt = time.Now()
	s.mu.Unlock()
	s.logf("arena %d: BATTLE period re-sent — the client has not shown it applied it yet", arenaID)
}
