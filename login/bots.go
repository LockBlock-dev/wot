package login

import (
	"math/rand"

	"github.com/LockBlock-dev/wot/lobby"
)

// The bot roster of a battle.
//
// The official server fills a battle with bots when the queue is short: they
// are ordinary vehicles, with the stock modules, the default shell and a
// default crew, driven and fired by the server. The reference's `bot.rs`
// drives one bot per `BattleOptions`; ours fills both teams.
//
// A bot is an `ArenaPlayerDoc` like a player's: the client builds its vehicle,
// its team panel entry and its scoreboard row from the same fields.

// botNames are the names a bot is given, in order; a roster longer than this
// starts reusing them with a suffix.
var botNames = []string{
	"Bot", "Bot2", "Bot3", "Bot4", "Bot5", "Bot6", "Bot7", "Bot8", "Bot9", "Bot10",
	"Bot11", "Bot12", "Bot13", "Bot14", "Bot15", "Bot16", "Bot17", "Bot18", "Bot19", "Bot20",
}

// BotRoster builds `count` bots for a battle, `allies` of them on the client's
// team: random playable tanks from the generated table, the stock modules, the
// default shell and a default crew. The player's own tank is left out so the
// teams don't mirror.
func BotRoster(count, allies int, playerTank []byte) []ArenaPlayerDoc {
	if count <= 0 {
		return nil
	}
	pool := lobby.AllOwnableVehicles
	if len(pool) == 0 {
		return nil
	}
	// The player's tank, by nation and type id, to leave it out.
	var playerNation, playerType uint8
	if len(playerTank) >= 3 {
		playerNation = playerTank[0] >> 4 & 0x0F
		playerType = playerTank[2]
	}
	bots := make([]ArenaPlayerDoc, 0, count)
	seen := map[int]bool{}
	for i := 0; i < count; i++ {
		var pick lobby.OwnableVehicle
		for tries := 0; tries < 50; tries++ {
			pick = pool[rand.Intn(len(pool))]
			if pick.Nation == playerNation && uint8(pick.TypeID) == playerType {
				continue
			}
			if seen[int(pick.Nation)<<16|int(pick.TypeID)] {
				continue
			}
			seen[int(pick.Nation)<<16|int(pick.TypeID)] = true
			break
		}
		team := uint8(2)
		if i < allies {
			team = 1
		}
		name := "Bot"
		if i < len(botNames) {
			name = botNames[i]
		} else {
			name = botNames[i%len(botNames)]
		}
		bots = append(bots, ArenaPlayerDoc{
			Name:             name,
			Team:             team,
			VehicleCompDescr: pick.CompDescr,
			CrewSize:         int(pick.CrewSize),
		})
	}
	return bots
}
