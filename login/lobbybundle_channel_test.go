package login

// Channel framing of lobby bundles (login side): primeBundled apps
// size exactly like the genuine wire (60/36/124B) and round-trip the
// channel footers. Builder bytes come from the lobby package.
import (
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

func TestLobbyBundleFraming(t *testing.T) {
	// Game UDP sizes from the channel math (flags + prime + calls +
	// footers, padded): poll 60B, token 36B, genuine 148B sync opener
	// (3× Int3 + chat tail).
	const nk = 0x01020304
	cases := []struct {
		name string
		bun  []byte
		udp  int
	}{
		{"poll", lobby.BuildLobbyBundle(nk, lobby.DoCmdInt3(lobby.RequestIDNoResponse, lobby.CmdReqServerStats, 0, 0, 0)), 60},
		{"token", lobby.BuildLobbyBundle(nk, lobby.BuildRequestToken(1, 1)), 36},
		{"sync1", lobby.BuildLobbyBundle(nk,
			lobby.DoCmdInt3(221, lobby.CmdSyncData, 0, 0, 0),
			lobby.DoCmdInt3(222, lobby.CmdSyncShop, 0, 0, 0),
			lobby.DoCmdInt3(223, lobby.CmdSyncDossiers, 0, 0, 0),
			lobby.BuildChatCommandFromClient(1, 22, 0, 0, 0, nil, nil)), 148},
		{"sync2b", lobby.BuildLobbyBundle(nk,
			lobby.DoCmdInt2(225, lobby.CmdSetActiveVehSeason, 0, 0),
			lobby.DoCmdInt3(226, lobby.CmdSyncDossiers, 0, 0, 0)), 84},
		{"poll68", lobby.BuildLobbyBundle(nk,
			lobby.DoCmdInt3(lobby.RequestIDNoResponse, lobby.CmdReqServerStats, 0, 0, 0),
			lobby.BuildRequestToken(2, 5)), 68},
		{"select52", lobby.BuildLobbyBundle(nk,
			lobby.DoCmdInt2(228, lobby.CmdSetActiveVehSeason, 10577, 2)), 52},
	}
	for _, c := range cases {
		pkt, err := buildChannelPacket(floodTestKey, flagsRel, c.bun, nil, 9, 0x345)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(pkt) != c.udp {
			t.Fatalf("%s = %d B, want %d", c.name, len(pkt), c.udp)
		}
		clear, err := decryptBlowfish(floodTestKey, pkt[4:])
		if err != nil {
			t.Fatalf("%s decrypt: %v", c.name, err)
		}
		if clear[0] != 0x58 || clear[1] != 0x04 {
			t.Fatalf("%s flags = %x", c.name, clear[:2])
		}
		if clear[2] != 0x02 || clear[3] != 0x04 || clear[4] != 0x03 || clear[5] != 0x02 || clear[6] != 0x01 {
			t.Fatalf("%s prime = %x", c.name, clear[2:7])
		}
		seq, cumul, ok := channelSeqs(clear)
		if !ok || seq != 9 || cumul != 0x345 {
			t.Fatalf("%s footers seq=%d cumul=%d ok=%v", c.name, seq, cumul, ok)
		}
	}
}
