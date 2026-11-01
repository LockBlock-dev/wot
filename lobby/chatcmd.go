package lobby

import (
	"encoding/binary"
	"fmt"
)

// ChatCommand is one Chat.chatCommandFromClient call (A1 tag 0x98).
//
// Wire: [0x98][len u16][requestID i64][command u8][channelID i32]
// [int64Arg i64][int16Arg i16][s1 packed][s2 packed]. The sole client
// sender is ClientChat.__baseChatCommand (shipped ClientChat.pyc); the
// command is a CHAT_COMMANDS ordinal (chat_shared.pyc).
type ChatCommand struct {
	RequestID int64
	Command   uint8
	ChannelID int32
	Int64Arg  int64
	Int16Arg  int16
	S1        string
	S2        string
}

// Name returns the shipped CHAT_COMMANDS name, or "" when unknown.
func (c ChatCommand) Name() string { return ChatCommandName(c.Command) }

// ParseChatCommandFromClient decodes a chatCommandFromClient app. It
// reports false when the app is not a chat command or is truncated.
func ParseChatCommandFromClient(app []byte) (ChatCommand, bool) {
	var c ChatCommand
	if len(app) < 3 || app[0] != A1ChatCommandFromClient {
		return c, false
	}
	n := int(binary.LittleEndian.Uint16(app[1:3]))
	if n < 0 || 3+n > len(app) {
		return c, false
	}
	b := app[3 : 3+n]
	// requestID i64 + command u8 + channelID i32 + int64Arg i64 +
	// int16Arg i16 = 23 bytes before the two packed strings.
	if len(b) < 23 {
		return c, false
	}
	c.RequestID = int64(binary.LittleEndian.Uint64(b[0:8]))
	c.Command = b[8]
	c.ChannelID = int32(binary.LittleEndian.Uint32(b[9:13]))
	c.Int64Arg = int64(binary.LittleEndian.Uint64(b[13:21]))
	c.Int16Arg = int16(binary.LittleEndian.Uint16(b[21:23]))
	rest := b[23:]
	s1, rest, err := readPackedStr(rest)
	if err != nil {
		return c, false
	}
	s2, _, err := readPackedStr(rest)
	if err != nil {
		return c, false
	}
	c.S1, c.S2 = s1, s2
	return c, true
}

// readPackedStr reads a BigWorld packed-int length followed by that many
// bytes (1 byte under 255, else 0xFF + 3 LE bytes).
func readPackedStr(b []byte) (string, []byte, error) {
	if len(b) < 1 {
		return "", nil, fmt.Errorf("lobby: packed string: empty")
	}
	n := int(b[0])
	off := 1
	if b[0] == 0xff {
		if len(b) < 4 {
			return "", nil, fmt.Errorf("lobby: packed string: short long form")
		}
		n = int(b[1]) | int(b[2])<<8 | int(b[3])<<16
		off = 4
	}
	if off+n > len(b) {
		return "", nil, fmt.Errorf("lobby: packed string: %d bytes wanted, %d left", n, len(b)-off)
	}
	return string(b[off : off+n]), b[off+n:], nil
}
