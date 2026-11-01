package lobby

import "testing"

// TestParseChatCommandFromClient uses the two genuine game vectors
// documented on BuildChatCommandFromClient: the 148B opener tail
// (1, 22, 0, 0, 0, "", "") pulls the sys-message backlog, and the 84B
// tail (2, 0, 0, 2, 0, "", "") acks chat stream 2.
func TestParseChatCommandFromClient(t *testing.T) {
	for _, c := range []struct {
		name string
		app  []byte
		want ChatCommand
	}{
		{
			name: "requestLastSysMessages",
			app:  BuildChatCommandFromClient(1, 22, 0, 0, 0, nil, nil),
			want: ChatCommand{RequestID: 1, Command: 22, ChannelID: 0, Int64Arg: 0, Int16Arg: 0},
		},
		{
			name: "initAck",
			app:  BuildChatCommandFromClient(2, 0, 0, 2, 0, nil, nil),
			want: ChatCommand{RequestID: 2, Command: 0, ChannelID: 0, Int64Arg: 2, Int16Arg: 0},
		},
	} {
		got, ok := ParseChatCommandFromClient(c.app)
		if !ok {
			t.Fatalf("%s: parse failed", c.name)
		}
		if got != c.want {
			t.Fatalf("%s: got %+v, want %+v", c.name, got, c.want)
		}
		if got.Name() == "" {
			t.Fatalf("%s: no name for ordinal %d", c.name, got.Command)
		}
	}
}

// TestChatCommandNames pins the ordinals the client actually sends.
func TestChatCommandNames(t *testing.T) {
	for ord, want := range map[uint8]string{
		0:  "initAck",
		22: "requestLastSysMessages",
		23: "chatAckInitialization",
	} {
		if got := ChatCommandName(ord); got != want {
			t.Errorf("ChatCommandName(%d) = %q, want %q", ord, got, want)
		}
	}
	if got := ChatCommandName(200); got != "" {
		t.Errorf("ChatCommandName(200) = %q, want empty", got)
	}
	if len(chatCommandNames) != 48 {
		t.Errorf("chatCommandNames has %d entries, want 48", len(chatCommandNames))
	}
}

// TestParseChatCommandRejects keeps the parser honest about bad input.
func TestParseChatCommandRejects(t *testing.T) {
	if _, ok := ParseChatCommandFromClient(nil); ok {
		t.Fatal("nil accepted")
	}
	if _, ok := ParseChatCommandFromClient([]byte{0x98, 0xff, 0xff}); ok {
		t.Fatal("overlong length accepted")
	}
	if _, ok := ParseChatCommandFromClient([]byte{0x13, 0, 0}); ok {
		t.Fatal("wrong tag accepted")
	}
}
