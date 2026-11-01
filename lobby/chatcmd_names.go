package lobby

// Chat command ordinals — CHAT_COMMANDS from the shipped
// scripts/common/chat_shared.pyc (48 entries). The client sends these
// inside Chat.chatCommandFromClient (A1 tag 0x98).
var chatCommandNames = map[uint8]string{
	0:  "initAck",
	1:  "updateMemeberStatus",
	2:  "findUser",
	3:  "addFriend",
	4:  "addIgnored",
	5:  "removeFriend",
	6:  "removeIgnored",
	7:  "createPrivate",
	8:  "joinPrivate",
	9:  "requestUsersRoster",
	10: "requestFriendStatus",
	11: "friendStatusChange",
	12: "addAdmirer",
	13: "addAdmirerAck",
	14: "removeAdmirer",
	15: "onAddToIgnored",
	16: "CHGCHNLNAME",
	17: "GREETING",
	18: "BAN",
	19: "UNBAN",
	20: "ADDMODERATOR",
	21: "DELMODERATOR",
	22: "requestLastSysMessages",
	23: "chatAckInitialization",
	24: "createInvite",
	25: "inviteReceived",
	26: "acceptInvite",
	27: "rejectInvite",
	28: "getActiveInvites",
	29: "getArchiveInvites",
	30: "getMembersCount",
	31: "requestSystemChatChannels",
	32: "findChatChannels",
	33: "getChannelInfoById",
	34: "createChatChannel",
	35: "destroyChatChannel",
	36: "requestChatChannelMembers",
	37: "enterChatChannel",
	38: "leaveChatChannel",
	39: "broadcast",
	40: "USERBAN",
	41: "USERUNBAN",
	42: "requestVOIPSettings",
	43: "requestVOIPCredentials",
	44: "setMuted",
	45: "unsetMuted",
	46: "logVivoxLogin",
	47: "chatMemberStatuses",
}

// ChatCommandName returns the shipped name for a CHAT_COMMANDS
// ordinal, or "" when unknown.
func ChatCommandName(ord uint8) string { return chatCommandNames[ord] }
