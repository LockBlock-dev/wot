// Package xmpp models the World of Tanks XMPP chat layer offline:
// JIDs, server settings (endpoint lists), the 124B endpoint-list
// encoding, chat/IQ/presence stanzas and BOSH framing.
//
// Hard rule: this package performs no network I/O. There are no
// TCP/UDP dials and no HTTP clients here — only builders and
// parsers over bytes the caller supplies (captures, dumps, tests).
// The live sockets belong to the operator's client; this package
// answers "what would the bytes be" and "what do these bytes mean".
//
// Layering: the (98,25) BaseApp chat tails (`login.BuildChatCommand-
// FromClient`) are NOT this layer — they are game-channel calls that
// trigger server-side backlog/init behavior. This package is the
// TCP/BOSH XMPP layer beneath them (gloox-shaped XML, JID =
// DBID@domain/resource, bosh path `/bosh/` hardcoded client-side).
//
// Wire sources (see docs/NETWORK_PROTOCOL.md §16): the 124B
// endpoint list (Sep-29 lobby #2, login key MITM-recovered offline),
// shipped `XmppServerSettings.pyc` (settings contract + iterator),
// `chat_shared.pyc` (command ordinals live in `lobby`, not here).
package xmpp
