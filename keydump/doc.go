// Package keydump recovers the live LogOnParams Blowfish encryptionKey
// out of a running WorldOfTanks.exe without Cheat Engine, so headless
// captures (wotproxy -dump, wotlogin -hijack) can trial-decrypt the 232 B
// LOGGED_ON reply and the BaseApp channel.
//
// Why memory, not wire or Python: the key is minted C++-side in
// ServerConnection::logOnBegin as pBlockCipher_->key()
// (BigWorld-Engine-14.4.1 programming/bigworld/lib/connection/
// server_connection.cpp:360) and never crosses the Python layer —
// ConnectionData carries username/password/clientContext only
// (connection_mgr.py:53). The RSA LogOnParams blob hides it on the wire.
// The durable recipe, ported from ce/wotkeydump.lua, is: find
// LogOnParams::addToStreamInternal by byte pattern (IDA sub_140E6E210),
// break on entry where RCX is the LogOnParams object, read the
// encryptionKey string at [RCX+0x58] (length at [RCX+0x68]).
package keydump
