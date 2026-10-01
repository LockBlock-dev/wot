package keydump

// DefaultPattern matches LogOnParams::addToStreamInternal on EU 2.4.0.0
// win64/WorldOfTanks.exe (78 MB, SHA1 11e4ac11…; IDA sub_140E6E210,
// session 2bbe1aa02efa). The 34 B prologue alone hits 3 functions, so the
// pattern extends through the four string stores — including
// `lea rdx,[rbp+58h]` (the encryptionKey slot, verified in disasm:
// +18h/+38h/+58h/+78h = username/password/encryptionKey/clientContext
// into sub_140E65FC0) — with ?? over the four E8 rel32 call targets,
// which drift per build. Excludes everything after the 4th call.
var DefaultPattern = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 20 45 0F B6 F8 4C 8B F2 48 8B E9 41 80 F8 FF 75 05 44 0F B6 79 10 48 8B 02 49 8B CE BA 01 00 00 00 FF 50 08 48 8D 55 18 49 8B CE 44 88 38 E8 ?? ?? ?? ?? 48 8B C8 48 8D 55 38 E8 ?? ?? ?? ?? 48 8B C8 48 8D 55 58 E8 ?? ?? ?? ?? 48 8B C8 48 8D 55 78 E8 ?? ?? ?? ?? 41 F6 C7 01 74 0F 48 8D 95 9C 00 00 00 49 8B CE"
