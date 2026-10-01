// Package tproxy is a transparent UDP forwarder for observing genuine
// game traffic without touching the client: with one pre-installed
// DNAT rule (see below) the kernel delivers the game's LoginApp (:20016)
// and BaseApp (ephemeral 32810-32999) datagrams to us, and each flow is
// routed upstream by its ORIGINAL destination (SO_ORIGINAL_DST), resolved
// per datagram. Forwarding is key-agnostic — decryption/annotation is a
// sidecar concern (wotkeydump keyfile); the data plane works with zero
// keys and never rewrites bytes (seq/cumul footers pass through, so the
// channel behaves exactly as without us).
//
// Pre-installed rules (game + proxy on the same Linux/Proton host; run
// the proxy as its own user so its own upstream packets are exempt):
//
//	nft add table ip wot
//	nft add chain ip wot out '{ type nat hook output priority dstnat; policy accept; }'
//	nft add rule ip wot out meta skuid != proxy udp dport { 20016, 32810-32999 } dnat to 127.0.0.1:32900
//
// or iptables:
//
//	iptables -t nat -A OUTPUT -m owner ! --uid-owner proxy -p udp --dport 20016 -j DNAT --to 127.0.0.1:32900
//	iptables -t nat -A OUTPUT -m owner ! --uid-owner proxy -p udp --dport 32810:32999 -j DNAT --to 127.0.0.1:32900
//
// nat OUTPUT hooks before routing, so this also holds under the proton0
// VPN tunnel. Game and resend tolerance cover everything: the genuine
// client resends its 22B with a fresh rid every ~0.5s (captures/
// logins.pcapng), so there is no startup race — the listener is simply
// always up before the game runs.
// LIMITATION (Sep 27, verified empirically on this host): OUTPUT-chain
// NAT (DNAT or REDIRECT, loopback or LAN target) to a local listener
// delivers the packet but IP_RECVORIGDSTADDR reports the POST-NAT
// destination (the listener itself) — conntrack proves the rewrite
// happened (reply tuple rewritten), yet the cmsg carries post-NAT.
// The redsocks-style cmsg path is only proven for PREROUTING (forwarded
// traffic, e.g. game in another netns). For same-host game capture use
// explicit mode (custom-server-mod, September-proven for LoginApp);
// transparent mode is parked until a PREROUTING setup exists.
package tproxy
