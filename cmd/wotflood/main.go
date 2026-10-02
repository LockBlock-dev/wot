package main

// Offline stage-2 lobby flood analyzer (structure only — sizes,
// counts, type/key-name summaries; never values, never key bytes).
import (
	"flag"
	"fmt"
	"os"

	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/login"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotflood:", err)
	os.Exit(1)
}

func main() {
	stream := flag.String("stream", "", "reassembled bundle file (skip dump stage)")
	dump := flag.String("dump", "", "wotproxy -dump file")
	flow := flag.String("flow", "", "flow substring (e.g. 50436->)")
	fragSize := flag.Int("fragsize", 1252, "bulk datagram size")
	keyFile := flag.String("keyfile", "", "hex block-key file (in; also -recover-key target)")
	recoverKey := flag.Bool("recover-key", false, "MITM-recover the login key from -dump into -keyfile")
	mitmPriv := flag.String("mitm-privkey", "", "MITM private key (with -recover-key)")
	mitmPub := flag.String("mitm-pubkey", "", "server public key (with -recover-key)")
	loginAddr := flag.String("login-addr", "", "login source prefix (with -recover-key, \"\" = any)")
	smalls := flag.Bool("smalls", false, "smalls census instead of bundle inventory")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wotflood -stream FILE | -dump FILE -flow SUB [-keyfile F | -recover-key -mitm-privkey P -mitm-pubkey S] [-smalls]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *stream != "" {
		analyzeStream(*stream)
		return
	}
	if *dump == "" || (*flow == "" && !*recoverKey) {
		flag.Usage()
		os.Exit(2)
	}
	f, err := os.Open(*dump)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	dd, err := login.ParseWotproxyDump(f)
	if err != nil {
		fatal(err)
	}
	key := ""
	if *recoverKey {
		if *keyFile == "" || *mitmPriv == "" || *mitmPub == "" {
			fatal(fmt.Errorf("-recover-key needs -keyfile -mitm-privkey -mitm-pubkey"))
		}
		key, err = login.RecoverLoginKey(dd, *mitmPriv, *mitmPub, *loginAddr)
		if err != nil {
			fatal(err)
		}
		if err := login.WriteKeyFile(*keyFile, key); err != nil {
			fatal(err)
		}
		fmt.Printf("key: len=%d id=%s -> %s\n", len(key), login.KeyID(key), *keyFile)
		return
	}
	if *keyFile == "" {
		fatal(fmt.Errorf("need -keyfile (or -recover-key)"))
	}
	key, err = login.ReadKeyFile(*keyFile)
	if err != nil {
		fatal(err)
	}
	if *smalls {
		rows, st, err := login.CensusSmalls(dd, *flow, *fragSize, key)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("smalls flow=%s datagrams=%d skipped=%d\n", *flow, st.Frags, st.Skipped)
		for _, r := range rows {
			fmt.Printf("  id=%02x type=%02x count=%d nlens=%d decoded=%d %s\n",
				r.ID, r.Type, r.Count, r.NLens, r.Decoded, r.Summary)
		}
		counters, dgs, skipped, err := login.CensusEntityBursts(dd, *flow, key)
		if err != nil {
			fmt.Printf("entity-burst: %s\n", cleanErr(err.Error()))
		} else {
			fmt.Printf("entity-burst datagrams=%d skipped=%d bodies=88B tail=[ctr+9][0000] first=%d last=%d\n",
				dgs, skipped, counters[0], counters[len(counters)-1])
		}
		return
	}
	frags, offsets, st, err := login.ReassembleFrags(dd, *flow, *fragSize, key)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("bundle flow=%s chunks=%d datagrams=%d bytes=%d skipped=%d\n",
		*flow, len(frags), st.Frags, st.FragBytes, st.Skipped)
	var app []byte
	for i, fr := range frags {
		if i < 8 || fr.NN == 0 {
			fmt.Printf("  chunk nn=%d seq=%d bytes=%d off=%d\n", fr.NN, fr.Seq, len(fr.Payload), offsets[i])
		}
		app = append(app, fr.Payload...)
	}
	if len(frags) > 8 {
		fmt.Printf("  ... %d more chunks (all headed, nn in order)\n", len(frags)-8)
	}
	for _, ch := range login.HarvestChunks(frags) {
		if ch.Distinct == 0 {
			fmt.Printf("  nn=%d seq=%d %dB: barren (prefix=%dB stack=%d)\n", ch.NN, ch.Seq, ch.Bytes, ch.Prefix, ch.Stack)
			continue
		}
		fmt.Printf("  nn=%d seq=%d %dB: prefix=%dB stack=%d keys=%d top=%s(%d)\n",
			ch.NN, ch.Seq, ch.Bytes, ch.Prefix, ch.Stack, ch.Distinct, ch.Top, ch.TopN)
	}
	printInventory(app)
}

func analyzeStream(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("stream %s bytes=%d\n", path, len(raw))
	printInventory(raw)
}

func printInventory(app []byte) {
	segs := lobby.Inventory(app)
	fmt.Printf("inventory segments=%d\n", len(segs))
	for i, s := range segs {
		if i >= 12 {
			fmt.Printf("  ... +%d more\n", len(segs)-12)
			break
		}
		if s.Consumed == 0 {
			fmt.Printf("  gap@%d +%dB err=%s\n", s.Offset, s.Gap, cleanErr(s.Err))
			continue
		}
		if s.Gap > 0 {
			fmt.Printf("  doc@%d %s (%dB, gap +%dB: %s)\n", s.Offset, s.Summary, s.Consumed, s.Gap, cleanErr(s.Err))
		} else {
			fmt.Printf("  doc@%d %s (%dB)\n", s.Offset, s.Summary, s.Consumed)
		}
	}
	counts, docs, gaps, valid := lobby.HarvestStream(app)
	fmt.Printf("harvest: docs=%d gaps=%d validPrefix=%dB distinctKeys=%d\n", docs, gaps, valid, len(counts))
	type kv struct {
		k string
		n int
	}
	var top []kv
	for k, n := range counts {
		if len(k) < 64 {
			top = append(top, kv{k, n})
		}
	}
	for i := 0; i < len(top); i++ {
		for j := i + 1; j < len(top); j++ {
			if top[j].n > top[i].n {
				top[i], top[j] = top[j], top[i]
			}
		}
	}
	for i, e := range top {
		if i >= 30 {
			fmt.Printf("  ... +%d more\n", len(top)-30)
			break
		}
		fmt.Printf("  %5d %s\n", e.n, e.k)
	}
}

// cleanErr keeps opcode/position diagnostics while stripping any
// quoted stream bytes and capping length (structure only on screen).
func cleanErr(s string) string {
	if i := indexByte(s, '"'); i >= 0 {
		s = s[:i]
	}
	var b []byte
	for i := 0; i < len(s) && len(b) < 100; i++ {
		c := s[i]
		if c < 32 || c > 126 {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
