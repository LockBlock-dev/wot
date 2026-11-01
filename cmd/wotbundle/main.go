// Command wotbundle authors and inspects lobby bundles.
//
// Two directions:
//
//	wotbundle -from DUMP -flow F [-key K] [-doc N]   capture -> JSON
//	wotbundle -json SPEC [-out FILE] [-frames KEY]   JSON -> bundle
//
// The JSON form is the builder's input: an object is a dict, an array a
// list, a number an int (or a float when it has a fraction), a string a
// str, true/false a bool and null None. A bundle is a list of documents,
// each a list of the nodes it carries — the lobby's outer dict is never
// closed on the wire, so a document is a stack, not one root value.
//
//	{"documents": [
//	   [{"shop": {"isEnabled": true}}],
//	   [{"stats": {"credits": 500000, "freeXP": 12345}}]
//	]}
//
// -frames additionally splits the built bundle into the stage-2 flood's
// fragment chain and writes it as a wotproxy-style dump, so the result
// can be replayed or diffed against a capture.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/login"
	"github.com/LockBlock-dev/wot/server"
)

func main() {
	from := flag.String("from", "", "wotproxy dump to read a bundle from")
	flow := flag.String("flow", "", "flow substring for -from")
	key := flag.String("key", "", "hex block key for -from (omit to recover it from the dump)")
	doc := flag.Int("doc", -1, "with -from: print only this document index")
	jsonPath := flag.String("json", "", "JSON spec to build a bundle from")
	out := flag.String("out", "", "write the built bundle here (default stdout, hex)")
	raw := flag.Bool("raw", false, "with -out: write raw bytes instead of hex")
	framesKey := flag.String("frames", "", "also build the flood frames with this block key (hex)")
	framesOut := flag.String("framesout", "", "write the frames here as a wotproxy-style dump")
	flag.Parse()

	switch {
	case *from != "":
		if err := dumpBundle(*from, *flow, *key, *doc); err != nil {
			fatal(err)
		}
	case *jsonPath != "":
		if err := buildBundle(*jsonPath, *out, *raw, *framesKey, *framesOut); err != nil {
			fatal(err)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// dumpBundle prints a capture's bundle as the JSON the builder accepts.
func dumpBundle(path, flow, keyHex string, only int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dump, err := login.ParseWotproxyDump(f)
	if err != nil {
		return err
	}
	// -key is hex; the reassembler wants the raw bytes.
	key := ""
	if keyHex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil {
			return fmt.Errorf("-key: %w", err)
		}
		key = string(b)
	} else {
		key, err = login.RecoverLoginKey(dump, "../mitm/loginapp_mitm.privkey",
			"../World_of_Tanks_EU/2.4.0.0/res/loginapp_wot.pubkey", "")
		if err != nil {
			return fmt.Errorf("recover key: %w", err)
		}
	}
	frags, _, _, err := login.ReassembleFrags(dump, flow, 1252, key)
	if err != nil {
		return err
	}
	var stream []byte
	for _, fr := range frags {
		stream = append(stream, fr.Payload...)
	}
	b, err := server.DecodeBundle(stream)
	if err != nil {
		return err
	}
	out := map[string]any{"documents": [][]any{}}
	docs := out["documents"].([][]any)
	for i, d := range b.Docs {
		if only >= 0 && i != only {
			continue
		}
		nodes := make([]any, 0, len(d.Stack))
		for _, n := range d.Stack {
			nodes = append(nodes, nodeToJSON(n))
		}
		docs = append(docs, nodes)
	}
	out["documents"] = docs
	out["bytes"] = len(stream)
	out["decoded"] = b.Decoded
	out["tail"] = len(b.Tail)
	out["account_doc"] = b.AccountDoc()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// buildBundle turns a JSON spec into a bundle, and optionally frames.
func buildBundle(path, out string, raw bool, framesKey, framesOut string) error {
	spec, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Documents [][]any `json:"documents"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		return fmt.Errorf("spec: %w", err)
	}
	if len(doc.Documents) == 0 {
		return fmt.Errorf("spec: no documents")
	}
	b := server.NewBundle()
	for i, nodes := range doc.Documents {
		built := make([]*lobby.FNode, 0, len(nodes))
		for _, v := range nodes {
			n, err := jsonToNode(v)
			if err != nil {
				return fmt.Errorf("spec: document %d: %w", i, err)
			}
			built = append(built, n)
		}
		b.Document(built...)
	}
	stream, err := b.Encode()
	if err != nil {
		return err
	}
	// Prove it decodes before writing anything.
	check, err := server.DecodeBundle(stream)
	if err != nil {
		return fmt.Errorf("built bundle does not decode: %w", err)
	}
	if len(check.Docs) != len(doc.Documents) {
		return fmt.Errorf("built %d documents, decoded %d", len(doc.Documents), len(check.Docs))
	}

	if out == "" {
		fmt.Println(hex.EncodeToString(stream))
	} else if raw {
		if err := os.WriteFile(out, stream, 0o644); err != nil {
			return err
		}
	} else if err := os.WriteFile(out, []byte(hex.EncodeToString(stream)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wotbundle: %d B bundle, %d documents, %d objects\n",
		len(stream), len(check.Docs), len(check.Stack))

	if framesKey == "" {
		return nil
	}
	rawKey, err := hex.DecodeString(strings.TrimSpace(framesKey))
	if err != nil {
		return fmt.Errorf("-frames: %w", err)
	}
	frames, err := login.BuildFrames(string(rawKey), stream, login.DefaultBulkPayload, 1)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wotbundle: %d frames of %d B\n", len(frames), login.FrameSize(login.DefaultBulkPayload))
	if framesOut == "" {
		return nil
	}
	var sb strings.Builder
	for i, fr := range frames {
		fmt.Fprintf(&sb, "00:00:00.000 S>C 127.0.0.1:0->0.0.0.0:0 %d %s\n", len(fr), hex.EncodeToString(fr))
		_ = i
	}
	return os.WriteFile(framesOut, []byte(sb.String()), 0o644)
}

// nodeToJSON renders a decoded node as the builder's JSON form.
func nodeToJSON(n *lobby.FNode) any {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case lobby.FNone:
		return nil
	case lobby.FBool:
		return n.B
	case lobby.FInt:
		return n.I
	case lobby.FFloat:
		return n.F
	case lobby.FString, lobby.FUnicode:
		return n.S
	case lobby.FList, lobby.FTuple:
		out := make([]any, 0, len(n.Items))
		for _, it := range n.Items {
			out = append(out, nodeToJSON(it))
		}
		return out
	case lobby.FDict:
		out := map[string]any{}
		for i, k := range n.Keys {
			out[k.S] = nodeToJSON(n.Items[i])
		}
		return out
	}
	return fmt.Sprintf("<%d>", n.Kind)
}

// jsonToNode builds a node from the builder's JSON form.
func jsonToNode(v any) (*lobby.FNode, error) {
	switch t := v.(type) {
	case nil:
		return lobby.NewNone(), nil
	case bool:
		return lobby.NewBool(t), nil
	case int64: // nodeToJSON's own output, for in-process round-trips
		return lobby.NewInt(t), nil
	case float64:
		if t == float64(int64(t)) {
			return lobby.NewInt(int64(t)), nil
		}
		return lobby.NewFloat(t), nil
	case string:
		return lobby.NewString(t), nil
	case []any:
		n := lobby.NewList()
		for _, it := range t {
			c, err := jsonToNode(it)
			if err != nil {
				return nil, err
			}
			n.Append(c)
		}
		return n, nil
	case map[string]any:
		n := lobby.NewDict()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic output
		for _, k := range keys {
			c, err := jsonToNode(t[k])
			if err != nil {
				return nil, err
			}
			n.Set(k, c)
		}
		return n, nil
	}
	return nil, fmt.Errorf("unsupported JSON value %T", v)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wotbundle: %v\n", err)
	os.Exit(1)
}
