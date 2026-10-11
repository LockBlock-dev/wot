package replay

// BigWorld value decoder driven by structural descriptors in
// entdef.DescribeDeep syntax (UINT8..UINT64, INT8..INT64, FLOAT32,
// FLOAT64, String, Blob, UnicodeString, Python, MAILBOX, VECTOR2/3/4,
// Array[n]{elem}, Tuple[n]{elem}, FixedDict{?name:type,...}).
//
// Wire rules (pinned on 2.3.1/2.4.0 fixtures, exact-consumption on
// every EntityMethod call): ints/floats little-endian fixed;
// String/Blob/UnicodeString/Python = [u8 len | 0xFF u24LE len][bytes];
// Python payload is raw pickle or zlib pickle (by magic); MAILBOX =
// 12 raw bytes; VECTORn = n f32; Array[0] = [u8 count | 0xFF u24LE
// count][elements] (explicit-size arrays carry no prefix); Tuple =
// concatenated; FixedDict with ? = [u8 present][fields if nonzero].

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

// Decode decodes one value of descriptor desc from buf, returning the
// value and bytes consumed.
func Decode(desc string, buf []byte) (any, int, error) {
	d, rest, err := parseDesc(desc)
	if err != nil {
		return nil, 0, err
	}
	if rest != "" {
		return nil, 0, fmt.Errorf("wotreplay: trailing descriptor %q", rest)
	}
	return d.decode(buf)
}

type dtype struct {
	op       string // int,uint,float,str,mailbox,vector,array,tuple,dict
	bits     int
	tag      string
	n        int
	size     int // array explicit size; -1 = prefixed
	elem     *dtype
	fields   []dfield
	optional bool
}

type dfield struct {
	name string
	typ  *dtype
}

// matchBrace splits a "FixedDict{...}" body at its matching close brace
// (nesting-aware). ok is false when the dict is unterminated.
func matchBrace(inner string) (body, rest string, ok bool) {
	depth := 1
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return inner[:i], inner[i+1:], true
			}
		}
	}
	return "", "", false
}

func parseDesc(s string) (*dtype, string, error) {
	if strings.HasPrefix(s, "Array[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return nil, "", fmt.Errorf("wotreplay: bad array %q", s)
		}
		var n int
		if _, err := fmt.Sscanf(s[6:end], "%d", &n); err != nil {
			return nil, "", fmt.Errorf("wotreplay: bad array %q", s)
		}
		sub := s[end+1:]
		if !strings.HasPrefix(sub, "{") {
			return nil, "", fmt.Errorf("wotreplay: array missing { in %q", s)
		}
		elem, rest, err := parseDesc(sub[1:])
		if err != nil {
			return nil, "", err
		}
		if !strings.HasPrefix(rest, "}") {
			return nil, "", fmt.Errorf("wotreplay: array missing } in %q", s)
		}
		return &dtype{op: "array", n: n, size: n, elem: elem}, rest[1:], nil
	}
	if strings.HasPrefix(s, "Tuple[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return nil, "", fmt.Errorf("wotreplay: bad tuple %q", s)
		}
		var n int
		if _, err := fmt.Sscanf(s[6:end], "%d", &n); err != nil {
			return nil, "", fmt.Errorf("wotreplay: bad tuple %q", s)
		}
		sub := s[end+1:]
		if !strings.HasPrefix(sub, "{") {
			return nil, "", fmt.Errorf("wotreplay: tuple missing { in %q", s)
		}
		elem, rest, err := parseDesc(sub[1:])
		if err != nil {
			return nil, "", err
		}
		if !strings.HasPrefix(rest, "}") {
			return nil, "", fmt.Errorf("wotreplay: tuple missing } in %q", s)
		}
		return &dtype{op: "tuple", n: n, elem: elem}, rest[1:], nil
	}
	if strings.HasPrefix(s, "FixedDict{") {
		body, rest, ok := matchBrace(s[len("FixedDict{"):])
		if !ok {
			return nil, "", fmt.Errorf("wotreplay: unterminated dict %q", s)
		}
		d := &dtype{op: "dict"}
		if strings.HasPrefix(body, "?") {
			d.optional = true
			body = body[1:]
		}
		if body != "" {
			for _, part := range splitTop(body) {
				c := strings.Index(part, ":")
				if c < 0 {
					return nil, "", fmt.Errorf("wotreplay: bad field %q", part)
				}
				ft, r2, err := parseDesc(part[c+1:])
				if err != nil {
					return nil, "", err
				}
				if r2 != "" {
					return nil, "", fmt.Errorf("wotreplay: trailing field %q", r2)
				}
				d.fields = append(d.fields, dfield{part[:c], ft})
			}
		}
		return d, rest, nil
	}
	for _, p := range []struct {
		pre string
		op  string
		b   int
	}{
		{"UINT64", "uint", 64}, {"UINT32", "uint", 32}, {"UINT16", "uint", 16}, {"UINT8", "uint", 8},
		{"INT64", "int", 64}, {"INT32", "int", 32}, {"INT16", "int", 16}, {"INT8", "int", 8},
		{"FLOAT64", "float", 64}, {"FLOAT32", "float", 32},
		{"VECTOR4", "vector", 4}, {"VECTOR3", "vector", 3}, {"VECTOR2", "vector", 2},
	} {
		if s == p.pre || strings.HasPrefix(s, p.pre+",") || strings.HasPrefix(s, p.pre+"}") {
			return &dtype{op: p.op, bits: p.b}, s[len(p.pre):], nil
		}
	}
	for _, tag := range []string{"String", "UnicodeString", "Blob", "Python", "MAILBOX"} {
		if s == tag || strings.HasPrefix(s, tag+",") || strings.HasPrefix(s, tag+"}") {
			op := "str"
			if tag == "MAILBOX" {
				op = "mailbox"
			}
			return &dtype{op: op, tag: tag}, s[len(tag):], nil
		}
	}
	return nil, "", fmt.Errorf("wotreplay: unknown descriptor %q", s)
}

func splitTop(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// readCount reads [u8 | FF u24LE]. The extended form is proven by
// onChatAction/updateArena payloads (ff 9301 00 = 403, ff e407 00 =
// 2020, ff dc04 00 = 1244 — u16 readings 0x0193/0x07e4/0x04dc would
// each leave a stray 00 and break exact consumption).
func readCount(buf []byte) (int, int, error) {
	if len(buf) < 1 {
		return 0, 0, fmt.Errorf("wotreplay: truncated count")
	}
	if buf[0] != 0xFF {
		return int(buf[0]), 1, nil
	}
	if len(buf) < 4 {
		return 0, 0, fmt.Errorf("wotreplay: truncated ext count")
	}
	return int(buf[1]) | int(buf[2])<<8 | int(buf[3])<<16, 4, nil
}

func (d *dtype) decode(buf []byte) (any, int, error) {
	switch d.op {
	case "uint", "int":
		n := d.bits / 8
		if len(buf) < n {
			return nil, 0, fmt.Errorf("wotreplay: truncated %d-bit int", d.bits)
		}
		switch d.bits {
		case 8:
			if d.op == "int" {
				return int64(int8(buf[0])), 1, nil
			}
			return uint64(buf[0]), 1, nil
		case 16:
			v := binary.LittleEndian.Uint16(buf[:2])
			if d.op == "int" {
				return int64(int16(v)), 2, nil
			}
			return uint64(v), 2, nil
		case 32:
			v := binary.LittleEndian.Uint32(buf[:4])
			if d.op == "int" {
				return int64(int32(v)), 4, nil
			}
			return uint64(v), 4, nil
		default:
			v := binary.LittleEndian.Uint64(buf[:8])
			if d.op == "int" {
				return int64(v), 8, nil
			}
			return v, 8, nil
		}
	case "float":
		if d.bits == 32 {
			if len(buf) < 4 {
				return nil, 0, fmt.Errorf("wotreplay: truncated f32")
			}
			return float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[:4]))), 4, nil
		}
		if len(buf) < 8 {
			return nil, 0, fmt.Errorf("wotreplay: truncated f64")
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(buf[:8])), 8, nil
	case "str":
		n, off, err := readCount(buf)
		if err != nil {
			return nil, 0, err
		}
		if len(buf[off:]) < n {
			return nil, 0, fmt.Errorf("wotreplay: truncated %s len=%d", d.tag, n)
		}
		raw := append([]byte{}, buf[off:off+n]...)
		if d.tag == "Python" {
			return PythonBlob{Raw: raw, Plain: gunzipMaybe(raw)}, off + n, nil
		}
		if d.tag == "Blob" {
			return raw, off + n, nil
		}
		return string(raw), off + n, nil
	case "mailbox":
		if len(buf) < 12 {
			return nil, 0, fmt.Errorf("wotreplay: truncated mailbox")
		}
		return append([]byte{}, buf[:12]...), 12, nil
	case "vector":
		if len(buf) < 4*d.bits {
			return nil, 0, fmt.Errorf("wotreplay: truncated vector%d", d.bits)
		}
		v := make([]float64, d.bits)
		for i := range v {
			v[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[4*i : 4*i+4])))
		}
		return v, 4 * d.bits, nil
	case "array":
		count := d.size
		off := 0
		if d.size == 0 {
			var err error
			count, off, err = readCount(buf)
			if err != nil {
				return nil, 0, err
			}
		}
		out := make([]any, 0, count)
		for i := 0; i < count; i++ {
			v, n, err := d.elem.decode(buf[off:])
			if err != nil {
				return nil, 0, err
			}
			off += n
			out = append(out, v)
		}
		return out, off, nil
	case "tuple":
		// Fixed-size tuples carry no prefix; size-0 tuples (only form
		// observed: steeringAngles etc.) are count-prefixed like
		// arrays — proven by 3 B [02 82 82] steering samples.
		count := d.n
		off := 0
		if d.n == 0 {
			var err error
			count, off, err = readCount(buf)
			if err != nil {
				return nil, 0, err
			}
		}
		out := make([]any, 0, count)
		for i := 0; i < count; i++ {
			v, n, err := d.elem.decode(buf[off:])
			if err != nil {
				return nil, 0, err
			}
			off += n
			out = append(out, v)
		}
		return out, off, nil
	case "dict":
		if d.optional {
			if len(buf) < 1 {
				return nil, 0, fmt.Errorf("wotreplay: truncated dict flag")
			}
			if buf[0] == 0 {
				return nil, 1, nil
			}
			buf = buf[1:]
			off := 1
			m := map[string]any{}
			for _, f := range d.fields {
				v, n, err := f.typ.decode(buf)
				if err != nil {
					return nil, 0, fmt.Errorf("wotreplay: field %s: %w", f.name, err)
				}
				buf = buf[n:]
				off += n
				m[f.name] = v
			}
			return m, off, nil
		}
		m := map[string]any{}
		off := 0
		for _, f := range d.fields {
			v, n, err := f.typ.decode(buf[off:])
			if err != nil {
				return nil, 0, fmt.Errorf("wotreplay: field %s: %w", f.name, err)
			}
			off += n
			m[f.name] = v
		}
		return m, off, nil
	}
	return nil, 0, fmt.Errorf("wotreplay: bad op %q", d.op)
}

// PythonBlob is a decoded PYTHON arg: raw wire bytes plus the pickle
// (decompressed when the sender zlib-wrapped it).
type PythonBlob struct {
	Raw   []byte
	Plain []byte
}

func gunzipMaybe(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x78 {
		return b
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return b
	}
	plain, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		return b
	}
	return plain
}
