package replay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// Battle-open records (each fires once at t=0): version, arena
// config, sub-version, digest, cell/base creates, control, map.
// Shapes pinned on all three fixtures; see REPLAY.md §6.

// ArenaConfig is a 0x2d record: [u32 len][ASCII "17, 1, 0, 5"].
type ArenaConfig struct {
	Text string
}

// ParseArenaConfig decodes a 0x2d payload.
func ParseArenaConfig(data []byte) (ArenaConfig, error) {
	var a ArenaConfig
	if len(data) < 4 {
		return a, fmt.Errorf("wotreplay: arena config len=%d", len(data))
	}
	n := int(binary.LittleEndian.Uint32(data[0:4]))
	if n != len(data)-4 {
		return a, fmt.Errorf("wotreplay: arena config len=%d, have %d", n, len(data)-4)
	}
	a.Text = string(data[4:])
	return a, nil
}

// SubVersion is a 0x30 record: [u32 2][u16 tag] (0x6468 on
// 2.3.1/2.4.0, 0x6473 on 2.1.1 — protocol tag, open).
type SubVersion struct {
	Tag uint16
}

// ParseSubVersion decodes a 0x30 payload.
func ParseSubVersion(data []byte) (SubVersion, error) {
	var s SubVersion
	if len(data) != 6 || binary.LittleEndian.Uint32(data[0:4]) != 2 {
		return s, fmt.Errorf("wotreplay: subversion=%x", data)
	}
	s.Tag = binary.LittleEndian.Uint16(data[4:6])
	return s, nil
}

// DigestRecord is a 0x3d record: [u32 len=32][32 ASCII hex] — the
// entity-defs digest, equal to the login ground truth.
type DigestRecord struct {
	Digest string
}

// ParseDigestRecord decodes a 0x3d payload.
func ParseDigestRecord(data []byte) (DigestRecord, error) {
	var d DigestRecord
	if len(data) != 36 || binary.LittleEndian.Uint32(data[0:4]) != 32 {
		return d, fmt.Errorf("wotreplay: digest record len=%d", len(data))
	}
	d.Digest = string(data[4:36])
	return d, nil
}

// SpawnRecord is a 0x1 CellPlayerCreate (107 B fixed): avatar spawn.
// [eid][spaceID][0000][vehicleEID][pos V3][yaw F32][8 B 0][tail…].
// Tail: zeros, player vehicle eid again, u32 0, two ~1e9 values A
// and CONST (0x2A55557F on 2.3/2.4, 0 on 2.1.1 — server
// IPs/stamps candidate, open), u32 0, u16 2, u16 2, zeros.
type SpawnRecord struct {
	EntityID  uint32
	SpaceID   uint32
	VehicleID uint32
	X, Y, Z   float32
	Yaw       float32
	Tail      []byte
}

// ParseSpawn decodes a 0x1 payload.
func ParseSpawn(data []byte) (SpawnRecord, error) {
	var s SpawnRecord
	if len(data) != 107 {
		return s, fmt.Errorf("wotreplay: spawn len=%d, want 107", len(data))
	}
	s.EntityID = binary.LittleEndian.Uint32(data[0:4])
	s.SpaceID = binary.LittleEndian.Uint32(data[4:8])
	s.VehicleID = binary.LittleEndian.Uint32(data[10:14])
	s.X = math.Float32frombits(binary.LittleEndian.Uint32(data[14:18]))
	s.Y = math.Float32frombits(binary.LittleEndian.Uint32(data[18:22]))
	s.Z = math.Float32frombits(binary.LittleEndian.Uint32(data[22:26]))
	s.Yaw = math.Float32frombits(binary.LittleEndian.Uint32(data[26:30]))
	s.Tail = append([]byte{}, data[30:]...)
	return s, nil
}

// ControlRecord is a 0x2 EntityControl: [eid][u8 flag] (0 observed).
type ControlRecord struct {
	EntityID uint32
	Flag     uint8
}

// ParseControl decodes a 0x2 payload.
func ParseControl(data []byte) (ControlRecord, error) {
	var c ControlRecord
	if len(data) != 5 {
		return c, fmt.Errorf("wotreplay: control len=%d", len(data))
	}
	c.EntityID = binary.LittleEndian.Uint32(data[0:4])
	c.Flag = data[4]
	return c, nil
}

// MapRecord is a 0xf record: [spaceID][arenaID][u8 namelen][name]
// [16×f32 identity matrix][u8 01].
type MapRecord struct {
	SpaceID uint32
	ArenaID uint32
	Name    string
}

// ParseMap decodes a 0xf payload (matrix must be identity).
func ParseMap(data []byte) (MapRecord, error) {
	var m MapRecord
	if len(data) < 10 {
		return m, fmt.Errorf("wotreplay: map len=%d", len(data))
	}
	m.SpaceID = binary.LittleEndian.Uint32(data[0:4])
	m.ArenaID = binary.LittleEndian.Uint32(data[4:8])
	n := int(data[8])
	if len(data) != 9+n+64+1 {
		return m, fmt.Errorf("wotreplay: map len=%d namelen=%d", len(data), n)
	}
	m.Name = string(data[9 : 9+n])
	mat := data[9+n : 9+n+64]
	for i := 0; i < 16; i++ {
		want := float32(0)
		if i%5 == 0 {
			want = 1
		}
		if got := math.Float32frombits(binary.LittleEndian.Uint32(mat[4*i : 4*i+4])); got != want {
			return m, fmt.Errorf("wotreplay: map matrix[%d]=%g", i, got)
		}
	}
	if data[len(data)-1] != 1 {
		return m, fmt.Errorf("wotreplay: map tail=%x", data[len(data)-1:])
	}
	return m, nil
}

// BaseRecord is a 0x0 BasePlayerCreate: [eid][typeID=2 u32][0 u16]
// [regionLen u16][0 u16][playerName u8-str][accountDBID u8-str]
// [arena-dict pickle + roster blobs, raw]. The pickle is kept opaque
// (no unpickler in this module); strings + region framing are exact.
type BaseRecord struct {
	EntityID uint32
	TypeID   uint32
	Name     string
	Account  string
	Rest     []byte
}

// ParseBase decodes a 0x0 payload.
func ParseBase(data []byte) (BaseRecord, error) {
	var b BaseRecord
	if len(data) < 16 {
		return b, fmt.Errorf("wotreplay: base len=%d", len(data))
	}
	b.EntityID = binary.LittleEndian.Uint32(data[0:4])
	b.TypeID = binary.LittleEndian.Uint32(data[4:8])
	n := int(binary.LittleEndian.Uint16(data[10:12]))
	if n != len(data)-14 {
		return b, fmt.Errorf("wotreplay: base region=%d, have %d", n, len(data)-14)
	}
	off := 14
	if off >= len(data) {
		return b, fmt.Errorf("wotreplay: base no name")
	}
	nl := int(data[off])
	off++
	if off+nl > len(data) {
		return b, fmt.Errorf("wotreplay: base name overrun")
	}
	b.Name = string(data[off : off+nl])
	off += nl
	if off >= len(data) {
		return b, fmt.Errorf("wotreplay: base no account")
	}
	al := int(data[off])
	off++
	if off+al > len(data) {
		return b, fmt.Errorf("wotreplay: base account overrun")
	}
	b.Account = string(data[off : off+al])
	off += al
	b.Rest = append([]byte{}, data[off:]...)
	return b, nil
}

// BaseRoster is the split of a 0x0 Rest payload: arena-dict pickle
// first, then `\x80\x02}q\x01.`-separated chunks — 33 B quest-log
// entries (counts vary per battle: 17/19/20), at most one odd-size
// special blob (80 B, 2.4.0 only), and a 1 B trailer. Quest IDs
// match the onChatAction quest pickles' family.
type BaseRoster struct {
	Arena   []byte
	Quests  [][]byte
	Special []byte
	Trailer byte
	HasTail bool
}

var rosterMark = []byte{0x80, 0x02, 0x7d, 0x71, 0x01, 0x2e}

// SplitRoster splits a BaseRecord Rest payload.
func SplitRoster(rest []byte) (BaseRoster, error) {
	var r BaseRoster
	idx := bytes.Index(rest, rosterMark)
	if idx < 0 {
		return r, fmt.Errorf("wotreplay: roster without arena pickle")
	}
	r.Arena = append([]byte{}, rest[:idx]...)
	for _, part := range bytes.Split(rest[idx+len(rosterMark):], rosterMark) {
		switch len(part) {
		case 33:
			r.Quests = append(r.Quests, append([]byte{}, part...))
		case 1:
			r.Trailer, r.HasTail = part[0], true
		default:
			if r.Special != nil {
				return r, fmt.Errorf("wotreplay: second special %dB", len(part))
			}
			r.Special = append([]byte{}, part...)
		}
	}
	return r, nil
}

// [0 u32][spaceID u32][0 u32][pos V3][dir V3 yaw/pitch/roll]; the two
// zero slots are constant across 802 creates on all fixtures
// (reserved); per-type state after that stays raw.
type CreateRecord struct {
	EntityID uint32
	TypeID   uint16
	SpaceID  uint32
	X, Y, Z  float32
	DirX     float32
	DirY     float32
	DirZ     float32
	State    []byte
}

// ParseCreate decodes a 0x5 payload prefix.
func ParseCreate(data []byte) (CreateRecord, error) {
	var c CreateRecord
	if len(data) < 42 {
		return c, fmt.Errorf("wotreplay: create len=%d < 42", len(data))
	}
	c.EntityID = binary.LittleEndian.Uint32(data[0:4])
	c.TypeID = binary.LittleEndian.Uint16(data[4:6])
	c.SpaceID = binary.LittleEndian.Uint32(data[10:14])
	c.X = math.Float32frombits(binary.LittleEndian.Uint32(data[18:22]))
	c.Y = math.Float32frombits(binary.LittleEndian.Uint32(data[22:26]))
	c.Z = math.Float32frombits(binary.LittleEndian.Uint32(data[26:30]))
	c.DirX = math.Float32frombits(binary.LittleEndian.Uint32(data[30:34]))
	c.DirY = math.Float32frombits(binary.LittleEndian.Uint32(data[34:38]))
	c.DirZ = math.Float32frombits(binary.LittleEndian.Uint32(data[38:42]))
	c.State = append([]byte{}, data[42:]...)
	return c, nil
}
