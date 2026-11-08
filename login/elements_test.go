package login

import (
	"math"
	"testing"
)

// TestClientElementTableMatchesTheReference pins the whole server-to-client
// element table: every id from 0x00 to 0x4D, its name, and its framing, as the
// reference's `app/client/element.rs` gives them (its lengths are pinned
// against the client's own length function).
func TestClientElementTableMatchesTheReference(t *testing.T) {
	want := []struct {
		id    uint8
		name  string
		fixed int
	}{
		{0x00, "authenticate", 4},
		{0x01, "bandwidthNotification", 4},
		{0x02, "updateFrequencyNotification", 7},
		{0x03, "setGameTime", 4},
		{0x04, "resetEntities", 1},
		{0x05, "createBasePlayer", -1},
		{0x06, "createCellPlayer", -1},
		{0x07, "dummyPacket", -1},
		{0x08, "spaceProperty", -1},
		{0x09, "addSpaceGeometryMapping", -1},
		{0x0A, "removeSpaceGeometryMapping", -1},
		{0x0B, "createEntity", -1},
		{0x0C, "createEntityDetailed", -1},
		{0x0D, "cellAppSuspended", 0},
		{0x0E, "cellAppResumed", 0},
		{0x0F, "clientSuspensionDetectionEnabled", 4},
		{0x10, "enterAoI", 5},
		{0x11, "enterAoIOnVehicle", 9},
		{0x12, "leaveAoI", -1},
		{0x13, "tickSync", 1},
		{0x14, "tickSyncPeriodic", 2},
		{0x15, "relativePositionReference", 1},
		{0x16, "relativePosition", 12},
		{0x17, "setVehicle", 8},
		{0x18, "selectAliasedEntity", 1},
		{0x19, "selectEntity", 4},
		{0x1A, "selectPlayerEntity", 0},
		{0x1B, "forcedPosition", 38},
		{0x1C, "avatarUpdateNoAliasDetailed", 29},
		{0x1D, "avatarUpdateAliasDetailed", 26},
		{0x1E, "avatarUpdatePlayerDetailed", 25},
		{0x1F, "avatarUpdateVolatileProperties", -1},
		{0x20, "changeVolatilePackerType", -1},
		{0x21, "nrlCreateNode", -1},
		{0x22, "nrlUnlinkTree", -1},
		{0x23, "nrlUpdateNode", -1},
		{0x24, "nrlUnlinkTreeFlag", 0},
		{0x25, "nrlUpdateNodeFlag", 0},
		{0x26, "nrlData", -1},
		{0x27, "nrlMsgToClient", -1},
		{0x28, "nrlUnreliableMsgToClient", -1},
		{0x29, "avatarUpdateNoAliasFullPosYawPitchRoll", 15},
		{0x2A, "avatarUpdateNoAliasFullPosYawPitch", 13},
		{0x2B, "avatarUpdateNoAliasFullPosYaw", 12},
		{0x2C, "avatarUpdateNoAliasFullPosNoDir", 11},
		{0x2D, "avatarUpdateNoAliasOnGroundYawPitchRoll", 12},
		{0x2E, "avatarUpdateNoAliasOnGroundYawPitch", 10},
		{0x2F, "avatarUpdateNoAliasOnGroundYaw", 9},
		{0x30, "avatarUpdateNoAliasOnGroundNoDir", 8},
		{0x31, "avatarUpdateNoAliasNoPosYawPitchRoll", 9},
		{0x32, "avatarUpdateNoAliasNoPosYawPitch", 7},
		{0x33, "avatarUpdateNoAliasNoPosYaw", 6},
		{0x34, "avatarUpdateNoAliasNoPosNoDir", 5},
		{0x35, "avatarUpdateAliasFullPosYawPitchRoll", 12},
		{0x36, "avatarUpdateAliasFullPosYawPitch", 10},
		{0x37, "avatarUpdateAliasFullPosYaw", 9},
		{0x38, "avatarUpdateAliasFullPosNoDir", 8},
		{0x39, "avatarUpdateAliasOnGroundYawPitchRoll", 9},
		{0x3A, "avatarUpdateAliasOnGroundYawPitch", 7},
		{0x3B, "avatarUpdateAliasOnGroundYaw", 6},
		{0x3C, "avatarUpdateAliasOnGroundNoDir", 5},
		{0x3D, "avatarUpdateAliasNoPosYawPitchRoll", 6},
		{0x3E, "avatarUpdateAliasNoPosYawPitch", 4},
		{0x3F, "avatarUpdateAliasNoPosYaw", 3},
		{0x40, "avatarUpdateAliasNoPosNoDir", 2},
		{0x41, "controlEntity", 5},
		{0x42, "voiceData", -1},
		{0x43, "restoreClient", -1},
		{0x44, "switchBaseApp", 9},
		{0x45, "resourceHeader", -1},
		{0x46, "resourceFragment", -1},
		{0x47, "loggedOff", 1},
		{0x48, "detailedPosition", 24},
		{0x49, "nestedEntityProperty", -1},
		{0x4A, "sliceEntityProperty", -1},
		{0x4B, "updateEntity", -1},
		{0x4C, "setCellAppExtAddress", -1},
		{0x4D, "lastProxyMessageAfterDirectCellAppConnection", 0},
	}
	if len(clientElements) != len(want) {
		t.Fatalf("%d elements, want %d", len(clientElements), len(want))
	}
	for i, w := range want {
		got := clientElements[i]
		if got.ID != w.id || got.Name != w.name || got.Length.Fixed != w.fixed {
			t.Errorf("element %d = %#02x %s fixed(%d), want %#02x %s fixed(%d)",
				i, got.ID, got.Name, got.Length.Fixed, w.id, w.name, w.fixed)
		}
	}
}

// TestEncodeElementFraming pins the generic framing: a fixed element carries no
// length, a variable one a u16.
func TestEncodeElementFraming(t *testing.T) {
	el, err := EncodeElement(0x03, []byte{1, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(el) != 5 || el[0] != 0x03 {
		t.Fatalf("setGameTime = % x, want [03][4 B]", el)
	}
	if _, err := EncodeElement(0x03, []byte{1}); err == nil {
		t.Fatal("a short fixed element was accepted")
	}
	el, err = EncodeElement(0x12, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(el) != 7 || el[0] != 0x12 || el[1] != 4 {
		t.Fatalf("leaveAoI = % x, want [12][04][4 B]", el)
	}
	// And the reader walks it back.
	id, body, rest, err := DecodeElement(el)
	if err != nil || id != 0x12 || len(body) != 4 || len(rest) != 0 {
		t.Fatalf("DecodeElement = %#02x % x % x %v", id, body, rest, err)
	}
}

// TestAvatarUpdateVariants pins the family: the builder picks the variant by
// which fields are present, and each one's length matches the table.
func TestAvatarUpdateVariants(t *testing.T) {
	pos := [3]float32{1, 2, 3}
	dir := [3]float32{0.5, 0.1, 0}
	alias := uint8(7)
	cases := []struct {
		name  string
		alias *uint8
		pos   *[3]float32
		dir   *[3]float32
		comps int
		id    uint8
	}{
		{"no alias, full pos, ypr", nil, &pos, &dir, 3, 0x29},
		{"no alias, full pos, yaw", nil, &pos, &[3]float32{1, 0, 0}, 1, 0x2B},
		{"no alias, no pos, yaw", nil, nil, &[3]float32{1, 0, 0}, 1, 0x33},
		{"alias, full pos, ypr", &alias, &pos, &dir, 3, 0x35},
		{"alias, no pos, no dir", &alias, nil, nil, 0, 0},
	}
	for _, c := range cases {
		if c.id == 0 {
			// No position and no direction is refused: there is nothing to say.
			if _, err := EncodeAvatarUpdate(0, 100, c.alias, c.pos, c.dir, c.comps, 1); err == nil {
				t.Errorf("%s: accepted an empty update", c.name)
			}
			continue
		}
		el, err := EncodeAvatarUpdate(0, 100, c.alias, c.pos, c.dir, c.comps, 1)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if el[0] != c.id {
			t.Errorf("%s: element %#02x, want %#02x", c.name, el[0], c.id)
		}
		spec := clientElementByID[c.id]
		if len(el) != 1+spec.Length.Fixed {
			t.Errorf("%s: %d B, want %d", c.name, len(el), 1+spec.Length.Fixed)
		}
	}
}

// TestPackedPositionRoundTrip pins the packed position codec: a small offset
// comes back close, and the byte widths are the wire's.
func TestPackedPositionRoundTrip(t *testing.T) {
	off := [3]float32{1.5, 0.25, -2.0}
	b := packXyz(off, 1)
	if len(b) != 6 {
		t.Fatalf("packXyz = %d B, want 6", len(b))
	}
	back := unpackXyz(b, 1)
	for i := range off {
		if math.Abs(float64(back[i]-off[i])) > 0.05 {
			t.Errorf("component %d = %v, want %v", i, back[i], off[i])
		}
	}
	if got := packXz(1, -2, 1); len(got) != 3 {
		t.Fatalf("packXz = %d B, want 3", len(got))
	}
	// The angles: one byte each, full range or half.
	if got := i8ToAngle(angleToI8(1.0)); math.Abs(float64(got-1.0)) > 0.03 {
		t.Errorf("yaw round trip = %v, want 1.0", got)
	}
	if got := i8ToHalfAngle(halfAngleToI8(0.5)); math.Abs(float64(got-0.5)) > 0.03 {
		t.Errorf("half pitch round trip = %v, want 0.5", got)
	}
}

// TestNewElementBuilders pins the builders this file adds: each one frames its
// payload the way its table row says.
func TestNewElementBuilders(t *testing.T) {
	if el := EncodeBandwidthNotification(5000); len(el) != 5 || el[0] != 0x01 {
		t.Errorf("bandwidth = % x", el)
	}
	if el := EncodeSetGameTime(1234); len(el) != 5 || el[0] != 0x03 {
		t.Errorf("setGameTime = % x", el)
	}
	if el := EncodeCellAppSuspended(); len(el) != 1 || el[0] != 0x0D {
		t.Errorf("cellAppSuspended = % x", el)
	}
	if el := EncodeTickSyncPeriodic(1, 2); len(el) != 3 || el[0] != 0x14 {
		t.Errorf("tickSyncPeriodic = % x", el)
	}
	if el := EncodeLoggedOff(1); len(el) != 2 || el[0] != 0x47 {
		t.Errorf("loggedOff = % x", el)
	}
	if el := EncodeDetailedPosition([3]float32{1, 2, 3}, [3]float32{4, 5, 6}); len(el) != 25 || el[0] != 0x48 {
		t.Errorf("detailedPosition = % x", el)
	}
	if el, err := EncodeResourceHeader(7, []byte("x")); err != nil || el[0] != 0x45 || el[1] != 4 {
		t.Errorf("resourceHeader = % x (%v)", el, err)
	}
	if el, err := EncodeSetCellAppExtAddress([4]byte{127, 0, 0, 1}, 32851, 0); err != nil || el[0] != 0x4C {
		t.Errorf("setCellAppExtAddress = % x (%v)", el, err)
	}
	if el := EncodeLastProxyMessage(); len(el) != 1 || el[0] != 0x4D {
		t.Errorf("lastProxyMessage = % x", el)
	}
}
