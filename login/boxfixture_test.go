package login

import (
	"math"
)

// The offline fixture for the armour tests: a box collision model built from
// the old per-part box, so the penetration, ricochet and HE rules are pinned
// without the game's files. The production path traces the real triangles.

// boxCollision is a synthetic collision model: one part, one group per box
// face, the twelve triangles of the box, each face's material the box's own
// armour.
//
// The face groups are named `armor_front`, `armor_side`, `armor_rear`,
// `armor_top`, `armor_bottom`; every one is main armour.
func boxCollision(b hitBox) *vehicleCollision {
	min, max := b.Bounds[0], b.Bounds[1]
	// Corners: 0..3 the -Y face (bottom), 4..7 the +Y one (top).
	c := [8][3]float32{
		{min[0], min[1], min[2]},
		{max[0], min[1], min[2]},
		{max[0], min[1], max[2]},
		{min[0], min[1], max[2]},
		{min[0], max[1], min[2]},
		{max[0], max[1], min[2]},
		{max[0], max[1], max[2]},
		{min[0], max[1], max[2]},
	}
	quad := func(a, b, c2, d int) [][3][3]float32 {
		return [][3][3]float32{{c[a], c[b], c[c2]}, {c[a], c[c2], c[d]}}
	}
	// A device's groups are named for it (`gun`), so the armour model treats
	// them as modules rather than armour; a tank's are its `armor_*` plates.
	name := func(face string) string {
		if b.Device {
			return "gun"
		}
		return "armor_" + face
	}
	groups := []armorGroup{
		{Name: name("side"), Kind: 1, Triangles: quad(1, 2, 6, 5)},   // +X
		{Name: name("side"), Kind: 1, Triangles: quad(0, 4, 7, 3)},   // -X
		{Name: name("top"), Kind: 1, Triangles: quad(4, 5, 6, 7)},    // +Y
		{Name: name("bottom"), Kind: 1, Triangles: quad(0, 1, 2, 3)}, // -Y
		{Name: name("front"), Kind: 1, Triangles: quad(2, 3, 7, 6)},  // +Z
		{Name: name("rear"), Kind: 1, Triangles: quad(0, 1, 5, 4)},   // -Z
	}
	armor := map[string]float32{
		name("side"):   b.Armor[1],
		name("top"):    b.Armor[3],
		name("bottom"): b.Armor[3],
		name("front"):  b.Armor[0],
		name("rear"):   b.Armor[2],
	}
	damageFactor := float32(1)
	if b.Device {
		// A device (the gun): the shell wrecks the module, the hull takes
		// nothing. The game's `gun` material has `vehicleDamageFactor` 0.
		damageFactor = 0
	}
	for i := range groups {
		m := &material{
			Armor:                       armor[groups[i].Name],
			VehicleDamageFactor:         damageFactor,
			UseHitAngle:                 true,
			MayRicochet:                 true,
			CheckCaliberForRicochet:     true,
			CheckCaliberForHitAngleNorm: true,
		}
		groups[i].Material = m
	}
	radius := float32(0)
	for _, g := range groups {
		for _, t := range g.Triangles {
			for _, v := range t {
				if l := v[0]*v[0] + v[1]*v[1] + v[2]*v[2]; l > radius*radius {
					radius = float32(math.Sqrt(float64(l)))
				}
			}
		}
	}
	return &vehicleCollision{Parts: []vehiclePartModel{{
		Part: b.Part,
		// The part's frame IS the box's frame here, so the fixture's caller
		// gives the ray in that frame and the offset stays zero.
		Offset: [3]float32{},
		Bounds: b.Bounds,
		Radius: radius,
		Groups: groups,
	}}}
}

// resolveShot traces one ray against the fixture boxes and rolls the armour,
// the way the production flight does: the nearest crossing wins.
func resolveShot(sh shellSpec, origin, dir [3]float32, boxes []hitBox) shotResult {
	best := shotResult{}
	for _, b := range boxes {
		c := boxCollision(b)
		// The part's offset is the box's origin, so the vehicle sits at 0.
		from := [3]float32{origin[0] - b.Origin[0], origin[1] - b.Origin[1], origin[2] - b.Origin[2]}
		to := [3]float32{from[0] + dir[0]*1e4, from[1] + dir[1]*1e4, from[2] + dir[2]*1e4}
		h, ok := c.firstHit([3]float32{}, 0, from, to)
		if !ok {
			continue
		}
		if best.Hit && h.Distance >= best.Distance {
			continue
		}
		res, ok := rollVehicleHit(sh, b.Target, h, dir, float64(h.Distance), 1, c, [3]float32{}, 0)
		if !ok {
			continue
		}
		best = res
	}
	return best
}

// dummyHullVehicleCollision is the hull's box in the VEHICLE frame (its bounds
// shifted by the hull's offset), which is what a target's collision model
// covers: the flight tests place a target at the vehicle origin.
func dummyHullVehicleCollision() *vehicleCollision {
	b := dummyBox([3]float32{0, 0, 0}, 0)
	off := dummyParts[0].Offset
	b.Bounds = [2][3]float32{
		{b.Bounds[0][0] + off[0], b.Bounds[0][1] + off[1], b.Bounds[0][2] + off[2]},
		{b.Bounds[1][0] + off[0], b.Bounds[1][1] + off[1], b.Bounds[1][2] + off[2]},
	}
	return boxCollision(b)
}

// dummyPart is one of the dummy's hit parts: its collision box in the PART's
// own frame, where that frame sits in the vehicle frame, and the armour of
// each face in millimetres.
//
// The boxes are NOT guesses: they are the client's own `getBoundingBox(part)`,
// which is what `DamageFromShotDecoder.decodeSegment` maps a hit point's
// quantized fractions back through. Each is the `HKBodyFlagsData`
// `minBounds_`/`maxBounds_` of the part's collision model, in the part's own
// frame — the model's origin, which sits at the part's offset in the vehicle
// frame.
type dummyPart struct {
	// Part is the client's `TankPartIndexes` index: 1 hull, 2 turret.
	Part   uint8
	Bounds [2][3]float32
	// Offset is the part's origin in the vehicle frame, from the item defs.
	Offset [3]float32
	// Armour by face: front (+Z), side (±X), rear (-Z), top (+Y).
	Front, Side, Rear, Top float32
	// Device marks a part that is a module, not armour: a shell that
	// penetrates it damages the module and does NO hull damage (the gun).
	Device bool
}

// dummyParts is the TOG II's hull and turret.
//
// The hull is `Hull.havok`'s box, its origin at the chassis's
// `<hullPosition>0 1.3553 0`. The turret is `Turret_01.havok`'s box, its origin
// at the chassis's `<turretPositions><turret>0 0.704143 1.81585` — which is
// relative to the HULL, not the vehicle, so it sits at 2.059 m and the turret
// rises above the hull's 2.088 m top. Without it a shell aimed at the turret
// passed over the hull box and did nothing at all.
//
// The armour is the item defs' per-material table: the hull's `armor_1` 76.2,
// `armor_4` 50.8, `armor_9` 25.4; the turret's `armor_1` 114.3, `armor_3` 76.2,
// `armor_4` 53.3, `armor_6` 19.
var dummyParts = []dummyPart{
	{
		Part:   1, // TankPartIndexes.HULL
		Bounds: [2][3]float32{{-1.5622, -0.8706, -5.2344}, {1.5622, 0.7324, 4.2737}},
		Offset: [3]float32{0, 1.3553, 0},
		Front:  76.2, Side: 76.2, Rear: 50.8, Top: 25.4,
	},
	{
		Part:   2, // TankPartIndexes.TURRET
		Bounds: [2][3]float32{{-1.025, -0.2735, -1.4434}, {1.025, 0.9986, 1.0816}},
		Offset: [3]float32{0, 1.3553 + 0.704143, 1.81585},
		Front:  114.3, Side: 76.2, Rear: 53.3, Top: 19,
	},
	{
		// The gun is a DEVICE, not armour: a shell that penetrates its 25.4 mm
		// damages the gun module and does no hull damage, which is why
		// shooting a barrel shows a critical hit and no health bar movement.
		// Box from `Gun_01.havok`, its origin at the turret's plus the
		// chassis's `<gunPosition>0 0.46479 0.76407`.
		Part:   3, // TankPartIndexes.GUN
		Bounds: [2][3]float32{{-0.1589, -0.1617, -0.632}, {0.1589, 0.1617, 3.8129}},
		Offset: [3]float32{0, 1.3553 + 0.704143 + 0.46479, 1.81585 + 0.76407},
		Front:  25.4, Side: 25.4, Rear: 25.4, Top: 25.4,
		Device: true,
	},
}

// dummyHullBounds is the hull part's box, the bounds the hull's hit segment is
// quantized over.
var dummyHullBounds = dummyParts[0].Bounds

// hitBox is an oriented box: the hull's collision volume for the trace.
//
// Center/Half are the trace volume in the vehicle frame; Origin is the HULL
// PART's origin in the world, which is the frame the hit point's segment is
// encoded in (the client decodes it against the part's own bounding box).
type hitBox struct {
	Center [3]float32
	Half   [3]float32
	Yaw    float32
	Origin [3]float32
	// Part is the client's `TankPartIndexes` index and Bounds the part's own
	// box, both of which the hit-point segment carries; Armor is front, side,
	// rear, top in millimetres.
	Part   uint8
	Bounds [2][3]float32
	Armor  [4]float32
	// Device marks a module part (the gun): a penetrating hit damages the
	// module and does no hull damage.
	Device bool
	// Target is the index into the session's targets of the tank this box
	// belongs to, so a hit names which one the shell met.
	Target int
}

// intersect traces the ray origin+dir*t through the box. It returns the
// nearest positive t, the world hit point and outward normal, the normal in
// the box's own frame, and the face it hit (0 ±X, 1 ±Y, 2 ±Z).
func (b hitBox) intersect(origin, dir [3]float32) (t float32, point, normal, localNormal [3]float32, face int, ok bool) {
	// Into the box's frame.
	lx := origin[0] - b.Center[0]
	ly := origin[1] - b.Center[1]
	lz := origin[2] - b.Center[2]
	c, s := cos32(b.Yaw), sin32(b.Yaw)
	ox := lx*c - lz*s
	oz := lx*s + lz*c
	dx := dir[0]*c - dir[2]*s
	dz := dir[0]*s + dir[2]*c
	o := [3]float32{ox, ly, oz}
	d := [3]float32{dx, dir[1], dz}
	half := b.Half

	tmin := float32(-math.MaxFloat32)
	tmax := float32(math.MaxFloat32)
	face = -1
	for i := 0; i < 3; i++ {
		if abs32(d[i]) < 1e-6 {
			if abs32(o[i]) > half[i] {
				return 0, [3]float32{}, [3]float32{}, [3]float32{}, 0, false
			}
			continue
		}
		a := (-half[i] - o[i]) / d[i]
		bb := (half[i] - o[i]) / d[i]
		if a > bb {
			a, bb = bb, a
		}
		if a > tmin {
			tmin = a
			face = i
		}
		if bb < tmax {
			tmax = bb
		}
		if tmin > tmax {
			return 0, [3]float32{}, [3]float32{}, [3]float32{}, 0, false
		}
	}
	if tmax < 0 {
		return 0, [3]float32{}, [3]float32{}, [3]float32{}, 0, false
	}
	if tmin < 0 {
		tmin = 0
	}
	lp := [3]float32{o[0] + d[0]*tmin, o[1] + d[1]*tmin, o[2] + d[2]*tmin}
	ln := [3]float32{}
	switch face {
	case 0:
		ln[0] = sign32(lp[0])
	case 1:
		ln[1] = sign32(lp[1])
	case 2:
		ln[2] = sign32(lp[2])
	}
	// Back to world.
	point = [3]float32{
		b.Center[0] + lp[0]*c + lp[2]*s,
		b.Center[1] + lp[1],
		b.Center[2] - lp[0]*s + lp[2]*c,
	}
	normal = [3]float32{
		ln[0]*c + ln[2]*s,
		ln[1],
		-ln[0]*s + ln[2]*c,
	}
	return tmin, point, normal, ln, face, true
}

// dummyBoxes is the dummy's parts at its spawn, in world space.
func dummyBoxes(pos [3]float32, yaw float32) []hitBox {
	out := make([]hitBox, 0, len(dummyParts))
	c, s := cos32(yaw), sin32(yaw)
	for _, p := range dummyParts {
		min, max := p.Bounds[0], p.Bounds[1]
		// The part frame's origin in the world.
		origin := [3]float32{
			pos[0] + p.Offset[0]*c + p.Offset[2]*s,
			pos[1] + p.Offset[1],
			pos[2] - p.Offset[0]*s + p.Offset[2]*c,
		}
		// The trace volume: the part frame's box centre, lifted by the part's
		// offset and turned with the hull.
		cx, cy, cz := (min[0]+max[0])/2, (min[1]+max[1])/2, (min[2]+max[2])/2
		out = append(out, hitBox{
			Center: [3]float32{
				origin[0] + cx*c + cz*s,
				origin[1] + cy,
				origin[2] - cx*s + cz*c,
			},
			Half:   [3]float32{(max[0] - min[0]) / 2, (max[1] - min[1]) / 2, (max[2] - min[2]) / 2},
			Yaw:    yaw,
			Origin: origin,
			Part:   p.Part,
			Bounds: p.Bounds,
			Armor:  [4]float32{p.Front, p.Side, p.Rear, p.Top},
			Device: p.Device,
		})
	}
	return out
}

// dummyBox is the hull part at its spawn, in world space.
func dummyBox(pos [3]float32, yaw float32) hitBox {
	return dummyBoxes(pos, yaw)[0]
}

// dummyBounds is the hull box in the HULL PART's frame, the bounds the
// hit-point segment is quantized over.
func dummyBounds() [2][3]float32 {
	return dummyHullBounds
}

// targetBoxes is every synthetic tank's hit boxes, tagged with the index of the
// target they belong to. A wreck is left out: a dead tank is not a target.
func targetBoxes(targets []*botTarget) []hitBox {
	var out []hitBox
	for i, t := range targets {
		if t == nil || t.health <= 0 {
			continue
		}
		for _, b := range dummyBoxes(t.pos, t.yaw) {
			b.Target = i
			out = append(out, b)
		}
	}
	return out
}

// armorForFace is the nominal armour of the face the shell met.
func (b hitBox) armorForFace(face int, localNormal [3]float32) float32 {
	switch face {
	case 0:
		return b.Armor[1]
	case 1:
		return b.Armor[3]
	case 2:
		if localNormal[2] > 0 {
			return b.Armor[0]
		}
		return b.Armor[2]
	}
	return b.Armor[1]
}
