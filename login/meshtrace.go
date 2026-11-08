package login

import (
	"math"
	"sort"
	"strings"
)

// Tracing a shell through a vehicle's collision mesh, and what its armour does
// to it.
//
// Ported from the reference's `wot/collision.rs` (`CollisionModel::hits`,
// `VehicleCollision::hits`) and `base/armor.rs` (`hit`, `penetrate`,
// `penetration_armor`, `ricochets`). The shell is followed through the real
// triangles, so a hit names the armour group it met (`armor_3`, `leftTrack`,
// `gun`, …), that group's material, and the surface's normal — which is what
// the penetration rules, the module picker and the shell-hole segment all
// need.

// How far before the point a shell first hits a vehicle, and past it, its way
// through is followed: the client's `VEHICLE_TRACE_BACKWARD_LENGTH` and
// `VEHICLE_TRACE_FORWARD_LENGTH`.
const (
	traceBackward = 0.1
	traceForward  = 20.0
)

// sameHit is how close two crossings of the same group are the same one, in
// metres: through an edge or a vertex its triangles share.
const sameHit = 0.001

// vehicleHit is where a shell meets a vehicle's collision mesh.
type vehicleHit struct {
	// Distance is how far along the ray, in metres.
	Distance float32
	// Fraction is the same as a share of the traced segment.
	Fraction float32
	// Part is the client's `TankPartIndexes` index of the part hit.
	Part uint8
	// Group is the index of the group in its part's model, GroupName its name.
	Group     int
	GroupName string
	// Material is what the group is made of, nil for a device the vehicle does
	// not armour (the shell passes through it).
	Material *material
	// Point is the world hit point, LocalPoint the same in the part's frame.
	Point      [3]float32
	LocalPoint [3]float32
	// LocalDir is the shell's direction in the part's frame.
	LocalDir [3]float32
	// Normal is the world surface normal, facing the ray's start; LocalNormal
	// the same in the part's frame.
	Normal      [3]float32
	LocalNormal [3]float32
	// Bounds is the part's box, which the hit-point segment is encoded over.
	Bounds [2][3]float32
}

// hits is everywhere a segment crosses the vehicle, nearest first. pos and yaw
// place the vehicle in the world (its chassis origin and heading).
func (c *vehicleCollision) hits(pos [3]float32, yaw float32, from, to [3]float32) []vehicleHit {
	if c == nil {
		return nil
	}
	cw, sw := cos32(-yaw), sin32(-yaw)
	var out []vehicleHit
	for _, part := range c.Parts {
		// The segment in the part's frame: undo the part's offset and the
		// vehicle's heading.
		ox, oy, oz := from[0]-pos[0]-part.Offset[0], from[1]-pos[1]-part.Offset[1], from[2]-pos[2]-part.Offset[2]
		tx, ty, tz := to[0]-pos[0]-part.Offset[0], to[1]-pos[1]-part.Offset[1], to[2]-pos[2]-part.Offset[2]
		lf := [3]float32{ox*cw - oz*sw, oy, ox*sw + oz*cw}
		lt := [3]float32{tx*cw - tz*sw, ty, tx*sw + tz*cw}
		delta := [3]float32{lt[0] - lf[0], lt[1] - lf[1], lt[2] - lf[2]}
		length := float32(math.Sqrt(float64(delta[0]*delta[0] + delta[1]*delta[1] + delta[2]*delta[2])))
		if length < 1e-9 {
			continue
		}
		dir := [3]float32{delta[0] / length, delta[1] / length, delta[2] / length}
		// The bounding sphere: a segment that misses it can miss the part.
		closest := [3]float32{
			lf[0] + delta[0]*clampF32(-dot3(lf, delta)/(delta[0]*delta[0]+delta[1]*delta[1]+delta[2]*delta[2]), 0, 1),
			lf[1] + delta[1]*clampF32(-dot3(lf, delta)/(delta[0]*delta[0]+delta[1]*delta[1]+delta[2]*delta[2]), 0, 1),
			lf[2] + delta[2]*clampF32(-dot3(lf, delta)/(delta[0]*delta[0]+delta[1]*delta[1]+delta[2]*delta[2]), 0, 1),
		}
		if dot3(closest, closest) > part.Radius*part.Radius {
			continue
		}
		for gi := range part.Groups {
			g := &part.Groups[gi]
			for _, tri := range g.Triangles {
				f, n, ok := segmentTriangle(lf, delta, tri)
				if !ok {
					continue
				}
				lp := [3]float32{lf[0] + delta[0]*f, lf[1] + delta[1]*f, lf[2] + delta[2]*f}
				// The normal faces the segment's start.
				if dot3(n, dir) > 0 {
					n = [3]float32{-n[0], -n[1], -n[2]}
				}
				out = append(out, vehicleHit{
					Distance:    f * length,
					Fraction:    f,
					Part:        part.Part,
					Group:       gi,
					GroupName:   g.Name,
					Material:    g.Material,
					Point:       [3]float32{pos[0] + part.Offset[0] + lp[0]*cos32(yaw) + lp[2]*sin32(yaw), pos[1] + part.Offset[1] + lp[1], pos[2] + part.Offset[2] - lp[0]*sin32(yaw) + lp[2]*cos32(yaw)},
					LocalPoint:  lp,
					LocalDir:    dir,
					Normal:      [3]float32{n[0]*cos32(yaw) + n[2]*sin32(yaw), n[1], -n[0]*sin32(yaw) + n[2]*cos32(yaw)},
					LocalNormal: n,
					Bounds:      part.Bounds,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fraction < out[j].Fraction })
	// A crossing through the edge two triangles of a group share is one.
	uniq := out[:0]
	for _, h := range out {
		same := false
		for i := len(uniq) - 1; i >= 0 && h.Distance-uniq[i].Distance < sameHit; i-- {
			if uniq[i].Part == h.Part && uniq[i].Group == h.Group {
				same = true
				break
			}
		}
		if !same {
			uniq = append(uniq, h)
		}
	}
	return uniq
}

// firstHit is the nearest crossing of the vehicle, or false when the segment
// misses it.
func (c *vehicleCollision) firstHit(pos [3]float32, yaw float32, from, to [3]float32) (vehicleHit, bool) {
	hits := c.hits(pos, yaw, from, to)
	if len(hits) == 0 {
		return vehicleHit{}, false
	}
	return hits[0], true
}

// segmentTriangle is the Möller–Trumbore test: the fraction along the segment
// where it crosses the triangle, and the triangle's normal.
func segmentTriangle(from, delta [3]float32, tri [3][3]float32) (float32, [3]float32, bool) {
	e1 := [3]float32{tri[1][0] - tri[0][0], tri[1][1] - tri[0][1], tri[1][2] - tri[0][2]}
	e2 := [3]float32{tri[2][0] - tri[0][0], tri[2][1] - tri[0][1], tri[2][2] - tri[0][2]}
	p := cross3(delta, e2)
	det := dot3(e1, p)
	if abs32(det) < 1e-9 {
		return 0, [3]float32{}, false
	}
	inv := 1 / det
	t := [3]float32{from[0] - tri[0][0], from[1] - tri[0][1], from[2] - tri[0][2]}
	u := dot3(t, p) * inv
	if u < 0 || u > 1 {
		return 0, [3]float32{}, false
	}
	q := cross3(t, e1)
	v := dot3(delta, q) * inv
	if v < 0 || u+v > 1 {
		return 0, [3]float32{}, false
	}
	f := dot3(e2, q) * inv
	if f < 0 || f > 1 {
		return 0, [3]float32{}, false
	}
	n := cross3(e1, e2)
	l := float32(math.Sqrt(float64(n[0]*n[0] + n[1]*n[1] + n[2]*n[2])))
	if l < 1e-9 {
		return 0, [3]float32{}, false
	}
	return f, [3]float32{n[0] / l, n[1] / l, n[2] / l}, true
}

// armorOutcome is how a shell meets a vehicle's armour.
type armorOutcome uint8

const (
	// outcomePierced: through its main armour, the vehicle takes the damage.
	outcomePierced armorOutcome = iota
	// outcomeNotPierced: stopped by its armour, a screen's or the main one's.
	outcomeNotPierced
	// outcomeRicochet: off its armour, at too shallow an angle.
	outcomeRicochet
	// outcomeScreens: through its screens and tracks only, missing the main
	// armour behind.
	outcomeScreens
)

func (o armorOutcome) String() string {
	switch o {
	case outcomePierced:
		return "pierced"
	case outcomeNotPierced:
		return "not pierced"
	case outcomeRicochet:
		return "ricochet"
	case outcomeScreens:
		return "screens"
	}
	return "?"
}

// armorImpact is what a shell does to the vehicle it meets.
type armorImpact struct {
	Outcome armorOutcome
	// Hit is where the outcome happens: the armour it pierces, stops on or
	// ricochets off.
	Hit vehicleHit
	// Damage is what the vehicle takes, before its spread.
	Damage float32
}

// armorHit follows a shell through a vehicle's armour, at the point it first
// meets it.
//
// The shell's penetration falls off with the distance it flew, varies by its
// own randomization, and is spent plate by plate: screens, tracks and the gun
// stop it without being the main armour, and a HEAT jet weakens once it is
// through a screen. A ricochet ends the walk at the plate it bounced off.
func armorHit(sh shellSpec, distance, penFactor float32, point, dir [3]float32, c *vehicleCollision, pos [3]float32, yaw float32) (armorImpact, bool) {
	if c == nil {
		return armorImpact{}, false
	}
	from := [3]float32{point[0] - dir[0]*traceBackward, point[1] - dir[1]*traceBackward, point[2] - dir[2]*traceBackward}
	to := [3]float32{point[0] + dir[0]*traceForward, point[1] + dir[1]*traceForward, point[2] + dir[2]*traceForward}
	hits := c.hits(pos, yaw, from, to)
	if len(hits) == 0 {
		return armorImpact{}, false
	}
	pen := randomizePen(float32(sh.penAt(float64(distance)))*penFactor, float32(sh.PenRandomization))
	outcome, idx, ok := penetrate(sh, pen, dir, hits)
	if !ok {
		return armorImpact{}, false
	}
	hit := hits[idx]
	impact := armorImpact{Outcome: outcome, Hit: hit}
	if outcome == outcomePierced {
		damage := float32(sh.damageAt(float64(distance)))
		if hit.Material != nil {
			damage *= hit.Material.VehicleDamageFactor
		}
		impact.Damage = damage
	}
	return impact, true
}

// penetrate follows a shell through the plates it meets along its way, nearest
// first, and reports the outcome and the index of the plate it happens at.
func penetrate(sh shellSpec, pen float32, dir [3]float32, hits []vehicleHit) (armorOutcome, int, bool) {
	seen := map[[2]int]bool{}
	jet := false
	jetStart := float32(0)
	last := -1
	for i := range hits {
		h := &hits[i]
		// A module the shell can only damage, not stopping it.
		if h.Material == nil {
			continue
		}
		// A device (the gun, a track, the surveying device) absorbs the
		// shell: it wrecks the module and the hull behind it takes nothing.
		// The game names them `gun`, `leftTrack`, `rightTrack` and
		// `surveyingDevice`; the armour plates are `armor_N`.
		if !strings.HasPrefix(h.GroupName, "armor_") {
			return outcomeScreens, i, true
		}
		m := *h.Material
		key := [2]int{int(h.Part), h.Group}
		if m.CollideOnceOnly && seen[key] {
			continue
		}
		seen[key] = true
		last = i
		if jet {
			if flown := h.Distance - jetStart; flown > 0 {
				if f := 1 - flown*float32(sh.JetPenLoss); f > 0 {
					pen *= f
				} else {
					pen = 0
				}
			}
		}
		hitAngleCos := float32(1)
		if m.UseHitAngle {
			hitAngleCos = clampF32(-dot3(dir, h.Normal), 0, 1)
		}
		if !jet && ricochetsOff(sh, hitAngleCos, m) {
			return outcomeRicochet, i, true
		}
		pen -= penetrationArmor(sh, hitAngleCos, m)
		if pen < 0 {
			return outcomeNotPierced, i, true
		}
		if m.isMainArmor() {
			return outcomePierced, i, true
		}
		if sh.isHEAT() && !jet {
			jet = true
			jetStart = h.Distance
		}
	}
	if last < 0 {
		return outcomeScreens, 0, false
	}
	return outcomeScreens, last, true
}

// ricochetsOff is `_shouldRicochet`: AP and APCR never off armour thinner than
// a third of their caliber.
func ricochetsOff(sh shellSpec, hitAngleCos float32, m material) bool {
	if !sh.HasRicochetAngle || !m.MayRicochet || m.Armor == 0 {
		return false
	}
	if float64(hitAngleCos) > sh.RicochetAngleCos {
		return false
	}
	kindChecks := sh.isAP() || sh.isAPCR()
	if !m.CheckCaliberForRicochet || !kindChecks {
		return true
	}
	// A caliber of more than three times the armour overmatches it: no
	// ricochet. Exactly three times still ricochets (the reference's
	// `armor * 3.0 >= shot.caliber`).
	return float64(m.Armor)*3 >= sh.Caliber
}

// penetrationArmor is `_computePenetrationArmor`: the thickness a shell goes
// through, meeting it at this angle, turned toward the normal by its
// normalization angle first, more for a caliber over twice the thickness.
func penetrationArmor(sh shellSpec, hitAngleCos float32, m material) float32 {
	if !m.UseHitAngle {
		return m.Armor
	}
	cos := hitAngleCos
	norm := 0.0
	if sh.isAP() || sh.isAPCR() || sh.Kind == "ARMOR_PIERCING_HE" {
		norm = sh.NormalizationAngle
	}
	if norm > 0 && cos < 1 {
		if m.CheckCaliberForHitAngleNorm && sh.Caliber > float64(m.Armor)*2 && m.Armor > 0 {
			norm *= 1.4 * sh.Caliber / (float64(m.Armor) * 2)
		}
		angle := math.Acos(float64(cos)) - norm
		if angle < 0 {
			cos = 1
		} else {
			cos = float32(math.Cos(math.Min(angle, maxHitAngle)))
		}
	}
	if cos < 1e-5 {
		cos = 1e-5
	}
	return m.Armor / cos
}

// randomizePen varies a penetration by up to `randomization` of it either way,
// normally, most shots within half of that.
func randomizePen(pen, randomization float32) float32 {
	return pen * (1 + clampF32(float32(normalRandom()*0.5), -1, 1)*randomization)
}

// reflect is the shell's velocity off a surface: `v - 2(v·n)n`.
func reflect(v, n [3]float32) [3]float32 {
	d := 2 * dot3(v, n)
	return [3]float32{v[0] - d*n[0], v[1] - d*n[1], v[2] - d*n[2]}
}

func dot3(a, b [3]float32) float32 { return a[0]*b[0] + a[1]*b[1] + a[2]*b[2] }

func clampF32(v, lo, hi float32) float32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Shell kinds, as the item defs spell them.
func (s shellSpec) isAP() bool   { return s.Kind == "ARMOR_PIERCING" }
func (s shellSpec) isAPCR() bool { return s.Kind == "ARMOR_PIERCING_CR" }
func (s shellSpec) isHEAT() bool { return s.Kind == "HOLLOW_CHARGE" }
func (s shellSpec) isHE() bool   { return s.Kind == "HIGH_EXPLOSIVE" }

// closestPoint is the point of the vehicle's main armour closest to a world
// point, and how far it is. It is what an explosion measures its reach to.
func (c *vehicleCollision) closestPoint(pos [3]float32, yaw float32, point [3]float32) ([3]float32, float32, vehicleHit, bool) {
	if c == nil {
		return [3]float32{}, 0, vehicleHit{}, false
	}
	best := float32(math.MaxFloat32)
	var bestPoint [3]float32
	var bestHit vehicleHit
	found := false
	for _, part := range c.Parts {
		// The point in the part's frame.
		dx, dy, dz := point[0]-pos[0]-part.Offset[0], point[1]-pos[1]-part.Offset[1], point[2]-pos[2]-part.Offset[2]
		cw, sw := cos32(-yaw), sin32(-yaw)
		local := [3]float32{dx*cw - dz*sw, dy, dx*sw + dz*cw}
		for gi := range part.Groups {
			g := &part.Groups[gi]
			if g.Material == nil || !g.Material.isMainArmor() {
				continue
			}
			for _, tri := range g.Triangles {
				cp := closestOnTriangle(local, tri)
				if d := dist3(cp, local); d < best {
					best = d
					bestPoint = [3]float32{
						pos[0] + part.Offset[0] + cp[0]*cos32(yaw) + cp[2]*sin32(yaw),
						pos[1] + part.Offset[1] + cp[1],
						pos[2] + part.Offset[2] - cp[0]*sin32(yaw) + cp[2]*cos32(yaw),
					}
					bestHit = vehicleHit{
						Part:       part.Part,
						Group:      gi,
						GroupName:  g.Name,
						Material:   g.Material,
						Point:      bestPoint,
						LocalPoint: cp,
						Bounds:     part.Bounds,
					}
					found = true
				}
			}
		}
	}
	return bestPoint, best, bestHit, found
}

// closestOnTriangle is the point of a triangle closest to p.
func closestOnTriangle(p [3]float32, tri [3][3]float32) [3]float32 {
	ab := sub3(tri[1], tri[0])
	ac := sub3(tri[2], tri[0])
	ap := sub3(p, tri[0])
	d1 := dot3(ab, ap)
	d2 := dot3(ac, ap)
	if d1 <= 0 && d2 <= 0 {
		return tri[0]
	}
	bp := sub3(p, tri[1])
	d3 := dot3(ab, bp)
	d4 := dot3(ac, bp)
	if d3 >= 0 && d4 <= d3 {
		return tri[1]
	}
	vc := d1*d4 - d3*d2
	if vc <= 0 && d1 >= 0 && d3 <= 0 {
		v := d1 / (d1 - d3)
		return [3]float32{tri[0][0] + ab[0]*v, tri[0][1] + ab[1]*v, tri[0][2] + ab[2]*v}
	}
	cp := sub3(p, tri[2])
	d5 := dot3(ab, cp)
	d6 := dot3(ac, cp)
	if d6 >= 0 && d5 <= d6 {
		return tri[2]
	}
	vb := d5*d2 - d1*d6
	if vb <= 0 && d2 >= 0 && d6 <= 0 {
		w := d2 / (d2 - d6)
		return [3]float32{tri[0][0] + ac[0]*w, tri[0][1] + ac[1]*w, tri[0][2] + ac[2]*w}
	}
	va := d3*d6 - d5*d4
	if va <= 0 && d4-d3 >= 0 && d5-d6 >= 0 {
		w := (d4 - d3) / ((d4 - d3) + (d5 - d6))
		return [3]float32{
			tri[1][0] + (tri[2][0]-tri[1][0])*w,
			tri[1][1] + (tri[2][1]-tri[1][1])*w,
			tri[1][2] + (tri[2][2]-tri[1][2])*w,
		}
	}
	denom := 1 / (va + vb + vc)
	v := vb * denom
	w := vc * denom
	return [3]float32{
		tri[0][0] + ab[0]*v + ac[0]*w,
		tri[0][1] + ab[1]*v + ac[1]*w,
		tri[0][2] + ab[2]*v + ac[2]*w,
	}
}

func dist3(a, b [3]float32) float32 {
	dx, dy, dz := a[0]-b[0], a[1]-b[1], a[2]-b[2]
	return float32(math.Sqrt(float64(dx*dx + dy*dy + dz*dz)))
}
