package login

import (
	"errors"
)

// Collision models, as WoT ships them for its vehicles' parts and its maps'
// static models: a Havok tagfile whose named variants each hold a "Collision
// Physics Data" system of mesh bodies, and an `HKBodyFlagsData` giving their
// bounds and each body's material kind.
//
// Ported from the reference's `havok/collision.rs` and `havok/mesh.rs`.

// collisionBody is one body of a collision model: its triangles of one
// material.
type collisionBody struct {
	// Name is its name without its `s_` or `n_` prefix, `armor_3` say.
	Name string
	// MaterialKind is its body flags' kind, 0 when they give none.
	MaterialKind uint32
	Triangles    [][3][3]float32
}

// collisionModel is a collision model's bodies and bounds.
type collisionModel struct {
	Bodies []collisionBody
	// Bounds is its bounding box, minimum then maximum.
	Bounds [2][3]float32
}

// loadCollisionModel reads a `.havok` collision model.
func loadCollisionModel(raw []byte) (*collisionModel, error) {
	f, err := parseTagfile(raw)
	if err != nil {
		return nil, err
	}
	root := f.root()
	if root == nil {
		return nil, errors.New("collision: no root")
	}
	named := root.get("namedVariants")
	if named == nil {
		return nil, errors.New("collision: no namedVariants")
	}
	variants := named.elements()
	if variants == nil {
		return nil, errors.New("collision: no variants")
	}
	var bodies []collisionBody
	var bounds [2][3]float32
	haveBounds := false
	for i := 0; i < variants.count; i++ {
		variant := variants.get(i)
		if variant == nil {
			continue
		}
		v := variant.get("variant")
		if v == nil {
			continue
		}
		v = v.deref()
		if v == nil {
			continue
		}
		handles := v.get("resourceHandles")
		if handles == nil {
			continue
		}
		els := handles.elements()
		if els == nil {
			continue
		}
		var handleNodes []*hkNode
		for j := 0; j < els.count; j++ {
			h := els.get(j)
			if h == nil {
				continue
			}
			if d := h.deref(); d != nil {
				handleNodes = append(handleNodes, d)
			}
		}
		flags := hkVariant(handleNodes, "HKBodyFlagsData")
		if flags == nil {
			continue
		}
		minV, ok1 := hkVector(flags, "minBounds_")
		maxV, ok2 := hkVector(flags, "maxBounds_")
		if !ok1 || !ok2 {
			continue
		}
		if !haveBounds {
			bounds = [2][3]float32{minV, maxV}
			haveBounds = true
		} else {
			for k := 0; k < 3; k++ {
				bounds[0][k] = min32(bounds[0][k], minV[k])
				bounds[1][k] = max32(bounds[1][k], maxV[k])
			}
		}
		kinds := map[string]uint32{}
		if fl := flags.get("flags_"); fl != nil {
			if fels := fl.elements(); fels != nil {
				for j := 0; j < fels.count; j++ {
					info := fels.get(j)
					if info == nil {
						continue
					}
					name, ok := info.get("name").asStr()
					if !ok {
						continue
					}
					kind, ok := info.get("normalMatKind").asInt()
					if !ok {
						continue
					}
					kinds[name] = uint32(kind)
				}
			}
		}
		physics := hkVariant(handleNodes, "Collision Physics Data")
		if physics == nil {
			continue
		}
		bodyCinfos := physics.get("bodyCinfos")
		if bodyCinfos == nil {
			continue
		}
		bels := bodyCinfos.elements()
		if bels == nil {
			continue
		}
		for j := 0; j < bels.count; j++ {
			body := bels.get(j)
			if body == nil {
				continue
			}
			name, _ := body.get("name").asStr()
			name = trimBodyPrefix(name)
			shape := body.get("shape")
			if shape == nil {
				continue
			}
			shape = shape.deref()
			if shape == nil || shape.typeName() != "hknpCompressedMeshShape" {
				continue
			}
			tris, err := compressedMeshTriangles(shape)
			if err != nil {
				continue
			}
			bodies = append(bodies, collisionBody{Name: name, MaterialKind: kinds[name], Triangles: tris})
		}
	}
	if !haveBounds {
		return nil, errors.New("collision: no bounds")
	}
	return &collisionModel{Bodies: bodies, Bounds: bounds}, nil
}

// trimBodyPrefix drops a body's `s_` (solid) or `n_` prefix.
func trimBodyPrefix(name string) string {
	if len(name) > 2 && (name[:2] == "s_" || name[:2] == "n_") {
		return name[2:]
	}
	return name
}

// hkVariant finds a named resource handle's variant.
func hkVariant(handles []*hkNode, name string) *hkNode {
	for _, h := range handles {
		n, ok := h.get("name").asStr()
		if !ok || n != name {
			continue
		}
		v := h.get("variant")
		if v == nil {
			continue
		}
		return v.deref()
	}
	return nil
}

// hkVector reads a record's `hkVector4` member, its first 3 coordinates.
func hkVector(n *hkNode, member string) ([3]float32, bool) {
	v := n.get(member)
	if v == nil {
		return [3]float32{}, false
	}
	f, ok := v.asF32s(4)
	if !ok {
		return [3]float32{}, false
	}
	return [3]float32{f[0], f[1], f[2]}, true
}

// compressedMeshTriangles reads a `hknpCompressedMeshShape`'s triangles.
//
// Its mesh tree is split in sections, each with its vertices packed in a u32
// as 11, 11 and 10 bits scaled by the section's `codecParms` (3 offsets, 3
// scales), or shared with other sections, packed in a u64 as 21, 21 and 22
// bits over the whole tree's domain. A primitive's 4 indices go to the
// section's packed vertices first, then to its shared ones; it is a triangle
// if its last two are the same, else a quad.
func compressedMeshTriangles(shape *hkNode) ([][3][3]float32, error) {
	data := shape.get("data")
	if data == nil {
		return nil, errors.New("mesh: no data")
	}
	data = data.deref()
	if data == nil {
		return nil, errors.New("mesh: no data")
	}
	tree := data.get("meshTree")
	if tree == nil {
		return nil, errors.New("mesh: no meshTree")
	}
	domain := tree.get("domain")
	if domain == nil {
		return nil, errors.New("mesh: no domain")
	}
	dmin, ok1 := hkVector(domain, "min")
	dmax, ok2 := hkVector(domain, "max")
	if !ok1 || !ok2 {
		return nil, errors.New("mesh: no domain bounds")
	}
	sharedScale := [3]float32{
		(dmax[0] - dmin[0]) / float32(0x1FFFFF),
		(dmax[1] - dmin[1]) / float32(0x1FFFFF),
		(dmax[2] - dmin[2]) / float32(0x3FFFFF),
	}
	packed := tree.get("packedVertices")
	shared := tree.get("sharedVertices")
	sharedIndex := tree.get("sharedVerticesIndex")
	primitives := tree.get("primitives")
	sections := tree.get("sections")
	if packed == nil || shared == nil || sharedIndex == nil || primitives == nil || sections == nil {
		return nil, errors.New("mesh: missing tree arrays")
	}
	packedEls, sharedEls, sharedIndexEls := packed.elements(), shared.elements(), sharedIndex.elements()
	primEls, secEls := primitives.elements(), sections.elements()
	if packedEls == nil || sharedEls == nil || sharedIndexEls == nil || primEls == nil || secEls == nil {
		return nil, errors.New("mesh: missing tree arrays")
	}
	intAt := func(els *hkElements, i int) (int64, bool) {
		n := els.get(i)
		if n == nil {
			return 0, false
		}
		return n.asInt()
	}
	var out [][3][3]float32
	for si := 0; si < secEls.count; si++ {
		section := secEls.get(si)
		if section == nil {
			continue
		}
		parmsNode := section.get("codecParms")
		if parmsNode == nil {
			continue
		}
		parms, ok := parmsNode.asF32s(6)
		if !ok {
			continue
		}
		offset := [3]float32{parms[0], parms[1], parms[2]}
		scale := [3]float32{parms[3], parms[4], parms[5]}
		intField := func(name string) (int64, bool) {
			n := section.get(name)
			if n == nil {
				return 0, false
			}
			return n.asInt()
		}
		firstPacked, ok1 := intField("firstPackedVertexIndex")
		numPacked, ok2 := intField("numPackedVertices")
		firstShared, ok3 := intField("firstSharedVertexIndex")
		firstPrimitive, ok4 := intField("firstPrimitiveIndex")
		numPrimitives, ok5 := intField("numPrimitives")
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			continue
		}
		vertex := func(index int) ([3]float32, bool) {
			if index < int(numPacked) {
				v, ok := intAt(packedEls, int(firstPacked)+index)
				if !ok {
					return [3]float32{}, false
				}
				u := uint32(v)
				q := [3]float32{
					float32(u & 0x7FF),
					float32(u >> 11 & 0x7FF),
					float32(u >> 22),
				}
				return [3]float32{
					offset[0] + q[0]*scale[0],
					offset[1] + q[1]*scale[1],
					offset[2] + q[2]*scale[2],
				}, true
			}
			at, ok := intAt(sharedIndexEls, int(firstShared)+index-int(numPacked))
			if !ok {
				return [3]float32{}, false
			}
			v, ok := intAt(sharedEls, int(at))
			if !ok {
				return [3]float32{}, false
			}
			u := uint64(v)
			q := [3]float32{
				float32(u & 0x1FFFFF),
				float32(u >> 21 & 0x1FFFFF),
				float32(u >> 42),
			}
			return [3]float32{
				dmin[0] + q[0]*sharedScale[0],
				dmin[1] + q[1]*sharedScale[1],
				dmin[2] + q[2]*sharedScale[2],
			}, true
		}
		for pi := int(firstPrimitive); pi < int(firstPrimitive+numPrimitives); pi++ {
			prim := primEls.get(pi)
			if prim == nil {
				continue
			}
			indicesNode := prim.get("indices")
			if indicesNode == nil {
				continue
			}
			inds := indicesNode.elements()
			if inds == nil || inds.count < 4 {
				continue
			}
			var idx [4]int
			ok := true
			for k := 0; k < 4; k++ {
				v, okk := intAt(inds, k)
				if !okk {
					ok = false
					break
				}
				idx[k] = int(v)
			}
			if !ok {
				continue
			}
			a, ok1 := vertex(idx[0])
			b, ok2 := vertex(idx[1])
			c, ok3 := vertex(idx[2])
			if !ok1 || !ok2 || !ok3 {
				continue
			}
			out = append(out, [3][3]float32{a, b, c})
			if idx[2] != idx[3] {
				d, ok4 := vertex(idx[3])
				if ok4 {
					out = append(out, [3][3]float32{a, c, d})
				}
			}
		}
	}
	return out, nil
}
