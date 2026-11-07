package login

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// The terrain's ground materials.
//
// WoT's physics drives differently on each: the chassis' `rotationSpeed` is
// measured on firm ground and drops on the softer ones as their resistance
// rises, and the engine fights a higher rolling friction. The client's
// `constants.py` names them in `GROUND_TYPE_BY_NAME`; the terrain paints them
// in its dominant-texture map, whose cells give the texture covering them most
// in their low bits and the ground in their high 4 bits.
//
// The map is `terrain2/dominanttextures` inside the same `cdata_processed`
// chunk the heights come from (the reference's `GroundMap::decode`).
const (
	groundMapMagic   uint32 = 0x0074616d // "mat\0"
	groundMapVersion uint32 = 1
	compressedMagic  uint32 = 0x7a697000 // "\0piz"
	groundNone       uint8  = 0
	groundFirm       uint8  = 1
	groundMedium     uint8  = 2
	groundSoft       uint8  = 3
)

// GroundMap is one chunk's ground per cell, row-major along Z like the heights.
type GroundMap struct {
	Width, Height int
	Grounds       []uint8
}

// decodeGroundMap reads a `terrain2/dominanttextures` block.
func decodeGroundMap(raw []byte) (*GroundMap, error) {
	le := binary.LittleEndian
	if len(raw) < 40 {
		return nil, fmt.Errorf("ground map is %d B, too short", len(raw))
	}
	if le.Uint32(raw[0:4]) != groundMapMagic {
		return nil, fmt.Errorf("not a dominant texture map")
	}
	if v := le.Uint32(raw[4:8]); v != groundMapVersion {
		return nil, fmt.Errorf("unsupported dominant texture map version %d", v)
	}
	textures := int(le.Uint32(raw[8:12]))
	nameSize := int(le.Uint32(raw[12:16]))
	width := int(le.Uint32(raw[16:20]))
	height := int(le.Uint32(raw[20:24]))
	off := 24 + 8 // the pad u64
	// The textures' names, which only the client draws.
	off += textures * nameSize
	if off+12 > len(raw) {
		return nil, fmt.Errorf("dominant texture names run past the block")
	}
	if le.Uint32(raw[off:off+4]) != compressedMagic {
		return nil, fmt.Errorf("dominant textures not compressed")
	}
	size := int(le.Uint32(raw[off+8 : off+12]))
	if size != width*height {
		return nil, fmt.Errorf("%d dominant textures for %dx%d cells", size, width, height)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[off+12:]))
	if err != nil {
		return nil, fmt.Errorf("dominant textures zlib: %w", err)
	}
	defer zr.Close()
	cells, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("dominant textures zlib: %w", err)
	}
	if len(cells) != size {
		return nil, fmt.Errorf("dominant textures are %d B, want %d", len(cells), size)
	}
	grounds := make([]uint8, size)
	for i, cell := range cells {
		switch cell >> 4 {
		case 1:
			grounds[i] = groundFirm
		case 2:
			grounds[i] = groundMedium
		case 3:
			grounds[i] = groundSoft
		}
	}
	return &GroundMap{Width: width, Height: height, Grounds: grounds}, nil
}

// groundAt is the ground at a position relative to the chunk's corner.
func (g *GroundMap) groundAt(x, z, chunkSize float32) uint8 {
	col := int(math.Max(float64(x/chunkSize*float32(g.Width)), 0))
	row := int(math.Max(float64(z/chunkSize*float32(g.Height)), 0))
	if col >= g.Width {
		col = g.Width - 1
	}
	if row >= g.Height {
		row = g.Height - 1
	}
	return g.Grounds[row*g.Width+col]
}

// GroundAt is the ground material at a world position: firm, medium or soft,
// or `groundNone` where the space has no chunk or the terrain is unpainted.
func (t *Terrain) GroundAt(x, z float32) uint8 {
	cx := int16(math.Floor(float64(x / t.ChunkSize)))
	cz := int16(math.Floor(float64(z / t.ChunkSize)))
	g := t.Grounds[[2]int16{cx, cz}]
	if g == nil {
		return groundNone
	}
	return g.groundAt(x-float32(cx)*t.ChunkSize, z-float32(cz)*t.ChunkSize, t.ChunkSize)
}
