package login

import (
	"encoding/binary"
	"net"
)

// A client's area of interest: which entities it knows about.
//
// BigWorld's base app sends `enterAoI` when an entity comes into a client's
// interest and `leaveAoI` when it goes out. The client draws and simulates
// only what is in its AoI; the arena's vehicle list — the team panels, the
// scoreboard — is a separate component (`AvatarVehiclesInfo`) and covers the
// whole battle.
//
// This server used to enter every entity at the battle entry and never leave
// one, so a 30-tank battle put all 30 in the client's entity table and every
// position update reached it. With the interest model each client holds the
// tanks around it, and the ones it drives away from leave.

// interestRadius is how far a client sees entities, in metres. The real
// server's witness radius is a few hundred metres; 500 keeps a kilometre-wide
// map's far corner out of the client's table.
const interestRadius = 500

// interestPeriod is how many arena ticks between two interest refreshes. The
// player drives at ~15 m/s, so ten ticks is 15 m: a tank is well inside the
// radius before the refresh notices it.
const interestPeriod = 10

// aoiEntity is one entity a client may see.
type aoiEntity struct {
	id  uint32
	pos [3]float32
	// always is an entity the client must hold whatever its distance: its own
	// vehicle, its Avatar, the arena's AvatarInfo.
	always bool
}

// interest is one client's area of interest.
type interest struct {
	pos    [3]float32
	radius float32
	// known is what the client has been told about.
	known map[uint32]bool
	// candidates is every entity it could be told about.
	candidates map[uint32]*aoiEntity
}

func newInterest(pos [3]float32) *interest {
	return &interest{
		pos:        pos,
		radius:     interestRadius,
		known:      map[uint32]bool{},
		candidates: map[uint32]*aoiEntity{},
	}
}

// add registers an entity the client may see. An `always` one is entered at
// once, whatever its distance.
func (i *interest) add(id uint32, pos [3]float32, always bool) {
	if i == nil {
		return
	}
	i.candidates[id] = &aoiEntity{id: id, pos: pos, always: always}
	if always {
		i.known[id] = true
	}
}

// forget drops an entity (it was destroyed).
func (i *interest) forget(id uint32) {
	if i == nil {
		return
	}
	delete(i.candidates, id)
	delete(i.known, id)
}

// move sets where the client is.
func (i *interest) move(pos [3]float32) {
	if i == nil {
		return
	}
	i.pos = pos
}

// diff returns the entities that have come into the interest and the ones that
// have left it, and updates what the client is known to hold.
func (i *interest) diff() (enter, leave []uint32) {
	if i == nil {
		return nil, nil
	}
	want := make(map[uint32]bool, len(i.candidates))
	for id, e := range i.candidates {
		if e.always || i.within(e.pos) {
			want[id] = true
		}
	}
	for id := range want {
		if !i.known[id] {
			enter = append(enter, id)
		}
	}
	for id := range i.known {
		if !want[id] {
			leave = append(leave, id)
		}
	}
	i.known = want
	return enter, leave
}

// within reports whether a point is inside the interest's sphere.
func (i *interest) within(p [3]float32) bool {
	dx := p[0] - i.pos[0]
	dy := p[1] - i.pos[1]
	dz := p[2] - i.pos[2]
	return dx*dx+dy*dy+dz*dz <= i.radius*i.radius
}

// EncodeLeaveAoI builds the element that takes an entity out of the client's
// AoI: `[0x12][len u16][entityID u32]`.
func EncodeLeaveAoI(id uint32) ([]byte, error) {
	var body [4]byte
	binary.LittleEndian.PutUint32(body[:], id)
	return appendElement(nil, elLeaveAoI, 2, body[:])
}

// refreshInterest sends the enterAoI/leaveAoI the client's interest changed by.
//
// The entities are created at the battle entry and only entered when they come
// into range, which is what the real server does: `createEntity` and
// `enterAoI` are separate steps, and the client's entity table is what the
// creates fill while the AoI decides what is drawn and simulated.
func (s *BaseAppServer) refreshInterest(conn Transport, from *net.UDPAddr, st *clientState) error {
	s.mu.Lock()
	in := st.interest
	s.mu.Unlock()
	if in == nil {
		return nil
	}
	enter, leave := in.diff()
	if len(enter) == 0 && len(leave) == 0 {
		return nil
	}
	// One entity per packet. A single enterAoI for an entity the client does
	// not know makes it drop the WHOLE packet, so bundling the batch meant one
	// bad id cost every other enter with it — and the sequence it carried was
	// never acknowledged, which stalled the reliable channel for the entire
	// battle.
	var apps [][]byte
	for _, id := range leave {
		if el, err := EncodeLeaveAoI(id); err == nil {
			apps = append(apps, el)
		}
	}
	for _, id := range enter {
		alias := uint8(0)
		s.mu.Lock()
		if st.vehicle != nil && id == st.vehicle.ID {
			alias = VehicleAlias
		}
		s.mu.Unlock()
		if el, err := EncodeEnterAoI(id, alias); err == nil {
			apps = append(apps, el)
		}
	}
	if len(apps) == 0 {
		return nil
	}
	for _, app := range apps {
		st.sendMu.Lock()
		seq, cumul := s.nextSeq(st)
		err := s.sendReliableLocked(conn, from, st, app, seq, cumul)
		st.sendMu.Unlock()
		if err != nil {
			return err
		}
	}
	s.logf("stage2 %s: interest: %d entered, %d left (%d held)", from, len(enter), len(leave), len(in.known))
	return nil
}
