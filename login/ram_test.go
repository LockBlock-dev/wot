package login

import "testing"

// TestRamDamage pins the ramming model: the closing speed squared, shared by
// mass, and nothing below a nudge.
func TestRamDamage(t *testing.T) {
	// Two 40-tonne tanks meeting at 30 km/h (8.3 m/s) hurt each other for a
	// couple of hundred.
	if got := ramDamage(8.3, 40000, 40000); got < 150 || got > 300 {
		t.Errorf("40t vs 40t at 8.3 m/s = %d, want a couple of hundred", got)
	}
	// Faster hurts more, quadratically.
	slow := ramDamage(4, 40000, 40000)
	fast := ramDamage(8, 40000, 40000)
	if fast < 3*slow {
		t.Errorf("8 m/s = %d, 4 m/s = %d: want the faster one about four times", fast, slow)
	}
	// A heavy tank ramming a light one hurts the light one more than itself.
	light := ramDamage(8, 20000, 60000)
	heavy := ramDamage(8, 60000, 20000)
	if light <= heavy {
		t.Errorf("a light victim took %d, a heavy one %d: want the light one more", light, heavy)
	}
	// Below the nudge speed nothing happens.
	if got := ramDamage(1, 40000, 40000); got != 0 {
		t.Errorf("1 m/s = %d, want 0", got)
	}
	if got := ramDamage(8, 0, 40000); got != 0 {
		t.Errorf("a massless tank = %d, want 0", got)
	}
}
