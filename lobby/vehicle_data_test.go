package lobby

import "testing"

// Generated tables must resolve battle content without files (the
// whole point of codegen: ParseBattleMounts over GeneratedTable,
// plus mounted-gun specs for the feed).
func TestGeneratedTableResolves(t *testing.T) {
	tab := GeneratedTable()
	if len(tab.Vehicles) != 11 {
		t.Fatalf("nations=%d, want 11", len(tab.Vehicles))
	}
	n := 0
	for _, byType := range tab.Vehicles {
		n += len(byType)
	}
	if n != 1251 {
		t.Fatalf("vehicles=%d, want 1251", n)
	}
	// Sweden SU-152 mount triple (nation/type/turret/gun from wire).
	v, ok := tab.Vehicle(0, 9)
	if !ok || v.Name != "R18_SU-152" || v.Turrets != 1 {
		t.Fatalf("ussr/9=%+v,%v", v, ok)
	}
	for _, tc := range []struct {
		kind CompKind
		id   uint16
		name string
	}{
		{CompTurret, 16, "Turret_1_R18_SU-152"},
		{CompGun, 32, "_152mm_ML-20_mod_1937"},
	} {
		s, ok := tab.Component(0, tc.kind, tc.id)
		if !ok || s != tc.name {
			t.Fatalf("comp %d/%d=%q,%v", tc.kind, tc.id, s, ok)
		}
	}
}

func TestGeneratedGunSpecs(t *testing.T) {
	for _, tc := range []struct {
		nation, id  uint16
		turret, gun string
		reload      float64
		check       func(g GenGun) bool
	}{
		{0, 9, "Turret_1_R18_SU-152", "_152mm_ML-20_mod_1937", 17.7,
			func(g GenGun) bool { return len(g.Shells) == 3 }},
		{1, 1, "Turret_2_G02_Hummel", "_150mm_s_F_H_18_L_29_5_Hummel", 31.1,
			func(g GenGun) bool { return len(g.Shells) > 0 }},
		{7, 5, "Turret_2_Cz08_T_25", "_75mm_Skoda_A18_s_automatickym_nabijenim", 10.0,
			func(g GenGun) bool { return g.ClipCount == 3 && g.ClipRate == 45 }},
		{10, 8, "Turret_2_It14_P44_Pantera", "Cannone_da_90_74", 10.4,
			func(g GenGun) bool {
				return len(g.Autoreload) == 3 && g.Autoreload[0] == 8 && g.Autoreload[2] == 11
			}},
		{5, 98, "Turret_1_GB156_Black_Prince_II", "Twin_OQF_77mm_Gun_Mk_II", 6.0,
			func(g GenGun) bool { return g.DualGun && len(g.DualTimes) == 2 }},
		{5, 25, "Turret_2_GB60_Covenanter", "_40mm_Bofors_MkI", 6.0,
			func(g GenGun) bool { return g.BurstSize == 2 }},
		{7, 18, "Turret_1_Cz24_Vz_64_Blesk", "_30_mm_protiletadlovy_dvojkanon_vz_53", 20.0,
			func(g GenGun) bool { return g.AutoShoot && g.ClipCount == 160 }},
		{2, 263, "Turret_1_A179_Black_Rock", "_114mm_Gun_M73", 10.5,
			func(g GenGun) bool { return g.Chargeable }},
		{4, 129, "Turret_1_F135_AS_XX_40_t", "_118mm_D_1507AS", 33.0,
			func(g GenGun) bool { return g.Stationary }},
		{4, 130, "Turret_1_F136_AMX_67_Imbattable", "_120mm_SA46_67", 31.0,
			func(g GenGun) bool { return g.ExtraShot && g.ExtraReload == 4.5 }},
	} {
		g, ok := GunSpec(uint8(tc.nation), tc.id, tc.turret, tc.gun)
		if !ok {
			t.Fatalf("%d/%d %s/%s: missing", tc.nation, tc.id, tc.turret, tc.gun)
		}
		if g.Reload != tc.reload {
			t.Fatalf("%s: reload=%v, want %v", tc.gun, g.Reload, tc.reload)
		}
		if !tc.check(g) {
			t.Fatalf("%s: check failed (%+v)", tc.gun, g)
		}
	}
	// ML-20 shell triple with pen/damage (HEAT/HEAT/HE).
	g, _ := GunSpec(0, 9, "Turret_1_R18_SU-152", "_152mm_ML-20_mod_1937")
	kinds := map[string]bool{}
	for _, s := range g.Shells {
		kinds[s.Kind] = true
		if s.Caliber != 152 || s.DamageArmor <= 0 || len(s.Pen) == 0 || s.Speed <= 0 {
			t.Fatalf("shell %+v incomplete", s)
		}
	}
	if len(kinds) != 2 || !kinds["HOLLOW_CHARGE"] || !kinds["HIGH_EXPLOSIVE"] {
		t.Fatalf("kinds=%v", kinds)
	}
}
