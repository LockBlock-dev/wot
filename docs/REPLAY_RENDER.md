# Plan — "Clock-Override" accelerated replay capture (official client, no renderer)

**Goal.** Turn the official 2.4.0 client into an offline renderer: a `.wotreplay`
fed directly to the exe, played at 1× *semantics* (Core graphics + Scaleform UI +
WWISE audio all on), engine clock overridden so frames pipe as fast as
rasterization allows, captured and muxed to MP4 (or WEBM/VP9/... whatever). Explicitly **not** a
Core/Scaleform/WWISE reimplementation.

> Why not a danser-go-style custom renderer, and why not OBS: at full fidelity
> the per-frame cost is rasterization, so the only real speedup you can get is
> *decoupling the sim clock from the render clock* (parallel/deterministic,
> never wall-bound). The client is the one thing that already has all three
> fidelity layers; over-riding its clock harvests that speedup without writing
> an engine. OBS is wall-clock-bound by construction (serially presented
> frames); the game's own 16× speed index is the wrong lever (effects off,
> sound muted — `REPLAY.md§4`).

## Verified facts (IDA, 2.4.0.0 `WorldOfTanks.exe`, base `0x140000000`)

| Claim | Verdict | Evidence |
|---|---|---|
| Exe accepts `.wotreplay` directly on cmdline | **PROVEN** | `winmain::parseCommandLine sub_140355DB0` matches `.wotreplay`/`.wotsrvreplay` magic, sets replay flag + path `qword_1442DA558`; consumed by `startPlayback sub_1405799D0` |
| Anti-tamper present | **NONE** | No protector/anti-cheat imports or strings; only BigWorld *network* `MachineGuardMessage` + replay `replay-sign.pubkey` checks (never the exe) |
| Launcher gate | **NONE** | Only `WOT_STARTUP_MUTEX` single-instance (`0x1435d7ea0`); automation switches: `--forceAlwaysActive`, `--benchmarkMode`, `--stealFocus`, `--nomulticore`, `-safe` (→ `pdcOff`) |
| Native replay→frames CLI exists | **PROVEN** | `--replay-from/to/times`, `--autoScreenshotTime`, `--replayScreenshotDirectory`, `--enableScreenshotsInReplay` (parser: `sub_140355DB0`) |
| Screenshot pump is **game-time-keyed** | **PROVEN** | `sub_14057B3E0`: accumulates frame-dt `a2` into ctrl clock `a1+812`; fires when **`--autoScreenshotTime>0`** and acc `>= a1+904` next-trigger → `sub_140573580` (`sub_140574F10` on the first call = mkdirs + flip `a1+949` to lock the **JPG** path; `sub_140574670` builds the built-in filename; `sub_142947090` saves the JPG; re-arms `a1+904 += dword_1442DA50C` (int seconds) after each); `startPlayback` seeds `a1+904 = autoScreenshotTime` and shoots once |
| Pump/replay share the **framework dt** | **PROVEN** | Frame-update vtable slots `sub_140368B80` / `sub_140365760`: store `dt`→`obj+8`, update world `qword_14483CCC0`, then `sub_14057B220(qword_144847A20, dt)` — replay controller *and* pump both consume the **same** `dt` the framework passed |
| `dt` source | **MODEL A CONFIRMED** — wall-clock stamps (`timeGetTime`+`timeBeginPeriod(1)`, or `__rdtsc` if `devicePreferences/useAlternateFrameTimer`), stamps at app+1520/1560 (`sub_14035A450` = `BW::Application::initialize`) | |
| Pacing is a **`Sleep` cap, not fixed-step** | **PROVEN** | Per-frame `sub_140362630` (0xf4f, the mainloop tick): computes elapsed from stamps, `Sleep(v100)` where `v100` = `maxFramePeriod − elapsed` (`app+1568` ← `renderer/maxFrameRate`, `app+1576` ← `renderer/reducedFrameRate`); extra floors `app+1760` (min-ms, init 0 = off), `byte app+1764`→20 ms (init 0 = **off by default**), inactive `!a2`→100 ms; `v100=0` → **no `Sleep` call at all** |
| Native "uncap" lever exists | **PROVEN** | `--noMaxFrameRate` → prints "Frame rate limiting is disabled", leaves `app+1568` = 0 → tick's sleep arg 0. `--forceAlwaysActive` (`byte_14483CAB4`) forces `a2=1` in the loop → kills the 100 ms inactive floor (`0x140354470`: `a2 = hasFocus \|\| byte_14483CAB4`). Net: **zero pacing, zero sleep** (`byte_14483CE10` is a per-process single-CPU-affinity check → worst case `Sleep(0)` yield). Sim still self-advances at 1× |
| Main loop | **PROVEN** | `WinMain sub_1402E8D50` → `sub_140352CB0` (launch + loop): `do { sub_1413DEEB0; PeekMessageW; sub_140362630(app, active); sub_14036C9F0; } while (running)`. `active = sub_141EC96D0() \|\| forceAlwaysActive` |
| dt funnel (world+replay+pump) | **PROVEN** | `sub_14037E8C0` (world update) and `sub_14057B220` (replay → pump) are called **only** from the two vtable slots `sub_140365760` / `sub_140368B80` (vtables `0x1435d92d0`/`0x1435d92b0`; installed indirectly, slot args `(obj, a3=dt_replay, a4=dt_world)`). **Single chokepoint → the Route-b patch target** |
| Auto-frame-count run length | **PARTIAL** | config `debug/framesCount` (`dword_1442D7680`) counts down in `sub_140362630`; hit 0 → loop stops. Configure exact frame budgets per slice |
| `--replay-from/to/times` | **PYTHON-BOUND, NOT the pump** | `sub_140ABE0A0` = `WGReplayController` Python module init: `getReplayStartTime/EndTime/Times` + `setReplayTimes` are script-facing (window/autoplay-seek seeds via `getAutoStartFileName` → `startPlayback`). They never touch `sub_14057B3E0`. The PNG pump is gated *only* by `--autoScreenshotTime>0` + its `a1+904` timer; `byte_144847A19` (set by `--benchmarkMode` at parseCommandLine `0x140356618`) gates only the separate benchmark beacon (armed at acc ≥ `benchmarkStartTime`); scripted screenshots (`onMakeScreenshot sub_140576670`) are gated by `byte_144847A1A` = `--enableScreenshotsInReplay` |

Globals from the parser:

```c
dword_144847A28  // --replay-from <float>
dword_1442DA500  // --replay-to   <float>
dword_1442DA504  // --replay-times <n|"infinite">  (infinite → -1)
dword_1442DA50C  // --autoScreenshotTime — parsed by **strtol (INT only)**, floor 1 s of replay time per shot; <1 rejected ("Invalid value of parameter 'autoScreenshotTime'", `0x1403566e1`) — THE pump gate
dword_1442DA508  // benchmarkStartTime (debugKeys config; ARM time for the benchmark beacon)
qword_1442DA578  // --replayScreenshotDirectory <path>
byte_144847A1A   // --enableScreenshotsInReplay (gates scripted onMakeScreenshot)
byte_144847A19   // =1 via --benchmarkMode (parseCommandLine 0x140356618); enables benchmark beacon
byte_14483CAB4   // --forceAlwaysActive
dword_14483CAD0  // --benchmarkMode
g2DA558           // replay path (set by parseCommandLine)
byte_144847A18   // replay-path flag
```

**Consequence.** The "override the clock" idea plugs straight into native
machinery — the collector already advances on game-time, never wall-time, and
the *only* thing tying it to wall time is the per-frame `Sleep` cap. The whole
hook surface narrows to: **kill the sleep (native flags) for 1×-all-frames,
or feed the framework dt from replay stamps for decoupled acceleration.**

## Native per-frame (60 fps) capture — DOCUMENTED, NOT APPLIED

`--autoScreenshotTime` is `strtol`'d to an **int** and `<=0` is rejected, so
the native pump's floor is **1 shot per replay-second** (the `a1+904 +=
autoScreenshotTime` re-arm is an integer add of seconds). To get video-rate
frames without touching the renderer, freeze the re-arm so the pump fires
**once per rendered frame**:

| Site | Existing bytes (VA) | Patch |
|---|---|---|
| `sub_140573580` re-arm | `8B 05 D2 6D D6 03 01 86 88 03 00 00` @ `0x140573734` (12 B) | 12× `0x90` (NOP) |

After the seed threshold is crossed once (`startPlayback` seeds `a1+904 =
autoScreenshotTime`; the flag is still required as the `>0` pump gate), `a1+904`
never advances and the fire test (`dt + a1+812 >= a1+904`) stays true every
frame → one JPG per frame. Uniqueness check for the patcher: the 12-byte
pattern (contains the `dword_1442DA50C` RIP-relative) appears exactly once in
`.text`.

Pace to ~60 fps with the engine's own cap: **drop `--noMaxFrameRate`** and, if
needed, set `renderer/maxFrameRate 60` explicitly in `res/engine_config.xml`
(the key the main-loop tick reads; default 60). Command shape (patched exe,
unchanged flags):

```
win64\WorldOfTanks_render.exe "<replay>.wotreplay" ^
  --forceAlwaysActive ^
  --autoScreenshotTime 1 ^
  --replayScreenshotDirectory "out"
```

Effective rate = `min(render fps, 1 / JPG-encode cost)`: the saver
(`sub_142947090`) runs synchronously on the render thread, so a slow
encode caps the rate below 60. Expected: one `.jpg` per frame ≈ 60/s at 1×.

## Path C — decoupled-clock raw capture (faster than wall time) — PLAN ONLY

Paths A/B are **wall-time-bound**: the sim self-advances 1× no matter how fast
the loop runs, and the per-frame JPG encode taxes the render thread. Wall time
for a 10-min replay is fixed at ~10 min; "60 fps" only means 60 JPG/s *of that
wall time*. Path C removes both limits at once:

1. **Decouple sim clock from wall clock** (Phase 2 Route b, single-chokepoint):
   feed the frame-update slots `sub_140365760`/`sub_140368B80` a **fixed replay
   step** (`dt = 1/TARGET_FPS`) instead of the wall-stamped dt. Every rendered
   frame then advances replay time by exactly one target-time step → the replay
   runs at `render_fps / TARGET_FPS` × wall speed, deterministic by construction.
2. **Dump raw, don't encode** (Phase 3 Track B): retarget the pump's JPG writer
   (`sub_142947090`) to a raw backbuffer dump (packed bgra, memcpy-speed, ring
   buffer + writer thread), so the fast loop is never stalled by the JPG
   encoder. Keeps every frame; ~8 MB/frame at 1080p → NVMe or memory-mapped.
3. **Encode offline / in parallel**: ffmpeg turns the raw sequence into the
   target 60 fps H.264/HEVC with full quality control (the "we do the JPG"
   knob from the A/B discussion) — no decimation needed, since the fixed-step
   clock already makes each frame exactly one target-time step.

**Rate math (honest).** Uncapped raster is the only wall limit (keep
`--noMaxFrameRate`). At ~300 fps render (medium settings, 1× semantics) Path C
captures a 10-min replay in ~3.3 min and yields exactly `60 × duration` frames
after mux. Paths A/B tie the same output to 10 min of wall time.

| | A (NOP pump) | B (Python sampler) | C (decoupled + raw) |
|---|---|---|---|
| Wall time | = replay duration | = replay duration | `duration × TARGET_FPS / render_fps` |
| Frame fidelity | 1:1 with presented | sampled; dupes possible | 1:1 with presented |
| Exe changes | 12-byte NOP | none | dt-feed patch + raw-writer patch |
| Disk | JPG (~1–4 MB/s) | JPG | raw (~0.5 GB/s) → NVMe/mmap |
| Encode | engine JPG, fixed quality | engine JPG | offline, any codec/Q |

**Audio.** Replays carry no audio stream — WWISE regenerates it live, so at >1×
it cannot timestretch coherently. Path C is **video-only** by default; pair it
with a separate 1× pass for sound if needed, or mute WWISE (the game's own 16×
index does the same — `REPLAY.md§4`).

**Feasibility anchors** (all already cited above): dt chokepoint = the two
frame-update vtable slots (`sub_140365760`/`sub_140368B80`, sole feeders of
world + replay/pump); pump = `sub_14057B3E0` → `sub_140573580`; JPG writer =
`sub_142947090`; backbuffer hook = Phase 3 Track B. **Open items** before it
works: whether the framework consumes injected dt at fixed-step granularity
without internal re-accumulation (physics is its own fixed-step — verify), the
exact raw-writer patch shape (retarget `sub_142947090` vs
`IDXGISwapChain::Present` hook), and NVMe write headroom at full rate.

## Phase 1 — Loop + pacing (RESOLVED by static analysis)
Static map (2.4.0.0):
```
WinMain sub_1402E8D50
  └─ sub_140352CB0                         launch + MAIN LOOP
       ├─ sub_14035A450                    BW::Application::initialize
       │    timeGetTime|rdtsc stamps (app+1520/1560); maxFrameRate→app+1568;
       │    reducedFrameRate→app+1576; --noMaxFrameRate disables cap;
       │    timePerFrameWarningThreshold→app+1616
       └─ do {
            sub_1413DEEB0;  PeekMessageW;  sub_140362630(app, active); …
          } while (running)
            ├─ sub_140362630               per-frame tick, 0xf4f
            │    QPC busy-time metering; Sleep(maxPeriod−elapsed); floors;
            │    debug/framesCount countdown → false = end run
            └─ `active` = hasFocus \|\| byte_14483CAB4 (--forceAlwaysActive)
        frame-update slots sub_140368B80 / sub_140365760 → world update
        sub_14037E8C0 → replay/pump sub_14057B220(qword_144847A20, dt)
        (two slots are the ONLY feeders → Route-b patch chokepoint)
```
- **Verdict: Model A.** dt derives from wall-clock stamps; pacing is one
  `Sleep` site. `--debug/framesCount` gives exact frame budgets.
- **Runtime confirmation (the one open item — needs the Windows box; no wine
  here):** run `--noMaxFrameRate --forceAlwaysActive --autoScreenshotTime 1
  --replayScreenshotDirectory out <replay>` for 30 s; pass = captured-count ≈
  simulated-seconds (collector on game-time only) AND frames not silently
  throttled by swapchain/vsync. If vsync still paces: `--benchmarkMode`
  fallback, else hook `IDXGISwapChain::Present` (Track B already touches D3D).

## Phase 2 — Clock override
- **Route a (no patch):** `--noMaxFrameRate --forceAlwaysActive` removes the
  cap. Sim then advances by actual compute time per frame (still 1×, every
  frame real); with capture that is *already* "all frames, no wall bookkeeping".
- **Route b (decouple, for >1×):** single patched clock fed to everything:
  engine, Scaleform, WWISE. Drive frame `N`'s dt from replay stamps
  (`replayCtrl.getTimeMark()`); frame N = consume all packets with
  `f32 time ≤ t_N`; rasterize; never wait. **Hook point is known**: the two
  vtable slots `sub_140365760`/`sub_140368B80` are the sole feeders of world
  update + replay/pump; replace their `a3`/`a4` (dt) with replay-derived dt.
  Preferred in-process patch (exe stays pristine — verified no integrity
  check); static patch only as fallback.
- Do **not** use the game's 16× speed index: it runs the replay controller
  burst-seek → effects off/sound muted (`REPLAY.md§4`).

## Phase 3 — Capture: two parallel tracks
- **Track A (native, zero render-touch):**
  `--autoScreenshotTime N --replayScreenshotDirectory DIR` (>0) drives the
  game-time-keyed pump: one JPG per N game-seconds (`sub_14057B3E0`,
  re-armed via `a1+904 += N`). Route a: pump fires per N *wall*-seconds too
  (sim self-paces 1×) — the exact "every frame at 1× semantics" capture.
  Route b: fires per N overridden game-seconds → accelerates with the clock.
  PNG stream → mux. Cheap; still no encoded-video path.
- **Track B (raw):** hook the D3D backbuffer/swap once (offscreen RT, no
  vsync), write packed RGBA → NVMe, offline encode (`x264 slow`). Better
  quality-per-bit; more work.
- `--replay-from/to` + `--replay-times` (incl. `infinite`) govern the window →
  natural slice bounds for Track B.

## Phase 4 — Audio / UI clocks
- Pin WWISE clock: game-time (accelerates coherently) or wall (must scale).
  Tone-test after override.
- Pin Scaleform clock: at high fps, flash clip frames would over-advance —
  verify and scale from the same source. Both are consequences of Phase 2's
  single-clock discipline, not separate surgical patches.

## Phase 5 — Parallel slicing (scale)
- Slice `[t0,t1]` per worker instance (same pinned 2.4.0 client),
  `--replay-from t0 --replay-to t1`, deterministic fast-forward seek per slice,
  native screenshot pump or raw frames; splice + mux.
- `--nomulticore` per worker makes instances independent.

## Phase 6 — Pipeline + verification
- Oracles unchanged: pause/±step frame equality (`REPLAY.md§4`), `wotreplay`
  `Extract` timeline (spawns/kills/shots), short OBS baseline.
- Exit criteria: frame at `t` == step-capture at `t` (AA tolerance);
  deterministic re-render; Route b (decoupled clock) → wall < battle
  (target ≥ 2–3× realtime at 1080p60; more with slices); Route a → ≥ 1×
  with no 16 ms sleep (every frame, 1× semantics).

## Risks
| Risk | Status / mitigation |
|---|---|
| `dt` wall-bound | **RESOLVED (Model A)** — wall-clock stamps, but the replay/pump consume the *framework* dt; the only wall tie is the `Sleep` cap, removed by `--noMaxFrameRate --forceAlwaysActive` |
| Extra sleep floors in tick | **RESOLVED** — `a1+1760`/`a1+1764` init 0 (off); the 100 ms inactive floor (`!a2`) is killed by `--forceAlwaysActive` (`a2 = hasFocus\|\|flag`); `byte_14483CE10` = single-CPU-affinity check (`sub_1403DDEF0`) → worst case a `Sleep(0)` yield, not a cap |
| vsync / present blocking | last unknown pacing site — swapchain present with vsync would still throttle; `--benchmarkMode` is the escape hatch; if needed, hook `IDXGISwapChain::Present` (Track B already touches D3D) |
| WWISE / Scaleform tied to wall | both consume the same dt → coherent under Route b; tone-test after override |
| Screenshot pump PNG/JPG only | both native paths exist (`sub_140573580`: PNG via `a1+949`=0, JPG otherwise); mux low-fps fine, raw preferred at 60 → Track B |
| `--replay-from/to` interacting with the pump | **RESOLVED** — Python-bound (`WGReplayController`), seeds the playback window/autoplay seek only; pump untouched |

## Effort
Shrunk by verification: capture exists, replay feed exists, lock-gates absent,
pacing is a single removable sleep → **~1 focused week** for Track A using
Route a (native flags only); Route b (decoupled clock hook) and Track B (raw
backbuffer) each add the hook work on top.
