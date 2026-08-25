# IOS_PLAN.md — iOS Detection Remediation (v0.12.x → v0.13.0)

> Status: **WS-I-A/B/C/D/E IMPLEMENTED (2026-08-25)** · WS-I-F (measurement)
> and WS-I-G (release) remain OPEN · Companion to `PLAN.md` (Android mount
> signals, same status) · Created: 2026-08-25 · Scope: every iOS heuristic in
> `cpp/IOSChecks.cpp`, `ios/HybridUrlSchemeProbe.swift`, the Expo config
> plugin, and the example app.
>
> Implementation notes (deltas from this plan):
> - F2 disposition: option (a) taken — `ios.sideload.trollstore` demoted to
>   LOW/5/rel 0.35 with the fabricated paths removed; `ios.jailbreak.dopamine`
>   and `ios.jailbreak.palera1n` are likewise **parked** (no verified
>   observable; `.installed_*` markers unfindable in two independent source
>   searches). All three ids remain public contract.
> - F4: classification is now a pure table lookup in `cpp/IOSMatchers.hpp`
>   (per-path, order-independent); every matched class is emitted. Hybrid
>   rootless+rootful devices score 40 — reviewed in `IOSMatcherTests.cpp`.
> - WS-I-D: matchers extracted to `cpp/IOSMatchers.hpp` (header-only, pure) —
>   not `ProcParsers` — with the fixture suite in `cpp/tests/IOSMatcherTests.cpp`.
> - WS-I-B.2: the plugin cannot know the host's linking SDK at prebuild time,
>   so the cap is a `schemeCap` prop (default 50, pass 25 for iOS 27+-linked
>   apps) with a dual-cap warning, rather than automatic version detection.
> - WS-I-E.4: replaced KVC with a metaclass `perform(sharedApplication)`
>   lookup — compiles in extension targets, returns nil (no ObjC exception)
>   where the shared app is unavailable.
> - F8 simulator note + scheme-cap reality (50/25, canOpenURL deprecated in
>   OS 27) folded into README Threat Model / iOS URL-scheme sections.

---

## 1. Findings being remediated

### F1 — The example app can never exercise the URL-scheme probe (severity: HIGH)

`UIApplication.canOpenURL` returns `false` for any scheme not declared in the
host app's `LSApplicationQueriesSchemes` — regardless of whether an app that
handles it is installed (Apple's current `canOpenURL(_:)` documentation states
this outright: *"This method always returns false for undeclared schemes"*).

- The Expo config plugin (`app.plugin.js`) merges the default schemes
  (`cydia`, `sileo`, `zbra`, `filza`) into Info.plist during prebuild and caps
  at 50 — Expo consumers are covered.
- **The bare React Native example app has no `LSApplicationQueriesSchemes`
  key at all** (`example/ios/RootJailDetectExample/Info.plist`). The library's
  primary integration test surface therefore reports zero scheme responses
  forever, silently, on both clean and jailbroken devices. Every manual
  validation run of `checkDetailed()` in the example app has been exercising a
  permanently-dead probe without anyone noticing.

**Cap drift (secondary):** `UrlSchemeOptions.ts` documents "iOS 15+ caps at 50"
and the plugin hardcodes 50. Current Apple docs add: apps linked on/after
iOS 15 are limited to **50** entries, and apps linked on/after
**iOS 27 are limited to 25**. The hardcoded 50 needs version awareness, and
the doc comments need updating — this matters because the cap is shared with
the host app's own queries.

### F2 — Both TrollStore artifact paths appear to be fabricated (severity: HIGH)

`cpp/IOSChecks.cpp` probes:

```
/var/containers/Bundle/trollstoreapp
/var/containers/Bundle/.trollstoreappinstalled
```

No TrollStore documentation, source tree, or community reference describes
either path. How TrollStore actually manifests (per opa334/TrollStore README,
retrieved Aug 2026):

- Apps install under `/var/containers/Bundle/Application/<UUID>/` exactly like
  App Store apps — indistinguishable by path.
- On jailbroken iOS 14, TrollHelper lives at `/Applications/TrollStore.app`.
- The Persistence Helper **overwrites a system app** (commonly Tips) — no
  stable path of its own.
- Since v1.3 (Oct 2022), TrollStore **deliberately hijacks the system
  `apple-magnifier://` scheme** precisely so scheme-based jailbreak detectors
  cannot see it.

Consequence: `ios.sideload.trollstore` (weight 15, MEDIUM, rel 0.50) is a
permanent false-negative factory — the id promises coverage of a threat the
implementation cannot observe. Either find real observables or demote the
signal honestly.

### F3 — Landscape drift: the 2026 jailbreak map is materially different (severity: MEDIUM-HIGH)

The artifact list and threat model encode a 2022–2024 world. Verified status
as of August 2026:

| Tool | Status | Layout implications |
|------|--------|---------------------|
| **Dopamine 3.0** (released **2026-08-07**) | Rootless, semi-untethered; iOS 15.0–17.3.1 broadly (A14–A17/M1–M2), A8–A13 through 18.7.1, **iOS 26.0–26.0.1 on A12/A13** | `/var/jb` symlink convention retained; ElleKit is the hooking framework (token already present ✓) |
| **palera1n** | checkm8, A8–A11, iOS 15+, rootless default (rootful discouraged); extends to iPadOS 17/18, tvOS 26 | `/var/jb` rootless; rootful puts files at classic rootfs paths |
| **Serotonin** (iOS 16.0–16.6.1) | "Semi-jailbreak": **TrollStore 2 + roothide Bootstrap** | Combines F2's blind spot with roothide's hiding |
| **roothide** environments | Active (wiki updated **2026-08-03**) | Randomized bootstrap under `/var/containers/Bundle/.jbroot-<brand>`; **deliberately avoids `/private/preboot`** ("causes detectable changes"); no extra mounts; URL schemes of JB apps hidden from blacklisted apps |

Specific defects against this map:

- `/private/preboot/jb`, `/private/preboot/dopamine`, `/private/preboot/palera1n`
  are **dead literals** — the real layout is `/private/preboot/<UUID>/jb`
  reached via the `/var/jb` symlink; nothing is mounted directly at those
  literal paths. Harmless at runtime, misleading in review, and they imply
  coverage that doesn't exist.
- `/var/jb/.installed_dopamine`, `/var/jb/.installed_palera1n` — plausible
  marker-file conventions but **unverified against Dopamine/BaseBin source**.
  Verify or drop; do not ship unverified literals as "profile-specific
  markers".
- Nothing acknowledges the roothide class: randomized paths mean **path-based
  checks have a documented, permanent ceiling** against it. This must be said
  plainly in README (as the Android plan says "do not market as
  DenyList-proof").

### F4 — Artifact-classification logic is order-coupled (severity: MEDIUM)

In `runIOSChecks`, `classicArtifactFound` is set only when *no other category
flag is already set* at the moment a classic path is examined:

```cpp
if (!rootlessArtifactFound && !dopamineArtifactFound &&
    !palera1nArtifactFound && !trollstoreArtifactFound) {
  classicArtifactFound = true;
}
```

Because the flags are monotonic across the loop, a device with **both**
`/var/jb` and `/Applications/Cydia.app` (e.g. rootless bootstrap over a
rootful remnant, or palera1n rootful after switching) reports only the
rootless signal — the classic artifact is silently swallowed depending on
array iteration order. Classification should be per-path-independent; the
emission policy ("which ids to emit when multiple classes match") should be an
explicit decision, not a side effect of evaluation order. Related gaps:

- `stat()` follows symlinks; a dangling `/var/jb` symlink (jailbreak
  deactivated but userspace reboot pending) is invisible. An `lstat()`
  companion check would catch the link itself.
- Unlike Android (`ProcParsers` + host fixture suite), the iOS matching logic
  has **no host-side unit tests at all** — every change to it is validated
  only by building and running on hardware.

### F5 — dyld loaded-image scan hardening gaps (severity: MEDIUM)

Current token set: `MobileSubstrate`, `Substitute`, `libhooker`, `ellekit`,
`rosalie`, `Frida`/`frida`, `libgadget`, `gadget.dylib`. Gaps:

- **Case sensitivity:** comparisons are `std::string::find` — `ElleKit` (any
  capitalization variant in a renamed build) misses while lowercase matches.
  Lowercase the image path once, match against lowercase tokens.
- **No location rule:** rootless tweaks load from under `/var/jb/…` (and
  roothide builds reference `.jbroot`). A path-prefix rule — any loaded image
  whose path contains `/var/jb/` or `/.jbroot` — catches renamed frameworks
  by provenance instead of name, complementing the token list.
- **Missing legacy/adjacent tokens:** `CydiaSubstrate` (the on-disk name on
  older rootful setups), `cynject`. Cheap additions, zero FP history.
- The single-`break` structure means at most one dyld signal per pass — fine,
  but undocumented; state it so nobody "fixes" it into duplicate scoring.

### F6 — Sandbox-write probe semantics are overstated (severity: LOW-MEDIUM)

Writing `/private/jbtest.txt` succeeds only when the process sandbox is gone
or escaped — which happens when (a) the user installed an unsandboxing tweak
targeting this app, (b) the app binary itself carries TrollStore-style
no-sandbox entitlements, or (c) something actively malicious is going on. It
does **not** fire on ordinary rootless-jailbroken devices where apps remain
sandboxed — i.e. it is a high-FN, high-precision "sandbox escape observed"
indicator, currently labeled as generic `ios.sandbox.write` at weight 30 /
rel 0.85.

Industry precedent confirms both the value and the aggressiveness: Verichains'
March 2025 analysis documented banking apps using a 0-day sandbox escape
specifically to enumerate TrollStore/jailbreak artifacts. The right move is
not to weaken the signal but to (a) rename/reword the human-readable reason to
say what actually happened ("a write outside the app sandbox succeeded"),
(b) document the rootless FN profile in README, (c) keep weight — a fired
sandbox escape *is* near-conclusive compromise evidence.

### F7 — Swift probe robustness details (severity: LOW)

`ios/HybridUrlSchemeProbe.swift`:

- `UIApplication.value(forKeyPath: #keyPath(UIApplication.shared))` reaches
  shared app via KVC for no benefit. In app-extension contexts
  (`UIApplication.shared` unavailable) KVC raises an **Objective-C exception,
  which Swift `try/catch` cannot intercept** — and the C++ caller's
  `try { ... } catch (...)` only catches C++ exceptions crossing the bridge,
  not ObjC throws raised inside the Swift frame before return. Replace with a
  guarded direct `UIApplication.shared` access compiled out of extension
  targets, returning `false` where unavailable.
- The synchronous main-thread dispatch deadlock (documented CLAUDE.md gotcha)
  remains; mitigation stays `urlSchemes.schemes: []`, but the plan proposes an
  async long-term option (see WS-E).

### F8 — Verified-sound items (for the record)

These survived verification and need no rework beyond documentation:
`sysctl`/`P_TRACED` debugger check (informational, weight 0 — consistent with
Android TracerPid); loopback TCP probes on 22/44/27042 (local-only, short
timeouts; port 44-as-SSH-alt is unmeasured but low-risk — fold into WS-F
measurement rather than changing now); simulator early-return emitting
`ios.simulator` and skipping device-only checks (intended, but README should
state simulator results are structurally non-representative).

---

## 2. Guiding principles

Identical to `PLAN.md` §2, plus iOS-specific corollaries:

1. Signal ids are public contract — `ios.*` ids are never renamed or
   repurposed; weights/severity/logic may be tuned.
2. Hypothesis ≠ evidence — `ios.sideload.trollstore` currently violates this
   (observable-free premise); fix the observable or fix the claim.
3. Documented ceilings are honest ceilings — path/scheme-based detection
   cannot defeat roothide-class hiding from userspace; say so instead of
   implying coverage.
4. Every positive heuristic keeps a distinct accurate reason string; every
   parser/matcher change lands with host-side fixture tests.
5. No destructive watchdog modes during measurement; `LOG_ONLY` throughout.

---

## 3. Workstreams

### WS-I-A — Documentation truthing (P0, docs-only)

| File | Change |
|------|--------|
| `README.md` | Threat-model section gains a coverage table: rootless (`/var/jb`: detected), rootful (classic paths: detected), roothide-class (randomized: **documented FN ceiling**), TrollStore (currently **not reliably detectable** pending WS-I-C). State the `LSApplicationQueriesSchemes` prerequisite prominently in the iOS setup section (not just the options JSDoc). Update the scheme-cap text to the iOS 15→50 / iOS 27-linked→25 reality. Reword `ios.sandbox.write` description per F6. Note that simulator results skip device checks entirely. |
| `src/specs/UrlSchemeOptions.ts` | Doc comments: cap numbers corrected; explicit warning that undeclared schemes always return `false` and the failure is silent. |
| `CLAUDE.md` | iOS section: record the roothide ceiling, the TrollStore verdict, and the example-app plist gap as known limitations; cross-link this plan. |

Acceptance: no unhedged claim that iOS detection covers hidden/randomized
environments; scheme prerequisite visible in README setup flow.
Validation: docs checklist (names, defaults, units, platform claims).

### WS-I-B — Example app + config plugin scheme wiring (P0, small)

1. Add `LSApplicationQueriesSchemes` (`cydia`, `sileo`, `zbra`, `filza`) to
   `example/ios/RootJailDetectExample/Info.plist`. This single edit turns the
   URL-scheme leg of every future manual validation from dead to live.
2. `app.plugin.js`: make the cap version-aware (25 for apps linked on iOS 27+;
   keep 50 otherwise), preserving the existing overflow warning; update its
   log message accordingly.
3. Extend `src/__tests__/app-plugin.test.ts`: plugin writes schemes; plugin
   respects existing entries; new cap-behavior cases.
4. README: bare-RN consumers get a copy-paste plist snippet (the plugin only
   helps Expo prebuild).

Validation: `bun run typecheck && bun run lint && bun run test --maxWorkers=2`;
example iOS build per CLAUDE.md xcodebuild recipe; manual run in the iOS
simulator confirming the probe path executes (simulator still early-returns
before scheme probing — verify on device or adjust the early-return to still
attempt scheme checks, decided in review).

### WS-I-C — Filesystem artifact rework (P1, detection-logic change)

Same signal ids; honest, verified content.

1. **Remove dead literals:** `/private/preboot/{jb,dopamine,palera1n}`.
2. **Verify-or-drop the marker files:** check Dopamine/BaseBin source for
   `.installed_dopamine` and Bootstrap for `.installed_palera1n`; keep only
   confirmed names, cite commit in a comment.
3. **TrollStore decision gate:** search opa334/TrollStore for any stable
   user-visible observable reachable from a sandboxed app. Realistic outcome:
   none exists (by design — magnifier hijack). Then either (a) reduce
   `ios.sideload.trollstore` to a hypothesis-tier weight (5–10, rel ≤ 0.40)
   with README disclosure, or (b) park the id at 0 until WS-I-F produces an
   observable. Do not delete the id (public contract).
4. **Add rootful candidates** (cheap, classic-rootful only):
   `/.procursus_strapped`, `/Applications/Sileo.app`, `/Applications/Zebra.app`.
5. **Classification independence (F4):** classify each path into its category
   unconditionally; decide emissions afterwards with an explicit rule
   (proposed: emit every matched category — deduplication downstream already
   prevents double-counting identical evidence; total-score impact reviewed in
   ScoringTests).
6. **Symlink visibility:** add `lstat()` companion for `/var/jb` (and
   `/private/jb`) so dangling links count as rootless artifacts with evidence
   noting `symlink-present`.

Every touched predicate gets host-side fixtures (WS-I-D). Validation: TS suite
+ native-test + both native builds.

### WS-I-D — Host-side fixture suite for iOS matchers (P1, test infrastructure)

Extract the path-classification and image-matching logic into pure functions
(`IOSMatchers.hpp` or a section of `ProcParsers`-style helpers compiled under
`ROOTJAILDETECT_HOST_TEST`), then port the Android fixture discipline:

- Clean corpus: stock iOS 17/26 mount/path shapes (must yield zero signals),
  simulator branch snapshot.
- Rooted corpus: rootless layout (`/var/jb` symlink + TweakInject),
  rootful palera1n shape, Dopamine marker variants (whatever WS-I-C verifies),
  **dangling-symlink** case.
- Evasion corpus: roothide-shaped inputs (randomized `.jbroot-*` path with
  `@loader_path/.jbroot` references) — pinned as *expected negative* for path
  rules, documenting the ceiling; renamed-framework images caught by the
  location rule (F5) as expected positives.
- dyld corpus: mixed-case `ElleKit`/`ELLEKIT` images, `CydiaSubstrate`,
  `cynject`, Frida gadget renames, benign lookalikes (`legitgadget.framework`
  must not fire unless the token list justifies it).

This closes the structural gap that let F2/F5 ship: iOS logic had no
non-hardware test path at all.

### WS-I-E — dyld scan + Swift probe hardening (P1, small code changes)

1. Lowercase-once comparison for image paths (F5).
2. Add location rule: image path containing `/var/jb/` or `/.jbroot` maps to
   `IOS_DYLD_HOOK` (same id — provenance-based injection evidence), evidence
   carries the path.
3. Token additions: `cydiasubstrate`, `cynject` (post-lowercase).
4. Swift: replace KVC sharedApplication access with guarded
   `UIApplication.shared`; compile-guard for extension targets returning
   `false`; leave sync dispatch as-is (async redesign deferred — breaking
   API change, separate decision).

Validation: native-test (new fixtures), example iOS build, device spot-check.

### WS-I-F — Measurement program (P1 execution / P2 completion)

Mirrors PLAN.md WS-F. Instrumentation: the diagnostics screen proposed in the
Android plan exports `CompromiseAssessment` + matched raw evidence here too.

| Class | Targets | Purpose |
|-------|---------|---------|
| Clean | iPhone on iOS 17.x, iPhone on iOS 26.x, iPads | FP baseline incl. sandbox-write silence |
| Rootless | iPhone X (A11) + palera1n rootless 16.7.x; iPhone 11 (A13) + **Dopamine 3.0 on iOS 26.0.1** (flagship modern case) | `/var/jb`, dyld location-rule TPs; scheme probe live post-WS-I-B |
| Rootful | A9/A10 device + palera1n rootful (discouraged but extant) | classic-path TPs |
| Hidden | iOS 16.6.1 device + TrollStore 2 + Serotonin/roothide Bootstrap | pin the documented ceiling; hunt accidental partial detections |
| TrollStore-only | 16.6.1 device, no bootstrap | F2 gate: confirm zero observables → finalize signal disposition |
| Injection | Self-built app with embedded FridaGadget; SSH enabled via package manager | dyld/network TP confirmation |

Decision gates (identical philosophy to Android): weights rise above interim
values only with zero clean-corpus FPs **and** ≥ 1 committed reproducible TP
fixture per signal; unresolvable observables (expected: TrollStore) get
honest hypothesis-tier treatment; results appended to README/measurement notes
with dates.

### WS-I-G — Release vehicle

Fold into the same remediation release train as PLAN.md (proposed **0.13.0**):
docs truthing + example/plugin fixes may ship as one PR early; native behavior
changes (WS-I-C/E) land with their fixtures in the second PR; measurement
results follow continuously. Native gates per release policy: full TS
preflight + `release:pods` + xcodebuild example build; physical-device passes
recorded in the release notes.

---

## 4. Sequencing

```
WS-I-A ─┐
WS-I-B ─┼─► PR #1: docs truthing + example plist + plugin cap (no native change)
        ┘        └─ TS suite + example iOS build

WS-I-C ─┐
WS-I-D ─┼─► PR #2: artifact rework + matcher extraction + fixtures + dyld hardening
WS-I-E ─┘        └─ TS suite + native-test + both native builds

WS-I-F ► measurement campaign (instrumentation rides PR #2's diagnostics work)
WS-I-G ► release 0.13.0 jointly with Android remediation
```

## 5. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Scheme checks become "too loud" once example plist fixed | Schemes are opt-out configurable; aggregate signal unchanged (15, rel 0.45); FP only if user installs a JB store — which *is* the signal's meaning |
| Emitting multiple artifact categories (F4 fix) raises scores on hybrid devices | Deliberate: hybrid states are more compromised, not less; score delta reviewed in ScoringTests and called out in changelog |
| `.jbroot` location rule FPs on benign software | Rule keys on `/.jbroot` symlink-name convention exclusive to roothide packaging; corpus fixture pins it; reliability starts ≤ 0.55 |
| Marker-file verification finds neither name exists | Drop the literals; dopamine/palera1n ids remain reachable via `/var/jb` rootless evidence — ids keep meaning, no orphaned promises |
| Measurement devices unavailable | Emulator/simulator legs bound nothing here (device-only checks); minimum viable set is one A11 palera1n device + one clean device — both cheap to borrow; Dopamine-3/iOS 26 leg is strongly preferred but the plan degrades gracefully without it |
| Plugin cap change breaks existing Expo users mid-upgrade | Cap only tightens for newly linked SDKs (Apple's rule); warn-and-truncate behavior preserved |

## 6. Explicit non-goals

- No claims (marketing or code comments) of detecting roothide-class hidden
  environments from userspace; the ceiling is documented, not fought.
- No kernel-level or entitlement-abuse techniques (sandbox-escape probes
  beyond the existing write test, CVE-based enumeration à la banking apps' —
  out of scope and reputationally wrong for an SDK).
- No DeviceCheck / App Attest server-side work — remains paired with the
  deferred Play Integrity effort, same as the Android plan's non-goal.
- No watchdog changes; `LOG_ONLY` during all measurement.
- No renaming of any `ios.*` signal id.

## 7. References (with dates — recheck before acting)

- Apple, `canOpenURL(_:)` documentation (current): undeclared schemes always
  return `false`; LSApplicationQueriesSchemes capped at 50 (apps linked ≥
  iOS 15) and **25 (apps linked ≥ iOS 27)**.
- opa334/TrollStore README + The Apple Wiki "TrollStore" (2026-04-01):
  supported ranges 14.0–16.6.1/17.0; persistence-helper mechanism;
  `apple-magnifier://` hijack since v1.3 (2022-10-29 changelog entry).
- The Apple Wiki "Roothide" (**2026-08-03**): randomized `.jbroot-<brand>`
  under `/var/containers/Bundle`; deliberate avoidance of `/private/preboot`;
  no extra mounts; URL-scheme hiding; `CFFIXED_USER_HOME` redirections.
- MacRumors / iClarified / palera1n.com (**2026-08-07/08**): Dopamine 3.0
  release; iOS 26.0–26.0.1 support on A12/A13; palera1n ranges; Serotonin =
  TrollStore 2 + roothide Bootstrap (pangu8.com).
- Verichains analysis via idownloadblog (**2025-03-28**): banking apps using
  sandbox escapes to detect TrollStore/jailbreak — precedent for F6 framing.
- 0xashfaq field notes (undated, retrieved 2026-08): canonical bypass-vector
  taxonomy (stat list, fork test, dyld walk, sysctl, 27042) — used to sanity-
  check vector coverage; note the `fork()` vector is deliberately **not**
  adopted here (crash-prone child reaping in-process; revisit only with
  dedicated design).
