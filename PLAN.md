# PLAN.md — Mount-Signal Remediation (v0.12.x → v0.13.0)

> Status: **WS-A/B/C/D/E + WS-G.1/G.2(fallback)/F3.3 IMPLEMENTED (2026-08-25)** ·
> WS-F (on-device measurement) and WS-G.3 (release vehicle) remain OPEN ·
> Created: 2026-08-25 · Scope: `android.mount.denylist_unmount`,
> `android.mount.overlayfs`, and review follow-ups from the v0.12.0 audit.
>
> Implementation notes (deltas from this plan):
> - WS-C shipped the structural variant (Indicator A: ≥2 distinct tmpfs over
>   canonical paths, **any** source) — a strict superset of the v0.12.0 gate,
>   so legacy MagiskHide-era detection is preserved.
> - WS-D: overlayfs `lowerdir` is **colon**-separated (kernel overlayfs docs;
>   Xiaomi fstab evidence), not comma-separated as § WS-E assumed; commas are
>   option separators, handled with unescaped-comma value scanning.
> - WS-G.2: the jsi-inclusive contract test was impractical per the fallback;
>   the drift guard is a Jest field-set assertion on the generated
>   `DetectionSignal.hpp` (`src/__tests__/index.test.tsx`).
> - Adjacent finding: `scanMountsForMagiskChain` counts any `overlay` line,
>   so stock Xiaomi OEM layering can co-fire it at hypothesis weight (5);
>   documented in CLAUDE.md, deliberately not changed here.
>
> Context: external verification of the two mount heuristics added in v0.12.0
> found that both were validated against stale references rather than current
> framework behavior. This plan brings the implementation, documentation, and
> scoring back in line with the repository's own signal-severity policy, and
> establishes the measurement program required before either signal can carry
> its originally proposed weight.

---

## 1. Findings being remediated

### F1 — `android.mount.denylist_unmount` is structurally blind to modern Magisk (severity: HIGH)

**What was built.** The parser (`scanDenyListUnmountFingerprint`,
`cpp/ProcParsers.cpp`) requires **all three** conditions on a
`/proc/self/mountinfo` line:

1. `fstype == tmpfs`
2. mountpoint ∈ {`/system`, `/vendor`, `/product`, `/system_ext`, `/odm`, `/oem`} (exact match)
3. `containsCI(source, "magisk")`

…on **≥ 2 distinct** paths. Shipped at `MEDIUM` / weight **15** / reliability 0.55.

**Why it is wrong.** Condition 3 requires exactly the marker that modern
DenyList removes. Verified against Magisk master (Aug 2026):

- `native/src/core/mount.rs` → `revert_unmount()` selects targets with
  `info.source == "magisk" || info.root.starts_with("/adb/modules")` and
  unmounts every match, including the Magisk tmpfs itself.
- `native/src/core/zygisk/hook.cpp` → denied app processes run
  `revert_unmount()` immediately after `unshare(CLONE_NEWNS)` under the
  `DO_REVERT_UNMOUNT` flag.

Net effect: on official Magisk v24+ (2022 → present) a correctly cleaned
namespace contains **zero** lines satisfying condition 3, so the signal cannot
fire. It only fires on (a) partial-cleanup failures (an inner unmount returns
`EBUSY`) or (b) pre-v24 MagiskHide-era versions (2019–2021).

**Aggravating factors.**

- The in-code comment claims *"newer builds use randomized names [but] the
  mount point coverage itself remains"* — contradicted by condition 3, which
  never matches randomized sources. Comment and code disagree.
- `CLAUDE.md` (consolidated policy section) calls this *"the only mount signal
  that survives DenyList"* — backwards: these mounts are precisely what
  DenyList strips.
- The cited technique (darvincitech/Detecting-Magisk-Hide) dates to
  **Nov 2019**, tested on Magisk v20.1, with a reader-reported fix by v20.4.
- Repository policy states hypothesis signals ship at weight 5–10 and are
  raised only after clean-device false-positive fixtures. This signal shipped
  at 15 without any on-device true-positive fixture.

### F2 — `android.mount.overlayfs` rests on a falsified "never stock" premise (severity: HIGH)

**What was built.** `scanMountsForOverlayFs` fires (weight **15**, MEDIUM,
reliability 0.6) on any line with `fstype ∈ {overlay, overlayfs}` whose
mountpoint **exactly equals** one of the six canonical partitions. Rationale
shipped in code, README, and CLAUDE.md: *"never stock"*.

**Why it is wrong.** Stock, unrooted Xiaomi devices running HyperOS / MIUI
(Android 13/14, bootloader frequently locked) ship overlayfs mounts as part of
the OEM resource-layering architecture. Documented with raw mountinfo evidence
in AnyCheck issue #19 (**2026-06-28**, reproducible across multiple devices):

```
overlay /product/app                lowerdir=/mnt/vendor/mi_ext/product/app:/product/app
overlay /product/priv-app           lowerdir=/mnt/vendor/mi_ext/product/priv-app:/product/priv-app
overlay /system/app                 lowerdir=/mnt/vendor/mi_ext/system/app:/product/pangu/system/app:/system/app
overlay /system_ext/etc/permissions lowerdir=/mnt/vendor/mi_ext/system_ext/etc/permissions:/system_ext/etc/permissions
```

Backing stores `/mnt/vendor/mi_ext/*` and `/product/pangu/*` are part of
Xiaomi's official OTA/dynamic-resource delivery, unrelated to any root
framework. The absolute "never stock" claim is false.

**Why we have not seen field FPs yet.** Accidentally, not by design: Xiaomi's
OEM overlays sit at **subpaths** (`/system/app`), while the parser requires
exact partition-root equality (`/system`). Nothing in code, tests, or docs
acknowledges this knife-edge. Two failure modes follow:

- **Latent FP:** any future ROM that layers an overlay *at* a partition root
  scores 15 on locked, stock devices.
- **Latent FN:** real root frameworks that overlay subpaths or `/`
  (KernelSU / APatch meta-modules commonly do) are missed. The exact match
  simultaneously narrows true-positive coverage and hides the false-positive
  exposure.

(The adb remount / GSI half of the original rationale is verified correct
against AOSP `fs_mgr/README.overlayfs.md`.)

### F3 — Review follow-ups (severity: LOW)

| # | Item | Detail |
|---|------|--------|
| F3.1 | npm-invisible optional peer | `@expo/config-plugins` appears only in `peerDependenciesMeta`. Bun honors meta-only entries (lockfile consistent, frozen install passes); **npm ignores them** unless also listed in `peerDependencies`. Commit `572feac` ("add Expo config plugins as optional peer dependency") is therefore a no-op for npm consumers. |
| F3.2 | Host-test struct drift | `cpp/Scoring.hpp` under `ROOTJAILDETECT_HOST_TEST` hand-declares a stand-in `DetectionSignal`. No mechanism detects drift from the nitrogen-generated struct; a silent field/type divergence would make fixture tests validate fiction. |
| F3.3 | Evidence dedup inconsistency | `scanMountsForOverlayFs` appends every matched path to the evidence string without deduplication; `scanDenyListUnmountFingerprint` dedupes. Cosmetic asymmetry, trivially fixed alongside WS-D. |

---

## 2. Guiding principles (from the existing detection policy)

1. **Signal ids are public contract.** `android.mount.denylist_unmount` and
   `android.mount.overlayfs` will **not** be renamed or repurposed. Weight,
   severity, reliability, detection logic, and documentation may change.
2. **Hypothesis ≠ evidence.** Until a signal has a captured true-positive
   fixture on the intended framework *and* zero false positives on the clean
   corpus, it ships at weight 5–10 with `reliability < 0.8`.
3. **Absence of FPs so far is not absence of FPs.** The Xiaomi case proves
   OEM behavior must be tested explicitly, not assumed.
4. **Never turn inability-to-inspect into detection.** All parser changes stay
   pure functions over fixture strings; unreadable files remain non-findings.
5. **No destructive validation.** Watchdog testing stays in `LOG_ONLY`; the
   measurement program below never exercises `TERMINATE`.

---

## 3. Workstreams

### WS-A — Documentation truthing (P0, docs-only, no behavior change)

Correct every place that currently states something the evidence disproves.

| File | Change |
|------|--------|
| `CLAUDE.md` | Replace the "only mount signal that survives DenyList" bullet with accurate wording: the fingerprint keys on mounts that modern `revert_unmount()` removes; the signal is hypothesis-class pending WS-F measurement. Add the Xiaomi OEM-overlay fact to the mountinfo parsing rules section. |
| `README.md` | Signal-catalog rows: mark both mount signals as *hypothesis / pending device measurement* with their interim weights; soften "never stock" to "not observed stock on AOSP/Pixel/Samsung; **known stock exception: Xiaomi HyperOS/MIUI OEM overlay layers** (see limitation)". Extend the Security Limitations section with the OEM-overlay caveat and the modern-Magisk cleanup caveat. |
| `cpp/ProcParsers.cpp` | Fix the contradictory comments in both scanners (remove the "randomized names still detected" claim; describe what the code actually requires). Comments only — no logic change in this workstream. |
| `src/wrappers.ts` | No change yet — reason strings stay accurate at the current granularity; revisit after WS-C/WS-D land. |

**Acceptance criteria:** grep for "survives DenyList" and "never stock"
returns no unhedged claims; README table matches catalog weights bit-for-bit.
**Validation:** documentation-only checklist from the validation matrix (links,
API names, defaults, platform claims vs. source). No build required.

### WS-B — Interim scoring alignment (P0, small behavior change)

Bring weights in line with policy *before* the rework lands, so no released
build carries unevidenced 15s.

| Signal | Current | Interim target | Rationale |
|--------|---------|----------------|-----------|
| `android.mount.denylist_unmount` | MEDIUM / 15.0 / rel 0.55 | LOW / **5.0** / rel **0.40** | Cannot fire on modern official Magisk (F1). Hypothesis class. Below `android.mount.magisk_chain`'s effective information content. |
| `android.mount.overlayfs` | MEDIUM / 15.0 / rel 0.60 | MEDIUM / **10.0** / rel **0.55** | True positives exist (adb remount, GSI/DSU, KSU/APatch root-level overlays) and no FP is known *at exact partition roots*, but the premise is falsified and coverage is unmeasured. Half-step until WS-D + WS-F. |

Files: `cpp/SignalCatalog.cpp` (+ weight-table in `SignalCatalog.hpp` doc
comment if present), `README.md` table, `CLAUDE.md` policy bullets.

**Acceptance criteria:** catalog lookup returns new weights; existing fixture
tests updated where they assert exact scores; README/CLAUDE.md agree with code.
**Validation:** `bun run native-test` (host fixtures), `bun run typecheck &&
bun run lint && bun run test --maxWorkers=2 && bun run build`, then the
Android example build (detection-behavior change ⇒ native rebuild required).

**Deliberate non-change:** neither signal may become the sole basis for
`compromised = true` at these weights (min-score default exceeds them); assert
this property in `ScoringTests.cpp`.

### WS-C — Rework the DenyList fingerprint parser (P1, detection-logic change)

Replace token-dependent detection with structure-dependent detection.

**New logic (pure function, same signature, same signal id):**

- **Indicator A (structural residue):** ≥ 2 *distinct* canonical system paths
  mounted as `tmpfs` — **regardless of source**. This is the actual residue
  pattern: old MagiskHide left empty tmpfs "stoppers", and incomplete modern
  cleanups leave the same shape with whatever source string the fork/module
  used (including randomized ones).
- **Indicator B (surviving artifacts):** any line whose *source or full line*
  carries a magisk token (bind mounts under `/adb/modules` roots,
  `.magisk`/mirror paths, `magisk` source).
- **Firing rules:**
  - A alone → fire, evidence lists the tmpfs paths.
  - A ∧ B → fire, richer evidence (indicates partial cleanup of an otherwise
    visible framework).
  - B alone → do **not** fire here; explicit-artifact signals already cover it
    at higher weights. Prevents double-counting the same evidence.
- **FP guard:** stock Android does not tmpfs-mount over the six canonical
  partitions (block-backed ext4/erofs/f2fs); work profiles/scoped storage
  tmpfs targets live elsewhere. Keep the six-path allowlist exact-match and
  the ≥2-distinct-paths gate. Re-verify against the clean-device corpus in
  WS-F before any weight increase.

**Expectation setting (documented in README, not hidden):** against official,
correctly functioning Magisk v24+ DenyList, even the structural variant is
expected to be a rare responder — modern cleanup unmounts everything. The
signal's realistic value is sloppy forks (Kitsune variants), third-party
unmount modules, failed EBUSY cleanups, and legacy versions. Say so plainly;
do not market it as DenyList-proof.

Files: `cpp/ProcParsers.cpp` / `.hpp`, `cpp/tests/ProcParsersTests.cpp` +
`DenyListFingerprintTests.cpp`, `cpp/ScoringTests.cpp`, README row.

**Acceptance criteria:**
- Fixture: two bare-tmpfs-over-system lines with source `debug_ramdisk` /
  random hex → fires (this is the behavioral change vs. v0.12.0; pin it).
- Fixture: one tmpfs line, one duplicate of the same path → no fire.
- Fixture: magisk-token bind lines only → no fire from this scanner.
- Fixture: mixed partial-cleanup corpus → single deduplicated finding with
  combined evidence.
- Existing Xiaomi/clean fixtures (WS-E) produce no fire.
**Validation:** full TS suite + `native-test` + Android native build.

### WS-D — Overlayfs lowerdir/upperdir classification (P1, detection-logic change)

Make the OEM-vs-user distinction explicit instead of relying on accidental
mountpoint equality.

**Parser extension (still pure, fixture-driven):**
`parseMountinfoLine` gains extraction of the super-options tail (fields after
`source`), from which the scanner pulls `lowerdir=`, `upperdir=`, `workdir=`.

**Classification rules for an overlay line:**

| Condition | Result |
|-----------|--------|
| Mountpoint exactly a canonical partition **and** any `lowerdir`/`upperdir` component is user-writable-backed (`/data/...`, `/storage/...`, `/sdcard/...`) | Fire — strongest form (meta-module / overlayfs-module root). Candidate for HIGH after WS-F; interim MEDIUM 10→15 only post-measurement. |
| Mountpoint exactly a canonical partition, all components block/vendor-backed, **no** user-writable component | Fire at interim weight (developer remount / GSI class) — unchanged semantics, now justified by inspection instead of assertion. |
| Known OEM backing prefixes (`/mnt/vendor/mi_ext/`, `/product/pangu/`, plus a documented, extensible list) in **every** component | Suppress entirely — stock OEM layering. Log-free, non-finding by design. |
| Subpath mountpoints (`/system/app`, …) | Still never fire (unchanged exact-root rule) — but now as a *documented decision* with the Xiaomi corpus as the reason, not an accident. |

The OEM prefix list lives next to the parser with a comment citing the
AnyCheck #19 evidence and instructing that additions require a corpus sample.

Files: `cpp/ProcParsers.{hpp,cpp}`, `cpp/AndroidChecks.cpp` (no call-site
change expected), tests, README row + limitations, `src/wrappers.ts` reason
string if evidence wording improves triage.

**Acceptance criteria:** every rule row above has a pinned fixture using the
verbatim Xiaomi lines from issue #19 (must produce **no** finding), a
`/data`-backed overlay at `/system` (fires), and a plain `overlay /system
overlay ro` remount-style line (fires). Evidence string deduplicates (fixes
F3.3).
**Validation:** TS suite + `native-test` + both native example builds
(cross-platform file compiles on iOS too).

### WS-E — Fixture corpus hardening (P1, test-only, prerequisite for WS-F sign-off)

Grow the host-side suite into the authoritative regression net:

1. **Clean-corpus fixtures** (must yield zero mount signals): synthetic
   stock-Pixel mountinfo (dm-linear ext4 system, erofs vendor, apex binds),
   stock-Samsung shape, **stock-Xiaomi HyperOS shape including the four
   verbatim issue-#19 overlay lines**, emulator (AOSP) shape including its
   usual extra tmpfs mounts outside the six-path list.
2. **Rooted-corpus fixtures**: Magisk magic-mount namespace (pre-cleanup),
   Magisk post-`revert_unmount` namespace (asserts the honest
   expected-negative for our own signal), Kitsune-style partial cleanup,
   KSU meta-overlayfs at `/`, APatch kernel-overlay shape.
3. **Adversarial parsing fixtures**: optional-field permutations
   (`shared:`/`master:`/`propagate_from:`/`unbindable` in varying counts)
   around `-`, overlay lines with escaped commas in `lowerdir=`
   (comma-separated dirs use `\,` escaping — parser must split on unescaped
   commas only), CRLF input, truncated final line, >1000-line input within the
   read budget cap.

Each fixture gets a one-line provenance comment (real device, date, source).
Fixtures derived from third-party bug reports cite the issue URL.

**Acceptance criteria:** `bun run native-test` runs green with the expanded
corpus; corpus files reviewed for absence of real personal data (paths only).

### WS-F — On-device measurement program (P1 execution / P2 completion)

The gate that decides whether interim weights rise, hold, or the signals get
parked. Follows the open item already recorded in CLAUDE.md.

**Instrumentation.** Extend the example app with an opt-in diagnostics screen
(watchdog strictly `LOG_ONLY`): dumps the parsed `CompromiseAssessment` plus
the raw `/proc/self/mountinfo` lines that matched any scanner predicate, and
exports them as a local JSON file via the share sheet. Read-only, off the JS
thread, no network. This turns every volunteer device into a corpus sample.

**Matrix.**

| Class | Targets | Purpose |
|-------|---------|---------|
| Clean | Pixel (stock), Samsung One UI (stock), **Xiaomi HyperOS 14/15 (stock)**, AOSP emulator | FP rate; Xiaomi is the mandatory case |
| Magisk | Latest stable, DenyList enforced on the example app; same + Shamiko (whitelist mode); ZygiskNext-on-KSU | FN confirmation for F1 rework; TP hunt for partial-cleanups |
| Other root | KernelSU (incl. meta-overlayfs module), APatch, Kitsune fork | Overlay + structural-residue TPs |
| Modified env | `adb remount` session, GSI boot | overlayfs TP at weight-10 tier |

**Decision gates (record results in README compatibility/measurement notes).**

- Signal may return to (or exceed) its pre-audit weight only when: **zero**
  clean-corpus FPs **and** ≥ 1 reproducible TP on the intended framework,
  captured as a committed fixture.
- Zero TPs after the full matrix → keep at hypothesis weight, keep the
  honest-limitations wording, and say so publicly. A quiet signal is better
  than a fictional one.
- Any clean-corpus FP → suppress path/class immediately (WS-D suppression
  list), drop reliability below 0.8 per policy, add the fixture.

**Exit artifact:** a short measurement appendix (device, OS, framework
version, verdict per signal) committed under `docs/` or folded into README —
so the next audit starts from evidence, not folklore.

### WS-G — Housekeeping (P2)

1. **F3.1 npm-visible optional peer.** Move `@expo/config-plugins` into
   `peerDependencies` as `"*"` while keeping
   `peerDependenciesMeta["@expo/config-plugins"].optional = true`.
   Regenerate `bun.lock`; confirm `npm view @psync/anti-jailbreak peerDependencies`
   shows it post-publish. Verify `app.plugin.js` degrades gracefully when the
   consumer lacks the package (it is optional, after all). Also close the
   standing CLAUDE.md open item: align the peer range story (`>=0.35.10` open
   range vs README `<0.37.0` vs compat table `~0.35.1`) in the same edit.
2. **F3.2 stand-in drift guard.** Attempt a `ROOTJAILDETECT_CONTRACT_TEST`
   translation unit compiled on host with `-I` into
   `node_modules/react-native-nitro-modules/cpp` +
   `nitrogen/generated/shared/c++`, asserting the stand-in's field-for-field
   agreement with the generated `DetectionSignal` (`offsetof`/type traits).
   If the transitive jsi include web makes this impractical, fall back to: a
   named `struct HostDetectionSignalShape` comment block mirroring the
   generated header **plus** a CI grep asserting the generated header still
   declares the exact field set the stand-in mirrors. Either way the failure
   mode becomes loud instead of silent.
3. **Release vehicle.** Ship WS-A+B(+G.1) as **0.13.0** together with WS-C/D/E
   once green — they are one coherent behavioral correction; splitting docs
   from behavior would publish a README describing weights the code doesn't
   have. Native gates per release policy: `release:preflight` then
   `release:android`; pods hook refreshes `Podfile.lock` post-bump.

---

## 4. Sequencing

```
WS-A (docs) ─┐
WS-B (weights) ─┼─► single PR #1: stop-the-bleeding (docs + scoring truth)
              ┘        └─ validated by: TS suite + native-test + android build

WS-C ─┐
WS-D ─┼─► PR #2: parser reworks + WS-E fixtures (one reviewable unit)
WS-E ─┘        └─ validated by: TS suite + native-test + both native builds

WS-F ► measurement campaign with the diagnostics screen (PR #3: instrumentation;
       results land continuously afterwards)
WS-G ► PR #4: housekeeping + release 0.13.0
```

PR #1 may ship independently if timeline pressure demands it — it restores
policy compliance with near-zero risk. PR #2 changes detection output and
must not precede its fixtures.

## 5. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Structural-residue rule (WS-C) fires on unknown OEM tmpfs quirks | Six-path exact allowlist + ≥2-distinct gate retained; Xiaomi/emulator clean fixtures mandatory; weight stays 5 until WS-F signs off |
| OEM prefix list (WS-D) becomes whack-a-mole | List is suppression-only (fails closed toward *fewer* detections, never more); additions require a corpus sample; subpath mounts never fire regardless |
| Lowerdir comma-escaping edge cases misparse | Dedicated adversarial fixtures (`\,` splitting) in WS-E before the classifier ships |
| Score drops break consumers who tuned `minScore` around 15-weight signals | Both signals were additive context, not sole triggers; changelog must call out the weight deltas explicitly; README documents the interim values |
| Measurement program stalls (no device access) | Emulator + GSI + adb-remount legs need no exotic hardware and already bound the overlay signal; Magisk-on-emulator covers DenyList mechanics; physical Xiaomi leg is the only truly mandatory borrow |
| Stand-in contract test drags in unbuildable jsi graph | Timeboxed attempt; documented fallback keeps the failure mode loud via CI grep |

## 6. Explicit non-goals

- No renaming/reusing `SignalId`s; no new signals born from this plan without
  passing the same WS-F gates.
- No anti-bypass arms race beyond honest documentation (a determined user with
  root can always defeat userspace heuristics; README already recommends
  layered server-side controls).
- No Play Integrity / key attestation work — remains paired with the deferred
  server-side effort as recorded in CLAUDE.md.
- No watchdog behavior changes; all measurement uses `LOG_ONLY`.

## 7. References (with dates — recheck before acting)

- Magisk `native/src/core/mount.rs` `revert_unmount()` — source-keyed target
  selection (master, retrieved Aug 2026).
- Magisk `native/src/core/zygisk/hook.cpp` — `DO_REVERT_UNMOUNT` invocation
  post-`unshare(CLONE_NEWNS)` (master, retrieved Aug 2026).
- Magisk docs `details.html` — MAGISKTMP layout, mirror/rootdir binds.
- AOSP `system/core/fs_mgr/README.overlayfs.md` — adb remount overlay
  mechanics (living document).
- AnyCheck issue #19 (2026-06-28) — stock Xiaomi HyperOS/MIUI overlay lines
  backed by `/mnt/vendor/mi_ext` and `/product/pangu`.
- darvincitech, "Detecting Magisk Hide" (2019-11-04; readers report fix in
  Magisk v20.4) — historical context only; **not** a valid basis for current
  behavior.
- XDA (2026-03) — KernelSU meta-module overlayfs usage in the wild.
