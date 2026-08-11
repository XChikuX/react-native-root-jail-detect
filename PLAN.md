# PLAN — Closing the Detection Gap vs. Native Root Detector

> **Created:** 2026-08-11
> **Status:** Implemented (2026-08-11) — Phases 1, 2, 4, and 5 shipped; Phase 3 deferred by design. See the "Shipped deltas vs. proposal" table below for weight and rule deviations.
> **Reference:** [`reveny/Android-Native-Root-Detector`](https://github.com/reveny/Android-Native-Root-Detector) v6.x–v7.7.0
>
> **Context — what is and isn't public:** The Kotlin/UI layer is open source, but the actual detector is shipped as a prebuilt, **closed native `.so`** that is not in the repository. The native algorithm is therefore **not** verifiable from the repo. What *is* public, and therefore authoritative, is:
> - `app/src/main/res/values/strings.xml` and its translations — these are the **user-visible labels** the app emits when a check fires.
> - The release notes for each tag — these describe **historical feature areas** in plain language.
> - The user's own report of which labels fire on their device.
>
> Everything below the surface (specific syscalls, file paths, anon-VMA heuristics, property cross-checks, etc.) is an **informed hypothesis** about how the closed detector might produce those labels. Hypotheses must be validated against fixtures and on-device behavior before they earn a high severity/weight. Until then they ship as **low-weight corroboration**, never as the sole basis for `compromised = true`.
>
> **Reading legend used in §1.2 and §2:**
> - ✅ **Evidence** — directly visible in the public repo (strings, manifest, release notes) or reported by the user.
> - 🔬 **Hypothesis** — a plausible implementation of the closed `.so`; not verified, may be wrong, must be tested before high-severity scoring.

---

## Implementation status (2026-08-11)

**Shipped:** Phases 1, 2, 4, and 5. The full set of proposed Android static and runtime probes is implemented in shared C++ (`cpp/ProcParsers.*`, `cpp/AndroidProbes.*`, `cpp/AndroidChecks.cpp`), the PackageManager edge HybridObject carries the three-method split (root / hiding / risky), Nitro bindings were regenerated with nitrogen `0.36.1`, and the example app renders categories, a module-tree notice, and a property-consistency section. The default `timeoutMs` is now **600 ms** (`cpp/DeviceRiskAssessment.hpp`, `src/specs/RootJailDetectOptions.ts`, README).

**Shipped deltas vs. proposal** (per this plan's own severity policy — 🔬 items land low until fixtures justify more):

| Plan item | Proposed | Shipped |
| --- | --- | --- |
| §1.1 anon-VMA threshold/rule | "feature set, refine by fixtures" | Count of executable anonymous VMAs ≥ 2 → `android.maps.anon_injection` (low, 10) |
| §1.2 Zygisk variants | maps/metadata fingerprints | Property-presence candidates only (`ro.zygisk.*`, `ro.rezygisk.version`, `persist.zygisk.assistant`) (low, 5 each) |
| §1.3 modules | medium 15/20 | low 10/10/10; unreadable tree → `android.check.modules` unavailable signal |
| §1.5 hosts writable | medium 15 | low 5 |
| §1.6 inconsistencies | low 10 | low 5 (`inconsistent_*`), low 10 (`magisk.disable_prop`) |
| §1.7 custom ROM / Lineage | medium 15/20 | low 10/10 (provenance signal, not root proof) |
| §1.8 PackageManager HMA | medium 20 | medium 15; risky stays low 5; root list expanded; `<queries>` + Expo plugin updated |
| §1.9 LSPosed cache | high 25 | low 10 (presence ≠ active hook) |
| §2.1 system-dir write | high 30 | high 30 (as proposed — should never succeed on stock) |
| §2.3/2.4 cmdline/PATH | medium 20/15 | low 10/10/5 (shell/PATH visibility is hookable) |
| §2.5 mount chain | medium 15 | low 5 (conservative layered-candidate rule) |
| §1.10 SELinux spoofed | do not ship | **Not shipped**, as recommended |
| §3 Play Integrity / attestation / keybox | deferred | **Deferred** — unchanged |

**Remaining gaps (measurement, not implementation):** per-variant Zygisk memory fingerprints, anon-VMA FP fixtures on stock devices, and on-device validation of module-tree readability on the target LineageOS 16.2 + Magisk stack. Whether the evidence-backed signals cross `minScore = 40` on that device is a measurement, not a guarantee.

---

## 1. Does the library do what it's supposed to do?

### TL;DR — **No, not on modern Magisk/Zygisk setups.** It catches the easy stuff (root paths, props, classic su), but it misses almost every signal that *reveny's* detector catches on a denylist-enabled Zygisk-Assistant + Tricky Store + Play Integrity Fix stack.

### What works today (positive cases the library catches)

The shipped Android scored baseline correctly fires when the user has any of the following:

- `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su` reachable → `android.su.binary` (low, 10)
- `/data/adb/magisk`, `/data/adb/modules`, `/data/data/com.topjohnwu.magisk` reachable → `android.root_manager.dir` (medium, 20)
- `Magisk`, `KernelSU`, `APatch`, `/data/adb` strings in `/proc/self/mountinfo` or `/proc/self/mounts` → `android.mount.magisk` (high, 35)
- `zygisk`, `lsposed`, `xposed`, `frida`, `libriru` strings in `/proc/self/maps` → `android.maps.zygisk` / `.lsposed` / `.frida` / `.riru` (high, 30)
- `/sys/fs/selinux/enforce` = `0` → `android.selinux.permissive` (high, 25)
- `ro.build.tags` = `test-keys`, `ro.boot.verifiedbootstate` = `orange|unlocked`, `goldfish|ranchu|sdk_gphone` emulator properties → `android.build.test_keys`, `android.bootloader.unlocked`, `android.emulator`
- Frida / SSH / ADB listening on 127.0.0.1:27042 / :22 / :44 / :5037 → `android.network.frida` / `.ssh` / `.adb`
- TracerPid ≠ 0 in `/proc/self/status` → `android.debugger.tracerpid`
- Sandbox write to `/data/local/tmp/su_check.txt` succeeds → `android.sandbox.write`
- A known Magisk/SuperSU/KingRoot package installed via PackageManager → `android.package_manager.root`

On iOS it covers classic jailbreak paths, rootless prefixes (`/var/jb`, `/private/preboot/jb`), Dopamine/palera1n-specific markers, TrollStore persistence, MobileSubstrate/Substitute/libhooker/ellekit/rosalie in `_dyld`, jailbreak-store URL schemes, and the sandbox write probe.

### What the user is reporting (and what reveny's app catches)

> *"On LineageOS 16.2 with Magisk + Zygisk Assistant + Tricky Store + Play Integrity Fix [INJECT], no denylist. Root Detect fires 'Boot Integrity signals' and 'Other signals'. This library does not."*

Mapping each reveny label to (a) what is publicly evidenced and (b) what we hypothesize, and where we stand today. Severity proposals below are **starting points for fixtures**, not commitments.

| reveny label | ✅ Evidence (public) | 🔬 Hypothesis (must be validated) | Our coverage today |
| --- | --- | --- | --- |
| `detected_magisk` / `detected_kernelsu_magisk` | Public label indicates Magisk/KernelSU evidence. | Candidate inputs: mount metadata, known paths, properties, package visibility, and/or process-memory artifacts. Exact mix unknown. | ⚠️ **Partial** — we match selected mount/path artifacts but not the broader candidate surface. |
| `detected_zygisk` / `detected_zygisk_official_magisk` / `detected_zygisk_next` / `detected_zygisk_assistant` | Public labels show **variant-specific** Zygisk reporting. | Variant fingerprints are not published in this repo; anon-VMA / module-metadata / property probes are all candidates, not confirmed mappings. | ⚠️ **Partial** — a few library-name tokens; no validated variant detector. |
| `found_injection` | Public label indicates generic in-process injection evidence. | Executable anonymous mappings, loaded-image names, and thread/socket artifacts are candidate signals; FP rate on stock devices unknown until measured. | ❌ **Missing.** |
| `detected_lsposed` | Public label indicates LSPosed evidence. | On-disk config/module dirs and loaded-image tokens are candidates; presence ≠ active hook. | ⚠️ **Partial** — we match `lsposed` in `/proc/self/maps`; we do not inspect module/config dirs. |
| `detected_magisk_module` | Public label indicates a Magisk module was found. | `/data/adb/modules/<id>/module.prop` is the canonical layout, but **ordinary apps are frequently not permitted to enumerate this path**; unreadable ≠ clean, readable ≠ universal. | ❌ **Missing.** |
| `suspicious_mount_detected` / `detected_mount_inconsistency` / `detected_mount_abnormality` / `umount_detected` / `detected_overlay_mounted` / `overlay_mounted_but_mount_may_be_hidden` / `detected_overlayfs` | Public labels indicate mount-based evidence across several sub-conditions. | Cross-namespace diffs vs `/proc/1/mountinfo` are a candidate, but `/proc/1/mountinfo` is **commonly unreadable** to untrusted apps, and legitimate mount differences exist on stock/OEM images. | ⚠️ **Partial** — `scanNamespaceOnlyMountArtifacts` exists but is documented as mostly dead code on production devices. |
| `detected_root_app` | Public label indicates a known root-management app is installed. | Specific package list is partly evidenced by other open-source detectors (RootBeer's `Const.java`) and can be cross-checked. | ⚠️ **Partial** — PackageManagerProbe has 6 entries; more exist in the wild. |
| `detected_risky_app` | Public label indicates "risky" (but not necessarily root) app installed. | Package lists vary by detector; informational-only by policy. | ❌ **Missing** (separate, lower-weight category). |
| `detected_hide_my_applist` | ✅ **User reports HMA installed**; public label confirms HMA is a target. | Package-visibility probes are candidate signals but HMA's entire purpose is to defeat them — a negative result is not clean. | ❌ **Missing.** |
| `detected_root_solution` | ✅ **User pasted `/system/addon.d/99-magisk.sh`**; public label matches. | Addon.d / install-recovery.sh presence is a well-known persistence marker and is directly testable. | ❌ **Missing.** |
| `detected_modified_hosts_file` | Public label indicates hosts-file modification. | Writability/modification heuristics are candidates; ad-blockers and VPN apps can produce similar state on non-root devices → FP risk. | ❌ **Missing.** |
| `detected_resetprop` | Public label indicates resetprop-related evidence. | Cross-property *inconsistency* is a candidate signal; **legitimate custom ROMs and OEM builds can also disagree**, so inconsistency is corroboration, not proof. | ⚠️ **Partial** — we read `ro.debuggable`, `service.adb.root`, `ro.secure` independently without cross-checking. |
| `detected_abnormal_boot_state` | Public label indicates boot-integrity evidence. | Verified-boot + vbmeta property cross-checks are candidates; exact decision rule not public. | ⚠️ **Partial** — `ro.boot.verifiedbootstate` only. |
| `vendor_sepolicy_contains_lineage` / `detected_custom_rom` / `detected_lineageos` | ✅ **User is on LineageOS 16.2**; public labels confirm ROM identification is a target. | `ro.lineage.*`, `ro.build.display.id`, sepolicy strings are documented ROM markers; low FP on production builds but high FP on legitimate custom ROMs (which is the point). | ❌ **Missing.** |
| `detected_custom_kernel` | Public label indicates non-stock kernel. | `/proc/version` / `uname` heuristics are candidates; FP rate on OEM kernels unknown. | ❌ **Missing.** |
| `detected_gapps` | Public label indicates GApps presence/absence. | Flavor/Play-Store path heuristics are candidates; informational-only. | ❌ **Missing.** |
| `detected_framework_patch` | Public label indicates framework patching. | Fingerprint/description mismatch is a candidate; needs fixture validation to avoid OEM FP. | ❌ **Missing.** |
| `debug_fingerprint_detected` | Public label indicates a debug fingerprint. | `test-keys` + `userdebug` + fingerprint-vs-description mismatch are candidates. | ⚠️ **Partial** — `test-keys` only. |
| `tee_is_broken` | Public label indicates a TEE/attestation result. | Exact semantics unavailable; should only be reported via validated attestation, not guessed. | ❌ **Missing.** Hardware-backed; deferred. |
| `keybox_revoked_by_google` | Public label indicates a revoked-keybox result. | Requires trusted attestation chain and current revocation data; **not guessable from local state**. | ❌ **Missing.** Server-side. |
| `key_attestation_failed` | Public label indicates failed key attestation. | Requires actually running attestation; result semantics not in repo. | ❌ **Missing.** |
| `detected_leaked_keybox` | Public label indicates leaked-keybox evidence. | Should be implemented only via validated attestation + server policy, not local string matching. | ❌ **Missing.** Server-side. |

### The miss-cause stack

The fundamental gap is that **our current Android baseline is a narrow heuristic model**: it looks at fixed files, fixed props, and fixed `/proc` tokens that the user can hide, and it does not validate the broader candidate surface that other detectors report against. Concretely we do not currently implement (or have only partial implementations of):

1. **Anonymous-VMA injection — 🔬 hypothesis.** Executable anonymous mappings are a *candidate* signal for in-process injection (Zygisk/Riru/LSPosed). They are **not unique to injection** (JIT and runtime mappings can look similar), so any anon-VMA heuristic must be fixture-tested for FP rate before it can carry high weight. We should not claim it is a universal or unmaskable fingerprint.
2. **Mount inconsistency — 🔬 hypothesis.** Cross-namespace diffs vs `/proc/1/mountinfo` are a *candidate* signal, but `/proc/1/mountinfo` is commonly unreadable to untrusted apps, and legitimate mount differences exist on stock and OEM images. Treat as corroboration, not proof.
3. **Module manifests — mixed.** Magisk modules normally ship a `module.prop`, but ordinary apps are frequently not permitted to enumerate `/data/adb/modules/`. An **unreadable** directory must never be reported as a clean result or as proof of compromise; only a **successfully read** module list counts as evidence.
4. **Custom-ROM fingerprints — ✅ evidence.** Documented ROM markers (`ro.lineage.*`, `ro.build.display.id` patterns) are public and the user is confirmed to be on LineageOS 16.2. Low FP risk on production stock builds; high FP on legitimate custom ROMs (which is the intended semantic).
5. **System-attribute consistency — 🔬 hypothesis.** Cross-checking `ro.debuggable`, `ro.build.type`, `ro.secure`, `ro.boot.verifiedbootstate`, and `ro.boot.vbmeta.device_state` is a *candidate* resetprop/Shamiko signal, but legitimate custom ROMs and OEM builds can also disagree. Inconsistency is corroboration, not proof.
6. **App-based hostile hiding — ✅ evidence (presence), 🔬 hypothesis (interpretation).** HMA (`com.tsng.hidemyapplist`) is confirmed installed on the user's device. Its presence is a useful signal. However HMA's purpose is to defeat package enumeration, so a **negative** package query must never be treated as clean.
7. **Server-attested keys — ✅ evidence (gap).** `enablePlayIntegrity` exists as a config flag but token acquisition is unimplemented. Without server verification we **cannot** make any trustworthy claim about keybox revocation or attestation failure. Any local "leaked keybox" string match would be unsafe.

---

## 2. Plan — implement the missing signals

### Phase 1 — fill the static-detection gap (no hardware, no JNI extensions) — ✅ shipped

**Goal:** On a LineageOS 16.2 device with Magisk + Zygisk Assistant + Tricky Store + Play Integrity Fix, this library's `checkDetailed()` should fire at least one high-severity signal per class the user's paste mentions, ideally producing a `score ≥ 40` so the default `compromised = true`.

**Scope:** All C++/Kotlin changes live in shared `cpp/` and edge HybridObjects. No new HybridObject types (we already have `PackageManagerProbe`; we extend it). No public TypeScript surface change beyond adding new signal ids and reasons.

**Estimated scope:** ~14 new signal ids, ~6 new pure parser helpers, ~3 Android-only probes. ~700 LOC C++, ~250 LOC Kotlin, ~50 LOC TypeScript reasons table, ~30 LOC new tests.

#### 1.1. Maps: anonymous-VMA injection scanner (🔬 hypothesis — validate before high weight) — ✅ shipped as low-weight corroboration

**File:** `cpp/ProcParsers.cpp` — add a new pure function `scanMapsForAnonymousInjection(mapsContent)` and call it alongside `scanMapsForHooks`.

**Why this is only a hypothesis:** Executable anonymous mappings occur legitimately (JIT runtimes, ART, GPU buffers). They can also be produced by Zygisk/Riru/LSPosed. The FP rate on stock devices is **not yet measured**, so this signal must ship as **low-weight corroboration** until fixtures establish a stable detection rule. Do not describe it as a universal fingerprint.

**Candidate algorithm (to be refined by fixtures):**
```text
Parse /proc/self/maps. For each executable anonymous mapping, record
(addr-range, perms, size,pathname). Do not flag on a single mapping;
build a small feature set (count, sizes, adjacency to known images,
ABI/SDK context) and only emit a signal once fixtures define a rule
with an acceptable FP profile on stock devices.
```

**Severity proposal (NOT a commitment):** Start at `android.maps.anon_injection` (low, weight 10, category=INJECTION). Raise only after fixture data justifies it.

**Relationship to `K_HOOK_PATTERNS`:** Library-name matchers remain the **primary** signal because their FP rate is already characterized. The anon scanner is additive corroboration, not a replacement.

#### 1.2. Maps: Zygisk-Assistant / Zygisk-Next / ReZygisk / JingMatrix discrimination (🔬 hypothesis — research-first) — ✅ shipped as property-presence candidates only

**File:** `cpp/ProcParsers.cpp` and `cpp/AndroidProbes.cpp` — only after §1.1 is validated.

**Why this is research-first:** The closed `.so`'s variant-classification algorithm is not public. The bullets below are **candidate** fingerprints, not confirmed ones. Each must be reproduced against a known-good fixture for that variant before it can map to its own signal id.

- **Official Magisk Zygisk** — investigate whether stable markers exist in maps or in loaded images. Do **not** assume a "nearest preceding region" rule.
- **Zygisk-Assistant** — investigate module metadata under `/data/adb/modules/zygisk-assistant/` where readable; an **unreadable** path must not be reported as evidence of absence or presence.
- **Zygisk-Next** — investigate properties (e.g. `ro.zygisk.next.version`) and loaded-image names; ship only fingerprints confirmed against fixtures.
- **ReZygisk** — investigate properties and loaded-image names; ship only fingerprints confirmed against fixtures.
- **JingMatrix** — candidate match via the LSPosed family tokens already in the catalog; needs confirmation.

**Proposed signal ids (only after validation; starting weights are low):**
- `android.zygisk.variant.official` (low, weight 10, category=INJECTION)
- `android.zygisk.variant.assistant` (low, weight 10, category=INJECTION)
- `android.zygisk.variant.next` (low, weight 10, category=INJECTION)
- `android.zygisk.variant.rezygisk` (low, weight 10, category=INJECTION)

#### 1.3. Modules tree: `/data/adb/modules/<id>/module.prop` enumeration — ✅ shipped (unreadable → `android.check.modules` unavailable)

**File:** `cpp/AndroidProbes.cpp` — add `probeMagiskModules()`. Reads `/data/adb/modules/` directory listing using `opendir`/`readdir`, opens each `module.prop` and parses `name=`, `version=`, `author=`. Emit one signal per module under a *category*-emitting signal; for well-known hiding/root modules, emit a *specific* high-severity signal.

**Why this matters:** `/data/adb/modules/` is the canonical Magisk module layout. The user's report names modules (`Zygisk-Assistant`, `Tricky Store`, `Play Integrity Fix [INJECT]`) that conventionally live there, **but we have not confirmed they are enumerable from the app's UID on the user's device**. This probe's value depends entirely on that readability — see the permission note below.

**New signal ids (proposed; weights are starting points):**
- `android.modules.magisk` (medium, weight 15, category=PACKAGE) — `/data/adb/modules/` was readable and non-empty.
- `android.modules.hiding` (medium, weight 20, category=PACKAGE) — a known hiding module name was read from `module.prop` (e.g. `zygisk-assistant`, `shamiko`, `magiskhide`).
- `android.modules.spoofing` (medium, weight 20, category=PACKAGE) — a known spoofing module name was read (e.g. `playintegrityfix`, `tricky_store`).

> **Permission note:** all three signals must be emitted only when the underlying `opendir`/`open` succeeded. A denied/NULL result is an `unavailable` signal, never evidence.

#### 1.4. `/system/addon.d/` and `/system/bin/install-recovery.sh` probe — ✅ shipped

**File:** `cpp/AndroidProbes.cpp` — add `probeAddonD()` and `probeInstallRecovery()`. These are Magisk-persistence markers; the user pasted `/system/addon.d/99-magisk.sh`.

**Proposed signal ids (evidence-backed, but a single path hit must not be the sole reason `compromised = true`):**
- `android.addon_d.magisk` (medium, weight 20, category=FILESYSTEM) — Magisk persistence script present (`/system/addon.d/99-magisk.sh` or any `*.sh` in `/system/addon.d/`). Low FP on stock devices.
- `android.install_recovery` (low, weight 10, category=FILESYSTEM) — `/system/bin/install-recovery.sh` present. Weaker because the file exists on stock Android too; only its *contents* (Magisk-modified) are strong evidence, and we should not `open()` arbitrary system scripts without measuring FP first.

#### 1.5. Hostname / hosts-file probe — ✅ shipped at low weight

**File:** `cpp/AndroidProbes.cpp` — add `probeHostsFile()`. Reads `/system/etc/hosts` and checks for non-empty entries pointing at 127.0.0.1 or 0.0.0.1 (ad-blocking is normal; we *don't* flag that). We *only* flag if `/system/etc/hosts` is writable by the app UID (via `access(W_OK)`) — that's a system tampering signal.

**New signal ids:**
- `android.hosts.writable` (medium, weight 15, category=FILESYSTEM) — `/system/etc/hosts` is writable to the app (system tampering).

#### 1.6. Build-property inconsistency cross-check (🔬 hypothesis — corroboration, not proof) — ✅ shipped via pure parser + `probeSystemAttributes()`

**File:** `cpp/AndroidProbes.cpp` — extend `probeBuildProperties()` (do **not** replace it; keep the existing single-prop signals for backwards compatibility) with an additional findings list whose evidence strings describe specific *inconsistencies*.

**Why this is a hypothesis:** Cross-property inconsistencies are **not unique to Magisk/Shamiko/Tricky Store/PIF**. Custom ROMs, OEM builds, and developer devices can all produce the same disagreements. Inconsistency is **corroboration**, not proof. The signal must ship at low/medium weight and never be the sole basis for `compromised = true`.

**Candidate inconsistency rules (each needs fixture validation):**
- `ro.debuggable=0` but `ro.build.type=userdebug` — candidate Shamiko fingerprint.
- `ro.debuggable=1` but `ro.secure=1` — candidate half-spoof.
- `ro.boot.verifiedbootstate=green` but `ro.boot.vbmeta.device_state=unlocked` — candidate vbmeta/boot disagreement.
- `ro.build.fingerprint` contains `release-keys` but `ro.build.tags=test-keys` — candidate cross-prop spoof.
- `ro.build.fingerprint` contains `user` but `ro.build.type=userdebug` — candidate partial spoof.
- Magisk-internal props leaking: `persist.magisk.hide`, `ro.magisk.disable`, `init.svc.magisk_daemon`, `init.svc.magisk_pfs` (these are stronger because they are Magisk-specific, but still corroboration).

**Proposed signal ids (starting weights; raise only after FP profile is known):**
- `android.props.inconsistent_debuggable` (low, weight 10, category=PROPERTY)
- `android.props.inconsistent_verifiedboot` (low, weight 10, category=PROPERTY)
- `android.props.inconsistent_fingerprint` (low, weight 10, category=PROPERTY)
- `android.magisk.disable_prop` (medium, weight 15, category=PROPERTY) — Magisk-specific prop leaking; stronger than the cross-prop checks above but still not proof on its own.

> **Do NOT claim** that this "is the exact technique that detects Tricky Store / Play Integrity Fix." It is a candidate signal that may fire on those setups; whether it fires reliably on the user's specific stack must be measured.

#### 1.7. Custom-ROM and LineageOS detection — ✅ shipped

**File:** `cpp/AndroidProbes.cpp` — add `probeCustomRom()`. Reads:
- `ro.lineage.version`, `ro.lineage.display.version`, `lineage.version`
- `ro.crdroid.version`, `ro.evolution.version`, `ro.pixelexperience.version`
- `ro.build.display.id` — match against `/lineage_/`, `/crdroid_/`, `/EvolutionX_/`, `/pixel_/`
- `ro.build.flavor` — match `gapps*`, `vanilla*`, `foss*`
- `ro.modversion`

**New signal ids:**
- `android.custom_rom` (medium, weight 15, category=SIGNATURE) — Custom ROM detected (carries the ROM name in evidence).
- `android.lineage` (medium, weight 20, category=SIGNATURE) — LineageOS detected (carries the version in evidence).

#### 1.8. PackageManager: hostile / hiding module enumeration — ✅ shipped (spec split + regenerated bindings + `<queries>`/Expo plugin)

**File:** `android/src/main/java/com/margelo/nitro/rootjaildetect/HybridPackageManagerProbe.kt` — extend `knownRootPackages` map. Add the missing roots and add new categories.

**New map:**
```kotlin
knownRootPackages = mapOf(
  // Original (kept)
  "com.topjohnwu.magisk" to "Magisk",
  "eu.chainfire.supersu" to "SuperSU",
  "com.noshufou.android.su" to "Superuser",
  "com.kingroot.kinguser" to "KingRoot",
  "com.koushikdutta.superuser" to "Superuser",
  "com.ramdroid.appquarantine" to "App Quarantine",

  // Additions for the missing roots
  "com.thirdparty.superuser" to "Superuser",
  "com.yellowes.su" to "YellowesSU",
  "com.zhiqupk.root.global" to "ZhiQuPK",
  "com.alephzain.framaroot" to "Framaroot",
  "com.kingo.root" to "KingoRoot",
  "com.smedialink.oneclickroot" to "OneClickRoot"
)

hostileHidingPackages = mapOf(
  "com.tsng.hidemyapplist" to "Hide My Applist",
  "org.meowcat.edxposed.manager" to "EdXposed Manager",
  "com.solohsu.android.edxp.manager" to "EdXposed Manager",
  "de.robv.android.xposed.installer" to "Xposed Installer",
  "com.saurik.substrate" to "MobileSubstrate",
  "org.lsposed.manager" to "LSPosed Manager",
  "io.github.lsposed.manager" to "LSPosed Manager",
  "com.zachspong.temprootremovejb" to "TempRootRemove",
  "com.amphoras.hidemyroot" to "Hide My Root"
)

riskyApps = mapOf(
  "com.koushikdutta.rommanager" to "ROM Manager",
  "com.dimonvideo.luckypatcher" to "Lucky Patcher",
  "com.chelpus.luckypatcher" to "Lucky Patcher",
  "com.blackmartalpha" to "BlackMart Alpha",
  "org.blackmart.market" to "BlackMart",
  "com.xmodgame" to "Xmodgames",
  "com.cih.game_cih" to "GameCIH",
  "cc.madkite.freedom" to "Freedom",
  "com.ramdroid.appquarantinepro" to "App Quarantine Pro"
)
```

**New signal ids (Kotlin side):**
- `android.package_manager.root` (already shipped) — keep, but expand the list.
- `android.package_manager.hma` (medium, weight 20, category=PACKAGE) — HMA / Xposed / Substrate / LSPosed manager package **detected by PackageManager**. Note: HMA's purpose is to defeat this exact probe, so a negative result is **not** clean.
- `android.package_manager.risky` (low, weight 5, category=PACKAGE) — Risky app installed (informational; presence is not root evidence).

> **Don't claim "this will fire on the user's device"** without measurement. HMA may hide itself from PackageManager, in which case the signal is correctly absent — that absence is not evidence of a clean device.

**API change:** Extend `getInstalledRootPackages()` → split into `getInstalledRootPackages()`, `getInstalledHidingPackages()`, `getInstalledRiskyPackages()`. Each returns `string[]`. The C++ side calls all three.

This requires updating the `.nitro.ts` spec, regenerating, and updating `HybridPackageManagerProbeSpec.kt` / `cpp/HybridPackageManagerProbe.cpp`. See §4 for the cross-cutting change.

#### 1.9. Maps: LSPosed `.lspd` cache signature — ✅ shipped at low weight

**File:** `cpp/AndroidProbes.cpp` — add `probeLspdCache()`. For each `/data/user/0/*/cache/lspd*`, `/data/adb/lspd/`, `/data/adb/modules/lsposed/` directory, emit `android.lsposed.cache`. Also stat `/data/adb/modules/lsposed/module.prop`.

**New signal ids:**
- `android.lsposed.cache` (high, weight 25, category=HOOK) — LSPosed cache or module directory present.

#### 1.10. SELinux cross-check (🔬 hypothesis — do not infer `spoofed` from circumstantial signals) — ✅ done: existing probe retained, `selinux.spoofed` **not** shipped

**File:** `cpp/AndroidProbes.cpp` — retain the existing kernel-backed `/sys/fs/selinux/enforce` probe unchanged (it is already evidence-backed).

**Do not ship** an `android.selinux.spoofed` signal based on "SELinux says enforcing AND bootloader unlocked AND anon-VMA present". That combination can occur on legitimate custom-ROM devices, so inferring spoofing from it would be a false-positive generator. If a stronger SELinux signal is wanted, it must be backed by a **reproducible contradiction** (e.g. SELinux userspace tooling reporting one state while the kernel reports another) and validated by fixtures first.

#### 1.11. Wire all of the above into `runAndroidChecks` — ✅ shipped

**File:** `cpp/AndroidChecks.cpp` — extend the orchestration:

```text
After ANDROID_CHECK_MAPS:   also call scanMapsForAnonymousInjection + scanMapsForZygiskVariant
After ANDROID_CHECK_ROOT_PATHS: also call probeMagiskModules + probeAddonD + probeInstallRecovery + probeLspdCache
After ANDROID_CHECK_PROPERTIES: replace probeBuildProperties with probeSystemAttributes (new)
New section ANDROID_CHECK_HOSTS: probeHostsFile
New section ANDROID_CHECK_ROM:   probeCustomRom
After PackageManager:           call getInstalledHidingPackages and getInstalledRiskyPackages
```

**Deadline budget impact:** Resolved — the default was raised to `timeoutMs = 600` (see §3.5, shipped). Module enumeration is additionally deadline-aware (`probeMagiskModules(deadline)`) and capped at 128 entries.

---

### Phase 2 — sandbox-escape / advanced runtime checks (🔬 mostly hypothesis) — ✅ shipped (2.1, 2.3, 2.4, 2.5); 2.2 held

> **Severity policy across the whole plan:** every proposed weight in this document is a **starting point for fixture testing**, not a commitment. The only signals that should ship at the weights shown here without additional validation are the ones explicitly marked ✅ **evidence** (Addon.d path, LineageOS markers, the existing library-name matchers, the existing `/sys/fs/selinux/enforce` probe). Everything else lands at **low weight** (5–10) and is raised only after FP data justifies it. A single new signal must never be the sole reason `compromised = true` until it has been measured on a clean device.

#### 2.1. Better sandbox-write probe — ✅ shipped (`android.sandbox.write.system_dir`, high 30)

Current probe writes to `/data/local/tmp/su_check.txt`. `/data/local/tmp/` is app-writable on many stock devices too, so a successful write there is weak evidence. **A successful write to `/system/` / `/vendor/` / `/product/` is much stronger**, because those should never be writable by an untrusted app. Keep the existing `android.sandbox.write` signal for the existing probe; add a separate, higher-weight signal only for the system-dir variant.

**Proposed signal id:**
- `android.sandbox.write.system_dir` (high, weight 30, category=SANDBOX) — Successfully wrote to a system directory. (This is one of the few Phase 2 candidates that is close to evidence-backed because the write should never succeed on a stock device; still validate before shipping.)

#### 2.2. `setprop` self-check (🔬 hypothesis — high FP risk) — ⏸️ held, not shipped

Attempt `__system_property_set("ro.test.anti_jb", "1")` then read it back. **This signal is risky:** it can be blocked by SELinux on legitimate stock devices and may succeed on some custom ROMs, so the FP/FN profile is unknown. Ship at low weight or hold until fixtures establish the rule.

**Proposed signal id (only after validation):**
- `android.props.writable_ro` (low, weight 10, category=PROPERTY)

#### 2.3. `app_process` / `am` exec fingerprint — ✅ shipped at low weight (`which su` / `which magisk` via bounded local command probe)

Try `Runtime.exec("which su")`, `Runtime.exec("which magisk")`. Capture exit code. If `which su` returns a path → `android.cmdline.su_exec`. If `which magisk` returns a path → `android.cmdline.magisk_exec`.

**New signal ids:**
- `android.cmdline.su_exec` (medium, weight 20, category=PROCESS) — `which su` returned a path.
- `android.cmdline.magisk_exec` (medium, weight 20, category=PROCESS) — `which magisk` returned a path.

#### 2.4. `PATH` introspection — ✅ shipped at low weight

Read `getenv("PATH")` in native code (Android `__system_property_get` is for props; for env vars we use `getenv`). If `PATH` contains `/sbin`, `/product/bin`, `/system_ext/bin`, `/data/adb/...` — those are Magisk-injected paths.

**New signal ids:**
- `android.env.path_magisk` (medium, weight 15, category=PROCESS) — `$PATH` contains Magisk-injected directory.

#### 2.5. Mount-loop detection — ✅ shipped as conservative layered-candidate rule (low 5)

The user's paste includes suspicious `/product/bin` and `/debug_ramdisk` paths. Read `/proc/self/mountinfo` and walk the *parent* chain for each suspicious mount — Magisk mounts a chain `magisk → /sbin → /system → /product`. The chain depth itself is a fingerprint.

**New signal ids:**
- `android.mount.magisk_chain` (medium, weight 15, category=MOUNT) — Suspicious mount chain depth (≥3 layered overlays).

---

### Phase 3 — server-attested checks (high-impact, deferred infra work) — ⏸️ deferred, unchanged by this implementation

#### 3.1. Play Integrity token acquisition

**File:** `android/src/main/java/com/margelo/nitro/rootjaildetect/HybridPlayIntegrityProbe.kt` — new edge HybridObject. Calls `PlayIntegrity.getClient(...).requestIntegrityToken(...)` with a caller-supplied nonce. Returns the JWS to JS.

**Public API change:** Add a `PlayIntegrityProbe` HybridObject spec to `src/specs/`. The `configure()` options.enablePlayIntegrity flag actually wires this up.

**Out of scope here** — this is a large enough change to deserve its own PR.

#### 3.2. Key Attestation (hardware-backed)

**File:** `android/src/main/java/com/margelo/nitro/rootjaildetect/HybridAttestationProbe.kt` — generate an attestation certificate chain via `KeyGenParameterSpec` + `KeyStore`. Pass the chain to the server for verification.

#### 3.3. Suspected leaked keybox fingerprint

Once Play Integrity is wired, server-side comparison against a published revoked-keybox list.

---

### Phase 4 — example app demo updates — ✅ shipped (within the existing `DetectionSignal` shape)

**File:** `example/src/App.tsx` — extended the result card to show categories, `unavailable` state, a "Module Tree" notice when module signals fire, and a "Property Consistency" section rendering redacted evidence for `android.props.inconsistent_*`. Layout otherwise unchanged.

#### 4.1. Module list renderer — ⚠️ adapted

A full `name`/`version`/`author` table requires structured data that `DetectionSignal` does not carry (only a redacted `evidence` string). Shipped form: a Module Tree section appears when `android.modules.*` fires and directs developers to `configure({ includeEvidence: true })` for redacted detail. A structured module list is an additive result-shape change and belongs in a follow-up.

#### 4.2. Inconsistency table — ✅ shipped (adapted)

The Property Consistency section lists each fired `android.props.inconsistent_*` id with its redacted evidence string (e.g. `ro.debuggable=0/build_type=userdebug`) instead of a raw 2-column property table — the property snapshot is not part of the public result shape.

#### 4.3. Anon-VMA count — ✅ shipped via evidence

`android.maps.anon_injection` evidence carries `executable-anonymous-mappings=<n>`; the signals list renders it when `includeEvidence` is enabled.

---

### Phase 5 — test updates — ✅ shipped

**File:** `src/__tests__/index.test.tsx` — extend mock coverage:

1. Test that `android.maps.anon_injection` appears in reasons when mock returns it.
2. Test that `android.package_manager.hma` appears in reasons when mock returns HMA packages.
3. Test that `android.modules.magisk` reason is human-readable (not just the id).
4. Test the new `getInstalledHidingPackages()` / `getInstalledRiskyPackages()` methods are called from `AndroidChecks`.
5. Test the inconsistency cross-check fires with a mock props set.

**File:** `cpp/ProcParsers.hpp` — add pure unit-testable functions:
- `parseMapsForAnonymousInjection(mapsContent)` — pure, fixture-testable with synthetic maps text.
- `parseMagiskModulesProps(modulesPropsText)` — pure parser for `module.prop` files.
- `parseSystemAttributeInconsistencies(props)` — pure cross-check logic.

**File:** `cpp/ProcParsers.cpp` — implement these as free functions, then test via host-side C++ binary or via Jest's `child_process` invoking a tiny test harness.

#### 5.1. Native fixture tests — ✅ shipped

`cpp/tests/ProcParsersTests.cpp` covers: anon-VMA cluster detection, `libzygisk.so` maps hook match, multi-document `module.prop` parsing, system-attribute inconsistency rules, mount-chain candidate detection, and `SignalCatalog` weight lookup. Runs via `bun run native-test` (host C++20 binary compiled with `-DROOTJAILDETECT_HOST_TEST`, which stubs the generated enum headers so `ProcParsers`/`SignalCatalog` link without Nitro). Jest additionally covers human-readable reasons for every new signal id (38 tests total). Note: Jest mocks the root HybridObject and cannot observe `AndroidChecks` → PackageManager calls; item 4 of the list above is covered by compile-time integration via the Android Gradle build instead.

---

## 3. Cross-cutting changes (any phase that adds a new signal)

### 3.1. New signal ids in `cpp/SignalCatalog.hpp` (and lookup table in `SignalCatalog.cpp`)

All new ids must be added to `SignalId` namespace AND `lookupSignal()` with appropriate severity/weight/category/reliability. Signal ids are **public contract** — never rename an existing one; always add new ones.

### 3.2. New human-readable reasons in `src/wrappers.ts`

`signalReasons` map must include every new id. Missing entries fall back to the raw id, which is bad UX.

### 3.3. README "Signal Catalog" table updates

Add a row per new id with severity, weight, description. Keep weights aligned between the table and the C++ `lookupSignal()`.

### 3.4. CLAUDE.md updates

Add the new helpers to the "Architecture and behavior" section, the "Coding style / C++" rules, and the "Watchdog caution" callouts if any new helper runs on a background thread.

### 3.5. Recommended `timeoutMs` default — ✅ shipped

`timeoutMs` default is now **600** (was 400) in `cpp/DeviceRiskAssessment.hpp`, documented in `src/specs/RootJailDetectOptions.ts` and README. `minScore = 40` unchanged.

### 3.6. Nitrogen codegen regeneration

Any new edge HybridObject method (`getInstalledHidingPackages`, `getInstalledRiskyPackages`) requires:
- Update `src/specs/PackageManagerProbe.nitro.ts`
- `bun run specs` (regenerates `nitrogen/generated/`)
- Commit the regenerated `nitrogen/generated/` tree

---

## 4. Cross-platform impact

### Android — primary impact

Everything above is Android-only. No iOS or watchOS code changes.

### iOS — minor updates needed

- Add the new Android signal ids to `src/wrappers.ts` `signalReasons` map. The iOS path will not *produce* them but the wrappers should be defensive.
- Update README to clarify which signals are Android-only.

### No TS API additions

All new signals surface as `DetectionSignal` entries; consumers already filter `signals` array. No new public method is added in Phase 1.

---

## 5. Order of implementation (recommended)

"Confidence" in the table below = how evidence-backed the signal is, not how impactful it would be if validated. Start with the highest-confidence, lowest-FP-risk items; treat the hypothesis-led items as research tasks with fixture gates.

| Order | Phase | Confidence | Why |
| --- | --- | --- | --- |
| 1 | **1.4** Addon.d / install-recovery.sh | ✅ evidence | User-pasted path; well-known marker; trivially testable; low FP. |
| 2 | **1.7** Custom-ROM / LineageOS markers | ✅ evidence | User confirmed on LineageOS 16.2; documented ROM props; low FP on stock. |
| 3 | **1.8** Hostile-package PackageManager (HMA et al.) | ✅ evidence (presence) | User-pasted `com.tsng.hidemyapplist`. Note HMA can hide itself; absence is not clean. |
| 4 | **1.6** Magisk-internal prop leak (`ro.magisk.disable`, `persist.magisk.hide`) | ✅ evidence | Magisk-specific props; low FP. Start with **only** these; defer the cross-prop inconsistency rules (🔬) until fixtures. |
| 5 | **1.3** Magisk modules tree enumeration | mixed | High value if `/data/adb/modules/` is readable; **unreadable must mean `unavailable`, not clean**. |
| 6 | **1.1** Maps anon-VMA scanner | 🔬 hypothesis | Needs FP fixtures on stock devices before any weight > low. |
| 7 | **1.9** LSPosed cache / module dir | 🔬 hypothesis | Useful corroboration; presence ≠ active hook. |
| 8 | **1.6** Cross-prop inconsistency rules | 🔬 hypothesis | Custom ROMs / OEM builds can disagree legitimately; corroboration only. |
| 9 | **1.2** Zygisk variant discriminator | 🔬 hypothesis | Blocked on §1.1 validation and per-variant fixtures. |
| 10 | **1.5** Hosts-file writable | 🔬 hypothesis | Lower priority; ad-blockers/VPNs cause FP. |
| 11 | **1.10** SELinux spoofed | ❌ do not ship as drafted | Inference from circumstantial signals is unsafe; needs a real contradiction. |
| 12 | **1.11** Wire into `runAndroidChecks` | n/a | Trivial once the chosen helpers exist. |
| 13 | **Phase 2** | 🔬 mostly hypothesis | FP profile unknown; ship at low weight or hold. |
| 14 | **Phase 4** Example app | n/a | Visualisation once the above lands. |
| 15 | **Phase 5** Tests | n/a | Coverage after each shipped item. |
| 16 | **Phase 3** | n/a | Server-attested work is its own PR. |

Each step was implemented with:
- C++ helper + unit fixture
- SignalCatalog entry + README row
- Wrappers.ts reason
- Test
- Native + example build verification

All rows shipped in one pass on 2026-08-11; hypothesis-led items (6–10, 13) deliberately shipped at lower weights than their proposed starting points per the severity policy in Phase 2's preamble.

---

## 6. Out-of-scope (explicitly)

The following are **not** in this plan:

1. **Server-side keybox revocation list** — needs server infra.
2. **Hardware key attestation** — requires Play Integrity infrastructure.
3. **JingMatrix-specific detection beyond LSPosed family match** — the LSPosed family match in §1.2 catches it.
4. **Native injection of our own library** to defend against in-process hooking — would require a parallel watchdog thread (out of scope, deferred to v9.x).
5. **iOS TrollStore-per-app persistence** — already shipped.
6. **Detecting Frida-gadget that runs *outside* the app's process namespace** — out of band; can't be detected by an app-scoped heuristic.
7. **Code obfuscation / anti-tampering of the library itself** — this is a hardening concern beyond detection. Separate plan.

---

## 7. Risks and tradeoffs

1. **False positives.** Every new signal carries a FP risk. Mitigations:
   - Keep weights conservative (don't go above 30 for single-condition signals).
   - Cross-checks (inconsistency between props, anon-VMA + bootloader unlocked) are stronger than individual checks.
   - Mark each new signal with a `reliability < 0.8` if it's known FP-prone.
   - For Shamiko-only scenarios, expect a *higher* FP floor because Shamiko is a defensive root tool. We're OK flagging Shamiko because the user opted in.

2. **Performance.** New probes add ~50-100ms to a single pass. Bump recommended `timeoutMs` default to 600ms.

3. **Permission scope.** The `opendir(/data/adb/modules/...)` probe reads a path that requires `DAC_OVERRIDE` or root. On non-root devices, `opendir` returns NULL and the probe correctly emits an `unavailable` signal. No additional permissions needed.

4. **Compiling.** No new C++ deps. `opendir`/`readdir` are POSIX and already available via `<dirent.h>`. No Kotlin new deps.

5. **Breaking changes.** None. All new signals are additive. No renames of existing ids. No API surface change in Phase 1.

6. **Catalog growth.** Public signal catalog grew from ~38 to ~60 ids (more than the original estimate because Zygisk variants, Phase 2 probes, and `android.check.modules` shipped). Documented in README's Signal Catalog table, with hypothesis flags noted.

---

## 8. Verification

Per-step:
```sh
bun run typecheck && bun run lint && bun run test --maxWorkers=2
bun run build
bun run native-test
bun run turbo run build:android --cache-dir=.turbo/android
# iOS unchanged but verify nothing regressed
bun run turbo run build:ios --cache-dir=.turbo/ios
```

**Results from the 2026-08-11 implementation** (direct Gradle/xcodebuild invocations per CLAUDE.md, not turbo):

- ✅ `bun run typecheck` — clean
- ✅ `bun run lint` — clean
- ✅ `bun run test --maxWorkers=2` — 2 suites, 38 tests pass
- ✅ `bun run build` — bob module + type definitions written
- ✅ `bun run native-test` — parser/catalog fixtures pass
- ✅ Android example: `./gradlew app:bundleDebug -PreactNativeArchitectures=arm64-v8a` — **BUILD SUCCESSFUL** (compiles all `cpp/**` including the new probes, plus the regenerated PackageManager JNI bridge and Kotlin edge)
- ✅ iOS example: `xcodebuild -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17'` — **BUILD SUCCEEDED** (regenerated bindings compile; iOS behavior unchanged)
- ⚠️ `git diff --check` reports trailing whitespace on two blank lines of regenerated `HybridPackageManagerProbeSpec.kt` (nitrogen `0.36.1` template output; not hand-edited)

**Still pending — device measurement** (cannot be done from a workstation): run the example app on the rooted LineageOS 16.2 device and check:
- The ✅-evidence signals fire as expected (Addon.d path, LineageOS markers, `ro.magisk.disable`/`persist.magisk.hide` if present, HMA package if PackageManager can see it).
- `score` moves toward `minScore` (default 40) but **whether it crosses the threshold is a measurement, not a guarantee** — that depends on which evidence is actually present and readable on the device.
- Hypothesis-led signals (anon-VMA, cross-prop inconsistency, module-tree enumeration) fire **only if at all** on the device, and their absence must not be treated as clean.
- The new Module Tree and Property Consistency sections render whatever was actually observed, including `unavailable` rows where probes were denied.

The success criterion is **honesty of the report on the device**, not a forced `compromised = true`. If the evidence-backed signals do not reach `minScore` on the user's setup, the next step is more signals and Play Integrity (Phase 3), not inflating weights.

---

## 9. Summary

**Update (2026-08-11):** Phases 1, 2, 4, and 5 are implemented and validated (builds + fixtures pass on this workstation). The signal catalog grew from ~38 to ~60 published ids; hypothesis-led signals shipped at low weight per this plan's severity policy. What remains is the device measurement described in §8 and the Phase 3 attestation work. The pre-implementation analysis below is retained for context.

The current library is honest about its scope — it is a scored heuristic that catches obvious cases. Against a hardened root setup (LineageOS + Magisk + Zygisk Assistant + Tricky Store + PIF) it falls short of what *reveny's* detector reportedly surfaces, but we must be precise about **why**, because the reference detector's internals are closed:

1. It relies on **file/path** matches that hiding modules can rename or hide.
2. It does not implement several **candidate** signals that plausibly contribute to reveny's labels — anonymous-VMA scanning, `/data/adb/modules/` enumeration, cross-property inconsistency checks — but each of those is a **🔬 hypothesis**, not a known fingerprint. Their FP rates on clean devices are unmeasured.
3. It does not enumerate **hostile packages** like HMA, even though HMA's presence is ✅ evidence on the user's device.
4. It does not detect the user's **custom ROM** (LineageOS 16.2) — a ✅-evidence gap with documented markers.
5. It does not detect the user-pasted **`/system/addon.d/99-magisk.sh`** — also ✅ evidence.

The plan above is therefore split by confidence: **✅-evidence** signals (Addon.d, LineageOS markers, Magisk-internal prop leak, hostile-package enumeration) ship first at sensible weights; **🔬 hypothesis** signals (anon-VMA, cross-prop inconsistency, Zygisk variant discrimination, SELinux spoofing) ship at low weight or behind fixture gates. No breaking API changes; all new signals are additive ids.

This plan narrows the gap with reveny's reported surface area, **but it cannot promise parity** with a closed-source detector whose algorithm we cannot read, and it cannot promise `compromised = true` on the user's specific device — that is a measurement we take after the evidence-backed items land.