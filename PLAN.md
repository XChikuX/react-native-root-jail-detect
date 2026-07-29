# Root/Jailbreak Detection Upgrade Plan

## Goal

Evolve `@psync/anti-jailbreak` from a path-based boolean checker into an Expo-compatible, Nitro-powered, scored device-risk module. The goal is to detect common rooted Android configurations including Magisk + Zygisk + DenyList more reliably, reduce false positives on stock iOS devices, and provide server-verifiable integrity signals.

This is a **full Nitro migration targeting v2.0.0**: New Architecture only, one native bridge, no handwritten Objective-C externs, no TurboModule codegen spec. The existing TurboModule (`src/NativeRootJailDetect.ts`), iOS `RootJailDetect.m` externs, and generated `NativeRootJailDetectSpec` classes are removed.

The package was previously published as `react-native-root-jail-detect`. Version 0.2.1 is published under the `@psync/anti-jailbreak` name.

## Scope and principles

- Treat root/jailbreak detection as risk assessment, not proof.
- Aggregate independent signals; never rely on a single `su` path or package name.
- Keep a simple backwards-compatible boolean API, but make structured results the primary API.
- Prefer native checks for Android process, mount, and memory state.
- Keep checks fast, deterministic, privacy-conscious, and explainable.
- Do not hard-block solely on a weak signal such as debugger attachment or `test-keys`.
- Support Expo through a config plugin and custom dev client/EAS Build; Expo Go cannot load this native module.
- New Architecture only. Nitro requires React Native 0.75+; this library targets RN 0.83. No Old Architecture bridge fallback.

## Non-goals

- Claiming permanent detection of every modified device.
- Treating a debugger as equivalent to jailbreak/root.
- Collecting unnecessary device identifiers or sending raw local paths to a server.
- Building an anti-analysis product that makes development or accessibility tooling unusable.
- Supporting React Native's Old Architecture.

## Public API

### Preserve legacy API

The existing published API remains as thin wrappers over `checkDetailed()`:

```ts
isDeviceCompromised(): Promise<boolean>  // score >= configured minScore
isEmulator(): Promise<boolean>
isDebuggerAttached(): Promise<boolean>
getDetectionReasons(): Promise<string[]> // derived from signal IDs
```

Existing error semantics are preserved: `isDeviceCompromised()` rethrows native errors; the others log and return safe fallbacks. New convenience aliases `isDeviceRooted()` / `isDeviceJailbroken()` may be added, but the published names above are not renamed or removed in v2.

### Primary structured API (shipped)

```ts
export type Severity = 'low' | 'medium' | 'high';
export type Confidence = 'low' | 'medium' | 'high' | 'extreme';
export type Platform = 'android' | 'ios';
// Source of truth: src/specs/SignalCategory.ts. Keep README and PLAN in sync.
export type SignalCategory =
  | 'filesystem'   // root-manager dirs, su binaries, jailbreak artifact paths
  | 'sandbox'      // TrollStore persistence, URL-scheme canOpenURL hits
  | 'mount'        // Magisk overlays, hidden bind-mounts in app namespace
  | 'process'      // cmdline tokens, local sockets, loopback SSH/ADB listeners
  | 'injection'    // Frida/Zygisk/Riru maps artifacts, loopback Frida port
  | 'hook'         // LSPosed/Xposed/MobileSubstrate/Substitute/libhooker/ellekit
  | 'property'     // ro.debuggable, service.adb.root, ro.secure, SELinux state
  | 'package'      // (reserved) PackageManager enumeration of root-manager apps
  | 'signature'    // bootloader unlocked, test-keys, verified boot, emulator
  | 'debugger';    // TracerPid, sysctl P_TRACED, *.check.* availability markers

export type DetectionSignal = {
  id: string;
  platform: Platform;
  category: SignalCategory;
  severity: Severity;
  score: number;
  detected: boolean;
  reliability: number; // 0..1; per-check reliability estimate
  evidence?: string; // Redacted; only when includeEvidence is enabled.
  unavailable?: boolean; // Check could not run; not a detection.
};

export type CompromiseAssessment = {
  platform: Platform;
  compromised: boolean;
  score: number; // 0 to 100
  confidence: Confidence;
  signals: DetectionSignal[];
  debuggerDetected: boolean;
  elapsedMs: number;
  partial: boolean; // True when the total deadline cut off remaining checks.
};

// Deprecated alias kept for backwards compatibility.
export type DeviceRiskResult = CompromiseAssessment;

export type RootJailDetectOptions = {
  minScore?: number;
  timeoutMs?: number;
  includeEvidence?: boolean;
  treatDebuggerAsCompromise?: boolean;
  enablePlayIntegrity?: boolean;
};

export function configure(options: RootJailDetectOptions): void;
export function checkDetailed(): Promise<CompromiseAssessment>;
export function assessRisk(): Promise<CompromiseAssessment>; // alias for checkDetailed()
```

`assessRisk()` is provided as a newer alias for callers that prefer the assessment-oriented name. It resolves to the same native call as `checkDetailed()` and is re-exported from `src/index.tsx`.

Nitro codegen supports string-literal unions and optional struct fields natively, so these types live in `src/specs/` as named types and are re-exported from `src/index.tsx`. `SignalCategory`, per-signal `platform`, `detected`, and `reliability` are additive, optional-shaped fields on the richer signal contract.

### Defaults

- `minScore`: 40
- `timeoutMs`: 400 total budget, with per-check deadlines; overrun checks return `unavailable` signals and set `partial: true` rather than failing the call
- `includeEvidence`: false in release builds
- `treatDebuggerAsCompromise`: false
- `enablePlayIntegrity`: false unless configured

### Signal shape evolution (shipped as additive fields)

The richer per-signal shape originally proposed as a future major-version change has been adopted as **non-breaking additive fields** on `DetectionSignal` rather than a breaking rename:

- `platform` per signal mirrors `CompromiseAssessment.platform` but makes per-signal analytics easier.
- `category` groups signals for backend policy filtering and display. The closed enum is `filesystem | sandbox | mount | process | injection | hook | property | package | signature | debugger` (source of truth: `src/specs/SignalCategory.ts`). Known limitation: `*.check.*` availability markers are currently bucketed under `debugger` because the enum has no dedicated `availability`/`info` value; adding one is a future additive change.
- `detected` makes explicit the previous convention that a non-`unavailable` signal is a positive finding.
- `reliability` `0..1` is a stable per-signal metadata estimate. It is informational and does not replace `score` in aggregation.

`Confidence` now includes `'extreme'`, reserved by the aggregator for passes where multiple high-severity, independent-category signals push the score very high (≳ 80), indicating strong convergence of distinct evidence.

## Risk model

Use weighted, independently generated signals. Cap the overall score at 100 and avoid counting equivalent evidence repeatedly.

| Signal class | Example | Initial score | Notes |
|---|---:|---:|---|
| High | Zygisk/Magisk artifact in mount metadata | 35 | Strong local signal |
| High | Zygisk, LSPosed, Frida, or Riru library mapped in process memory | 30 | Use exact and normalized pattern matching |
| High | SELinux disabled/permissive on production device | 25 | OEM/debug exemptions must be documented |
| High | Local debug/instrumentation TCP service responding | 30 | Loopback-only; short timeout; see Phase 4 |
| Medium | Root manager/kernel-root data directory accessible | 20 | Multi-method native probes |
| Medium | Boot verification unlocked or orange | 20 | Do not treat alone as root |
| Medium | Integrity verdict fails server policy | 30 | Verify only on backend |
| Medium | iOS rootless jailbreak artifact (Dopamine/palera1n-class) | 20 | Validate on physical devices before raising |
| Medium | iOS URL scheme presence (cydia/sileo/zbra/filza) | 15 | Scheme ≠ proof; 50-entry budget cap; see gap #5 |
| Low | `su` executable/path found | 10 | Commonly hidden and easy to hook |
| Low | `test-keys` build tag | 10 | Often legitimate on custom ROMs; whitelist path in Phase 4 |
| Low | Hidden mount-namespace overlay content | 10 | See note below; current impl is dead code, see gap #10 |
| Informational | Debugger/TracerPid | 0 by default | Separate signal from compromise |

**Mount namespaces:** on modern Android, apps legitimately run in their own mount namespace, so a namespace *identity mismatch* (`/proc/1/ns/mnt` vs `/proc/self/ns/mnt`) is expected and must not be a signal by itself. The current `scanNamespaceOnlyMountArtifacts` reads `/proc/1/mountinfo` for comparison, but **this file is unreadable by untrusted apps on stock Android** (PID 1 hides it via SELinux). The signal is effectively dead code in the current path; see gap #10 for the reshaped plan using `statx` and self-namespace diffs.

`compromised` is true when the score meets `minScore`, or when server policy marks an integrity verdict as failed. The host app can choose a stricter or more permissive threshold.

## Architecture

```text
TypeScript API (src/index.tsx barrel + wrappers)
  -> Nitro HybridObjects (nitrogen codegen)
    -> Shared C++ core: scoring, signal catalog, pattern matching, /proc parsing (Android)
    -> Shared C++ platform runners: AndroidChecks.cpp / IOSChecks.cpp
    -> Android edge (future): Kotlin HybridObjects (PackageManager, Play Integrity)
    -> iOS edge (future): Swift HybridObjects (URL schemes, sandbox helpers needing UIKit)
  -> Optional backend attestation verifier
```

### Native core: cross-platform C++

The root HybridObject is implemented in C++ (`{ ios: 'c++'; android: 'c++' }`) so scoring primitives, the signal catalog, deduplication, and pattern matching are shared across platforms in one implementation. Platform-specific work stays in focused C++ helpers today; thin Swift/Kotlin HybridObjects are reserved for APIs that truly require the platform runtime:

- C++: `/proc` parsing (Android), mountinfo/maps pattern matching, scoring and signal aggregation, TracerPid checks, iOS jailbreak paths / `_dyld` / `sysctl`.
- Kotlin (deferred): `PackageManager` queries, Play Integrity token acquisition.
- Swift (deferred): `UIApplication.canOpenURL` and any UIKit-bound probes.
- TypeScript: configuration, typed result shaping, legacy wrapper compatibility, watchdog option defaults.

### Nitro object model

- `RootJailDetect` (root HybridObject, autolinked): `configure(options)`, `checkDetailed(): Promise<CompromiseAssessment>`, sync cheap getters for cached state. Default-constructible.
- `SecurityWatchdog` (separate HybridObject): owns the long-lived background thread and mutable lifecycle state. Created from the root object, exposes `start(options)` / `stop()` / `isRunning`. **The watchdog consumes `checkDetailed()` with the configured threshold** — it must not duplicate boolean detection logic. Existing modes (`LOG_ONLY`, `THROW_EXCEPTION`, `TERMINATE`) and millisecond intervals are preserved on both platforms.
- Named spec types live in their own files under `src/specs/` and are re-exported publicly.

## Implementation status (audit)

### Shipped baseline

The open-source library already implements a substantial scored baseline on both platforms through the shared C++ core:

**Android (Phase 1 — done)**

- Root-manager directories and conventional `su` binaries (`stat(2)` probes).
- Writable / suspicious mount metadata via `/proc/self/mountinfo` and `/proc/self/mounts` (Magisk, KernelSU, APatch, overlays).
- `/proc/self/maps` scan for Zygisk, LSPosed/Xposed, Frida (`frida`, `gum-js-loop`, etc.), Riru.
- SELinux enforce state via `/sys/fs/selinux/enforce`.
- Build/verified-boot properties (`test-keys`, bootloader unlocked, emulator props) via `__system_property_get`.
- Runtime instrumentation: Frida-like cmdline tokens and local unix-socket indicators.
- `TracerPid` as an informational debugger signal (score 0 by default).
- Total `timeoutMs` budget with `unavailable` + `partial` semantics.
- Pure, fixture-testable parsers in `cpp/ProcParsers.*` and aggregation in `cpp/Scoring.hpp`.

**iOS (Phase 1 — done, conservative)**

- Classic jailbreak artifact paths (`/Applications/Cydia.app`, MobileSubstrate, `/var/jb`, `/private/jb`).
- `_dyld` loaded-image scan for MobileSubstrate, Substitute, Frida, libhooker.
- `sysctl` `P_TRACED` debugger state (informational).
- Simulator flag.
- Shared signal catalog + scoring path (same as Android).

**Cross-cutting (done)**

- Nitro HybridObjects, nitrogen codegen, legacy boolean wrappers over `checkDetailed()`.
- Security watchdog background loop consuming the same assessment path.
- Expo config plugin skeleton (`app.plugin.js`) for scoped Android `<queries>`.
- Jest coverage for the TypeScript wrapper layer.

### Gaps and missing checks

Fundamentals are in place, but several modern evasion paths and hardening items remain open. Each item below is scoped to the current architecture (shared C++ first; Swift/Kotlin only when required).

#### 1. Rootless iOS / modern jailbreak indicators — **open (P0)**

Classic paths miss rootless jailbreaks (Dopamine, palera1n rootless) that avoid `/Applications/Cydia.app` and classic MobileSubstrate layouts. As of 2025/2026, Dopamine supports iOS 15–16.6.1 natively with extensions to 17.0–18.7.1; palera1n supports A8–A11 on iOS 15–16.x+ (checkm8-based). Both are rootless by default. Many still leave:

- Rootless prefix trees under `/var/jb`, `/private/preboot/...`, or bootstrap-specific paths beyond the current short list.
- Dopamine bootstrap markers (`/var/jb/.installed_dopamine`, `/var/jb/usr/lib/TweakInject.dylib`).
- Injected or renamed hook libraries not covered by the current `_dyld` token list (ellekit, rosalie, newer Substitute forks).
- Entitlement / sandbox anomalies best probed from a narrow Swift edge if pure filesystem checks are insufficient.

**Note on TrollStore:** TrollStore is **not a jailbreak** — it is a sideloading tool using a CoreTrust bypass ([The Apple Wiki](https://theapplewiki.com/wiki/TrollStore)). It does not provide full filesystem access and does not create jailbreak artifacts. As of 2025, TrollStore does **not** work on iOS 17.1+ or iOS 18+. If included, it should be a separate signal category (`ios.sideload.trollstore`) with appropriate weight, not grouped with rootless jailbreaks.

**Plan:** extend `cpp/IOSChecks.cpp` path and image lists with versioned, documented artifacts; add distinct signal ids (for example `ios.jailbreak.rootless`, `ios.jailbreak.dopamine`, `ios.sideload.trollstore`) rather than overloading `ios.jailbreak.artifact`. Keep weights medium until validated on physical devices. Do not treat a single missing classic path as clean.

#### 2. Frida / instrumentation renaming — **partial**

Android maps already match several Frida-related tokens (`frida`, `frida-agent`, `gum-js-loop`, `gmain`, `linjector`, `pool-frida`). Gaps:

- Renamed gadgets (`libgadget`, `libhelper`, generic `gadget` dylib/so names) need careful, low-FP patterns.
- iOS `_dyld` scan should include common renamed Frida/gadget strings, not only `Frida`.
- Optional deeper memory-region inspection on iOS (`vm_region` / related) only if it stays within the timeout budget and has a clear FP profile.

**Plan:** extend pattern tables in `ProcParsers` and `IOSChecks`; keep one high-weight maps/dyld signal family; dedupe equivalent evidence in scoring.

#### 3. Local network service probes — **open (P1)**

No loopback TCP probes exist today. Compromised devices often expose:

| Port | Typical service | Suggested signal id | Strength | Notes |
|---:|---|---|---|---|
| 22 / 44 | SSH (OpenSSH on jailbroken iOS, Dropbear on Meridian/checkra1n) | `ios.network.ssh` / `android.network.ssh` | High | Standard jailbreak signal; ports 22 and 44 both documented ([ElcomSoft](https://medium.com/@elcomsoft/ios-jailbreaks-ssh-and-root-password-a911441e33a)). |
| 27042 | Frida default | `android.network.frida` / `ios.network.frida` | High | Confirmed default in Frida 17.x (2025); port is changeable via `-l` so absence is not proof of clean. |
| 5037 | ADB | `android.network.adb` | Weak | **ADB server runs on the host machine, not the device.** From an app's perspective, `127.0.0.1:5037` only responds if the device is running `adbd` in TCP mode (rare) or is an emulator. Useful as an emulator indicator, not a root signal. |

**Plan:** new `cpp/TcpProbe.hpp` / `.cpp` with non-blocking connect, short per-port deadline, RAII socket cleanup, **127.0.0.1 / ::1 only**. Wire from `AndroidChecks` and `IOSChecks`. Success (connect or identifiable banner) is a high-weight signal; failure to connect is silence (not a clean bill of health). Never probe non-loopback addresses. Fold into the existing `timeoutMs` budget so a slow localhost stack cannot stall the pass. Weight the ADB (5037) signal low — it mainly catches emulators. P3 may extend the same helper with `meta.tcp.*` banner fingerprints.

#### 4. SELinux and dangerous Android properties — **partial**

Shipped: `/sys/fs/selinux/enforce` → `android.selinux.permissive`. Still useful:

- **Do not rely on `ro.build.selinux`** as a cross-check. This property is unreliable: it can be `0` while SELinux is `Enforcing` ([Magisk issue #1477](https://github.com/topjohnwu/Magisk/issues/1477)) and is frequently empty on production devices ([Stack Overflow](https://stackoverflow.com/questions/18727941/how-do-i-detect-if-selinux-is-enabled-in-an-android-application)). Use it only as a very weak correlation signal, or drop it entirely.
- Additional properties (`ro.debuggable`, `service.adb.root`, `ro.secure`) are real but **hidden by Shamiko** via `resetprop`. They also flag legitimate `userdebug`/`eng` builds (development devices, CI emulators). Treat as low-weight signals with explicit dev-build caveats; never block on them alone.
- Dedupe equivalent SELinux evidence in scoring so the sysfs file and a property cross-check (if added) do not double-count.
- Prefer `__system_property_get` in `AndroidProbes` (already the pattern); do **not** shell out to `getprop` via `Runtime.exec`.

#### 5. iOS URL scheme checks — **open (P1)**

`UIApplication.canOpenURL` for schemes such as `cydia://`, `sileo://`, `zbra://`, `filza://` is not implemented. This requires a thin Swift edge HybridObject (UIKit) called from the C++ runner, plus `LSApplicationQueriesSchemes` entries via the Expo config plugin / app config.

**iOS 15+ constraint:** `LSApplicationQueriesSchemes` is hard-capped at **50 entries** per app ([Cromulent Labs](https://cromulentlabs.wordpress.com/tag/canopenurl/), [Apple Developer Forums](https://developer.apple.com/forums/thread/4650)). This cap is **shared across the entire host app** — not just the library. Host apps may already be using part of their budget for unrelated purposes (payment SDKs, social login, etc.). All schemes beyond the first 50 will silently return `NO` from `canOpenURL`.

**Plan:**
- Declare a **minimal** set of schemes (start with 2–4: `cydia`, `sileo`, `zbra`, `filza`). Exclude lower-value schemes like `undecimus://` and `activator://` to conserve budget.
- Make the scheme list **configurable** so host apps can drop ones they don't want to spend budget on.
- Document the 50-entry cap clearly in the README so adopters can budget correctly.
- Async-safe main-thread hop only if UIKit requires it; cache the result for the duration of one `checkDetailed()` pass; missing scheme registration must yield `unavailable` or no signal, never a false positive.

#### 6. File-read deadlines — **partial**

`readFileIfExists` exists and the Android/iOS runners honor a shared steady-clock deadline, but individual reads are still unbounded syscalls. Under pathological FS latency a single read can burn the whole budget.

**Plan:** extend `readFileIfExists(path, deadline)` (and/or a max-bytes cap) in `cpp/ProcParsers.*`; used by `/proc` and path probes; keep “unreadable or timed out ⇒ no detection / `unavailable`”.

#### 7. String obfuscation — **open (P2)**

Suspicious path and token tables are plaintext in the binary today. A compile-time or build-time obfuscation step for literal tables raises the bar for casual static inspection. Prefer a simple reversible decode at startup over heavy commercial packers; never claim this stops a determined reverse engineer.

#### 8. OEM / benign whitelist — **open (P2)**

Some preview/OEM builds legitimately ship `test-keys` or unusual SELinux states. A small, reviewed allowlist (build fingerprint / model / tags) can suppress specific low-severity signals. Ship as data (JSON or constexpr table), default empty/minimal, and document every entry. Do not silently drop high-severity memory/mount signals via whitelist.

#### 9. Native unit tests — **partial (P2)**

Jest covers wrappers. Pure C++ parsers/scoring are structured for fixtures but host-side native tests are not yet a first-class CI job on all platforms. Add:

- Host-side (or Android instrumented) tests for `ProcParsers`, `Scoring`, SELinux text parsing, and TCP probe state machines with fake FDs where possible.
- Keep device/emulator behavioral checks in the example app and `e2e/matrix.md`.

#### 10. Mount namespace refinement — **partial / broken in practice**

`scanNamespaceOnlyMountArtifacts` today reads `/proc/1/mountinfo` to compare against the app's own mountinfo. **This file is unreadable by untrusted Android apps on stock devices** — the kernel/PID 1 hides it from the app's SELinux domain (confirmed by [gopsutil issue #1159](https://github.com/shirou/gopsutil/issues/1159) and Android SELinux policy for `untrusted_app`). The current code handles the failure gracefully (`readFileIfExists` returns `std::nullopt`), which means the `ANDROID_MOUNT_OVERLAY` signal **effectively never fires on most devices** — it is dead code in the current path.

**Plan:** drop the `/proc/1/mountinfo` comparison in favor of alternatives that work within the app's own namespace:

- Parse the app's `/proc/self/mountinfo` and `/proc/self/mounts` for structured path/content diffs (lines present in one but not the other, suspicious overlay paths, unexpected mount sources) rather than token-only matching.
- Use `statx(2)` with `STATX_ATTR_MOUNT_ROOT` on expected-mount-root paths (e.g. `/data/adb/Modules`) to detect files that are *not* a mount root but should be, or vice versa — Shamiko does not yet hide this attribute.
- Never flag namespace identity mismatch alone. On iOS, unexpected nesting under `/private` remains a research item with high FP risk — gate behind validation.

#### 11. Extended meta.tcp / advanced probes — **open (P3)**

Higher-level loopback HTTP or JNI `Socket.connect` metadata is optional after the basic port probes prove stable. Secure hardware / Play Integrity remains server-attestation work behind `enablePlayIntegrity`.

## Implementation roadmap

### Completed milestones (reference)

1. **Nitro skeleton** — specs, codegen, wrappers, stub-to-real HybridObjects.
2. **Android scored baseline** — mounts, maps, SELinux, properties, paths, runtime sockets/cmdline, TracerPid, scoring + fixtures layout.
3. **iOS Phase 1 + watchdog** — conservative artifacts, dyld, sysctl debugger split, `SecurityWatchdog` over `checkDetailed()`.
4. **Expo skeleton** — root `app.plugin.js`, scoped `<queries>`.

### Summary — what to do next

Canonical work queue. Prefer one row per PR. Every new positive check needs a catalog id, README row, and (for user-visible ids) a `signalReasons` entry in `src/wrappers.ts`.

| Priority | Item | Where it lands | Notes |
|---|---|---|---|
| **P0** | Rootless iOS detection paths and distinct signal ids (Dopamine/palera1n bootstrap, expanded artifacts) | `cpp/IOSChecks.cpp`, `cpp/SignalCatalog.hpp` + `.cpp`, `src/wrappers.ts` (`signalReasons`), README catalog | Do not overload `ios.jailbreak.artifact` forever; add e.g. `ios.jailbreak.rootless`, `ios.jailbreak.dopamine`. TrollStore is a separate category (`ios.sideload.trollstore`) — not a jailbreak. Medium weight until physical-device validated. |
| **P0** | Frida-renamed patterns (`libhelper`, `libgadget`, cautious `gadget` tokens) | `cpp/ProcParsers.cpp` (`K_HOOK_PATTERNS`), mirror tokens in `cpp/IOSChecks.cpp` `_dyld` scan | Keep under existing high-weight Frida/maps/dyld signal families; watch false positives on benign libs named `helper`. |
| **P1** | Loopback TCP port probes (27042 Frida, 22/44 SSH, 5037 ADB) | New `cpp/TcpProbe.hpp` / `cpp/TcpProbe.cpp` (or `LocalPortProbes.*`); wire from `cpp/AndroidChecks.cpp` and `cpp/IOSChecks.cpp`; catalog ids; CMake + podspec sources | `127.0.0.1` / `::1` only; non-blocking connect; short per-port deadline inside total `timeoutMs`; RAII FDs; refused/timeout = no signal. Weight ADB (5037) low — it mainly catches emulators, not physical-device root. |
| **P1** | SELinux property depth (with caveats) | `cpp/AndroidProbes.cpp`, optional fold in `cpp/AndroidChecks.cpp` | `/sys/fs/selinux/enforce` already ships. Do **not** rely on `ro.build.selinux` — it's unreliable (can be `0` when enforcing, often empty). `ro.debuggable`, `service.adb.root`, `ro.secure` are hidden by Shamiko and flag legitimate dev builds; treat as low-weight signals with explicit caveats. Dedupe with `android.selinux.permissive` where equivalent. |
| **P1** | iOS Swift edge HybridObject for `UIApplication.canOpenURL` | New files under `ios/` (currently empty/reserved); Nitro/Swift edge + call from C++ runner; `app.plugin.js` merges `LSApplicationQueriesSchemes` | Schemes: `cydia`, `sileo`, `zbra`, `filza` (start minimal, 4 entries). `LSApplicationQueriesSchemes` is hard-capped at 50 entries shared with the host app; make the scheme list configurable so hosts can drop ones they don't want to spend budget on. Undeclared scheme → no false positive. |
| **P1** | `readFileIfExists` with deadline (and/or size cap) | `cpp/ProcParsers.hpp` / `.cpp` (`readFileIfExists`), call sites in `cpp/AndroidChecks.cpp` | Runner-level deadline exists; individual reads can still stall. Unreadable or timed-out read ⇒ no detection / `unavailable`, never invert to compromise. |
| **P2** | String obfuscation for path/token tables | New `cpp/ObfuscatedString.hpp` (or build-time encode); apply at `K_HOOK_PATTERNS`, mount tokens, iOS path lists | Raises casual RE bar only; do not claim bypass resistance. |
| **P2** | OEM whitelist for benign `test-keys` / unusual SELinux | Small JSON or constexpr table + gate in `cpp/AndroidChecks.cpp` / probes | Low-severity signals only. Document every entry. Never whitelist away maps/mount high signals. |
| **P2** | C++ unit tests for pure logic | `cpp/__tests__/` (or host test target) for `Scoring.hpp`, `ProcParsers`, `SignalCatalog`; keep Jest for `src/wrappers.ts` | Fixture strings already match the pure-parser split. Add TcpProbe state-machine tests with fakes where possible. |
| **P2** | Mount-namespace overlay detection reshaped (path/content diff, `statx`) | `cpp/ProcParsers.cpp` (`scanNamespaceOnlyMountArtifacts`) | Today: known root token in self mountinfo and absent from init; `/proc/1/mountinfo` is unreadable on stock Android. Evolve toward structured path diff and `statx(STATX_ATTR_MOUNT_ROOT)`; **never** flag namespace identity mismatch alone. |
| **P3** | Richer `meta.tcp.*` probes (banner/fingerprint beyond connect) | Extend `cpp/TcpProbe.*`; optional signals from both platform checkers | Only after basic connect probes are stable and FP-reviewed. |
| **P3** | Play Integrity + backend policy | Kotlin edge (deferred), `enablePlayIntegrity`, backend verifier docs | Server verifies token; client score is never authoritative. |
| **P3** | Quarterly artifact/catalog refresh + optional sanitized signal-id telemetry | `SignalCatalog`, README, `e2e/matrix.md` | No raw paths in production telemetry. |

### PR slicing (suggested order)

| PR | Bundles rows above | Primary touch points |
|---|---|---|
| **PR 6** | P0 rootless iOS + P0 Frida rename tokens | `IOSChecks`, `ProcParsers` `K_HOOK_PATTERNS`, `SignalCatalog`, `wrappers.ts` reasons, README, matrix |
| **PR 7** | P1 TCP probes | `cpp/TcpProbe.*`, both checkers, catalog, CMake/podspec, unit tests for connect state machine |
| **PR 8** | P1 SELinux property + debug/adb props | `AndroidProbes`, `AndroidChecks`, catalog/FP notes |
| **PR 9** | P1 `canOpenURL` Swift edge | `ios/*`, nitro autolinking if needed, `app.plugin.js`, docs |
| **PR 10** | P1 deadline-aware `readFileIfExists` | `ProcParsers`, Android (and any shared) readers |
| **Later** | P2/P3 rows | obfuscation, OEM whitelist, native CI tests, mount path-diff, meta.tcp, Play Integrity |

## Android implementation (historical phases)

### Phase 0: repository audit and test harness

1. Inventory all current Android checks, their implementation language, and their false-positive profile.
2. Add a sample React Native app and Expo prebuild sample app.
3. Add a debug-only screen that renders signal IDs, severities, score, and elapsed time; do not display raw sensitive evidence in release builds.
4. Establish a device matrix: stock Android, bootloader-unlocked stock Android, Magisk with Zygisk, Magisk with DenyList, Magisk with common hiding modules, KernelSU, APatch, emulator, and custom ROM.
5. Record expected results in `e2e/matrix.md`.

### Phase 1: scored native baseline — **done**

1. Parse `/proc/self/mountinfo` and `/proc/self/mounts` for root-framework overlays, suspicious bind mounts, and known Magisk/KSU/APatch remnants.
2. Compare mount namespaces only to surface hidden overlay content, never as identity-mismatch proof.
3. Parse `/proc/self/maps` for loaded Zygisk, Riru, LSPosed, Frida, and known hooking-framework artifacts.
4. Check SELinux enforcement state using native file reads.
5. Read relevant verified-boot and debug build properties.
6. Probe root-manager directories and conventional `su` locations through native filesystem APIs.
7. Add `TracerPid` and debugger checks as informational signals.
8. Return all signals through `checkDetailed()`.

### Phase 2: package and runtime checks — **partial**

1. Detect known root-management and hook-management packages through `PackageManager` while treating renamed/hidden apps as expected evasion. (**Kotlin edge — deferred**)
2. Add defensive process, command-line, and local-socket indicators for runtime instrumentation. (**cmdline + unix socket — done**; TCP Frida/ADB — **open**)
3. Enforce per-check deadlines and the total `timeoutMs` budget. (**done at runner level**; per-read caps — **open**)
4. Ensure the implementation works without `QUERY_ALL_PACKAGES`; request only narrowly necessary package visibility entries where possible. (**manifest queries present**)

### Phase 3: resilience and integrity — **open**

1. Optional light self-integrity for native assets.
2. Avoid presenting client self-integrity as authoritative.
3. Integrate Play Integrity token acquisition behind an explicit option.
4. Backend verifies with Google and applies product-specific policy.
5. Bind sensitive API actions to short-lived server-issued session decisions.

### Phase 4: local service and property depth — **open (this plan)**

See roadmap PRs 7–8. Network probes are loopback-only; property expansion stays in `AndroidProbes`.

## iOS implementation

### Correct debugger semantics — **done**

- `debuggerDetected` is diagnostic and must not affect `compromised` by default.
- Enable debugger-based blocking only through `treatDebuggerAsCompromise: true`.
- Exclude expected development workflows where appropriate, including Xcode-attached debug sessions.
- Document the behavior for development, TestFlight, enterprise/MDM, and App Store builds.

### Jailbreak checks

| Item | Status |
|---|---|
| Conservative classic artifact paths | Done |
| Sandbox-boundary write probes | Open (high FP risk; design carefully) |
| Injected dylib / loaded-image names | Done (expand rename list) |
| URL schemes (`canOpenURL`) | Open — PR 9 |
| Rootless / TrollStore-class artifacts | Open — PR 6 |
| Independent signals in `checkDetailed()` | Done |

## Expo delivery

1. Keep the Expo config plugin at the root-level `app.plugin.js` (move under `plugin/src/` only if it grows non-trivial) to configure Android/iOS native project changes during `expo prebuild`.
2. When URL schemes ship, the plugin must merge `LSApplicationQueriesSchemes` safely.
3. Ensure the module works with EAS Build and a custom development client.
4. Fail clearly in Expo Go with an actionable error: native checks require prebuild/custom client.
5. Provide an Expo example app with development and release configuration examples.
6. Nitro requires the New Architecture, which is the only supported mode; no bridge fallback is provided.

## Repository layout

```text
src/
  index.tsx              # Barrel: re-exports wrappers and spec types
  specs/
    RootJailDetect.nitro.ts    # Root HybridObject spec (configure, checkDetailed, getWatchdog)
    SecurityWatchdog.nitro.ts  # Watchdog HybridObject spec (start, stop, isRunning)
    *.ts                       # Named codegen types (CompromiseAssessment, DeviceRiskResult alias,
                               # DetectionSignal, Severity, Confidence, Platform, ProtectionMode,
                               # RootJailDetectOptions, SecurityWatchdogOptions, SignalCategory) —
                               # each in its own file for codegen
  wrappers.ts            # Legacy boolean API over checkDetailed() + lazily-created root handle
cpp/                     # Shared C++ HybridObject implementations + detection core
  HybridRootJailDetect.*
  HybridSecurityWatchdog.*
  DeviceRiskAssessment.*
  SignalCatalog.* / Scoring.hpp
  ProcParsers.* / AndroidProbes.* / AndroidChecks.*
  IOSChecks.*
  TcpProbe.*             # Planned — loopback TCP probes (Frida/SSH/ADB)
android/
  build.gradle           # Android library config (Nitro autolinking + CMake externalNativeBuild)
  CMakeLists.txt         # Builds the RootJailDetect shared library from cpp/
  src/main/AndroidManifest.xml   # Narrow <queries> set for known root-manager apps
ios/                     # Swift edge HybridObjects (URL schemes) — currently empty / reserved
nitro.json               # Namespaces + autolinking entries (root + watchdog, both C++-backed)
nitrogen/generated/      # Codegen output; committed, never hand-edited
app.plugin.js            # Expo config plugin entry (scoped <queries>; future URL schemes)
example/
  src/App.tsx            # Usage demo for both legacy boolean API and checkDetailed()
  android/               # Native example project
  ios/                   # Native example project
e2e/
  matrix.md              # Manual validation matrix for release sign-off
  fixtures/              # Fixture strings for the deterministic /proc parsers
```

Migration notes:

- Delete `src/NativeRootJailDetect.ts`, `ios/RootJailDetect.m`, and the hand-written JNI layer; Nitro generates all bindings.
- `nitrogen/generated/` must be committed and included in the npm `files` field so consumers can build.
- Keep the native library/module registration names stable where consumer-facing; update `System.loadLibrary` and CMake target names together if renamed.

## Documentation

All user-facing documentation lives in `README.md` as the single source of truth. It must cover:

- The full signal catalog: every public signal ID, severity, initial weight, supported platform, evidence-redaction policy, and known false-positive limitations. Do not publish implementation details that make bypassing individual checks trivial; publish enough to let adopters make safe policy decisions.
- The threat model and policy guidance: client-side detection is bypassable; root detection should not be the only authorization control; server-side attestation, short-lived credentials, rate limits, telemetry, TLS pinning where appropriate, and step-up authentication provide layered protection; a rooted power user is not automatically malicious.
- Expo delivery: installation, prebuild, custom dev client, EAS Build, Android manifest/package-visibility needs, Play Integrity setup, and troubleshooting.

Keep `README.md` synchronized with the exported APIs, defaults, signal catalog, and security limitations whenever the public contract changes.

## Testing and acceptance criteria

### Automated tests

- Unit-test `/proc` parsers with fixtures for stock and modified mount/maps samples.
- Unit-test scoring: duplicate/equivalent signals must not inflate scores unexpectedly.
- Unit-test local port probe state machine (connect success/refused/timeout) without requiring a real Frida server when fakes are feasible.
- Instrumentation-test native bridge failures, timeouts, and malformed input.
- Type-test the public TypeScript API.
- Prefer `react-native-harness` E2E tests in a real RN environment for the Nitro API surface.
- Run iOS simulator tests for safe fallback behavior; simulator results must not be interpreted as physical-device integrity.

### Manual matrix

Validate every release on:

- Stock locked Android device
- Stock but bootloader-unlocked Android device
- Magisk + Zygisk
- Magisk + Zygisk + DenyList
- A common root hiding stack
- KernelSU or APatch when available
- Stock iPhone
- iPhone attached to Xcode debugger
- Jailbroken iPhone when available (including at least one rootless profile when possible)
- TrollStore or equivalent sideload profile when available

### Acceptance criteria for v2.0.0 baseline (local scored API)

- A stock locked Android device produces no high-severity root signals.
- A Magisk + Zygisk device that hides `su` still produces one or more meaningful environment or memory-related signals when artifacts remain visible.
- A stock iPhone with an attached debugger reports `debuggerDetected: true` but `compromised: false` under default configuration.
- All checks finish within the default total timeout and never crash on unreadable `/proc` entries; deadline overruns surface as `unavailable` signals with `partial: true`.
- Expo prebuild + EAS Build integration is documented and verified in the example app.
- Watchdog start, duplicate start, stop, and restart behave correctly in `LOG_ONLY` mode and consume the same scoring path as `checkDetailed()`.
- The library never claims that it is impossible to bypass.

### Additional acceptance criteria for post-baseline PRs

- Loopback probes never leave the local host and always respect the shared timeout budget.
- URL scheme checks degrade safely when schemes are not declared in `LSApplicationQueriesSchemes`.
- New rootless signals are validated against at least one physical jailbreak profile or explicitly marked experimental in the catalog docs.
- Whitelist entries, if any, are documented and limited to low-severity property/tag signals.

## Release milestones

### Milestone 1: Nitro migration + reliable local baseline — **complete**

- Nitro spec, codegen pipeline, shared C++ core
- Detailed scored API and legacy wrappers
- Android mounts, maps, SELinux, properties, path probes, runtime indicators, debugger status
- iOS debugger/jailbreak separation + conservative artifacts
- Watchdog as a HybridObject over the scoring path
- Tests, sample app, and detection documentation

### Milestone 2: Expo-ready package — **skeleton present**

- Config plugin
- Expo prebuild and EAS sample
- Clear Expo Go behavior
- URL-scheme plist merging when PR 9 lands

### Milestone 2b: evasion depth (this audit)

- Rootless iOS + Frida rename coverage
- Loopback TCP service probes
- Expanded Android debug properties
- iOS URL schemes
- Read-deadline hardening

### Milestone 3: integrity-backed decisions

- Optional Play Integrity client integration
- Reference backend verifier contract
- FastAPI example endpoint and policy examples

### Milestone 4: ongoing maintenance

- Quarterly test-matrix refresh
- Versioned signal catalog
- Regression tests for new Android releases and commonly used root frameworks
- Optional string-table obfuscation and OEM allowlist maintenance
- Changelog entries describing detection changes and compatibility impact

## Backend integration contract

The mobile client should send a minimal payload to a backend endpoint:

```ts
{
  riskScore: number,
  signalIds: string[],
  integrityToken?: string,
  appVersion: string,
  nonce: string
}
```

The backend must verify the Integrity token directly with the provider, validate the nonce/session binding, and issue a short-lived policy decision. Do not accept client-provided scores or signal IDs as proof of device state.

## Immediate next PRs

Kept small and focused, in order (see **Summary — what to do next** for file-level detail):

1. **PR 6 — Rootless iOS + Frida rename tokens (P0):** `IOSChecks` paths/ids for Dopamine/palera1n (TrollStore as separate category); `K_HOOK_PATTERNS` + iOS `_dyld` renames (`libhelper`, `libgadget`, …); `SignalCatalog` + `signalReasons` + README.
2. **PR 7 — Loopback TCP probes (P1):** new `cpp/TcpProbe.*` for 27042 / 22 / 44 / 5037; wire both platform checkers; high-weight signals (5037 low); budget-aware; state-machine tests.
3. **PR 8 — SELinux property depth with caveats (P1):** skip `ro.build.selinux` (unreliable); add `ro.debuggable` / `service.adb.root` / `ro.secure` as low-weight signals with explicit dev-build caveats in `AndroidProbes`. Document Shamiko hiding in the catalog.
4. **PR 9 — iOS URL schemes (P1):** Swift edge HybridObject under `ios/` for `canOpenURL`; config plugin `LSApplicationQueriesSchemes`; **make scheme list configurable** to respect host app's 50-entry budget; C++ orchestration.
5. **PR 10 — Deadline-aware `readFileIfExists` (P1):** deadline/size caps in `ProcParsers`; call sites honor shared budget without stalling.
6. **Later — P2/P3:** `ObfuscatedString.hpp`, OEM whitelist in `AndroidChecks`, C++ unit tests under `cpp/__tests__/`, `scanNamespaceOnlyMountArtifacts` reshaped (acknowledge `/proc/1/mountinfo` is unreadable on stock Android; use `statx` + self-namespace path diff), `meta.tcp.*`, Play Integrity.

## Security implementation notes for new checks

- Every new heuristic is fallible. Unreadable files, closed ports, and missing URL schemes are **not** proof of a clean device.
- Catch expected access failures narrowly; return no signal or `unavailable`, never invert into compromise without an explicit design.
- Keep boolean wrappers derived from `CompromiseAssessment` so logic stays singular; `DeviceRiskResult` remains a deprecated alias.
- Add a distinct public signal id (and redacted evidence when enabled) for every new positive condition.
- Network probes: loopback only, short timeouts, deterministic FD cleanup (RAII).
- Do not exercise watchdog `TERMINATE` in automated tests; use `LOG_ONLY`.
- Update `SignalCatalog`, README catalog table, example app (when user-visible), and tests together with any new id.

## Conclusion

The Nitro scored baseline covers classic Android root and conservative iOS jailbreak signals, with shared aggregation and a watchdog that cannot drift from `checkDetailed()`. Remaining work targets modern concealment: rootless iOS footprints (Dopamine/palera1n), renamed instrumentation, loopback service exposure, UIKit URL schemes (within the 50-entry budget cap), and hardening/obfuscation.

**Known limitations to carry forward:**
- `ro.build.selinux` is unreliable and should not be used as a cross-check for SELinux enforcement.
- `/proc/1/mountinfo` is unreadable by untrusted apps on stock Android; the current namespace-only mount signal is dead code and must be reshaped to use `statx` + self-namespace diffs.
- ADB port 5037 is a weak signal on physical devices (mainly catches emulators).
- Shamiko hides `ro.debuggable` / `service.adb.root` / `ro.secure` via `resetprop`; these are low-weight, high-FP signals.
- `LSApplicationQueriesSchemes` is capped at 50 entries shared with the host app; URL scheme probes must be minimal and configurable.

Combining filesystem, process, memory, network, and property signals into a fused risk score — rather than a single boolean — remains the design center. Each new check should land as a small PR with catalog ids, timeout safety, and matrix notes; none of this replaces server-side attestation for authorization decisions.
