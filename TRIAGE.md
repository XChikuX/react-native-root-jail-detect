# Triage — Post-`0c83306` Audit (`@psync/anti-jailbreak`)

Findings from a full-codebase audit triggered by commit `0c83306`
("fix: refactor PackageManagerProbe to use NitroModules context"), which
replaced fragile `ActivityThread` reflection with
`NitroModules.applicationContext` and added a `SecurityException` catch in the
Kotlin probe. The goal of this audit was to find any remaining issues of the
same class — **detections that silently cannot fire, or silently change
meaning, because of an assumption that does not hold at runtime** — before the
next release.

Scope: all of `cpp/`, `android/`, `ios/`, `src/`, `app.plugin.js`, the
committed `nitrogen/generated/` tree, and `nitro.json`. Cross-checked against
the canonical Nitro patterns (the `build-nitro-modules` skill references and
the upstream `HybridTestObject*` examples they cite) and against the
**installed** Nitro core sources in `node_modules/react-native-nitro-modules`
rather than against docs alone.

Last updated: 2026-08-16 (validated on macOS / Xcode 26.5)

---

## Issue summary

| # | Finding | Severity | Status | Fix |
|---|---------|----------|--------|-----|
| 1 | 5 packages queried by the Kotlin probe were not declared in `<queries>` → silently undetectable on Android 11+ | HIGH | ✅ Fixed | Manifests + plugin aligned with the probe |
| 2 | KernelSU (`me.weishu.kernelsu`) and APatch (`me.bmax.apatch`) had visibility grants but were never queried | HIGH | ✅ Fixed | Added to `knownRootPackages` |
| 3 | `perSchemeSignals: true` silently dropped the URL-scheme score from 15 → 0 and degraded confidence | MEDIUM | ✅ Fixed | Aggregate signal always emitted; per-scheme signals are informational detail |
| 4 | `setDetectionCallback` doc claimed "every detection pass" but only `checkDetailed()`/`assessRisk()` emit | LOW | ✅ Fixed | Doc corrected (no behavior change) |
| 5 | `ObfuscatedString` in `cpp/SignalCatalog.hpp` is dead code (zero call sites) | INFO | 🟡 Open | Left in place; decision needed |

Issues 1 and 2 are two halves of the same drift and are fixed together with a
permanent regression test (`src/__tests__/package-visibility.test.ts`).

---

## Issue 1 + 2 — Android package visibility ↔ probe list drift (HIGH)

**Symptom (silent).** On Android 11+ (API 30+), `PackageManager.getPackageInfo()`
only sees packages the app has visibility into, granted by `<queries>`
declarations in the merged manifest. A query for an undeclared package throws
`NameNotFoundException` **whether or not the package is installed** — the
`catch` that is supposed to mean "not installed, continue" then also swallows
"is installed but invisible". The detection can never fire and nothing logs.

**Evidence.** The Kotlin probe (`HybridPackageManagerProbe.kt`) queried 5
packages that appear in **neither** the library manifest
(`android/src/main/AndroidManifest.xml`) nor the Expo config plugin
(`app.plugin.js`):

- `eu.chainfire.supersu` — SuperSU, one of the most classic root managers and
  explicitly named in `README.md`'s signal table
  (`android.package_manager.root` … "Magisk, SuperSU, KingRoot, etc.")
- `com.noshufou.android.su` (Superuser/ClockworkMod)
- `com.kingroot.kinguser` (KingRoot — also named in the README table)
- `com.koushikdutta.superuser`
- `com.ramdroid.appquarantine`

Conversely, both manifests granted visibility for `me.weishu.kernelsu`
(KernelSU) and `me.bmax.apatch` (APatch) — two of the three most popular
current root managers alongside Magisk — but the probe never queried them, so
the grants were dead weight and the detections were missed.

**Why this is the same class as `0c83306`.** That commit fixed "the probe
cannot reach the platform API it needs" (no `Context`). This is "the probe
cannot see the packages it asks about" (no visibility grant). Both produce the
same failure signature: an `unavailable`-looking empty result, no error, no
signal — on every device, every pass, including every watchdog tick.

**Fix.** All three lists now declare/query the same set:

- `android/src/main/AndroidManifest.xml`: added the 5 missing `<package>`
  entries (bare RN apps get these via the Gradle manifest merger).
- `app.plugin.js`: added the same 5 to the plugin's `Set` (Expo prebuild
  writes them into the app manifest).
- `HybridPackageManagerProbe.kt`: added KernelSU and APatch to
  `knownRootPackages` (root managers → `android.package_manager.root`, weight
  25, same signal as Magisk/SuperSU).

**Regression test.** `src/__tests__/package-visibility.test.ts` parses all
three sources and asserts: every queried package is declared in the manifest,
every queried package is declared by the plugin, the manifest and plugin sets
are identical, and every declared package is actually queried (no dead
visibility grants). Red/green verified: removing one entry fails the suite.
This pins the contract so the lists cannot drift independently again.

---

## Issue 3 — `perSchemeSignals` silently zeroed the URL-scheme score (MEDIUM)

**Symptom.** With `urlSchemes.perSchemeSignals: true`, a responding jailbreak
store contributed **0** to `score` and left `confidence` at `low`; with the
flag `false` (default), the same evidence contributed **15** and could lift
`confidence` to `medium`. Nothing in the docs mentioned scoring.

**Mechanism.** Per-scheme signals use dynamic ids (`ios.urlscheme.<scheme>`)
because the scheme list is caller-configured. Dynamic ids are not in
`SignalCatalog`, so `lookupSignal()` returns `std::nullopt` and `buildSignal()`
in `cpp/IOSChecks.cpp` emitted its fallback placeholder: `score: 0`,
`severity: LOW`, and — worst for consumers grouping by category —
`category: 'debugger'`. At the same time the branch
`if (!context.urlSchemesPerSignal && anySchemeResponded)` suppressed the
aggregate `ios.urlscheme.jailbreak_store` signal, so its weight (15, MEDIUM,
reliability 0.45, category `sandbox`) vanished entirely.

At the default `minScore: 40` a lone store hit does not flip `compromised`
either way, which is why this hid — but `score`, `confidence`, and any backend
policy keyed on signal categories were silently wrong, and a lower `minScore`
could flip the verdict outright.

**Fix chosen — score stability over score inflation.** Two designs were
considered:

1. *Always emit the aggregate; per-scheme signals are informational detail
   (score 0).* The flag becomes purely additive: callers learn **which**
   stores responded, while the score contribution is identical in both modes.
2. *Score each per-scheme signal 15 and keep suppressing the aggregate.* This
   over-counts: a jailbroken device with both Cydia and Sileo (common — modern
   jailbreaks ship both) would score 30 where aggregate mode scores 15, so the
   flag would change the calibration of the check itself.

Option 1 was implemented because toggling a detail flag must not change the
risk score for the same evidence. Concretely, in `cpp/IOSChecks.cpp`:

- The aggregate `ios.urlscheme.jailbreak_store` signal is emitted whenever any
  scheme responds, regardless of the flag.
- Per-scheme detail signals carry `score: 0` but mirror the aggregate's real
  metadata (category `sandbox`, severity `medium`, reliability `0.45`) via
  `lookupSignal(IOS_URLSCHEME_JAILBREAK_STORE)` instead of the debugger
  placeholder.

**Documented behavior change (vs v0.9.2).** The old docs said per-scheme
signals were emitted "instead of" the aggregate; they are now emitted **in
addition to** it. `README.md` and `src/specs/UrlSchemeOptions.ts` were updated
to say so explicitly, and `getDetectionReasons()` now renders the dynamic
per-scheme ids as "The `<scheme>` URL scheme responded to canOpenURL." instead
of leaking the raw id (they cannot be pre-listed in the static reason map).

---

## Issue 4 — `setDetectionCallback` doc overpromise (LOW)

The doc said the callback fires "after every detection pass", but only
`checkDetailed()`/`assessRisk()` emit telemetry — the legacy boolean wrappers
(`isDeviceCompromised()`, etc.) each trigger a native pass without emitting,
and the watchdog's native passes cannot emit into JS at all. Fixed by
correcting the doc comment rather than changing behavior: the legacy wrappers
are frozen by the backwards-compatibility contract, and making them emit would
double-fire for consumers who call both APIs. If broader telemetry is ever
wanted, that is a deliberate API change, not a doc fix.

---

## Issue 5 — `ObfuscatedString` is dead code (INFO, open)

`ObfuscatedString` in `cpp/SignalCatalog.hpp` — including the careful
per-instance-cache repair from `065b24a` that fixed same-length string
aliasing — has **zero call sites** in the entire repo (verified by
`git log -S` and global grep). The shipped binaries do not obfuscate any
literals today. Left in place because removing it is a judgment call: either
delete it, or actually adopt it for the sensitive literal tables
(jailbreak paths, package names, hook patterns). Deciding is out of scope for
this audit; flagged here so the next release makes an explicit choice.

---

## Verified clean — audit coverage and why

These areas were examined in detail and found sound; they are listed so future
audits know the coverage and the reasoning:

- **No remaining reflection/hidden-API hacks.** `Class.forName`,
  `getDeclaredMethod`, `isAccessible`, and `ActivityThread` appear nowhere in
  the repo (post-`0c83306`). The Swift edge's
  `UIApplication.value(forKeyPath: #keyPath(UIApplication.shared))` is *not*
  the same class of hack: `UIApplication.shared` is public API (the KVC dance
  only bypasses the app-extension *compile-time* availability annotation), it
  is nil-guarded, and there is no Nitro-provided alternative.
- **Kotlin/Swift edges match canonical Nitro patterns.** `@Keep` +
  `@DoNotStrip`, correct `com.margelo.nitro.rootjaildetect` package, lazy
  `NitroModules.applicationContext` access (never stored in a field),
  `SecurityException` handled, per-scheme scalar calls across the Swift↔C++
  boundary (the old TRIAGE Issue 3 lesson). Returning `emptyArray()` when the
  context is null — instead of the skill's `throw` recommendation — is a
  deliberate divergence consistent with this package's rule that unavailable
  data is never a detection.
- **Registration and fallback paths.** Verified against the installed core
  (`node_modules/.../HybridObjectRegistry.cpp`): `createHybridObject` throws
  for unregistered names (so the try/catch + no-op-C++-stub fallbacks in
  `AndroidChecks.cpp`/`IOSChecks.cpp` are correct), and duplicate registration
  throws only in `NITRO_DEBUG` builds (so `cpp-adapter.cpp`'s
  `hasHybridObject`-then-register guard is exactly right, including the
  R8-renamed-Kotlin degradation path).
- **Watchdog lifecycle** (`065b24a` fixes in place): strong
  `shared_from_this()` captures in async `start()`/`stop()`, `_startMutex`
  serializing transitions, no lock held during `assessDevice()` or threat
  actions, `_wake.wait_for` releasing `_lifecycleMutex` during sleep so
  teardown joins cannot deadlock, `TERMINATE`/`THROW_EXCEPTION` semantics
  preserved.
- **Resource safety.** `TcpProbe` RAII sockets (loopback-only, 1s per-port
  cap, `SOCK_CLOEXEC` fallback); every `DIR*` in `AndroidProbes.cpp` closed on
  all `break`/`return` paths (`probeMagiskModules`, `probeAddonD`,
  `probeLspdCache`); sandbox-write probes clean up via `ofstream` +
  `std::remove`; `readFileIfExists` is deadline-polled, size-capped, and
  exception-safe; no `popen`/`system` anywhere (PATH checks use
  `access(X_OK)`).
- **Timeout budgets.** Every check in `AndroidChecks.cpp`/`IOSChecks.cpp` is
  deadline-guarded and reports `partial` + an `unavailable` signal rather than
  throwing or overrunning.
- **`nitro.json` ↔ `.nitro.ts` specs ↔ `nitrogen/generated/`** are consistent:
  4 HybridObjects, correct language split (`UrlSchemeProbe` Swift/C++,
  `PackageManagerProbe` C++/Kotlin), Kotlin descriptor path matches the
  package, autolinking cmake/gradle reference the right sources.
- **JS layer.** `src/wrappers.ts` preserves the documented error semantics
  (propagate for `checkDetailed`/`configure`, safe fallbacks elsewhere,
  fire-and-forget watchdog wrappers), and the Jest suite pins them — including
  a test that every cataloged signal id renders a human-readable reason.

---

## Validation performed (all with the changes applied)

| Gate | Result |
|------|--------|
| `bun run typecheck` | ✅ pass |
| `bun run lint` | ✅ pass |
| `bun run test --maxWorkers=2` | ✅ 42/42 (38 pre-existing + 4 new sync tests) |
| `bun run build` | ✅ pass |
| `bun run native-test` (host C++ fixture tests) | ✅ pass |
| `IOSChecks.cpp` full syntax check on the Apple toolchain (`c++ -std=c++20 -Wall -fsyntax-only`, Apple path compiled) | ✅ exit 0 |
| Android release gate `./gradlew app:bundleDebug` (single ABI `arm64-v8a`, example app — compiles the Kotlin probe, merges the manifest, builds all C++ incl. `IOSChecks.cpp`'s Android path, links the bundle) | ✅ `BUILD SUCCESSFUL` |

Red/green check for the new regression test: temporarily removing KernelSU
from the Kotlin probe makes
"every declared package is actually queried by the probe" fail, confirming the
test bites.

## Not validated / follow-ups

- **iOS `xcodebuild` example build not run** in this pass. `IOSChecks.cpp` is
  fully syntax-checked on the Apple toolchain, but the URL-scheme change has
  not been through a full `pod install` + `xcodebuild` cycle. Run it before
  the next release (commands in `CLAUDE.md`).
- **On-device verification** of the PackageManager fixes (a rooted
  KernelSU/APatch device should now produce `android.package_manager.root`)
  and of the per-scheme URL-scheme output (simulator + jailbroken device)
  remains manual device work, per the validation matrix in `CLAUDE.md`.
- **`ObfuscatedString` decision** (Issue 5): remove or adopt.
