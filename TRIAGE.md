# Triage — Native Build Failures (`@psync/anti-jailbreak`)

Status of native (fastlane/Gradle/Xcode) build failures encountered while
shipping the `UrlSchemeProbe` Swift HybridObject and the surrounding
C++/Swift/Kotlin glue. Most are fixed and shipped; one Android issue remains
open.

Last updated: 2026-07-30 (validated on macOS / Xcode 26.5)

---

## Issue summary

| # | Error | Status | Fix |
|---|-------|--------|-----|
| 1 | C++ `only virtual member functions can be marked 'override'` (`getMemorySize`) | ✅ Fixed | Renamed to `getExternalMemorySize() noexcept override` in all three HybridObjects |
| 2 | Swift `overriding declaration requires an 'override' keyword` (`init()`) | ✅ Fixed | `public init()` → `public override init()` in `ios/HybridUrlSchemeProbe.swift` |
| 3 | Swift `std__vector_std__string_ has no member 'map'` (generated `_cxx.swift`) | ✅ Fixed | Refactored spec to `canOpenUrl(scheme: string): boolean` — eliminated the `string[]` at the Swift↔C++ boundary |
| 4 | C++ `use of undeclared identifier 'SOCK_CLOEXEC'` (`TcpProbe.cpp`) | ✅ Fixed | `#define SOCK_CLOEXEC 0` fallback (iOS SDK lacks the Linux-only flag) |
| 5 | `HybridRootJailDetect is not default-constructible` / `abstract class` | ✅ Fixed | Added the missing `assessRisk()` override (it is a pure virtual on the generated base) |
| 6 | Android `./gradlew app:bundleDebug` hangs at `:app:mergeDebugShaders` | ⛔ **Blocked** | Gradle 9.0.0 + AGP 8.12.0 daemon busy-spin — see below |

---

## Resolved notes (why Issues 1–5 matter)

These are all fixed in shipped code. They are recorded here so the same classes
of regression are not reintroduced:

- **Issue 1 — ABI rename.** `HybridObject::getExternalMemorySize()` is the
  override target; there is **no** `getMemorySize()` on the base. The rename
  has existed in NitroModules since `0.25.0`. iOS catches this because it
  consumes NitroModules as a **source-built** CocoaPod (live headers), while a
  **cached** Android prefab/prebuilt build can mask the same incorrect
  override. See the compatibility matrix in `README.md`.
- **Issue 3 — avoid `std::vector` across the Swift↔C++ boundary.** The
  generated `_cxx.swift` bridge calls `.map()` on a `std::vector<std::string>`,
  which relies on Swift's C++ interop synthesizing `Sequence` conformance. This
  is the canonical NitroModules pattern and *should* work under
  `SWIFT_OBJC_INTEROP_MODE = objcxx`, but it reproducibly failed even on
  Xcode 26.5. Resolution: `UrlSchemeProbe` now takes a single `scheme: string`
  and `cpp/IOSChecks.cpp` calls it once per scheme. This is a general lesson —
  prefer scalar parameters at Swift↔C++ HybridObject boundaries.
- **Issue 5 — pure-virtual aliases must be overridden.** When a `.nitro.ts`
  spec declares a method, nitrogen emits it as a pure virtual on the generated
  C++ base. `assessRisk()` is an alias for `checkDetailed()`, but it still
  **must** be implemented or the class becomes abstract and fails Nitro's
  default-constructible autolinking assertion.

---

## Issue 6 — Android Gradle build hangs at `:app:mergeDebugShaders` (OPEN)

**Symptom**

`./gradlew app:bundleDebug` prints through all `:psync_anti-jailbreak` native
CMake/NDK tasks (which **succeed**) and then appears to stall on
`:app:mergeDebugShaders` with no further output.

**Root cause — daemon CPU busy-spin, not slow compilation**

`ps` shows the Gradle daemon JVM at **~140% CPU, sustained for 29+ minutes,
with zero child processes** (no `clang`/`cmake`/`ninja`/`cc1plus`). RSS is only
~73 MB, so it is not GC/memory thrashing — the JVM is in a busy loop.
`mergeDebugShaders` is a trivial AGP resource-merge task that should never burn
a core for minutes. The toolchain is bleeding-edge: **Gradle 9.0.0** +
**AGP 8.12.0** (`@react-native/gradle-plugin`'s `libs.versions.toml`) +
**React Native 0.83**. The most likely cause is a Gradle 9 / AGP 8.12
incompatibility in the resource-merge/configuration pipeline. (`/Volumes/Xcode`
is also mounted `noowners`, which can interact badly with AGP file ops, but
that normally errors rather than spins.)

**Important:** the native library itself compiles cleanly on Android, so the
C++/Kotlin changes from Issues 3–5 are **not** the cause.

**Recommended paths**

1. **Localize the spin** — kill the stuck daemon and retry with `--info`:
   ```sh
   JAVA_HOME=... ANDROID_HOME=... ./gradlew app:bundleDebug \
     --no-daemon --console=plain -PreactNativeArchitectures=arm64-v8a --info
   ```
2. **Pin a known-stable toolchain** — if it reproduces, downgrade the Gradle
   wrapper to a `8.x` that RN 0.83 + AGP 8.12 are known to work with, or pin
   AGP to a version matched to Gradle 8.x.
3. Do not run two `./gradlew` invocations concurrently — they fight over
   `~/.gradle/daemon/9.0.0/registry.bin.lock`.

---

## Operational notes (macOS validation)

- **Xcode location** — Xcode.app is at `/Volumes/Xcode/Applications/Xcode.app`
  (Xcode 26.5). `/Volumes/Xcode/Xcode/` is only a `DerivedData` scratch dir.
- **`DEVELOPER_DIR` vs turbo** — Xcode is not the active `xcode-select` target
  (Command Line Tools is). `export DEVELOPER_DIR=...` overrides it without
  sudo, **but `turbo` sanitizes the environment** and does not pass
  `DEVELOPER_DIR` through (`turbo.json` `build:ios.env` does not list it). So
  `bun run turbo run build:ios` loses it and CocoaPods fails to find Xcode.
  Workaround: run the example build directly (`bun run example build:ios`), or
  add `DEVELOPER_DIR` to `turbo.json` `globalPassThroughEnv`.
- **`nitrogen` CLI is not in `node_modules/.bin`** — use
  `npx nitrogen@0.36.1` to regenerate (matches the version that produced the
  committed generated code). The bare `"specs": "nitrogen"` script fails until
  nitrogen is added as a devDependency; `bun run specs` resolves it from the
  workspace.
- **ReactAppDependencyProvider podspec** — if `pod install` errors with
  `No podspec found for ReactAppDependencyProvider in build/generated/ios/...`,
  delete `example/ios/Pods` + `example/ios/Podfile.lock` and re-run
  `pod install`; it is a stale-codegen-artifact state, not a real failure.

---

## Pre-existing version split (background risk)

The repo exercises three different NitroModules versions across its workspaces:

| Location | `react-native-nitro-modules` |
|----------|------------------------------|
| `package.json` `peerDependencies` | `~0.35.1` |
| root `bun.lock` | `0.36.1` |
| `example/` `bun.lock` | `0.35.10` |

The committed `nitrogen/generated/` was produced by nitrogen `0.36.1`. The
mismatch was confirmed but did **not** cause Issue 3 (it reproduces regardless
of the installed NitroModules version). Consumers bring their own version; if
it diverges, build mismatches become more likely. Recommended follow-up (separate
task): decide whether the example should match the library, and whether the peer
range should formally widen (e.g. `~0.35.1 || ~0.36.0`) when 0.36 is adopted.

---

## Validation status

| Check | Status |
|-------|--------|
| `bun run typecheck` | ✅ Pass |
| `bun run lint` | ✅ Pass |
| `bun run test --maxWorkers=2` | ✅ Pass (22/22) |
| `bun run build` | ✅ Pass |
| iOS `xcodebuild` (iPhone 17 sim, Debug, Xcode 26.5) | ✅ **BUILD SUCCEEDED** |
| Android `./gradlew app:bundleDebug` (arm64-v8a) | ⛔ Hangs at `:app:mergeDebugShaders` (Issue 6) |

iOS was validated with `xcodebuild` directly rather than
`bun run turbo run build:ios`, because turbo strips `DEVELOPER_DIR` from the
task environment (see Operational notes). The native `:psync_anti-jailbreak`
Android module compiles cleanly; only the downstream app AGP task hangs.

---

## Next actions

1. **Resolve Issue 6** — retry with `--info` to localize the spin, and if it
   reproduces pin the Gradle/AGP pair to a known-stable combination.
2. **Reconcile the version split** — align example + peer NitroModules;
   optionally add `nitrogen` as a pinned devDependency (separate task).
3. Optionally add `DEVELOPER_DIR` to `turbo.json` `globalPassThroughEnv` so
   `bun run turbo run build:ios` works without bypassing turbo.
4. Commit and release only when explicitly requested.
