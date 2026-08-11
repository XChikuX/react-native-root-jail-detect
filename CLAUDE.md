# CLAUDE.md

## Repository overview

This repository contains `@psync/anti-jailbreak`, a React Native **Nitro Module** that detects rooted Android devices, jailbroken iOS devices, emulators/simulators, debuggers, Frida/runtime instrumentation, and hooking frameworks. It exposes a scored, structured device-risk API plus a periodic native security watchdog.

The repository is a Bun workspace:

- The publishable library lives at the repository root.
- `example/` is a React Native app that consumes the local library and is the primary integration test surface.

The library is **New Architecture only** and is built on [Nitro Modules](https://nitro.margelo.com/). There is no Old-Architecture bridge fallback, no TurboModule codegen spec, and no handwritten Objective-C externs. Nitrogen generates the C++/Swift/Kotlin bindings from `.nitro.ts` specs; the shared detection core is implemented in C++ and called from thin Swift/Kotlin edge HybridObjects at the platform boundary.

Preserve compatibility across the TypeScript specs, JavaScript wrappers, shared C++ core, platform edge HybridObjects, generated Nitro code, and documentation whenever changing the public API. The scored baseline is shipped; remaining future work is summarized in the "Roadmap" section of `README.md`.

## Toolchain

Use the versions and package manager committed to the repository:

- Node.js: `v22.20.0` from `.nvmrc`
- Bun: `1.3.10+` from `packageManager`
- React Native: `0.83.10` (New Architecture only)
- React: `19.2.7`
- TypeScript: `7.0.x` strict mode (TypeScript 7+ removed `noImplicitUseStrict` / `noStrictGenericChecks`; do not reintroduce them)
- ESLint: `10.x`, native flat config in `eslint.config.mjs` (do not reintroduce the legacy `FlatCompat` wrapper around `@react-native/eslint-config` — it uses ESLint internals removed in v10)
- Jest: `30.x`. The Jest config in `package.json` overrides `testEnvironment` to `jest/environment.js`, which re-exports the top-level `jest-environment-node` (v30). Do **not** add a `package.json` `overrides` entry for `jest-environment-node` — npm 11 rejects it as a direct-dependency conflict, which breaks `npm publish` and CI. The `jest/environment.js` shim is the only workaround that satisfies both Bun and npm.
- Nitro Modules: `react-native-nitro-modules` + `nitrogen` codegen. `peerDependencies` pins `~0.35.1`; `0.36.x` is also verified (see the compatibility matrix in `README.md`). The committed `nitrogen/generated/` tree was produced by nitrogen `0.36.1`, so regenerate with a matching nitrogen CLI (`npx nitrogen@0.36.1` — the CLI is **not** in `node_modules/.bin`; `bun run specs` resolves it from the workspace).
- Android: Kotlin `2.2.0`, min SDK 24, compile/target SDK 36, AGP `8.8.2` (library) — example app uses the React Native Gradle plugin's AGP, Gradle `9.0.0`, and NDK `27.1.12297006`. Gradle may run on JDK 17, 21, or 23; JDK 21 is valid and does not require installing JDK 17. Java and Kotlin bytecode must both target JVM 17 (`sourceCompatibility`/`targetCompatibility` and Kotlin `jvmTarget`/`compilerOptions.jvmTarget`) to avoid incompatible class targets. When the app uses a newer runtime JDK, configure this target consistently for the app and every Android subproject, including autolinked dependencies.
- iOS: minimum version supplied by React Native's `min_ios_version_supported`, Xcode 16.4+ (validated on Xcode 26.5), Swift 5.9+, C++20

Install dependencies from the repository root:

```sh
bun install --frozen-lockfile
```

Do not use npm for repository development; the workspace and lockfile are Bun-managed.

## Important paths

### Public JavaScript/TypeScript API

- `src/specs/RootJailDetect.nitro.ts` — root HybridObject Nitro spec (`configure`, `checkDetailed`/`assessRisk`, `getWatchdog`). Source of truth for the native contract.
- `src/specs/SecurityWatchdog.nitro.ts` — watchdog HybridObject Nitro spec (`start`, `stop`, `isRunning`).
- `src/specs/UrlSchemeProbe.nitro.ts` — **internal** iOS edge HybridObject Nitro spec (`canOpenUrl(scheme: string): boolean`). Not exported from `src/` and not referenced by any JS-facing API; consumed only by `cpp/IOSChecks.cpp`. Backed by Swift on iOS (`{ ios: 'swift'; android: 'c++' }`) and a no-op C++ stub on Android.
- `src/specs/PackageManagerProbe.nitro.ts` — **internal** Android edge HybridObject Nitro spec (`getInstalledRootPackages(): string[]`). Not exported from `src/` and not referenced by any JS-facing API; consumed only by `cpp/AndroidChecks.cpp`. Backed by Kotlin on Android (`{ ios: 'c++'; android: 'kotlin' }`) and a no-op C++ stub on iOS.
- `src/specs/*.ts` — named codegen types (`CompromiseAssessment`, `DeviceRiskResult` (deprecated alias kept for backwards compatibility), `DetectionSignal`, `Severity`, `Confidence`, `Platform`, `ProtectionMode`, `RootJailDetectOptions`, `SecurityWatchdogOptions`, `SignalCategory`, `UrlSchemeOptions`). Each lives in its own file because Nitro requires named types for native codegen.
- `src/specs/index.ts` — barrel re-exporting all spec types (specs themselves must not re-export unrelated types).
- `src/wrappers.ts` — legacy boolean API (`isDeviceCompromised`, `isEmulator`, `isDebuggerAttached`, `getDetectionReasons`, `startSecurityWatchdog`, `stopSecurityWatchdog`) implemented as thin wrappers over `checkDetailed()`, plus the `setDetectionCallback` detection-event telemetry hook. Owns the lazily-created root HybridObject handle.
- `src/index.tsx` — public entry point, barrel only (no logic; re-exports wrappers and spec types, plus a backwards-compatible default object).
- `src/types.ts` — re-exports the public spec types for older import paths.
- `src/__tests__/index.test.tsx` — Jest tests for the wrapper layer (mocks the native HybridObject before importing the entry point).

### Shared C++ core

- `cpp/HybridRootJailDetect.hpp` / `.cpp` — shared C++ implementation of the root HybridObject. Owns resolved configuration and lazily creates the watchdog. Stays as orchestration: resolves config, measures the total `timeoutMs` budget, delegates platform work to focused helper files, and aggregates signals into a `CompromiseAssessment`. Overrides both `checkDetailed()` and `assessRisk()` (the latter is a documented alias that delegates to `checkDetailed()`; it is a pure virtual on the nitrogen-generated base, so it **must** be overridden or the class becomes abstract and fails Nitro's default-constructible autolinking assertion).
- `cpp/HybridSecurityWatchdog.hpp` / `.cpp` — shared C++ implementation of the watchdog HybridObject. Owns the background thread and lifecycle state and consumes `checkDetailed()` (no duplicated boolean logic). Serializes `start()`/`stop()` transitions with a dedicated mutex so two concurrent Nitro-worker-thread invocations cannot spawn duplicate background loops; `run()` only takes the lifecycle mutex during its timed sleep so the join in `start()`/`stop()` cannot deadlock.
- `cpp/DeviceRiskAssessment.hpp` / `.cpp` — the blocking assessment entry point shared by the root API and the watchdog. Picks the platform-specific check runner under `#if defined(__ANDROID__)`, computes `elapsedMs`, runs the aggregator, and folds the result together with `treatDebuggerAsCompromise`. Keeping this path singular prevents the watchdog's compromise decision from drifting from `checkDetailed()`.
- `cpp/IOSChecks.hpp` / `.cpp` — conservative iOS-only probes (jailbreak artifact paths, `_dyld` loaded-image scan, `sysctl` debugger state, simulator flag). Body compiled under `#if defined(__APPLE__)` so Android and host builds stay safe. Routes every signal through `SignalCatalog::lookupSignal()` so weights and severities never drift from the catalog.
- `cpp/SignalCatalog.hpp` / `.cpp` — stable, public signal ids (`SignalId::*`) and their default severity/score weights, plus `lookupSignal(id)`. Signal ids are part of the public contract: callers and backends use them to reason about which checks fired, so they must never be renamed or reused for a different meaning once published. Weights mirror the risk table in the "Signal Catalog" section of `README.md`.
- `cpp/Scoring.hpp` — header-only, side-effect-free aggregation (`aggregateSignals`) of fired signals into a clamped 0–100 score and a confidence level, with per-id deduplication so equivalent evidence is not double-counted.
- `cpp/ProcParsers.hpp` / `.cpp` — pure, side-effect-free parsing of Linux `/proc` text formats (`/proc/self/maps`, `/proc/self/mountinfo`, `/proc/self/mounts`, `/proc/self/status`, `/sys/fs/selinux/enforce`) used by the Android path. Every parser takes already-read file content and returns structured findings, so the logic is deterministic and unit-testable with fixture strings. `readFileIfExists` is the single impure entry point and never turns an unreadable file into a detection.
- `cpp/AndroidProbes.hpp` / `.cpp` — Android-specific probes that require platform APIs: filesystem existence checks for root-manager directories and `su` binaries (`stat(2)`), and reads of Android system properties (`__system_property_get`) for verified-boot and build-tag signals. Compiled under `#if defined(__ANDROID__)`; outside Android they return an empty set so the same files are safe in a host-side unit-test build.
- `cpp/AndroidChecks.hpp` / `.cpp` — orchestrates the Android scored baseline: reads the relevant `/proc`/`/sys` files, runs the pure parsers, probes paths/properties, runs the loopback TCP probes via `TcpProbe`, and folds everything into a deduplicated list of `DetectionSignal`s plus the informational `debuggerDetected` flag. This is the only place that knows the full set of Android checks; `DeviceRiskAssessment.cpp` calls it under `#if defined(__ANDROID__)`.
- `cpp/TcpProbe.hpp` / `.cpp` — loopback TCP probes used by both platforms to detect Frida server (27042), SSH (22/44), and ADB (emulator) responders. Pure C++ with a small RAII `TcpSocket` wrapper; takes short non-blocking connect timeouts and releases the fd on every path. Compiled on both platforms under `#if defined(__ANDROID__)` / `#elif defined(__APPLE__)` includes; defines `SOCK_CLOEXEC` to `0` when the iOS SDK lacks it (the flag is Linux-only and the sockets are short-lived, so the no-op define is safe).
- `cpp/HybridUrlSchemeProbe.hpp` / `.cpp` — no-op C++ stub of the `UrlSchemeProbe` HybridObject, used on Android and any host build where URL-scheme probing is iOS-only. The real implementation is the Swift `HybridUrlSchemeProbe` class reached through the generated Swift-C++ bridge on iOS; `cpp/IOSChecks.cpp` calls `probe->canOpenUrl(scheme)` once per scheme rather than passing a `string[]` across the Swift boundary (see `TRIAGE.md` Issue 3 for the rationale — avoiding `std::vector` Sequence-conformance interop).
- `cpp/HybridPackageManagerProbe.hpp` / `.cpp` — no-op C++ stub of the `PackageManagerProbe` HybridObject, used on iOS and any host build where PackageManager queries are Android-only. The real implementation is the Kotlin `HybridPackageManagerProbe` edge class (`android/src/main/java/com/rootjaildetect/HybridPackageManagerProbe.kt`), reached through the generated Kotlin-C++ bridge on Android; `cpp/AndroidChecks.cpp` calls `probe->getInstalledRootPackages()` once per pass.

### Android

- `android/CMakeLists.txt` — builds the `RootJailDetect` shared library, compiles the hand-written C++ HybridObjects and the detection helpers (`HybridRootJailDetect`, `HybridSecurityWatchdog`, `HybridUrlSchemeProbe` (no-op), `HybridPackageManagerProbe` (no-op), `cpp-adapter`, `DeviceRiskAssessment`, `SignalCatalog`, `ProcParsers`, `AndroidProbes`, `AndroidChecks`, `IOSChecks`, `TcpProbe`), and includes the generated autolinking cmake. `IOSChecks` and `TcpProbe` are included so the same files compile on both platforms; platform-specific code is guarded by `#if defined(__ANDROID__)` / `#elif defined(__APPLE__)` and is otherwise empty.
- `android/build.gradle` — Android library config; pins Kotlin `2.2.0`, AGP `8.8.2`, `minSdk` 24, `compileSdk`/`targetSdk` 36, and JVM 17 output for both Java (`sourceCompatibility`/`targetCompatibility`) and Kotlin (`jvmTarget`); applies the generated Nitro autolinking gradle and points `externalNativeBuild` at `CMakeLists.txt`.
- `android/src/main/AndroidManifest.xml` — library manifest declaring the narrow `<queries>` set used by the Expo config plugin (`app.plugin.js`).
- Kotlin edge HybridObject for Play Integrity token acquisition remains intentionally deferred — Play Integrity is server-attestation work and `RootJailDetectOptions.enablePlayIntegrity` is documented as such. PackageManager enumeration is shipped as the `PackageManagerProbe` HybridObject (Kotlin edge, `android/src/main/java/com/rootjaildetect/HybridPackageManagerProbe.kt`).

### iOS

- `ios/HybridUrlSchemeProbe.swift` — Swift edge implementation of the `UrlSchemeProbe` HybridObject. The only Swift-backed HybridObject in this library (root and watchdog are pure C++). Implements `canOpenUrl(scheme: String) throws -> Bool` by dispatching to the main actor to call `UIApplication.canOpenURL(URL(string: "\(scheme)://")!)`. The C++ core (`cpp/IOSChecks.cpp`) calls it once per scheme so the Swift↔C++ boundary never crosses a `string[]`. The class `init()` is marked `override` to satisfy the nitrogen-generated `HybridUrlSchemeProbeSpec_base` designated initializer.
- `ios/` (rest of the directory) — reserved for future Swift edge HybridObjects (for example, additional `_dyld` probes). The bulk of iOS detection lives in the shared C++ core at `cpp/IOSChecks.cpp` so the simulator/device branching, signal catalog, and scoring stay in one place.
- `RootJailDetect.podspec` — CocoaPods spec; pulls in generated specs/bridges via `nitrogen/generated/ios/RootJailDetect+autolinking.rb` and the shared C++ sources from `cpp/**/*.{hpp,cpp}`. The autolinking `.rb` sets `SWIFT_OBJC_INTEROP_MODE = objcxx` (required for Swift↔C++ bridging).

### Generated Nitro code (committed, never hand-edited)

- `nitro.json` — Nitrogen config: `cxxNamespace`, `iosModuleName`, `androidCxxLibName`, and the `autolinking` map. Four HybridObjects are autolinked: `RootJailDetect` and `SecurityWatchdog` are C++-backed via the `"all"` key; `UrlSchemeProbe` is Swift on iOS and a C++ stub on Android (matching `{ ios: 'swift'; android: 'c++' }` in `UrlSchemeProbe.nitro.ts`); `PackageManagerProbe` is Kotlin on Android and a C++ stub on iOS (matching `{ ios: 'c++'; android: 'kotlin' }` in `PackageManagerProbe.nitro.ts`).
- `nitrogen/generated/` — codegen output. **Committed** (see `.gitignore` negation) and shipped in the npm package so consumers can build without running codegen. Includes:
  - `shared/c++/` — C++ spec abstract bases (`Hybrid*Spec.hpp/.cpp`) and struct/enum headers.
  - `android/` — `RootJailDetectOnLoad.cpp/.hpp/.kt`, `RootJailDetect+autolinking.cmake/.gradle`.
  - `ios/` — `RootJailDetectAutolinking.swift/.mm`, `RootJailDetect+autolinking.rb`, Swift-C++ bridge headers.
- Re-run `bun run specs` (i.e. `nitrogen`) after any `.nitro.ts` change. Do **not** edit generated files directly.

### Example and automation

- `example/src/App.tsx` — usage demo covering both the legacy boolean API and the new `checkDetailed()` scored API.
- `example/android/` and `example/ios/` — native example projects.
- `.github/workflows/ci.yml` — authoritative CI jobs and build commands.
- `turbo.json` — cached Android/iOS example build inputs.
- `CONTRIBUTING.md` — contributor workflow and conventional commit policy.

## Architecture and behavior

### API flow

The main call path is:

```text
Consumer
  -> src/index.tsx (barrel)
  -> src/wrappers.ts (legacy boolean API over checkDetailed)
  -> Nitro HybridObjects (nitrogen codegen)
    -> Shared C++ core: scoring, signal catalog, pattern matching, /proc parsing (Android)
    -> Shared C++ platform runner: AndroidChecks.cpp on Android, IOSChecks.cpp on iOS
```

`checkDetailed()` is the primary, structured API and returns a `CompromiseAssessment` (score, signals, confidence `'low'|'medium'|'high'|'extreme'`, debugger state, partial flag). `DeviceRiskResult` is kept as a deprecated type alias for backwards compatibility. `assessRisk()` is an alias for `checkDetailed()`. The legacy boolean wrappers are derived from the assessment so all detection logic lives in one place.

`DetectionSignal` carries extra context helpful for UI, analytics, and issue triage: `platform`, `category` (`filesystem`, `mount`, `injection`, `debugger`, `emulator`, `hooking`, `runtime`, `integrity`, `volume`, `urlScheme`, `info`, ...), `detected`, and a `reliability` score `0..1`. Unavailable checks are represented as signals with `detected: false` and `unavailable: true`.

**Implementation status:** the Android scored baseline lives in shared C++ — `/proc/self/maps`, `/proc/self/mountinfo` + `/proc/self/mounts`, `/sys/fs/selinux/enforce`, root-manager paths, `su` binaries, build/verified-boot properties, runtime instrumentation (Frida cmdline + local socket), PackageManager root-package enumeration, sandbox write probes, and `TracerPid` as informational. iOS Phase 1 checks (jailbreak artifact paths, `_dyld` loaded-image scan, `sysctl` debugger state, simulator flag) live in shared C++ at `cpp/IOSChecks.cpp`; the iOS-only `UrlSchemeProbe` (Swift edge, `ios/HybridUrlSchemeProbe.swift`) probes jailbreak-store URL schemes via `UIApplication.canOpenURL`, called one scheme at a time from `cpp/IOSChecks.cpp`. The security watchdog has its real background loop in `cpp/HybridSecurityWatchdog.cpp`. The C++ is not Windows-compilable — a Gradle build with the NDK must be run on macOS/Linux/WSL for native validation before publishing.

`isDeviceCompromised()` resolves to `result.compromised` (score >= configured `minScore`). It is intentionally broader than literal root/jailbreak detection — on both platforms it also includes selected Frida, hook, and low-level anti-debug/injection checks. Do not narrow or broaden this semantic accidentally; update documentation and both platforms when changing it.

`getDetectionReasons()` derives human-readable strings from the fired signal ids (and redacted `evidence` when enabled), skipping `unavailable` signals, and deduplicates. A new positive heuristic should normally have a corresponding signal id so callers can understand why a device was flagged.

`isEmulator()` in `src/wrappers.ts` normalizes Android emulator and iOS simulator signals (platform-prefixed signal ids) into one public boolean.

The watchdog is a **separate HybridObject** (`SecurityWatchdog`) that consumes `checkDetailed()` with the configured threshold on each tick — it must not duplicate boolean detection logic. It periodically checks compromise state and supports:

- `LOG_ONLY`
- `THROW_EXCEPTION`
- `TERMINATE`

The public interval is milliseconds (`intervalMs` on `SecurityWatchdogOptions`). The legacy `startSecurityWatchdog` wrapper still accepts the old `interval` field as an alias. Both platforms consume milliseconds in the native core; keep these units aligned.

### Error semantics

Wrapper behavior (preserved from v1 for backwards compatibility):

- `isDeviceCompromised()` logs and rethrows native errors.
- `isEmulator()`, `isDebuggerAttached()`, and `getDetectionReasons()` log and return safe fallback values (`false`, `false`, `[]`).
- `checkDetailed()` and `configure()` propagate directly (no swallow).
- Watchdog `start`/`stop` wrappers keep the historical synchronous signature by firing the async native methods without awaiting; rejections are logged, not rethrown.

Preserve this behavior unless the task explicitly changes the API contract. If changing error semantics, update tests, README examples, and all affected call sites.

## Rules for public API changes

Any native method change must be treated as a cross-platform change. Review and update all applicable files:

1. `src/specs/*.nitro.ts` (HybridObject specs — source of truth for the native contract)
2. `src/specs/*.ts` (named codegen types: structs, unions, options)
3. `src/wrappers.ts` and `src/index.tsx`
4. `cpp/Hybrid*.hpp` / `.cpp` (shared C++ core)
5. Kotlin edge HybridObjects under `android/src/main/java/...` as needed
6. Swift edge HybridObjects under `ios/` as needed
7. `nitro.json` (autolinking) and re-run `bun run specs` (nitrogen codegen)
8. `RootJailDetect.podspec` and `android/build.gradle` / `CMakeLists.txt` if sources/dependencies change
9. `README.md`
10. `example/src/App.tsx` when the feature should be demonstrated
11. Jest tests

Keep the module registration name exactly `RootJailDetect` (the `createHybridObject<RootJailDetect>('RootJailDetect')` string must match the `nitro.json` autolinking key). Native implementation classes (`HybridRootJailDetect`, `HybridSecurityWatchdog`, `HybridUrlSchemeProbe`) must be **default-constructible** because Nitro autolinks them with no constructor arguments. Do not hand-edit generated code under `nitrogen/generated/`; change the `.nitro.ts` spec and re-run nitrogen.

Prefer one cross-platform public concept rather than exposing platform-specific names. Platform-specific native details may remain in the codegen spec only when needed for normalization, as with `isEmulator`/`isSimulator`.

Use explicit option types instead of `{}` or unbounded strings when improving an API. Public time values should include units in their names when compatibility allows (for example, `intervalMs`). Since this package is already published, avoid breaking names or return/error behavior without an explicit migration plan.

## Security implementation guidelines

This is heuristic security code. Optimize for predictable behavior and low false-positive risk, not marketing claims.

- Treat every new heuristic as fallible. Restricted files, process data, URL schemes, sockets, system properties, and symbols may be unavailable on normal devices.
- Catch expected platform access failures narrowly and return a non-detection result. Do not turn inability to inspect into proof of compromise unless that behavior is explicitly designed and documented.
- Keep `is...Detected()` and `getReasons()` logically consistent. Prefer deriving the boolean from the scored `DeviceRiskResult` so all detection logic lives in one place.
- Add a distinct, useful human-readable reason (via the signal `id`, and redacted `evidence` when enabled) for every positive condition.
- Deduplicate repeated reasons and avoid misleading text. Verify that the reason describes the actual condition checked.
- Consider simulator/emulator behavior explicitly. Host paths and simulator capabilities differ from physical devices.
- Avoid expensive work on the UI/main thread. Several checks read files, enumerate processes/threads, inspect memory maps, execute commands, or open sockets. Run `checkDetailed()` work off the JS caller; the native implementation owns its execution context.
- Network probes must target local endpoints only, use short timeouts, and close sockets/resources deterministically.
- C++ file descriptors, `FILE*`, `dlopen` handles, sockets, and allocated Mach memory must be released on every path. Use RAII.
- Preserve platform compile guards such as `#if defined(__ANDROID__)` (C++) or `#if targetEnvironment(simulator)` (Swift) where physical-device checks are unsafe or misleading.
- Never claim root/jailbreak detection is foolproof. README language should continue to recommend layered server-side and application security controls.

### Watchdog caution

The watchdog owns long-lived mutable state and a background thread. Changes here can terminate the host application.

- Validate intervals before using them for sleep or random jitter. Non-positive intervals can create invalid ranges or tight loops.
- Make start/stop and shared state thread-safe when modifying lifecycle behavior.
- Do not hold locks while running detection checks or threat actions.
- Do not silently swallow unexpected exceptions. Existing behavior does this in places; avoid expanding that pattern.
- `TERMINATE` is destructive (it ends the host process via `std::terminate()`). `THROW_EXCEPTION` fired from the watchdog background thread is demoted to a logged warning because a background thread cannot safely throw into the JS runtime; it is retained for API completeness. Do not exercise `TERMINATE` in automated tests or routine manual validation. Use `LOG_ONLY` for safe watchdog testing.
- Verify repeated `start()`, `stop()`, and restart behavior whenever changing lifecycle code.

## Coding style

Follow the style already used in each language and keep changes focused.

### TypeScript/React

- Strict TypeScript is enabled, including unused and unchecked-index checks.
- Use single quotes, 2-space indentation, and ES5 trailing commas per Prettier configuration.
- ESLint runs Prettier as an error.
- Prefer named exports for individual APIs while preserving the existing default object for compatibility.
- Do not add logic to generated output under `lib/`; edit `src/` and rebuild.
- `src/index.tsx` is a barrel only — no logic, branching, or side effects. Detection/wrapper logic lives in `src/wrappers.ts`; native contract lives in `src/specs/*.nitro.ts`.
- Add meaningful Jest mocks for the Nitro HybridObject (`NitroModules.createHybridObject`) when testing wrappers; mock before importing the entry point.

### Kotlin/Android

- Keep edge HybridObject responsibilities narrow: PackageManager queries, system-property reads, verified-boot properties, Play Integrity token acquisition. Heavy scoring and parsing stay in the shared C++ core.
- Use Kotlin null safety and scoped resource helpers such as `use`.
- Avoid blocking the React Native caller thread; the C++ core owns its execution context and the Kotlin edge does platform-service lookups.
- Annotate HybridObject implementation classes with `@Keep` and `@DoNotStrip`.
- Do not modify generated `Hybrid*Spec.kt` files under `nitrogen/generated/`.

### Swift/iOS

- Keep edge HybridObject responsibilities narrow: sandbox-boundary probes, `_dyld` loaded-image inspection, URL-scheme checks, `sysctl` debugger state. Checker logic lives in focused files under `ios/`.
- Keep classes `final` unless inheritance is intentional.
- Prefer `guard`, Swift value types, and `defer` for cleanup.
- Avoid main-thread work unless UIKit requires it. Keep any `UIApplication` boundary narrow and safe.
- Do not modify generated `Hybrid*Spec.swift` files under `nitrogen/generated/`.

### C++ (shared core)

- The root and watchdog HybridObjects are implemented in shared C++ (`{ ios: 'c++'; android: 'c++' }`) so scoring, the signal catalog, `/proc` parsing (Android), pattern matching, and TracerPid checks are shared across platforms.
- Keep `cpp/HybridRootJailDetect.cpp` as orchestration; detection helpers live in focused files (`SignalCatalog`, `Scoring`, `ProcParsers`, `AndroidProbes`, `AndroidChecks`). Add new helpers as separate files rather than growing the HybridObject implementation.
- Use RAII where possible and close native resources (`FILE*`, `dlopen`, sockets, Mach memory) on all returns.
- Avoid undefined behavior from architecture-specific instruction assumptions; validate checks on every supported ABI.
- The C++ core can call Swift/Kotlin edge HybridObjects through their generated C++ spec API. Verify codegen support before assuming the inverse direction (Swift/Kotlin consuming C++-backed objects).
- Preserve the CMake library name `RootJailDetect` (matches `androidCxxLibName` in `nitro.json` and `System.loadLibrary("RootJailDetect")` in the generated Kotlin).

## Generated and ignored artifacts

Do not manually edit or commit generated/build outputs unless a task specifically requires it:

- `lib/`
- `android/build/`
- `example/android/build/`
- `example/android/app/build/`
- `example/ios/build/`
- `example/ios/Pods/`
- Gradle caches and `node_modules/`
- React Native codegen output inside build directories

**Exception — `nitrogen/generated/` is committed and shipped in the npm package.** Consumers must be able to build the native library without running Nitrogen themselves. Re-run `bun run specs` after any `.nitro.ts` change and commit the regenerated files; never hand-edit them.

The package build is produced by React Native Builder Bob from `src/`.

## Commands

Run commands from the repository root unless noted otherwise.

```sh
# Install
bun install --frozen-lockfile

# TypeScript validation
bun run typecheck
bun run lint
bun run test --maxWorkers=2

# Regenerate Nitro C++/Swift/Kotlin bindings after changing any .nitro.ts spec
bun run specs

# Build publishable JS and declaration output
bun run build

# Example app
bun run example start
bun run example android
bun run example ios

# CI-equivalent native builds
bun run turbo run build:android --cache-dir=.turbo/android
bun run turbo run build:ios --cache-dir=.turbo/ios

# Remove generated build products
bun run clean
```

Do not run Metro or other persistent/watch commands as unattended validation; they do not terminate on their own.

## Native build commands (validated on macOS / Xcode 26.5)

The commands below are the **exact ones that produced working builds** on this machine. They are deliberately not wrapped in `turbo` because turbo sanitizes the task environment and drops the env vars the SDKs need (see gotchas). Run from the repository root unless noted.

### Environment variables

The library publishes no env contract of its own, but the toolchains do. Set these per shell session (do not put them in `~/.zshrc` — they point at machine-specific paths):

```sh
# macOS / Xcode
export DEVELOPER_DIR="/Volumes/Xcode/Applications/Xcode.app/Contents/Developer"
# `xcode-select` on this machine points at CommandLineTools, which cannot build
# RN/CocoaPods. DEVELOPER_DIR overrides it for the current process only.

# Android / JDK / SDK
export ANDROID_HOME="/Volumes/Xcode/Android/sdk"
export ANDROID_SDK_ROOT="/Volumes/Xcode/Android/sdk"
export JAVA_HOME="/usr/local/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home"
# Only JDK 21 is installed. The library targets JDK 17 bytecode
# (`sourceCompatibility`/`targetCompatibility` VERSION_17) so the JDK 21
# runtime is fine. `example/android/gradle.properties` pins the toolchain to
# this JDK and disables auto-download.
```

### JavaScript / TypeScript / Nitro

```sh
# Install dependencies (workspace is Bun-managed; do not use npm)
bun install --frozen-lockfile

# Validate (always run before native builds; cheap and fast)
bun run typecheck
bun run lint
bun run test --maxWorkers=2
bun run build

# Regenerate Nitrogen bindings after any .nitro.ts change
# `nitrogen` is NOT in node_modules/.bin; bun run specs resolves it via Bun
# workspace. If it ever errors with "command not found", run it directly:
#   npx nitrogen@0.36.1
bun run specs
```

### iOS build (xcodebuild)

```sh
cd example/ios

# 1. Install Pods. Must come first — RN's codegen produces Pods/ inputs.
#    If pod install errors with "No podspec found for ReactAppDependencyProvider
#    in build/generated/ios/...", delete Pods/ + Podfile.lock and retry; that is
#    a stale-codegen state, not a real failure.
pod install

# 2. Build the Debug app for an iOS simulator.
xcodebuild \
  -workspace RootJailDetectExample.xcworkspace \
  -scheme RootJailDetectExample \
  -configuration Debug \
  -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath build \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Expected: `** BUILD SUCCEEDED **`. This was the command that produced the working build after fixing TRIAGE Issues 1–5.

### Android build (Gradle + CMake + NDK)

```sh
cd example/android

# Build a single ABI to keep the first compile under ~10 minutes. Use all
# architectures only when validating a release.
./gradlew app:bundleDebug \
  --no-daemon \
  --console=plain \
  -PreactNativeArchitectures=arm64-v8a
```

Expected: `BUILD SUCCESSFUL`. The CMake/NDK pass of `:psync_anti-jailbreak` compiles `cpp/**` (12 sources: HybridRootJailDetect, HybridSecurityWatchdog, HybridUrlSchemeProbe, HybridPackageManagerProbe, cpp-adapter, DeviceRiskAssessment, SignalCatalog, ProcParsers, AndroidProbes, AndroidChecks, IOSChecks, TcpProbe) plus the generated autolinking glue, then links into the example APK.

### Why these are not the `bun run turbo` versions

`turbo run build:ios` / `turbo run build:android` are listed as the CI-equivalent invocations above and remain authoritative for CI. On a workstation they are unreliable because:

- `turbo` strips `DEVELOPER_DIR` from the task environment (not listed in `turbo.json` `build:ios.env`), so CocoaPods loses Xcode and fails.
- `turbo` does not always forward the custom `JAVA_HOME` to nested gradlew invocations on this toolchain mix.

Use the direct invocations above for local validation. The CI workflows in `.github/workflows/ci.yml` use the turbo versions inside a clean GitHub Actions runner where the toolchains are already on PATH.

### Gotchas (machine-specific)

- **iOS — `nitrogen` CLI is not installed.** `bun run specs` resolves it from the workspace; if it errors with "command not found", run `npx nitrogen@0.36.1` instead. The committed `nitrogen/generated/` was produced by nitrogen `0.36.1`.
- **iOS — stale `Pods/`.** A failed prebuild leaves behind `Pods/` with `ReactAppDependencyProvider` from an older RN codegen run. Delete `example/ios/Pods` + `example/ios/Podfile.lock` and re-run `pod install` before retrying.
- **Android — daemon busy-spin on this Gradle/AGP pair.** Gradle 9.0.0 + AGP 8.12.0 (from `@react-native/gradle-plugin`) has been observed to spin a daemon JVM on `:app:mergeDebugShaders` with no child processes. The native library still compiles cleanly. If you hit it, kill the daemon (`jps` then `kill <pid>`), and retry with `--info` to localize; if it reproduces, downgrade Gradle wrapper to `8.x` known to match AGP 8.12.
- **Android — JDK detection.** Without the toolchain overrides in `example/android/gradle.properties`, Gradle attempts foojay auto-provisioning, which fails on this host kernel string. Do not delete those lines.
- **Do not run two `./gradlew` invocations concurrently** — they fight over `~/.gradle/daemon/9.0.0/registry.bin.lock`.

## Validation matrix

Use the smallest relevant checks first, then broaden based on what changed.

### Documentation-only changes

- Review links, examples, API names, defaults, units, and platform claims against the source.
- No build is normally required.

### TypeScript wrapper or type changes

Run:

```sh
bun run typecheck
bun run lint
bun run test --maxWorkers=2
bun run build
```

### Nitro/codegen API changes

Run all TypeScript checks, re-run `bun run specs`, and run both native example builds. Codegen mismatches often appear only during Gradle/Xcode builds.

### Android Kotlin/C++/Gradle changes

Run TypeScript checks if the bridge changed, then:

```sh
bun run turbo run build:android --cache-dir=.turbo/android
```

For behavioral detection changes, also run the example on an emulator and at least one physical Android device when available. Native changes require rebuilding the app.

### iOS Swift/Objective-C/podspec changes

Run TypeScript checks if the bridge changed, then on macOS:

```sh
bun run turbo run build:ios --cache-dir=.turbo/ios
```

For behavioral detection changes, test both simulator and physical iOS device when available. Native changes require reinstalling pods when podspec/source integration changes and rebuilding the app.

### Cross-platform security changes

Compare results for:

- `isDeviceCompromised()`
- emulator/simulator status
- debugger status
- detection reasons
- watchdog start, duplicate start, stop, and restart in `LOG_ONLY` mode

Document any intentional platform difference. Do not infer physical-device correctness solely from emulator/simulator builds.

## Testing expectations

The Jest suite covers the wrapper layer (`src/__tests__/index.test.tsx`). When changing JavaScript behavior:

- Mock the Nitro HybridObject (`NitroModules.createHybridObject`) before importing the public entry point.
- Cover successful values, native rejection behavior, platform normalization, default watchdog options, and explicit watchdog options.
- Verify `isDeviceCompromised()` rejects while fallback APIs return their documented fallback values.
- Reset mocks and `Platform.OS` changes between tests.

Native heuristics are difficult to validate with unit tests alone. Prefer extracting deterministic parsing/matching logic into pure functions where feasible, then test those functions natively. The PR 2 Android baseline follows this split: `cpp/ProcParsers.*` (pure `/proc`/`/sys` parsing), `cpp/Scoring.hpp` (pure aggregation), and `cpp/SignalCatalog.*` (id → weight lookup) are deterministic and fixture-testable; `cpp/AndroidProbes.*` and `cpp/AndroidChecks.*` carry the platform I/O. Keep device-level verification through the example app for filesystem, process, debugger, socket, and runtime-instrumentation behavior.

## Package publishing

This package is published as `@psync/anti-jailbreak` on npmjs.org (scoped
package, public access). To publish:

```sh
bun run release   # release-it handles version bump, tag, and npm publish
```

The `publishConfig` in `package.json` sets `access: public` (required for
scoped packages). Native files in `cpp/`, `android/`, `ios/`, and
`nitrogen/generated/` are included in the shipped package via the `files`
field. The `.podspec` at the root is picked up by React Native CocoaPods
autolinking.

## Documentation and contribution requirements

- Keep `README.md` synchronized with exported APIs, defaults, supported modes, setup, and security limitations.
- Update the example app for user-visible APIs when practical.
- Keep pull requests small and focused.
- Do not fix unrelated detection heuristics while implementing a scoped change.
- Follow Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`) if asked to create a commit.
- Do not publish, release, tag, commit, or create branches unless explicitly requested.

## Review checklist

Before considering a change complete, verify:

- Public TypeScript, codegen spec, Android, and iOS signatures agree.
- Promise/synchronous behavior and fallback semantics are preserved or documented.
- Millisecond/second conversions are correct.
- New positive heuristics provide accurate detection reasons.
- File, socket, symbol, thread, JNI, and native-memory resources are cleaned up.
- Simulator/emulator and physical-device behavior were considered separately.
- Watchdog changes are safe under repeated start/stop and do not use destructive modes during tests.
- Generated artifacts under `nitrogen/generated/` were not edited directly; `.nitro.ts` specs and `nitro.json` are the source of truth and `bun run specs` was re-run after spec changes.
- Relevant lint, typecheck, tests, package build, and native build commands were actually run and reported.
