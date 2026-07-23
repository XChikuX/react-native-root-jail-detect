# CLAUDE.md

## Repository overview

This repository contains `react-native-root-jail-detect`, a React Native **Nitro Module** that detects rooted Android devices, jailbroken iOS devices, emulators/simulators, debuggers, Frida/runtime instrumentation, and hooking frameworks. It exposes a scored, structured device-risk API plus a periodic native security watchdog.

The repository is a Bun workspace:

- The publishable library lives at the repository root.
- `example/` is a React Native app that consumes the local library and is the primary integration test surface.

The library is **New Architecture only** and is built on [Nitro Modules](https://nitro.margelo.com/). There is no Old-Architecture bridge fallback, no TurboModule codegen spec, and no handwritten Objective-C externs. Nitrogen generates the C++/Swift/Kotlin bindings from `.nitro.ts` specs; the shared detection core is implemented in C++ and called from thin Swift/Kotlin edge HybridObjects at the platform boundary.

Preserve compatibility across the TypeScript specs, JavaScript wrappers, shared C++ core, platform edge HybridObjects, generated Nitro code, and documentation whenever changing the public API. The full migration plan lives in `PLAN.md`.

## Toolchain

Use the versions and package manager committed to the repository:

- Node.js: `v22.20.0` from `.nvmrc`
- Bun: `1.x` from `packageManager`
- React Native: `0.83.0` (New Architecture only)
- React: `19.2.0`
- TypeScript: `5.9.x`, strict mode
- Nitro Modules: `react-native-nitro-modules` + `nitrogen` codegen (currently `0.36.x`)
- Android: Kotlin `2.0.21`, min SDK 24, compile/target SDK 36, JDK 17 in CI, NDK 27+
- iOS: minimum version supplied by React Native's `min_ios_version_supported`, Xcode 16.4+, Swift 5.9+, C++20

Install dependencies from the repository root:

```sh
bun install --frozen-lockfile
```

Do not use npm for repository development; the workspace and lockfile are Bun-managed.

## Important paths

### Public JavaScript/TypeScript API

- `src/specs/RootJailDetect.nitro.ts` — root HybridObject Nitro spec (`configure`, `checkDetailed`, `getWatchdog`). Source of truth for the native contract.
- `src/specs/SecurityWatchdog.nitro.ts` — watchdog HybridObject Nitro spec (`start`, `stop`, `isRunning`).
- `src/specs/*.ts` — named codegen types (`DeviceRiskResult`, `DetectionSignal`, `Severity`, `Confidence`, `Platform`, `ProtectionMode`, `RootJailDetectOptions`, `SecurityWatchdogOptions`). Each lives in its own file because Nitro requires named types for native codegen.
- `src/specs/index.ts` — barrel re-exporting all spec types (specs themselves must not re-export unrelated types).
- `src/wrappers.ts` — legacy boolean API (`isDeviceCompromised`, `isEmulator`, `isDebuggerAttached`, `getDetectionReasons`, `startSecurityWatchdog`, `stopSecurityWatchdog`) implemented as thin wrappers over `checkDetailed()`. Owns the lazily-created root HybridObject handle.
- `src/index.tsx` — public entry point, barrel only (no logic; re-exports wrappers and spec types, plus a backwards-compatible default object).
- `src/types.ts` — re-exports the public spec types for older import paths.
- `src/__tests__/index.test.tsx` — Jest tests for the wrapper layer (mocks the native HybridObject before importing the entry point).

### Shared C++ core

- `cpp/HybridRootJailDetect.hpp` / `.cpp` — shared C++ implementation of the root HybridObject. Owns resolved configuration and creates the watchdog. Stays as orchestration; detection helpers live in focused files.
- `cpp/HybridSecurityWatchdog.hpp` / `.cpp` — shared C++ implementation of the watchdog HybridObject. Owns the background thread and lifecycle state and consumes `checkDetailed()` (no duplicated boolean logic).

### Android

- `android/CMakeLists.txt` — builds the `RootJailDetect` shared library and includes the generated autolinking cmake.
- `android/build.gradle` — Android library config; applies the generated Nitro autolinking gradle and points `externalNativeBuild` at `CMakeLists.txt`.
- `android/src/main/AndroidManifest.xml` — library manifest.
- (Future, PR 2) thin Kotlin edge HybridObjects under `android/src/main/java/...` for PackageManager, system properties, and Play Integrity, called from the C++ core through their generated spec API.

### iOS

- `ios/` — reserved for thin Swift edge HybridObjects (PR 3: sandbox, `_dyld`, URL schemes, debugger state).
- `RootJailDetect.podspec` — CocoaPods spec; uses `add_nitrogen_files(s)` to pull in generated specs/bridges and the `NitroModules` dependency.

### Generated Nitro code (committed, never hand-edited)

- `nitro.json` — Nitrogen config: `cxxNamespace`, `iosModuleName`, `androidCxxLibName`, and the `autolinking` map (root + watchdog HybridObjects, both C++-backed via the `"all"` key).
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
    -> Android edge: Kotlin HybridObjects (PackageManager, system properties, Play Integrity)
    -> iOS edge: Swift HybridObjects (sandbox, loaded images, URL schemes, debugger state)
```

`checkDetailed()` is the primary, structured API and returns a `DeviceRiskResult` (score, signals, confidence, debugger state, partial flag). The legacy boolean wrappers are derived from it so all detection logic lives in one place.

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

Keep the module registration name exactly `RootJailDetect` (the `createHybridObject<RootJailDetect>('RootJailDetect')` string must match the `nitro.json` autolinking key). Native implementation classes (`HybridRootJailDetect`, `HybridSecurityWatchdog`) must be **default-constructible** because Nitro autolinks them with no constructor arguments. Do not hand-edit generated code under `nitrogen/generated/`; change the `.nitro.ts` spec and re-run nitrogen.

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
- `TERMINATE` and iOS `THROW_EXCEPTION`/`fatalError` are destructive. Do not exercise them in automated tests or routine manual validation. Use `LOG_ONLY` for safe watchdog testing.
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
- Keep `cpp/HybridRootJailDetect.cpp` as orchestration; extract detection helpers into focused files (e.g. `ProcParsers.cpp`, `PatternMatcher.cpp`) as complexity grows.
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

Native heuristics are difficult to validate with unit tests alone. Prefer extracting deterministic parsing/matching logic into pure functions where feasible, then test those functions natively. Keep device-level verification through the example app for filesystem, process, debugger, socket, and runtime-instrumentation behavior.

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
