# Root/Jailbreak Detection Upgrade Plan

## Goal

Evolve `react-native-root-jail-detect` from a path-based boolean checker into an Expo-compatible, Nitro-powered, scored device-risk module. The goal is to detect common rooted Android configurations including Magisk + Zygisk + DenyList more reliably, reduce false positives on stock iOS devices, and provide server-verifiable integrity signals.

This is a **full migration to Nitro Modules targeting v2.0.0**: New Architecture only, one native bridge, no handwritten Objective-C externs, no TurboModule codegen spec. The existing TurboModule (`src/NativeRootJailDetect.ts`), iOS `RootJailDetect.m` externs, and generated `NativeRootJailDetectSpec` classes are removed.

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

### Add a detailed API

```ts
export type Severity = 'low' | 'medium' | 'high';

export type DetectionSignal = {
  id: string;
  severity: Severity;
  score: number;
  evidence?: string; // Redacted, development/debug builds only.
  unavailable?: boolean; // Check could not run; not a detection.
};

export type DeviceRiskResult = {
  platform: 'android' | 'ios';
  compromised: boolean;
  score: number; // 0 to 100
  confidence: 'low' | 'medium' | 'high';
  signals: DetectionSignal[];
  debuggerDetected: boolean;
  elapsedMs: number;
  partial: boolean; // True when the total deadline cut off remaining checks.
};

export type RootJailDetectOptions = {
  minScore?: number;
  timeoutMs?: number;
  includeEvidence?: boolean;
  treatDebuggerAsCompromise?: boolean;
  enablePlayIntegrity?: boolean;
};

export function configure(options: RootJailDetectOptions): void;
export function checkDetailed(): Promise<DeviceRiskResult>;
```

Nitro codegen supports string-literal unions (`Severity`, `confidence`) and optional struct fields natively, so these types live in `src/specs/` as named types and are re-exported from `src/index.ts`.

### Defaults

- `minScore`: 40
- `timeoutMs`: 400 total budget, with per-check deadlines; overrun checks return `unavailable` signals and set `partial: true` rather than failing the call
- `includeEvidence`: false in release builds
- `treatDebuggerAsCompromise`: false
- `enablePlayIntegrity`: false unless configured

## Risk model

Use weighted, independently generated signals. Cap the overall score at 100 and avoid counting equivalent evidence repeatedly.

| Signal class | Example | Initial score | Notes |
|---|---:|---:|---|
| High | Zygisk/Magisk artifact in mount metadata | 35 | Strong local signal |
| High | Zygisk, LSPosed, Frida, or Riru library mapped in process memory | 30 | Use exact and normalized pattern matching |
| High | SELinux disabled/permissive on production device | 25 | OEM/debug exemptions must be documented |
| Medium | Root manager/kernel-root data directory accessible | 20 | Multi-method native probes |
| Medium | Boot verification unlocked or orange | 20 | Do not treat alone as root |
| Medium | Integrity verdict fails server policy | 30 | Verify only on backend |
| Low | `su` executable/path found | 10 | Commonly hidden and easy to hook |
| Low | `test-keys` build tag | 10 | Often legitimate on custom ROMs |
| Low | Hidden mount-namespace overlay content | 10 | See note below |
| Informational | Debugger/TracerPid | 0 by default | Separate signal from compromise |

**Mount namespaces:** on modern Android, apps legitimately run in their own mount namespace, so a namespace *identity mismatch* (`/proc/1/ns/mnt` vs `/proc/self/ns/mnt`) is expected and must not be a signal by itself. The useful signal is specific hidden overlay/bind-mount *content* visible only through namespace comparison. Weight low until validated on the device matrix.

`compromised` is true when the score meets `minScore`, or when server policy marks an integrity verdict as failed. The host app can choose a stricter or more permissive threshold.

## Architecture

```text
TypeScript API (src/index.ts barrel + wrappers)
  -> Nitro HybridObjects (nitrogen codegen)
    -> Shared C++ core: scoring, signal catalog, pattern matching, /proc parsing (Android)
    -> Android edge: Kotlin HybridObjects (PackageManager, system properties, Play Integrity)
    -> iOS edge: Swift HybridObjects (sandbox, loaded images, URL schemes, debugger state)
  -> Optional backend attestation verifier
```

### Native core: cross-platform C++

The root HybridObject is implemented in C++ (`{ ios: 'c++'; android: 'c++' }`) so scoring primitives, the signal catalog, deduplication, and pattern matching are shared across platforms in one implementation. Platform-specific work stays in thin Swift/Kotlin HybridObjects at the edges:

- C++: `/proc` parsing (Android), mountinfo/maps pattern matching, scoring and signal aggregation, TracerPid checks.
- Kotlin: `PackageManager` queries, system-property reads, verified-boot properties, Play Integrity token acquisition. The C++ core can call these through the generated C++ spec interface.
- Swift: sandbox-boundary probes, `_dyld` loaded-image inspection, URL-scheme checks, `sysctl` debugger state.
- TypeScript: configuration, typed result shaping, legacy wrapper compatibility, watchdog option defaults.

The existing `android/src/main/java/com/rootjaildetect/native/native_security.cpp` JNI checks migrate into the C++ core; the hand-written JNI export layer is deleted because Nitro generates the bindings.

### Nitro object model

- `RootJailDetect` (root HybridObject, autolinked): `configure(options)`, `checkDetailed(): Promise<DeviceRiskResult>`, sync cheap getters for cached state. Default-constructible.
- `SecurityWatchdog` (separate HybridObject): owns the long-lived background thread and mutable lifecycle state, per the one-lifecycle-per-HybridObject rule. Created from the root object, exposes `start(options)` / `stop()` / `isRunning`. **The watchdog consumes `checkDetailed()` with the configured threshold** — it must not duplicate boolean detection logic. Existing modes (`LOG_ONLY`, `THROW_EXCEPTION`, `TERMINATE`) and millisecond intervals are preserved on both platforms.
- Named spec types (`DetectionSignal`, `DeviceRiskResult`, options, enums) live in their own files under `src/specs/` and are re-exported publicly.

## Android implementation

### Phase 0: repository audit and test harness

1. Inventory all current Android checks, their implementation language, and their false-positive profile.
2. Add a sample React Native app and Expo prebuild sample app.
3. Add a debug-only screen that renders signal IDs, severities, score, and elapsed time; do not display raw sensitive evidence in release builds.
4. Establish a device matrix: stock Android, bootloader-unlocked stock Android, Magisk with Zygisk, Magisk with DenyList, Magisk with common hiding modules, KernelSU, APatch, emulator, and custom ROM.
5. Record expected results in `e2e/matrix.md`.

### Phase 1: scored native baseline

Implement these checks first, in priority order:

1. Parse `/proc/self/mountinfo` and `/proc/self/mounts` for root-framework overlays, suspicious bind mounts, and known Magisk/KSU/APatch remnants.
2. Compare mount namespaces only to surface hidden overlay content, never as identity-mismatch proof (see risk model note).
3. Parse `/proc/self/maps` for loaded Zygisk, Riru, LSPosed, Frida, and known hooking-framework artifacts.
4. Check SELinux enforcement state using system interfaces and native file reads.
5. Read relevant verified-boot and debug build properties.
6. Probe root-manager directories and conventional `su` locations through more than one native filesystem API.
7. Add `TracerPid` and debugger checks as informational signals.
8. Return all signals through `checkDetailed()`.

### Phase 2: package and runtime checks

1. Detect known root-management and hook-management packages through `PackageManager` while treating renamed/hidden apps as expected evasion.
2. Add defensive process, command-line, and local-socket indicators for runtime instrumentation.
3. Enforce per-check deadlines and the total `timeoutMs` budget; failures and timeouts return `unavailable` signals rather than crashing or blocking the app.
4. Ensure the implementation works without `QUERY_ALL_PACKAGES`; request only narrowly necessary package visibility entries where possible.

### Phase 3: resilience and integrity

1. Add optional light self-integrity for native assets, such as expected library metadata/check values supplied at build time.
2. Avoid presenting client self-integrity as authoritative: local code can always be modified by a sufficiently capable attacker.
3. Integrate Play Integrity token acquisition behind an explicit option.
4. Send the token to the application backend; the backend verifies it with Google and applies product-specific policy.
5. Bind sensitive API actions to a short-lived server-issued session decision rather than trusting an unverified client boolean.

## iOS implementation

### Correct debugger semantics

Split debugger status from jailbreak status immediately:

- `debuggerDetected` is diagnostic and must not affect `compromised` by default.
- Enable debugger-based blocking only through `treatDebuggerAsCompromise: true`.
- Exclude expected development workflows where appropriate, including Xcode-attached debug sessions.
- Document the behavior for development, TestFlight, enterprise/MDM, and App Store builds.

### Jailbreak checks

1. Maintain a conservative list of known jailbreak application/file artifacts.
2. Attempt sandbox-boundary checks safely, without modifying user data.
3. Inspect suspicious injected dynamic libraries and loaded-image names as a best-effort signal.
4. Check URL schemes carefully; unavailable schemes are not proof of a clean device.
5. Make each signal independently visible in `checkDetailed()` and tune weights against real stock-device testing.

## Expo delivery

1. Create a root-level `app.plugin.js` (with source under `plugin/src/` if it grows) to configure Android/iOS native project changes during `expo prebuild`.
2. Ensure the module works with EAS Build and a custom development client.
3. Fail clearly in Expo Go with an actionable error: native checks require prebuild/custom client.
4. Provide an Expo example app with development and release configuration examples.
5. Nitro requires the New Architecture, which is the only supported mode; no bridge fallback is provided.

## Repository layout

```text
src/
  index.ts               # Barrel: re-exports + root Nitro object creation
  specs/
    RootJailDetect.nitro.ts
    SecurityWatchdog.nitro.ts
    DeviceRiskResult.ts  # Named structs, unions, option types
  wrappers.ts            # Legacy boolean API over checkDetailed()
cpp/                     # Shared C++ HybridObject implementations + detection core
android/
  src/main/java/.../     # Thin Kotlin edge HybridObjects
ios/                     # Thin Swift edge HybridObjects
nitro.json               # Namespaces + autolinking entries
nitrogen/generated/      # Codegen output; committed, never hand-edited
app.plugin.js            # Expo config plugin entry
plugin/src/              # Plugin source if non-trivial
example/
  expo/
  react-native/
docs/
  DETECTION.md
  EXPO.md
  THREAT_MODEL.md
e2e/
  matrix.md
  fixtures/
```

Migration notes:

- Delete `src/NativeRootJailDetect.ts`, `ios/RootJailDetect.m`, and the hand-written JNI layer; Nitro generates all bindings.
- `nitrogen/generated/` must be committed and included in the npm `files` field so consumers can build.
- Keep the native library/module registration names stable where consumer-facing; update `System.loadLibrary` and CMake target names together if renamed.

## Documentation

### `docs/DETECTION.md`

Document every public signal ID, severity, initial weight, supported platform, evidence-redaction policy, and known false-positive limitations. Do not publish implementation details that make bypassing individual checks trivial; publish enough to let adopters make safe policy decisions.

### `docs/THREAT_MODEL.md`

State explicitly that:

- Client-side detection is bypassable.
- Root detection should not be the only authorization control.
- Server-side attestation, short-lived credentials, rate limits, telemetry, TLS pinning where appropriate, and step-up authentication provide layered protection.
- A rooted power user is not automatically malicious; product policy must balance fraud prevention and user access.

### `docs/EXPO.md`

Include installation, prebuild, custom dev client, EAS Build, Android manifest/package-visibility needs, Play Integrity setup, and troubleshooting.

## Testing and acceptance criteria

### Automated tests

- Unit-test `/proc` parsers with fixtures for stock and modified mount/maps samples.
- Unit-test scoring: duplicate/equivalent signals must not inflate scores unexpectedly.
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
- Jailbroken iPhone when available

### Acceptance criteria for v2.0.0

- A stock locked Android device produces no high-severity root signals.
- A Magisk + Zygisk device that hides `su` still produces one or more meaningful environment or memory-related signals when artifacts remain visible.
- A stock iPhone with an attached debugger reports `debuggerDetected: true` but `compromised: false` under default configuration.
- All checks finish within the default total timeout and never crash on unreadable `/proc` entries; deadline overruns surface as `unavailable` signals with `partial: true`.
- Expo prebuild + EAS Build integration is documented and verified in the example app.
- Watchdog start, duplicate start, stop, and restart behave correctly in `LOG_ONLY` mode and consume the same scoring path as `checkDetailed()`.
- The library never claims that it is impossible to bypass.

## Release milestones

### Milestone 1: Nitro migration + reliable local baseline

- Nitro spec, codegen pipeline, shared C++ core, thin Kotlin/Swift edges
- Detailed scored API and legacy wrappers
- Android mounts, maps, SELinux, properties, path probes, and debugger status
- iOS debugger/jailbreak separation
- Watchdog reimplemented as a HybridObject over the scoring path
- Tests, sample app, and detection documentation
- Published as `2.0.0` with a migration guide (New Architecture required, no API renames)

### Milestone 2: Expo-ready package

- Config plugin
- Expo prebuild and EAS sample
- Clear Expo Go behavior

### Milestone 3: integrity-backed decisions

- Optional Play Integrity client integration
- Reference backend verifier contract
- FastAPI example endpoint and policy examples

### Milestone 4: ongoing maintenance

- Quarterly test-matrix refresh
- Versioned signal catalog
- Regression tests for new Android releases and commonly used root frameworks
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

Kept small and focused, in order:

1. **PR 1 — Nitro skeleton:** `nitro.json`, `src/specs/RootJailDetect.nitro.ts` with `checkDetailed()` returning the full `DeviceRiskResult` struct, nitrogen codegen wired into the build, example app compiling against generated specs with stub native implementations returning empty results. Legacy wrappers reshaped over `checkDetailed()` with stub data.
2. **PR 2 — Android scored baseline:** C++ mountinfo/maps parsers, SELinux and verified-boot checks, TracerPid as informational, scoring with dedup, fixture-based parser unit tests.
3. **PR 3 — iOS separation + watchdog:** debugger/jailbreak split, `SecurityWatchdog` HybridObject consuming `checkDetailed()`, repeated start/stop/restart coverage in `LOG_ONLY` mode.
4. **PR 4 — Expo skeleton:** config plugin stub, Expo prebuild example, Expo Go error path.
5. **PR 5 — Matrix documentation:** Magisk + Zygisk + DenyList test profile and recorded observed signals in `e2e/matrix.md`.
