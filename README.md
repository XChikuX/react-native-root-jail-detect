# @psync/anti-jailbreak

[![npm version](https://img.shields.io/npm/v/@psync/anti-jailbreak.svg)](https://www.npmjs.com/package/@psync/anti-jailbreak)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A **React Native Nitro Module** (New Architecture only) for detecting rooted (Android) and jailbroken (iOS) devices, emulators/simulators, attached debuggers, and runtime instrumentation frameworks (Frida, Zygisk, LSPosed, Riru). Features a scored risk API, stable signal catalog, and optional periodic security watchdog.

> **Security Note:** Client-side detection is a defense-in-depth heuristic, not a guarantee. Determined attackers can hook or bypass checks. Never use client booleans as sole authorization for sensitive actions—pair with backend Play Integrity / App Attest verification.

---

## Installation

```sh
# npm
npm install @psync/anti-jailbreak react-native-nitro-modules

# bun (recommended for development)
bun add @psync/anti-jailbreak react-native-nitro-modules
```

*(Requires React Native 0.83+ New Architecture and `react-native-nitro-modules` >= 0.35.0)*

### iOS & Expo

- **iOS:** Run `cd ios && pod install`
- **Expo:** Custom dev client or EAS Build required (cannot run in Expo Go). The package ships an Expo config plugin (`app.plugin.js`) that adds narrowly scoped `<queries>` entries for known root-manager apps on Android; it is wired automatically, but can be referenced explicitly with `plugins: ["@psync/anti-jailbreak"]` in `app.json` if package plugins are not auto-resolved. `@expo/config-plugins` is an optional peer (declared in `peerDependenciesMeta`); Expo prebuild always provides it as a transitive dependency of `expo`.

---

## Quick Start

```ts
import { checkDetailed, isDeviceCompromised, startSecurityWatchdog } from '@psync/anti-jailbreak';

// 1. Primary scored API
const result = await checkDetailed();
console.log(result.score, result.compromised, result.signals);

// 2. Legacy boolean helper
if (await isDeviceCompromised()) {
  console.warn('Device compromised!');
}

// 3. Optional periodic background watchdog
startSecurityWatchdog({ intervalMs: 5000, protectionMode: 'LOG_ONLY' });
```

---

## API Summary

- **`checkDetailed(): Promise<DeviceRiskResult>`** — Runs all enabled checks within a timeout budget (default `400ms`). Overrun checks return `unavailable: true` with `partial: true` rather than throwing.
- **`configure(options: RootJailDetectOptions): void`** — Configure `minScore` (default `40`), `timeoutMs`, `includeEvidence`, and `treatDebuggerAsCompromise`.
- **`isDeviceCompromised(): Promise<boolean>`** — Returns `true` if `score >= minScore`.
- **`isEmulator(): Promise<boolean>`** — Returns `true` if running in an emulator/simulator.
- **`isDebuggerAttached(): Promise<boolean>`** — Returns `true` if a debugger is attached.
- **`getDetectionReasons(): Promise<string[]>`** — Returns human-readable reasons for fired signals.
- **`startSecurityWatchdog(options): void`** — Periodically runs checks in background. `protectionMode` is `'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE'`. Note: `THROW_EXCEPTION` is demoted to a logged warning on the background thread (it cannot throw into the JS runtime); `TERMINATE` ends the process. To react in app code, poll `checkDetailed()` / `isDeviceCompromised()` from JS.
- **`stopSecurityWatchdog(): void`** — Stops the security watchdog thread.

---

## Result & option shapes

`checkDetailed()` returns a `DeviceRiskResult`:

```ts
interface DeviceRiskResult {
  platform: 'android' | 'ios';
  compromised: boolean;        // score >= minScore
  score: number;               // 0–100, clamped
  confidence: 'low' | 'medium' | 'high';
  signals: DetectionSignal[];  // all fired signals, including `unavailable: true` ones
  debuggerDetected: boolean;   // informational; folds into `compromised` only if configured
  elapsedMs: number;           // total detection pass time
  partial: boolean;            // true when the timeoutMs budget ran out before all checks finished
}

interface DetectionSignal {
  id: string;             // platform-prefixed, e.g. `android.mount.magisk`
  severity: 'low' | 'medium' | 'high';
  score: number;          // weight contributed to the aggregated score
  evidence?: string;      // only when RootJailDetectOptions.includeEvidence = true
  unavailable?: boolean;  // true when the check could not complete; never evidence of compromise
}
```

`configure()` accepts a `RootJailDetectOptions` partial:

```ts
interface RootJailDetectOptions {
  minScore?: number;                 // default 40 — `compromised` becomes true at or above this
  timeoutMs?: number;                // default 400 — total wall-clock budget per pass
  includeEvidence?: boolean;         // default false — see "Evidence redaction" below
  treatDebuggerAsCompromise?: boolean; // default false
  enablePlayIntegrity?: boolean;     // default false — server-attested; not yet wired
}
```

---

## Error semantics

Wrapper behavior is preserved from v1 for backwards compatibility:

- `isDeviceCompromised()` **logs and rethrows** native errors. Callers who call it directly must catch and decide policy.
- `isEmulator()`, `isDebuggerAttached()`, and `getDetectionReasons()` log the error and return safe fallbacks (`false`, `false`, `[]`) — they never throw.
- `checkDetailed()` and `configure()` propagate native errors directly without swallowing them.
- `startSecurityWatchdog()` / `stopSecurityWatchdog()` keep the legacy synchronous signature by firing the async native methods without awaiting; Promise rejections are logged, not rethrown.

Tests in `src/__tests__/index.test.tsx` pin these semantics; treat any change as a breaking change.

---

## Evidence redaction

`DetectionSignal.evidence` carries redacted, human-readable hints about what was observed (e.g. `"known-jailbreak-artifact"`, `"selinux=enforce:0"`). It is **off by default** and is additionally forced off in release builds:

```cpp
#if defined(NDEBUG)
    const bool includeEvidence = false;   // release builds: evidence is never attached
#else
    const bool includeEvidence = options.includeEvidence;  // debug builds: opt in via configure()
#endif
```

Leave `includeEvidence` disabled (the default) in production. The redacted hints are still meaningful to an attacker monitoring logcat or console output; treat them as development-only.

---

## Signal Catalog

| Severity | Signal ID | Weight | Description |
| --- | --- | ---: | --- |
| high | `android.mount.magisk` | 35 | Magisk / KernelSU / APatch mount overlay |
| high | `android.maps.zygisk` | 30 | Zygisk library mapped in process memory |
| high | `android.maps.lsposed` | 30 | LSPosed / Xposed library mapped in memory |
| high | `android.maps.frida` | 30 | Frida agent / artifact mapped in memory |
| high | `android.maps.riru` | 30 | Riru framework library mapped in memory |
| high | `android.selinux.permissive` | 25 | SELinux permissive mode on production device |
| high | `android.cmdline.instrumentation` | 30 | Instrumentation token in process command line |
| high | `android.socket.instrumentation` | 30 | Instrumentation token in local sockets |
| medium | `android.root_manager.dir` | 20 | Root-manager directory accessible |
| medium | `android.bootloader.unlocked` | 20 | Unlocked bootloader / verified boot orange |
| medium | `android.emulator` | 20 | Android emulator indicators |
| low | `android.su.binary` | 10 | `su` binary at conventional location |
| low | `android.build.test_keys` | 10 | `ro.build.tags` reports `test-keys` |
| low | `android.mount.overlay` | 10 | Hidden mount overlay in app namespace |
| informational | `android.debugger.tracerpid` | 0 | `TracerPid` non-zero (diagnostic) |
| high | `ios.dyld.hook` | 30 | Suspicious injection framework loaded |
| medium | `ios.jailbreak.artifact` | 20 | Jailbreak file or directory accessible |
| medium | `ios.simulator` | 20 | iOS simulator environment |
| informational | `ios.debugger.sysctl` | 0 | `sysctl` reports P_TRACED (diagnostic) |
| low | `*.check.*` | 0 | Check timed out / unavailable (not compromise) |

---

## Threat Model & Policy

- **Client heuristics are non-authoritative:** Always bind sensitive decisions to short-lived server sessions with backend attestation (Play Integrity / App Attest).
- **Legitimate custom ROMs & devs:** Unlocked bootloaders, `test-keys`, and permissive SELinux can occur on legitimate developer devices. Tune `minScore` appropriately.

---

## License

MIT © Psync
