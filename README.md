# @psync/anti-jailbreak

[![npm version](https://img.shields.io/npm/v/@psync/anti-jailbreak.svg)](https://www.npmjs.com/package/@psync/anti-jailbreak)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A **React Native Nitro Module** that detects rooted (Android) and jailbroken
(iOS) devices, emulators/simulators, attached debuggers, and runtime
instrumentation frameworks (Frida, Zygisk/LSPosed/Riru). It exposes a **scored,
structured device-risk API** plus an optional periodic security watchdog.

@psync/anti-jailbreak is a [Nitro Module](https://nitro.margelo.com/).
It is **New Architecture only** — there is no Old-Architecture bridge fallback, no
TurboModule spec, and no handwritten JNI/externs. The shared detection core is
written in C++ and shared across iOS and Android; Swift and Kotlin are used only
for thin platform-edge probes.

> **Security note:** no client-side root/jailbreak detection is foolproof. This
> library is a defense-in-depth signal, not a guarantee. Pair it with server-side
> attestation (e.g. Play Integrity verified on your backend), SSL pinning, and
> other layered controls. See [Security limitations](#security-limitations).

---

## Features

- **Scored, structured results** — every check produces a `DetectionSignal` with
  a stable id, severity, and weight; signals aggregate into a 0–100 risk score
  with a confidence level.
- **Cross-platform C++ core** — scoring, the signal catalog, pattern matching,
  and `/proc` parsing are shared; platform-specific probes live at the edges.
- **New Architecture only** — built on Nitro Modules; no bridge fallback.
- **Runtime watchdog** — a separate `SecurityWatchdog` HybridObject that
  periodically re-runs detection and can log, throw, or terminate.
- **Timeout budget & partial results** — checks that overrun the configured
  budget surface as `unavailable` signals with `partial: true` rather than
  throwing.
- **Stable signal ids** — every detection maps to a documented, versioned id so
  callers and backends can reason about *what* fired.

---

## Installation

```sh
npm install @psync/anti-jailbreak react-native-nitro-modules
```

or

```sh
bun add @psync/anti-jailbreak react-native-nitro-modules
```

`react-native-nitro-modules` >=35.0.0 is a required peer dependency.

### iOS

```sh
cd ios && pod install && cd ..
```

### Android

Autolinking handles the rest. React Native 0.83+ with the New Architecture is
required.

---

## Quick start

```ts
import {
  isDeviceCompromised,
  getDetectionReasons,
  checkDetailed,
  configure,
} from '@psync/anti-jailbreak';

// Optional: tune thresholds before checking. `undefined` fields keep prior values.
configure({ minScore: 40, timeoutMs: 400 });

// Primary, structured API.
const result = await checkDetailed();
console.log(result.score, result.confidence, result.signals);

// Legacy boolean convenience (derived from checkDetailed).
const compromised = await isDeviceCompromised();
if (compromised) {
  console.warn(await getDetectionReasons());
}
```

---

## API

### `checkDetailed(): Promise<DeviceRiskResult>`

Run every enabled device-risk check within the configured timeout budget and
return the full structured result. This is the primary API; the boolean helpers
below are derived from it.

Checks that cannot complete in time report `unavailable` signals and the result
is marked `partial: true` rather than failing the call.

### `configure(options: RootJailDetectOptions): void`

Apply configuration that affects subsequent `checkDetailed()` passes and the
watchdog. Passing `undefined` for a field keeps the existing value.

```ts
type RootJailDetectOptions = {
  minScore?: number;              // default 40 — score at/above which compromised=true
  timeoutMs?: number;             // default 400 — total detection budget
  includeEvidence?: boolean;      // default false — attach redacted evidence strings
  treatDebuggerAsCompromise?: boolean; // default false
  enablePlayIntegrity?: boolean;  // default false
};
```

### Legacy boolean API

These remain for backwards compatibility. They are thin wrappers over
`checkDetailed()` and preserve the historical error semantics:
`isDeviceCompromised()` rethrows native errors; the others log and return a safe
fallback.

| Function | Resolves to | Safe fallback |
| --- | --- | --- |
| `isDeviceCompromised()` | `result.compromised` | rethrows |
| `isEmulator()` | platform emulator/simulator signal | `false` |
| `isDebuggerAttached()` | `result.debuggerDetected` | `false` |
| `getDetectionReasons()` | derived from signal ids + redacted evidence | `[]` |

### Security watchdog

```ts
import { startSecurityWatchdog, stopSecurityWatchdog } from '@psync/anti-jailbreak';

startSecurityWatchdog({
  intervalMs: 5000,          // milliseconds; legacy `interval` is accepted as an alias
  protectionMode: 'LOG_ONLY', // 'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE'
});

stopSecurityWatchdog();
```

The watchdog is a separate `SecurityWatchdog` HybridObject that consumes
`checkDetailed()` with the configured threshold on each tick. It does not
duplicate detection logic.

| Mode | Behavior |
| --- | --- |
| `LOG_ONLY` | Logs detection events. Safe for testing. |
| `THROW_EXCEPTION` | Throws a runtime exception when the threshold is exceeded. |
| `TERMINATE` | Terminates the application. **Destructive — do not use in tests.** |

### Result types

```ts
type Severity = 'low' | 'medium' | 'high';
type Confidence = 'low' | 'medium' | 'high';

interface DetectionSignal {
  id: string;            // stable, versioned identifier (see signal catalog)
  severity: Severity;
  score: number;         // weight contributed to the total
  evidence?: string;     // only when includeEvidence is enabled; redacted
  unavailable?: boolean; // check could not run — NOT evidence of compromise
}

interface DeviceRiskResult {
  platform: 'android' | 'ios';
  compromised: boolean;
  score: number;         // 0–100, clamped
  confidence: Confidence;
  signals: DetectionSignal[];
  debuggerDetected: boolean;
  elapsedMs: number;
  partial: boolean;      // true when the budget cut off remaining checks
}
```

---

## Signal catalog

Signal ids are part of the public contract: they never change once published
(weights may be tuned between versions). Each id maps to a default severity and
score weight.

| Severity | Signal id | Score | Description |
| --- | --- | ---: | --- |
| high | `android.mount.magisk` | 35 | Magisk/KSU/APatch overlay in mount metadata |
| high | `android.maps.zygisk` | 30 | Zygisk library mapped in memory |
| high | `android.maps.lsposed` | 30 | LSPosed/Xposed library mapped in memory |
| high | `android.maps.frida` | 30 | Frida agent/artifact mapped in memory |
| high | `android.maps.riru` | 30 | Riru library mapped in memory |
| high | `android.selinux.permissive` | 25 | SELinux not enforcing on a production device |
| medium | `android.root_manager.dir` | 20 | Root-manager data/app directory accessible |
| medium | `android.bootloader.unlocked` | 20 | Verified boot reports unlocked/orange state |
| medium | `android.emulator` | 20 | Strong emulator indicators |
| low | `android.su.binary` | 10 | `su` binary at a conventional location |
| low | `android.build.test_keys` | 10 | `ro.build.tags` reports `test-keys` |
| low | `android.mount.overlay` | 10 | Hidden overlay/bind-mount content |
| informational | `android.debugger.tracerpid` | 0 | `TracerPid` nonzero (diagnostic; see below) |

> **Debugger semantics:** `debuggerDetected` is reported separately and does
> **not** affect `compromised` by default. Set `treatDebuggerAsCompromise: true`
> in `configure()` to fold it into the compromise decision. iOS signals
> (`ios.simulator` and others) land in PR 3.

`compromised` is true when the aggregated score meets the configured `minScore`,
or when the caller opts the debugger flag into the decision.

---

## Example app

`example/` contains a React Native app that consumes the local library and
renders the score, confidence, every fired signal, and the derived booleans.
It is the primary integration-test surface.

```sh
bun install --frozen-lockfile
bun run example android   # or: bun run example ios
```

---

## Platform support

- **Android:** Kotlin `2.0.21`, min SDK 24, compile/target SDK 36, NDK 27+.
- **iOS:** minimum version supplied by React Native's `min_ios_version_supported`,
  Xcode 16.4+, Swift 5.9+, C++20.
- **React Native:** 0.83+ (New Architecture only).

### Detection coverage

**Android (PR 2):** `/proc/self/maps` hook scanning (Zygisk/LSPosed/Frida/Riru),
`/proc/self/mountinfo` + `/proc/self/mounts` root-framework overlays, SELinux
enforcement state, root-manager directory and `su` binary probes, build-tag and
verified-boot properties, and `TracerPid` as an informational debugger signal.

**iOS (PR 3, in progress):** sandbox-boundary probes, `_dyld` loaded-image
inspection, URL-scheme checks, and `sysctl` debugger state.

**Play Integrity (future):** optional client-side token acquisition behind
`enablePlayIntegrity`; the token must be verified by your backend with Google
and bound to a short-lived server-issued decision.

---

## Security limitations

- **Not foolproof.** Determined attackers with sufficient capability can hide
  root/jailbreak and hook these checks. Treat absence of signals as "no evidence
  found", not as proof of a clean device.
- **Client booleans are not authoritative.** Never gate sensitive actions solely
  on a client-reported score or signal list. Use server-side attestation and
  short-lived session decisions.
- **False positives are possible.** `test-keys`, unlocked bootloaders, and
  permissive SELinux occur on legitimate custom ROMs and developer devices.
  Tune `minScore` and review `signals` before blocking users.
- **Heuristics evolve.** Root frameworks update their hiding techniques; keep
  the library updated and contribute observed signals to the device matrix.

---

## Contributing

PRs are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow and
conventional-commit policy. Keep PRs small and focused, and do not fix unrelated
detection heuristics while implementing a scoped change.

---

## License

MIT © Psync
