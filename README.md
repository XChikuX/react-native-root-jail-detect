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

*(Requires React Native 0.83+ New Architecture and `react-native-nitro-modules` `~0.35.1` — see the compatibility matrix below)*

### Compatibility

`@psync/anti-jailbreak` is built on `react-native-nitro-modules` HybridObjects implemented in shared C++. The C++ must override NitroModules `HybridObject` virtuals with exact signatures, so compatibility is pinned to the NitroModules C++ ABI.

| `react-native-nitro-modules` | Status | Notes |
| --- | --- | --- |
| `< 0.35.1` | ❌ Not supported | `HybridObject` virtuals differ; outside the `~0.35.1` peer range. |
| `0.35.x` (`~0.35.1`) | ✅ Supported (current) | Current peerDependency range. `HybridObject::getExternalMemorySize()` is the override target; do **not** use the legacy `getMemorySize()` name. |
| `0.36.x` | ✅ Supported | Same `HybridObject::getExternalMemorySize()` API; verified against `0.36.1`. No code changes required. |
| `0.37.x` and above | ⚠️ Unverified | Not yet validated. Re-run `bun run specs` and a clean native build (iOS pod build + Android Gradle `clean`) before adopting, since NitroModules may rename or remove `HybridObject` virtuals again. |

> **Why this matters:** NitroModules once exposed `HybridObject::getMemorySize()` and later renamed it to `getExternalMemorySize()`. Because iOS consumes NitroModules as a **source-built** CocoaPod (live headers) while Android consumes it via a **prefab/prebuilt** header snapshot, an API rename can fail the iOS build while a cached Android build still passes. Whenever you bump NitroModules, clear both caches and rebuild natively.

### iOS & Expo

- **iOS:** Run `cd ios && pod install`
- **Expo:** Custom dev client or EAS Build required (cannot run in Expo Go). The package ships an Expo config plugin (`app.plugin.js`) that adds narrowly scoped `<queries>` entries for known root-manager apps on Android; it is wired automatically, but can be referenced explicitly with `plugins: ["@psync/anti-jailbreak"]` in `app.json` if package plugins are not auto-resolved. `@expo/config-plugins` is an optional peer (declared in `peerDependenciesMeta`); Expo prebuild always provides it as a transitive dependency of `expo`.

---

## Quick Start

```ts
import {
  checkDetailed,
  isDeviceCompromised,
  startSecurityWatchdog,
} from '@psync/anti-jailbreak';

// 1. Primary scored API — full structured assessment
const result = await checkDetailed();
console.log(result.score, result.compromised, result.confidence);

// 2. Legacy boolean helper (derives from checkDetailed)
if (await isDeviceCompromised()) {
  console.warn('Device compromised!');
}

// 3. Optional periodic background watchdog
startSecurityWatchdog({ intervalMs: 5000, protectionMode: 'LOG_ONLY' });
```

---

## Usage examples

### App-startup security gate

Run a single structured pass at startup, derive every value you need from the one result, and avoid calling multiple wrappers (each wrapper would re-run the native pass):

```ts
import { useEffect } from 'react';
import { Alert } from 'react-native';
import { checkDetailed, getDetectionReasons } from '@psync/anti-jailbreak';

function useStartupSecurityGate() {
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const result = await checkDetailed();
        if (cancelled) return;

        // One pass — derive every boolean locally instead of calling
        // isDeviceCompromised()/isEmulator()/isDebuggerAttached() again.
        const isEmu = result.signals.some(
          (s) => s.id.startsWith('android.emulator') || s.id.startsWith('ios.simulator'),
        );

        if (result.compromised) {
          const reasons = await getDetectionReasons();
          Alert.alert(
            'Security warning',
            `Device score ${Math.round(result.score)}/100.\n${reasons.join('\n')}`,
          );
        }

        console.log({
          compromised: result.compromised,
          score: result.score,
          confidence: result.confidence,
          emulator: isEmu,
          debugger: result.debuggerDetected,
          partial: result.partial,
        });
      } catch (error) {
        // checkDetailed() propagates native errors — decide your own policy.
        console.error('Security check failed:', error);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);
}
```

### Working with the scored API

`checkDetailed()` (or its alias `assessRisk()`) returns a `CompromiseAssessment`. Iterate `signals` for analytics, gating, or telemetry. Always filter out `unavailable` signals — they mean "the check couldn't run", not "evidence of compromise":

```ts
import { checkDetailed } from '@psync/anti-jailbreak';

const result = await checkDetailed();

// Positive findings only — skip unavailable rows.
const positiveSignals = result.signals.filter(
  (s) => s.unavailable !== true && s.detected,
);

for (const signal of positiveSignals) {
  console.log({
    id: signal.id,           // stable, e.g. 'android.mount.magisk'
    platform: signal.platform, // 'android' | 'ios'
    category: signal.category, // 'mount' | 'injection' | ... (see enum below)
    severity: signal.severity, // 'low' | 'medium' | 'high'
    score: signal.score,      // weight this signal contributed
    reliability: signal.reliability, // 0..1 — backend policy hint
    evidence: signal.evidence, // present only if includeEvidence is enabled
  });
}

// Partial results: the timeoutMs budget ran out before every check could run.
// Treat as non-authoritative and re-check before deciding.
if (result.partial) {
  console.warn('Detection pass was partial; some checks did not complete.');
}

// Confidence reflects how complete and convergent the evidence is.
// 'extreme' is reserved for passes with multiple high-severity signals
// from independent categories with a score near 100.
if (result.confidence === 'extreme' || result.score >= 80) {
  // Strong local indicator — still cross-check server-side.
}
```

### Configuring thresholds and behavior

`configure()` updates the native HybridObject in place; subsequent `checkDetailed()` passes and watchdog ticks observe the new values. Pass `undefined` for any field you want to leave untouched:

```ts
import { configure } from '@psync/anti-jailbreak';

configure({
  // `compromised` becomes true at or above this score (default 40).
  // Lower → stricter (more devices flagged); higher → looser.
  minScore: 50,

  // Total wall-clock budget per pass in ms (default 400).
  // Overrun checks return `unavailable` signals and `partial: true`.
  timeoutMs: 600,

  // Redacted per-signal evidence hints. Development/debug only — the native
  // core forces this off in release (NDEBUG) builds regardless.
  includeEvidence: __DEV__,

  // Off by default. Fold debugger attachment into `compromised` in addition
  // to surfacing it on `debuggerDetected`. A debugger alone is not an attack.
  treatDebuggerAsCompromise: false,
});
```

### iOS URL-scheme probing

iOS URL-scheme checks use `UIApplication.canOpenURL`, which iOS 15+ caps at 50 declared schemes per app via `LSApplicationQueriesSchemes`. The cap is shared across the host app — keep the list minimal and configurable. The Expo config plugin merges the configured schemes during prebuild:

```ts
import { configure } from '@psync/anti-jailbreak';

configure({
  urlSchemes: {
    // Defaults are the four most common jailbreak-store schemes.
    schemes: ['cydia', 'sileo', 'zbra', 'filza'],
    // Set to [] to disable URL-scheme probing entirely.
    // schemes: [],

    // Emit one `ios.urlscheme.<scheme>` signal per responding scheme
    // instead of the single aggregate `ios.urlscheme.jailbreak_store`.
    perSchemeSignals: true,
  },
});
```

For bare React Native, declare the schemes in `ios/<App>/Info.plist`:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
  <string>cydia</string>
  <string>sileo</string>
  <string>zbra</string>
  <string>filza</string>
</array>
```

Undeclared schemes safely return `NO` and never produce a false positive.

For Expo, the config plugin's own `urlSchemes` prop (separate from `configure()`) merges schemes into `Info.plist` during prebuild and enforces the 50-entry cap:

```json
{
  "expo": {
    "plugins": [
      ["@psync/anti-jailbreak", { "urlSchemes": ["cydia", "sileo"] }]
    ]
  }
}
```

Pass `urlSchemes: []` to skip adding any schemes, or omit the prop to use the defaults. The plugin never requests `QUERY_ALL_PACKAGES` and only adds narrowly scoped `<queries>` entries for known root-manager apps on Android.

### Background watchdog

The watchdog consumes `checkDetailed()` on its own background thread using the configured threshold. It does not duplicate detection logic. Use `LOG_ONLY` for safe testing — never `TERMINATE` in automated tests:

```ts
import {
  startSecurityWatchdog,
  stopSecurityWatchdog,
  type LegacySecurityWatchdogOptions,
} from '@psync/anti-jailbreak';

const options: LegacySecurityWatchdogOptions = {
  intervalMs: 5000, // milliseconds between ticks (legacy alias: `interval`)
  protectionMode: 'LOG_ONLY', // 'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE'
};

startSecurityWatchdog(options);

// Later (e.g. on logout, or once your server has re-attested the device):
stopSecurityWatchdog();
```

Notes on protection modes:

- **`LOG_ONLY`** — Safe everywhere. Use for testing and when JS-side policy is the source of truth.
- **`THROW_EXCEPTION`** — Demoted to a logged warning on the background thread (it cannot throw into the JS runtime). Retained for API completeness; poll `checkDetailed()` from JS to actually react.
- **`TERMINATE`** — Ends the process via `std::terminate()`. Destructive; do not exercise in tests.

### Error handling per wrapper

The wrappers preserve v1 error semantics for backwards compatibility. `isDeviceCompromised()` is the only one that rethrows — the others return safe fallbacks so a faulty probe can never crash your app:

```ts
import {
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
  getDetectionReasons,
  checkDetailed,
} from '@psync/anti-jailbreak';

// checkDetailed() — propagates native errors directly.
try {
  const result = await checkDetailed();
} catch (error) {
  // Handle or surface to the user.
}

// isDeviceCompromised() — logs and RETHROWS. Always wrap in try/catch.
try {
  if (await isDeviceCompromised()) {
    /* … */
  }
} catch (error) {
  /* Native failure — decide policy (fail open or closed). */
}

// isEmulator() / isDebuggerAttached() / getDetectionReasons() — log and
// return safe fallbacks (false / false / []). They never throw.
const isEmu = await isEmulator(); // never throws
const reasons = await getDetectionReasons(); // never throws
```

### Recommended pattern: pair with backend attestation

Client heuristics are bypassable. For sensitive decisions, send the score and signal ids to your backend as a *hint*, and combine with hardware-backed attestation that the server verifies:

```ts
import { checkDetailed } from '@psync/anti-jailbreak';

async function fetchSessionToken() {
  const assessment = await checkDetailed();

  const response = await fetch('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      // Hints only — never the sole authorization factor.
      clientRiskScore: assessment.score,
      clientConfidence: assessment.confidence,
      clientPartial: assessment.partial,
      clientSignalIds: assessment.signals
        .filter((s) => s.unavailable !== true && s.detected)
        .map((s) => s.id),

      // Authoritative signal (acquire separately via Play Integrity / App
      // Attest and verify server-side). This library does not issue tokens.
      // integrityToken: await getPlayIntegrityToken(),
    }),
  });

  return response.json();
}
```

---

## API Summary

- **`checkDetailed(): Promise<CompromiseAssessment>`** — Runs all enabled checks within a timeout budget (default `400ms`). Overrun checks return `unavailable: true` with `partial: true` rather than throwing.
- **`assessRisk(): Promise<CompromiseAssessment>`** — Alias for `checkDetailed()`; prefer whichever name reads better in your codebase.
- **`configure(options: RootJailDetectOptions): void`** — Configure `minScore` (default `40`), `timeoutMs`, `includeEvidence`, `treatDebuggerAsCompromise`, and iOS `urlSchemes`.
- **`isDeviceCompromised(): Promise<boolean>`** — Returns `true` if `score >= minScore`. Rethrows native errors.
- **`isEmulator(): Promise<boolean>`** — Returns `true` if running in an emulator/simulator. Returns `false` on error.
- **`isDebuggerAttached(): Promise<boolean>`** — Returns `true` if a debugger is attached. Returns `false` on error.
- **`getDetectionReasons(): Promise<string[]>`** — Returns human-readable reasons for fired signals. Returns `[]` on error.
- **`startSecurityWatchdog(options): void`** — Periodically runs checks in background. `protectionMode` is `'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE'`. Note: `THROW_EXCEPTION` is demoted to a logged warning on the background thread (it cannot throw into the JS runtime); `TERMINATE` ends the process. To react in app code, poll `checkDetailed()` / `isDeviceCompromised()` from JS.
- **`stopSecurityWatchdog(): void`** — Stops the security watchdog thread.

---

## Result & option shapes

`checkDetailed()` returns a `CompromiseAssessment` (`DeviceRiskResult` is kept as a deprecated alias):

```ts
interface CompromiseAssessment {
  platform: 'android' | 'ios';
  compromised: boolean;              // score >= minScore
  score: number;                     // 0–100, clamped
  confidence: 'low' | 'medium' | 'high' | 'extreme';
  signals: DetectionSignal[];        // all fired signals, including `unavailable: true` ones
  debuggerDetected: boolean;         // informational; folds into `compromised` only if configured
  elapsedMs: number;                 // total detection pass time
  partial: boolean;                  // true when the timeoutMs budget ran out before all checks finished
}

interface DetectionSignal {
  id: string;               // platform-prefixed, e.g. `android.mount.magisk`
  platform: 'android' | 'ios';
  category: SignalCategory; // see enum below
  severity: 'low' | 'medium' | 'high';
  score: number;            // weight contributed to the aggregated score
  detected: boolean;        // true for a positive finding; false when returning a clean row
  reliability: number;      // 0..1 stable estimate of how reliable this signal is
  evidence?: string;        // only when RootJailDetectOptions.includeEvidence = true
  unavailable?: boolean;    // true when the check could not complete; never evidence of compromise
}

// Source of truth: src/specs/SignalCategory.ts. Closed enum.
type SignalCategory =
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
```

`configure()` accepts a `RootJailDetectOptions` partial:

```ts
interface RootJailDetectOptions {
  minScore?: number;                 // default 40 — `compromised` becomes true at or above this
  timeoutMs?: number;                // default 400 — total wall-clock budget per pass
  includeEvidence?: boolean;         // default false — see "Evidence redaction" below
  treatDebuggerAsCompromise?: boolean; // default false
  enablePlayIntegrity?: boolean;     // default false — server-attested; not yet wired
  urlSchemes?: {
    schemes?: string[];              // default ['cydia', 'sileo', 'zbra', 'filza']; [] disables
    perSchemeSignals?: boolean;      // default false
  };
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
| high | `android.network.frida` | 30 | Frida server responding on loopback 27042 |
| high | `android.network.ssh` | 30 | SSH server responding on loopback |
| low | `android.network.adb` | 10 | ADB daemon on loopback (emulator / rare TCP-mode adbd) |
| medium | `android.root_manager.dir` | 20 | Root-manager directory accessible |
| medium | `android.bootloader.unlocked` | 20 | Unlocked bootloader / verified boot orange |
| medium | `android.emulator` | 20 | Android emulator indicators |
| low | `android.su.binary` | 10 | `su` binary at conventional location |
| low | `android.build.test_keys` | 10 | `ro.build.tags` reports `test-keys` |
| low | `android.build.debuggable` | 5 | `ro.debuggable` set (dev build or Shamiko) |
| low | `android.build.adb_root` | 5 | `service.adb.root` set (dev build or Shamiko) |
| low | `android.build.ro_secure_zero` | 5 | `ro.secure` is `0` (dev build or Shamiko) |
| low | `android.mount.overlay` | 10 | Hidden mount overlay in app namespace |
| informational | `android.debugger.tracerpid` | 0 | `TracerPid` non-zero (diagnostic) |
| high | `ios.dyld.hook` | 30 | Suspicious injection framework loaded (Frida, MobileSubstrate, Substitute, libhooker, ellekit, rosalie, renamed gadgets) |
| high | `ios.network.frida` | 30 | Frida server responding on loopback 27042 |
| high | `ios.network.ssh` | 30 | SSH server responding on loopback (22 or 44) |
| medium | `ios.jailbreak.artifact` | 20 | Classic jailbreak file or directory accessible |
| medium | `ios.jailbreak.rootless` | 20 | Rootless jailbreak bootstrap prefix present (e.g. `/var/jb`, `/private/preboot/jb`) |
| medium | `ios.jailbreak.dopamine` | 20 | Dopamine-specific artifact present |
| medium | `ios.jailbreak.palera1n` | 20 | palera1n-specific artifact present |
| medium | `ios.sideload.trollstore` | 15 | TrollStore sideloading artifact present (not a jailbreak) |
| medium | `ios.urlscheme.jailbreak_store` | 15 | Jailbreak-store URL scheme responded to `canOpenURL` |
| medium | `ios.simulator` | 20 | iOS simulator environment |
| informational | `ios.debugger.sysctl` | 0 | `sysctl` reports P_TRACED (diagnostic) |
| informational | `*.check.*` | 0 | Check timed out / unavailable (not compromise) |

Signal ids are part of the public contract — they are never renamed or reused for a different meaning once published. Tuning a weight or severity is allowed; repurposing an id is a breaking change.

---

## Threat Model & Policy

- **Client heuristics are non-authoritative:** Always bind sensitive decisions to short-lived server sessions with backend attestation (Play Integrity / App Attest).
- **Legitimate custom ROMs & devs:** Unlocked bootloaders, `test-keys`, and permissive SELinux can occur on legitimate developer devices. Tune `minScore` appropriately.
- **Rootless jailbreaks and TrollStore:** iOS rootless jailbreaks (Dopamine, palera1n) deliberately avoid classic paths and use `/var/jb` or `/private/preboot/...` prefixes. TrollStore is a sideloading tool, not a jailbreak, and is reported separately under `ios.sideload.trollstore`.
- **Renamed Frida gadgets:** Memory-map and `_dyld` scans include common rename patterns (`libgadget`, `gadget.dylib`, etc.), but a determined attacker can rename further. Treat these as defensive signals, not proof.
- **iOS URL schemes:** The default probe list (`cydia`, `sileo`, `zbra`, `filza`) respects the 50-entry `LSApplicationQueriesSchemes` cap shared with the host app. Configure `RootJailDetectOptions.urlSchemes.schemes` to change or disable the list. Undeclared schemes safely return `NO` and never produce a false positive.
- **Confidence levels:** `low`/`medium`/`high` reflect how complete and convergent the pass was. `extreme` is reserved by the aggregator for combinations of multiple high-severity, independent-category signals that together push the score very high (≈ 80).

---

## License

MIT © Psync
