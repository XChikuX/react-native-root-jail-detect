# @psync/anti-jailbreak

[![npm version](https://img.shields.io/npm/v/@psync/anti-jailbreak.svg)](https://www.npmjs.com/package/@psync/anti-jailbreak)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A **React Native Nitro Module** (New Architecture only) for detecting rooted (Android) and jailbroken (iOS) devices, emulators/simulators, attached debuggers, and runtime instrumentation frameworks (Frida, Zygisk, LSPosed, Riru). Features a scored risk API, stable signal catalog, and optional periodic security watchdog.

> **Security Note:** Client-side detection is a defense-in-depth heuristic, not a guarantee. Determined attackers can hook or bypass checks. Never use client booleans as sole authorization for sensitive actions—pair with backend Play Integrity / App Attest verification.

---

## Installation

```sh
bun add @psync/anti-jailbreak react-native-nitro-modules
```

*(Requires React Native 0.83+ New Architecture and `react-native-nitro-modules` >= 0.35.0)*

### iOS & Expo

- **iOS:** Run `cd ios && pod install`
- **Expo:** Custom dev client or EAS Build required (cannot run in Expo Go). Add `plugins: ["@psync/anti-jailbreak"]` to `app.json` if package plugins aren't auto-resolved.

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
- **`startSecurityWatchdog(options): void`** — Periodically runs checks in background (`'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE'`).
- **`stopSecurityWatchdog(): void`** — Stops the security watchdog thread.

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
