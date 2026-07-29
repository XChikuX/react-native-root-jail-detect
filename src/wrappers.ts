import { NitroModules } from 'react-native-nitro-modules';
import { Platform } from 'react-native';

import type {
  CompromiseAssessment,
  ProtectionMode,
  RootJailDetect,
  RootJailDetectOptions,
  SecurityWatchdogOptions,
} from './specs';

// Root HybridObject is created lazily so the first call (and only the first
// call) pays the native object construction cost. Keep this handle inside the
// module so wrappers and the watchdog share one detection core.
let _root: RootJailDetect | undefined;

function getRoot(): RootJailDetect {
  if (_root === undefined) {
    _root = NitroModules.createHybridObject<RootJailDetect>('RootJailDetect');
  }
  return _root;
}

// Internal helper: run an async native operation without awaiting it, logging
// any rejection. Used to preserve the historical synchronous signatures of
// the watchdog start/stop wrappers. Returns nothing — callers ignore it.
function fireAsync(promise: Promise<unknown>, context: string): void {
  promise.catch((error) => {
    console.error(`Failed to ${context}:`, error);
  });
}

const signalReasons: Record<string, string> = {
  'android.bootloader.unlocked': 'Bootloader verification reports an unlocked state.',
  'android.build.adb_root': '`service.adb.root` is set (development build or hidden by Shamiko).',
  'android.build.debuggable': '`ro.debuggable` is set (development build or hidden by Shamiko).',
  'android.build.ro_secure_zero': '`ro.secure` is `0` (development build or hidden by Shamiko).',
  'android.build.test_keys': 'The Android build uses test keys.',
  'android.cmdline.instrumentation': 'Runtime instrumentation was found in the process command line.',
  'android.debugger.tracerpid': 'Process status indicates a debugger is attached (TracerPid).',
  'android.emulator': 'Multiple Android build properties indicate an emulator.',
  'android.maps.frida': 'A Frida artifact is mapped into the process.',
  'android.maps.lsposed': 'An LSPosed or Xposed artifact is mapped into the process.',
  'android.maps.riru': 'A Riru framework artifact is mapped into the process.',
  'android.maps.zygisk': 'A Zygisk artifact is mapped into the process.',
  'android.mount.magisk': 'A known root-framework artifact is visible in mount metadata.',
  'android.mount.overlay': 'A root-framework artifact is visible only in the app mount namespace.',
  'android.network.adb': 'An ADB daemon is listening on loopback (emulator or rare TCP-mode adbd).',
  'android.network.frida': 'A Frida server is listening on the default loopback port.',
  'android.network.ssh': 'An SSH server is listening on a loopback port.',
  'android.root_manager.dir': 'A conventional root-manager location is accessible.',
  'android.selinux.permissive': 'SELinux is not enforcing.',
  'android.socket.instrumentation': 'Runtime instrumentation exposed a local socket.',
  'android.su.binary': 'A conventional su binary is accessible.',
  // The `*.check.*` markers all carry `unavailable: true` and are filtered
  // out by `getDetectionReasons()` today, but we keep them here so future
  // changes that surface them still render human-readable text instead of
  // the raw signal id.
  'android.check.debugger': 'The debugger check did not complete within the time budget.',
  'android.check.maps': 'The memory-map scan did not complete within the time budget.',
  'android.check.mounts': 'The mount-metadata scan did not complete within the time budget.',
  'android.check.properties': 'The Android property probe did not complete within the time budget.',
  'android.check.root_paths': 'The root-path probe did not complete within the time budget.',
  'android.check.runtime': 'The runtime instrumentation probe did not complete within the time budget.',
  'android.check.selinux': 'The SELinux state check did not complete within the time budget.',
  'ios.check.debugger': 'The iOS debugger check did not complete within the time budget.',
  'ios.check.dyld': 'The dyld image scan did not complete within the time budget.',
  'ios.check.jailbreak': 'The jailbreak artifact probe did not complete within the time budget.',
  'ios.check.urlscheme': 'The URL-scheme check did not complete within the time budget.',
  'ios.debugger.sysctl': 'Process state indicates a debugger is attached (sysctl).',
  'ios.dyld.hook': 'A suspicious runtime hook image is loaded.',
  'ios.jailbreak.artifact': 'A known jailbreak artifact is accessible.',
  'ios.jailbreak.rootless': 'A rootless jailbreak bootstrap artifact is present.',
  'ios.jailbreak.dopamine': 'A Dopamine-specific artifact is present.',
  'ios.jailbreak.palera1n': 'A palera1n-specific artifact is present.',
  'ios.network.frida': 'A Frida server is listening on the default loopback port.',
  'ios.network.ssh': 'An SSH server is listening on a loopback port.',
  'ios.sideload.trollstore': 'A TrollStore-related artifact is present (sideloading tool, not a full jailbreak).',
  'ios.urlscheme.jailbreak_store': 'A jailbreak-store URL scheme responded to canOpenURL.',
  'ios.simulator': 'The app is running in the iOS simulator.',
};

/**
 * Apply configuration that affects subsequent `checkDetailed()` passes and the
 * security watchdog. Passing `undefined` for a field keeps the existing value.
 *
 * @see {@link RootJailDetectOptions}
 */
export function configure(options: RootJailDetectOptions): void {
  getRoot().configure(options);
}

/**
 * Run every enabled device-risk check within the configured timeout budget
 * and return the full, structured {@linkcode CompromiseAssessment}.
 *
 * This is the primary API. The legacy boolean wrappers below are derived from
 * it. Checks that cannot complete in time surface as `unavailable` signals and
 * the result is marked `partial: true` rather than throwing.
 */
export async function checkDetailed(): Promise<CompromiseAssessment> {
  return getRoot().checkDetailed();
}

/**
 * Alias for {@linkcode checkDetailed}. Provided for callers that prefer the
 * `assess*` verb in security-policy code. There is no behavioral difference;
 * both names invoke the same native pass.
 */
export async function assessRisk(): Promise<CompromiseAssessment> {
  return getRoot().checkDetailed();
}

/**
 * Checks if the device is compromised (rooted on Android, jailbroken on iOS).
 *
 * Thin wrapper over {@linkcode checkDetailed}: resolves to the
 * {@linkcode CompromiseAssessment.compromised} boolean. Preserves the legacy error
 * semantics — native errors are logged and rethrown, not swallowed.
 *
 * @returns Promise that resolves to `true` if the device is compromised.
 */
export async function isDeviceCompromised(): Promise<boolean> {
  try {
    const result = await getRoot().checkDetailed();
    return Boolean(result.compromised);
  } catch (error) {
    console.error('Error checking device security:', error);
    throw error;
  }
}

/**
 * Checks if the app is running in an emulator (Android) or simulator (iOS).
 *
 * Thin wrapper over {@linkcode checkDetailed}: derived from the platform's
 * emulator/simulator signal. Preserves the legacy error semantics — native
 * errors are logged and a safe `false` fallback is returned.
 *
 * @returns Promise that resolves to `true` if running in an emulator/simulator.
 */
export async function isEmulator(): Promise<boolean> {
  try {
    const result = await getRoot().checkDetailed();
    // The detailed result is the single source of truth; emulator/simulator
    // state is reflected through a platform-prefixed signal id emitted by the
    // native detectors. Matching by `startsWith` so any future
    // `android.emulator.*` / `ios.simulator.*` refinement is picked up here
    // without changing the wrapper.
    return Boolean(
      result.signals.some(
        (signal) =>
          signal.id.startsWith(`${Platform.OS}.emulator`) ||
          signal.id.startsWith(`${Platform.OS}.simulator`)
      )
    );
  } catch (error) {
    console.error('Error checking emulator status:', error);
    return false;
  }
}

/**
 * Checks if a debugger is currently attached to the process.
 *
 * Thin wrapper over {@linkcode checkDetailed}: resolves to
 * {@linkcode CompromiseAssessment.debuggerDetected}. Preserves the legacy error
 * semantics — native errors are logged and a safe `false` fallback is returned.
 *
 * @returns Promise that resolves to `true` if a debugger is attached.
 */
export async function isDebuggerAttached(): Promise<boolean> {
  try {
    const result = await getRoot().checkDetailed();
    return Boolean(result.debuggerDetected);
  } catch (error) {
    console.error('Error checking debugger status:', error);
    return false;
  }
}

/**
 * Returns human-readable reasons describing why the device was flagged.
 *
 * Thin wrapper over {@linkcode checkDetailed}: derived from the fired
 * signal ids (and redacted evidence when enabled). Deduplicated. Preserves
 * the legacy error semantics — native errors are logged and an empty array is
 * returned as a safe fallback.
 */
export async function getDetectionReasons(): Promise<string[]> {
  try {
    const result = await getRoot().checkDetailed();
    const reasons = new Set<string>();
    for (const signal of result.signals) {
      if (signal.unavailable === true) {
        // Unavailable checks produced no evidence and must not appear as a
        // detection reason.
        continue;
      }
      reasons.add(signal.evidence ?? signalReasons[signal.id] ?? signal.id);
    }
    return Array.from(reasons);
  } catch (error) {
    console.error('Error checking detection reasons:', error);
    return [];
  }
}

/**
 * Backwards-compatible options for the security watchdog.
 *
 * The new spec uses {@linkcode SecurityWatchdogOptions.intervalMs} (with an
 * explicit unit, per the package's naming rules). The published wrapper still
 * accepts the legacy `interval` field so existing call sites keep working.
 */
export interface LegacySecurityWatchdogOptions {
  /** Interval between checks, in milliseconds. Alias for `intervalMs`. */
  interval?: number;
  /** @inheritDoc SecurityWatchdogOptions.intervalMs */
  intervalMs?: number;
  /** @inheritDoc ProtectionMode */
  protectionMode?: ProtectionMode;
}

/**
 * Starts the runtime security watchdog with the specified interval and
 * protection mode.
 *
 * The watchdog consumes {@linkcode checkDetailed} on each tick using the score
 * threshold configured on the root object; it does not duplicate detection
 * logic. Preserves the legacy synchronous signature by firing the async native
 * `start()` without awaiting it — the watchdog begins running on its own
 * background thread.
 *
 * @example
 * startSecurityWatchdog({ interval: 5000, protectionMode: 'LOG_ONLY' });
 */
export function startSecurityWatchdog(
  options: LegacySecurityWatchdogOptions = {}
): void {
  const intervalMs = options.intervalMs ?? options.interval ?? 3000;
  const protectionMode: ProtectionMode = options.protectionMode ?? 'LOG_ONLY';
  const nativeOptions: SecurityWatchdogOptions = {
    intervalMs,
    protectionMode,
  };
  // Fire-and-forget to preserve the historical synchronous signature. Errors
  // are logged but not rethrown, matching the previous bridge behavior.
  fireAsync(
    getRoot().getWatchdog().start(nativeOptions),
    'start security watchdog'
  );
}

/**
 * Stops the runtime security watchdog if it is currently running.
 *
 * Preserves the legacy synchronous signature by firing the async native
 * `stop()` without awaiting it.
 */
export function stopSecurityWatchdog(): void {
  fireAsync(getRoot().getWatchdog().stop(), 'stop security watchdog');
}
