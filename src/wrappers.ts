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

// ---- Detection event telemetry -----------------------------------------------
// Basic telemetry: an optional, module-level callback invoked whenever a
// detection pass completes and emits signals. Intended for logging, analytics,
// or server-side reporting. The callback runs in the JS thread and does not
// block the native pass.
//
// Usage:
//   import { setDetectionCallback } from '@psync/anti-jailbreak';
//   setDetectionCallback((assessment) => {
//     console.log('Detection pass:', assessment);
//   });

/** Callback invoked after each {@linkcode checkDetailed} pass. */
export type DetectionEventCallback = (
  assessment: CompromiseAssessment,
  metadata: {
    platform: string;
    timestampMs: number;
  }
) => void;

let _detectionCallback: DetectionEventCallback | undefined;

/**
 * Register a callback that fires after every `checkDetailed()` / `assessRisk()`
 * detection pass (the legacy boolean wrappers intentionally do not emit
 * telemetry). Pass `undefined` to deregister.
 *
 * @example
 * setDetectionCallback((assessment, meta) => {
 *   if (assessment.compromised) {
 *     analytics.track('device_compromised', { score: assessment.score });
 *   }
 * });
 */
export function setDetectionCallback(cb: DetectionEventCallback | undefined): void {
  _detectionCallback = cb;
}

/**
 * Invoke the telemetry callback if one is registered. Called from the
 * promise resolution of `checkDetailed` so it does not block the native pass.
 */
function maybeEmitDetectionEvent(assessment: CompromiseAssessment): void {
  if (_detectionCallback) {
    try {
      _detectionCallback(assessment, {
        platform: Platform.OS,
        timestampMs: Date.now(),
      });
    } catch (e) {
      console.error('Detection callback threw:', e);
    }
  }
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
  'android.sandbox.write': 'A sandbox write to a restricted path succeeded.',
  'android.check.sandbox': 'The sandbox write test did not complete within the time budget.',
  'android.package_manager.root': 'A known root management package was detected via PackageManager.',
  'android.package_manager.hma': 'A hiding or hooking-related package was detected via PackageManager.',
  'android.package_manager.risky': 'A potentially risky patching or piracy-related package was detected.',
  'android.modules.magisk': 'A readable Magisk module tree contains module metadata.',
  'android.modules.hiding': 'A module associated with hiding root or hooks was found.',
  'android.modules.spoofing': 'A module associated with integrity or property spoofing was found.',
  'android.addon_d.magisk': 'A Magisk persistence script was found under addon.d.',
  'android.install_recovery': 'The Android install-recovery script is present.',
  'android.hosts.writable': 'The system hosts file is writable by the app process.',
  'android.custom_rom': 'Android properties identify a custom ROM.',
  'android.lineage': 'Android properties identify LineageOS.',
  'android.lsposed.cache': 'An LSPosed cache or module marker is accessible.',
  'android.maps.anon_injection': 'A cluster of executable anonymous memory mappings was found.',
  'android.props.inconsistent_debuggable': 'Android build properties disagree about debuggable state.',
  'android.props.inconsistent_verifiedboot': 'Android verified-boot properties disagree with vbmeta state.',
  'android.props.inconsistent_fingerprint': 'Android fingerprint, build type, or build tags are inconsistent.',
  'android.magisk.disable_prop': 'A Magisk-specific system property is visible.',
  'android.zygisk.variant.official': 'A candidate official Magisk Zygisk property is visible.',
  'android.zygisk.variant.assistant': 'A candidate Zygisk Assistant property is visible.',
  'android.zygisk.variant.next': 'A candidate Zygisk Next property is visible.',
  'android.zygisk.variant.rezygisk': 'A candidate ReZygisk property is visible.',
  'android.sandbox.write.system_dir': 'A write to a normally immutable system directory succeeded.',
  'android.cmdline.su_exec': 'An `su` executable is present in the process PATH.',
  'android.cmdline.magisk_exec': 'A `magisk` executable is present in the process PATH.',
  'android.env.path_magisk': 'The process PATH contains a candidate Magisk-injected directory.',
  'android.mount.magisk_chain': 'Mount metadata contains a layered root-overlay candidate.',
  'ios.sandbox.write': 'A sandbox write to a restricted path succeeded.',
  'ios.check.sandbox': 'The sandbox write test did not complete within the time budget.',
  'android.check.selinux': 'The SELinux state check did not complete within the time budget.',
  'android.check.modules': 'The Magisk module tree could not be inspected; absence is not evidence of a clean device.',
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
 * Human-readable fallback for the dynamic `ios.urlscheme.<scheme>` detail
 * signals, which cannot be pre-listed in `signalReasons` because the scheme
 * list is caller-configurable. Unknown ids still fall back to the raw id.
 */
function urlSchemeReason(id: string): string {
  const prefix = 'ios.urlscheme.';
  if (id.startsWith(prefix) && id.length > prefix.length) {
    return `The ${id.slice(prefix.length)} URL scheme responded to canOpenURL.`;
  }
  return id;
}

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
  const result = await getRoot().checkDetailed();
  maybeEmitDetectionEvent(result);
  return result;
}

/**
 * Alias for {@linkcode checkDetailed}. Provided for callers that prefer the
 * `assess*` verb in security-policy code. There is no behavioral difference;
 * both names invoke the same native pass.
 */
export async function assessRisk(): Promise<CompromiseAssessment> {
  const result = await getRoot().checkDetailed();
  maybeEmitDetectionEvent(result);
  return result;
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
      reasons.add(signal.evidence ?? signalReasons[signal.id] ?? urlSchemeReason(signal.id));
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
