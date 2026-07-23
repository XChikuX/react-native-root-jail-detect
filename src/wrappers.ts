import { NitroModules } from 'react-native-nitro-modules';
import { Platform } from 'react-native';

import type {
  DeviceRiskResult,
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
 * and return the full, structured {@linkcode DeviceRiskResult}.
 *
 * This is the primary API. The legacy boolean wrappers below are derived from
 * it. Checks that cannot complete in time surface as `unavailable` signals and
 * the result is marked `partial: true` rather than throwing.
 */
export async function checkDetailed(): Promise<DeviceRiskResult> {
  return getRoot().checkDetailed();
}

/**
 * Checks if the device is compromised (rooted on Android, jailbroken on iOS).
 *
 * Thin wrapper over {@linkcode checkDetailed}: resolves to the
 * {@linkcode DeviceRiskResult.compromised} boolean. Preserves the legacy error
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
    // state is reflected through a platform-prefixed signal id. Until the
    // native emulator signals land (PR 2/PR 3), this returns `false` on a
    // clean stub result, matching the documented safe fallback.
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
 * {@linkcode DeviceRiskResult.debuggerDetected}. Preserves the legacy error
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
      reasons.add(signal.evidence ?? signal.id);
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
