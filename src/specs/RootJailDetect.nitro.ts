import type { HybridObject } from 'react-native-nitro-modules';
import type { DeviceRiskResult } from './DeviceRiskResult';
import type { RootJailDetectOptions } from './RootJailDetectOptions';
import type { SecurityWatchdog } from './SecurityWatchdog.nitro';

/**
 * Root device-risk HybridObject. Implemented in shared C++ so that scoring,
 * the signal catalog, pattern matching, and `/proc` parsing (Android) are
 * shared across platforms. Platform-specific probes (PackageManager, system
 * properties, sandbox, `_dyld`, debugger state) live in thin Swift/Kotlin
 * edge objects that the C++ core can call through their generated spec API.
 *
 * New Architecture only. There is no Old-Architecture bridge fallback.
 *
 * The legacy published JS API (`isDeviceCompromised`, `isEmulator`,
 * `isDebuggerAttached`, `getDetectionReasons`, `startSecurityWatchdog`,
 * `stopSecurityWatchdog`) is preserved as a thin wrapper over
 * {@linkcode RootJailDetect.checkDetailed} in `src/index.tsx`.
 *
 * @see {@linkcode RootJailDetect.checkDetailed}
 */
export interface RootJailDetect
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /**
   * Apply configuration that persists on the native object and affects
   * subsequent {@linkcode RootJailDetect.checkDetailed} passes and the
   * {@linkcode SecurityWatchdog}. Passing `undefined` for a field keeps the
   * existing value.
   *
   * Synchronous because it only updates in-memory configuration; the next
   * detection pass observes the new values.
   *
   * @see {@linkcode RootJailDetectOptions}
   */
  configure(options: RootJailDetectOptions): void;
  /**
   * Run all enabled device-risk checks within the configured
   * {@linkcode RootJailDetectOptions.timeoutMs} budget and return the
   * aggregated {@linkcode DeviceRiskResult}.
   *
   * Returns a Promise because the pass reads files, inspects memory maps,
   * enumerates packages, and may perform other work that must not block the
   * JS caller thread.
   *
   * Checks that cannot complete within the budget report
   * {@linkcode DetectionSignal.unavailable} signals and the result is marked
   * {@linkcode DeviceRiskResult.partial} rather than failing the call.
   */
  checkDetailed(): Promise<DeviceRiskResult>;
  /**
   * Create or return the singleton {@linkcode SecurityWatchdog} owned by this
   * root object. The watchdog consumes {@linkcode RootJailDetect.checkDetailed}
   * with the configured threshold and does not duplicate detection logic.
   */
  getWatchdog(): SecurityWatchdog;
}
