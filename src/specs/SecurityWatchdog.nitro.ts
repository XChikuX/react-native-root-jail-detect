import type { HybridObject } from 'react-native-nitro-modules';
import type { SecurityWatchdogOptions } from './SecurityWatchdogOptions';

/**
 * Periodic native security watchdog. A separate HybridObject from
 * {@linkcode RootJailDetect} because it owns a long-lived background thread
 * and mutable lifecycle state — the one-lifecycle-per-HybridObject rule.
 *
 * The watchdog runs a full {@linkcode RootJailDetect.checkDetailed} pass on
 * each tick using the score threshold configured on the parent
 * {@linkcode RootJailDetect} object. It does not duplicate any boolean
 * detection logic.
 *
 * Repeated `start()`, `stop()`, and restart must all behave correctly.
 * Destructive {@linkcode ProtectionMode}s (`THROW_EXCEPTION`, `TERMINATE`)
 * must never be exercised in automated tests or routine manual validation;
 * use `LOG_ONLY` for safe testing.
 *
 * @see {@linkcode RootJailDetect.getWatchdog}
 */
export interface SecurityWatchdog
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /**
   * Begin periodic detection passes. Resolves once the background thread is
   * running. Calling `start()` while already running is a no-op and resolves
   * successfully rather than throwing.
   *
   * The interval and protection mode come from
   * {@linkcode SecurityWatchdogOptions}; their defaults are documented there.
   */
  start(options: SecurityWatchdogOptions): Promise<void>;
  /**
   * Stop periodic detection passes and wait for the in-flight check (if any)
   * to finish. Resolves once the background thread has exited. Calling
   * `stop()` when not running is a no-op and resolves successfully.
   */
  stop(): Promise<void>;
  /**
   * `true` while the background thread is actively running periodic checks.
   * Cheap, synchronous, cached state — safe to read from the JS thread.
   */
  readonly isRunning: boolean;
}
