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
 * `TERMINATE` is destructive (it ends the host process). `THROW_EXCEPTION` is
 * demoted to a logged warning on the background thread (it cannot synchronously
 * throw into the JS runtime); use `LOG_ONLY` for safe testing and poll
 * {@linkcode RootJailDetect.checkDetailed} from JS if you need to react in app
 * code.
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
   * Note that `THROW_EXCEPTION` fired from the background thread is demoted to a
   * logged warning — see {@linkcode ProtectionMode} for details.
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
