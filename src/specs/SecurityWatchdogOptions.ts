import type { ProtectionMode } from './ProtectionMode';

/**
 * Options for starting the {@linkcode SecurityWatchdog}.
 *
 * The watchdog periodically runs a full
 * {@linkcode RootJailDetect.checkDetailed} pass using the score threshold
 * configured on the root {@linkcode RootJailDetect} object. It does not
 * duplicate detection logic.
 *
 * @see {@linkcode SecurityWatchdog.start}
 */
export interface SecurityWatchdogOptions {
  /**
   * Time between periodic detection passes, in milliseconds.
   *
   * @default 3000
   */
  intervalMs?: number;
  /**
   * Action to take when the periodic pass reports a compromised device.
   *
   * @default 'LOG_ONLY'
   */
  protectionMode?: ProtectionMode;
}
