import type { Confidence } from './Confidence';
import type { DetectionSignal } from './DetectionSignal';
import type { Platform } from './Platform';

/**
 * Aggregated, cross-platform device-risk assessment returned by
 * {@linkcode RootJailDetect.checkDetailed}.
 *
 * This is the primary structured API. The legacy boolean wrappers
 * (`isDeviceCompromised`, `isEmulator`, `isDebuggerAttached`,
 * `getDetectionReasons`) are derived from this result so that all detection
 * logic lives in one place.
 *
 * Risk assessment is heuristic and bypassable. A `compromised: false` result
 * means "no evidence of compromise was found", not "this device is clean".
 * Authoritative access decisions should rely on server-side attestation, not
 * on this client-produced value alone.
 *
 * @see {@linkcode RootJailDetect.checkDetailed}
 */
export interface DeviceRiskResult {
  /**
   * Platform the result was produced on. Mirrors `Platform.OS` so a result
   * serialized and sent to a backend carries its origin.
   */
  platform: Platform;
  /**
   * Convenience boolean derived from {@linkcode score} and the configured
   * {@linkcode RootJailDetectOptions.minScore}. `true` when the score meets
   * the threshold. This does not reflect an authoritative server decision.
   */
  compromised: boolean;
  /**
   * Aggregated risk score in the range 0-100, computed by summing the
   * {@linkcode DetectionSignal.score} values of the fired signals (after
   * deduplication of equivalent evidence) and clamping to 100.
   */
  score: number;
  /**
   * How complete and trustworthy the signal set is. See {@linkcode Confidence}.
   */
  confidence: Confidence;
  /**
   * All independently generated findings, including any that are
   * {@linkcode DetectionSignal.unavailable}. The full list is returned so
   * callers can understand which checks ran.
   */
  signals: DetectionSignal[];
  /**
   * `true` when a debugger or tracer was observed attached to the process.
   *
   * Debugger status is **diagnostic** and is deliberately kept separate from
   * {@linkcode compromised} unless the caller explicitly opts in via
   * {@linkcode RootJailDetectOptions.treatDebuggerAsCompromise}. A debugger
   * is a normal part of development and is not, by itself, proof of an attack.
   */
  debuggerDetected: boolean;
  /**
   * Wall-clock time the detection pass took, in milliseconds. Useful for
   * tuning the {@linkcode RootJailDetectOptions.timeoutMs} budget.
   */
  elapsedMs: number;
  /**
   * `true` when the total {@linkcode RootJailDetectOptions.timeoutMs} budget
   * ran out before all checks could run. Remaining checks are reported as
   * {@linkcode DetectionSignal.unavailable} signals rather than being skipped
   * silently. A `partial` result is not authoritative.
   */
  partial: boolean;
}
