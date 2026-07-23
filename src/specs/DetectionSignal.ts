import type { Severity } from './Severity';

/**
 * One independently generated finding produced by a native security check.
 *
 * A signal is a single piece of evidence (for example, a Magisk artifact seen
 * in `/proc/self/maps`). The library aggregates many signals into a weighted
 * risk score on {@linkcode DeviceRiskResult}.
 *
 * Signals are heuristic and may be hidden by determined attackers; treat the
 * absence of signals as "no evidence found", not as proof of a clean device.
 *
 * @see {@linkcode DeviceRiskResult.signals}
 */
export interface DetectionSignal {
  /**
   * Stable, machine-readable identifier for the check that produced this
   * signal (for example, `android.maps.zygisk`). The ID is part of the public
   * contract: it is what callers and servers use to reason about which checks
   * fired, so it must not change once published without a version bump.
   */
  id: string;
  /**
   * Coarse severity bucket for this signal. Useful for filtering and display;
   * the numeric contribution to the overall score is {@linkcode score}.
   */
  severity: Severity;
  /**
   * Numeric weight this signal contributes to the aggregated risk score
   * (0-100 scale before clamping the total). Tuned per check, not user-facing
   * as a configuration knob.
   */
  score: number;
  /**
   * Short, redacted, human-readable explanation of what was observed.
   *
   * Only populated when the caller opts in via
   * {@linkcode RootJailDetectOptions.includeEvidence}, and even then redacted
   * to avoid leaking raw local paths or sensitive device state to the JS layer
   * or to backends. Production deployments should keep this disabled.
   */
  evidence?: string;
  /**
   * `true` when the check could not complete (for example, because the
   * `/proc` entry was unreadable or the total {@linkcode RootJailDetectOptions.timeoutMs}
   * budget ran out before the check ran).
   *
   * An `unavailable` signal is **not** evidence of compromise. Callers and
   * servers must treat it as "no data".
   */
  unavailable?: boolean;
}
