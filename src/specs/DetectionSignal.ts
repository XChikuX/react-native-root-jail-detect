import type { Platform } from './Platform';
import type { Severity } from './Severity';
import type { SignalCategory } from './SignalCategory';

/**
 * One independently generated finding produced by a native security check.
 *
 * A signal is a single piece of evidence (for example, a Magisk artifact seen
 * in `/proc/self/maps`). The library aggregates many signals into a weighted
 * risk score on {@linkcode CompromiseAssessment}.
 *
 * Signals are heuristic and may be hidden by determined attackers; treat the
 * absence of signals as "no evidence found", not as proof of a clean device.
 *
 * @see {@linkcode CompromiseAssessment.signals}
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
   * Platform this signal belongs to. Derived from the signal id prefix; per-signal
   * platform is useful for backend filtering even though a single result only
   * comes from one platform.
   */
  platform: Platform;
  /**
   * Category of evidence (filesystem, mount, injection, etc.). Useful for
   * backend policy filtering and display; the numeric contribution to the
   * overall score is {@linkcode score}.
   */
  category: SignalCategory;
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
   * `true` for positive findings, `false` for explicit non-findings. Today the
   * runner only emits positive signals and unavailable markers; the field is
   * part of the richer shape to support future negative/clean check rows.
   */
  detected: boolean;
  /**
   * Normalized reliability of this signal (0-1). High values mean the check is
   * robust against casual evasion; low values mean it is easily hidden or has
   * a notable false-positive profile. Not a configuration knob.
   */
  reliability: number;
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
