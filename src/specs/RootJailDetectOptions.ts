/**
 * Configuration applied to subsequent calls to
 * {@linkcode RootJailDetect.checkDetailed} and to the {@linkcode SecurityWatchdog}.
 *
 * Set through {@linkcode RootJailDetect.configure}. Values persist on the
 * native HybridObject until changed; passing `undefined` for a field keeps the
 * existing value.
 *
 * @see {@linkcode RootJailDetect.configure}
 */
export interface RootJailDetectOptions {
  /**
   * Minimum aggregated risk score (0-100) at which
   * {@linkcode DeviceRiskResult.compromised} is reported as `true`.
   *
   * @default 40
   */
  minScore?: number;
  /**
   * Total wall-clock budget for one detection pass, in milliseconds. Individual
   * checks also have per-check deadlines. Checks that cannot complete within
   * the budget report an {@linkcode DetectionSignal.unavailable} signal and
   * the result is marked {@linkcode DeviceRiskResult.partial}.
   *
   * @default 400
   */
  timeoutMs?: number;
  /**
   * When `true`, populate {@linkcode DetectionSignal.evidence} with redacted,
   * human-readable detail. Evidence is intended for development and debug
   * builds only; keep it disabled in release builds to avoid exposing local
   * paths and device state to the JS layer or to backends.
   *
   * @default false
   */
  includeEvidence?: boolean;
  /**
   * When `true`, fold debugger attachment into {@linkcode DeviceRiskResult.compromised}
   * in addition to reporting it on {@linkcode DeviceRiskResult.debuggerDetected}.
   * Off by default because a debugger is a normal part of development and is
   * not, by itself, proof of an attack.
   *
   * @default false
   */
  treatDebuggerAsCompromise?: boolean;
  /**
   * When `true`, attempt to acquire a Play Integrity token as part of the pass
   * and surface it for server-side verification. Acquisition runs only when
   * explicitly enabled because it depends on Google Play services and on a
   * backend verifier. The client must never treat a self-attested token as
   * proof of device state.
   *
   * @default false
   * @platform android
   */
  enablePlayIntegrity?: boolean;
}
