/**
 * Severity bucket for an individual {@linkcode DetectionSignal}.
 *
 * Severity is a coarse classification that lets callers build policy without
 * reasoning about raw scores. The numeric weight that actually drives the
 * aggregated risk score lives on {@linkcode DetectionSignal.score}.
 *
 * @see {@linkcode DetectionSignal.severity}
 */
export type Severity = 'low' | 'medium' | 'high';
