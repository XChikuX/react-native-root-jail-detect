/**
 * Confidence level of an aggregated {@linkcode DeviceRiskResult}.
 *
 * Confidence reflects how complete and trustworthy the underlying signal set
 * is, not how strong the individual signals are. A `low` confidence result
 * should not be treated as authoritative; callers should usually re-check or
 * defer to server-side policy before making access decisions based on it.
 *
 * @see {@linkcode DeviceRiskResult.confidence}
 */
export type Confidence = 'low' | 'medium' | 'high';
