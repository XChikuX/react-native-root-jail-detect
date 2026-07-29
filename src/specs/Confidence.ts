/**
 * Confidence level of an aggregated {@linkcode CompromiseAssessment}.
 *
 * Confidence reflects how complete and trustworthy the underlying signal set
 * is, not how strong the individual signals are. A `low` confidence result
 * should not be treated as authoritative; callers should usually re-check or
 * defer to server-side policy before making access decisions based on it.
 *
 * `extreme` is reserved by the aggregator for passes where multiple
 * high-severity signals from independent categories converge and push the
 * score near the top of the range.
 *
 * @see {@linkcode CompromiseAssessment.confidence}
 */
export type Confidence = 'low' | 'medium' | 'high' | 'extreme';
