/**
 * Platform a {@linkcode DeviceRiskResult} was produced on.
 *
 * Mirrors `Platform.OS` so a result serialized and sent to a backend carries
 * its origin. Kept as a named union because Nitro codegen requires named types
 * for string-literal unions.
 *
 * @see {@linkcode DeviceRiskResult.platform}
 */
export type Platform = 'android' | 'ios';
