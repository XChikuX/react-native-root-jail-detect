/**
 * Where the running app was installed from, as best as the platform can
 * tell locally. This is provenance information, not a security attestation.
 *
 * - Android: derived from the installer package recorded by the system.
 *   A missing record (ADB, system installs, uninstalled installer app)
 *   resolves to `'unknown'`; an explicitly recorded installer other than
 *   Google Play resolves to `'other'`.
 * - iOS: derived from StoreKit. On iOS 16+ StoreKit cryptographically
 *   verifies the app transaction (`AppTransaction`) before it is surfaced as
 *   `.verified`: a production environment resolves to `'app_store'` and a
 *   sandbox environment (TestFlight or StoreKit sandbox) resolves to
 *   `'testflight'`. On iOS 15 the probe falls back to the legacy App Store
 *   receipt (`StoreKit/receipt` → `'app_store'`,
 *   `StoreKit/sandboxReceipt` → `'testflight'`), which is existence-only and
 *   spoofable. Every other state (Xcode/dev installs, simulator, sideloaded,
 *   enterprise, an unverifiable transaction, or a transiently missing
 *   receipt) resolves to `'unknown'`.
 *
 * iOS deliberately never resolves to `'other'`: absence or unverifiability is
 * legitimate in too many benign states to be evidence of sideloading, so the
 * value is informational on iOS and never feeds the scored signal catalog. Use
 * DeviceCheck / App Attest for cryptographic install verification.
 */
export type InstallOrigin =
  | 'app_store'
  | 'testflight'
  | 'google_play'
  | 'other'
  | 'unknown';
