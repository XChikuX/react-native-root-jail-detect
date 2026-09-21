/**
 * Where the running app was installed from, as best as the platform can
 * tell locally. This is provenance information, not a security attestation.
 *
 * - Android: derived from the installer package recorded by the system.
 *   A missing record (ADB, system installs, uninstalled installer app)
 *   resolves to `'unknown'`; an explicitly recorded installer other than
 *   Google Play resolves to `'other'`.
 * - iOS: derived from the App Store receipt inside the app bundle. A signed
 *   production receipt resolves to `'app_store'`, the sandbox receipt used by
 *   TestFlight resolves to `'testflight'`, and every other state (Xcode/dev
 *   installs, simulator, sideloaded, enterprise, or a transiently missing
 *   receipt) resolves to `'unknown'`.
 *
 * iOS deliberately never resolves to `'other'`: receipt absence is legitimate
 * in too many benign states to be evidence of sideloading, so the value is
 * informational on iOS and never feeds the scored signal catalog. Use
 * DeviceCheck / App Attest for cryptographic install verification.
 */
export type InstallOrigin =
  | 'app_store'
  | 'testflight'
  | 'google_play'
  | 'other'
  | 'unknown';
