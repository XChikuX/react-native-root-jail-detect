import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Thin iOS edge HybridObject for App Store receipt presence checks.
 *
 * `Bundle.appStoreReceiptURL` is a Foundation API and therefore must run from
 * a Swift (or Objective-C) edge. The C++ core creates this object on iOS to
 * resolve the public `getInstallOrigin()` provenance heuristic. On Android
 * this object is not used; install origin comes from the PackageManager
 * installer record instead.
 *
 * This probe is **internal**: it is not exported from `src/` and is not
 * referenced by any JS-facing API. It is consumed only by the shared C++ core
 * (`cpp/InstallOriginResolver.cpp`).
 */
export interface AppStoreReceiptProbe
  extends HybridObject<{ ios: 'swift'; android: 'c++' }> {
  /**
   * Report the App Store receipt state inside the app bundle:
   *
   * - `'app_store'` — a receipt file exists (installed from the App Store;
   *   existence alone does not validate the Apple signature).
   * - `'sandbox'` — the file exists and is the TestFlight sandbox receipt
   *   (`StoreKit/sandboxReceipt` rather than `StoreKit/receipt`).
   * - `'none'` — no receipt file exists. This is the normal state for
   *   Xcode/dev installs, simulators, and sideloaded or enterprise builds;
   *   it is also a legitimate transient state on rare App Store installs,
   *   so it is never treated as a finding.
   *
   * Existence-only by design: on a jailbroken device an attacker with
   * filesystem write access outside the sandbox can plant a file, so a
   * positive result is spoofable and must not be used as security evidence.
   */
  getReceiptState(): string;
}
