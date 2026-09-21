import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Thin iOS edge HybridObject for App Store install-origin checks.
 *
 * `AppTransaction` (StoreKit 2) and `Bundle.appStoreReceiptURL` are
 * Swift/Foundation APIs and therefore must run from a Swift (or Objective-C)
 * edge. The C++ core creates this object on iOS to resolve the public
 * `getInstallOrigin()` provenance heuristic. On Android this object is not
 * used; install origin comes from the PackageManager installer record instead.
 *
 * This probe is **internal**: it is not exported from `src/` and is not
 * referenced by any JS-facing API. It is consumed only by the shared C++ core
 * (`cpp/HybridRootJailDetect.cpp` and `cpp/InstallOriginResolver.cpp`).
 */
export interface AppStoreReceiptProbe
  extends HybridObject<{ ios: 'swift'; android: 'c++' }> {
  /**
   * Report the best-effort App Store install state:
   *
   * - `'app_store'` — a production App Store install.
   * - `'sandbox'` — a sandbox install (TestFlight, or StoreKit sandbox).
   * - `'none'` — not a verifiable App Store install, or the state could not
   *   be determined.
   *
   * On iOS 16+ the state comes from StoreKit 2 `AppTransaction.shared`, which
   * StoreKit verifies cryptographically against Apple's signature before it is
   * exposed as `.verified`; `.unverified` and thrown errors never claim an
   * origin. On iOS 15 the probe falls back to the legacy receipt-existence
   * check (`StoreKit/receipt` vs the TestFlight `StoreKit/sandboxReceipt`).
   *
   * The iOS 15 fallback and any `AppTransaction` failure path are
   * **existence/availability heuristics**: a receipt file is spoofable by an
   * attacker with filesystem write access outside the sandbox on a jailbroken
   * device, so a positive result must not be treated as security evidence.
   * This is provenance, not attestation.
   */
  getReceiptState(): Promise<string>;
}
