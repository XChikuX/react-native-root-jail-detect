import Foundation
import NitroModules
import StoreKit

/**
 * Swift edge HybridObject for the App Store install-origin check.
 *
 * On iOS 16+ the state comes from StoreKit 2 `AppTransaction.shared`, which
 * StoreKit verifies cryptographically against Apple's signature before it is
 * surfaced as `.verified`. An `.unverified` result or a thrown error never
 * claims an origin. On iOS 15 (and any `AppTransaction` failure path) the
 * probe falls back to the receipt-existence heuristic, which is existence-only
 * and therefore spoofable on jailbroken devices.
 *
 * Returns one of:
 * - `"app_store"` — a production App Store install.
 * - `"sandbox"` — a sandbox install (TestFlight, or StoreKit sandbox).
 * - `"none"` — not a verifiable App Store install, or the state could not be
 *   determined. This is the normal state for Xcode/dev installs, simulators,
 *   and sideloaded or enterprise builds; it is also a legitimate transient
 *   state on rare App Store installs. It is never treated as a finding.
 *
 * The class `init()` is marked `override` to satisfy the nitrogen-generated
 * `HybridAppStoreReceiptProbeSpec_base` designated initializer.
 */
public final class HybridAppStoreReceiptProbe: HybridAppStoreReceiptProbeSpec {

  public override init() { }

  /**
   * Resolve the install state off the JS caller thread. `AppTransaction.shared`
   * is `async` and may require network connectivity, so the probe runs inside
   * a Swift `Task` and resolves the returned Promise when it settles.
   */
  public func getReceiptState() throws -> Promise<String> {
    return Promise.async {
      // iOS 16+: StoreKit 2 AppTransaction. The replacement for the
      // deprecated `appStoreReceiptURL` on modern devices.
      if #available(iOS 16.0, *) {
        if let verifiedState = await Self.appTransactionState() {
          return verifiedState
        }
      }
      // iOS 15, or an unavailable/unverifiable AppTransaction: fall back to
      // the legacy receipt probe (documented as spoofable).
      return Self.legacyReceiptState()
    }
  }

  /**
   * Returns the environment of a StoreKit-verified `AppTransaction`, or `nil`
   * when no trustworthy transaction is available (the caller then falls back
   * to the legacy receipt probe).
   */
  @available(iOS 16.0, *)
  private static func appTransactionState() async -> String? {
    do {
      switch try await AppTransaction.shared {
      case .verified(let transaction):
        if transaction.environment == .production {
          return "app_store"
        }
        if transaction.environment == .sandbox {
          return "sandbox"
        }
        // `.xcode` (StoreKit Testing) or a future environment: no claim.
        return "none"
      case .unverified:
        // StoreKit could not verify the Apple signature. Never claim an
        // origin we cannot cryptographically trust.
        return "none"
      }
    } catch {
      // No AppTransaction available (offline, unauthenticated, dev build).
      // Fall through to the legacy probe for a conservative result.
      return nil
    }
  }

  /**
   * Legacy receipt-existence probe, retained for iOS 15 and AppTransaction
   * failure paths. Existence-only: an attacker with filesystem write access
   * outside the sandbox on a jailbroken device can plant `StoreKit/receipt`,
   * so a positive result is provenance, not attestation.
   */
  private static func legacyReceiptState() -> String {
    guard let url = Bundle.main.appStoreReceiptURL else {
      return "none"
    }
    let path = url.path
    guard FileManager.default.fileExists(atPath: path) else {
      return "none"
    }
    let last = (path as NSString).lastPathComponent
    if last == "sandboxReceipt" { return "sandbox" }
    if last == "receipt" { return "app_store" }
    return "none"
  }
}
