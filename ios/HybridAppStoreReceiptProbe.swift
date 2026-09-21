import Foundation
import NitroModules

/**
 * Swift edge HybridObject for the App Store receipt presence check.
 *
 * Existence-only by design. `Bundle.appStoreReceiptURL` returns a file
 * `NSURL` whether or not the file actually exists on disk, so the
 * implementation has to `FileManager.default.fileExists(atPath:)` before
 * classifying.
 *
 * Returns one of:
 * - `"app_store"` — a `StoreKit/receipt` file exists (production App Store).
 * - `"sandbox"` — a `StoreKit/sandboxReceipt` file exists (TestFlight).
 * - `"none"` — no receipt file is present. This is the normal state for
 *   Xcode/dev installs, simulators, sideloaded builds, and enterprise
 *   deployments; it is also a legitimate transient state on rare App Store
 *   installs (e.g. right after restore). It is never treated as a finding
 *   on its own.
 *
 * The class `init()` is marked `override` to satisfy the
 * nitrogen-generated `HybridAppStoreReceiptProbeSpec_base` designated
 * initializer.
 */
public final class HybridAppStoreReceiptProbe: HybridAppStoreReceiptProbeSpec {

  public override init() { }

  public func getReceiptState() throws -> String {
    let bundle = Bundle.main
    guard let url = bundle.appStoreReceiptURL else {
      // No URL means we cannot make any claim. The resolver treats this as
      // absence (unknown) on iOS, matching the policy that inability to
      // inspect is never evidence of sideloading.
      return "none"
    }
    let path = url.path
    let exists = FileManager.default.fileExists(atPath: path)
    guard exists else { return "none" }

    let last = (path as NSString).lastPathComponent
    // `StoreKit/sandboxReceipt` is the TestFlight marker. The production
    // receipt lives at `StoreKit/receipt`. Anything else is unexpected but
    // the conservative "none" mapping is the only safe one — we never want
    // to claim "app_store" on a path we don't recognize.
    if last == "sandboxReceipt" { return "sandbox" }
    if last == "receipt" { return "app_store" }
    return "none"
  }
}
