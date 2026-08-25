import UIKit
import NitroModules

/**
 * Swift edge HybridObject for iOS URL-scheme sandbox checks.
 *
 * `UIApplication.canOpenURL` must be called from UIKit's main actor; the
 * implementation dispatches synchronously to the main thread and returns
 * whether the scheme is declared in `LSApplicationQueriesSchemes` and
 * responds with `true`.
 */
public final class HybridUrlSchemeProbe: HybridUrlSchemeProbeSpec {

  public override init() { }

  public func canOpenUrl(scheme: String) throws -> Bool {
    guard Thread.isMainThread else {
      var result = false
      DispatchQueue.main.sync {
        result = self.canOpenUrlOnMainThread(scheme)
      }
      return result
    }
    return canOpenUrlOnMainThread(scheme)
  }

  private func canOpenUrlOnMainThread(_ scheme: String) -> Bool {
    guard let app = Self.sharedApplication() else {
      return false
    }
    guard isValidScheme(scheme) else { return false }
    let urlString = "\(scheme)://"
    guard let url = URL(string: urlString) else { return false }
    return app.canOpenURL(url)
  }

  /// Reach the shared `UIApplication` without referencing the `shared`
  /// property directly.
  ///
  /// `UIApplication.shared` is API-unavailable in app-extension targets, so
  /// a direct reference would break any consumer compiling this file into an
  /// extension. The previous KVC workaround
  /// (`value(forKeyPath: "shared")`) can raise an Objective-C exception that
  /// Swift `catch` cannot intercept when the key is not value-compliant.
  /// Calling the selector through the metaclass compiles in every target,
  /// returns `nil` where the shared application does not exist (extensions
  /// get a nil-returning stub), and never raises.
  private static func sharedApplication() -> UIApplication? {
    return UIApplication.perform(NSSelectorFromString("sharedApplication"))?
      .takeUnretainedValue() as? UIApplication
  }

  private func isValidScheme(_ scheme: String) -> Bool {
    if scheme.isEmpty { return false }
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "+-"))
    return scheme.unicodeScalars.allSatisfy { allowed.contains($0) }
  }
}
