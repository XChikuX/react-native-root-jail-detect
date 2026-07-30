import UIKit
import NitroModules

/**
 * Swift edge HybridObject for iOS URL-scheme sandbox checks.
 *
 * `UIApplication.canOpenURL` must be called from UIKit's main actor; the
 * implementation dispatches synchronously to the main thread and returns the
 * subset of requested schemes that are declared in
 * `LSApplicationQueriesSchemes` and respond with `true`.
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
    guard let app = UIApplication.value(forKeyPath: #keyPath(UIApplication.shared)) as? UIApplication else {
      return false
    }
    guard isValidScheme(scheme) else { return false }
    let urlString = "\(scheme)://"
    guard let url = URL(string: urlString) else { return false }
    return app.canOpenURL(url)
  }

  private func isValidScheme(_ scheme: String) -> Bool {
    if scheme.isEmpty { return false }
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "+-"))
    return scheme.unicodeScalars.allSatisfy { allowed.contains($0) }
  }
}
