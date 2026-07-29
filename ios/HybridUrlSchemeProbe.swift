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

  public func checkSchemes(schemes: [String]) throws -> [String] {
    var responding: [String] = []

    guard Thread.isMainThread else {
      DispatchQueue.main.sync {
        responding = self.checkSchemesOnMainThread(schemes)
      }
      return responding
    }

    return checkSchemesOnMainThread(schemes)
  }

  private func checkSchemesOnMainThread(_ schemes: [String]) -> [String] {
    guard let app = UIApplication.value(forKeyPath: #keyPath(UIApplication.shared)) as? UIApplication else {
      return []
    }

    var result: [String] = []
    for scheme in schemes {
      guard isValidScheme(scheme) else { continue }
      let urlString = "\(scheme)://"
      guard let url = URL(string: urlString) else { continue }
      if app.canOpenURL(url) {
        result.append(scheme)
      }
    }
    return result
  }

  private func isValidScheme(_ scheme: String) -> Bool {
    // Reject empty schemes or anything that looks like a full URL/has whitespace.
    if scheme.isEmpty { return false }
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "+-"))
    return scheme.unicodeScalars.allSatisfy { allowed.contains($0) }
  }
}
