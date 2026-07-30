import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Thin iOS edge HybridObject for URL-scheme sandbox checks.
 *
 * `UIApplication.canOpenURL` is a UIKit API and therefore must run from a Swift
 * (or Objective-C) edge. The C++ core creates this object on iOS when it needs
 * to test jailbreak-related URL schemes. On Android this object is not used.
 *
 * The scheme list is intentionally minimal to respect the iOS 15+ hard cap of
 * 50 entries in `LSApplicationQueriesSchemes`, which is shared across the
 * entire host app. Hosts can configure the default list via
 * {@linkcode RootJailDetectOptions.urlSchemes}.
 *
 * @see {@linkcode RootJailDetectOptions}
 */
export interface UrlSchemeProbe extends HybridObject<{ ios: 'swift'; android: 'c++' }> {
  /**
   * Test whether `scheme://` can be opened via `UIApplication.canOpenURL`.
   * Returns `true` if the scheme can be opened, `false` otherwise.
   * A scheme that is not declared in `LSApplicationQueriesSchemes` returns
   * `false` from `canOpenURL` — never a false positive.
   *
   * The implementation must run on the main actor to call the UIKit API, and
   * then return the result to the C++ caller.
   */
  canOpenUrl(scheme: string): boolean;
}
