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
   * Attempt to open `scheme://` via `UIApplication.canOpenURL`.
   * Returns the list of schemes that returned `true`, filtered to those that
   * are present in `LSApplicationQueriesSchemes`. A scheme that is not declared
   * returns `false` from `canOpenURL` and is reported as unavailable — never as
   * a false positive.
   *
   * The implementation must run on the main actor only for the UIKit call, and
   * then return the result to the C++ caller.
   */
  checkSchemes(schemes: string[]): string[];
}
