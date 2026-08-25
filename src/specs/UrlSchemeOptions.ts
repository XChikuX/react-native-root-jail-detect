/**
 * Options controlling iOS URL-scheme probes.
 *
 * URL scheme checks use `UIApplication.canOpenURL`, which only sees schemes
 * declared in the host app's `LSApplicationQueriesSchemes` Info.plist key:
 * **an undeclared scheme always returns `false`**, silently, whether or not
 * an app that handles it is installed. Apps linked on iOS 15+ may declare at
 * most 50 schemes; apps linked on iOS 27+ are limited to 25 (and
 * `canOpenURL` itself is deprecated there, though still functional). Because
 * the cap is shared across the entire host app (not just this library), the
 * scheme list is configurable and defaults to a minimal set.
 *
 * @see {@linkcode RootJailDetectOptions.urlSchemes}
 */
export interface UrlSchemeOptions {
  /**
   * Schemes to test on iOS. Defaults to `['cydia', 'sileo', 'zbra', 'filza']`.
   * Set to an empty array to disable URL-scheme checks entirely.
   *
   * **Prerequisite:** every scheme must also be declared in the host app's
   * `LSApplicationQueriesSchemes`, otherwise `canOpenURL` always returns
   * `false` for it and no signal is emitted — the miss is silent. The
   * package's Expo config plugin merges the default schemes during prebuild
   * (pass `schemeCap: 25` if your app links on iOS 27+); bare React Native
   * apps must add the key to their Info.plist manually:
   *
   * ```xml
   * <key>LSApplicationQueriesSchemes</key>
   * <array>
   *   <string>cydia</string>
   *   <string>sileo</string>
   *   <string>zbra</string>
   *   <string>filza</string>
   * </array>
   * ```
   */
  schemes?: string[];
  /**
   * If `true`, emit an additional `ios.urlscheme.<scheme>` detail signal for
   * each responding scheme. The aggregate signal
   * `ios.urlscheme.jailbreak_store` is always emitted when any scheme
   * responds, so the score contribution is identical in both modes; the
   * per-scheme signals are informational (score `0`) and identify which
   * stores are installed.
   */
  perSchemeSignals?: boolean;
}
