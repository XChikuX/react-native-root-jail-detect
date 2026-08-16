/**
 * Options controlling iOS URL-scheme probes.
 *
 * URL scheme checks use `UIApplication.canOpenURL`, which iOS 15+ caps at 50
 * declared schemes per app via `LSApplicationQueriesSchemes`. Because the cap
 * is shared across the entire host app (not just this library), the scheme list
 * is configurable and defaults to a minimal set.
 *
 * @see {@linkcode RootJailDetectOptions.urlSchemes}
 */
export interface UrlSchemeOptions {
  /**
   * Schemes to test on iOS. Defaults to `['cydia', 'sileo', 'zbra', 'filza']`.
   * Set to an empty array to disable URL-scheme checks entirely.
   *
   * Schemes must also be declared in the host app's
   * `LSApplicationQueriesSchemes`; otherwise `canOpenURL` returns `NO` and no
   * signal is emitted. The package's Expo config plugin can merge the default
   * schemes during prebuild.
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
