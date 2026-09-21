///
/// InstallOriginResolver.hpp
///
/// Cross-platform helper that resolves the public
/// {@linkcode InstallOrigin} provenance value from the two platform-specific
/// probe edges (PackageManager on Android, App Store receipt on iOS).
///
/// This is **provenance, not attestation**. It is intentionally separate from
/// the scored `CompromiseAssessment` path so the resolution logic cannot
/// accidentally feed the signal catalog or shift the compromise threshold.
///

#pragma once

#include <optional>
#include <string>

#if defined(ROOTJAILDETECT_HOST_TEST)
// Host-side fixture builds cannot resolve the nitrogen-generated
// `InstallOrigin.hpp` (it pulls in NitroModules/jsi). Mirror the existing
// `SignalCatalog.hpp` pattern: declare a shape-agreeing stand-in under the
// same guard so `InstallOriginResolver.cpp` stays fixture-testable.
namespace margelo::nitro::rootjaildetect {
  enum class InstallOrigin {
    APP_STORE = 0,
    TESTFLIGHT = 1,
    GOOGLE_PLAY = 2,
    OTHER = 3,
    UNKNOWN = 4,
  };
}
#else
#include "InstallOrigin.hpp"
#endif

namespace margelo::nitro::rootjaildetect {

  /**
   * Resolve the current install origin on iOS.
   *
   * @param receiptState  String returned by the Swift
   *                      `HybridAppStoreReceiptProbe.getReceiptState()`:
   *                      `"app_store"`, `"sandbox"`, or `"none"`. Anything
   *                      else is treated as `"none"` (defensive parse — the
   *                      Swift side's contract is those three values only).
   *
   * @return `InstallOrigin::APP_STORE` for `"app_store"`,
   *         `InstallOrigin::TESTFLIGHT` for `"sandbox"`, and
   *         `InstallOrigin::UNKNOWN` for `"none"` or any unexpected value.
   *         iOS never resolves to `OTHER`: receipt absence is legitimate in
   *         too many benign states (Xcode/dev, simulator, sideloaded,
   *         enterprise, transiently-missing) to be evidence of sideloading.
   */
  InstallOrigin resolveIOSInstallOrigin(const std::string& receiptState) noexcept;

  /**
   * Resolve the current install origin on Android.
   *
   * @param installerPackage  Optional installer package name as reported by
   *                          PackageManager (`PackageManager.getInstallSourceInfo`
   *                          on API 30+, `getInstallerPackageName` on older
   *                          versions). A nullopt means the system has no
   *                          installer record (ADB installs, system installs,
   *                          or after the installer app was uninstalled).
   *
   * @return `InstallOrigin::GOOGLE_PLAY` for `"com.android.vending"` and the
   *         legacy `"com.google.android.feedback"` identity, `OTHER` for any
   *         other recognized string, and `UNKNOWN` for nullopt. The Android
   *         installer record is the only signal source that yields `OTHER`.
   */
  InstallOrigin resolveAndroidInstallOrigin(const std::optional<std::string>& installerPackage) noexcept;

} // namespace margelo::nitro::rootjaildetect
