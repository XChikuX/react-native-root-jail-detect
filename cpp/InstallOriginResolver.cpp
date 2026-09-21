///
/// InstallOriginResolver.cpp
///

#include "InstallOriginResolver.hpp"

namespace margelo::nitro::rootjaildetect {

  InstallOrigin resolveIOSInstallOrigin(const std::string& receiptState) noexcept {
    // The Swift probe's contract is exactly these three values; we treat any
    // other string as `"none"` so a malformed future contract never resolves
    // to a claim of provenance.
    if (receiptState == "app_store") return InstallOrigin::APP_STORE;
    if (receiptState == "sandbox")  return InstallOrigin::TESTFLIGHT;
    return InstallOrigin::UNKNOWN;
  }

  InstallOrigin resolveAndroidInstallOrigin(const std::optional<std::string>& installerPackage) noexcept {
    if (!installerPackage.has_value()) {
      // A missing installer record is normal for system/ADB installs and can
      // also occur after the installer app was uninstalled. Unknown is the
      // honest answer — not "other".
      return InstallOrigin::UNKNOWN;
    }
    const std::string& installer = installerPackage.value();
    // `com.google.android.feedback` is a legacy installer identity emitted for
    // some Play-managed installs on Android versions before API 30.
    if (installer == "com.android.vending" || installer == "com.google.android.feedback") {
      return InstallOrigin::GOOGLE_PLAY;
    }
    return InstallOrigin::OTHER;
  }

} // namespace margelo::nitro::rootjaildetect
