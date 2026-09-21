///
/// InstallOriginResolverTests.cpp
///
/// Fixture coverage for the cross-platform install-origin resolver. Pure
/// string/enum mapping; no I/O. Compiled in host-test mode
/// (`-DROOTJAILDETECT_HOST_TEST`). This suite is invoked by `main()` in
/// `ProcParsersTests.cpp` via `runInstallOriginResolverTests()` so the host
/// test binary keeps a single entry point.
///

#include "InstallOriginResolver.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

using namespace margelo::nitro::rootjaildetect;

namespace {

  // Convenience: pretty-print enum values so test failures are actionable.
  const char* nameOf(InstallOrigin origin) noexcept {
    switch (origin) {
      case InstallOrigin::APP_STORE: return "app_store";
      case InstallOrigin::TESTFLIGHT: return "testflight";
      case InstallOrigin::GOOGLE_PLAY: return "google_play";
      case InstallOrigin::OTHER: return "other";
      case InstallOrigin::UNKNOWN: return "unknown";
    }
    return "?";
  }

  void expect(InstallOrigin actual, InstallOrigin expected, const char* label) {
    if (actual != expected) {
      std::fprintf(stderr,
        "FAIL [%s]: expected %s, got %s\n",
        label, nameOf(expected), nameOf(actual));
      std::abort();
    }
  }

} // namespace

void runInstallOriginResolverTests() {
  // ---- iOS: receipt-state mapping -------------------------------------------
  expect(resolveIOSInstallOrigin("app_store"), InstallOrigin::APP_STORE, "ios:app_store");
  expect(resolveIOSInstallOrigin("sandbox"), InstallOrigin::TESTFLIGHT, "ios:sandbox");

  // The conservative unknown-on-absence rule. Receipt absence is legitimate in
  // too many benign states (Xcode/dev, simulator, sideloaded, enterprise,
  // transiently-missing) to be evidence of sideloading — so iOS never resolves
  // to OTHER. The wrapper must collapse these all to UNKNOWN.
  expect(resolveIOSInstallOrigin("none"), InstallOrigin::UNKNOWN, "ios:none");
  expect(resolveIOSInstallOrigin(""), InstallOrigin::UNKNOWN, "ios:empty");
  // Defensive parse: the Swift probe's contract is exactly the three values
  // above, but a future contract change must never silently resolve to a
  // claim of provenance. Anything else falls to UNKNOWN.
  expect(resolveIOSInstallOrigin("cracked"), InstallOrigin::UNKNOWN, "ios:unexpected");
  expect(resolveIOSInstallOrigin("app_store\n"), InstallOrigin::UNKNOWN, "ios:trailing-newline");

  // ---- Android: installer-package mapping -----------------------------------
  expect(resolveAndroidInstallOrigin(std::nullopt),
         InstallOrigin::UNKNOWN, "android:missing");

  expect(resolveAndroidInstallOrigin(std::optional<std::string>("com.android.vending")),
         InstallOrigin::GOOGLE_PLAY, "android:vending");
  // Legacy identity for some Play-managed installs on Android < API 30.
  expect(resolveAndroidInstallOrigin(std::optional<std::string>("com.google.android.feedback")),
         InstallOrigin::GOOGLE_PLAY, "android:legacy-feedback");

  // Non-Play recognized installer string -> OTHER (this is the only path
  // that yields OTHER on either platform).
  expect(resolveAndroidInstallOrigin(std::optional<std::string>("com.altstore.app")),
         InstallOrigin::OTHER, "android:altstore");
  expect(resolveAndroidInstallOrigin(std::optional<std::string>("org.twidere.alphadon")),
         InstallOrigin::OTHER, "android:other-store");

  // The Play identity must not match a substring of a longer spoofed name.
  // (Documented invariant: the comparison is exact, not substring-based.)
  expect(resolveAndroidInstallOrigin(std::optional<std::string>("com.android.vending.evil.twin")),
         InstallOrigin::OTHER, "android:spoofed-substring");
}
