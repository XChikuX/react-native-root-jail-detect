///
/// IOSChecks.hpp
///
/// Conservative iOS-only probes used by the shared C++ root object. The checks
/// are compiled out on non-Apple targets so Android and host builds stay safe.
///

#pragma once

#include "DetectionSignal.hpp"
#include "HybridUrlSchemeProbeSpec.hpp"

#include <chrono>
#include <memory>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  struct IOSCheckResult final {
    std::vector<DetectionSignal> signals;
    bool debuggerDetected = false;
    bool partial = false;
  };

  /// Context carrying iOS-only dependencies.
  struct IOSCheckContext final {
    bool includeEvidence = false;
    std::chrono::steady_clock::time_point deadline;
    std::shared_ptr<HybridUrlSchemeProbeSpec> urlSchemeProbe;
    std::vector<std::string> urlSchemes = {"cydia", "sileo", "zbra", "filza"};
    bool urlSchemesPerSignal = false;
  };

  /// Default iOS URL schemes tested by `canOpenURL`. Host apps may configure a
  /// different list via `RootJailDetectOptions.urlSchemes` to respect the 50-entry
  /// `LSApplicationQueriesSchemes` cap.
  inline constexpr const char* K_DEFAULT_IOS_URL_SCHEMES[] = {"cydia", "sileo", "zbra", "filza"};

  IOSCheckResult runIOSChecks(bool includeEvidence,
                              std::chrono::steady_clock::time_point deadline) noexcept;
  IOSCheckResult runIOSChecks(const IOSCheckContext& context) noexcept;

} // namespace margelo::nitro::rootjaildetect
