///
/// IOSChecks.hpp
///
/// Conservative iOS-only probes used by the shared C++ root object. The checks
/// are compiled out on non-Apple targets so Android and host builds stay safe.
///

#pragma once

#include "DetectionSignal.hpp"

#include <chrono>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  struct IOSCheckResult final {
    std::vector<DetectionSignal> signals;
    bool debuggerDetected = false;
    bool partial = false;
  };

  IOSCheckResult runIOSChecks(bool includeEvidence,
                              std::chrono::steady_clock::time_point deadline) noexcept;

} // namespace margelo::nitro::rootjaildetect
