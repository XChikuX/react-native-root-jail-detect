///
/// DeviceRiskAssessment.hpp
///
/// Shared blocking assessment entry point used by the root API and watchdog.
/// Keeping this path singular prevents periodic checks from drifting from the
/// public `checkDetailed()` result semantics.
///

#pragma once

#include "DeviceRiskResult.hpp"

#include <mutex>

namespace margelo::nitro::rootjaildetect {

  struct ResolvedRootJailDetectOptions final {
    double minScore = 40.0;
    double timeoutMs = 400.0;
    bool includeEvidence = false;
    bool treatDebuggerAsCompromise = false;
    bool enablePlayIntegrity = false;
  };

  struct RootJailDetectConfiguration final {
    std::mutex mutex;
    ResolvedRootJailDetectOptions options;
  };

  DeviceRiskResult assessDevice(const ResolvedRootJailDetectOptions& options);

} // namespace margelo::nitro::rootjaildetect
