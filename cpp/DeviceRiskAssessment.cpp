///
/// DeviceRiskAssessment.cpp
///

#include "DeviceRiskAssessment.hpp"
#include "AndroidChecks.hpp"
#include "IOSChecks.hpp"
#include "Scoring.hpp"

#include <chrono>
#include <utility>

namespace margelo::nitro::rootjaildetect {

  CompromiseAssessment assessDevice(const ResolvedRootJailDetectOptions& options) {
    // Play Integrity token acquisition requires a server-issued nonce and is
    // intentionally kept out of this local assessment pass.
    (void) options.enablePlayIntegrity;
    const auto startTime = std::chrono::steady_clock::now();
    const auto deadline = startTime + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
      std::chrono::duration<double, std::milli>(options.timeoutMs)
    );

#if defined(NDEBUG)
    const bool includeEvidence = false;
#else
    const bool includeEvidence = options.includeEvidence;
#endif

#if defined(__ANDROID__)
    Platform platform = Platform::ANDROID;
    AndroidCheckResult nativeResult = runAndroidChecks(includeEvidence, deadline);
#else
    Platform platform = Platform::IOS;
    IOSCheckContext iosContext;
    iosContext.includeEvidence = includeEvidence;
    iosContext.deadline = deadline;
    iosContext.urlSchemes = options.urlSchemes;
    iosContext.urlSchemesPerSignal = options.urlSchemesPerSignal;
    IOSCheckResult nativeResult = runIOSChecks(iosContext);
#endif

    const auto endTime = std::chrono::steady_clock::now();
    const double elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    AggregatedScore aggregated = aggregateSignals(nativeResult.signals);
    const bool compromised = aggregated.score >= options.minScore ||
                             (options.treatDebuggerAsCompromise && nativeResult.debuggerDetected);

    return CompromiseAssessment(
      platform,
      compromised,
      aggregated.score,
      aggregated.confidence,
      std::move(nativeResult.signals),
      nativeResult.debuggerDetected,
      elapsedMs,
      nativeResult.partial || elapsedMs > options.timeoutMs
    );
  }

} // namespace margelo::nitro::rootjaildetect
