///
/// DeviceRiskAssessment.cpp
///

#include "DeviceRiskAssessment.hpp"
#include "AndroidChecks.hpp"
#include "IOSChecks.hpp"
#include "Scoring.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <utility>

namespace margelo::nitro::rootjaildetect {

  CompromiseAssessment assessDevice(const ResolvedRootJailDetectOptions& options) {
    // Play Integrity token acquisition requires a server-issued nonce and is
    // intentionally kept out of this local assessment pass.
    (void) options.enablePlayIntegrity;
    const auto startTime = std::chrono::steady_clock::now();
    // Clamp the budget before converting it. `configure()` accepts any positive
    // finite value, and a caller meaning "no timeout" may pass something like
    // `Number.MAX_VALUE`; converting that to the clock's integer tick type
    // overflows (undefined behavior) and can yield a deadline in the past,
    // which would silently skip every check. One hour is far beyond any real
    // pass and safely representable.
    constexpr double kMaxTimeoutMs = 60.0 * 60.0 * 1000.0;
    const double timeoutMs = std::isfinite(options.timeoutMs) && options.timeoutMs > 0.0
      ? std::min(options.timeoutMs, kMaxTimeoutMs)
      : kMaxTimeoutMs;
    const auto deadline = startTime + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
      std::chrono::duration<double, std::milli>(timeoutMs)
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
