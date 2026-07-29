///
/// HybridRootJailDetect.cpp
///

#include "HybridRootJailDetect.hpp"
#include "AndroidChecks.hpp"
#include "HybridSecurityWatchdog.hpp"
#include "Scoring.hpp"

#include <NitroModules/Promise.hpp>

#include <chrono>

namespace margelo::nitro::rootjaildetect {

  HybridRootJailDetect::HybridRootJailDetect()
    : HybridObject(TAG) {}

  void HybridRootJailDetect::configure(const RootJailDetectOptions& options) {
    // Keep previous values when an option is omitted (`undefined`), matching
    // the public contract that `configure()` only updates provided fields.
    if (options.minScore.has_value()) {
      _minScore = options.minScore.value();
    }
    if (options.timeoutMs.has_value()) {
      _timeoutMs = options.timeoutMs.value();
    }
    if (options.includeEvidence.has_value()) {
      _includeEvidence = options.includeEvidence.value();
    }
    if (options.treatDebuggerAsCompromise.has_value()) {
      _treatDebuggerAsCompromise = options.treatDebuggerAsCompromise.value();
    }
    if (options.enablePlayIntegrity.has_value()) {
      _enablePlayIntegrity = options.enablePlayIntegrity.value();
    }
  }

  std::shared_ptr<Promise<DeviceRiskResult>> HybridRootJailDetect::checkDetailed() {
    // Capture the resolved config by value so the async work is immune to a
    // concurrent `configure()` call mid-pass. `minScore`/`timeoutMs` are the
    // values that actually affect this pass's result.
    const double minScore = _minScore;
    const double timeoutMs = _timeoutMs;
    const bool includeEvidence = _includeEvidence;
    const bool treatDebuggerAsCompromise = _treatDebuggerAsCompromise;

    return Promise<DeviceRiskResult>::async([=]() -> DeviceRiskResult {
      const auto startTime = std::chrono::steady_clock::now();

#if defined(__ANDROID__)
      Platform platform = Platform::ANDROID;
      AndroidCheckResult android = runAndroidChecks(includeEvidence);
      std::vector<DetectionSignal> signals = std::move(android.signals);
      bool debuggerDetected = android.debuggerDetected;
#else
      // iOS Phase 1 checks land in PR 3. Until then the iOS path returns a
      // clean empty result so the JS layer and example app remain stable.
      Platform platform = Platform::IOS;
      std::vector<DetectionSignal> signals;
      bool debuggerDetected = false;
#endif

      const auto endTime = std::chrono::steady_clock::now();
      const double elapsedMs = std::chrono::duration<double, std::milli>(
                                 endTime - startTime
                               ).count();

      // Per-check deadline enforcement lands in a later phase. For now every
      // Phase 1 check is a fast local read, so we only surface the total budget
      // overrun as `partial: true` rather than failing the call.
      const bool partial = elapsedMs > timeoutMs;

      // Aggregate the fired signals into a clamped score and a confidence level.
      // `aggregateSignals` also deduplicates by id so equivalent evidence is not
      // counted twice.
      AggregatedScore aggregated = aggregateSignals(signals);

      // `compromised` is true when the score meets the configured threshold, or
      // when the caller explicitly asked the debugger flag to count as a
      // compromise (otherwise `debuggerDetected` stays purely diagnostic).
      const bool compromised = aggregated.score >= minScore ||
                               (treatDebuggerAsCompromise && debuggerDetected);

      DeviceRiskResult result(
        /* platform */ platform,
        /* compromised */ compromised,
        /* score */ aggregated.score,
        /* confidence */ aggregated.confidence,
        /* signals */ std::move(signals),
        /* debuggerDetected */ debuggerDetected,
        /* elapsedMs */ elapsedMs,
        /* partial */ partial
      );
      // `enablePlayIntegrity` is consumed by PR 2b/3 once the Play Integrity
      // edge HybridObject exists; reference it here to avoid an unused-warning
      // and to make the future hook site obvious.
      (void) _enablePlayIntegrity;
      return result;
    });
  }

  std::shared_ptr<HybridSecurityWatchdogSpec> HybridRootJailDetect::getWatchdog() {
    if (!_watchdog) {
      _watchdog = std::make_shared<HybridSecurityWatchdog>();
    }
    return _watchdog;
  }

  size_t HybridRootJailDetect::getMemorySize() {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
