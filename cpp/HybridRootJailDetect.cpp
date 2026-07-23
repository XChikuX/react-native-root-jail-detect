///
/// HybridRootJailDetect.cpp
///

#include "HybridRootJailDetect.hpp"
#include "HybridSecurityWatchdog.hpp"

#include <NitroModules/Promise.hpp>

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
    // PR 1 (Nitro skeleton): resolve immediately with a clean, empty result so
    // the JS layer and example app compile and run end-to-end. Real detection
    // checks land in subsequent PRs and will run within the configured
    // `_timeoutMs` budget, surfacing overrun checks as `unavailable` signals
    // with `partial: true` rather than failing the call.
    return Promise<DeviceRiskResult>::async([this]() -> DeviceRiskResult {
#if defined(__ANDROID__)
      Platform platform = Platform::ANDROID;
#else
      Platform platform = Platform::IOS;
#endif
      DeviceRiskResult result(
        /* platform */ platform,
        /* compromised */ false,
        /* score */ 0.0,
        /* confidence */ Confidence::LOW,
        /* signals */ {},
        /* debuggerDetected */ false,
        /* elapsedMs */ 0.0,
        /* partial */ false
      );
      (void) _minScore;           // used by future scoring logic
      (void) _timeoutMs;          // used by future deadline enforcement
      (void) _includeEvidence;    // used by future evidence redaction
      (void) _treatDebuggerAsCompromise; // used by future debugger policy
      (void) _enablePlayIntegrity; // used by future Play Integrity path
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
