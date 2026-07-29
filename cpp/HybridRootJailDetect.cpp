///
/// HybridRootJailDetect.cpp
///

#include "HybridRootJailDetect.hpp"
#include "HybridSecurityWatchdog.hpp"

#include <NitroModules/Promise.hpp>

#include <cmath>
#include <mutex>
#include <stdexcept>

namespace margelo::nitro::rootjaildetect {

  HybridRootJailDetect::HybridRootJailDetect()
    : HybridObject(TAG),
      _configuration(std::make_shared<RootJailDetectConfiguration>()) {}

  void HybridRootJailDetect::configure(const RootJailDetectOptions& options) {
    std::scoped_lock lock(_configuration->mutex);
    // Keep previous values when an option is omitted (`undefined`), matching
    // the public contract that `configure()` only updates provided fields.
    if (options.minScore.has_value()) {
      if (!std::isfinite(options.minScore.value()) || options.minScore.value() < 0.0 ||
          options.minScore.value() > 100.0) {
        throw std::invalid_argument("minScore must be a finite value from 0 to 100.");
      }
      _configuration->options.minScore = options.minScore.value();
    }
    if (options.timeoutMs.has_value()) {
      if (!std::isfinite(options.timeoutMs.value()) || options.timeoutMs.value() <= 0.0) {
        throw std::invalid_argument("timeoutMs must be a positive finite value.");
      }
      _configuration->options.timeoutMs = options.timeoutMs.value();
    }
    if (options.includeEvidence.has_value()) {
      _configuration->options.includeEvidence = options.includeEvidence.value();
    }
    if (options.treatDebuggerAsCompromise.has_value()) {
      _configuration->options.treatDebuggerAsCompromise = options.treatDebuggerAsCompromise.value();
    }
    if (options.enablePlayIntegrity.has_value()) {
      _configuration->options.enablePlayIntegrity = options.enablePlayIntegrity.value();
    }
    if (options.urlSchemes.has_value()) {
      if (options.urlSchemes.value().schemes.has_value()) {
        _configuration->options.urlSchemes = options.urlSchemes.value().schemes.value();
      }
      if (options.urlSchemes.value().perSchemeSignals.has_value()) {
        _configuration->options.urlSchemesPerSignal = options.urlSchemes.value().perSchemeSignals.value();
      }
    }
  }

  std::shared_ptr<Promise<DeviceRiskResult>> HybridRootJailDetect::checkDetailed() {
    std::shared_ptr<RootJailDetectConfiguration> configuration = _configuration;
    return Promise<DeviceRiskResult>::async([configuration]() -> DeviceRiskResult {
      ResolvedRootJailDetectOptions options;
      {
        std::scoped_lock lock(configuration->mutex);
        options = configuration->options;
      }
      return assessDevice(options);
    });
  }

  std::shared_ptr<HybridSecurityWatchdogSpec> HybridRootJailDetect::getWatchdog() {
    // `getWatchdog()` is a synchronous JS entry point, so serialize only the
    // one-time handle creation; the watchdog itself owns its lifecycle lock.
    std::scoped_lock lock(_configuration->mutex);
    if (!_watchdog) {
      _watchdog = std::make_shared<HybridSecurityWatchdog>(_configuration);
    }
    return _watchdog;
  }

  size_t HybridRootJailDetect::getMemorySize() {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
