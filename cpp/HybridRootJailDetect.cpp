///
/// HybridRootJailDetect.cpp
///

#include "HybridRootJailDetect.hpp"
#include "HybridAppStoreReceiptProbe.hpp"
#include "HybridPackageManagerProbe.hpp"
#include "HybridSecurityWatchdog.hpp"

#include <NitroModules/HybridObjectRegistry.hpp>
#include <NitroModules/Promise.hpp>

#include <cmath>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>

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

  std::shared_ptr<Promise<CompromiseAssessment>> HybridRootJailDetect::checkDetailed() {
    std::shared_ptr<RootJailDetectConfiguration> configuration = _configuration;
    return Promise<CompromiseAssessment>::async([configuration]() -> CompromiseAssessment {
      ResolvedRootJailDetectOptions options;
      {
        std::scoped_lock lock(configuration->mutex);
        options = configuration->options;
      }
      return assessDevice(options);
    });
  }

  std::shared_ptr<Promise<CompromiseAssessment>> HybridRootJailDetect::assessRisk() {
    return checkDetailed();
  }

  std::shared_ptr<Promise<InstallOrigin>> HybridRootJailDetect::getInstallOrigin() {
    // Provenance resolution is informational and never feeds the scored
    // signal catalog. We still run it on a Nitro worker thread (Promise::async)
    // because the Android path makes a PackageManager binder query that
    // must not block the JS caller thread.
    return Promise<InstallOrigin>::async([]() -> InstallOrigin {
#if defined(__APPLE__)
      // iOS path: Swift receipt probe. The probe lookup follows the same
      // pattern used by `IOSChecks.cpp` for `UrlSchemeProbe` — iOS is safe
      // to construct synchronously (no fbjni/ThreadScope required), and the
      // Swift edge returns immediately because Foundation file-exists is
      // a fast stat, not a UIKit dispatch.
      std::shared_ptr<HybridAppStoreReceiptProbeSpec> probe;
      try {
        std::shared_ptr<margelo::nitro::HybridObject> object =
          margelo::nitro::HybridObjectRegistry::createHybridObject("AppStoreReceiptProbe");
        probe = std::dynamic_pointer_cast<HybridAppStoreReceiptProbeSpec>(object);
      } catch (...) {
        probe = nullptr;
      }
      if (!probe) {
        probe = std::make_shared<HybridAppStoreReceiptProbe>();
      }
      std::string state = "none";
      try {
        state = probe->getReceiptState();
      } catch (...) {
        // Swift `throws` paths and registry construction failures must both
        // resolve to unknown — never to a claimed origin.
        state = "none";
      }
      return resolveIOSInstallOrigin(state);
#else
      // Android path: PackageManager installer record. The PackageManager
      // binder call lives inside the Kotlin edge, so we delegate through the
      // same HybridObject pattern. Failure modes (registry miss, R8 rename,
      // missing context) all collapse to UNKNOWN — inability to inspect is
      // never evidence of sideloading.
      std::shared_ptr<HybridPackageManagerProbeSpec> probe;
      try {
        std::shared_ptr<margelo::nitro::HybridObject> object =
          margelo::nitro::HybridObjectRegistry::createHybridObject("PackageManagerProbe");
        probe = std::dynamic_pointer_cast<HybridPackageManagerProbeSpec>(object);
      } catch (...) {
        probe = nullptr;
      }
      if (!probe) {
        probe = std::make_shared<HybridPackageManagerProbe>();
      }
      std::optional<std::string> installer;
      try {
        installer = probe->getInstallerPackageName();
      } catch (...) {
        installer = std::nullopt;
      }
      return resolveAndroidInstallOrigin(installer);
#endif
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

  size_t HybridRootJailDetect::getExternalMemorySize() noexcept {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
