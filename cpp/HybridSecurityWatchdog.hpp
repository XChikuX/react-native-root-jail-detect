///
/// HybridSecurityWatchdog.hpp
///
/// Separate HybridObject that owns the long-lived watchdog background thread
/// and mutable lifecycle state. A separate object from `RootJailDetect`
/// because of the one-lifecycle-per-HybridObject rule.
///
/// The watchdog consumes `RootJailDetect::checkDetailed()` with the configured
/// threshold; it must not duplicate detection logic.
///
/// PR 1 (Nitro skeleton) tracks running state and resolves `start()`/`stop()`
/// immediately. A real background loop lands in PR 3 (iOS separation + watchdog)
/// so that lifecycle state can be hardened with the rest of the watchdog work.
///

#pragma once

#include "HybridSecurityWatchdogSpec.hpp"

#include <atomic>

namespace margelo::nitro::rootjaildetect {

  class HybridSecurityWatchdog final : public HybridSecurityWatchdogSpec {
  public:
    HybridSecurityWatchdog();

  public:
    // Properties
    bool getIsRunning() override;

  public:
    // Methods
    std::shared_ptr<Promise<void>> start(const SecurityWatchdogOptions& options) override;
    std::shared_ptr<Promise<void>> stop() override;

  public:
    // HybridObject
    size_t getMemorySize() override;

  private:
    std::atomic<bool> _isRunning{false};
  };

} // namespace margelo::nitro::rootjaildetect
