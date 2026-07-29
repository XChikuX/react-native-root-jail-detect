///
/// HybridRootJailDetect.hpp
///
/// Shared C++ implementation of the `RootJailDetect` HybridObject.
///
/// The implementation owns resolved configuration and delegates each platform
/// pass to focused helpers. The watchdog reuses the same assessment entry point
/// so its compromise decision cannot diverge from `checkDetailed()`.
///
/// The HybridObject itself stays orchestration-only: it resolves config,
/// measures the total time budget, delegates platform work to focused helper
/// files under `cpp/`, and aggregates their signals into a `DeviceRiskResult`.
///

#pragma once

#include "DeviceRiskAssessment.hpp"
#include "HybridRootJailDetectSpec.hpp"

#include <memory>

namespace margelo::nitro::rootjaildetect {

  /**
   * Root device-risk HybridObject. Implemented in shared C++ so scoring,
   * the signal catalog, pattern matching, and `/proc` parsing are shared across
   * iOS and Android. Platform-specific probes live in thin Swift/Kotlin edge
   * HybridObjects that this core calls through their generated spec API.
   */
  class HybridRootJailDetect final : public HybridRootJailDetectSpec {
  public:
    HybridRootJailDetect();

  public:
    void configure(const RootJailDetectOptions& options) override;
    std::shared_ptr<Promise<DeviceRiskResult>> checkDetailed() override;
    std::shared_ptr<HybridSecurityWatchdogSpec> getWatchdog() override;

  public:
    // HybridObject
    size_t getMemorySize() override;

  private:
    std::shared_ptr<RootJailDetectConfiguration> _configuration;

    // The watchdog is created lazily on first `getWatchdog()` call and shared
    // across subsequent calls so JS always observes one lifecycle owner.
    std::shared_ptr<HybridSecurityWatchdogSpec> _watchdog;

  };

} // namespace margelo::nitro::rootjaildetect
