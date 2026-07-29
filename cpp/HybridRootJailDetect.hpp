///
/// HybridRootJailDetect.hpp
///
/// Shared C++ implementation of the `RootJailDetect` HybridObject.
///
/// PR 1 (Nitro skeleton) shipped an empty stub. PR 2 adds the Android scored
/// baseline (PLAN.md Phase 1): `/proc` parsing, SELinux, root-manager paths,
/// build properties, and `TracerPid` as informational. iOS Phase 1 checks and
/// the real `SecurityWatchdog` background thread land in PR 3.
///
/// The HybridObject itself stays orchestration-only: it resolves config,
/// measures the total time budget, delegates platform work to focused helper
/// files under `cpp/`, and aggregates their signals into a `DeviceRiskResult`.
///

#pragma once

#include "HybridRootJailDetectSpec.hpp"

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
    // Resolved configuration. Stored as plain values; `undefined` options
    // passed to `configure()` keep the previous value. Defaults match the
    // public `RootJailDetectOptions` JSDoc.
    double _minScore = 40.0;
    double _timeoutMs = 400.0;
    bool _includeEvidence = false;
    bool _treatDebuggerAsCompromise = false;
    bool _enablePlayIntegrity = false;

    // The watchdog is created lazily on first `getWatchdog()` call and shared
    // across subsequent calls so JS always observes one lifecycle owner.
    std::shared_ptr<HybridSecurityWatchdogSpec> _watchdog;
  };

} // namespace margelo::nitro::rootjaildetect
