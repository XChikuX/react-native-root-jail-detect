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

#pragma once

#include "DeviceRiskAssessment.hpp"
#include "HybridSecurityWatchdogSpec.hpp"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace margelo::nitro::rootjaildetect {

  class HybridSecurityWatchdog final : public HybridSecurityWatchdogSpec {
  public:
    HybridSecurityWatchdog();
    explicit HybridSecurityWatchdog(std::shared_ptr<RootJailDetectConfiguration> configuration);
    ~HybridSecurityWatchdog() override;

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
    std::shared_ptr<RootJailDetectConfiguration> _configuration;
    std::mutex _lifecycleMutex;
    std::condition_variable _wake;
    std::thread _thread;
    double _intervalMs = 3000.0;
    ProtectionMode _protectionMode = ProtectionMode::LOG_ONLY;

    void run();
  };

} // namespace margelo::nitro::rootjaildetect
