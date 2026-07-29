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
    size_t getExternalMemorySize() noexcept override;

  private:
    std::atomic<bool> _isRunning{false};
    std::shared_ptr<RootJailDetectConfiguration> _configuration;
    // Serializes lifecycle transitions (`start()`/`stop()`) so the
    // "is it running?" check and the thread launch/join happen atomically
    // with respect to each other. Without it, two overlapping `start()` calls
    // (each runs on its own Nitro background thread) could both observe
    // "not running" and both spawn a `run()` thread, leaking a thread and
    // producing two concurrent watchdogs.
    std::mutex _startMutex;
    // Protects the `_thread` handle and backs the `_wake` condition variable.
    // Held only briefly during transitions and during the timed sleep in
    // `run()`; never held while running `assessDevice()` or threat actions.
    std::mutex _lifecycleMutex;
    std::condition_variable _wake;
    std::thread _thread;
    double _intervalMs = 3000.0;
    ProtectionMode _protectionMode = ProtectionMode::LOG_ONLY;

    void run();
  };

} // namespace margelo::nitro::rootjaildetect
