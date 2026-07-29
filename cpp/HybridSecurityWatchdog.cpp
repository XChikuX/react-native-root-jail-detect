///
/// HybridSecurityWatchdog.cpp
///

#include "HybridSecurityWatchdog.hpp"

#include <NitroModules/Promise.hpp>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <exception>
#include <stdexcept>

namespace margelo::nitro::rootjaildetect {

  HybridSecurityWatchdog::HybridSecurityWatchdog()
    : HybridSecurityWatchdog(std::make_shared<RootJailDetectConfiguration>()) {}

  HybridSecurityWatchdog::HybridSecurityWatchdog(
    std::shared_ptr<RootJailDetectConfiguration> configuration
  ) : HybridObject(TAG),
      _configuration(std::move(configuration)) {}

  HybridSecurityWatchdog::~HybridSecurityWatchdog() {
    _isRunning.store(false, std::memory_order_release);
    _wake.notify_all();
    if (_thread.joinable()) {
      _thread.join();
    }
  }

  bool HybridSecurityWatchdog::getIsRunning() {
    return _isRunning.load(std::memory_order_acquire);
  }

  std::shared_ptr<Promise<void>> HybridSecurityWatchdog::start(const SecurityWatchdogOptions& options) {
    return Promise<void>::async([this, options]() -> void {
      const double intervalMs = options.intervalMs.value_or(3000.0);
      if (!std::isfinite(intervalMs) || intervalMs <= 0.0) {
        throw std::invalid_argument("intervalMs must be a positive finite value.");
      }

      std::thread oldThread;
      {
        std::scoped_lock lock(_lifecycleMutex);
        if (_isRunning.load(std::memory_order_acquire)) {
          return;
        }
        if (_thread.joinable()) {
          oldThread = std::move(_thread);
        }
      }

      if (oldThread.joinable()) {
        oldThread.join();
      }

      std::scoped_lock lock(_lifecycleMutex);
      if (_isRunning.load(std::memory_order_acquire)) {
        return;
      }
      _intervalMs = intervalMs;
      _protectionMode = options.protectionMode.value_or(ProtectionMode::LOG_ONLY);
      _isRunning.store(true, std::memory_order_release);
      _thread = std::thread(&HybridSecurityWatchdog::run, this);
    });
  }

  std::shared_ptr<Promise<void>> HybridSecurityWatchdog::stop() {
    return Promise<void>::async([this]() -> void {
      _isRunning.store(false, std::memory_order_release);
      _wake.notify_all();
      std::thread thread;
      {
        std::scoped_lock lock(_lifecycleMutex);
        if (_thread.joinable()) {
          thread = std::move(_thread);
        }
      }
      if (thread.joinable()) {
        thread.join();
      }
    });
  }

  void HybridSecurityWatchdog::run() {
    while (_isRunning.load(std::memory_order_acquire)) {
      ResolvedRootJailDetectOptions options;
      {
        std::scoped_lock lock(_configuration->mutex);
        options = _configuration->options;
      }

      const DeviceRiskResult result = assessDevice(options);
      if (result.compromised) {
        switch (_protectionMode) {
          case ProtectionMode::LOG_ONLY:
            std::fprintf(stderr, "SecurityWatchdog detected a compromised device.\n");
            break;
          case ProtectionMode::THROW_EXCEPTION:
            // A background worker cannot safely throw through the JS runtime.
            // Log the event instead of silently turning this mode into
            // termination; callers that need a destructive response should use
            // TERMINATE explicitly.
            std::fprintf(stderr, "SecurityWatchdog would throw for a compromised device.\n");
            break;
          case ProtectionMode::TERMINATE:
            std::terminate();
        }
      }

      std::unique_lock lock(_lifecycleMutex);
      const auto interval = std::chrono::duration<double, std::milli>(_intervalMs);
      _wake.wait_for(lock, interval, [this] {
        return !_isRunning.load(std::memory_order_acquire);
      });
    }
  }

  size_t HybridSecurityWatchdog::getMemorySize() {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
