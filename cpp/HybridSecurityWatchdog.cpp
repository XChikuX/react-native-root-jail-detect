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
    // Object lifetime guarantees no JS-triggered `start()`/`stop()` is in
    // flight here, but still access `_thread` under `_lifecycleMutex` for a
    // single, consistent access pattern. `run()` only touches `_lifecycleMutex`
    // during its timed sleep, so the join below cannot deadlock.
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

      // Serialize the whole transition against concurrent `start()`/`stop()`
      // calls. Each Nitro `Promise::async` runs on its own thread, so without
      // this guard two overlapping starts could both pass the "not running"
      // check and both spawn a `run()` thread. Holding `_startMutex` for the
      // entire decision guarantees at most one lifecycle transition is in
      // flight at a time; it is never acquired by `run()`, so joining a thread
      // while holding it cannot deadlock.
      std::scoped_lock startLock(_startMutex);

      // Fast path: a watchdog is already running, nothing to do.
      if (_isRunning.load(std::memory_order_acquire)) {
        return;
      }

      // Take ownership of any previous `run()` thread handle so we can join it
      // outside `_lifecycleMutex` (the join may block while the old thread
      // finishes its current pass, and `run()` acquires `_lifecycleMutex` for
      // its timed sleep). The previous thread is only joinable here when a
      // prior `stop()` flipped `_isRunning` to false but had not yet been
      // joined; it is already exiting, so the join is bounded.
      std::thread oldThread;
      {
        std::scoped_lock lock(_lifecycleMutex);
        if (_thread.joinable()) {
          oldThread = std::move(_thread);
        }
      }
      if (oldThread.joinable()) {
        oldThread.join();
      }

      // Launch the new background thread. `_startMutex` guarantees no other
      // transition can interleave between the running-check and the launch.
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
      // Serialize against concurrent `start()`/`stop()` so the flag flip, the
      // thread-handle move, and the join form one atomic transition.
      std::scoped_lock startLock(_startMutex);

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

      const CompromiseAssessment result = assessDevice(options);
      if (result.compromised) {
        switch (_protectionMode) {
          case ProtectionMode::LOG_ONLY:
            std::fprintf(stderr, "SecurityWatchdog detected a compromised device.\n");
            break;
          case ProtectionMode::THROW_EXCEPTION:
            // A background thread cannot synchronously throw into the JS
            // runtime, so THROW_EXCEPTION is intentionally demoted to a logged
            // warning here. This behavior is documented on the public
            // `ProtectionMode` type; callers that need to react in app code
            // should poll `checkDetailed()` on the JS thread and throw there.
            // We do NOT silently turn THROW_EXCEPTION into TERMINATE.
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
