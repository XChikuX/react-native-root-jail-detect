///
/// HybridSecurityWatchdog.cpp
///

#include "HybridSecurityWatchdog.hpp"

#include <NitroModules/Promise.hpp>

namespace margelo::nitro::rootjaildetect {

  HybridSecurityWatchdog::HybridSecurityWatchdog()
    : HybridObject(TAG) {}

  bool HybridSecurityWatchdog::getIsRunning() {
    return _isRunning.load(std::memory_order_acquire);
  }

  std::shared_ptr<Promise<void>> HybridSecurityWatchdog::start(const SecurityWatchdogOptions& options) {
    return Promise<void>::async([this, options]() -> void {
      // PR 1 skeleton: record intent only. The real background loop that runs
      // `checkDetailed()` on each tick lands in PR 3 so lifecycle hardening can
      // happen alongside the rest of the watchdog work. We deliberately do not
      // spawn a thread yet so automated tests cannot accidentally exercise a
      // partially-implemented destructive protection mode.
      (void) options;
      _isRunning.store(true, std::memory_order_release);
    });
  }

  std::shared_ptr<Promise<void>> HybridSecurityWatchdog::stop() {
    return Promise<void>::async([this]() -> void {
      _isRunning.store(false, std::memory_order_release);
    });
  }

  size_t HybridSecurityWatchdog::getMemorySize() {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
