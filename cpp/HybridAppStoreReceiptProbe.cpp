///
/// HybridAppStoreReceiptProbe.cpp
///

#include "HybridAppStoreReceiptProbe.hpp"

namespace margelo::nitro::rootjaildetect {

  // The generated spec inherits `HybridObject` virtually, so this most-derived
  // constructor must initialize the virtual base explicitly — a defaulted
  // constructor would hit Nitro's throwing default `HybridObject()` instead.
  HybridAppStoreReceiptProbe::HybridAppStoreReceiptProbe() : HybridObject(TAG) {}

  std::shared_ptr<Promise<std::string>> HybridAppStoreReceiptProbe::getReceiptState() {
    // No-op on Android and on host builds; the real implementation is the
    // Swift `HybridAppStoreReceiptProbe` on iOS. Return an already-resolved
    // `"none"` so the resolver's conservative "absence is unknown" rule takes
    // over, never a claim of App Store provenance.
    return Promise<std::string>::resolved("none");
  }

  size_t HybridAppStoreReceiptProbe::getExternalMemorySize() noexcept {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
