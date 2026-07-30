///
/// HybridUrlSchemeProbe.cpp
///

#include "HybridUrlSchemeProbe.hpp"

namespace margelo::nitro::rootjaildetect {

  HybridUrlSchemeProbe::HybridUrlSchemeProbe() : HybridObject(TAG) {}

  bool HybridUrlSchemeProbe::canOpenUrl(const std::string& scheme) {
    // No-op on Android and on host builds; real implementation is the Swift
    // HybridUrlSchemeProbe on iOS.
    (void) scheme;
    return false;
  }

  size_t HybridUrlSchemeProbe::getExternalMemorySize() noexcept {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
