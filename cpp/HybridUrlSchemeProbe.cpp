///
/// HybridUrlSchemeProbe.cpp
///

#include "HybridUrlSchemeProbe.hpp"

namespace margelo::nitro::rootjaildetect {

  HybridUrlSchemeProbe::HybridUrlSchemeProbe() : HybridObject(TAG) {}

  std::vector<std::string> HybridUrlSchemeProbe::checkSchemes(const std::vector<std::string>& schemes) {
    // No-op on Android and on host builds; real implementation is the Swift
    // HybridUrlSchemeProbe on iOS.
    (void) schemes;
    return {};
  }

  size_t HybridUrlSchemeProbe::getMemorySize() {
    return sizeof(*this);
  }

} // namespace margelo::nitro::rootjaildetect
