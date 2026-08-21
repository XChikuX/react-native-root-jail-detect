///
/// HybridPackageManagerProbe.cpp
///
/// No-op C++ stub for Android PackageManager root package enumeration.
/// The real implementation is in Kotlin on Android.
///

#include "HybridPackageManagerProbe.hpp"

namespace margelo::nitro::rootjaildetect {

// The generated spec inherits `HybridObject` virtually, so this most-derived
// constructor must initialize the virtual base explicitly — a defaulted
// constructor would hit Nitro's throwing default `HybridObject()` instead.
HybridPackageManagerProbe::HybridPackageManagerProbe() : HybridObject(TAG) {}

std::vector<std::string> HybridPackageManagerProbe::getInstalledRootPackages() {
  // No-op on iOS/host. The Android implementation lives in Kotlin.
  return {};
}

std::vector<std::string> HybridPackageManagerProbe::getInstalledHidingPackages() {
  return {};
}

std::vector<std::string> HybridPackageManagerProbe::getInstalledRiskyPackages() {
  return {};
}

size_t HybridPackageManagerProbe::getExternalMemorySize() noexcept {
  return sizeof(*this);
}

} // namespace margelo::nitro::rootjaildetect
