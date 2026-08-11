/**
 * cpp-adapter.cpp
 * JNI_OnLoad entry point for Nitro Modules autolinking.
 * This file registers all native HybridObjects with the Nitro Modules registry.
 */

#include <jni.h>
#include <fbjni/fbjni.h>

#include <cstdio>
#include <exception>
#include <memory>

#include <NitroModules/HybridObjectRegistry.hpp>

#include "HybridRootJailDetect.hpp"
#include "HybridSecurityWatchdog.hpp"
#include "HybridUrlSchemeProbe.hpp"

// Include the generated registration header
#include "RootJailDetectOnLoad.hpp"

namespace {

// Register one pure-C++ HybridObject, skipping names that are already
// registered (the registry throws on duplicates in NITRO_DEBUG builds).
template <typename T>
void registerCxxHybridObject(const char* name) {
  if (margelo::nitro::HybridObjectRegistry::hasHybridObject(name)) {
    return;
  }
  margelo::nitro::HybridObjectRegistry::registerHybridObjectConstructor(
    name,
    []() -> std::shared_ptr<margelo::nitro::HybridObject> {
      return std::make_shared<T>();
    }
  );
}

} // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, []() {
    try {
      // Register all RootJailDetect HybridObjects
      margelo::nitro::rootjaildetect::registerAllNatives();
    } catch (const std::exception& error) {
      // The generated registration also touches the Kotlin edge class
      // `com.margelo.nitro.rootjaildetect.HybridPackageManagerProbe` via JNI.
      // If a consumer's release build strips or renames that class, fbjni
      // throws here — and without this guard the exception would escape
      // JNI_OnLoad and abort the process at System.loadLibrary time with no
      // JS-side log. Degrade instead: register the pure-C++ HybridObjects and
      // leave "PackageManagerProbe" unregistered so AndroidChecks falls back
      // to its no-op C++ stub (detection continues, package signals absent).
      std::fprintf(
        stderr,
        "RootJailDetect: full native registration failed (%s); "
        "falling back to C++-only HybridObjects.\n",
        error.what()
      );
    } catch (...) {
      std::fprintf(
        stderr,
        "RootJailDetect: full native registration failed (unknown error); "
        "falling back to C++-only HybridObjects.\n"
      );
    }

    using namespace margelo::nitro::rootjaildetect;
    registerCxxHybridObject<HybridRootJailDetect>("RootJailDetect");
    registerCxxHybridObject<HybridSecurityWatchdog>("SecurityWatchdog");
    registerCxxHybridObject<HybridUrlSchemeProbe>("UrlSchemeProbe");
  });
}
