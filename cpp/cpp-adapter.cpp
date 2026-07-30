/**
 * cpp-adapter.cpp
 * JNI_OnLoad entry point for Nitro Modules autolinking.
 * This file registers all native HybridObjects with the Nitro Modules registry.
 */

#include <jni.h>
#include <fbjni/fbjni.h>

// Include the generated registration header
#include "RootJailDetectOnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, []() {
    // Register all RootJailDetect HybridObjects
    margelo::nitro::rootjaildetect::registerAllNatives();
    // Any other custom registrations go here.
  });
}